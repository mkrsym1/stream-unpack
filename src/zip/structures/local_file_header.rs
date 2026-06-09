use std::io::Cursor;

use byteorder::{ReadBytesExt, LittleEndian};

use crate::{decrypt::{Decryptor, DecryptorCreationError}, zip::structures::file_header::{AEX_EXTRA_FIELD_ID, COMPRESSION_AEX, ENCRYPTED_FLAG}};

use super::{CompressionMethod, file_header::{FileHeaderExtraField, Zip64ProcessedData, Zip64OriginalData}};

#[cfg(feature = "zipcrypto")]
use crate::decrypt::zipcrypto::ZipCryptoDecryptor;

pub const LFH_SIGNATURE: u32 = 0x04034b50;
pub const LFH_CONSTANT_SIZE: usize = 26;

/// Represents the result of reading a ZIP local file header (LFH)
///
/// The layout of this object does not follow the original ZIP LFH structure
#[derive(Debug, Clone)]
pub struct LocalFileHeader {
    pub version: u16,

    pub flag: u16,

    pub compression_method: Option<CompressionMethod>,

    pub mod_time: u16,
    pub mod_date: u16,

    pub crc32: u32,

    pub compressed_size: u64,
    pub uncompressed_size: u64,

    pub filename: String,

    pub extra_fields: Vec<FileHeaderExtraField>,

    pub encryption: EncryptionData,

    pub header_size: usize
}

impl LocalFileHeader {
    /// Attempts to read a local file header from the provided
    /// byte buffer. Returns None if there isn't enought data
    pub fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self> {
        let data = data.as_ref();
        if data.len() < LFH_CONSTANT_SIZE {
            return None;
        }

        let mut cursor = Cursor::new(data);

        let version = cursor.read_u16::<LittleEndian>().unwrap();
        let flag = cursor.read_u16::<LittleEndian>().unwrap();
        let compression_method = cursor.read_u16::<LittleEndian>().unwrap();
        let mod_time = cursor.read_u16::<LittleEndian>().unwrap();
        let mod_date = cursor.read_u16::<LittleEndian>().unwrap();
        let crc32 = cursor.read_u32::<LittleEndian>().unwrap();
        let compressed_size = cursor.read_u32::<LittleEndian>().unwrap();
        let uncompressed_size = cursor.read_u32::<LittleEndian>().unwrap();
        let filename_length = cursor.read_u16::<LittleEndian>().unwrap();
        let extra_fields_length = cursor.read_u16::<LittleEndian>().unwrap();

        let filename_length = filename_length as usize;
        let extra_fields_length = extra_fields_length as usize;
        if data.len() < LFH_CONSTANT_SIZE + filename_length + extra_fields_length {
            return None;
        }

        let filename_start = LFH_CONSTANT_SIZE;
        let filename_end = filename_start + filename_length;
        let filename = String::from_utf8_lossy(&data[filename_start..filename_end]).to_string();

        let extra_fields_start = filename_end;
        let extra_fields_end = extra_fields_start + extra_fields_length;
        let extra_fields = FileHeaderExtraField::read_extra_fields(&data[extra_fields_start..extra_fields_end])?;

        let original_zip64_data = Zip64OriginalData {
            uncompressed_size,
            compressed_size,
            ..Default::default()
        };

        let Zip64ProcessedData {
            uncompressed_size,
            compressed_size,
            ..
        } = original_zip64_data.process(&extra_fields)?;

        let mut compressed_size = compressed_size;
        let mut compression_method = compression_method;
        let mut header_size = extra_fields_end;
        let mut encryption = EncryptionData::None;
        if flag & ENCRYPTED_FLAG != 0 {
            if compression_method == COMPRESSION_AEX {
                let aex_ef = extra_fields.iter()
                    .find(|f| f.id == AEX_EXTRA_FIELD_ID)?;
                if aex_ef.size() < 7 {
                    return None;
                }

                let strength = aex_ef.data[4];

                let salt_length = match strength {
                    0x01 => 8, 0x02 => 12, 0x03 => 16,
                    _ => { return None; }
                };

                let salt_start = header_size;
                let salt_end = salt_start + salt_length;
                if salt_end > data.len() {
                    return None;
                }

                let salt = &data[salt_start..salt_end];
                let aex_variant = match strength {
                    0x01 => AExVariant::AES128(salt.try_into().unwrap()),
                    0x02 => AExVariant::AES192(salt.try_into().unwrap()),
                    0x03 => AExVariant::AES256(salt.try_into().unwrap()),
                    _ => { return None; }
                };

                let pvv_start = salt_end;
                let pvv_end = pvv_start + 2;
                if pvv_end > data.len() {
                    return None;
                }

                let pvv = u16::from_le_bytes([data[pvv_start], data[pvv_start + 1]]);

                compressed_size -= (salt_length + 2 + 10) as u64;
                compression_method = u16::from_le_bytes([aex_ef.data[5], aex_ef.data[6]]);
                header_size = salt_end;
                encryption = EncryptionData::AEx(aex_variant, pvv)
            } else {
                let zipcrypto_header_start = header_size;
                let zipcrypto_header_end = zipcrypto_header_start + 12;
                if zipcrypto_header_end > data.len() {
                    return None;
                }

                compressed_size -= 12;
                header_size = zipcrypto_header_end;
                encryption = EncryptionData::ZipCrypto(
                    data[zipcrypto_header_start..zipcrypto_header_end].try_into().unwrap()
                );
            }
        }

        Some(Self {
            version,
            flag,
            compression_method: CompressionMethod::from_id(compression_method),
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            filename,
            extra_fields,

            encryption,

            header_size
        })
    }

    pub fn is_directory(&self) -> bool {
        self.filename.ends_with('/')
    }

    pub fn is_encrypted(&self) -> bool {
        return !matches!(self.encryption, EncryptionData::None);
    }

    /// Create a [Decryptor] for the file described by this LFH with the given password. Returns
    /// an error if the file is not encrypted.
    pub fn create_decryptor(&self, password: &[u8]) -> Result<Box<dyn Decryptor>, DecryptorCreationError> {
        match &self.encryption {
            EncryptionData::None => Err(DecryptorCreationError::NotEncrypted),

            EncryptionData::ZipCrypto(zipcrypto_header) => {
                #[cfg(feature = "zipcrypto")] {
                    Ok(Box::new(ZipCryptoDecryptor::new(password, *zipcrypto_header, self.crc32)?))
                }
                #[cfg(not(feature = "zipcrypto"))] {
                    let _ = password;
                    let _ = zipcrypto_header;
                    Err(DecryptorCreationError::NoFeature("zipcrypto".to_string()))
                }
            }

            EncryptionData::AEx(salt, pvv) => todo!("AEx, {:?}, {}", salt, pvv)
        }
    }
}

#[derive(Debug, Clone)]
pub enum EncryptionData {
    None,
    ZipCrypto([u8; 12]),
    AEx(AExVariant, u16)
}

#[derive(Debug, Clone)]
pub enum AExVariant {
    AES128([u8; 8]),
    AES192([u8; 12]),
    AES256([u8; 16])
}
