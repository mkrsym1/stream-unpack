use std::io::Cursor;

use byteorder::{ReadBytesExt, LittleEndian};

use super::{CompressionMethod, file_header::{FileHeaderExtraField, Zip64ProcessedData, Zip64OriginalData}};

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

        let compression_method = CompressionMethod::from_id(compression_method);

        let filename_start = LFH_CONSTANT_SIZE;
        let filename_end = filename_start + filename_length;
        let filename = String::from_utf8_lossy(&data[filename_start..filename_end]).to_string();

        let extra_fields_start = filename_end;
        let extra_fields_end = extra_fields_start + extra_fields_length;
        let Some(extra_fields) = FileHeaderExtraField::read_extra_fields(&data[extra_fields_start..extra_fields_end]) else {
            return None;
        };
        
        let original_zip64_data = Zip64OriginalData {
            uncompressed_size,
            compressed_size,
            ..Default::default()
        };

        let Some(Zip64ProcessedData {
            uncompressed_size,
            compressed_size,
            ..
        }) = original_zip64_data.process(&extra_fields) else {
            return None;
        };

        Some(Self {
            version,
            flag,
            compression_method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            filename,
            extra_fields,

            header_size: extra_fields_end
        })
    }

    pub fn is_directory(&self) -> bool {
        self.filename.ends_with('/')
    }
}
