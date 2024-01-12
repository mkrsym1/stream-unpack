use std::io::Cursor;

use byteorder::{ReadBytesExt, LittleEndian};
use thiserror::Error;

use crate::zip::ZipPosition;

use super::{CompressionMethod, file_header::{FileHeaderExtraField, Zip64OriginalData, Zip64ProcessedData}};

#[derive(Debug, Error)]
pub enum CentralDirectoryError {
    #[error("input too short")]
    InputTooShort,

    #[error("invalid central directory file header signature at {0}")]
    InvalidSignature(usize),

    #[error("malformed central directory file header at {0}")]
    MalformedHeader(usize),

    #[error("{0} bytes left over after reading entire central directory")]
    LeftoverBytes(usize)
}

/// Represents a ZIP central directory.
/// 
/// The unpacker requires the central directory to be sorted
/// in the order of ascending position. [CentralDirectory::sort] 
/// can be used to obtain a [SortedCentralDirectory]
#[derive(Debug)]
pub struct CentralDirectory {
    headers: Vec<CentralDirectoryFileHeader>
}

impl CentralDirectory {
    /// Tries to read all CDFH from the central directory
    pub fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self, CentralDirectoryError> {
        let data = data.as_ref();
        if data.len() < 4 + CDFH_CONSTANT_SIZE {
            return Err(CentralDirectoryError::InputTooShort);
        }

        let mut headers = Vec::new();

        let mut offset = 0;
        while offset < data.len() - 3 {
            let signature = u32::from_le_bytes(data[offset..(offset + 4)].try_into().unwrap());
            if signature != CDFH_SIGNATURE {
                return Err(CentralDirectoryError::InvalidSignature(offset));
            }

            let Some(cdfh) = CentralDirectoryFileHeader::from_bytes(&data[(offset + 4)..]) else {
                return Err(CentralDirectoryError::MalformedHeader(offset));
            };

            offset += cdfh.header_size + 4;
            headers.push(cdfh);
        }

        if offset != data.len() {
            // There is something left over
            return Err(CentralDirectoryError::LeftoverBytes(data.len() - offset));
        }

        Ok(Self {
            headers
        })
    }

    /// Returns a reference to the CDFHs
    pub fn headers_ref(&self) -> &[CentralDirectoryFileHeader] {
        &self.headers
    }

    pub fn sort(mut self) -> SortedCentralDirectory {
        self.headers.sort_by(|a, b| {
            a.header_position().cmp(&b.header_position())    
        });

        SortedCentralDirectory {
            headers: self.headers
        }
    }
}

/// Represents a sorted ZIP central directory
#[derive(Debug)]
pub struct SortedCentralDirectory {
    headers: Vec<CentralDirectoryFileHeader>
}

impl SortedCentralDirectory {
    /// Returns a reference to the CDFHs
    pub fn headers_ref(&self) -> &[CentralDirectoryFileHeader] {
        &self.headers
    }
}

pub const CDFH_SIGNATURE: u32 = 0x02014B50;
pub const CDFH_CONSTANT_SIZE: usize = 42;

/// Represents the result of reading a central directory file header (CDFH)
/// 
/// The layout of this object does not follow the original ZIP CDFH structure
#[derive(Debug, Clone)]
pub struct CentralDirectoryFileHeader {
    pub version_made_by: u16,
    pub version_needed: u16,

    pub flag: u16,

    pub compression_method: Option<CompressionMethod>,

    pub mod_time: u16,
    pub mod_date: u16,

    pub crc32: u32,

    pub compressed_size: u64,
    pub uncompressed_size: u64,

    pub filename: String,
    
    pub extra_fields: Vec<FileHeaderExtraField>,

    pub disk_number: u32,

    pub internal_attributes: u16,
    pub external_attributes: u32,

    pub local_header_offset: u64,

    #[cfg(feature = "zip-comments")]
    pub comment: String,

    pub header_size: usize
}

impl CentralDirectoryFileHeader {
    /// Attempts to read a central directory file header from the provided
    /// byte buffer. Returns None if there isn't enought data
    pub fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self> {
        let data = data.as_ref();
        if data.len() < CDFH_CONSTANT_SIZE {
            return None;
        }

        let mut cursor = Cursor::new(data);

        let version_made_by = cursor.read_u16::<LittleEndian>().unwrap();
        let version_needed = cursor.read_u16::<LittleEndian>().unwrap();
        let flag = cursor.read_u16::<LittleEndian>().unwrap();
        let compression_method = cursor.read_u16::<LittleEndian>().unwrap();
        let mod_time = cursor.read_u16::<LittleEndian>().unwrap();
        let mod_date = cursor.read_u16::<LittleEndian>().unwrap();
        let crc32 = cursor.read_u32::<LittleEndian>().unwrap();
        let compressed_size = cursor.read_u32::<LittleEndian>().unwrap();
        let uncompressed_size = cursor.read_u32::<LittleEndian>().unwrap();
        let filename_length = cursor.read_u16::<LittleEndian>().unwrap();
        let extra_fields_length = cursor.read_u16::<LittleEndian>().unwrap();
        let comment_length = cursor.read_u16::<LittleEndian>().unwrap();
        let disk_number = cursor.read_u16::<LittleEndian>().unwrap();
        let internal_attributes = cursor.read_u16::<LittleEndian>().unwrap();
        let external_attributes = cursor.read_u32::<LittleEndian>().unwrap();
        let local_header_offset = cursor.read_u32::<LittleEndian>().unwrap();

        let filename_length = filename_length as usize;
        let extra_fields_length = extra_fields_length as usize;
        let comment_length = comment_length as usize;
        if data.len() < CDFH_CONSTANT_SIZE + filename_length + extra_fields_length + comment_length {
            return None;
        }

        let compression_method = CompressionMethod::from_id(compression_method);

        let filename_start = CDFH_CONSTANT_SIZE;
        let filename_end = filename_start + filename_length;
        let filename = String::from_utf8_lossy(&data[filename_start..filename_end]).to_string();

        let extra_fields_start = filename_end;
        let extra_fields_end = extra_fields_start + extra_fields_length;
        let Some(extra_fields) = FileHeaderExtraField::read_extra_fields(&data[extra_fields_start..extra_fields_end]) else {
            return None;
        };

        let comment_start = extra_fields_end;
        let comment_end = comment_start + comment_length;

        let original_zip64_data = Zip64OriginalData {
            uncompressed_size,
            compressed_size,
            local_header_offset,
            disk_number
        };

        let Some(Zip64ProcessedData {
            uncompressed_size,
            compressed_size,
            local_header_offset,
            disk_number
        }) = original_zip64_data.process(&extra_fields) else {
            return None;
        };

        Some(Self {
            version_made_by,
            version_needed,
            flag,
            compression_method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            filename,
            extra_fields,
            disk_number,
            internal_attributes,
            external_attributes,
            local_header_offset,

            #[cfg(feature = "zip-comments")]
            comment: String::from_utf8_lossy(&data[comment_start..comment_end]).to_string(),

            header_size: comment_end
        })
    }

    pub fn is_directory(&self) -> bool {
        self.filename.ends_with('/')
    }

    /// Returns the [ZipPosition] of the LFH corresponding to this CDFH
    pub fn header_position(&self) -> ZipPosition {
        ZipPosition::new(
            self.disk_number as usize,
            self.local_header_offset as usize
        )
    }
}
