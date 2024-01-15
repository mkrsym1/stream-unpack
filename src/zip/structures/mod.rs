use thiserror::Error;

use crate::decompress::Decompressor;

#[cfg(feature = "deflate")]
use crate::decompress::deflate::DeflateDecompressor;

/// Provides utilities for locating a ZIP central directory
pub mod cd_location;

/// Provides general ZIP file header utilities
pub mod file_header;

/// Provides utilities for processing ZIP central directory file headers
pub mod central_directory;

/// Provides utilities for processing ZIP local file headers
pub mod local_file_header;

#[derive(Error, Debug)]
pub enum DecompressorCreationError {
    #[error("unknown compression method: {0}")]
    UnknownMethod(u16)
}

/// Represents a ZIP compression method. 
/// See [CompressionMethod::create_decompressor]
#[derive(Debug, Clone)]
pub enum CompressionMethod {
    #[cfg(feature = "deflate")]
    Deflate,

    Unknown(u16)
}

impl CompressionMethod {
    /// Tries to turn a ZIP compression id into a [CompressionMethod] variant. 
    /// 
    /// Returns None if the id is 0, [CompressionMethod::Unknown] if a 
    /// decompressor for it is not available
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => None,

            #[cfg(feature = "deflate")]
            8 => Some(Self::Deflate),

            _ => Some(Self::Unknown(id))
        }
    }

    /// Tries to create a [Decompressor] for this [CompressionMethod]
    /// 
    /// Returns error if it is [CompressionMethod::Unknown]
    pub fn create_decompressor(&self) -> Result<Box<dyn Decompressor>, DecompressorCreationError> {
        match self {
            #[cfg(feature = "deflate")]
            Self::Deflate => Ok(Box::new(DeflateDecompressor::new())),

            Self::Unknown(id) => Err(DecompressorCreationError::UnknownMethod(*id))
        }
    }

    /// Returns whether decompression is supported for this method
    pub fn is_supported(&self) -> bool {
        !(matches!(self, Self::Unknown(..)))
    }
}
