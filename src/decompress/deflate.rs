use std::fmt::Debug;

use inflate::InflateStream;

use super::{Decompressor, DecompressionError};

/// Simple wrapper around an [InflateStream]
pub struct DeflateDecompressor(InflateStream);

impl Debug for DeflateDecompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeflateDecompressor")
            .finish()
    }
}

impl Default for DeflateDecompressor {
    /// Identical to [DeflateDecompressor::new]
    fn default() -> Self {
        Self::new()    
    }
}

impl Decompressor for DeflateDecompressor {
    fn update(&mut self, data: &[u8]) -> Result<(usize, &[u8]), DecompressionError> {
        self.0.update(data)
            .map_err(DecompressionError::Generic)
    }
}

impl DeflateDecompressor {
    /// Creates a new DeflateDecompressor, with a new [InflateStream]
    pub fn new() -> Self {
        Self(InflateStream::new())
    }
}
