use thiserror::Error;

/// Provides a [Decompressor] for the DEFLATE algorithm using [inflate::InflateStream]
#[cfg(feature = "deflate")]
pub mod deflate;

#[derive(Error, Debug)]
pub enum DecompressionError {
    #[error("generic decompression error: {0}")]
    Generic(String)
}

pub trait Decompressor: std::fmt::Debug + Send + Sync {
    /// Tries to decompress data
    /// 
    /// The return values are the amount of input bytes decompressed,
    /// and the result of this decompression operation
    fn update(&mut self, data: &[u8]) -> Result<(usize, &[u8]), DecompressionError>;
}
