/// Provides utilities for decompressing data
pub mod decompress;

/// Provides utilities for decrypting data
pub mod decrypt;

/// Provides generalized utilities for handling file data
pub mod pipeline;

/// Provides utilities for unpacking ZIP archives
#[cfg(feature = "zip")]
pub mod zip;
