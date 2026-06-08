use thiserror::Error;

/// Provides a [Decryptor] for the ZipCrypto (PKWARE encryption) algorithm, used in old ZIP files.
#[cfg(feature = "zipcrypto")]
pub mod zipcrypto;

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("generic decryption error: {0}")]
    Generic(String),

    #[error("incorrect password")]
    IncorrectPassword
}

pub trait Decryptor: std::fmt::Debug + Send + Sync {
    /// Tries to decrypt data
    ///
    /// The return values are the amount of input bytes consumed,
    /// and the result of this decryption operation
    fn update(&mut self, data: &[u8]) -> Result<(usize, &[u8]), DecryptionError>;
}
