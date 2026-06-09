use thiserror::Error;

/// Provides a [Decryptor] for the ZipCrypto (PKWARE encryption) algorithm, used in old ZIP files.
#[cfg(feature = "zipcrypto")]
pub mod zipcrypto;

/// Provides a [Decryptor] for the AE-x algorithm, used in ZIP files.
#[cfg(feature = "ae-x")]
pub mod aex;

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("generic decryption error: {0}")]
    Generic(String)
}

#[derive(Error, Debug)]
pub enum DecryptorCreationError {
    #[error("generic decryptor creation error: {0}")]
    Generic(String),

    #[error("missing feature flag for encryption method: {0}")]
    NoFeature(String),

    #[error("incorrect password")]
    IncorrectPassword,

    #[error("data is not encrypted")]
    NotEncrypted
}

pub trait Decryptor: std::fmt::Debug + Send + Sync {
    /// Tries to decrypt data
    ///
    /// The return values are the amount of input bytes consumed,
    /// and the result of this decryption operation
    fn update(&mut self, data: &[u8]) -> Result<(usize, &[u8]), DecryptionError>;
}
