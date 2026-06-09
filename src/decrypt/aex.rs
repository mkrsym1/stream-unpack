// This is in part based (very loosely) on
// https://github.com/nih-at/libzip/blob/0ee634d3bf88cbedaa8ac81a54945937e16a5979/lib/zip_winzip_aes.c

use aes::{Aes128Enc, Aes192Enc, Aes256Enc, cipher::{BlockCipherEncrypt, Block, KeyInit}};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

use crate::decrypt::{DecryptionError, Decryptor, DecryptorCreationError};

/// Represents a [Decryptor] for AE-x streams. To be constructible, T must be [KeyInit].
/// To be usable as a [Decryptor], T must be [std::fmt::Debug] + [Send] + [Sync].
///
/// The aliases [AEx128Decryptor], [AEx192Decryptor], [AEx256Decryptor] should be used instead of this
/// type directly.
#[derive(Debug)]
pub struct AExDecryptor<T: BlockCipherEncrypt> {
    cipher: T,

    counter: Block<T>,
    pad: Block<T>,
    pad_offset: usize,

    buffer: Vec<u8>
}

pub type AEx128Decryptor = AExDecryptor<Aes128Enc>;
pub type AEx192Decryptor = AExDecryptor<Aes192Enc>;
pub type AEx256Decryptor = AExDecryptor<Aes256Enc>;

impl<T: KeyInit + BlockCipherEncrypt> AExDecryptor<T> {
    /// Create a new AE-x decryptor. The salt size shoult be half of the algorhitm's key size.
    pub fn new(password: &[u8], salt: &[u8], pvv: u16) -> Result<Self, DecryptorCreationError> {
        let ks = T::key_size();
        let bs = T::block_size();

        if salt.len() != ks/2 {
            return Err(DecryptorCreationError::Generic(
                format!("invalid salt length {} expected {}", salt.len(), ks/2)
            ));
        }

        let mut derivation = vec![0u8; ks + ks + 2];
        pbkdf2_hmac::<Sha1>(password, salt, 1000, &mut derivation);

        let dec_key = &derivation[0..ks];
        let auth_key = &derivation[ks..(ks+ks)];
        let derived_pvv = u16::from_le_bytes([derivation[ks+ks], derivation[ks+ks+1]]);

        // FIXME maybe do something with it later?
        let _ = auth_key;

        if pvv != derived_pvv {
            return Err(DecryptorCreationError::IncorrectPassword);
        }

        Ok(Self {
            cipher: T::new(dec_key.try_into().unwrap()),

            counter: Block::<T>::default(),
            pad: Block::<T>::default(),
            pad_offset: bs,

            buffer: Vec::new()
        })
    }
}

impl<T: BlockCipherEncrypt + std::fmt::Debug + Send + Sync> Decryptor for AExDecryptor<T> {
    fn update(&mut self, data: &[u8]) -> Result<(usize, &[u8]), DecryptionError> {
        self.buffer.clear();
        self.buffer.reserve_exact(data.len());
        for byte in data {
            if self.pad_offset == T::block_size() {
                for i in 0..8 {
                    self.counter[i] = self.counter[i].wrapping_add(1);
                    if self.counter[i] != 0 {
                        break;
                    }
                }
                self.cipher.encrypt_block_b2b(&self.counter, &mut self.pad);
                self.pad_offset = 0;
            }
            self.buffer.push(byte ^ self.pad[self.pad_offset]);
            self.pad_offset += 1;
        }
        Ok((data.len(), &self.buffer))
    }
}
