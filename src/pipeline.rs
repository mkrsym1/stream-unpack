use thiserror::Error;

use crate::{decompress::{DecompressionError, Decompressor}, decrypt::{DecryptionError, Decryptor}};

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("decryption error: {0}")]
    Decryption(#[from] DecryptionError),

    #[error("decompression error: {0}")]
    Decompression(#[from] DecompressionError)
}

/// Represents a generalized decompression pipeline for a file (decrypt then decompress)
/// as a single entity.
///
/// Either of the steps can be skipped.
#[derive(Debug)]
pub struct Pipeline {
    decryptor: Option<Box<dyn Decryptor>>,
    decompressor: Option<Box<dyn Decompressor>>,

    decrypt_buffer: Vec<u8>,
    result_buffer: Vec<u8>
}

impl Pipeline {
    /// Creates a new Pipeilne. Providing None for either step skips it. None can be provided for both steps.
    pub fn new(decryptor: Option<Box<dyn Decryptor>>, decompressor: Option<Box<dyn Decompressor>>) -> Self {
        Self {
            decryptor,
            decompressor,

            decrypt_buffer: Vec::new(),
            result_buffer: Vec::new()
        }
    }

    /// Updates the current pipeline with new data. Returns the amount of data actually consumed, and the
    /// pipeline result. The input data should be advanced exactly the amount that this method returned.
    ///
    /// The returned result data may be empty, which should not be of concern to the caller.
    /// The returned amount can be zero, which means that there is not enough data in the input to do
    /// anything meaningful, and the caller should retry with a larger slice when it becomes available.
    pub fn update(&mut self, data: &[u8]) -> Result<(usize, &[u8]), PipelineError> {
        if self.decryptor.is_some() && self.decompressor.is_some() {
            let decryptor = self.decryptor.as_deref_mut().unwrap();
            let decompressor = self.decompressor.as_deref_mut().unwrap();

            let (dcr_count, dcr_data) = decryptor.update(data)?;
            self.decrypt_buffer.extend(dcr_data);

            self.result_buffer.clear();
            let decrypt_slice = self.decrypt_buffer.as_slice();
            let mut offset = 0;
            loop {
                let (dcm_count, dcm_data) = decompressor.update(&decrypt_slice[offset..])?;
                self.result_buffer.extend(dcm_data);
                if dcm_count == 0 {
                    break;
                }
                offset += dcm_count;
            }
            self.decrypt_buffer.drain(0..offset);

            Ok((dcr_count, &self.result_buffer))
        } else if let Some(decryptor) = self.decryptor.as_deref_mut() {
            Ok(decryptor.update(data)?)
        } else if let Some(decompressor) = self.decompressor.as_deref_mut() {
            Ok(decompressor.update(data)?)
        } else {
            // FIXME maybe it is worth to avoid this copy...
            self.result_buffer = Vec::from(data);
            Ok((data.len(), &self.result_buffer))
        }
    }
}
