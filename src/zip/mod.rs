use thiserror::Error;

use crate::{decrypt::DecryptorCreationError, pipeline::{Pipeline, PipelineError}};

use self::structures::{local_file_header::{LocalFileHeader, LFH_SIGNATURE, LFH_CONSTANT_SIZE}, DecompressorCreationError, central_directory::{CentralDirectoryFileHeader, SortedCentralDirectory}};

/// Provides utilities for wokring with ZIP structures
pub mod structures;

/// Provides utilities for automatically locating and reading a central directory
pub mod read_cd;

#[derive(Debug, Error)]
pub enum DecoderError {
    #[error("file pipeline failed: {0}")]
    Pipeline(#[from] PipelineError),

    #[error("could not create decompressor: {0}")]
    DecompressorInit(#[from] DecompressorCreationError),

    #[error("could not create decryptor: {0}")]
    DecryptorInit(#[from] DecryptorCreationError),

    #[error("no password provided for encrypted file")]
    NoPassword,

    #[error("data exceeded archive size")]
    ExtraData,

    #[error("next header is at {0} but current position is {1}, one of the disk sizes is probably invalid")]
    Overshoot(ZipPosition, ZipPosition),

    #[error("could not find a file with position {0} in the central directory")]
    InvalidOffset(ZipPosition),

    #[error("file header has an invalid signature")]
    InvalidSignature,

    #[error("error within callback: {0}")]
    FromDecodeCallback(#[from] anyhow::Error)
}

#[derive(Debug)]
enum ZipDecoderState {
    FileHeader,
    FileData(u64, LocalFileHeader, Pipeline)
}

/// Represents a position in a (possbly multipart) ZIP archive
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct ZipPosition {
    pub disk: usize,
    pub offset: usize
}

impl std::fmt::Display for ZipPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.disk, self.offset)
    }
}

impl ZipPosition {
    /// Creates a new ZipPosition from the specified disk number and offset
    pub fn new(disk: usize, offset: usize) -> Self {
        Self {
            offset,
            disk
        }
    }

    /// Creates a new ZipPosition from the offset with disk number 0
    pub fn from_offset(offset: usize) -> Self {
        Self::new(0, offset)
    }
}

/// A chunk of decoded ZIP data
#[derive(Debug)]
pub enum ZipDecodedData<'a> {
    /// The ZIP file headers for a file
    FileHeader(&'a CentralDirectoryFileHeader, &'a LocalFileHeader),

    /// Decoded (uncompressed or decompressed) file bytes
    FileData(&'a [u8])
}

/// A stream unpacker for ZIP archives
pub struct ZipUnpacker<'a> {
    decoder_state: ZipDecoderState,
    current_index: usize,
    current_position: ZipPosition,

    disk_sizes: Vec<usize>,
    central_directory: SortedCentralDirectory,

    password: Option<Vec<u8>>,

    #[allow(clippy::type_complexity)]
    on_decode: Option<Box<dyn Fn(ZipDecodedData) -> anyhow::Result<()> + 'a>>
}

impl std::fmt::Debug for ZipUnpacker<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipUnpacker")
            .field("decoder_state", &self.decoder_state)
            .field("current_index", &self.current_index)
            .field("current_position", &self.current_position)
            .field("disk_sizes", &self.disk_sizes)
            .finish()
    }
}

impl<'a> ZipUnpacker<'a> {
    /// Creates a new ZipUnpacker
    ///
    /// The easiest way to obtain a central directory object is to use [read_cd::from_provider].
    /// "disk_sizes" must only contain one element if the archive is a cut one, and not a
    /// real split one.
    pub fn new(central_directory: SortedCentralDirectory, disk_sizes: Vec<usize>) -> Self {
        Self {
            decoder_state: ZipDecoderState::FileHeader,
            current_index: 0,
            current_position: ZipPosition::default(),

            disk_sizes,
            central_directory,

            password: None,

            on_decode: None
        }
    }

    /// Creates a new ZipUnpacker capable of decrypting files with a specified password.
    /// See [ZipUnpacker::new] for more information.
    pub fn new_with_password(central_directory: SortedCentralDirectory, disk_sizes: Vec<usize>, password: Vec<u8>) -> Self {
        Self {
            password: Some(password),
            ..Self::new(central_directory, disk_sizes)
        }
    }

    /// Creates a new ZipUnpacker, starting from the specified position. If the archive
    /// is not actually split, you must set disk number to 0 and use the absolute offset,
    /// even if there are multiple files
    ///
    /// The easiest way to obtain a central directory object is to use [read_cd::from_provider].
    /// "disk_sizes" must only contain one element if the archive is a cut one, and not a
    /// real split one.
    pub fn resume(central_directory: SortedCentralDirectory, disk_sizes: Vec<usize>, position: ZipPosition) -> Result<Self, DecoderError> {
        let index = central_directory.headers_ref()
            .binary_search_by(|h| h.header_position().cmp(&position))
            .map_err(|_| DecoderError::InvalidOffset(position))?;

        Ok(Self {
            decoder_state: ZipDecoderState::FileHeader,
            current_index: index,
            current_position: position,

            disk_sizes,
            central_directory,

            password: None,

            on_decode: None
        })
    }

    /// Creates a new ZipUnpacker capable of decrypting files with the specified password, starting at
    /// the specified position. See [ZipUnpacker::resume] for more information.
    pub fn resume_with_password(central_directory: SortedCentralDirectory, disk_sizes: Vec<usize>, password: Vec<u8>, position: ZipPosition) -> Result<Self, DecoderError> {
        Ok(Self {
            password: Some(password),
            ..(Self::resume(central_directory, disk_sizes, position)?)
        })
    }

    /// Sets the decode callback. The passed closure will be invoked
    /// when new data is decoded from bytes passed to [ZipUnpacker::update]
    pub fn set_callback(&mut self, on_decode: impl Fn(ZipDecodedData) -> anyhow::Result<()> + 'a) {
        self.on_decode = Some(Box::new(on_decode));
    }

    /// Update this ZipUnpacker with new bytes. The callback may or
    /// may not be fired, depending on the content. The callback may
    /// be fired multiple times.
    ///
    /// The first return value is how much the caller should advance the input buffer
    /// (0 means that there wasn't enough data in the buffer and the caller should 
    /// provide more), and the second value determines whether all files were processed 
    /// (which means that the caller should stop providing data)
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(usize, bool), DecoderError> {
        let data = data.as_ref();

        let mut buf_offset = 0;
        loop {
            let (advanced, reached_end) = self.update_internal(&data[buf_offset..])?;
            buf_offset += advanced;

            self.current_position.offset += advanced;
            if self.current_position.offset >= self.disk_sizes[self.current_position.disk] {
                // Find which disk this offset will be at
                let mut new_offset = self.current_position.offset;
                let mut new_disk_number = None;
                for d in (self.current_position.disk)..(self.disk_sizes.len() - 1) {
                    new_offset -= self.disk_sizes[d];
                    if new_offset < self.disk_sizes[d + 1] {
                        new_disk_number = Some(d + 1);
                        break;
                    }
                }

                let Some(new_disk_number) = new_disk_number else {
                    return Err(DecoderError::ExtraData);
                };

                self.current_position.offset = new_offset;
                self.current_position.disk = new_disk_number;
            }

            if advanced == 0 || reached_end {
                return Ok((buf_offset, reached_end));
            }
        }
    }

    fn update_internal(&mut self, data: impl AsRef<[u8]>) -> Result<(usize, bool), DecoderError> {
        let headers = self.central_directory.headers_ref();
        if self.current_index >= headers.len() {
            return Ok((0, true));
        }
        let cdfh = &headers[self.current_index];

        let data = data.as_ref();

        match &mut self.decoder_state {
            ZipDecoderState::FileHeader => {
                if self.current_position > cdfh.header_position() {
                    return Err(DecoderError::Overshoot(cdfh.header_position(), self.current_position));
                }

                if self.current_position.disk < cdfh.disk_number as usize {
                    // Next disk
                    return Ok((std::cmp::min(self.disk_sizes[self.current_position.disk] - self.current_position.offset, data.len()), false));
                }

                if self.current_position.offset < cdfh.local_header_offset as usize {
                    return Ok((std::cmp::min(cdfh.local_header_offset as usize - self.current_position.offset, data.len()), false));
                }

                if data.len() < 4 + LFH_CONSTANT_SIZE {
                    return Ok((0, false));
                }

                let signature = u32::from_le_bytes(data[..4].try_into().unwrap());
                if signature != LFH_SIGNATURE {
                    return Err(DecoderError::InvalidSignature);
                }

                let Some(lfh) = LocalFileHeader::from_bytes(&data[4..]) else {
                    return Ok((0, false));
                };
                let header_size = lfh.header_size;

                if let Some(on_decode) = &self.on_decode {
                    (on_decode)(ZipDecodedData::FileHeader(cdfh, &lfh))?;
                }

                let decryptor = if lfh.is_encrypted() {
                    if let Some(password) = &self.password {
                        Some(lfh.create_decryptor(password)?)
                    } else {
                        return Err(DecoderError::NoPassword);
                    }
                } else { None };

                if lfh.uncompressed_size != 0 {
                    let decompressor = lfh.compression_method
                        .as_ref()
                        .map(|m| m.create_decompressor())
                        .transpose()?;

                    let pipeline = Pipeline::new(decryptor, decompressor);
                    self.decoder_state = ZipDecoderState::FileData(0, lfh, pipeline);
                } else {
                    self.decoder_state = ZipDecoderState::FileHeader;
                    self.current_index += 1;
                }

                Ok((4 + header_size, false))
            },

            ZipDecoderState::FileData(pos, lfh, pipeline) => {
                let bytes_left = lfh.compressed_size - *pos;
                let bytes_to_read = std::cmp::min(bytes_left as usize, data.len());
                let file_bytes = &data[..bytes_to_read];

                let (count, data) = pipeline.update(file_bytes)?;
                *pos += count as u64;

                if let Some(on_decode) = &self.on_decode {
                    (on_decode)(ZipDecodedData::FileData(data))?;
                }

                if count as u64 == bytes_left {
                    self.decoder_state = ZipDecoderState::FileHeader;
                    self.current_index += 1;
                }

                Ok((count, false))
            }
        }
    }
}
