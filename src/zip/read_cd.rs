use thiserror::Error;

use super::{structures::{central_directory::{CentralDirectoryError, CentralDirectory}, cd_location::{CDLD_MAX_SIZE, EndOfCentralDirectory32, CentralDirectoryLocationData, EOCD64_LOCATOR_CONSTANT_SIZE, EOCD64_LOCATOR_SIGNATURE, EndOfCentralDirectory64Locator, EOCD64_CONSTANT_SIZE, EOCD64_SIGNATURE, EndOfCentralDirectory64}}, ZipPosition};

#[derive(Debug, Error)]
pub enum CentralDirectoryReadError {
    #[error("failed to map required data spans to disks")]
    Map,

    #[error("provider returned an error: {0}")]
    FromProvider(#[from] anyhow::Error),

    #[error("provider returned wrong amount of bytes: expected {0}, got {1}")]
    ProviderByteCount(usize, usize),

    #[error("failed to find end of central directory")]
    NoEOCD32,

    #[error("invalid disk sizes")]
    InvalidDiskSizes,

    #[error("failed to read end of central directory at")]
    BadEOCD32,

    #[error("failed to read end of zip64 central directory locator")]
    BadEOCD64Locator,

    #[error("failed to read end of zip64 central directory")]
    BadEOCD64,

    #[error("failed to decode central directory: {0}")]
    DecodeCentralDirectory(#[from] CentralDirectoryError),
}

/// Tries to locate and read a central directory by using the provider callback.
/// Disk sizes must be provided starting from the first disk (usually .001 or .z01). 
/// The last disk file is sometimes not labeled with a number
/// 
/// The "is_cut" option enables processing "multipart archives" which are not actually
/// multipart archives, and instead just a regular archive file split into pieces, 
/// without changing any of the structures
/// 
/// The arguments to the provider callback are a [ZipPosition] and length. It is guaranteed
/// that the length will not exceed the remaining size of the disk
pub fn from_provider(disk_sizes: impl AsRef<[usize]>, is_cut: bool, provider: impl Fn(ZipPosition, usize) -> Result<Vec<u8>, anyhow::Error>) -> Result<CentralDirectory, CentralDirectoryReadError> {
    let disk_sizes = disk_sizes.as_ref();
    let total_size = disk_sizes.iter().sum::<usize>();

    let cdld_offset = total_size - std::cmp::min(total_size, CDLD_MAX_SIZE);
    let cdld_bytes = make_calls(map_global_to_calls(disk_sizes, cdld_offset, CDLD_MAX_SIZE)?, &provider)?;

    let eocd32_offset = EndOfCentralDirectory32::find_offset(&cdld_bytes)
        .ok_or(CentralDirectoryReadError::NoEOCD32)?;

    let eocd32 = EndOfCentralDirectory32::from_bytes(&cdld_bytes[(eocd32_offset + 4)..])
        .ok_or(CentralDirectoryReadError::BadEOCD32)?;

    if eocd32_offset + 4 + eocd32.eocd32_size as usize != cdld_bytes.len() {
        return Err(CentralDirectoryReadError::InvalidDiskSizes);
    }

    let cdld = if !eocd32.requires_zip64() || eocd32_offset < 4 + EOCD64_LOCATOR_CONSTANT_SIZE {
        CentralDirectoryLocationData::from_eocd32(eocd32)
    } else {
        let locator_offset = eocd32_offset - 4 - EOCD64_LOCATOR_CONSTANT_SIZE;
        
        let locator_signature = u32::from_le_bytes(cdld_bytes[locator_offset..(locator_offset + 4)].try_into().unwrap());
        if locator_signature != EOCD64_LOCATOR_SIGNATURE {
            return Err(CentralDirectoryReadError::BadEOCD64Locator);
        }

        let locator = EndOfCentralDirectory64Locator::from_bytes(&cdld_bytes[(locator_offset + 4)..])
            .ok_or(CentralDirectoryReadError::BadEOCD64Locator)?;

        let eocd64_pos = ZipPosition::new(
            locator.eocd64_disk_number as usize, 
            locator.eocd64_offset as usize
        );

        let eocd64_bytes = make_calls(map_to_calls(disk_sizes, eocd64_pos, 4 + EOCD64_CONSTANT_SIZE, is_cut)?, &provider)?;

        let eocd64_signature = u32::from_le_bytes(eocd64_bytes[..4].try_into().unwrap());
        if eocd64_signature != EOCD64_SIGNATURE {
            return Err(CentralDirectoryReadError::BadEOCD64);
        }

        let eocd64 = EndOfCentralDirectory64::from_bytes(&eocd64_bytes[4..])
            .ok_or(CentralDirectoryReadError::BadEOCD64)?;

        CentralDirectoryLocationData::from_eocd64(eocd32, eocd64)
    };

    let cd_pos = ZipPosition::new(
        cdld.cd_disk_number as usize,
        cdld.cd_offset as usize
    );
    let cd_bytes = make_calls(map_to_calls(disk_sizes, cd_pos, cdld.cd_size as usize, is_cut)?, &provider)?;

    Ok(CentralDirectory::from_bytes(cd_bytes)?)
}

#[inline]
fn make_calls(calls: Vec<(ZipPosition, usize)>, provider: &dyn Fn(ZipPosition, usize) -> Result<Vec<u8>, anyhow::Error>) -> Result<Vec<u8>, CentralDirectoryReadError> {
    let mut bytes = Vec::new();

    for call in calls {
        let data = provider(call.0, call.1)?;

        if data.len() != call.1 {
            return Err(CentralDirectoryReadError::ProviderByteCount(call.1, data.len()));
        }

        bytes.extend(data);
    }

    Ok(bytes)
}

#[inline]
fn map_local_to_calls(disk_sizes: &[usize], pos: ZipPosition, length: usize) -> Result<Vec<(ZipPosition, usize)>, CentralDirectoryReadError> {
    let mut out = Vec::new();

    let mut cur_offset = pos.offset;
    let mut left = length;
    for (i, size) in disk_sizes.iter().enumerate().skip(pos.disk) {
        let from_this = std::cmp::min(size - cur_offset, left);
        out.push((ZipPosition::new(i, cur_offset), from_this));

        left -= from_this;
        if left == 0 {
            break;
        }

        cur_offset = 0;
    }

    if !out.is_empty() {
        Ok(out)
    } else {
        Err(CentralDirectoryReadError::Map)
    }
}

#[inline]
fn map_global_to_calls(disk_sizes: &[usize], offset: usize, length: usize) -> Result<Vec<(ZipPosition, usize)>, CentralDirectoryReadError> {
    let mut left = offset;
    for (i, size) in disk_sizes.iter().enumerate() {
        if left < *size {
            return map_local_to_calls(disk_sizes, ZipPosition::new(i, left), length);
        }

        left -= *size;
    }

    Err(CentralDirectoryReadError::Map)
}

fn map_to_calls(disk_sizes: &[usize], pos: ZipPosition, length: usize, global: bool) -> Result<Vec<(ZipPosition, usize)>, CentralDirectoryReadError> {
    if !global {
        map_local_to_calls(disk_sizes, pos, length)
    } else {
        map_global_to_calls(disk_sizes, pos.offset, length)
    }
}
