use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

pub const CDLD_MAX_SIZE: usize = EOCD32_MAX_SIZE + 4 + EOCD64_LOCATOR_CONSTANT_SIZE;

#[derive(Debug, Clone)]
pub struct CentralDirectoryLocationData {
    pub cd_disk_number: u32,
    pub cd_size: u64,
    pub cd_offset: u64,

    #[cfg(feature = "zip-comments")]
    pub comment: String
}

impl CentralDirectoryLocationData {
    pub fn from_eocd32(eocd32: EndOfCentralDirectory32) -> Self {
        Self {
            cd_disk_number: eocd32.cd_disk_number as u32,
            cd_size: eocd32.cd_size as u64,
            cd_offset: eocd32.cd_offset as u64,

            #[cfg(feature = "zip-comments")]
            comment: eocd32.comment
        }
    }

    pub fn from_eocd64(eocd32: EndOfCentralDirectory32, eocd64: EndOfCentralDirectory64) -> Self {
        let mut data = Self::from_eocd32(eocd32);

        if data.cd_disk_number == u16::MAX as u32 {
            data.cd_disk_number = eocd64.cd_disk_number;
        }

        if data.cd_size == u32::MAX as u64 {
            data.cd_size = eocd64.cd_size;
        }

        if data.cd_offset == u32::MAX as u64 {
            data.cd_offset = eocd64.cd_offset;
        }

        data
    }
}

pub const EOCD32_SIGNATURE: u32 = 0x06054b50;
pub const EOCD32_CONSTANT_SIZE: usize = 18;
pub const EOCD32_MAX_SIZE: usize = EOCD32_CONSTANT_SIZE + 4 + (u16::MAX as usize);

#[derive(Debug, Clone)]
pub struct EndOfCentralDirectory32 {
    pub disk_number: u16,
    pub cd_disk_number: u16,

    pub cd_entry_count: u16,
    pub cd_entry_count_total: u16,

    pub cd_size: u32,
    pub cd_offset: u32,

    #[cfg(feature = "zip-comments")]
    pub comment: String,

    pub eocd32_size: usize
}

impl EndOfCentralDirectory32 {
    pub fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self> {
        let data = data.as_ref();
        if data.len() < EOCD32_CONSTANT_SIZE {
            return None;
        }

        let mut cursor = Cursor::new(data);
        
        let disk_number = cursor.read_u16::<LittleEndian>().unwrap();
        let cd_disk_number = cursor.read_u16::<LittleEndian>().unwrap();
        let cd_entry_count = cursor.read_u16::<LittleEndian>().unwrap();
        let cd_entry_count_total = cursor.read_u16::<LittleEndian>().unwrap();
        let cd_size = cursor.read_u32::<LittleEndian>().unwrap();
        let cd_offset = cursor.read_u32::<LittleEndian>().unwrap();
        let comment_length = cursor.read_u16::<LittleEndian>().unwrap();

        if data.len() < EOCD32_CONSTANT_SIZE + comment_length as usize {
            return None;
        }

        let comment_start = EOCD32_CONSTANT_SIZE;
        let comment_end = comment_start + comment_length as usize;

        Some(Self {
            disk_number,
            cd_disk_number,
            cd_entry_count,
            cd_entry_count_total,
            cd_size,
            cd_offset,

            #[cfg(feature = "zip-comments")]
            comment: String::from_utf8_lossy(&data[comment_start..comment_end]).to_string(),

            eocd32_size: comment_end
        })
    }

    /// Tries to find an end of central directory structure at the end of given data.
    /// This searches at most 2^16 bytes
    /// 
    /// Returns the offset of this structure within the data if it is found
    pub fn find_offset(data: impl AsRef<[u8]>) -> Option<usize> {
        let data = data.as_ref();
        if data.len() < EOCD32_CONSTANT_SIZE {
            return None;
        }

        let first_offset = data.len() - std::cmp::min(data.len(), EOCD32_MAX_SIZE);

        for offset in (first_offset..(data.len() - EOCD32_CONSTANT_SIZE)).rev() {
            let signature = u32::from_le_bytes(data[offset..(offset + 4)].try_into().unwrap());
            if signature == EOCD32_SIGNATURE {
                return Some(offset);
            }
        }

        None
    }

    pub fn requires_zip64(&self) -> bool {
        self.disk_number == u16::MAX ||
        self.cd_disk_number == u16::MAX ||
        self.cd_entry_count == u16::MAX ||
        self.cd_entry_count_total == u16::MAX ||
        self.cd_size == u32::MAX ||
        self.cd_offset == u32::MAX
    }
}

pub const EOCD64_LOCATOR_SIGNATURE: u32 = 0x07064b50;
pub const EOCD64_LOCATOR_CONSTANT_SIZE: usize = 16;

#[derive(Debug, Clone)]
pub struct EndOfCentralDirectory64Locator {
    pub eocd64_disk_number: u32,
    pub eocd64_offset: u64,

    pub disk_count: u32
}

impl EndOfCentralDirectory64Locator {
    pub fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self> {
        let data = data.as_ref();
        if data.len() < EOCD64_LOCATOR_CONSTANT_SIZE {
            return None;
        }

        let mut cursor = Cursor::new(data);

        let eocd64_disk_number = cursor.read_u32::<LittleEndian>().unwrap();
        let eocd64_offset = cursor.read_u64::<LittleEndian>().unwrap();
        let disk_count = cursor.read_u32::<LittleEndian>().unwrap();

        Some(Self {
            eocd64_disk_number,
            eocd64_offset,
            disk_count
        })
    }
}

pub const EOCD64_SIGNATURE: u32 = 0x06064b50;
pub const EOCD64_CONSTANT_SIZE: usize = 52;

#[derive(Debug, Clone)]
pub struct EndOfCentralDirectory64 {
    pub eocd64_size: u64,

    pub version_made_by: u16,
    pub version_needed: u16,

    pub disk_number: u32,
    pub cd_disk_number: u32,

    pub cd_entry_count: u64,
    pub cd_entry_count_total: u64,

    pub cd_size: u64,
    pub cd_offset: u64
}

impl EndOfCentralDirectory64 {
    pub fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self> {
        let data = data.as_ref();
        if data.len() < EOCD64_CONSTANT_SIZE {
            return None;
        }

        let mut cursor = Cursor::new(data);

        let eocd64_size = cursor.read_u64::<LittleEndian>().unwrap();
        let version_made_by = cursor.read_u16::<LittleEndian>().unwrap();
        let version_needed = cursor.read_u16::<LittleEndian>().unwrap();
        let disk_number = cursor.read_u32::<LittleEndian>().unwrap();
        let cd_disk_number = cursor.read_u32::<LittleEndian>().unwrap();
        let cd_entry_count = cursor.read_u64::<LittleEndian>().unwrap();
        let cd_entry_count_total = cursor.read_u64::<LittleEndian>().unwrap();
        let cd_size = cursor.read_u64::<LittleEndian>().unwrap();
        let cd_offset = cursor.read_u64::<LittleEndian>().unwrap();

        // TODO: extensible data field

        Some(Self {
            eocd64_size,
            version_made_by,
            version_needed,
            disk_number,
            cd_disk_number,
            cd_entry_count,
            cd_entry_count_total,
            cd_size,
            cd_offset
        })
    }
}
