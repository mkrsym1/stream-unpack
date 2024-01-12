use std::io::Cursor;

use byteorder::{ReadBytesExt, LittleEndian};

/// Contains raw ZIP file header extra field data
#[derive(Debug, Clone)]
pub struct FileHeaderExtraField {
    pub id: u16,
    pub data: Vec<u8>
}

impl FileHeaderExtraField {
    /// Attempts to read a ZIP file header extra field. 
    /// Returns None if there is not enough data
    pub fn from_bytes(data: impl AsRef<[u8]>) -> Option<Self> {
        let data = data.as_ref();
        if data.len() < 4 {
            return None;
        }

        let mut cursor = Cursor::new(data);

        let id = cursor.read_u16::<LittleEndian>().unwrap();
        let size = cursor.read_u16::<LittleEndian>().unwrap();

        if data.len() < 4 + (size as usize) {
            return None;
        }

        Some(Self {
            id,
            data: data[4..(4 + size as usize)].to_owned()
        })
    }

    /// Attempts to read all ZIP file headers from the provided data.
    /// Returns None if there is an error
    pub fn read_extra_fields(data: impl AsRef<[u8]>) -> Option<Vec<FileHeaderExtraField>> {
        let data = data.as_ref();

        let mut extra_fileds = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let Some(field) = FileHeaderExtraField::from_bytes(&data[offset..]) else {
                return None;
            };

            offset += field.size();
            extra_fileds.push(field);
        }

        Some(extra_fileds)
    }

    /// The size of this field (together with the header)
    pub fn size(&self) -> usize {
        4 + self.data.len()
    }
}

pub const ZIP64_EXTRA_FIELD_ID: u16 = 0x0001;

#[derive(Debug, Default)]
pub struct Zip64OriginalData {
    pub uncompressed_size: u32,
    pub compressed_size: u32,
    pub local_header_offset: u32,
    pub disk_number: u16
}

#[derive(Debug)]
pub struct Zip64ProcessedData {
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub local_header_offset: u64,
    pub disk_number: u32
}

impl Zip64OriginalData {
    /// Processes a ZIP64 extra field if it exists in the input fields.
    /// Returns None if processing fails
    pub fn process(&self, fields: impl AsRef<[FileHeaderExtraField]>) -> Option<Zip64ProcessedData> {
        let required_size = self.required_zip64_size();

        if required_size == 0 {
            return Some(self.as_processed());
        }

        let fields = fields.as_ref();
        let Some(zip64) = fields.iter().find(|f| f.id == ZIP64_EXTRA_FIELD_ID) else {
            return Some(self.as_processed());
        };

        if zip64.data.len() < required_size {
            return None;
        }

        Some(self.read_all_if_needed(&zip64.data))
    }

    fn required_zip64_size(&self) -> usize {
        (
            if self.uncompressed_size   == u32::MAX { 8 } else { 0 } +
            if self.compressed_size     == u32::MAX { 8 } else { 0 } + 
            if self.local_header_offset == u32::MAX { 8 } else { 0 } +
            if self.disk_number         == u16::MAX { 4 } else { 0 }
        )
    }

    fn as_processed(&self) -> Zip64ProcessedData {
        Zip64ProcessedData { 
            compressed_size: self.compressed_size as u64, 
            uncompressed_size: self.uncompressed_size as u64, 
            local_header_offset: self.local_header_offset as u64, 
            disk_number: self.disk_number as u32 
        }
    }

    fn read_all_if_needed(&self, data: impl AsRef<[u8]>) -> Zip64ProcessedData {
        let data = data.as_ref();
        let mut cursor = Cursor::new(data);

        let uncompressed_size = Self::read_u64_if_needed(&mut cursor, self.uncompressed_size);
        let compressed_size = Self::read_u64_if_needed(&mut cursor, self.compressed_size);
        let file_header_offset = Self::read_u64_if_needed(&mut cursor, self.local_header_offset);
        let disk_number = Self::read_u32_if_needed(&mut cursor, self.disk_number);

        Zip64ProcessedData { 
            uncompressed_size, 
            compressed_size,
            local_header_offset: file_header_offset, 
            disk_number
        }
    }

    fn read_u64_if_needed(cursor: &mut Cursor<&[u8]>, value: u32) -> u64 {
        if value != u32::MAX {
            value as u64
        } else {
            cursor.read_u64::<LittleEndian>().unwrap()
        }
    }

    fn read_u32_if_needed(cursor: &mut Cursor<&[u8]>, value: u16) -> u32 {
        if value != u16::MAX {
            value as u32
        } else {
            cursor.read_u32::<LittleEndian>().unwrap()
        }
    }
}
