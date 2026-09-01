//! Little-endian command and result envelope byte codecs.

use super::*;

pub(super) struct FaultByteWriter<'a> {
    bytes: &'a mut [u8],
    cursor: usize,
}

impl<'a> FaultByteWriter<'a> {
    pub(super) const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(super) fn write(&mut self, value: &[u8]) {
        let end = self.cursor + value.len();
        self.bytes[self.cursor..end].copy_from_slice(value);
        self.cursor = end;
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    pub(super) fn array32(&mut self, value: [u8; 32]) {
        self.write(&value);
    }
}

pub(super) struct FaultByteReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> FaultByteReader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(super) fn read<const N: usize>(&mut self) -> Result<[u8; N], FaultAbiError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(FaultAbiError::HeaderLength)?;
        let source = self
            .bytes
            .get(self.cursor..end)
            .ok_or(FaultAbiError::HeaderLength)?;
        let mut value = [0_u8; N];
        value.copy_from_slice(source);
        self.cursor = end;
        Ok(value)
    }

    pub(super) fn u16(&mut self) -> Result<u16, FaultAbiError> {
        Ok(u16::from_le_bytes(self.read()?))
    }

    pub(super) fn u32(&mut self) -> Result<u32, FaultAbiError> {
        Ok(u32::from_le_bytes(self.read()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, FaultAbiError> {
        Ok(u64::from_le_bytes(self.read()?))
    }

    pub(super) fn array32(&mut self) -> Result<[u8; 32], FaultAbiError> {
        self.read()
    }

    pub(super) const fn exhausted(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}
