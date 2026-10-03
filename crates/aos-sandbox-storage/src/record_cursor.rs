//! Checked cursor for authenticated Storage state records.
//!
//! Record-specific lengths and field validation stay with each format. This
//! cursor only reads bounded bytes and network-order integers, returning the
//! same corrupt-record error for malformed input in every caller.

use crate::StorageStateError;

/// Reads primitive fields from one authenticated Storage record.
pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    /// Starts at the first byte of a record body.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Takes an exact byte span without advancing after a failed bound check.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-record error if the span exceeds the input or offset.
    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], StorageStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StorageStateError::CorruptRecord)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StorageStateError::CorruptRecord)?;
        self.offset = end;
        Ok(value)
    }

    /// Reads a fixed-width byte array.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-record error if the input is truncated.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], StorageStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-record error if the input is truncated.
    pub(crate) fn u8(&mut self) -> Result<u8, StorageStateError> {
        Ok(self.array::<1>()?[0])
    }

    /// Reads a network-order 16-bit integer.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-record error if the input is truncated.
    pub(crate) fn u16(&mut self) -> Result<u16, StorageStateError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Reads a network-order 32-bit integer.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-record error if the input is truncated.
    pub(crate) fn u32(&mut self) -> Result<u32, StorageStateError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Reads a network-order 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns a corrupt-record error if the input is truncated.
    pub(crate) fn u64(&mut self) -> Result<u64, StorageStateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// Returns the number of unconsumed bytes.
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    /// Reports whether the entire record has been consumed.
    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
}
