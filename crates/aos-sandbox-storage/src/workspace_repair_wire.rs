//! Checked byte cursor shared by the private workspace-repair worker codecs.
//!
//! Each caller retains its own record-length policy and wire diagnostics. The
//! cursor only owns bounded slicing, fixed-width integers, and exact ending.

use crate::ZfsWorkerError;

/// Preserves each repair protocol's existing malformed-field diagnostics.
pub(crate) struct DecodeErrors {
    pub(crate) overflow: &'static str,
    pub(crate) truncated: &'static str,
    pub(crate) field: &'static str,
    pub(crate) trailing: &'static str,
}

/// Reads exact fields without advancing after a failed bound check.
pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    errors: &'static DecodeErrors,
}

impl<'a> Decoder<'a> {
    /// Starts at the first byte of one complete worker record.
    pub(crate) const fn new(bytes: &'a [u8], errors: &'static DecodeErrors) -> Self {
        Self {
            bytes,
            offset: 0,
            errors,
        }
    }

    /// Takes an exact bounded field.
    ///
    /// # Errors
    ///
    /// Returns the caller's overflow or truncation diagnostic.
    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], ZfsWorkerError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ZfsWorkerError::Protocol(self.errors.overflow))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ZfsWorkerError::Protocol(self.errors.truncated))?;
        self.offset = end;
        Ok(value)
    }

    /// Reads a fixed-width byte array.
    ///
    /// # Errors
    ///
    /// Returns a bound or fixed-field diagnostic.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ZfsWorkerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ZfsWorkerError::Protocol(self.errors.field))
    }

    /// Reads a single byte.
    ///
    /// # Errors
    ///
    /// Returns a bound or fixed-field diagnostic.
    pub(crate) fn u8(&mut self) -> Result<u8, ZfsWorkerError> {
        Ok(self.array::<1>()?[0])
    }

    /// Reads one network-order 16-bit integer.
    ///
    /// # Errors
    ///
    /// Returns a bound or fixed-field diagnostic.
    pub(crate) fn u16(&mut self) -> Result<u16, ZfsWorkerError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Reads one network-order 32-bit integer.
    ///
    /// # Errors
    ///
    /// Returns a bound or fixed-field diagnostic.
    pub(crate) fn u32(&mut self) -> Result<u32, ZfsWorkerError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Reads one network-order 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns a bound or fixed-field diagnostic.
    pub(crate) fn u64(&mut self) -> Result<u64, ZfsWorkerError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// Requires the caller to consume every byte of the record.
    ///
    /// # Errors
    ///
    /// Returns the caller's trailing-byte diagnostic.
    pub(crate) fn finish(self) -> Result<(), ZfsWorkerError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ZfsWorkerError::Protocol(self.errors.trailing))
        }
    }
}
