//! Shares the original no-growth canonical bank writer with ordinary construction.

use std::io::Write;

/// Writes into an existing byte bank without increasing its capacity.
///
/// The caller retains the original bank and separately admits its requested
/// storage. This adapter only checks the existing capacity and logical bound;
/// it grants no Source, native or allocation authority.
pub struct ReservedWriter<'a> {
    /// Borrows the original output bank, retaining partial bytes on failure.
    pub bank: &'a mut Vec<u8>,
    /// Bounds the complete written bank independently of its actual capacity.
    pub maximum: usize,
}

impl Write for ReservedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let _end = self
            .bank
            .len()
            .checked_add(bytes.len())
            .filter(|end| *end <= self.maximum && *end <= self.bank.capacity())
            .ok_or(std::io::ErrorKind::WriteZero)?;
        self.bank.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
