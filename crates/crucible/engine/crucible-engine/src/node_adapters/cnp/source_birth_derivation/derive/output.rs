//! Shares the original no-growth canonical bank writer with ordinary construction.

use std::io::Write;

pub(crate) struct ReservedWriter<'a> {
    pub(crate) bank: &'a mut Vec<u8>,
    pub(crate) maximum: usize,
}

impl Write for ReservedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
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
