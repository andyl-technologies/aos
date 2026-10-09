//! Bounded serialization precedes retained-input admission.

use crate::RuntimeError;
use serde::Serialize;
use std::io::{self, Write};

pub(crate) fn encode<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        maximum,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.exceeded {
            return Err(RuntimeError::Overloaded("encoded input bytes"));
        }
        return Err(RuntimeError::Json(error));
    }
    Ok(writer.bytes)
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let required = self.bytes.len().checked_add(bytes.len());
        let Some(required) = required.filter(|required| *required <= self.maximum) else {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "encoded input exceeds admission bound",
            ));
        };
        if required > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .max(1024)
                .saturating_mul(2)
                .min(self.maximum)
                .max(required);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn large_documents_fail_without_growing_past_the_bound() {
        let input = "x".repeat(4096);
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            maximum: 64,
            exceeded: false,
        };
        assert!(serde_json::to_writer(&mut writer, &input).is_err());
        assert!(writer.exceeded);
        assert!(writer.bytes.capacity() <= 64);
    }
}
