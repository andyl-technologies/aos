//! Retains a bounded canonical hash sink, including its partial refused state.
//!
//! This sink owns no output bank. The authoritative JCS writer supplies every
//! accepted byte directly to the same retained BLAKE3 state.

use std::io::{self, Write};

/// Owns the accepted prefix state and a sticky byte-ceiling refusal.
pub(super) struct HashSink {
    /// Retains the actual compressed prefix and incomplete chunk.
    pub(super) hasher: blake3::Hasher,
    /// Counts only bytes accepted by this same sink.
    pub(super) written: usize,
    maximum: usize,
    /// Prevents accepting further bytes after a refused write.
    pub(super) refused: bool,
}

impl HashSink {
    /// Initializes inline state without an output allocation.
    pub(super) fn empty_data() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            written: 0,
            maximum: 0,
            refused: false,
        }
    }

    /// Starts the next independently admitted role after prior observation.
    pub(super) fn begin_data(&mut self, maximum: usize) {
        self.hasher.reset();
        self.written = 0;
        self.maximum = maximum;
        self.refused = false;
    }
}

impl Write for HashSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self
            .written
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum)
        else {
            self.refused = true;
            return Err(io::ErrorKind::WriteZero.into());
        };
        if self.refused {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.hasher.update(bytes);
        self.written = next;
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
    fn exact_limit_hashes_bytes_and_short_limit_keeps_the_actual_prefix() {
        let mut sink = HashSink::empty_data();
        sink.begin_data(6);
        sink.write_all(b"abc").unwrap();
        sink.write_all(b"def").unwrap();
        assert_eq!(sink.written, 6);
        assert_eq!(sink.hasher.finalize(), blake3::hash(b"abcdef"));
        assert!(!sink.refused);

        assert!(sink.write_all(b"g").is_err());
        assert!(sink.refused);
        assert_eq!(sink.written, 6);
        assert_eq!(sink.hasher.finalize(), blake3::hash(b"abcdef"));
        assert!(sink.write(b"g").is_err());

        sink.begin_data(5);
        sink.write_all(b"abc").unwrap();
        assert!(sink.write_all(b"def").is_err());
        assert_eq!(sink.written, 3);
        assert_eq!(sink.hasher.finalize(), blake3::hash(b"abc"));
    }
}
