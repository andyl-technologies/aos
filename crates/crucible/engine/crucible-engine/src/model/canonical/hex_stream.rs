//! Carries one canonical hexadecimal field across arbitrary writer boundaries.
//!
//! The material length is mixed once before its lowercase hexadecimal bytes.
//! A partial word survives serializer writes and is padded only at completion.

use std::io;

use super::{ContentHash, MaterialHasher};

pub(super) struct HexWord {
    bytes: [u8; 8],
    length: usize,
}

impl HexWord {
    pub(super) const fn new() -> Self {
        Self {
            bytes: [0; 8],
            length: 0,
        }
    }

    pub(super) fn write(&mut self, hasher: &mut MaterialHasher, bytes: &[u8]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        for byte in bytes {
            for nibble in [byte >> 4, byte & 0x0f] {
                self.bytes[self.length] = HEX[usize::from(nibble)];
                self.length += 1;
                if self.length == self.bytes.len() {
                    hasher.mix_word(u64::from_le_bytes(self.bytes));
                    self.bytes = [0; 8];
                    self.length = 0;
                }
            }
        }
    }

    pub(super) fn finish(self, hasher: &mut MaterialHasher) {
        if self.length != 0 {
            hasher.mix_word(u64::from_le_bytes(self.bytes));
        }
    }
}

/// Streams one exactly sized hexadecimal material field without a buffer.
pub(crate) struct HexMaterialWriter {
    hasher: MaterialHasher,
    word: HexWord,
    expected: usize,
    written: usize,
}

impl HexMaterialWriter {
    pub(crate) fn new(domain: &str, expected: usize) -> Option<Self> {
        let material_bytes = u64::try_from(expected).ok()?.checked_mul(2)?;
        let mut hasher = MaterialHasher::new();
        hasher.write_bytes(b"crucible.content-hash.v1");
        hasher.write_bytes(domain.as_bytes());
        hasher.write_u64(material_bytes);
        Some(Self {
            hasher,
            word: HexWord::new(),
            expected,
            written: 0,
        })
    }

    pub(crate) fn finish(mut self) -> Option<ContentHash> {
        if self.written != self.expected {
            return None;
        }
        self.word.finish(&mut self.hasher);
        self.hasher.bytes_written = self
            .hasher
            .bytes_written
            .checked_add(u64::try_from(self.written).ok()?.checked_mul(2)?)?;
        Some(ContentHash {
            bytes: self.hasher.finish(),
        })
    }
}

impl io::Write for HexMaterialWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self
            .written
            .checked_add(bytes.len())
            .filter(|written| *written <= self.expected)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.word.write(&mut self.hasher, bytes);
        self.written = written;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn arbitrary_boundaries_preserve_one_material_field() {
        let all_bytes = (0_u8..=255).collect::<Vec<_>>();
        for length in [0, 1, 2, 3, 4, 7, 8, 9, 31, 32, 255, 256] {
            let bytes = &all_bytes[..length];
            let expected = ContentHash::from_canonical_hex_bytes("hex-boundaries", bytes);
            for first in 0..=bytes.len() {
                let mut writer = HexMaterialWriter::new("hex-boundaries", bytes.len()).unwrap();
                writer.write_all(&bytes[..first]).unwrap();
                writer.write_all(&[]).unwrap();
                writer.write_all(&bytes[first..]).unwrap();
                assert_eq!(writer.finish(), Some(expected));
            }
            for chunk in 1..=17 {
                let mut writer = HexMaterialWriter::new("hex-boundaries", bytes.len()).unwrap();
                for bytes in bytes.chunks(chunk) {
                    writer.write_all(bytes).unwrap();
                }
                assert_eq!(writer.finish(), Some(expected));
            }
        }
    }

    #[test]
    fn wrong_lengths_fail_before_extra_material_is_hashed() {
        let mut short = HexMaterialWriter::new("length", 2).unwrap();
        short.write_all(&[0]).unwrap();
        assert!(short.finish().is_none());

        let mut exact = HexMaterialWriter::new("length", 1).unwrap();
        exact.write_all(&[0]).unwrap();
        let error = exact.write_all(&[1]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            exact.finish(),
            Some(ContentHash::from_canonical_hex_bytes("length", &[0]))
        );
    }
}
