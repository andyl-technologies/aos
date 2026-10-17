//! Allocation-free canonical identity text and streamed content hashing.

use super::{ContentId, ObjectKind, content_hasher};

impl ContentId {
    /// Borrows the canonical ASCII identity spelling from fixed stack storage.
    ///
    /// The callback receives the same bytes as [`Self::encode`] without a heap
    /// allocation or ambient decoder charge. The spelling remains valid only
    /// during the callback; no storage identity or admission is changed.
    pub fn with_encoded_text<T>(self, consume: impl FnOnce(&[u8]) -> T) -> T {
        // The longest closed kind tag is 17 bytes. Two separators, ten decimal
        // version digits and 64 digest digits need at most 93 bytes.
        let mut encoded = [0_u8; 96];
        let kind = self.kind.as_str().as_bytes();
        encoded[..kind.len()].copy_from_slice(kind);
        let mut cursor = kind.len();
        encoded[cursor] = b'.';
        cursor += 1;

        let mut decimal = [0_u8; 10];
        let mut first = decimal.len();
        let mut version = self.schema_version;
        loop {
            first -= 1;
            decimal[first] = b'0' + (version % 10) as u8;
            version /= 10;
            if version == 0 {
                break;
            }
        }
        let digits = &decimal[first..];
        encoded[cursor..cursor + digits.len()].copy_from_slice(digits);
        cursor += digits.len();
        encoded[cursor] = b'.';
        cursor += 1;

        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.digest {
            encoded[cursor] = HEX[(byte >> 4) as usize];
            encoded[cursor + 1] = HEX[(byte & 0x0f) as usize];
            cursor += 2;
        }
        consume(&encoded[..cursor])
    }

    /// Hashes an internal canonical writer with the ordinary identity domain.
    pub(crate) fn for_canonical_chunks(
        kind: ObjectKind,
        schema_version: u32,
        logical_length: u64,
        write: impl FnOnce(&mut dyn FnMut(&[u8])),
    ) -> Self {
        let mut hasher = content_hasher(kind, schema_version, logical_length);
        write(&mut |bytes| {
            hasher.update(bytes);
        });
        Self {
            kind,
            schema_version,
            digest: *hasher.finalize().as_bytes(),
        }
    }
}
