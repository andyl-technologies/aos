//! `crucible-sim` owns Crucible's deterministic core primitives.
//!
//! This L0 crate is the future home for seeded decision streams, ordered
//! collections, deterministic selection, virtual-time arithmetic, and the
//! content-addressing seam described by RFC-0010 files 04, 08, 09, and 27.
//! It intentionally has no QEMU, transport, scheduler-policy, or wall-clock
//! surface.

#![forbid(unsafe_code)]

/// A deterministic 256-bit digest produced by [`StableHasher`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct StableDigest {
    /// The digest bytes in canonical little-endian lane order.
    pub bytes: [u8; 32],
}

/// A small deterministic hasher for simulation-state fingerprints.
///
/// This hasher is deliberately not cryptographic. It exists to give test
/// doubles and deterministic model tests a stable, host-independent byte
/// accumulator before the production content-addressing implementation lands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableHasher {
    lanes: [u64; 4],
    bytes_written: u64,
}

impl Default for StableHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl StableHasher {
    /// Builds an empty stable hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lanes: [
                0x243f_6a88_85a3_08d3,
                0x1319_8a2e_0370_7344,
                0xa409_3822_299f_31d0,
                0x082e_fa98_ec4e_6c89,
            ],
            bytes_written: 0,
        }
    }

    /// Adds a domain-separation tag to the stream.
    pub fn write_tag(&mut self, tag: &str) {
        self.write_bytes(tag.as_bytes());
    }

    /// Adds one unsigned integer to the stream in little-endian order.
    pub fn write_u64(&mut self, value: u64) {
        self.mix_word(value);
        self.bytes_written = self.bytes_written.wrapping_add(8);
    }

    /// Adds one boolean value to the stream.
    pub fn write_bool(&mut self, value: bool) {
        self.write_u64(u64::from(value));
    }

    /// Adds a byte slice to the stream with its length.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u64(bytes.len() as u64);

        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let mut word = [0; 8];
            word.copy_from_slice(chunk);
            self.mix_word(u64::from_le_bytes(word));
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut word = [0; 8];
            for (index, byte) in remainder.iter().enumerate() {
                word[index] = *byte;
            }
            self.mix_word(u64::from_le_bytes(word));
        }

        self.bytes_written = self.bytes_written.wrapping_add(bytes.len() as u64);
    }

    /// Finishes the stream and returns its deterministic digest.
    #[must_use]
    pub fn finish(&self) -> StableDigest {
        let mut lanes = self.lanes;
        for (index, lane) in lanes.iter_mut().enumerate() {
            let salt = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            *lane = finalize_word(lane.wrapping_add(self.bytes_written).wrapping_add(salt));
        }

        let mut bytes = [0; 32];
        for (index, lane) in lanes.iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&lane.to_le_bytes());
        }
        StableDigest { bytes }
    }

    fn mix_word(&mut self, word: u64) {
        for (index, lane) in self.lanes.iter_mut().enumerate() {
            let rotation = 13 + (index as u32 * 7);
            let salt = (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
            *lane ^= word.wrapping_add(salt);
            *lane = lane
                .rotate_left(rotation)
                .wrapping_mul(0x9e37_79b1_85eb_ca87);
            *lane ^= *lane >> 33;
        }
    }
}

fn finalize_word(mut word: u64) -> u64 {
    word ^= word >> 30;
    word = word.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    word ^= word >> 27;
    word = word.wrapping_mul(0x94d0_49bb_1331_11eb);
    word ^ (word >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_hasher_is_repeatable() {
        let mut first = StableHasher::new();
        first.write_tag("node");
        first.write_u64(42);

        let mut second = StableHasher::new();
        second.write_tag("node");
        second.write_u64(42);

        assert_eq!(first.finish(), second.finish());
    }

    #[test]
    fn stable_hasher_is_order_sensitive() {
        let mut first = StableHasher::new();
        first.write_u64(1);
        first.write_u64(2);

        let mut second = StableHasher::new();
        second.write_u64(2);
        second.write_u64(1);

        assert_ne!(first.finish(), second.finish());
    }
}
