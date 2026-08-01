//! Local stable byte accumulator for execution fingerprints.
//!
//! This is deliberately not cryptographic. It provides deterministic,
//! host-independent digest bytes for the harness while keeping `crucible-harness`
//! free of production dependencies.

use super::definition::FingerprintDigest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FingerprintHasher {
    lanes: [u64; 4],
    bytes_written: u64,
}

impl FingerprintHasher {
    pub(super) fn new() -> Self {
        Self {
            lanes: [
                0x6a09_e667_f3bc_c908,
                0xbb67_ae85_84ca_a73b,
                0x3c6e_f372_fe94_f82b,
                0xa54f_f53a_5f1d_36f1,
            ],
            bytes_written: 0,
        }
    }

    pub(super) fn write_tag(&mut self, tag: &str) {
        self.write_bytes(tag.as_bytes());
    }

    pub(super) fn write_bool(&mut self, value: bool) {
        self.write_u64(u64::from(value));
    }

    pub(super) fn write_u64(&mut self, value: u64) {
        self.mix_word(value);
        self.bytes_written = self.bytes_written.wrapping_add(8);
    }

    pub(super) fn write_bytes(&mut self, bytes: &[u8]) {
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

    pub(super) fn finish(&self) -> FingerprintDigest {
        let mut lanes = self.lanes;
        for (index, lane) in lanes.iter_mut().enumerate() {
            let salt = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            *lane = finalize_word(lane.wrapping_add(self.bytes_written).wrapping_add(salt));
        }

        let mut bytes = Vec::with_capacity(32);
        for lane in lanes {
            bytes.extend_from_slice(&lane.to_le_bytes());
        }
        bytes
    }

    fn mix_word(&mut self, word: u64) {
        for (index, lane) in self.lanes.iter_mut().enumerate() {
            let rotation = 17 + (index as u32 * 5);
            let salt = (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
            *lane ^= word.wrapping_add(salt);
            *lane = lane
                .rotate_left(rotation)
                .wrapping_mul(0x9e37_79b1_85eb_ca87);
            *lane ^= *lane >> 31;
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
