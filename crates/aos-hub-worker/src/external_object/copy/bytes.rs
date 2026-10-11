//! Exact bounded source hashing; continuation is private executor state.
//!
//! No type in this module is deserializable from public control messages. The
//! physical guard separately authenticates the original continuation and turn.

use anyhow::{ensure, Result};
use aos_hub_core::{db::OciSha256State, direct_upload::MAX_DIRECT_PART_BYTES};
use md5::Digest as _;
use sha2::{Digest as _, Sha256};

pub(super) const CHUNK_BYTES: usize = 64 * 1024;

/// Owns a bounded range hash beside the full-source portable continuation.
pub(super) struct RangeDigest {
    bytes: u64,
    counted: u64,
    part: Sha256,
    md5: md5::Md5,
    source: OciSha256State,
}

/// Describes bytes actually consumed to clean EOF; grants no provider authority.
pub(super) struct RangeBytes {
    pub(super) sha256: String,
    pub(super) md5: String,
    pub(super) source_state: OciSha256State,
}

impl RangeDigest {
    /// Starts at the exact privately authenticated whole-source continuation.
    ///
    /// # Errors
    /// Refuses a corrupt continuation, wrong offset or excessive/overflowing range.
    pub(super) fn new(offset: u64, bytes: u64, source: OciSha256State) -> Result<Self> {
        source.validate()?;
        ensure!(
            bytes > 0 && bytes <= MAX_DIRECT_PART_BYTES && source.total_bytes == offset,
            "copy source continuation or range differs"
        );
        offset
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("copy source range overflow"))?;
        Ok(Self {
            bytes,
            counted: 0,
            part: Sha256::new(),
            md5: md5::Md5::new(),
            source,
        })
    }

    /// Adds one actual bounded source view without collecting a part body.
    ///
    /// # Errors
    /// Refuses empty/oversized chunks, overrun or corrupt source state.
    pub(super) fn update(&mut self, chunk: &[u8]) -> Result<()> {
        let next = self
            .counted
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("copy source length overflow"))?;
        ensure!(
            !chunk.is_empty() && chunk.len() <= CHUNK_BYTES && next <= self.bytes,
            "copy source chunk exceeds exact range"
        );
        self.source.update(chunk)?;
        self.part.update(chunk);
        self.md5.update(chunk);
        self.counted = next;
        Ok(())
    }

    /// Is called only after the native reader reports clean source EOF.
    ///
    /// # Errors
    /// Refuses a source shorter than its exact selected range.
    pub(super) fn finish(self) -> Result<RangeBytes> {
        ensure!(self.counted == self.bytes, "copy source truncated");
        Ok(RangeBytes {
            sha256: hex::encode(self.part.finalize()),
            md5: hex::encode(self.md5.finalize()),
            source_state: self.source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_chunks_extend_exact_source_and_part_hashes() {
        let mut prior = OciSha256State::initial();
        prior.update(b"prior bytes").unwrap();
        let mut range = RangeDigest::new(prior.total_bytes, 7, prior.clone()).unwrap();
        range.update(b"con").unwrap();
        range.update(b"tent").unwrap();
        let result = range.finish().unwrap();
        prior.update(b"content").unwrap();
        assert_eq!(result.source_state, prior);
        assert_eq!(result.sha256, hex::encode(Sha256::digest(b"content")));
    }

    #[test]
    fn overrun_truncation_changed_continuation_and_large_chunks_refuse() {
        let initial = OciSha256State::initial();
        assert!(RangeDigest::new(1, 7, initial.clone()).is_err());
        assert!(RangeDigest::new(0, 0, initial.clone()).is_err());
        assert!(RangeDigest::new(0, MAX_DIRECT_PART_BYTES + 1, initial.clone()).is_err());
        let mut range = RangeDigest::new(0, 7, initial.clone()).unwrap();
        assert!(range.update(b"too long").is_err());
        range.update(b"short").unwrap();
        assert!(range.finish().is_err());

        let mut range = RangeDigest::new(0, MAX_DIRECT_PART_BYTES, initial).unwrap();
        assert!(range.update(&vec![1; CHUNK_BYTES + 1]).is_err());
    }
}
