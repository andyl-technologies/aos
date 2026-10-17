//! Read-only checkpoint consumer evidence for admitted lifecycle fixtures.

use crucible::ContentHash;

/// Reports the actual committed and pending checkpoint consumer coordinates.
///
/// Each identity contains the checkpoint, target and frontier content hashes,
/// in that order. This copied evidence cannot publish, acknowledge or construct
/// a checkpoint, and does not grant node or resource authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointConsumerEpochEvidence {
    pub(super) epoch_generation: u64,
    pub(super) committed: Option<[ContentHash; 3]>,
    pub(super) candidate: Option<[ContentHash; 3]>,
    pub(super) committed_capture_generation: Option<u64>,
    pub(super) candidate_capture_generation: Option<u64>,
}

impl CheckpointConsumerEpochEvidence {
    /// Returns the committed epoch generation.
    #[must_use]
    pub const fn epoch_generation(self) -> u64 {
        self.epoch_generation
    }

    /// Returns the committed checkpoint, target and frontier hashes.
    #[must_use]
    pub const fn committed(self) -> Option<[ContentHash; 3]> {
        self.committed
    }

    /// Returns the pending checkpoint, target and frontier hashes.
    #[must_use]
    pub const fn candidate(self) -> Option<[ContentHash; 3]> {
        self.candidate
    }

    /// Returns the acknowledged operational capture generation.
    #[must_use]
    pub const fn committed_capture_generation(self) -> Option<u64> {
        self.committed_capture_generation
    }

    /// Returns the pending operational capture generation.
    #[must_use]
    pub const fn candidate_capture_generation(self) -> Option<u64> {
        self.candidate_capture_generation
    }
}
