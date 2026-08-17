//! Opportunistic debugger checkpoint stride and cadence policy.

use super::*;

/// Non-zero opportunistic checkpoint stride for debug time travel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DebugCheckpointStride {
    pub(in crate::model) every: NonZeroUsize,
}

impl DebugCheckpointStride {
    /// Builds a non-zero checkpoint stride.
    #[must_use]
    pub fn new(every: usize) -> Option<Self> {
        NonZeroUsize::new(every).map(|every| Self { every })
    }

    /// Returns the stride interval.
    #[must_use]
    pub const fn every(self) -> usize {
        self.every.get()
    }

    pub(in crate::model) fn includes_prefix(self, prefix_len: usize) -> bool {
        prefix_len > 0 && prefix_len.is_multiple_of(self.every())
    }
}

/// Request to apply an opportunistic checkpoint cadence.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugCheckpointCadenceRequest {
    /// Configuration whose prefix region should receive cadence checkpoints.
    pub current: Configuration,
    /// Non-zero checkpoint stride.
    pub stride: DebugCheckpointStride,
    /// Savevm hedge that decides whether cadence points may be fat.
    pub hedge: SavevmCompletenessHedge,
}

impl DebugCheckpointCadenceRequest {
    /// Builds a checkpoint-cadence request with an explicit savevm hedge.
    #[must_use]
    pub fn with_hedge(
        current: Configuration,
        stride: DebugCheckpointStride,
        hedge: SavevmCompletenessHedge,
    ) -> Self {
        Self {
            current,
            stride,
            hedge,
        }
    }

    /// Builds the default S3-conservative cadence request.
    #[must_use]
    pub fn thin_replay_until_full_s3(
        current: Configuration,
        stride: DebugCheckpointStride,
    ) -> Self {
        Self::with_hedge(
            current,
            stride,
            SavevmCompletenessHedge::thin_replay_until_full_s3(),
        )
    }
}

/// Report for opportunistic checkpoint cadence application.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugCheckpointCadenceReport {
    /// Configuration whose prefix region was considered.
    pub current_configuration: ContentHash,
    /// Non-zero stride that selected candidate prefixes.
    pub stride: DebugCheckpointStride,
    /// Savevm hedge used for every candidate prefix.
    pub hedge: SavevmCompletenessHedge,
    /// Candidate prefix configuration ids selected by the stride.
    pub candidate_configurations: Vec<ContentHash>,
    /// Candidate ids cached as fat checkpoints.
    pub fat_checkpoints: Vec<ContentHash>,
    /// Candidate ids kept as thin replay checkpoints.
    pub thin_checkpoints: Vec<ContentHash>,
    /// Fat cache count before applying the cadence.
    pub cached_snapshots_before: usize,
    /// Fat cache count after applying the cadence.
    pub cached_snapshots_after: usize,
}

impl DebugCheckpointCadenceReport {
    /// Returns whether the S3-conservative default kept all cadence points thin.
    #[must_use]
    pub fn defaults_to_thin_replay_until_full_s3(&self) -> bool {
        !self.hedge.fat_snapshot_default()
            && self.fat_checkpoints.is_empty()
            && self.thin_checkpoints.len() == self.candidate_configurations.len()
    }

    /// Returns whether checkpoint cadence only changed cache materialization.
    #[must_use]
    pub fn is_performance_only_cache_decision(&self) -> bool {
        let classified = self
            .fat_checkpoints
            .iter()
            .chain(self.thin_checkpoints.iter())
            .copied()
            .collect::<BTreeSet<_>>();
        let candidates = self
            .candidate_configurations
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        classified == candidates
    }
}
