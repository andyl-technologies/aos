//! Retained-source coordinates for the hot-checkpoint pool.
//!
//! Current world hot-fork pools use this key to bind a retained source to its
//! campaign lineage and paused configuration.

use crucible::ContentHash;
use crucible_campaign::CampaignLineageId;

/// Exact semantic basis of one retained source world.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HotCheckpointPoolKey {
    lineage: CampaignLineageId,
    configuration: ContentHash,
}

impl HotCheckpointPoolKey {
    /// Binds one lineage to one exact paused configuration.
    #[must_use]
    pub const fn new(lineage: CampaignLineageId, configuration: ContentHash) -> Self {
        Self {
            lineage,
            configuration,
        }
    }

    /// Returns the exact campaign lineage.
    #[must_use]
    pub const fn lineage(self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the exact paused source configuration.
    #[must_use]
    pub const fn configuration(self) -> ContentHash {
        self.configuration
    }
}

/// Maximum retained source worlds admitted by one in-process hot-checkpoint pool.
pub const MAX_HOT_CHECKPOINT_POOL_SLOTS: usize = crate::MAX_LOCAL_EXECUTOR_WORKERS;

/// Stable coordinate of one retained source world within the pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HotCheckpointPoolSlot {
    key: HotCheckpointPoolKey,
    slot: usize,
}

impl HotCheckpointPoolSlot {
    /// Returns the exact lineage/configuration key of the source world.
    #[must_use]
    pub const fn template_key(self) -> HotCheckpointPoolKey {
        self.key
    }

    /// Returns the stable per-key slot index.
    #[must_use]
    pub const fn slot_index(self) -> usize {
        self.slot
    }

    pub(crate) const fn new(key: HotCheckpointPoolKey, slot: usize) -> Self {
        Self { key, slot }
    }
}
