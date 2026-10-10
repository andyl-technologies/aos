//! Plugin continuation cursors and authored storage-history launch limits.

use super::{FaultResourceLimits, QemuLiveNodeStepGateConfig};

impl QemuLiveNodeStepGateConfig {
    /// Returns this configuration with its immutable process generation.
    #[must_use]
    pub const fn with_process_generation(mut self, process_generation: u64) -> Self {
        self.process_generation = process_generation;
        self
    }

    /// Returns this configuration with the restored plugin network TX cursor.
    #[must_use]
    pub const fn with_network_tx_next_sequence(mut self, next_sequence: u32) -> Self {
        self.network_tx_next_sequence = next_sequence;
        self
    }

    /// Returns this configuration with authored completed block-history limits.
    #[must_use]
    pub const fn with_storage_completed_history_limits(mut self, epochs: u64, gaps: u64) -> Self {
        self.storage_completed_history_epochs = epochs;
        self.storage_completed_history_gaps = gaps;
        self
    }

    /// Returns this configuration with the plan's complete authored limits.
    #[must_use]
    pub const fn with_fault_resource_limits(mut self, limits: FaultResourceLimits) -> Self {
        self.storage_completed_history_epochs = limits.storage_completed_history_epochs;
        self.storage_completed_history_gaps = limits.storage_completed_history_gaps;
        self
    }
}
