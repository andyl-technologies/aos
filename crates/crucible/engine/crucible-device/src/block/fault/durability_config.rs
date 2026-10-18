//! Immutable block geometry and durability-bound validation.

use super::*;

impl BlockDurabilityConfig {
    /// Builds the fault-free write-through contract for a device.
    #[must_use]
    pub fn write_through(length_bytes: u64) -> Self {
        Self {
            length_bytes,
            atomic_write_bytes: 1,
            maximum_request_bytes: length_bytes.max(1),
            discard_granularity_bytes: 0,
            discard_semantics: BlockDiscardSemantics::DeterministicZero,
            volatile_cache_bytes: 0,
            cache_entries: 0,
            controller_buffer_bytes: 0,
            controller_entries: 0,
            persistence_dependencies: crate::block::persistence::HARD_BLOCK_PERSISTENCE_EDGES
                as u32,
            retained_versions: 1,
            completion_durability: BlockCompletionDurability::Durable,
        }
    }

    /// Validates geometry and hard resource bounds.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when a bound is zero,
    /// inconsistent with device length, or exceeds a compiled hard ceiling.
    pub fn validate(&self) -> Result<(), DeviceError> {
        let cache_entries = usize::try_from(self.cache_entries).unwrap_or(usize::MAX);
        let controller_entries = usize::try_from(self.controller_entries).unwrap_or(usize::MAX);
        let retained_versions = usize::try_from(self.retained_versions).unwrap_or(usize::MAX);
        let persistence_dependencies =
            usize::try_from(self.persistence_dependencies).unwrap_or(usize::MAX);
        if self.atomic_write_bytes == 0
            || self.maximum_request_bytes == 0
            || (self.length_bytes > 0 && self.maximum_request_bytes > self.length_bytes)
            || (self.discard_granularity_bytes != 0
                && !self.discard_granularity_bytes.is_power_of_two())
            || cache_entries > HARD_BLOCK_CACHE_ENTRIES
            || controller_entries > HARD_BLOCK_CONTROLLER_ENTRIES
            || persistence_dependencies > crate::block::persistence::HARD_BLOCK_PERSISTENCE_EDGES
            || persistence_dependencies == 0
            || self.volatile_cache_bytes > HARD_BLOCK_VOLATILE_LAYER_BYTES
            || self.controller_buffer_bytes > HARD_BLOCK_VOLATILE_LAYER_BYTES
            || retained_versions == 0
            || retained_versions > HARD_BLOCK_RETAINED_VERSIONS
            || (self.volatile_cache_bytes == 0) != (self.cache_entries == 0)
            || (self.controller_buffer_bytes == 0) != (self.controller_entries == 0)
            || (self.completion_durability == BlockCompletionDurability::VolatileCacheAccepted
                && self.volatile_cache_bytes == 0)
            || (self.completion_durability == BlockCompletionDurability::ControllerAccepted
                && self.controller_buffer_bytes == 0)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "invalid block durability configuration",
            });
        }
        Ok(())
    }
}
