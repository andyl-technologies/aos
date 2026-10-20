//! Conservative common Native receiving terms for a genuinely captured prefix.
//!
//! This reconciles the shared parser's physical-clipped replay work with its
//! independent BEGIN reservation and reached frame allocation. The result is
//! DATA, never a grant, a decoder permit, or a receiving-owner constructor.
//! Role consumers retain their actual opener and independently price semantic
//! models, paths, controls, transport, errors and the original physical limits.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::{JournalError, ProtectedJournalPreopenReplayExtentV1};

impl ProtectedJournalPreopenReplayExtentV1 {
    /// Prices the common Native replay representations without clipping EOF work.
    ///
    /// Release work contains physical-clipped pending records but already
    /// includes the shared incremental reader's reached Vec capacity and fixed
    /// scratch. BEGIN can reserve its complete declared count before EOF, so
    /// only that pending term is replaced with its independent full maximum.
    /// Absent advertised payload bytes receive no allocation or semantic charge.
    /// Reached map/checkpoint owners remain separately priced.
    ///
    /// Only an extent borrowed from the actual staged original can be joined
    /// to a payer. Writable DATA fields and this calculation create no authority.
    /// Semantic decoded models and collections need their own conservative
    /// shape allowance. Strict parsers and the genuine service cgroup back
    /// residual allocator metadata and kernel/page-cache overhead (RFC-0006).
    ///
    /// # Errors
    /// Refuses inconsistent clipped terms, checked overflow, or an extent whose
    /// complete logical receiving terms cannot be represented by the vector.
    pub fn dominant_native_receiving_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("native receiving replay demand");
        let physical = usize::try_from(self.native_bytes).map_err(|_| invalid())?;
        let advertised = self.limits.maximum_record_bytes.checked_add(7).ok_or_else(invalid)?;
        let frame = aos_sandbox_journal::framing::reached_frame_read_memory_bound_v1(
            advertised, physical,
        ).map_err(|_| invalid())?;
        if self.clipped_native_pending_record_bytes > self.declared_pending_record_bytes
            || self.maximum_advertised_payload_bytes != advertised
            || self.native_frame_read_memory_bytes != frame
            || self.native_replay_representation_bytes < frame
        {
            return Err(invalid());
        }
        let memory = self.native_replay_representation_bytes
            .checked_sub(self.clipped_native_pending_record_bytes)
            .and_then(|bytes| bytes.checked_add(self.declared_pending_record_bytes))
            .and_then(|bytes| bytes.checked_add(self.reached_transaction_id_bytes))
            .and_then(|bytes| bytes.checked_add(self.reached_materialized_cell_bytes))
            .and_then(|bytes| bytes.checked_add(self.source_checkpoint_representation_bytes))
            .and_then(|bytes| bytes.checked_add(self.source_cache_metadata_bytes))
            .and_then(|bytes| bytes.checked_add(self.native_owner_result_bytes))
            .ok_or_else(invalid)?;
        let memory = u64::try_from(memory).map_err(|_| invalid())?;
        let metadata = self.source_checkpoint_rows.checked_mul(2)
            .and_then(|count| count.checked_add(self.source_transactions))
            .and_then(|count| count.checked_add(self.limits.maximum_records_per_transaction))
            .and_then(|count| count.checked_add(1)).ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::MetadataEntries, u64::try_from(metadata).map_err(|_| invalid())?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JournalLimits;
    use crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1;

    fn extent(prefix: u64) -> ProtectedJournalPreopenReplayExtentV1 {
        protected_journal_preopen_replay_extent_for_prefix_v1(JournalLimits::default(), prefix)
            .unwrap()
    }

    #[test]
    fn empty_prefix_prices_fixed_read_scratch_and_full_begin_without_absent_payload() {
        let extent = extent(0);
        let demand = extent.dominant_native_receiving_demand_v1().unwrap();

        assert_eq!(extent.clipped_native_pending_record_bytes, 0);
        assert_eq!(extent.native_frame_read_memory_bytes,
            aos_sandbox_journal::framing::FRAME_READ_SCRATCH_BYTES);
        assert!(demand.get(D::MemoryBytes) >= (extent.declared_pending_record_bytes
            + aos_sandbox_journal::framing::FRAME_READ_SCRATCH_BYTES) as u64);
        assert_eq!(demand.get(D::MetadataEntries),
            (extent.limits.maximum_records_per_transaction + 1) as u64);
    }

    #[test]
    fn different_advertised_wire_caps_do_not_allocate_missing_zero_prefix_bytes() {
        let small = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
            JournalLimits { maximum_record_bytes: 1024, ..JournalLimits::default() }, 0,
        ).unwrap();
        let large = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
            JournalLimits::default(), 0,
        ).unwrap();

        assert_ne!(small.maximum_advertised_payload_bytes, large.maximum_advertised_payload_bytes);
        assert_eq!(small.dominant_native_receiving_demand_v1().unwrap(),
            large.dominant_native_receiving_demand_v1().unwrap());
    }

    #[test]
    fn full_begin_replaces_only_the_physical_pending_term_once() {
        let mut extent = extent(1024);
        let before = extent.dominant_native_receiving_demand_v1().unwrap();
        let delta = extent.declared_pending_record_bytes - extent.clipped_native_pending_record_bytes;
        extent.native_replay_representation_bytes += delta;
        extent.clipped_native_pending_record_bytes = extent.declared_pending_record_bytes;

        assert_eq!(before, extent.dominant_native_receiving_demand_v1().unwrap());
    }

    #[test]
    fn direct_release_work_and_receiving_use_the_same_reached_frame_bound() {
        let limits = JournalLimits::default();
        for physical in [0, 1, 1024, 128 * 1024] {
            let work = crate::journal::original_release_capture::native_release_replay_work_v1(physical, limits).unwrap();
            let extent = extent(physical as u64);
            assert_eq!(work.frame_payload, extent.native_frame_read_memory_bytes);
            assert_eq!(work.frame_payload,
                aos_sandbox_journal::framing::reached_frame_read_memory_bound_v1(
                    limits.maximum_record_bytes + 7, physical,
                ).unwrap());
        }
    }

    #[test]
    fn inconsistent_or_overflowing_data_does_not_become_a_demand() {
        let mut extent = extent(0);
        extent.native_frame_read_memory_bytes += 1;
        assert!(extent.dominant_native_receiving_demand_v1().is_err());

        let mut extent = self::extent(0);
        extent.native_owner_result_bytes = usize::MAX;
        assert!(extent.dominant_native_receiving_demand_v1().is_err());
    }
}
