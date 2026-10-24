//! Conservative common Native receiving terms for a genuinely captured prefix.
//!
//! This reconciles the shared parser's physical-clipped replay work with its
//! independent BEGIN reservation and reached frame allocation. The result is
//! DATA, never a grant, a decoder permit, or a receiving-owner constructor.
//! Role consumers retain their actual opener and independently price semantic
//! models, paths, controls, transport, errors and the original physical limits.

#[cfg(test)]
use aos_sandbox_model::ResourceDimension as D;

#[cfg(test)]
use super::ProtectedJournalPreopenReplayExtentV1;



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
