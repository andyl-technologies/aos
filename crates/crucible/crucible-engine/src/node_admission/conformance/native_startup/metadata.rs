//! Preserves native startup members and their nested shared/weak capacity views.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;

impl OriginalNativeStartupQuote {
    /// Keeps every fixed baseline quote field in its defining Copy roster.
    ///
    /// # Errors
    /// Refuses checked traversal-work overflow.
    pub(super) fn observe_inline_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            rows,
            finalization_bytes,
            source_capture_backend_bytes,
            source_capture_execution_bytes,
            source_capture_execution_scratch,
            wire_requested_bytes,
            publication_bytes,
            publication_rows,
            launch_digest,
            maximum_boot_bytes,
        } = self;
        census.observe_inline_data(rows)?;
        census.observe_inline_data(finalization_bytes)?;
        census.observe_inline_data(source_capture_backend_bytes)?;
        census.observe_inline_data(source_capture_execution_bytes)?;
        census.observe_inline_data(source_capture_execution_scratch)?;
        census.observe_inline_data(wire_requested_bytes)?;
        census.observe_inline_data(publication_bytes)?;
        census.observe_inline_data(publication_rows)?;
        census.observe_inline_data(launch_digest)?;
        census.observe_inline_data(maximum_boot_bytes)?;
        Ok(())
    }

    /// Names the fixed quote's field views and fallible observation controls.
    pub(super) fn inline_capacity_counter_scratch_data() -> usize {
        fn field_view_bytes<T>(_: impl FnOnce(&'static OriginalNativeStartupQuote) -> T) -> usize {
            size_of::<T>()
        }

        field_view_bytes(|quote| {
            let Self {
                rows,
                finalization_bytes,
                source_capture_backend_bytes,
                source_capture_execution_bytes,
                source_capture_execution_scratch,
                wire_requested_bytes,
                publication_bytes,
                publication_rows,
                launch_digest,
                maximum_boot_bytes,
            } = quote;
            (
                rows,
                finalization_bytes,
                source_capture_backend_bytes,
                source_capture_execution_bytes,
                source_capture_execution_scratch,
                wire_requested_bytes,
                publication_bytes,
                publication_rows,
                launch_digest,
                maximum_boot_bytes,
            )
        }) + size_of::<&Self>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'static>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

impl OriginalNativeStartupMember {
    /// Records every original weak view and the full retained shared barrier.
    ///
    /// # Errors
    /// Refuses exhausted rows, invalid layout, unready backing or unsupported
    /// nested SDK geometry. Capacity DATA creates no native or restored grant.
    pub(crate) fn record_retained_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            host_finalization,
            host_finalization_index,
            edition,
            process,
            thread,
            source,
            plan,
            rows,
            suffix,
            finalization_bytes,
            source_capture_backend_bytes,
            source_capture_execution_bytes,
            source_capture_execution_scratch,
            wire_requested_bytes,
            host_launch_requested_bytes,
            launch_digest,
            maximum_boot_bytes,
        } = self;
        census.observe_inline_data(host_finalization_index)?;
        census.observe_inline_data(edition)?;
        census.observe_inline_data(process)?;
        census.observe_inline_data(thread)?;
        census.observe_inline_data(rows)?;
        census.observe_inline_data(finalization_bytes)?;
        census.observe_inline_data(source_capture_backend_bytes)?;
        census.observe_inline_data(source_capture_execution_bytes)?;
        census.observe_inline_data(source_capture_execution_scratch)?;
        census.observe_inline_data(wire_requested_bytes)?;
        census.observe_inline_data(host_launch_requested_bytes)?;
        census.observe_inline_data(launch_digest)?;
        census.observe_inline_data(maximum_boot_bytes)?;

        plan.record_retained_capacity_data(census)?;
        census.observe_weak_allocation_data(source)?;
        host_finalization.record_retained_capacity_data(census)?;
        if let Some(suffix) = suffix {
            suffix.record_retained_capacity_data(census)?;
        }
        Ok(())
    }
}

impl OriginalNativeStartupMember {
    /// Names actual shared member/quote/barrier and restored nested loan controls.
    pub(crate) fn retained_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + size_of::<&Self>()
            + OriginalNativeStartupQuote::inline_capacity_counter_scratch_data()
            + size_of::<&WeakInstalledConformancePlan>()
            + size_of::<&Weak<PacketCompleteSemanticSource>>()
            + size_of::<&Rc<OriginalHostFinalizationBarrier>>()
            + size_of::<std::slice::Iter<'static, Weak<PacketCompleteSemanticSource>>>()
            + OriginalHostFinalizationBarrier::retained_capacity_counter_scratch_data()
            + OriginalRestoredSuffixStartupMember::retained_capacity_counter_scratch_data()
            + size_of::<Result<(), RuntimeError>>()
    }
}
