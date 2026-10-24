//! Quotes one complete current inspection from genuine cached startup geometry.

use super::*;

impl PacketCompleteSemanticSource {
    pub(crate) fn original_current_observation_construction_data(
        &self,
        controller: &CnpController,
        read_owner: *const (),
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        ordinal: u64,
        first: &OriginalSourceRestorationObservationConstructionData,
        maximum: usize,
    ) -> Result<OriginalRestoredSchedulingObservationConstructionData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        first.authenticate_original(self, controller)?;
        let startup = self.original_restored_suffix_observation_startup_data()?;
        if ordinal == 0 || ordinal > startup.reservation_data().maximum_originals.get() {
            return Err(RuntimeError::ResourceLimit);
        }
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let history = original
            .current_observations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.authenticate_origin_data()?;
        if history.failed
            || history
                .attempts
                .last()
                .is_some_and(|attempt| attempt.stage != Stage::Verified)
            || u64::try_from(history.attempts.len())
                .map_err(|_| RuntimeError::ResourceLimit)?
                .checked_add(1)
                != Some(ordinal)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let body = controller
            .original_restored_suffix_observation_body_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let provider = original_native_restored_suffix_observation_storage_data(
            &startup,
            launch,
            canonical_launch5,
            body,
            maximum,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let body_facts = RetainedRestorationObservationData::Body(body)
            .original_retained_metadata_facts()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let body_backing =
            Self::complete_retained_metadata_storage_precredit_data(&body_facts, maximum)?;
        let native = provider.native_allocation_data();
        let native_retained = usize::try_from(native.retained_requested_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let native_transient = usize::try_from(native.maximum_simultaneous_transient_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let native_scratch = usize::try_from(native.declared_counter_scratch_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let scheduling = first.scheduling_observation_requested_bytes_data();
        let retained = sum([
            provider.host_retained_requested_bytes_data(),
            provider.source_evidence_retained_requested_bytes_data(),
            native_retained,
            size_of::<CurrentObservationAttempt>().checked_mul(2).ok_or(RuntimeError::ResourceLimit)?,
            body_backing,
            REQUEST_PREFIX.len().checked_add(20).ok_or(RuntimeError::ResourceLimit)?,
            scheduling.checked_mul(3).ok_or(RuntimeError::ResourceLimit)?,
            crate::node_adapters::cnp::CnpSemanticNode::original_current_observation_node_growth_data(),
            projection::future_reference_backing_data(maximum)?,
        ], maximum)?;
        let new_source_slots = history
            .attempts
            .len()
            .checked_add(1)
            .and_then(|slots| slots.checked_mul(size_of::<CurrentObservationAttempt>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let new_node_slots = crate::node_adapters::cnp::CnpSemanticNode::original_current_observation_node_reallocation_data(ordinal)?;
        let transient = sum(
            [
                // Reallocation can keep the entire old Vec live beside the full
                // requested new bank. Current census already counts the old bank.
                new_source_slots,
                new_node_slots,
                provider.host_maximum_simultaneous_transient_bytes_data(),
                provider.source_evidence_maximum_simultaneous_transient_bytes_data(),
                native_transient,
                // Initial World/Hold reauthentication is repeated independently.
                // Its old owners/future row stay charged beside these new walks.
                first
                    .requested_peak_bytes_data()
                    .checked_mul(2)
                    .ok_or(RuntimeError::ResourceLimit)?,
                scheduling,
                20, // Existing U64 serializer's separately live decimal String bank.
                REQUEST_PREFIX
                    .len()
                    .checked_add(20)
                    .ok_or(RuntimeError::ResourceLimit)?,
                crate::node_adapters::cnp::OriginalInitialLifecycleDiagnostics::requested_bytes(),
            ],
            maximum,
        )?;
        let scratch = sum(
            [
                Self::original_current_observation_counter_scratch_data(),
                provider.host_counter_scratch_bytes_data(),
                provider.source_evidence_counter_scratch_bytes_data(),
                native_scratch,
                first.counter_scratch_bytes_data(),
            ],
            maximum,
        )?;
        let requested = sum([retained, transient, scratch], maximum)?;
        Ok(OriginalRestoredSchedulingObservationConstructionData {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source: self,
            controller,
            read_owner,
            ordinal,
            startup,
            provider,
            first: *first,
            retained,
            transient,
            scratch,
            requested,
            runtime_retained: 0,
            runtime_transient: 0,
            runtime_scratch: 0,
            maximum,
        })
    }

    /// Names the complete independent row/call/parser/census fixed views.
    pub(crate) fn original_current_observation_counter_scratch_data() -> usize {
        use crucible_node_transport::ProviderError;
        use std::cell::{BorrowError, BorrowMutError, Ref, RefMut};
        // The reused U64 formatter owns one bounded decimal bank even in the
        // pre-admission DATA walk. It is independently precredited here.
        20 + size_of::<CurrentObservationHistory>()
            + size_of::<CurrentObservationAttempt>()
            + size_of::<Option<CurrentObservationAttempt>>()
            + size_of::<RefCell<CurrentObservationHistory>>()
            + size_of::<Ref<'static, CurrentObservationHistory>>()
            + size_of::<RefMut<'static, CurrentObservationHistory>>()
            + size_of::<Result<Ref<'static, CurrentObservationHistory>, BorrowError>>()
            + size_of::<Result<RefMut<'static, CurrentObservationHistory>, BorrowMutError>>()
            + size_of::<Result<Ref<'static, CurrentObservationHistory>, RuntimeError>>()
            + size_of::<Result<RefMut<'static, CurrentObservationHistory>, RuntimeError>>()
            + size_of::<AttemptGuard<'static>>()
            + size_of::<std::slice::Iter<'static, CurrentObservationAttempt>>()
            + size_of::<Option<&CurrentObservationAttempt>>()
            + size_of::<Option<&mut CurrentObservationAttempt>>()
            + size_of::<Result<&CurrentObservationAttempt, RuntimeError>>()
            + size_of::<Result<&mut CurrentObservationAttempt, RuntimeError>>()
            + size_of::<[usize; 9]>()
            + size_of::<std::array::IntoIter<usize, 9>>()
            + size_of::<[usize; 10]>()
            + size_of::<std::array::IntoIter<usize, 10>>()
            + size_of::<[usize; 5]>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<u64, RuntimeError>>()
            + size_of::<Option<u64>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<&crucible_node_transport::bodies::ObserveRequest, ProviderError>>()
            + size_of::<Option<&crucible_node_transport::bodies::ObserveRequest>>()
            + size_of::<Result<crucible_node_transport::reference_packet::service::native_startup::PacketNativeRestoredSuffixStartupStorageData, RuntimeError>>()
            + OriginalRestoredSchedulingObservationConstructionData::fixed_counter_scratch_data()
            + OriginalRestoredSuffixHostAttempt::counter_scratch_data()
            + original_native_restored_suffix_observation_counter_scratch_data()
            + Self::original_restoration_observation_source_construction_counter_scratch_data()
            + validation::counter_scratch_data()
            + effect::counter_scratch_data()
    }
}
