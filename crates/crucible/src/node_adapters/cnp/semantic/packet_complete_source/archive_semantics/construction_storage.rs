//! Records the existing archive predicates' actual admitted construction phases.
//!
//! The original archive callback retains these fixed DATA before releasing its
//! typed historical owners. The selected final validator replays the same real
//! predicates under those per-phase limits. Neither a row nor a decoded graph
//! creates a fresh ACK, Source operation, restoration proof or active context.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner::ArchivedContentData;
use crate::node_adapters::cnp::semantic::packet_complete_source::{
    archive_native_input::{NativeInputData, NativeInputSelection},
    archive_owner::OriginalRestorationColdOwnerView,
};
use crate::node_contract::OriginalLineageRuntimeRecord;
use crate::node_state::{
    CompleteOriginalArchivedValidationConstructionData, ValidatedCompleteNativeRestorationData,
    VerifiedStateContent,
};
use crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold;
use std::{cell::Cell, mem::size_of};

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct ValidationConstructionCounter
{
    baseline: usize,
    limit: usize,
    peak: Cell<usize>,
}

impl ValidationConstructionCounter {
    fn new(baseline: usize, limit: usize) -> Self {
        Self {
            baseline,
            limit,
            peak: Cell::new(0),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn observe(
        &self,
        retained: usize,
        transient: usize,
    ) -> Result<(), OperationFailure> {
        let requested = retained
            .checked_add(transient)
            .and_then(|bytes| bytes.checked_sub(self.baseline))
            .filter(|bytes| *bytes <= self.limit)
            .ok_or_else(|| {
                refused("archived validation construction exceeds its original phase")
            })?;
        self.peak.set(self.peak.get().max(requested));
        Ok(())
    }
}

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn observe(
    counter: Option<&ValidationConstructionCounter>,
    retained: usize,
    transient: usize,
) -> Result<(), OperationFailure> {
    if let Some(counter) = counter {
        counter.observe(retained, transient)?;
    }
    Ok(())
}

impl PacketCompleteSemanticSource {
    /// Names fixed counters and views used by complete archived validation.
    ///
    /// Compiler-generated traversal frames, allocator residency and erased caller
    /// workspaces are outside this explicit logical-header roster.
    ///
    /// The caller admits this row before constructing the counters or borrowing
    /// the protocol graphs. It excludes the separately retained historical
    /// graphs and the measured dynamic parser/comparison phase rows.
    ///
    /// # Errors
    /// Refuses checked addition overflow in the compiled fixed layout roster.
    pub fn original_archived_restoration_validation_counter_scratch_data()
    -> Result<usize, OperationFailure> {
        [
            size_of::<[ValidationConstructionCounter; 3]>(),
            size_of::<CompleteOriginalArchivedValidationConstructionData>(),
            size_of::<Result<CompleteOriginalArchivedValidationConstructionData, crate::node_contract::RuntimeError>>(),
            size_of::<ValidatedCompleteNativeRestorationData<'_>>(),
            size_of::<Result<ValidatedCompleteNativeRestorationData<'_>, OperationFailure>>(),
            size_of::<OriginalRestorationColdOwnerView<'_>>(),
            size_of::<&crucible_node_provider::protocol_snapshot::owned11::outer::HistoricalControllerState>(),
            size_of::<[[usize; 3]; 2]>(),
            size_of::<PacketCompleteArchivedSemantics>(),
            size_of::<Result<PacketCompleteArchivedSemantics, OperationFailure>>(),
            size_of::<[serde_json::Value; 3]>(),
            size_of::<Result<serde_json::Value, crucible_node_contract::ContractError>>(),
            size_of::<[usize; 13]>(),
            size_of::<[usize; 19]>(),
            size_of::<std::array::IntoIter<usize, 19>>(),
            super::protocol::counter_scratch_data(),
            super::validate::counter_scratch_data(),
            NativeInputData::counter_scratch_data(),
            crucible_node_provider::reference_packet::continuation_models::packet_model_capture_boundary_counter_scratch_data(),
        ].into_iter().try_fold(0usize, |sum, bytes| sum.checked_add(bytes)
            .ok_or_else(|| refused("archived validation fixed view storage overflow")))
    }

    /// Validates an original archive and preserves its concrete future workspace.
    ///
    /// This runs the same runtime, protocol and native predicates as the ordinary
    /// archive callback. The returned fixed row remains bound to that callback's
    /// actual native owner and verified content. Historical model-boundary data
    /// is derived under the full Control decoder lease, without inventing a
    /// fresh Hold. The caller separately precharges the fixed counter getter.
    ///
    /// # Errors
    /// Refuses foreign/incomplete owners, any existing historical predicate,
    /// changed model boundaries or exhausted simultaneous requested storage.
    pub fn authenticate_archived_restoration_validation_data<'a>(
        &self,
        cold: &'a PacketCompleteArchivedOwnerData<'_>,
        semantics: &PacketCompleteArchivedSemantics,
        runtime: &OriginalLineageRuntimeRecord,
        maximum_record_bytes: usize,
        common_additional_retained_bytes: usize,
        native_additional_retained_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<ValidatedCompleteNativeRestorationData<'a>, OperationFailure> {
        self.ensure_origin()?;
        let content = cold.source_content_data(self)?;
        let runtime_counter = ValidationConstructionCounter::new(
            common_additional_retained_bytes,
            maximum_total_bytes,
        );
        let protocol_counter = ValidationConstructionCounter::new(
            common_additional_retained_bytes,
            maximum_total_bytes,
        );
        let native_baseline = native_additional_retained_bytes
            .checked_add(cold.known_requested_bytes()?)
            .ok_or_else(|| refused("archived native validation baseline overflow"))?;
        let native_counter =
            ValidationConstructionCounter::new(native_baseline, maximum_total_bytes);
        semantics.authenticate_runtime_with_construction_data(
            &self.installation().descriptor.id,
            runtime,
            content,
            maximum_record_bytes,
            common_additional_retained_bytes,
            maximum_total_bytes,
            Some(&runtime_counter),
        )?;
        semantics.authenticate_protocol_with_construction_data(
            cold.host()?,
            common_additional_retained_bytes,
            maximum_total_bytes,
            Some(&protocol_counter),
        )?;
        let data = NativeInputData {
            selection: NativeInputSelection::Live(self),
            host: cold.host()?,
            native: cold.native_after()?,
            content: ArchivedContentData::Verified(content),
            retained: native_baseline
                .checked_add(20 + 256)
                .filter(|bytes| *bytes <= maximum_total_bytes)
                .ok_or_else(|| refused("archived native validation retained storage exhausted"))?,
            maximum: maximum_total_bytes,
            scratch: Cell::new(0),
            construction: Some(&native_counter),
        };
        native_counter.observe(data.retained, 0)?;
        data.host.require_complete_reader_state().map_err(unknown)?;
        self.authenticate_original_native_input_history_data(&data, semantics)?;
        self.authenticate_original_native_semantic_history_data(&data, cold.journal()?, semantics)?;
        // Boundary derivation charges the full Control lease and independent
        // returned hash strings; neither output is retained beyond this phase.
        data.capture_boundary_data(cold.journal()?)?;
        self.ensure_origin()?;
        let row = CompleteOriginalArchivedValidationConstructionData::from_validated_phases(
            [
                runtime_counter.peak.get(),
                protocol_counter.peak.get(),
                native_counter.peak.get(),
            ],
            semantics.reserved_decoder_bytes,
            Self::original_archived_restoration_validation_counter_scratch_data()?,
        )
        .map_err(unknown)?;
        Ok(cold
            .original_native_restoration_data()?
            .with_archived_validation_data(row))
    }

    /// Repeats archived predicates beneath the actual Source-fenced Commit Hold.
    ///
    /// The same verified journal bodies are decoded after the independently saved
    /// semantic demand is admitted. This temporary owner is retained throughout
    /// runtime, protocol and native history checks; no operation subset replaces it.
    ///
    /// The private installed window separately authenticates and funds the same
    /// archive/content/runtime, all three sources and fresh target owners. This
    /// method consumes no proof and creates no context. The caller lends `held`
    /// only inside the genuine Source evidence closure after full target,
    /// reference, signed Commit and currentness checks; old ACKs are insufficient.
    pub(crate) fn authenticate_original_retained_restoration_validation_data(
        &self,
        cold: &OriginalRestorationColdOwnerView<'_>,
        runtime: &OriginalLineageRuntimeRecord,
        content: &VerifiedStateContent,
        held: &PacketNativeRestoredCommitHold,
        admitted: &CompleteOriginalArchivedValidationConstructionData,
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if !std::ptr::eq(cold.source, self) {
            return Err(refused("retained validation uses another original Source"));
        }
        let fixed = Self::original_archived_restoration_validation_counter_scratch_data()?;
        if fixed > admitted.fixed_counter_scratch_bytes_data() {
            return Err(refused(
                "retained validation fixed views exceed original row",
            ));
        }
        additional_retained_bytes
            .checked_add(admitted.requested_bytes_data())
            .filter(|bytes| *bytes <= maximum_total_bytes)
            .ok_or_else(|| refused("retained archived validation precredit exhausted"))?;
        let host = cold.host.historical().map_err(unknown)?;
        if host.node != self.installation().descriptor.id
            || cold.owner.owner != self.installation().owner.owner.id
        {
            return Err(refused("retained cold native source or owner differs"));
        }
        let semantic = content
            .get(&cold.journal.semantic)
            .ok_or_else(|| refused("retained original semantic body absent"))?;
        let ancestry = content
            .get(&cold.journal.ancestry)
            .ok_or_else(|| refused("retained original ancestry body absent"))?;
        let demand = PacketCompleteArchivedSemantics::decode_demand_data(
            semantic,
            ancestry,
            maximum_record_bytes,
            maximum_total_bytes,
        )?;
        if demand > admitted.semantic_decode_requested_bytes_data() {
            return Err(refused(
                "retained semantic decoder exceeds its original row",
            ));
        }
        let other = additional_retained_bytes
            .checked_add(fixed)
            .ok_or_else(|| refused("retained semantic fixed views overflow"))?;
        let semantics = PacketCompleteArchivedSemantics::decode_data(
            semantic,
            ancestry,
            maximum_record_bytes,
            other,
            maximum_total_bytes,
        )?;
        self.authenticate_retained_with_semantics(
            cold,
            runtime,
            content,
            held,
            admitted,
            maximum_record_bytes,
            other,
            maximum_total_bytes,
            &semantics,
        )?;
        self.ensure_origin()
    }

    fn authenticate_retained_with_semantics(
        &self,
        cold: &OriginalRestorationColdOwnerView<'_>,
        runtime: &OriginalLineageRuntimeRecord,
        content: &VerifiedStateContent,
        held: &PacketNativeRestoredCommitHold,
        admitted: &CompleteOriginalArchivedValidationConstructionData,
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
        semantics: &PacketCompleteArchivedSemantics,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if !std::ptr::eq(cold.source, self) {
            return Err(refused("retained validation uses another original Source"));
        }
        let fixed = Self::original_archived_restoration_validation_counter_scratch_data()?;
        if fixed > admitted.fixed_counter_scratch_bytes_data() {
            return Err(refused(
                "retained validation fixed views exceed original row",
            ));
        }
        let [runtime_limit, protocol_limit, native_limit] = admitted.phase_requested_bytes_data();
        let runtime_counter =
            ValidationConstructionCounter::new(additional_retained_bytes, runtime_limit);
        let protocol_counter =
            ValidationConstructionCounter::new(additional_retained_bytes, protocol_limit);
        let native_baseline = additional_retained_bytes
            .checked_add(semantics.reserved_decoder_bytes)
            .ok_or_else(|| refused("retained native semantic owner storage overflow"))?;
        let native_counter = ValidationConstructionCounter::new(native_baseline, native_limit);
        let host = cold.host.historical().map_err(unknown)?;
        let native = cold.native_after.historical().map_err(unknown)?;
        semantics.authenticate_runtime_with_construction_data(
            &self.installation().descriptor.id,
            runtime,
            content,
            maximum_record_bytes,
            additional_retained_bytes,
            maximum_total_bytes,
            Some(&runtime_counter),
        )?;
        semantics.authenticate_protocol_with_construction_data(
            host,
            additional_retained_bytes,
            maximum_total_bytes,
            Some(&protocol_counter),
        )?;
        let data = NativeInputData {
            selection: NativeInputSelection::Live(self),
            host,
            native,
            content: ArchivedContentData::Verified(content),
            retained: native_baseline
                .checked_add(20 + 256)
                .filter(|bytes| *bytes <= maximum_total_bytes)
                .ok_or_else(|| refused("retained native validation storage exhausted"))?,
            maximum: maximum_total_bytes,
            scratch: Cell::new(0),
            construction: Some(&native_counter),
        };
        native_counter.observe(data.retained, 0)?;
        data.host.require_complete_reader_state().map_err(unknown)?;
        self.authenticate_original_native_input_history_data(&data, semantics)?;
        self.authenticate_original_native_semantic_history_data(&data, cold.journal, semantics)?;
        let boundary = data.capture_boundary_data(cold.journal)?;
        authenticate_held_boundary(held, &boundary)?;
        self.ensure_origin()
    }
}

fn authenticate_held_boundary(
    held: &PacketNativeRestoredCommitHold,
    boundary: &crucible_node_provider::reference_packet::continuation_models::PacketModelCaptureBoundaryData,
) -> Result<(), OperationFailure> {
    if held.local_cursor != boundary.local_cursor || held.inventory_hash != boundary.inventory_hash
    {
        return Err(refused(
            "fresh Commit Hold changed the archived complete model boundary",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_phase_limit_refuses_before_recording_an_excess_lease() {
        let counter = ValidationConstructionCounter::new(100, 40);
        counter.observe(110, 30).unwrap();
        assert_eq!(counter.peak.get(), 40);
        assert!(counter.observe(110, 31).is_err());
        assert_eq!(counter.peak.get(), 40);
        assert!(counter.observe(99, 0).is_err());
        assert!(counter.observe(usize::MAX, 1).is_err());
    }

    #[test]
    fn completed_sequential_phase_row_keeps_each_limit_and_fixed_views() {
        let row = CompleteOriginalArchivedValidationConstructionData::from_validated_phases(
            [30, 50, 40],
            11,
            7,
        )
        .unwrap();
        assert_eq!(row.phase_requested_bytes_data(), [30, 50, 40]);
        assert_eq!(row.fixed_counter_scratch_bytes_data(), 7);
        assert_eq!(row.semantic_decode_requested_bytes_data(), 11);
        assert_eq!(row.requested_bytes_data(), 68);
        assert!(
            CompleteOriginalArchivedValidationConstructionData::from_validated_phases(
                [usize::MAX, 1, 2],
                0,
                1
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use crucible_node_contract::{Id, Phase, Position, U64, canonical};
    use crucible_node_provider::reference_packet::continuation_models::PacketModelCaptureBoundaryData;

    #[test]
    fn held_model_correspondence_refuses_changed_cursor_or_full_inventory_identity() {
        let reference =
            canonical::content_ref(b"retained original", "application/octet-stream").unwrap();
        let inventory = canonical::json_hash(
            "source-owned.packet-inventory.v1",
            &vec!["actual retained event"],
        )
        .unwrap();
        let cursor = Position::new(U64::new(8), U64::new(2), Phase::Publication);
        let mut held = PacketNativeRestoredCommitHold {
            schema: "source-owned.packet-restored-commit-held/12".to_owned(),
            native_pid: U64::new(1),
            target_world: inventory.clone(),
            target_owner: Id::new("owner").unwrap(),
            target_owner_binding: inventory.clone(),
            target_activation: Id::new("activation").unwrap(),
            target_generation: U64::new(1),
            captured_owner_state: reference.clone(),
            captured_control: reference.clone(),
            captured_journal: reference.clone(),
            mapping: reference.clone(),
            restore_commit: reference,
            context_digest: crucible_node_contract::Bytes::new(vec![1; 32]),
            local_cursor: cursor,
            inventory_hash: inventory.clone(),
            physical_gate_held: true,
        };
        let boundary = PacketModelCaptureBoundaryData {
            local_cursor: cursor,
            gate_closed: false,
            retained_outputs: 1,
            earliest_pending_completion: None,
            inventory_hash: inventory,
        };
        // This control tests model DATA correlation only. It does not fabricate
        // a Source evidence closure or assert that this fixture is a real Hold.
        authenticate_held_boundary(&held, &boundary).unwrap();
        held.local_cursor = Position::new(U64::new(8), U64::new(2), Phase::Delivery);
        assert!(authenticate_held_boundary(&held, &boundary).is_err());
        held.local_cursor = cursor;
        held.inventory_hash.domain.push_str("-foreign");
        assert!(authenticate_held_boundary(&held, &boundary).is_err());
        held.inventory_hash = boundary.inventory_hash.clone();
        held.inventory_hash.digest.replace_range(..1, "f");
        if held.inventory_hash == boundary.inventory_hash {
            held.inventory_hash.digest.replace_range(..1, "0");
        }
        assert!(authenticate_held_boundary(&held, &boundary).is_err());
    }
}
