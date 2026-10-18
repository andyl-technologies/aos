//! Prices current Runtime7 validation before a restored Capture owner is lent.
//!
//! The borrowed defining serializer walks the actual current Runtime ledger.
//! Imported immutable ancestry and fresh completed operations keep their actual
//! distinct records. This DATA is neither a Capture ticket nor a Source claim.

use super::*;
use crate::node_contract::runtime::original_input_lineage::snapshot_credit::SnapshotView;
use crucible_node_contract::Validate;
use std::mem::size_of;

/// Bounds the new independent validation of the actual current Runtime object.
///
/// Only the owning Runtime constructs this row from its complete live ledger.
/// The original administrative Capture ticket and current Window/Source fences
/// remain independently required before native effects.
#[derive(Clone, Copy)]
pub struct OriginalRestoredCaptureRuntimeConstructionData {
    runtime: *const NodeRuntime,
    world: *const (),
    cut: crucible_node_contract::Position,
    ordinal: crucible_node_contract::U64,
    encoded: usize,
    scheduling_encoded: usize,
    validation: usize,
    checkpoint_inputs_construction: usize,
    scratch: usize,
    maximum: usize,
}

impl OriginalRestoredCaptureRuntimeConstructionData {
    /// Returns the complete current Runtime7 serialization-event byte extent.
    pub fn maximum_runtime_record_encoded_bytes_data(&self) -> usize {
        self.encoded
    }

    /// Returns the independently quoted current scheduling encoding bound.
    pub fn maximum_scheduling_record_encoded_bytes_data(&self) -> usize {
        self.scheduling_encoded
    }

    /// Returns six complete ticket validation windows for three Sources.
    pub fn ticket_validation_transient_requested_bytes_data(&self) -> usize {
        self.validation
    }

    /// Returns the separate current Runtime7 and scheduling constructor credit.
    ///
    /// These retained inputs are additional to all six Source ticket-validation
    /// windows. They are built before the unchanged whole-owner reobservation.
    pub fn checkpoint_inputs_construction_requested_bytes_data(&self) -> usize {
        self.checkpoint_inputs_construction
    }

    /// Returns the independently committed validation and counter sum.
    ///
    /// # Errors
    /// Refuses checked overflow or the unchanged whole construction ceiling.
    pub fn requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        self.validation
            .checked_add(self.checkpoint_inputs_construction)
            .and_then(|bytes| bytes.checked_add(self.scratch))
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Returns the independently named defining counter and borrowed views.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    pub(crate) fn authenticate_original_data(
        &self,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        cut: crucible_node_contract::Position,
        ordinal: crucible_node_contract::U64,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.runtime, runtime)
            || self.world != Rc::as_ptr(&world.authority)
            || self.cut != cut
            || self.ordinal != ordinal
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.validation
            .checked_add(self.checkpoint_inputs_construction)
            .and_then(|bytes| bytes.checked_add(self.scratch))
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        runtime.validate_activation(world)
    }
}

impl NodeRuntime {
    /// Counts new ticket validation work from the actual complete current ledger.
    ///
    /// No Runtime7 DTO, Value, canonical bank, owner ticket or Source permit is
    /// allocated by this producer. Its row is an additional commitment beside
    /// ordinary archive/capture geometry, not a refund of that geometry.
    pub(crate) fn original_restored_capture_runtime_construction_data(
        &self,
        world: &WorldActivation,
        cut: crucible_node_contract::Position,
        ordinal: crucible_node_contract::U64,
        maximum_record_bytes: usize,
        maximum: usize,
    ) -> Result<OriginalRestoredCaptureRuntimeConstructionData, RuntimeError> {
        self.validate_activation(world)?;
        self.require_settled_capture_custody()?;
        if self.terminal.is_some()
            || self.condition_stop.is_some()
            || self
                .operations
                .values()
                .any(|entry| !matches!(entry.result, RetainedResult::Acknowledged(_)))
            || self.owners.values().any(|owner| owner.operation.is_some())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        cut.validate().map_err(|_| RuntimeError::InvalidReceipt)?;
        let view = SnapshotView {
            runtime: self,
            cut,
            ordinal,
        };
        // Every named type is an actual owned Runtime7 child family. Their sum
        // conservatively dominates a single typed slot without a guessed byte
        // multiplier or a serialized-length substitute for current ownership.
        let typed_slot = [
            size_of::<OriginalLineageRuntimeRecord>(),
            size_of::<SavedRuntimeActivation>(),
            size_of::<SavedRuntimeOwner>(),
            size_of::<SavedRuntimeOperation>(),
            size_of::<SavedRuntimeResult>(),
            size_of::<OriginalLineageInputRecord>(),
            size_of::<OriginalLineageProvenanceRecord>(),
            size_of::<SavedOriginalInputLineage>(),
            size_of::<SavedOriginalPublication>(),
            size_of::<OperationOutcome>(),
            size_of::<crate::node_scheduling::NativeSchedulingObservation>(),
            size_of::<crate::node_scheduling::NativePublication>(),
            size_of::<crate::node_scheduling::event::Delivery>(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })?;
        let (one_validation, encoded) =
            Self::original_restoration_coordinator_serialization_geometry_data(
                &view, typed_slot, maximum,
            )?;
        if encoded > maximum_record_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        let validation = one_validation
            .checked_mul(6)
            .ok_or(RuntimeError::ResourceLimit)?;
        let (scheduling_construction, scheduling_encoded) = self
            .scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .retained()?
            .restored17_snapshot_geometry_data(cut, ordinal, maximum)?;
        let checkpoint_inputs_construction = one_validation
            .checked_add(scheduling_construction)
            .ok_or(RuntimeError::ResourceLimit)?;
        let scratch = Self::original_restored_capture_runtime_counter_scratch_data();
        validation
            .checked_add(checkpoint_inputs_construction)
            .and_then(|bytes| bytes.checked_add(scratch))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(OriginalRestoredCaptureRuntimeConstructionData {
            runtime: self,
            world: Rc::as_ptr(&world.authority),
            cut,
            ordinal,
            encoded,
            scheduling_encoded,
            validation,
            checkpoint_inputs_construction,
            scratch,
            maximum,
        })
    }

    pub(crate) fn original_restored_capture_runtime_counter_scratch_data() -> usize {
        super::original_input_lineage::snapshot_credit::original_restored_snapshot_counter_scratch_data()
            + Self::capture_serialization_counter_scratch_data()
            + Self::capture_opaque_owner_observer_scratch_data()
            + size_of::<SnapshotView<'static>>()
            + size_of::<OriginalRestoredCaptureRuntimeConstructionData>()
            + size_of::<Result<OriginalRestoredCaptureRuntimeConstructionData, RuntimeError>>()
            + size_of::<[usize; 13]>()
            + size_of::<std::array::IntoIter<usize, 13>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<(usize, usize)>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<&Self>()
            + size_of::<&WorldActivation>()
            + crate::node_scheduling::CausalScheduler::restored17_snapshot_geometry_additional_counter_scratch_data()
    }
}

impl NodeRuntime {
    pub(crate) fn quote_original_restored_capture_prequote_data(
        &self,
        node: &Id,
        launch: &crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &crate::node_admission::OriginalRestoredCaptureRequestData<'_>,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        let snapshot = self.snapshots.get(node).ok_or(RuntimeError::UnknownNode)?;
        let handle = self.nodes.get(node).ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(handle.as_ref())?;
        let row =
            handle.quote_original_restored_capture_prequote(launch, raw5, request, maximum)?;
        snapshot.validate_current(handle.as_ref())?;
        Ok(row)
    }
}

impl NodeRuntime {
    /// Reserves the actual selected Node/Source counting owners after admission.
    ///
    /// # Errors
    /// Refuses an unknown/stale Node, a missing concrete bridge, mismatched
    /// current owners or any bounded bank reservation failure.
    pub(crate) fn reserve_original_restored_capture_counting_banks_data(
        &self,
        node: &Id,
        launch: &crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &crate::node_admission::OriginalRestoredCaptureRequestData<'_>,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        let snapshot = self.snapshots.get(node).ok_or(RuntimeError::UnknownNode)?;
        let handle = self.nodes.get(node).ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(handle.as_ref())?;
        let result =
            handle.reserve_original_restored_capture_counting_banks(launch, raw5, request, maximum);
        snapshot.validate_current(handle.as_ref())?;
        result
    }
}

impl NodeRuntime {
    pub(crate) fn quote_original_restored_capture_construction_data(
        &self,
        node: &Id,
        launch: &crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &crate::node_admission::OriginalRestoredCaptureRequestData<'_>,
        maximum: usize,
    ) -> Result<
        crate::node_adapters::cnp::OriginalSourceRestoredCaptureConstructionData,
        RuntimeError,
    > {
        let snapshot = self.snapshots.get(node).ok_or(RuntimeError::UnknownNode)?;
        let handle = self.nodes.get(node).ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(handle.as_ref())?;
        let row =
            handle.quote_original_restored_capture_construction(launch, raw5, request, maximum)?;
        snapshot.validate_current(handle.as_ref())?;
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settled_fixture() -> (
        NodeRuntime,
        WorldActivation,
        crucible_node_contract::Position,
    ) {
        super::super::tests::settled_capture_runtime_fixture()
    }

    #[test]
    fn actual_current_runtime_projection_covers_owned_value_and_canonical_banks() {
        let (runtime, world, cut) = settled_fixture();
        let maximum = 256 * 1024 * 1024;
        let row = runtime
            .original_restored_capture_runtime_construction_data(
                &world,
                cut,
                2.into(),
                maximum,
                maximum,
            )
            .unwrap();
        let view = SnapshotView {
            runtime: &runtime,
            cut,
            ordinal: 2.into(),
        };
        let value = serde_json::to_value(&view).unwrap();
        let canonical = crucible_node_contract::canonical::canonical_json(&value).unwrap();
        let actual = NodeRuntime::original_json_value_requested_storage_data(&value, maximum)
            .unwrap()
            .checked_add(canonical.capacity())
            .unwrap();

        assert!(actual <= row.ticket_validation_transient_requested_bytes_data() / 6);
        assert!(canonical.len() <= row.maximum_runtime_record_encoded_bytes_data());
        assert_eq!(value["schema_version"], 7);
        assert_eq!(
            value["operations"].as_array().unwrap().len(),
            runtime.operations.len()
        );
        assert_eq!(
            value["owners"].as_array().unwrap().len(),
            runtime.owners.len()
        );
    }

    #[test]
    fn current_runtime_quote_exact_and_one_short_do_not_change_retained_custody() {
        let (runtime, world, cut) = settled_fixture();
        let broad = runtime
            .original_restored_capture_runtime_construction_data(
                &world,
                cut,
                2.into(),
                256 * 1024 * 1024,
                256 * 1024 * 1024,
            )
            .unwrap();
        let exact = broad.requested_bytes_data().unwrap();
        let operations = runtime.operations.len();
        let captures = runtime.original_capture_attempts.len();

        let admitted = runtime
            .original_restored_capture_runtime_construction_data(
                &world,
                cut,
                2.into(),
                broad.maximum_runtime_record_encoded_bytes_data(),
                exact,
            )
            .unwrap();
        assert_eq!(admitted.requested_bytes_data().unwrap(), exact);
        assert!(matches!(
            runtime.original_restored_capture_runtime_construction_data(
                &world,
                cut,
                2.into(),
                broad.maximum_runtime_record_encoded_bytes_data(),
                exact - 1,
            ),
            Err(RuntimeError::ResourceLimit)
        ));
        assert_eq!(runtime.operations.len(), operations);
        assert_eq!(runtime.original_capture_attempts.len(), captures);
        assert!(
            runtime
                .owners
                .values()
                .all(|owner| owner.operation.is_none())
        );
    }

    #[test]
    fn current_runtime_projection_requires_settled_and_same_actual_authority() {
        let (pending, _) = super::super::tests::capture_ticket_fixture();
        let world = pending
            .operations
            .values()
            .next()
            .unwrap()
            .admission
            .activation()
            .clone();
        let cut = world.record().boundary;
        assert!(matches!(
            pending.original_restored_capture_runtime_construction_data(
                &world,
                cut,
                1.into(),
                256 * 1024 * 1024,
                256 * 1024 * 1024,
            ),
            Err(RuntimeError::OutstandingObligations)
        ));

        let (runtime, world, cut) = settled_fixture();
        let row = runtime
            .original_restored_capture_runtime_construction_data(
                &world,
                cut,
                2.into(),
                256 * 1024 * 1024,
                256 * 1024 * 1024,
            )
            .unwrap();
        let sibling_view = world.clone();
        assert!(
            row.authenticate_original_data(&runtime, &sibling_view, cut, 2.into())
                .is_ok()
        );
        let (foreign, foreign_world, _) = settled_fixture();
        assert!(matches!(
            row.authenticate_original_data(&foreign, &foreign_world, cut, 2.into()),
            Err(RuntimeError::ForeignAuthority)
        ));
    }
}
