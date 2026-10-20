//! Derives semantic receiving geometry from the actual captured raw history.
//!
//! The same canonical native cursor visits every historical COMMIT, including
//! values later replaced or deleted. This mechanical pass never validates role
//! semantics or returns a protected view. Root must pay the actual native
//! extent before entry, then pay the resulting peak before the second, existing
//! Domain role replay of the same original. Neither peak DATA nor a completed
//! native pass can authorize that replay or any Controller/Root effect.

mod delete_admission;
pub(crate) use delete_admission::DeleteAdmissionAuditInputsDataV3;
use delete_admission::DeleteAdmissionAuditOriginalV3;
mod delete_auxiliary;
pub(crate) use delete_auxiliary::RootDeleteAuxiliaryRowDataV3;
use delete_auxiliary::DeleteAuxiliaryCaptureV3;

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::{
    CanonicalReplayExtentDataV1, CanonicalReplayOriginalV1, CanonicalReplayCursorV1,
    NativeJournalDataErrorV1,

};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::{JournalError, JournalLimits, JournalTransaction, ReadOnlyJournalOpenOriginalsV1,
    ProtectedJournalPreopenReplayExtentV1, RecordNamespace};

use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryReadonlyOpeningV1;

// Both variants name an actual retained file source. Neither accepts a callback,
// imported native map or successful replay marker.
enum AuditNativeInputV1<'file> {
    #[cfg(test)]
    Existing(&'file std::fs::File),
    Ordinary(&'file CanonicalOrdinaryReadonlyOpeningV1<JournalError>),
}

impl<'file> AuditNativeInputV1<'file> {
    fn begin<'original>(
        self, original: &'original mut CanonicalReplayOriginalV1,
        limits: JournalLimits, bytes: u64,
    ) -> Result<CanonicalReplayCursorV1<'file, 'original>, NativeJournalDataErrorV1> {
        match self {
            #[cfg(test)]
            Self::Existing(file) => original.begin_semantic_cursor_once(file, limits, bytes),
            Self::Ordinary(opened) => opened.begin_geometry_cursor_v1(original),
        }
    }
}

type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

pub(crate) struct RootControllerReadonlyGeometryAuditV1 {
    native: CanonicalReplayOriginalV1,
    geometry: Option<Result<ResourceVector, JournalError>>,
    result: Option<Result<(), JournalError>>,
    extent: Option<ProtectedJournalPreopenReplayExtentV1>,
    peak: ResourceVector,
    maximum_desired_state_value_bytes: usize,
    graph_geometry: Option<Result<ResourceVector, JournalError>>,
    graph_peak: ResourceVector,
    graph_entered: bool,
    delete_auxiliary: Option<DeleteAuxiliaryCaptureV3>,
    delete_admission: Option<DeleteAdmissionAuditOriginalV3>,
    entered: bool,
    closed: bool,
}

impl RootControllerReadonlyGeometryAuditV1 {
    pub(crate) const fn new() -> Self {
        Self {
            native: CanonicalReplayOriginalV1::new(), geometry: None, result: None,
            extent: None, peak: ResourceVector::ZERO, maximum_desired_state_value_bytes: 0,
            graph_geometry: None, graph_peak: ResourceVector::ZERO, graph_entered: false, delete_auxiliary: None, delete_admission: None,
            entered: false, closed: false,
        }
    }

    pub(crate) fn prepare_delete_admission_comparison_v3(&mut self, inputs: DeleteAdmissionAuditInputsDataV3)
        -> Result<(), JournalError> {
        if self.entered || self.closed || self.delete_admission.is_some() || self.delete_auxiliary.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.delete_admission = Some(DeleteAdmissionAuditOriginalV3::new(inputs));
        Ok(())
    }

    pub(crate) fn require_delete_admission_comparison_v3(&self) -> Result<(), JournalError> {
        self.additional_semantic_demand_v1()?;
        self.delete_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_completed_v3()
    }

    pub(crate) fn require_delete_admission_current_rows_v3(&self, rows: &State) -> Result<(), JournalError> {
        self.require_delete_admission_comparison_v3()?;
        self.delete_admission.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_current_rows_v3(rows)
    }

    pub(crate) fn prepare_delete_auxiliary_capture_v3(&mut self,
        project: aos_sandbox_core::ProjectId, operation: aos_sandbox_core::OperationId,
    ) -> Result<(), JournalError> {
        if self.entered || self.closed || self.delete_auxiliary.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.delete_auxiliary = Some(DeleteAuxiliaryCaptureV3::new(project, operation));
        Ok(())
    }

    pub(crate) fn delete_auxiliary_capture_receiving_demand_v3(&self, bytes: u64)
        -> Result<ResourceVector, JournalError>
    {
        match &self.delete_auxiliary { Some(capture) => capture.receiving_demand_v3(bytes), None => Ok(ResourceVector::ZERO) }
    }

    pub(crate) fn delete_auxiliary_rows_v3(&self) -> Result<&[RootDeleteAuxiliaryRowDataV3], JournalError> {
        self.additional_semantic_demand_v1()?;
        self.delete_auxiliary.as_ref().ok_or(JournalError::ProtectedBoundary)?.rows_v3()
    }

    // The surrounding actual Root purpose pays this fixed owner before Box or
    // physical opening. No caller-selected amount enters this layout supplier.
    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::JournalTooLarge;
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<AuditGeometryFramesV1>()))
            // The closed native input is constructed, passed to the shared
            // fold, then consumed by its existing canonical cursor entry.
            .and_then(|bytes| bytes.checked_add(size_of::<AuditNativeInputV1<'_>>().checked_mul(3)?))
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?))
    }

    // Both the first native DATA audit and the later existing role replay have
    // separate resident partials/maps. Admit both from the actual held extent.
    pub(crate) fn additional_native_demand_v1(extent: &ProtectedJournalPreopenReplayExtentV1)
        -> Result<ResourceVector, JournalError>
    {
        let canonical = CanonicalReplayExtentDataV1::new(extent.limits, extent.native_bytes)
            .map_err(|_| JournalError::JournalTooLarge)?;
        let native = canonical.dominant_native_receiving_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?;
        let codec = canonical.dominant_semantic_receiving_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?;
        let domain = extent.dominant_native_receiving_demand_v1()?;
        native.checked_add(codec).and_then(|value| value.checked_add(domain))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    // The actual held preparation alone lends its own File/extent. This is a
    // mechanical one-shot operation; its private caller retains real R payment.
    pub(crate) fn observe_captured_once(&mut self, opened: &ReadOnlyJournalOpenOriginalsV1) {
        if self.entered || self.closed {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.result = Some(match opened.captured_opening_for_geometry_audit_v1() {
            Some((opening, extent)) => {
                self.extent = Some(extent);
                self.observe_native_with_graph_inner_v1(
                    AuditNativeInputV1::Ordinary(opening), extent.limits, extent.native_bytes, None,
                )
            }
            None => Err(JournalError::ProtectedBoundary),
        });
    }

    // Root's actual ordinary readonly acquisition lends the canonical cursor,
    // while this same audit original retains its independent full traversal.
    pub(crate) fn observe_fixed_opening_once_v1(
        &mut self, opened: &CanonicalOrdinaryReadonlyOpeningV1<JournalError>,
        extent: ProtectedJournalPreopenReplayExtentV1, controller: Option<&State>,
    ) {
        if self.entered || self.closed { self.closed = true; return; }
        self.entered = true;
        self.graph_entered = controller.is_some();
        self.extent = Some(extent);
        self.result = Some(self.observe_native_with_graph_inner_v1(
            AuditNativeInputV1::Ordinary(opened), extent.limits, extent.native_bytes, controller));
    }

    #[cfg(test)]
    fn observe_file_inner(&mut self, file: &std::fs::File, limits: JournalLimits, bytes: u64)
        -> Result<(), JournalError>
    {
        self.observe_native_with_graph_inner_v1(AuditNativeInputV1::Existing(file), limits, bytes, None)
    }

    fn observe_native_with_graph_inner_v1(
        &mut self, input: AuditNativeInputV1<'_>, limits: JournalLimits,
        bytes: u64, controller: Option<&State>,
    ) -> Result<(), JournalError> {
        let mut cursor = input.begin(&mut self.native, limits, bytes)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        while cursor.advance_once().map_err(|_| JournalError::ProtectedBoundary)? {
            let view = cursor.current_commit().ok_or(JournalError::ProtectedBoundary)?;
            for row in view.transaction().records() {
                if row.namespace() == RecordNamespace::DesiredState {
                    if let Some(value) = row.value() {
                        self.maximum_desired_state_value_bytes = self.maximum_desired_state_value_bytes.max(value.len());
                    }
                }
            }
            self.geometry = Some(semantic_geometry_v1(view.prior_state(), Some(view.transaction())));
            let demand = self.geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(JournalError::ProtectedBoundary)?;
            self.peak = self.peak.componentwise_max(demand);
            if let Some(controller) = controller {
                self.graph_geometry = Some(graph_geometry_v2(
                    view.prior_state(), Some(view.transaction()), controller));
                let graph = self.graph_geometry.as_ref().and_then(|result| result.as_ref().ok())
                    .copied().ok_or(JournalError::ProtectedBoundary)?;
                self.graph_peak = self.graph_peak.componentwise_max(graph);
            }

            // Native-only stage ordering is identical to the ordinary canonical
            // engine. No role hook is skipped in the later Domain replay.
            cursor.validate_compaction_once().map_err(|_| JournalError::ProtectedBoundary)?;
            cursor.register_transaction_once().map_err(|_| JournalError::ProtectedBoundary)?;
            if let Some(capture) = self.delete_auxiliary.as_mut() {
                let actual = cursor.current_commit().ok_or(JournalError::ProtectedBoundary)?;
                capture.observe_commit_v3(&actual)?;
            }
            if let Some(comparison) = self.delete_admission.as_mut() {
                let actual = cursor.current_commit().ok_or(JournalError::ProtectedBoundary)?;
                comparison.observe_commit_v3(&actual)?;
            }
            cursor.prepare_change_once().map_err(|_| JournalError::ProtectedBoundary)?;
            cursor.apply_commit_once().map_err(|_| JournalError::ProtectedBoundary)?;
        }
        if let Some(comparison) = self.delete_admission.as_mut() {
            comparison.finish_prefix_v3(cursor.completed_prefix().ok_or(JournalError::ProtectedBoundary)?, bytes)?;
        }
        drop(cursor);
        let final_state = self.native.state().ok_or(JournalError::ProtectedBoundary)?;
        self.geometry = Some(semantic_geometry_v1(final_state, None));
        let demand = self.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.peak = self.peak.componentwise_max(demand);
        if let Some(controller) = controller {
            self.graph_geometry = Some(graph_geometry_v2(final_state, None, controller));
            let graph = self.graph_geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(JournalError::ProtectedBoundary)?;
            self.graph_peak = self.graph_peak.componentwise_max(graph);
        }
        Ok(())
    }

    pub(crate) fn additional_semantic_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        if self.closed || !matches!(self.result, Some(Ok(()))) || self.native.report().is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        // The generic per-row fold and the Source-family dynamic term were
        // sampled at every actual prior+transaction frontier, including deletes.
        let (bytes, _representation_controls) = super::source_native_family_fixed_footprint_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        let family = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?);
        self.peak.checked_add(family).map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn additional_graph_demand_v2(&self) -> Result<ResourceVector, JournalError> {
        self.additional_semantic_demand_v1()?;
        if !self.graph_entered || !matches!(self.graph_geometry, Some(Ok(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(self.graph_peak)
    }

    pub(crate) fn require_actual_semantic_frontier_v1(
        &self, state: &State, transaction: Option<&JournalTransaction>,
    ) -> Result<(), JournalError> {
        let paid_shape = self.additional_semantic_demand_v1()?;
        let actual = semantic_geometry_v1(state, transaction)?;
        paid_shape.checked_sub(actual).map_err(|_| JournalError::ProtectedBoundary)?;
        Ok(())
    }

    pub(crate) fn captured_extent_v1(&self) -> Option<ProtectedJournalPreopenReplayExtentV1> {
        self.additional_semantic_demand_v1().ok()?;
        self.extent
    }

    pub(crate) fn maximum_desired_state_value_bytes_v2(&self) -> Result<usize, JournalError> {
        self.additional_semantic_demand_v1()?;
        Ok(self.maximum_desired_state_value_bytes)
    }

    pub(crate) fn native_data_v1(&self) -> Option<&CanonicalReplayOriginalV1> {
        self.additional_semantic_demand_v1().ok()?;
        Some(&self.native)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native.failure()
            .or_else(|| self.delete_admission.as_ref().and_then(|comparison| comparison.failure()))
            .or_else(|| self.delete_auxiliary.as_ref().and_then(|capture| capture.failure()).map(|cause| cause as _))
            .or_else(|| self.geometry.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| self.graph_geometry.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| self.closed.then_some(&CLOSED as &(dyn Error + 'static)))
    }
}

fn semantic_geometry_v1(state: &State, transaction: Option<&JournalTransaction>)
    -> Result<ResourceVector, JournalError>
{
    super::source_readonly_semantic_demand_v1(state, transaction)?
        .checked_add(super::source_native_family_dynamic_demand_v1(state, transaction)?)
        .map_err(|_| JournalError::JournalTooLarge)
}

// A proposed PUT may add one row; counting all records is conservative for
// replacements/deletes and avoids constructing any second materialized state.
fn graph_geometry_v2(state: &State, transaction: Option<&JournalTransaction>, controller: &State)
    -> Result<ResourceVector, JournalError>
{
    let rows = state.len().checked_add(transaction.map_or(0, |tx| tx.records().len()))
        .ok_or(JournalError::JournalTooLarge)?;
    let bytes = aos_sandbox_ledger_replay::delete_graph::
        delete_dependency_graph_prefix_receiving_bytes_v2(rows, controller, 0)
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;

// Pure geometry computation itself enters before the resulting semantic stage
// is paid. These actual fixed scalar/return/hash-free carriers are paid first.
#[allow(dead_code)]
struct AuditGeometryFramesV1 {
    widths: [[usize; 8]; 2],
    demands: [ResourceVector; 8],
    results: [Result<ResourceVector, JournalError>; 4],
    counters: [usize; 6],
    graph_result: Option<Result<ResourceVector, JournalError>>,
    controller: Option<&'static State>,
    slices: [&'static [u8]; 4],
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use aos_sandbox_broker::canonical_journal::JournalRecord;
    use aos_sandbox_protocol::domain_ledger::transaction::encode_transaction;
    use super::*;

    fn append(file: &mut std::fs::File, id: u8, sequence: u64, value: Vec<u8>) -> u64 {
        let transaction = JournalTransaction::new([id; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![7], value),
        ]).unwrap();
        let frames = encode_transaction(&transaction, sequence).unwrap();
        let next = sequence + frames.len() as u64;
        for frame in frames { file.write_all(&frame).unwrap(); }
        next
    }

    #[test]
    fn native_data_audit_keeps_larger_replaced_historical_frontier() {
        let mut file = tempfile::tempfile().unwrap();
        let sequence = append(&mut file, 1, 1, vec![8; 4_096]);
        append(&mut file, 2, sequence, vec![9]);
        let bytes = file.metadata().unwrap().len();
        let mut audit = RootControllerReadonlyGeometryAuditV1::new();

        // Offline native DATA fixture only; it constructs no protected reader,
        // paid R original or valid semantic Operation record.
        audit.entered = true;
        audit.result = Some(audit.observe_file_inner(&file, JournalLimits::default(), bytes));

        assert!(matches!(audit.result, Some(Ok(()))));
        let final_state = audit.native.state().unwrap();
        let final_only = semantic_geometry_v1(final_state, None).unwrap();
        assert!(audit.additional_semantic_demand_v1().unwrap().get(D::MemoryBytes)
            > final_only.get(D::MemoryBytes));
        assert_eq!(final_state.get(&(RecordNamespace::Operation, vec![7])), Some(&vec![9]));
        assert!(audit.failure().is_none());
    }

    #[test]
    fn historical_desired_state_width_survives_a_smaller_current_row() {
        let mut file = tempfile::tempfile().unwrap();
        let mut sequence = 1;
        for (id, width) in [(1, 4096), (2, 8)] {
            let transaction = JournalTransaction::new([id; 16], vec![
                JournalRecord::put(RecordNamespace::DesiredState, vec![7], vec![9; width]),
            ]).unwrap();
            let frames = encode_transaction(&transaction, sequence).unwrap();
            sequence += frames.len() as u64;
            for frame in frames { file.write_all(&frame).unwrap(); }
        }
        let bytes = file.metadata().unwrap().len();
        let mut audit = RootControllerReadonlyGeometryAuditV1::new();
        // These are raw geometry fixtures; they supply no valid role model or
        // native historical proof from their arbitrary DesiredState bodies.
        audit.entered = true;
        audit.result = Some(audit.observe_file_inner(&file, JournalLimits::default(), bytes));

        assert!(matches!(audit.result, Some(Ok(()))));
        assert_eq!(audit.maximum_desired_state_value_bytes_v2().unwrap(), 4096);
        assert_eq!(audit.native.state().unwrap().get(&(RecordNamespace::DesiredState, vec![7])).unwrap().len(), 8);
    }

    #[test]
    fn failed_native_registration_keeps_the_actual_cursor_cause_and_partial_map() {
        let mut file = tempfile::tempfile().unwrap();
        let sequence = append(&mut file, 1, 1, vec![8]);
        append(&mut file, 1, sequence, vec![9]);
        let bytes = file.metadata().unwrap().len();
        let mut audit = RootControllerReadonlyGeometryAuditV1::new();

        audit.entered = true;
        audit.result = Some(audit.observe_file_inner(&file, JournalLimits::default(), bytes));

        assert!(matches!(audit.result, Some(Err(_))));
        assert!(audit.native.report().is_none());
        assert!(audit.native.failure().is_some());
        assert!(audit.additional_semantic_demand_v1().is_err());
        let native = audit.native.failure().unwrap() as *const dyn Error as *const ();
        assert_eq!(audit.failure().unwrap() as *const dyn Error as *const (), native);
    }
}
