//! Compares first-restoration families with their complete original custody.
//!
//! Original protocol bodies stay owned by the opaque initial15 group. Current
//! admissions/batches carry a fresh World and owner incarnation, while the
//! literal requests, results, input bytes and first lineage remain unchanged.

use super::super::installed_restoration::{
    historical_outcome_correspondence17_counter_scratch_data as outcome_counter_scratch_data,
    historical_outcome_correspondence17_data as outcome_correspondence_data,
};
use super::*;
use crate::{
    node_adapters::cnp::{OriginalInitial15ArchivedGroup, OriginalInitial15ArchivedOwnerRead},
    node_contract::{
        OriginalLineageInputRecord, OriginalLineageNativeScope, OwnerIdentity,
        SavedRuntimeOperation, SavedRuntimeResult,
    },
    node_scheduling::NativeInputAcknowledgement,
};
use crucible_node_format::Validate;

use record::{AdmissionRecord17, BatchRecord17, HistoricalAdmission17, HistoricalBatch17};
use std::mem::size_of;

#[cfg(test)]
#[path = "initial15/tests.rs"]
mod tests;

impl CnpRestoredSettledValidatedNode17 {
    /// Compares complete imported families against actual initial15 owners.
    ///
    /// `restoration` is the independently verified historical native/mapping
    /// scope, including the actual fresh ACK roster. It is DATA, not a live
    /// context. The owning collector must establish its native/SDK provenance
    /// before this comparison and precharge this method's fixed scratch row.
    ///
    /// # Errors
    /// Refuses missing/extra imported owners, a changed literal body or fullref,
    /// lost result/effect/lineage knowledge, a changed fresh ACK roster, another
    /// fresh World or any transformation outside the defining restore behavior.
    pub(crate) fn authenticate_initial15_originals_data(
        &self,
        original: &OriginalInitial15ArchivedOwnerRead<'_>,
        current: &OriginalLineageRuntimeRecord,
        restoration: &OriginalLineageNativeScope,
    ) -> Result<(), RuntimeError> {
        let (semantic_reference, semantics) = original
            .semantic_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let previous = original
            .original_runtime_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let journal = original
            .journal_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let common = semantics.source_common_data();

        let (original_operations, original_inputs) = original
            .original_generic_counts_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let (maximum_operations, _, _, _) = original
            .original_semantic_caps_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let current_associations = self
            .family_counts_data()?
            .into_iter()
            .try_fold(0usize, |total, count| {
                total.checked_add(count).ok_or(RuntimeError::ResourceLimit)
            })?;
        if original_operations != common.operations.len()
            || original_inputs != common.inputs.len()
            || current_associations > maximum_operations
        {
            return Err(RuntimeError::InvalidReceipt);
        }

        // The actual first-restoration writer emits null, unlike a later
        // Node17-to-Node25 installation with an inherited immutable family root.
        if self.record.restored_families.is_some()
            || restoration.source_record != journal.runtime
            || restoration.source_capture != previous.source_activation
            || common.active.as_ref() != Some(&previous.source_activation)
            || !same_target_data(&restoration.target, &current.source_activation)
            || self.record.base.active.as_ref() != Some(&current.source_activation)
            || journal.semantic != *semantic_reference
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        authenticate_scope_roster_data(previous, current, restoration)?;
        authenticate_owner_mapping_data(previous, current, &self.route, restoration)?;
        authenticate_native_journal_data(previous, &self.route.node, restoration)?;

        let previous_operations = previous
            .operations
            .iter()
            .filter(|saved| saved.route.node == self.route.node)
            .count();
        let previous_inputs = previous
            .inputs
            .iter()
            .filter(|saved| saved.node == self.route.node)
            .count();
        if self.record.original_operations.len() != previous_operations
            || common.operations.len() != previous_operations
            || self.record.original_inputs.len() != previous_inputs
            || common.inputs.len() != previous_inputs
            || !self
                .record
                .original_operations
                .iter()
                .map(|row| {
                    let HistoricalAdmission17::Admission(row) = row;
                    &row.operation
                })
                .eq(previous
                    .operations
                    .iter()
                    .filter(|row| row.route.node == self.route.node)
                    .map(|row| &row.operation))
            || !self
                .record
                .original_inputs
                .iter()
                .map(|row| {
                    let HistoricalBatch17::InputBatch(row) = row;
                    &row.stage_operation
                })
                .eq(previous
                    .inputs
                    .iter()
                    .filter(|row| row.node == self.route.node)
                    .map(|row| &row.stage_operation))
        {
            return Err(RuntimeError::InvalidReceipt);
        }

        for original in &self.record.original_operations {
            let HistoricalAdmission17::Admission(admission) = original;
            let saved = unique_operation_data(previous, &self.route.node, &admission.operation)?;
            let current = unique_operation_data(current, &self.route.node, &admission.operation)?;
            authenticate_operation_data(saved, current, admission, &self.route)?;

            let mut common_rows = common
                .operations
                .values()
                .filter(|row| row.operation == saved.operation);
            let old = common_rows.next().ok_or(RuntimeError::InvalidReceipt)?;
            if common_rows.next().is_some()
                || old.request != admission.request
                || old.route != saved.route
                || old.activation != previous.source_activation
                || old.inputs.as_ref().map(|input| &input.batch) != saved.input_batch.as_ref()
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            match (old.inputs.as_ref(), admission.inputs.as_ref()) {
                (None, None) => {}
                (Some(old), Some(fresh)) => {
                    // Compare actual bytes, not merely a digest/length pair.
                    if old.node != fresh.node
                        || old.stage_operation != fresh.stage_operation
                        || old.batch != fresh.batch
                        || old.cutoff != fresh.cutoff
                        || old.inventory != fresh.inventory
                        || old.deliveries != fresh.deliveries
                        || old.payloads != fresh.payloads
                    {
                        return Err(RuntimeError::InvalidReceipt);
                    }
                }
                _ => return Err(RuntimeError::InvalidReceipt),
            }
        }

        for original in &self.record.original_inputs {
            let HistoricalBatch17::InputBatch(batch) = original;
            let saved = unique_input_data(previous, &self.route.node, &batch.stage_operation)?;
            let fresh = unique_input_data(current, &self.route.node, &batch.stage_operation)?;
            authenticate_input_data(saved, fresh, batch, &self.route, restoration)?;

            let mut common_rows = common
                .inputs
                .values()
                .filter(|row| row.original.stage_operation == saved.stage_operation);
            let old = common_rows.next().ok_or(RuntimeError::InvalidReceipt)?;
            if common_rows.next().is_some()
                || old.original.activation != previous.source_activation
                || old.original.node != batch.node
                || old.original.batch != batch.batch
                || old.original.cutoff != batch.cutoff
                || old.original.inventory != batch.inventory
                || old.original.deliveries != batch.deliveries
                || old.original.payloads != batch.payloads
                || old.acknowledgement != saved.acknowledgement
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }

        // The original group retains the full old common/ancestry/protocol
        // owners. Fresh base/Producer owners are separately validated by the
        // strict Node25 and Source17 readers against current Runtime/Scheduler.
        // Their native IDs cannot be substituted for an imported owner's ID.
        for saved in previous
            .operations
            .iter()
            .filter(|saved| saved.route.node == self.route.node)
        {
            if self.operation_family_data(&saved.operation)?
                != CnpRestoredNode17OperationFamily::Imported
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        for saved in previous
            .inputs
            .iter()
            .filter(|saved| saved.node == self.route.node)
        {
            if self.input_family_data(&saved.stage_operation)?
                != CnpRestoredNode17InputFamily::Imported
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        original
            .semantic_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        Ok(())
    }

    /// Counts defining comparison frames without allocating any comparison tree.
    pub(crate) fn initial15_correspondence_counter_scratch_data() -> usize {
        OriginalInitial15ArchivedGroup::counter_scratch_data()
            + outcome_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&OriginalInitial15ArchivedOwnerRead<'static>>()
            + size_of::<&OriginalLineageRuntimeRecord>() * 3
            + size_of::<&OriginalLineageNativeScope>()
            + size_of::<&NodeRoute>()
            + size_of::<&SavedRuntimeOperation>() * 3
            + size_of::<&OriginalLineageInputRecord>() * 3
            + size_of::<Option<&SavedRuntimeOperation>>()
            + size_of::<Option<&OriginalLineageInputRecord>>()
            + size_of::<Result<&SavedRuntimeOperation, RuntimeError>>()
            + size_of::<Result<&OriginalLineageInputRecord, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::slice::Iter<'static, SavedRuntimeOperation>>() * 3
            + size_of::<std::slice::Iter<'static, OriginalLineageInputRecord>>() * 3
            + size_of::<std::slice::Iter<'static, HistoricalAdmission17>>()
            + size_of::<std::slice::Iter<'static, HistoricalBatch17>>()
            + size_of::<std::slice::Iter<'static, OwnerIdentity>>() * 2
            + size_of::<std::slice::Iter<'static, NativeInputAcknowledgement>>()
            + size_of::<std::slice::Iter<'static, crate::node_contract::OriginalLineageOwnerMapping>>(
            )
            + size_of::<std::slice::Iter<'static, crate::node_contract::OriginalLineageJournal>>()
            + size_of::<std::slice::Iter<'static, Id>>() * 4
            + size_of::<[&ContentRef; 8]>()
            + size_of::<[usize; 8]>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<Result<usize, RuntimeError>>()
    }
}

fn same_target_data(
    target: &crate::node_contract::ActivationRecord,
    saved: &crate::node_contract::SavedRuntimeActivation,
) -> bool {
    target.generation == saved.generation
        && target.activation_id == saved.activation_id
        && target.world_binding_hash == saved.world_binding_hash
        && target.owners == saved.owners
        && target.boundary == saved.boundary
}

fn authenticate_scope_roster_data(
    previous: &OriginalLineageRuntimeRecord,
    current: &OriginalLineageRuntimeRecord,
    restoration: &OriginalLineageNativeScope,
) -> Result<(), RuntimeError> {
    if restoration.owners.len() != previous.owners.len()
        || restoration.owners.len() != current.source_activation.owners.len()
        || !restoration.first_scopes.iter().eq(previous
            .inputs
            .iter()
            .filter_map(|input| input.lineage.as_ref().map(|lineage| &lineage.source)))
        || restoration.input_acknowledgements.len()
            != previous
                .inputs
                .iter()
                .filter(|input| input.acknowledgement.is_some())
                .count()
        || restoration
            .input_acknowledgements
            .windows(2)
            .any(|pair| pair[0].stage_operation >= pair[1].stage_operation)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for (mapping, old) in restoration.owners.iter().zip(&previous.owners) {
        if mapping.source != old.identity
            || mapping.source.owner != mapping.target.owner
            || mapping.target.incarnation == mapping.source.incarnation
            || mapping.target.generation <= mapping.source.generation
            || !current.source_activation.owners.contains(&mapping.target)
            || restoration
                .owners
                .iter()
                .filter(|other| other.target == mapping.target)
                .count()
                != 1
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

fn authenticate_owner_mapping_data(
    previous: &OriginalLineageRuntimeRecord,
    current: &OriginalLineageRuntimeRecord,
    route: &NodeRoute,
    restoration: &OriginalLineageNativeScope,
) -> Result<(), RuntimeError> {
    if restoration.coordinator_schema != 7
        || restoration.proof.validate().is_err()
        || route.owners.is_empty()
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for fresh in &route.owners {
        let mut mappings = restoration
            .owners
            .iter()
            .filter(|mapping| mapping.target == *fresh);
        let mapping = mappings.next().ok_or(RuntimeError::InvalidReceipt)?;
        if mappings.next().is_some()
            || mapping.source.owner != fresh.owner
            || mapping.source == mapping.target
            || mapping.target.generation <= mapping.source.generation
            || mapping.target.incarnation == mapping.source.incarnation
            || !previous.source_activation.owners.contains(&mapping.source)
            || !current.source_activation.owners.contains(fresh)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

fn authenticate_native_journal_data(
    previous: &OriginalLineageRuntimeRecord,
    node: &Id,
    restoration: &OriginalLineageNativeScope,
) -> Result<(), RuntimeError> {
    let mut journals = restoration
        .journals
        .iter()
        .filter(|journal| &journal.node == node);
    let journal = journals.next().ok_or(RuntimeError::InvalidReceipt)?;
    if journals.next().is_some()
        || !journal.operations.iter().eq(previous
            .operations
            .iter()
            .filter(|entry| &entry.route.node == node)
            .map(|entry| &entry.operation))
        || !journal.pending_operations.iter().eq(previous
            .operations
            .iter()
            .filter(|entry| {
                &entry.route.node == node && matches!(entry.result, SavedRuntimeResult::Pending)
            })
            .map(|entry| &entry.operation))
        || !journal.acknowledged_operations.iter().eq(previous
            .operations
            .iter()
            .filter(|entry| {
                &entry.route.node == node
                    && matches!(entry.result, SavedRuntimeResult::Acknowledged(_))
            })
            .map(|entry| &entry.operation))
        || !journal.input_stages.iter().eq(previous
            .inputs
            .iter()
            .filter(|entry| &entry.node == node)
            .map(|entry| &entry.stage_operation))
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

fn unique_operation_data<'a>(
    runtime: &'a OriginalLineageRuntimeRecord,
    node: &Id,
    operation: &Id,
) -> Result<&'a SavedRuntimeOperation, RuntimeError> {
    let mut rows = runtime
        .operations
        .iter()
        .filter(|row| &row.route.node == node && &row.operation == operation);
    let row = rows.next().ok_or(RuntimeError::InvalidReceipt)?;
    if rows.next().is_some() {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(row)
}

fn unique_input_data<'a>(
    runtime: &'a OriginalLineageRuntimeRecord,
    node: &Id,
    stage: &Id,
) -> Result<&'a OriginalLineageInputRecord, RuntimeError> {
    let mut rows = runtime
        .inputs
        .iter()
        .filter(|row| &row.node == node && &row.stage_operation == stage);
    let row = rows.next().ok_or(RuntimeError::InvalidReceipt)?;
    if rows.next().is_some() {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(row)
}

fn authenticate_operation_data(
    saved: &SavedRuntimeOperation,
    fresh: &SavedRuntimeOperation,
    admission: &AdmissionRecord17,
    route: &NodeRoute,
) -> Result<(), RuntimeError> {
    let SavedRuntimeOperation {
        operation: _,
        route: _,
        request: _,
        input_batch: _,
        result: _,
        close_submission: _,
        submission_effects: _,
        scheduling_commit: _,
    } = saved;
    if saved.operation != fresh.operation
        || admission.operation != saved.operation
        || saved.route.node != route.node
        || fresh.route != *route
        || admission.route != *route
        || saved.request != fresh.request
        || admission.request != saved.request
        || saved.input_batch != fresh.input_batch
        || saved.close_submission != fresh.close_submission
        || saved.submission_effects != fresh.submission_effects
        || saved.scheduling_commit != fresh.scheduling_commit
        || saved.route.owners.len() != route.owners.len()
        || saved
            .route
            .owners
            .iter()
            .zip(&route.owners)
            .any(|(old, fresh)| old.owner != fresh.owner)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    match (&saved.result, &fresh.result) {
        (SavedRuntimeResult::Pending, SavedRuntimeResult::Pending) => Ok(()),
        (SavedRuntimeResult::Failed(old), SavedRuntimeResult::Failed(fresh)) if old == fresh => {
            Ok(())
        }
        (SavedRuntimeResult::Complete(old), SavedRuntimeResult::Complete(fresh))
        | (SavedRuntimeResult::Acknowledged(old), SavedRuntimeResult::Acknowledged(fresh)) => {
            outcome_correspondence_data(old, &route.owners, fresh)
        }
        _ => Err(RuntimeError::InvalidReceipt),
    }
}

fn authenticate_input_data(
    saved: &OriginalLineageInputRecord,
    fresh: &OriginalLineageInputRecord,
    batch: &BatchRecord17,
    route: &NodeRoute,
    restoration: &OriginalLineageNativeScope,
) -> Result<(), RuntimeError> {
    let OriginalLineageInputRecord {
        node: _,
        stage_operation: _,
        batch: _,
        owners: _,
        cutoff: _,
        inventory: _,
        deliveries: _,
        payloads: _,
        provenance: _,
        lineage: _,
        acknowledgement: _,
        failure: _,
        committed: _,
        coordinator_committed: _,
    } = saved;
    if saved.node != fresh.node
        || saved.stage_operation != fresh.stage_operation
        || saved.batch != fresh.batch
        || saved.cutoff != fresh.cutoff
        || saved.inventory != fresh.inventory
        || saved.deliveries != fresh.deliveries
        || saved.payloads != fresh.payloads
        || saved.provenance != fresh.provenance
        || saved.lineage != fresh.lineage
        || saved.failure != fresh.failure
        || saved.committed != fresh.committed
        || saved.coordinator_committed != fresh.coordinator_committed
        || fresh.owners != route.owners
        || batch.owners != route.owners
        || batch.node != saved.node
        || batch.stage_operation != saved.stage_operation
        || batch.batch != saved.batch
        || batch.cutoff != saved.cutoff
        || batch.inventory != saved.inventory
        || batch.deliveries != saved.deliveries
        || batch
            .payloads
            .iter()
            .map(|body| &body.reference)
            .ne(saved.payloads.iter())
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    match (&saved.acknowledgement, &fresh.acknowledgement) {
        (None, None) => {
            if restoration
                .input_acknowledgements
                .iter()
                .any(|ack| ack.node == saved.node && ack.stage_operation == saved.stage_operation)
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        (Some(old), Some(fresh)) => {
            let mut roster = restoration.input_acknowledgements.iter().filter(|ack| {
                ack.node == saved.node && ack.stage_operation == saved.stage_operation
            });
            let actual = roster.next().ok_or(RuntimeError::InvalidReceipt)?;
            if roster.next().is_some()
                || actual != fresh
                || old.node != fresh.node
                || old.stage_operation != fresh.stage_operation
                || old.batch != fresh.batch
                || old.cutoff != fresh.cutoff
                || old.inventory != fresh.inventory
                || old.owners != saved.owners
                || fresh.owners != route.owners
                || fresh.proof_ref != restoration.proof
                || fresh.proof_ref == old.proof_ref
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        _ => return Err(RuntimeError::InvalidReceipt),
    }
    Ok(())
}
