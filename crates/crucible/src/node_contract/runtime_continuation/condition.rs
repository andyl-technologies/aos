//! Closed historical condition-control validation without restoring live authority.
//!
//! This selected-edition decoder validates the unchanged original stop/report,
//! native ACK and resume journal. Installed native continuation verification
//! separately authenticates every original body and fresh owner custody.

use super::*;
use crate::node_contract::{
    ConditionControlRequest, ConditionPublicationState, ProgressEvidence, SavedConditionStop,
};
use crucible_node_contract::{Validate, canonical};

pub(super) fn validate(snapshot: &RuntimeSnapshot) -> Result<(), RuntimeError> {
    let has_controls = snapshot.operations.iter().any(|operation| {
        matches!(operation.request, OperationRequest::DebugConditionV1(_))
            || matches!(&operation.result,
                SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome)
                if matches!(outcome.progress, ProgressEvidence::DebugConditionAppliedV1 { .. }))
    });
    let Some(saved) = &snapshot.condition_stop else {
        return if snapshot.schema_version != 6 && !has_controls {
            Ok(())
        } else {
            Err(RuntimeError::InvalidReceipt)
        };
    };
    validate_saved(snapshot, saved)
}

// Canonical indexes deliberately omit native body ownership. Static validation
// accepts that representation; the separate installed native gate must reopen
// and authenticate every original body before fresh custody is constructed.
fn validate_saved(
    snapshot: &RuntimeSnapshot,
    saved: &SavedConditionStop,
) -> Result<(), RuntimeError> {
    let record = &saved.record;
    saved
        .reference
        .verify(&encode(record)?)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if snapshot.schema_version != 6
        || snapshot.terminal.is_some()
        || record.version != 1
        || record.source.world_binding_hash != snapshot.source_activation.world_binding_hash
        || record.source.generation > snapshot.source_activation.generation
        || record.cut > snapshot.capture_cut
        || (!saved.resumed && record.cut != snapshot.capture_cut)
        || record.hit.input.consumer != record.node
        || record.hit.evaluation > record.cut
        || record.hit.evaluation.time_ps != record.cut.time_ps
        || record.native.is_empty()
        || record.native.len() > 256
        || record.source.generation.get() == 0
        || record
            .source
            .owners
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || record
            .native
            .windows(2)
            .any(|pair| pair[0].node >= pair[1].node)
        || saved.report.is_some() != saved.publication.is_some()
        || saved.resume_receipt.is_some() != saved.resume_publication.is_some()
    {
        return Err(RuntimeError::InvalidReceipt);
    }

    record
        .source
        .activation_id
        .validate()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    record
        .source
        .world_binding_hash
        .validate()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let mut original_owners = Vec::new();
    for inventory in &record.native {
        inventory
            .receipt
            .reference
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if !inventory.receipt.bytes.is_empty() {
            inventory
                .receipt
                .reference
                .verify(&inventory.receipt.bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }
        if inventory.boundary != record.cut
            || inventory.receipt.reference.length.get() == 0
            || inventory.owners.is_empty()
            || inventory.owners.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        original_owners.extend(inventory.owners.iter().cloned());
    }
    original_owners.sort();
    if original_owners.windows(2).any(|pair| pair[0] == pair[1])
        || original_owners != record.source.owners
        || original_owners
            .iter()
            .map(|owner| &owner.owner)
            .collect::<Vec<_>>()
            != snapshot
                .source_activation
                .owners
                .iter()
                .map(|owner| &owner.owner)
                .collect::<Vec<_>>()
    {
        return Err(RuntimeError::InvalidReceipt);
    }

    let controls: Vec<_> = snapshot
        .operations
        .iter()
        .filter(|operation| {
            matches!(operation.request, OperationRequest::DebugConditionV1(_))
                || matches!(
                    &operation.result,
                    SavedRuntimeResult::Complete(outcome)
                        | SavedRuntimeResult::Acknowledged(outcome)
                        if matches!(outcome.progress, ProgressEvidence::DebugConditionAppliedV1 { .. })
                )
        })
        .collect();
    // The initial preservation scope starts only after a complete original
    // stop. Pending or uncertain native control is not relabeled preservable.
    if !saved.submitted || controls.len() != 1 + usize::from(saved.resume_operation.is_some()) {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let stop = controls
        .iter()
        .find(|operation| operation.operation == record.operation)
        .ok_or(RuntimeError::InvalidReceipt)?;
    if !matches!(&stop.request,
        OperationRequest::DebugConditionV1(request)
            if matches!(request.as_ref(), ConditionControlRequest::Stop {barrier, receipt}
                if encode(barrier.as_ref())? == encode(record)? && receipt == &saved.reference))
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let report = saved.report.as_ref().ok_or(RuntimeError::InvalidReceipt)?;
    let original_report = encode(&serde_json::json!({
        "format": "crucible.host-condition-stop-report",
        "version": 1,
        "stop_operation": record.operation,
        "node": record.node,
        "condition": record.hit.condition,
        "source": record.source,
        "triggering_evaluation": record.hit.evaluation,
        "actual_stopped_cut": record.cut,
        "original_input": record.hit.input,
        "original_outcome": record.hit.outcome,
        "barrier": saved.reference,
        "canonical": true,
        "mutates_guest_memory": false,
    }))?;
    if report.bytes != original_report {
        return Err(RuntimeError::InvalidReceipt);
    }
    validate_outcome(stop, saved, report, false, saved.acknowledged)?;
    if saved.acknowledged && saved.publication != Some(ConditionPublicationState::Committed) {
        return Err(RuntimeError::InvalidReceipt);
    }

    let Some(resume_operation) = &saved.resume_operation else {
        return if saved.resume_receipt.is_none() && !saved.resumed {
            Ok(())
        } else {
            Err(RuntimeError::InvalidReceipt)
        };
    };
    if !saved.acknowledged || resume_operation == &record.operation {
        return Err(RuntimeError::InvalidReceipt);
    }
    let resume = controls
        .iter()
        .find(|operation| &operation.operation == resume_operation)
        .ok_or(RuntimeError::InvalidReceipt)?;
    if !matches!(&resume.request,
        OperationRequest::DebugConditionV1(request)
            if matches!(request.as_ref(), ConditionControlRequest::Resume {stop_operation,barrier,report: original_report}
                if stop_operation == &record.operation && barrier == &saved.reference
                    && original_report == &report.reference))
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let receipt = saved
        .resume_receipt
        .as_ref()
        .ok_or(RuntimeError::InvalidReceipt)?;
    validate_outcome(resume, saved, receipt, true, saved.resumed)?;
    if saved.resumed && saved.resume_publication != Some(ConditionPublicationState::Committed) {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

/// Checks original authenticated bodies independently of the historical marker.
///
/// This routine creates no live fence or current result-store permit. The
/// caller retains the installed native proof and complete fresh-world custody.
pub(super) fn validate_reopened(
    snapshot: &RuntimeSnapshot,
    saved: &SavedConditionStop,
    limits: RuntimeLimits,
    maximum_bytes: usize,
) -> Result<(), RuntimeError> {
    let encoded = snapshot
        .condition_stop
        .as_ref()
        .ok_or(RuntimeError::InvalidReceipt)?;
    if encode(encoded)? != encode(saved)? {
        return Err(RuntimeError::InvalidReceipt);
    }
    validate_saved(snapshot, saved)?;
    let maximum_objects = limits
        .maximum_operations
        .checked_mul(16)
        .and_then(|count| count.checked_add(64))
        .map(|count| count.min(65_536))
        .ok_or(RuntimeError::ResourceLimit)?;
    let mut objects = BTreeMap::new();
    let mut remaining = maximum_bytes;
    for object in saved.record.dependency_objects() {
        if object.bytes.is_empty() || object.reference.verify(&object.bytes).is_err() {
            return Err(RuntimeError::InvalidReceipt);
        }
        match objects.entry(object.reference.hash.clone()) {
            std::collections::btree_map::Entry::Occupied(previous) => {
                if *previous.get() != object {
                    return Err(RuntimeError::InvalidReceipt);
                }
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                remaining = remaining
                    .checked_sub(object.bytes.len())
                    .ok_or(RuntimeError::ResourceLimit)?;
                entry.insert(object);
            }
        }
        if objects.len() > maximum_objects {
            return Err(RuntimeError::ResourceLimit);
        }
    }
    saved
        .record
        .verify_dependency_closure(
            &objects.into_values().collect::<Vec<_>>(),
            maximum_objects,
            maximum_bytes,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(())
}

fn validate_outcome(
    original: &SavedRuntimeOperation,
    saved: &SavedConditionStop,
    control: &InputPayload,
    resumed: bool,
    acknowledged: bool,
) -> Result<(), RuntimeError> {
    control
        .reference
        .verify(&control.bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let outcome = match &original.result {
        SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
            outcome
        }
        _ => return Err(RuntimeError::UnsupportedFacet),
    };
    let report = saved.report.as_ref().ok_or(RuntimeError::InvalidReceipt)?;
    if original.route.node != saved.record.node
        || original.input_batch.is_some()
        || original.scheduling_commit.is_some()
        || !outcome.retained_outputs.is_empty()
        || outcome.scheduling.is_some()
        || original.close_submission.is_some()
        || original.submission_effects.is_some()
        || acknowledged != matches!(original.result, SavedRuntimeResult::Acknowledged(_))
        || !matches!(&outcome.progress,
            ProgressEvidence::DebugConditionAppliedV1 {
                reached,stop_operation,barrier,report: original_report,control: original_control,resumed: applied
            } if *reached == saved.record.cut && stop_operation == &saved.record.operation
                && barrier == &saved.reference && original_report == &report.reference
                && original_control == &control.reference && *applied == resumed)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, RuntimeError> {
    canonical::canonical_json(
        &serde_json::to_value(value).map_err(|_| RuntimeError::InvalidReceipt)?,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)
}
