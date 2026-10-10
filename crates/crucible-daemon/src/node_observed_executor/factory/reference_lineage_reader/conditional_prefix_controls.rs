//! Checks copied adverse views of the actual conditional prefix.
//!
//! These fixture-only controls preserve live runtime ownership, pending tokens
//! and source bodies. Their bounded copies change one receipt role or Stage ID;
//! the independently installed validator must refuse each altered view.

#![cfg(test)]

use crucible::{
    node_admission::AdmittedGraph, node_contract::OriginalLineageRuntimeRecord,
    node_scheduling::SchedulingSnapshot,
};
use crucible_node_contract::{Id, Phase, Position};

use super::{
    conditional_capture_factory::ConditionalCaptureFactory,
    conditional_profile::ConditionalProfile, conditional_source::InspectionError,
};

/// Refuses original Stop and altered-media references in both Measurement roles.
pub(super) fn receipt_roles(
    profile: &ConditionalProfile,
    graph: &AdmittedGraph,
    factory: &ConditionalCaptureFactory,
    record: &OriginalLineageRuntimeRecord,
    original_record_bytes: usize,
) -> Result<(), InspectionError> {
    // The authentic Measurement and Stop are distinct typed receipts. This
    // finite negative view changes only that role after the exact view passes;
    // it never alters the original runtime or its held q2 permission.
    if original_record_bytes > 8 * 1024 * 1024 {
        return Err("original prefix exceeds its fixed metadata copy credit".into());
    }
    let mut wrong_receipt = record.clone();
    let operation = wrong_receipt
        .operations
        .iter_mut()
        .find(|entry| {
            matches!(
                entry.result,
                crucible::node_contract::SavedRuntimeResult::Acknowledged(_)
            )
        })
        .ok_or("original acknowledged operation absent")?;
    let claim = profile
        .history
        .publications
        .iter()
        .find(|claim| {
            claim.origin.operation_id == operation.operation
                && claim.origin.execution_owner_id == operation.route.owners[0].owner
        })
        .ok_or("native original receipt association absent")?;
    if claim.origin.measurement == claim.origin.stop_receipt {
        return Err("distinct original Measurement and Stop roles collapsed".into());
    }
    let crucible::node_contract::SavedRuntimeResult::Acknowledged(outcome) = &mut operation.result
    else {
        return Err("original acknowledged view changed".into());
    };
    outcome
        .scheduling
        .as_mut()
        .ok_or("original scheduling view absent")?
        .proof_ref = claim.origin.stop_receipt.clone();
    if factory.authenticate_prefix(graph, &wrong_receipt).is_ok() {
        return Err("original Stop receipt was accepted as Measurement".into());
    }
    let operation = wrong_receipt
        .operations
        .iter_mut()
        .find(|entry| {
            matches!(
                entry.result,
                crucible::node_contract::SavedRuntimeResult::Acknowledged(_)
            )
        })
        .ok_or("negative acknowledged view absent")?;
    let crucible::node_contract::SavedRuntimeResult::Acknowledged(outcome) = &mut operation.result
    else {
        return Err("negative acknowledged view changed".into());
    };
    let proof = &mut outcome
        .scheduling
        .as_mut()
        .ok_or("negative scheduling view absent")?
        .proof_ref;
    *proof = claim.origin.measurement.clone();
    proof.media_type = "application/octet-stream".into();
    if factory.authenticate_prefix(graph, &wrong_receipt).is_ok() {
        return Err("altered full Measurement media role was accepted".into());
    }
    // Reuse the same bounded view after restoring its original scheduling
    // receipt. Delivery provenance has the same Measurement role, while its
    // ordered lineage keeps the independently authenticated Stop root.
    let operation = wrong_receipt
        .operations
        .iter_mut()
        .find(|entry| entry.operation == claim.origin.operation_id)
        .ok_or("negative original operation absent")?;
    let crucible::node_contract::SavedRuntimeResult::Acknowledged(outcome) = &mut operation.result
    else {
        return Err("negative original outcome changed".into());
    };
    outcome
        .scheduling
        .as_mut()
        .ok_or("negative original scheduling absent")?
        .proof_ref = claim.origin.measurement.clone();
    let input_index = record
        .inputs
        .iter()
        .position(|input| !input.deliveries.is_empty())
        .ok_or("original consumed delivery absent")?;
    let delivered_claim = record.inputs[input_index]
        .lineage
        .as_ref()
        .and_then(|lineage| lineage.publications.first())
        .ok_or("original delivered lineage absent")?;
    if delivered_claim.origin.measurement == delivered_claim.origin.stop_receipt {
        return Err("distinct delivered Measurement and Stop roles collapsed".into());
    }
    wrong_receipt.inputs[input_index].deliveries[0].provenance_ref =
        delivered_claim.origin.stop_receipt.clone();
    if factory.authenticate_prefix(graph, &wrong_receipt).is_ok() {
        return Err("delivered Stop receipt was accepted as Measurement".into());
    }
    let delivered_proof = &mut wrong_receipt.inputs[input_index].deliveries[0].provenance_ref;
    *delivered_proof = delivered_claim.origin.measurement.clone();
    delivered_proof.media_type = "application/octet-stream".into();
    if factory.authenticate_prefix(graph, &wrong_receipt).is_ok() {
        return Err("altered full delivered Measurement media role was accepted".into());
    }
    Ok(())
}

/// Refuses a missing or foreign Stage ID after the actual scheduler is accepted.
pub(super) fn scheduler_roster(
    profile: &ConditionalProfile,
    record: &OriginalLineageRuntimeRecord,
    scheduler: &SchedulingSnapshot,
    original_scheduler_bytes: usize,
) -> Result<(), InspectionError> {
    super::conditional_capture_scope::authenticate_scheduler(profile, record, scheduler)
        .map_err(text)?;
    if original_scheduler_bytes > 8 * 1024 * 1024 {
        return Err("original scheduler exceeds fixed metadata copy credit".into());
    }
    let stage = &record.inputs[0].stage_operation;
    let stage_index = scheduler
        .used_operations
        .iter()
        .position(|id| id == stage)
        .ok_or("original scheduler Stage ID absent")?;
    let mut changed_scheduler = scheduler.clone();
    changed_scheduler.used_operations.remove(stage_index);
    if super::conditional_capture_scope::authenticate_scheduler(profile, record, &changed_scheduler)
        .is_ok()
    {
        return Err("missing original Stage ID was accepted".into());
    }
    changed_scheduler
        .used_operations
        .insert(stage_index, identity("foreign/stage".into())?);
    if super::conditional_capture_scope::authenticate_scheduler(profile, record, &changed_scheduler)
        .is_ok()
    {
        return Err("foreign Stage ID replaced original admission".into());
    }
    // Restore the exact Stage ID before independently changing only the retained
    // unconsumed delivery roster, preserving all original input/native receipts.
    changed_scheduler.used_operations[stage_index] = stage.clone();
    if scheduler.pending_deliveries.len() != 2 {
        return Err("declared original pending delivery roster differs".into());
    }
    changed_scheduler.pending_deliveries.remove(0);
    if super::conditional_capture_scope::authenticate_scheduler(profile, record, &changed_scheduler)
        .is_ok()
    {
        return Err("missing original pending delivery was accepted".into());
    }
    changed_scheduler
        .pending_deliveries
        .insert(0, scheduler.pending_deliveries[0].clone());
    changed_scheduler.pending_deliveries[0]
        .provenance_ref
        .media_type = "application/octet-stream".into();
    if super::conditional_capture_scope::authenticate_scheduler(profile, record, &changed_scheduler)
        .is_ok()
    {
        return Err("changed full original pending delivery was accepted".into());
    }
    // Restore that complete Delivery before changing only the exclusive quantum
    // end phase. The committed cursor is BoundaryControl; its permission end is
    // the original Publication coordinate and cannot be normalized to that cut.
    changed_scheduler.pending_deliveries[0] = scheduler.pending_deliveries[0].clone();
    let crucible::node_scheduling::SavedPermission::Quantum { end, .. } =
        &mut changed_scheduler.reservations[0].permission
    else {
        return Err("original quantum reservation grammar changed".into());
    };
    *end = Position::new(end.time_ps, end.microstep, Phase::BoundaryControl);
    if super::conditional_capture_scope::authenticate_scheduler(profile, record, &changed_scheduler)
        .is_ok()
    {
        return Err("BoundaryControl substituted for original Publication end".into());
    }
    Ok(())
}

fn identity(value: String) -> Result<Id, InspectionError> {
    Id::new(value).map_err(text)
}

fn text(error: impl std::fmt::Display) -> InspectionError {
    error.to_string().into()
}
