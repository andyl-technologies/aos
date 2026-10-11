//! Projects the fixed original device's terminal inventory constructor.
//!
//! Only MAC-authenticated Complete responses select these roles. FIRST node,
//! owner, operation, grant and native measurement must match the independently
//! inspected source publication. Future records remain data, not cut permission.

use std::collections::BTreeMap;

use crucible::{
    node_adapters::transcript::TranscriptAction,
    node_contract::{OperationOutcome, OwnerIdentity, ProgressEvidence},
    node_scheduling::NativePublication,
    node_state::StateError,
};
use crucible_node_contract::{ContentRef, Event, Id, canonical};
use crucible_node_provider::reference_device::DeviceReceipt;
use serde::{Deserialize, Serialize};

use super::{
    conditional_capture_records::insert, conditional_capture_scope::refused,
    conditional_profile::ConditionalProfile,
};

const MAXIMUM_BYTES: usize = 65_536;

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum OriginalComplete {
    Outcome(Box<OperationOutcome>),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingInventory {
    schema_version: u16,
    input_batch: Id,
    input_disposition: String,
    original_buffer_retained: bool,
    outputs_retained: bool,
    application_parked: bool,
    owner: OwnerIdentity,
}

/// Adds only inventories named by the original terminal response's typed closure.
pub(super) fn install(
    profile: &ConditionalProfile,
    rows: &mut BTreeMap<ContentRef, Vec<ContentRef>>,
) -> Result<(), StateError> {
    // The selected source has exactly nine single-output terminal windows.
    // Charge all candidate row/edge occurrences before typed vector copies.
    let count = profile
        .history
        .originals
        .values()
        .try_fold(0usize, |n, tape| {
            n.checked_add(
                tape.transcript()
                    .records
                    .iter()
                    .filter(|record| record.request.action == TranscriptAction::Complete)
                    .count(),
            )
        })
        .ok_or_else(|| refused("original terminal occurrence overflow"))?;
    let edges = rows
        .values()
        .try_fold(count, |n, row| n.checked_add(row.len()));
    if count != 9
        || rows.len().checked_add(count * 2).is_none_or(|n| n > 4096)
        || edges.is_none_or(|n| n > 65_536)
    {
        return Err(refused("original terminal inventory credit exhausted"));
    }

    for (node, source) in &profile.history.originals {
        let origin = &source.transcript().origin;
        for record in &source.transcript().records {
            if record.request.action != TranscriptAction::Complete {
                continue;
            }
            record.request.request_metadata().map_err(refused)?;
            let value = verified(&record.response, &record.response_bytes)?;
            response_credit(&value)?;
            let response: OriginalComplete = serde_json::from_value(value).map_err(refused)?;
            if canonical::canonical_json(&serde_json::to_value(&response).map_err(refused)?)
                .map_err(refused)?
                != record.response_bytes
            {
                return Err(refused("original terminal typed encoding differs"));
            }
            let OriginalComplete::Outcome(outcome) = response;
            let scheduling = outcome
                .scheduling
                .as_ref()
                .ok_or_else(|| refused("original terminal scheduling is absent"))?;
            if outcome.operation != record.request.identity
                || outcome.node != *node
                || outcome.owners != origin.route.owners
                || scheduling.node != *node
                || scheduling.owners != origin.route.owners
            {
                return Err(refused(
                    "original FIRST terminal owner or operation differs",
                ));
            }
            let claim = profile
                .history
                .publications
                .iter()
                .find(|claim| {
                    claim.origin.operation_id == outcome.operation
                        && claim.origin.execution_owner_id == origin.route.owners[0].owner
                })
                .ok_or_else(|| refused("original terminal native claim is absent"))?;
            let event: Event = read(profile, &claim.published)?;
            // The full measurement codec and predecessor were independently
            // checked before this table. This exact native field is its receipt.
            let measurement = verified(
                &claim.origin.measurement,
                body(profile, &claim.origin.measurement)?,
            )?;
            if measurement
                .get("schema")
                .and_then(serde_json::Value::as_str)
                != Some("crucible.reference.lineage-measurement.v1")
            {
                return Err(refused("original measurement edition differs"));
            }
            let native: DeviceReceipt = serde_json::from_value(
                measurement
                    .get("native")
                    .cloned()
                    .ok_or_else(|| refused("original native receipt is absent"))?,
            )
            .map_err(refused)?;
            let ProgressEvidence::Quantized {
                window,
                publication,
                closure,
                ..
            } = &outcome.progress
            else {
                return Err(refused("original terminal is not quantized"));
            };
            if window != &claim.origin.grant_id
                || publication != &event.publication_position
                || native.grant.window_id != *window
                || native.grant.publication != *publication
                || native.grant.input_batch_id != closure.input_batch
                || closure.close_receipt != claim.origin.measurement
                || closure.clock_evidence != claim.origin.measurement
                || scheduling.proof_ref != claim.origin.measurement
                || scheduling.publications.len() != 1
                || outcome.retained_outputs != vec![event.id.clone()]
            {
                return Err(refused("original terminal grant or measurement differs"));
            }

            let outputs: Vec<NativePublication> = read(profile, &closure.output_inventory)?;
            if outputs != scheduling.publications || outputs.len() != 1 {
                return Err(refused("original terminal output inventory differs"));
            }
            let output = &outputs[0];
            if output.publication_id != event.id
                || output.endpoint != event.source
                || output.native_sequence != event.source_sequence
                || output.publication != event.publication_position
                || output.payload != event.payload
                || output.evaluation.is_some()
                || !output.causal_parents.is_empty()
                || !event.causal_parent_ids.is_empty()
                || body(profile, &output.payload)? != output.payload_bytes
            {
                return Err(refused("original terminal publication/FIFO/body differs"));
            }
            output
                .payload
                .verify(&output.payload_bytes)
                .map_err(refused)?;
            let pending: PendingInventory = read(profile, &closure.pending_inventory)?;
            if pending.schema_version != 1
                || pending.input_batch != closure.input_batch
                || pending.input_disposition != "consumed"
                || !pending.original_buffer_retained
                || !pending.outputs_retained
                || pending.application_parked != native.application_parked
                || !pending.application_parked
                || pending.owner != origin.route.owners[0]
            {
                return Err(refused("original terminal retained disposition differs"));
            }
            // Role selection came from this exact MAC terminal, not body shape.
            // Pending fields are scalar; inline outputs retain payload edges.
            insert(
                rows,
                closure.output_inventory.clone(),
                vec![output.payload.clone()],
            )?;
            insert(rows, closure.pending_inventory.clone(), Vec::new())?;
        }
    }
    Ok(())
}

fn body<'a>(
    profile: &'a ConditionalProfile,
    reference: &ContentRef,
) -> Result<&'a [u8], StateError> {
    profile
        .history
        .objects
        .get(reference)
        .map(Vec::as_slice)
        .ok_or_else(|| refused("original terminal body is absent"))
}

fn read<T: serde::de::DeserializeOwned + Serialize>(
    profile: &ConditionalProfile,
    reference: &ContentRef,
) -> Result<T, StateError> {
    let value = verified(reference, body(profile, reference)?)?;
    // This exact source emits one small publication and <=4096 payload bytes.
    if let Some(array) = value.as_array()
        && (array.len() != 1
            || array[0]
                .get("payload_bytes")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|bytes| bytes.len() > 4096))
    {
        return Err(refused("original terminal output copy credit exhausted"));
    }
    let typed: T = serde_json::from_value(value).map_err(refused)?;
    if canonical::canonical_json(&serde_json::to_value(&typed).map_err(refused)?)
        .map_err(refused)?
        != body(profile, reference)?
    {
        return Err(refused("original terminal typed body encoding differs"));
    }
    Ok(typed)
}

fn verified(reference: &ContentRef, bytes: &[u8]) -> Result<serde_json::Value, StateError> {
    reference.verify(bytes).map_err(refused)?;
    let value = canonical::parse_json(bytes, MAXIMUM_BYTES).map_err(refused)?;
    if canonical::canonical_json(&value).map_err(refused)? != bytes {
        return Err(refused("original terminal role is not canonical"));
    }
    Ok(value)
}

fn response_credit(value: &serde_json::Value) -> Result<(), StateError> {
    let outcome = value
        .get("value")
        .ok_or_else(|| refused("original terminal value is absent"))?;
    let scheduling = outcome
        .get("scheduling")
        .ok_or_else(|| refused("original terminal scheduling is absent"))?;
    array(outcome, "owners", 1)?;
    array(outcome, "retained_outputs", 1)?;
    array(scheduling, "owners", 1)?;
    array(scheduling, "bounds", 1)?;
    array(scheduling, "external_inputs", 0)?;
    let publications = array(scheduling, "publications", 1)?;
    if publications.len() != 1 {
        return Err(refused("original terminal publication count differs"));
    }
    array(&publications[0], "payload_bytes", 4096)?;
    array(&publications[0], "causal_parents", 0)?;
    array(&scheduling["input_progress"], "consumed", 64)?;
    Ok(())
}

fn array<'a>(
    object: &'a serde_json::Value,
    key: &str,
    maximum: usize,
) -> Result<&'a Vec<serde_json::Value>, StateError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_array)
        .filter(|items| items.len() <= maximum)
        .ok_or_else(|| refused("original terminal named-array credit exhausted"))
}
