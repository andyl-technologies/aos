//! Projects closed future owners from the actual selected two-event Producer.
//!
//! The wire projection is a structural superset of each supported lifecycle
//! request/terminal, not a message that may be sent. Each field is counted with
//! its defining contract bound, including repeated Poll outcome and Observe
//! batch owners. Malformed raw JSON is independently covered by ingress extent.

use super::*;
use crate::reference_packet::service::connected::PacketConnectedSourceProgram;
use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection as Projection;
use crucible_node_format::{Bytes, ContentRef};

pub(super) struct Projected {
    pub(super) wire: OriginalSerializationStorageData,
    pub(super) proof: OriginalSerializationStorageData,
    pub(super) report: OriginalSerializationStorageData,
    pub(super) upload_bytes: usize,
}

pub(super) fn population(
    input: &PacketRestoredProducerLifecycleInputs<'_>,
) -> Result<PacketRestoredProducerPopulationData, ProviderError> {
    let PacketConnectedSourceProgram::Producer { program } = &input.launch.program else {
        return Err(invalid());
    };
    let [private, output] = program.events.as_slice() else {
        return Err(invalid());
    };
    if private.payload.is_some()
        || output
            .payload
            .as_ref()
            .is_none_or(|payload| payload.as_slice().len() > 32)
        || input.producer.inventory.gate_closed
        || input.producer.grant.is_some()
        || !input.producer.inventory.retained_outputs.is_empty()
        || input.operation.start != input.producer.inventory.reached
        || input.operation.start > input.operation.limit
        || (input.operation.kind == BeginKind::ExactRun
            && (input.operation.limit.microstep.get() != 0
                || input.operation.limit.phase != crucible_node_format::Phase::BoundaryControl))
        || (input.operation.kind == BeginKind::BoundarySettle
            && input.operation.start.time_ps != input.operation.limit.time_ps)
        || !matches!(
            input.operation.kind,
            BeginKind::ExactRun | BeginKind::BoundarySettle
        )
        || input.arguments.maximum_authorization_bytes == 0
        || input.arguments.maximum_authorization_bytes > 8192
        || input.canonical_checkpoint.is_empty()
        || input.canonical_checkpoint.len() > 65_536
        || input.canonical_producer.is_empty()
        || input.canonical_producer.len() > 65_536
    {
        return Err(invalid());
    }
    let pending = input.producer.inventory.pending.as_slice();
    if pending.len() > program.events.len()
        || pending != &program.events[program.events.len() - pending.len()..]
        || pending
            .first()
            .is_some_and(|event| event.evaluation < input.operation.start)
    {
        return Err(invalid());
    }
    let completed = pending
        .iter()
        .take_while(|event| event.completion < input.operation.limit)
        .count();
    let mut newborn = 0usize;
    let mut payload_bytes = 0usize;
    let mut event_id_bytes = 0usize;
    for event in &pending[..completed] {
        if let Some(payload) = &event.payload {
            newborn = newborn.checked_add(1).ok_or_else(invalid)?;
            payload_bytes = payload_bytes
                .checked_add(payload.as_slice().len())
                .ok_or_else(invalid)?;
            event_id_bytes = event_id_bytes
                .checked_add(event.id.as_str().len())
                .ok_or_else(invalid)?;
        }
    }
    Ok(PacketRestoredProducerPopulationData {
        pending_before: pending.len(),
        pending_after: pending.len() - completed,
        completed,
        newborn,
        payload_bytes,
        event_id_bytes,
        operation_id_bytes: input.operation.operation.as_str().len(),
    })
}

pub(super) fn identity(input: &PacketRestoredProducerLifecycleInputs<'_>) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"restored-producer-lifecycle-quote/1");
    for bytes in [
        input.canonical_launch5,
        input.canonical_checkpoint,
        input.canonical_producer,
        input.operation.operation.as_str().as_bytes(),
    ] {
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hash.update(&input.arguments.maximum_authorization_bytes.to_le_bytes());
    hash.update(&(input.arguments.held.target_activation.as_str().len() as u64).to_le_bytes());
    hash.update(input.arguments.held.target_activation.as_str().as_bytes());
    hash.update(&input.arguments.held.target_generation.get().to_le_bytes());
    hash.update(&[match input.operation.kind {
        BeginKind::ExactRun => 0,
        BeginKind::BoundarySettle => 1,
        _ => 255,
    }]);
    for position in [input.operation.start, input.operation.limit] {
        hash.update(&position.time_ps.get().to_le_bytes());
        hash.update(&position.microstep.get().to_le_bytes());
        hash.update(&(position.phase as u16).to_le_bytes());
    }
    *hash.finalize().as_bytes()
}

pub(super) fn project(
    input: &PacketRestoredProducerLifecycleInputs<'_>,
    maximum: usize,
) -> Result<Projected, ProviderError> {
    let mut wire = Projection::new(maximum)?;
    envelope(&mut wire, input)?;
    let wire = wire.finish(maximum)?;
    let proof = crate::reference_packet::service::complete_restore::producer_progress::report_storage::projection(maximum)?;
    let report = crate::reference_packet::service::complete_restore::producer_progress::report_storage::projection(maximum)?;
    let upload_bytes = sum(&[
        input.arguments.maximum_authorization_bytes,
        consumption_bytes(input)?,
    ])?;
    Ok(Projected {
        wire,
        proof,
        report,
        upload_bytes,
    })
}

pub(super) fn originals(
    input: &PacketRestoredProducerLifecycleInputs<'_>,
    frame: usize,
) -> Result<usize, ProviderError> {
    let chunk = chunk_bytes(frame)?;
    let authorization = input.arguments.maximum_authorization_bytes;
    let consumption = consumption_bytes(input)?;
    let mut originals = 4usize; // Begin, Poll, Retire, fresh Observe.
    for bytes in [authorization, consumption] {
        let chunks = bytes.checked_add(chunk - 1).ok_or_else(invalid)? / chunk;
        originals = sum(&[originals, 2, chunks])?; // BlobBegin, every Chunk, BlobFinish.
    }
    if originals > 256 {
        return Err(invalid());
    }
    Ok(originals)
}

pub(in crate::reference_packet::service::native_startup::restored_suffix) fn chunk_bytes(
    frame: usize,
) -> Result<usize, ProviderError> {
    // The closed BlobChunk envelope has at most 32 fixed 128-byte identifier,
    // reference and key strings, plus 20-byte decimal coordinates. Charge each
    // with six-byte escaping rather than assuming the payload is the whole frame.
    let header = 32usize.checked_mul(128 * 6 + 20 + 8).ok_or_else(invalid)?;
    let encoded = frame.checked_sub(header).ok_or_else(invalid)?;
    let bytes = encoded
        .checked_div(4)
        .and_then(|n| n.checked_mul(3))
        .filter(|n| *n > 0)
        .ok_or_else(invalid)?;
    Ok(bytes.min(1_048_576))
}

fn consumption_bytes(
    input: &PacketRestoredProducerLifecycleInputs<'_>,
) -> Result<usize, ProviderError> {
    let population = population(input)?;
    // Actual three-field consumption serializer: fixed schema, same operation,
    // and exactly the new original event IDs. Every identifier can escape fully.
    sum(&[
        128,
        mul(6, input.operation.operation.as_str().len())?,
        mul(population.newborn, 128 * 6 + 3)?,
    ])
}

pub(super) fn typed_model_backing(
    input: &PacketRestoredProducerLifecycleInputs<'_>,
) -> Result<usize, ProviderError> {
    let population = population(input)?;
    // Actual PacketProgram preview reserves the complete original event count
    // for newborns even when this prefix births no output. Grant and inventory
    // copies have independent owned strings/Bytes; no wire-length multiplier.
    let event = sum(&[size_of::<PacketEvent>(), 128, 32])?;
    let output = sum(&[
        size_of::<PacketPublication>(),
        128,
        input.operation.operation.as_str().len(),
        32,
    ])?;
    let grant = sum(&[
        size_of::<PacketGrant>(),
        input.operation.operation.as_str().len(),
        size_of::<PacketInventory>(),
        mul(2, event)?,
        mul(4, output)?,
    ])?;
    sum(&[grant, mul(population.newborn, output)?,
        crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data::<Id, PacketGrant>()?,
        crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data::<Id, crate::bodies::BeginRequest>()?,
        crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data::<Id, Id>()?])
}

fn field(
    p: &mut Projection,
    name: &str,
    value: &impl serde::Serialize,
) -> Result<(), ProviderError> {
    p.add_field(name)?;
    p.add_value(value)
}
fn text(p: &mut Projection, name: &str, maximum: usize) -> Result<(), ProviderError> {
    p.add_field(name)?;
    p.add_string_extent(maximum)
}
fn empty(p: &mut Projection, name: &str) -> Result<(), ProviderError> {
    p.add_field(name)?;
    p.add_object()
}
fn content(p: &mut Projection) -> Result<(), ProviderError> {
    p.add_object()?;
    p.add_field("hash")?;
    p.add_object()?;
    field(p, "algorithm", &"blake3-256")?;
    text(p, "domain", 128)?;
    text(p, "digest", 64)?;
    field(p, "length", &V::Text("18446744073709551615"))?;
    text(p, "media_type", 128)
}
fn position(p: &mut Projection) -> Result<(), ProviderError> {
    p.add_object()?;
    field(p, "time_ps", &V::Text("18446744073709551615"))?;
    field(p, "microstep", &V::Text("18446744073709551615"))?;
    field(p, "phase", &3u16)
}
fn payload(p: &mut Projection, bytes: usize) -> Result<(), ProviderError> {
    let width = bytes
        .checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .ok_or_else(invalid)?
        / 3;
    p.add_unescaped_ascii_extent(width)
}
fn arguments(
    p: &mut Projection,
    input: &PacketRestoredProducerLifecycleInputs<'_>,
) -> Result<(), ProviderError> {
    let owner = input
        .launch
        .selection
        .realization
        .owners
        .first()
        .ok_or_else(invalid)?;
    let binding = input
        .launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(invalid)?;
    p.add_object()?;
    field(p, "grant_id", input.operation.operation)?;
    field(p, "participant_ids", &owner.participant_ids)?;
    field(
        p,
        "realization_id",
        &input.launch.selection.realize.realization_id,
    )?;
    field(p, "activation_id", &input.arguments.held.target_activation)?;
    field(p, "world_generation", &V::Text("18446744073709551615"))?;
    field(p, "owner_generation", &V::Text("18446744073709551615"))?;
    field(p, "input_epoch", &binding.authority.input_epoch)?;
    field(p, "mode", &"exact")?;
    field(p, "ordering_profile", &"superdense-v1")?;
    p.add_field("start")?;
    position(p)?;
    p.add_field("limit")?;
    position(p)?;
    field(p, "boundary_policy", &"ordinary_stop")?;
    p.add_field("input_authorization")?;
    content(p)?;
    field(p, "input_watermark", &V::Text("0"))
}

fn envelope(
    p: &mut Projection,
    input: &PacketRestoredProducerLifecycleInputs<'_>,
) -> Result<(), ProviderError> {
    p.add_object()?;
    field(p, "protocol", &"CNP/1")?;
    for name in [
        "message",
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
        "method",
    ] {
        text(p, name, 128)?;
    }
    field(p, "sequence", &V::Text("18446744073709551615"))?;
    p.add_field("body")?;
    p.add_object()?;
    // A structural superset covers each supported request without claiming this
    // combined object is a valid wire message or giving unknown methods access.
    text(p, "kind", 32)?;
    p.add_field("binding_hash")?;
    content(p)?;
    field(p, "owner_generation", &V::Text("18446744073709551615"))?;
    text(p, "activation_id", 128)?;
    field(p, "world_generation", &V::Text("18446744073709551615"))?;
    p.add_field("arguments")?;
    arguments(p, input)?;
    for name in [
        "after_observation_sequence",
        "maximum_items",
        "offset",
        "next_offset",
        "maximum_chunk_bytes",
    ] {
        field(p, name, &V::Text("18446744073709551615"))?;
    }
    for name in ["transfer_id", "disposition", "status", "operation_state"] {
        text(p, name, 128)?;
    }
    for name in ["custody_receipt", "object", "content"] {
        p.add_field(name)?;
        content(p)?;
    }
    for name in ["request_ids", "operation_ids"] {
        p.add_field(name)?;
        p.add_array_extent(1)?;
        p.add_string_extent(128)?;
    }
    p.add_field("bytes")?;
    payload(p, chunk_bytes(input.startup.frame_bytes_data())?)?;
    p.add_field("result")?;
    result(p, input)?;
    empty(p, "extensions")?;
    empty(p, "extensions")
}
fn result(
    p: &mut Projection,
    input: &PacketRestoredProducerLifecycleInputs<'_>,
) -> Result<(), ProviderError> {
    p.add_object()?;
    for name in ["grant_id", "operation_id"] {
        text(p, name, 128)?;
    }
    p.add_field("reached")?;
    position(p)?;
    text(p, "stop_reason", 32)?;
    for name in ["stop_receipt", "observation_batch", "pending_inventory"] {
        p.add_field(name)?;
        content(p)?;
    }
    p.add_field("next_attention")?;
    p.add_object()?;
    text(p, "kind", 32)?;
    p.add_field("position")?;
    position(p)?;
    p.add_field("evidence")?;
    content(p)?;
    p.add_field("outcome")?;
    p.add_object()?;
    text(p, "status", 32)?;
    text(p, "operation_state", 32)?;
    p.add_field("result")?;
    p.add_object()?;
    text(p, "grant_id", 128)?;
    p.add_field("reached")?;
    position(p)?;
    text(p, "stop_reason", 32)?;
    for name in ["stop_receipt", "observation_batch", "pending_inventory"] {
        p.add_field(name)?;
        content(p)?;
    }
    p.add_field("next_attention")?;
    p.add_object()?;
    text(p, "kind", 32)?;
    p.add_field("position")?;
    position(p)?;
    p.add_field("evidence")?;
    content(p)?;
    empty(p, "extensions")?;
    p.add_field("observations")?;
    p.add_array_extent(1)?;
    p.add_object()?;
    field(p, "schema_version", &1u32)?;
    for name in [
        "execution_owner_id",
        "activation_id",
        "operation_id",
        "grant_id",
    ] {
        text(p, name, 128)?;
    }
    for name in ["owner_binding_hash", "world_binding_hash"] {
        p.add_field(name)?;
        content(p)?;
    }
    for name in [
        "world_generation",
        "owner_generation",
        "first_sequence",
        "last_sequence",
    ] {
        field(p, name, &V::Text("18446744073709551615"))?;
    }
    p.add_field("events")?;
    p.add_array_extent(0)?;
    text(p, "visibility", 32)?;
    p.add_field("measurement_ref")?;
    content(p)?;
    empty(p, "extensions")?;
    for name in ["next_sequence", "next_observation_sequence"] {
        field(p, name, &V::Text("18446744073709551615"))?;
    }
    field(p, "complete", &true)?;
    p.add_field("inventory_hash")?;
    content(p)?;
    for name in ["retired_request_ids", "retired_operation_ids"] {
        p.add_field(name)?;
        p.add_array_extent(1)?;
        p.add_string_extent(128)?;
    }
    // Content references rather than payload bytes are the report's full proof
    // edges. Actual payload owners occur in Producer grant/inventory separately.
    let _ = input;
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<Projection>()
        + size_of::<Result<Projection, ProviderError>>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<std::slice::Iter<'static, PacketEvent>>() * 2
        + size_of::<std::slice::Iter<'static, &str>>() * 4
        + size_of::<Option<&PacketEvent>>()
        + size_of::<Option<&Bytes>>()
        + size_of::<Option<&ContentRef>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<&Id>()
        + size_of::<Position>() * 2
}
