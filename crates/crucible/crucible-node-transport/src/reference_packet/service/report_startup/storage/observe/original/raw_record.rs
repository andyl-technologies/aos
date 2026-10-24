//! Counts the closed stopped raw2/4 grammar before a native owner exists.
//!
//! Inventory populations use the real finite model constructor/transition
//! limits. Producer fields borrow the installed event definition. Reactive
//! fields account every independently retained inventory view, including each
//! repeated payload. The ordinary proof's 64 KiB encoded ceiling is enforced
//! separately; it never stands in for these DOM/canonical allocations.

use super::observe::{decimal, id, object, original, position, reference};
use super::*;
use crate::reference_packet::connected::PacketConnectedProgram;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
};

type Projection = OriginalSerializationStorageProjection;

fn bytes(projection: &mut Projection, length: usize) -> Result<(), ProviderError> {
    let encoded = length.div_ceil(3).checked_mul(4).ok_or_else(exhausted)?;
    projection.add_unescaped_ascii_extent(encoded)
}

fn reaction(projection: &mut Projection, payload: usize) -> Result<(), ProviderError> {
    object(
        projection,
        &[
            "input_event",
            "input_producer",
            "input_sequence",
            "stage_operation",
            "commit_request",
            "payload",
            "parent",
            "evaluation",
        ],
    )?;
    id(projection)?;
    id(projection)?;
    decimal(projection)?;
    id(projection)?;
    id(projection)?;
    bytes(projection, payload)?;
    position(projection)?;
    position(projection)
}

fn pending(projection: &mut Projection, payload: usize) -> Result<(), ProviderError> {
    object(
        projection,
        &["event", "reaction", "reaction_operation", "publication"],
    )?;
    id(projection)?;
    reaction(projection, payload)?;
    id(projection)?;
    position(projection)
}

fn publication(
    projection: &mut Projection,
    event: Option<&crucible_node_format::Id>,
    payload: usize,
) -> Result<(), ProviderError> {
    object(
        projection,
        &[
            "event",
            "operation",
            "sequence",
            "evaluation",
            "publication",
            "payload",
        ],
    )?;
    if let Some(event) = event {
        projection.add_string(event.as_str())?;
    } else {
        id(projection)?;
    }
    id(projection)?;
    decimal(projection)?;
    position(projection)?;
    position(projection)?;
    bytes(projection, payload)
}

fn producer(
    projection: &mut Projection,
    program: &crate::reference_packet::PacketProgramDefinition,
) -> Result<(), ProviderError> {
    object(
        projection,
        &[
            "reached",
            "gate_closed",
            "pending",
            "retained_outputs",
            "private_mutations",
            "packet_effects",
        ],
    )?;
    position(projection)?;
    projection.add_value(&false)?;
    projection.add_array_extent(program.events.len())?;
    for event in &program.events {
        object(projection, &["id", "evaluation", "completion", "payload"])?;
        projection.add_string(event.id.as_str())?;
        position(projection)?;
        position(projection)?;
        if let Some(payload) = &event.payload {
            bytes(projection, payload.as_slice().len())?;
        } else {
            projection.add_value(&())?;
        }
    }
    let outputs = program
        .events
        .iter()
        .filter(|event| event.payload.is_some())
        .count();
    projection.add_array_extent(outputs)?;
    // Pending and emitted subsets cannot both contain the same event. Counting
    // both complete sets safely dominates every actual stopped inventory.
    for event in &program.events {
        if let Some(payload) = &event.payload {
            publication(projection, Some(&event.id), payload.as_slice().len())?;
        }
    }
    decimal(projection)?;
    decimal(projection)
}

fn reactive(projection: &mut Projection) -> Result<(), ProviderError> {
    let limits = PacketConnectedProgram::original_stopped_inventory_row_limits_data();
    let events = limits.events;
    let batches = limits.batches;
    let payload = limits.payload_bytes;
    object(
        projection,
        &[
            "reached",
            "gate_closed",
            "reactions",
            "delivered_inputs",
            "publications",
            "retained_outputs",
            "reactions_completed",
            "packet_effects",
            "stages",
            "commits",
        ],
    )?;
    position(projection)?;
    projection.add_value(&false)?;
    projection.add_array_extent(events)?;
    for _ in 0..events {
        reaction(projection, payload)?;
    }
    projection.add_array_extent(events)?;
    for _ in 0..events {
        object(projection, &["reaction", "delivery_operation"])?;
        reaction(projection, payload)?;
        id(projection)?;
    }
    projection.add_array_extent(events)?;
    for _ in 0..events {
        pending(projection, payload)?;
    }
    projection.add_array_extent(events)?;
    for _ in 0..events {
        object(projection, &["output", "pending"])?;
        publication(projection, None, payload)?;
        pending(projection, payload)?;
    }
    decimal(projection)?;
    decimal(projection)?;
    for _ in 0..2 {
        projection.add_array_extent(batches)?;
        for _ in 0..batches {
            reference(projection, "application/json")?;
        }
    }
    Ok(())
}

pub(super) fn project(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut projection = Projection::new(maximum)?;
    object(
        &mut projection,
        &["schema", "native_pid", "original", "inventory", "grant"],
    )?;
    projection.add_string(match &launch.program {
        PacketConnectedSourceProgram::Producer { .. } => "source-owned.packet-native/2",
        PacketConnectedSourceProgram::Reactive { .. } => "source-owned.packet-native/4",
    })?;
    decimal(&mut projection)?;
    original(&mut projection, launch)?;
    match &launch.program {
        PacketConnectedSourceProgram::Producer { program } => {
            producer(&mut projection, program)?;
        }
        PacketConnectedSourceProgram::Reactive { .. } => reactive(&mut projection)?,
    }
    // The selected producer is an Observe: no semantic grant is serialized.
    projection.add_value(&())?;
    projection.finish(maximum)
}

/// Projects only the actual untouched Source14 model checked before live quote.
///
/// The original constructor owns all initial event payloads. No callback/input
/// has executed, and the actual activated model has no output or input history.
/// The complete old stopped-state projection remains available independently.
pub(super) fn project_initial(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut projection = Projection::new(maximum)?;
    object(
        &mut projection,
        &["schema", "native_pid", "original", "inventory", "grant"],
    )?;
    projection.add_string(match &launch.program {
        PacketConnectedSourceProgram::Producer { .. } => "source-owned.packet-native/2",
        PacketConnectedSourceProgram::Reactive { .. } => "source-owned.packet-native/4",
    })?;
    decimal(&mut projection)?;
    original(&mut projection, launch)?;
    initial_inventory(&mut projection, &launch.program)?;
    projection.add_value(&())?;
    projection.finish(maximum)
}

fn initial_inventory(
    projection: &mut Projection,
    program: &PacketConnectedSourceProgram,
) -> Result<(), ProviderError> {
    match program {
        PacketConnectedSourceProgram::Producer { program } => {
            object(
                projection,
                &[
                    "reached",
                    "gate_closed",
                    "pending",
                    "retained_outputs",
                    "private_mutations",
                    "packet_effects",
                ],
            )?;
            projection.add_value(&crucible_node_format::Position::new(
                crucible_node_format::U64::new(0),
                crucible_node_format::U64::new(0),
                crucible_node_format::Phase::BoundaryControl,
            ))?;
            projection.add_value(&false)?;
            projection.add_array_extent(program.events.len())?;
            for event in &program.events {
                projection.add_value(event)?;
            }
            projection.add_array_extent(0)?;
            for _ in 0..2 {
                projection.add_value(&crucible_node_format::U64::new(0))?;
            }
        }
        PacketConnectedSourceProgram::Reactive { .. } => {
            object(
                projection,
                &[
                    "reached",
                    "gate_closed",
                    "reactions",
                    "delivered_inputs",
                    "publications",
                    "retained_outputs",
                    "reactions_completed",
                    "packet_effects",
                    "stages",
                    "commits",
                ],
            )?;
            projection.add_value(&crucible_node_format::Position::new(
                crucible_node_format::U64::new(0),
                crucible_node_format::U64::new(0),
                crucible_node_format::Phase::BoundaryControl,
            ))?;
            projection.add_value(&false)?;
            for _ in 0..4 {
                projection.add_array_extent(0)?;
            }
            for _ in 0..2 {
                projection.add_value(&crucible_node_format::U64::new(0))?;
            }
            for _ in 0..2 {
                projection.add_array_extent(0)?;
            }
        }
    }
    Ok(())
}
