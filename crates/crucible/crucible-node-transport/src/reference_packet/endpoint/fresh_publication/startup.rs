//! Bounds the actual Fresh publisher before its native owners are constructed.
//!
//! The immutable launch supplies the constructor's exact initial inventory.
//! Query/report schemas and the ordinary one-proof planner provide independent
//! field and layout bounds. These are requested-storage data; the same private
//! startup admission, current query and live owning reconciliation remain
//! mandatory. Fixed Prepare construction has its own separately admitted row.

use super::*;
use crate::connection::{OriginalContinuationContentExtent, OriginalPacketPrefixProjectionInput};
use crate::reference_packet::service::{PacketConnectedSourceProgram, PacketNative5SourceLaunch};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};
use std::mem::size_of;

mod layout;

/// Contains only the three separately checked publication demand axes.
pub(crate) struct PacketNativeFreshPublicationStartupStorageData {
    pub(crate) retained_growth_bytes: usize,
    pub(crate) maximum_simultaneous_transient_bytes: usize,
    pub(crate) declared_counter_scratch_bytes: usize,
}

/// Counts the closed actual publisher from the installed original launch.
///
/// The caller first admits the static counter window and independently checks
/// the full selected launch/schema tuple. This function neither constructs a
/// native owner nor authenticates a Source grant. The later live quote keeps
/// all unchanged frame/history/wire ceilings and recounts actual capacities.
pub(crate) fn original_fresh_report_startup_publication_data(
    launch: &PacketNative5SourceLaunch,
    maximum_requested_bytes: usize,
) -> Result<PacketNativeFreshPublicationStartupStorageData, ProviderError> {
    let shapes = fresh_restore_allocation_startup_shapes(launch, maximum_requested_bytes)?;
    let inventory = initial_inventory(&launch.program, maximum_requested_bytes)?;
    let objects = [OriginalContinuationContentExtent {
        maximum_payload_bytes: PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        media_type: PACKET_FRESH_RESTORE_ALLOCATION_MEDIA,
    }];
    let prefix = crate::connection::quote_original_packet_prefix_startup_storage_data(
        launch,
        OriginalPacketPrefixProjectionInput {
            original: &shapes.original,
            terminal: &shapes.terminal,
            objects: &objects,
            maximum_requested_bytes,
        },
    )?;

    let reference_children = sum(&[
        "blake3-256".len(),
        "cnp.blob.v1".len(),
        64,
        PACKET_FRESH_RESTORE_ALLOCATION_MEDIA.len(),
    ])?;
    let inventory_hash_children = sum(&[
        "blake3-256".len(),
        64,
        "source-owned.packet-connected-inventory/4".len(),
    ])?;
    let fixed = layout::project();
    let retained = sum(&[
        layout::owner_bytes_data(),
        // The real owner retains both the raw query Envelope and the decoded
        // Observe request. Ordinary planner containment clones are additional.
        mul(2, shapes.original.dom_and_canonical_scratch_bytes)?,
        shapes.query_typed_requested_bytes,
        fixed.received_frame_bytes,
        fixed.request_body_bytes,
        shapes.report_typed_requested_bytes,
        shapes.receipt_typed_requested_bytes,
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        inventory.maximum_encoded_bytes,
        shapes.terminal.dom_and_canonical_scratch_bytes,
        fixed.observe_result_bytes,
        fixed.control_reply_bytes,
        fixed.content_slot_bytes,
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        mul(2, inventory_hash_children)?,
        mul(3, reference_children)?,
        prefix.exchange.requested_bytes()?,
        prefix.source_owner_requested_bytes,
    ])?;
    let scratch = layout::counter_output_data();
    let initial_receive = crate::connection::original_report_query_receive_storage_data(
        launch,
        crate::reference_packet::service::report_startup::PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
    )?.requested_bytes()?;
    // The restricted receive has returned before publication starts. Its raw
    // parser/error work cannot overlap this complete encoding phase. Returned
    // raw/typed query owners remain independently retained above, including
    // failures; the live publication quote uses this same encoding sum.
    let transient = sum(&[
        inventory.requested_total()?,
        shapes.report_authentication_transient_requested_bytes,
        shapes.report.requested_total()?,
        shapes.receipt.requested_total()?,
        shapes.terminal.requested_total()?,
        shapes.original.requested_total()?,
        shapes.terminal.dom_and_canonical_scratch_bytes,
        shapes.receipt.dom_and_canonical_scratch_bytes,
        prefix.exchange.requested_bytes()?,
        prefix.declared_counter_scratch_bytes,
        scratch,
    ])?;
    let data = PacketNativeFreshPublicationStartupStorageData {
        retained_growth_bytes: retained,
        maximum_simultaneous_transient_bytes: initial_receive.max(transient),
        declared_counter_scratch_bytes: scratch,
    };
    if sum(&[
        data.retained_growth_bytes,
        data.maximum_simultaneous_transient_bytes,
        data.declared_counter_scratch_bytes,
    ])? > maximum_requested_bytes
    {
        return Err(exhausted());
    }
    Ok(data)
}

/// Names fixed real counter/header layouts before any projection or schema work.
///
/// The enclosing report-startup producer separately includes initial raw query
/// parsing and fixed schema generation. This getter excludes recursive/compiler
/// frames and allocator overhead. Overflow is an unadmittable demand.
pub(crate) fn original_fresh_report_startup_publication_counter_scratch_data() -> usize {
    let terms = [
        original_fresh_report_publication_counter_scratch_data(),
        crate::connection::original_packet_prefix_startup_counter_scratch_data(),
        size_of::<PacketNativeFreshPublicationStartupStorageData>(),
        size_of::<Projection>(),
        2 * size_of::<OriginalSerializationStorageData>(),
        size_of::<FreshRestoreAllocationStartupShapes>(),
        size_of::<crate::connection::OriginalPacketPrefixProjectionStorageData>(),
        size_of::<[OriginalContinuationContentExtent<'static>; 1]>(),
        size_of::<[usize; 24]>(),
        size_of::<std::slice::Iter<'static, usize>>(),
        size_of::<std::slice::Iter<'static, crate::reference_packet::PacketEvent>>(),
        size_of::<[u8; 20]>(),
        layout::counter_scratch_data(),
    ];
    terms
        .iter()
        .try_fold(std::mem::size_of_val(&terms), |total, term| {
            total.checked_add(*term)
        })
        .unwrap_or(usize::MAX)
}

// This is the actual inventory grammar of the two constructors, without making
// a model, report or generic Value. The stopped-owner live quote independently
// checks the initial state before lending its equivalent borrowed serializer.
fn initial_inventory(
    program: &PacketConnectedSourceProgram,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut projection = Projection::new(maximum)?;
    let mut formatter_capacity = 0usize;
    let mut formatter_banks = 0usize;
    projection.add_object()?;
    let fields: &[&str] = match program {
        PacketConnectedSourceProgram::Producer { .. } => &[
            "reached",
            "gate_closed",
            "pending",
            "retained_outputs",
            "private_mutations",
            "packet_effects",
        ],
        PacketConnectedSourceProgram::Reactive { .. } => &[
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
    };
    for field in fields {
        projection.add_field(field)?;
    }
    projection.add_value(&crucible_node_format::Position::new(
        U64::new(0),
        U64::new(0),
        crucible_node_format::Phase::BoundaryControl,
    ))?;
    projection.add_value(&true)?;
    match program {
        PacketConnectedSourceProgram::Producer { program } => {
            projection.add_array_extent(program.events.len())?;
            for event in &program.events {
                projection.add_object()?;
                for field in ["id", "evaluation", "completion", "payload"] {
                    projection.add_field(field)?;
                }
                projection.add_value(&event.id)?;
                projection.add_value(&event.evaluation)?;
                projection.add_value(&event.completion)?;
                if let Some(payload) = &event.payload {
                    // Bytes is base64url text. Count its exact encoded extent
                    // without invoking its allocating pre-callback formatter.
                    let bytes = payload.as_slice().len();
                    // The pinned base64 decoder reserves at most two trailing
                    // estimate bytes beyond initialized length. Twice length
                    // plus four is a conservative requested-bank bound; the
                    // live counter still reconciles the actual same fields.
                    formatter_capacity = sum(&[formatter_capacity, mul(2, bytes)?, 4])?;
                    formatter_banks = formatter_banks.checked_add(1).ok_or_else(exhausted)?;
                    let encoded = bytes
                        .checked_div(3)
                        .and_then(|full| full.checked_mul(4))
                        .and_then(|full| {
                            full.checked_add(match bytes % 3 {
                                0 => 0,
                                1 => 2,
                                _ => 3,
                            })
                        })
                        .ok_or_else(exhausted)?;
                    // Match the same generic serializer counter used by the live
                    // inventory plan, including its conservative string bound.
                    projection.add_string_extent(encoded)?;
                } else {
                    projection.add_value(&())?;
                }
            }
            projection.add_array_extent(0)?; // Actual retained outputs are empty.
        }
        PacketConnectedSourceProgram::Reactive { .. } => {
            // The constructor creates six empty logical arrays. Their retained
            // capacities belong to baseline, not this serialized inventory.
            for _ in 0..6 {
                projection.add_array_extent(0)?;
            }
        }
    }
    projection.add_value(&U64::new(0))?;
    projection.add_value(&U64::new(0))?;
    let mut data = projection.finish(maximum)?;
    data.serializer_temporary_requested_bytes =
        sum(&[formatter_capacity, mul(2, formatter_banks)?])?
            .checked_div(3)
            .and_then(|groups| groups.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(20))
            .ok_or_else(exhausted)?;
    if data.requested_total()? > maximum {
        return Err(exhausted());
    }
    Ok(data)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(exhausted)
    })
}

fn mul(count: usize, value: usize) -> Result<usize, ProviderError> {
    count.checked_mul(value).ok_or_else(exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::connected::{
        PacketConnectedDefinition, PacketConnectedProgram, PacketInputConnection,
    };
    use crate::reference_packet::{PacketEvent, PacketProgram, PacketProgramDefinition};
    use crate::retained_metadata::{
        MetadataObserver, serialization_storage::actual_serialization_storage_data,
    };
    use crucible_node_format::{Bytes, Endpoint, Phase, Position};
    use std::os::unix::net::UnixDatagram;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn fresh_initial_producer_counter_covers_actual_decoded_constructor_and_formatter() -> TestResult
    {
        let program = PacketConnectedSourceProgram::Producer {
            program: PacketProgramDefinition {
                schema: "source-owned.packet-program.v1".into(),
                events: vec![PacketEvent {
                    id: Id::new("fresh-pending-byte-bank")?,
                    evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                    payload: Some(Bytes::new(vec![255; 1024])),
                }],
            },
        };
        // The native launch path decodes the transmitted program before moving
        // its real event banks into the actual model constructor.
        let decoded: PacketConnectedSourceProgram =
            serde_json::from_value(serde_json::to_value(&program)?)?;
        let bound = initial_inventory(&decoded, 512 * 1024 * 1024)?;
        let PacketConnectedSourceProgram::Producer { program } = decoded else {
            return Err("wrong actual program".into());
        };
        let (socket, _peer) = UnixDatagram::pair()?;
        let model = PacketProgram::new(program.events, socket)?;
        let view = model.borrow_original_fresh_inventory(&mut MetadataObserver::new())?;
        let actual = actual_serialization_storage_data(
            &view,
            view.formatter_fields_data()?,
            512 * 1024 * 1024,
        )?;

        assert!(bound.maximum_encoded_bytes >= actual.maximum_encoded_bytes);
        assert!(bound.requested_total()? >= actual.requested_total()?);
        assert!(
            bound.maximum_encoded_bytes
                >= crucible_node_format::canonical::canonical_json(&serde_json::to_value(&view)?)?
                    .len()
        );
        Ok(())
    }

    #[test]
    fn fresh_initial_reactive_counter_covers_actual_empty_reserved_constructor() -> TestResult {
        let definition = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: vec![PacketInputConnection {
                id: Id::new("fresh-original-route")?,
                policy: crucible_node_format::canonical::content_ref(
                    b"policy",
                    "application/json",
                )?,
                producer: Endpoint {
                    node_id: Id::new("source")?,
                    port_id: Id::new("port")?,
                    lane_id: Id::new("lane")?,
                },
                consumer: Endpoint {
                    node_id: Id::new("sink")?,
                    port_id: Id::new("port")?,
                    lane_id: Id::new("lane")?,
                },
                delay_ps: U64::new(3),
            }],
            output: None,
        };
        let program = PacketConnectedSourceProgram::Reactive {
            program: definition,
        };
        let bound = initial_inventory(&program, 512 * 1024 * 1024)?;
        let PacketConnectedSourceProgram::Reactive { program } = program else {
            return Err("wrong actual program".into());
        };
        let (socket, _peer) = UnixDatagram::pair()?;
        let model = PacketConnectedProgram::new(program, socket)?;
        let mut retained = MetadataObserver::new();
        let view = model.borrow_original_fresh_inventory(&mut retained)?;
        let actual = actual_serialization_storage_data(
            &view,
            MetadataObserver::new().finish(),
            512 * 1024 * 1024,
        )?;

        assert!(retained.finish().vector_capacity_bytes > 0);
        assert!(bound.maximum_encoded_bytes >= actual.maximum_encoded_bytes);
        assert!(bound.requested_total()? >= actual.requested_total()?);
        Ok(())
    }
}
