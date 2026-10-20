//! Compares the shared shape producer with complete independent old bodies.

use super::*;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;
use crucible_node_format::{Bytes, U64};
use crucible_source_birth_data::profile::reference_packet::service::native_startup::original_report::AGGREGATION_COUNTER_SCRATCH_DATA;
use serde_json::json;

#[path = "original.rs"]
mod original;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn geometry_launch() -> Result<PacketNative5SourceLaunch, serde_json::Error> {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // This is geometry-only launch DATA from the actual canonical fixture.
    // Empty program events do not assert native launch or report admission.
    let mut launch: PacketNative5SourceLaunch = serde_json::from_value(json!({
        "schema_version":5,"selection":selection,
        "program":{"kind":"producer","program":{"schema":"source-owned.packet-program.v1","events":[]}},
        "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
        "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
        "limits":{"frame_bytes":"65536","nesting":"64","requests":"256","journal_entries":"4096","blob_chunk_bytes":"1024"},
        "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192","protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536","frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
        "effects":"/not-opened-by-report-layout-control"
    }))?;
    launch.capture_profile =
        crate::reference_packet::service::PacketNative5CaptureProfile::OwnedProtocol11 {
            native_before_protocol_bytes: U64::new(65536),
            native_after_protocol_bytes: U64::new(65536),
            host_protocol_bytes: U64::new(65536),
        };
    launch.capture_allocation_selection = Some(crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12);
    launch.ack_emitter_selection =
        Some(crate::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5);
    launch.native_codec_metadata_extent =
        Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB);
    launch.protocol_metadata_limits = Some(
        crate::reference_packet::service::PacketNative5ProtocolMetadataLimits {
            native_before_rows: U64::new(64),
            native_after_rows: U64::new(64),
        },
    );
    Ok(launch)
}

fn report_data(data: &OriginalSerializationStorageData) -> [usize; 11] {
    [
        data.dom_and_canonical_scratch_bytes,
        data.retained_value_backing_bytes,
        data.projected_parser_requested_bytes,
        data.canonical_output_requested_bytes,
        data.serializer_temporary_requested_bytes,
        data.declared_counter_scratch_bytes,
        data.maximum_encoded_bytes,
        data.sequence_elements,
        data.sequence_containers,
        data.serialized_value_nodes,
        data.serialized_capacity_records,
    ]
}

fn actual_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
    initial: bool,
) -> Result<[[usize; 11]; 6], ProviderError> {
    let shapes = if initial {
        project_initial(launch, maximum)?
    } else {
        project(launch, maximum)?
    };
    Ok([
        report_data(&shapes.original),
        report_data(&shapes.terminal),
        report_data(&shapes.receipt),
        report_data(&shapes.wrapper),
        report_data(&shapes.report),
        report_data(&shapes.raw),
    ])
}

fn outcome(result: Result<[[usize; 11]; 6], ProviderError>) -> Result<[[usize; 11]; 6], String> {
    result.map_err(|error| format!("{error:?}; {error}"))
}

fn reactive(launch: &mut PacketNative5SourceLaunch) -> TestResult {
    use crate::reference_packet::connected::{PacketConnectedDefinition, PacketInputConnection};
    use crucible_node_format::{Endpoint, Id, canonical};
    let endpoint = |node| -> Result<Endpoint, ProviderError> {
        Ok(Endpoint {
            node_id: Id::new(node)?,
            port_id: Id::new("port")?,
            lane_id: Id::new("lane")?,
        })
    };
    launch.program = PacketConnectedSourceProgram::Reactive {
        program: PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: vec![PacketInputConnection {
                id: Id::new("report-shape-route")?,
                policy: canonical::content_ref(b"policy", "application/octet-stream")?,
                producer: endpoint("producer")?,
                consumer: endpoint("consumer")?,
                delay_ps: U64::new(1),
            }],
            output: None,
        },
    };
    Ok(())
}

#[test]
fn actual_report_shapes_match_all_old_components_for_both_models_and_initial_paths() -> TestResult {
    let maximum = MAXIMUM_COMPILED_PROJECTION_BYTES;
    let mut launch = geometry_launch()?;
    // Preserve an actual payload with escaping-sensitive bytes in the producer.
    if let PacketConnectedSourceProgram::Producer { program } = &mut launch.program {
        program.events.push(crate::reference_packet::PacketEvent {
            id: crucible_node_format::Id::new("report-shape-event")?,
            evaluation: crucible_node_format::Position::new(
                U64::new(2),
                U64::new(0),
                crucible_node_format::Phase::Reaction,
            ),
            completion: crucible_node_format::Position::new(
                U64::new(2),
                U64::new(1),
                crucible_node_format::Phase::Publication,
            ),
            payload: Some(Bytes::new(vec![0, 255, 13, 10, 92, 34])),
        });
    }
    for model in 0..2 {
        if model == 1 {
            reactive(&mut launch)?;
        }
        for initial in [false, true] {
            let actual = actual_data(&launch, maximum, initial)?;
            let old = original::shape_data(&launch, maximum, initial)?;
            assert_eq!(actual, old);
        }
    }
    Ok(())
}

#[test]
fn actual_report_shapes_keep_exact_limit_one_short_and_original_first_refusals() -> TestResult {
    let mut launch = geometry_launch()?;
    for model in 0..2 {
        if model == 1 {
            reactive(&mut launch)?;
        }
        for initial in [false, true] {
            let shapes = if initial {
                project_initial(&launch, MAXIMUM_COMPILED_PROJECTION_BYTES)?
            } else {
                project(&launch, MAXIMUM_COMPILED_PROJECTION_BYTES)?
            };
            // project_initial deliberately runs the old stopped projection
            // first, then replaces raw. Admit both real traversals even when
            // the returned initial raw report is smaller.
            let stopped = project(&launch, MAXIMUM_COMPILED_PROJECTION_BYTES)?;
            let mut exact = stopped.raw.requested_total()?;
            for shape in [
                &shapes.original,
                &shapes.terminal,
                &shapes.receipt,
                &shapes.wrapper,
                &shapes.report,
                &shapes.raw,
            ] {
                exact = exact.max(shape.requested_total()?);
            }
            assert_eq!(
                actual_data(&launch, exact, initial)?,
                original::shape_data(&launch, exact, initial)?
            );
            let short = actual_data(&launch, exact - 1, initial);
            assert!(short.is_err());
            assert_eq!(
                outcome(short),
                outcome(original::shape_data(&launch, exact - 1, initial))
            );
        }
    }
    let changes: &[fn(&mut PacketNative5SourceLaunch)] = &[
        |launch| launch.capture_allocation_selection = None,
        |launch| launch.protocol_metadata_limits = None,
        |launch| launch.selection.realization.bindings.clear(),
        |launch| launch.selection.realization.owners.clear(),
    ];
    for change in changes {
        let mut launch = geometry_launch()?;
        change(&mut launch);
        for maximum in [0, 1, MAXIMUM_COMPILED_PROJECTION_BYTES] {
            for initial in [false, true] {
                let actual = actual_data(&launch, maximum, initial);
                assert!(actual.is_err());
                assert_eq!(
                    outcome(actual),
                    outcome(original::shape_data(&launch, maximum, initial))
                );
            }
        }
    }
    Ok(())
}

#[test]
fn report_shape_adapter_counter_adds_only_actual_headers_and_its_real_sum_slot() {
    let headers = 3 * size_of::<PacketNative5LaunchValidationFields<'static>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + 2 * size_of::<&PacketNative5LaunchValidationFields<'static>>()
        + size_of::<Result<(), ProviderError>>()
        + 2 * size_of::<report_shapes::raw::StoppedInventoryRowLimitsData>()
        + 2 * size_of::<&report_shapes::raw::StoppedInventoryRowLimitsData>()
        + size_of::<Result<(), ProviderError>>();
    assert_eq!(counter_scratch_data(), headers);
    // Independent aggregation adds its defining family and its own real sum slot.
    assert_eq!(
        original_report_startup_counter_scratch_data(),
        original::counter_scratch_data()
            + headers
            + size_of::<usize>()
            + AGGREGATION_COUNTER_SCRATCH_DATA
            + size_of::<usize>()
    );
}
