//! Compares real borrowed shape adapters with independent original algorithms.

use super::*;
use crucible_node_format::{Bytes, U64};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn components(data: &OriginalSerializationStorageData) -> [usize; 11] {
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

fn launch() -> Result<PacketNative5SourceLaunch, serde_json::Error> {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // This is a real typed geometry fixture, not a full validated launch or
    // Source/native authority. Geometry does not authenticate its world/program.
    serde_json::from_value(json!({
        "schema_version":5,"selection":selection,
        "program":{"kind":"producer","program":{"schema":"source-owned.packet-program.v1","events":[]}},
        "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
        "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
        "limits":{"frame_bytes":"65536","nesting":"64","requests":"64","journal_entries":"256","blob_chunk_bytes":"1024"},
        "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192","protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536","frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
        "effects":"/not-opened-by-initial-shape-control"
    }))
}

fn outcome(
    value: Result<OriginalSerializationStorageData, ProviderError>,
) -> Result<[usize; 11], String> {
    value
        .map(|data| components(&data))
        .map_err(|error| format!("{error:?};{error}"))
}

#[test]
fn literal_shapes_keep_all_original_components_for_both_programs_and_families() -> TestResult {
    for reactive in [false, true] {
        for selected in [false, true] {
            let mut launch = launch()?;
            if reactive {
                launch.program =
                    crate::reference_packet::service::PacketConnectedSourceProgram::Reactive {
                        program: crate::reference_packet::connected::PacketConnectedDefinition {
                            schema: "source-owned.packet-connected-program/4".into(),
                            connections: Vec::new(),
                            output: None,
                        },
                    };
            }
            if let crate::reference_packet::service::PacketConnectedSourceProgram::Producer {
                program,
            } = &mut launch.program
            {
                program.events.push(crate::reference_packet::PacketEvent {
                    id: crucible_node_format::Id::new("shape-payload")?,
                    evaluation: crucible_node_format::Position::new(
                        U64::new(5),
                        U64::new(0),
                        crucible_node_format::Phase::Reaction,
                    ),
                    completion: crucible_node_format::Position::new(
                        U64::new(5),
                        U64::new(1),
                        crucible_node_format::Phase::Publication,
                    ),
                    payload: Some(Bytes::new(vec![255; 5])),
                });
            }
            if selected {
                launch.capture_profile = crate::reference_packet::service::PacketNative5CaptureProfile::OwnedProtocol11 {
                    native_before_protocol_bytes: U64::new(65_536), native_after_protocol_bytes: U64::new(65_536), host_protocol_bytes: U64::new(65_536),
                };
                launch.confirmation_selection = Some(crate::reference_packet::service::PacketNative5ConfirmationSelection::AfterProtocolPoll5);
                launch.ack_emitter_selection = Some(crate::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5);
                launch.native_codec_metadata_extent =
                    Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB);
                launch.protocol_metadata_limits = Some(
                    crate::reference_packet::service::PacketNative5ProtocolMetadataLimits {
                        native_before_rows: U64::new(64),
                        native_after_rows: U64::new(64),
                    },
                );
                launch.complete_restore_selection = Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12);
                launch.restore_input_emitter_selection = Some(crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12);
                launch.capture_allocation_selection = Some(crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12);
                launch.fresh_restore_allocation_selection = Some(crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13);
            }
            for (actual_kind, old_kind) in [
                (Kind::Discover, original::Kind::Discover),
                (Kind::Realize, original::Kind::Realize),
                (Kind::Admit, original::Kind::Admit),
            ] {
                assert_eq!(
                    components(&request(&launch, actual_kind, usize::MAX)?),
                    components(&original::request(&launch, old_kind, usize::MAX)?)
                );
                assert_eq!(
                    components(&terminal(&launch, actual_kind, usize::MAX)?),
                    components(&original::terminal(&launch, old_kind, usize::MAX)?)
                );
            }
            assert_eq!(
                components(&raw_record(&launch, usize::MAX)?),
                components(&original::raw_record(&launch, usize::MAX)?)
            );
            assert_eq!(
                components(&receipt(&launch, usize::MAX)?),
                components(&original::receipt(&launch, usize::MAX)?)
            );
            assert_eq!(
                components(&admit_projection(&launch, usize::MAX)?),
                components(&original::admit_projection(&launch, usize::MAX)?)
            );
        }
    }
    Ok(())
}

#[test]
fn shared_fields_keep_original_cap_target_and_counter_boundaries() -> TestResult {
    let mut launch = launch()?;
    for maximum in [0, 1, 64, 65_536, usize::MAX] {
        assert_eq!(
            outcome(request(&launch, Kind::Realize, maximum)),
            outcome(original::request(&launch, original::Kind::Realize, maximum))
        );
        assert_eq!(
            outcome(terminal(&launch, Kind::Admit, maximum)),
            outcome(original::terminal(&launch, original::Kind::Admit, maximum))
        );
        assert_eq!(
            outcome(raw_record(&launch, maximum)),
            outcome(original::raw_record(&launch, maximum))
        );
        assert_eq!(
            outcome(receipt(&launch, maximum)),
            outcome(original::receipt(&launch, maximum))
        );
    }
    launch.selection.realization.bindings.clear();
    assert_eq!(
        outcome(request(&launch, Kind::Discover, usize::MAX)),
        outcome(original::request(
            &launch,
            original::Kind::Discover,
            usize::MAX
        ))
    );
    assert!(request(&launch, Kind::Discover, usize::MAX).is_err());
    let declared = original_initial_literal_shape_counter_scratch_data();
    assert!(crate::reference_packet::service::native_startup::original_native_birth_startup_counter_scratch_data() >= declared);
    assert!(
        crate::client::original_packet_host_initial_lifecycle_counter_scratch_data() >= declared
    );
    Ok(())
}

// Actual defining getter family before the separate lower maximum input.
const fn adapter_scope_without_maximum() -> usize {
    2 * size_of::<Fields<'static>>() // actual from_launch_data return
        + size_of::<&Fields<'static>>() // shared producer input loan
        + size_of::<&PacketNative5SourceLaunch>() // defining getter input loan
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>() // direct returned shape
        + size_of::<Result<OriginalHostInitialLifecycleShapes, ProviderError>>() // direct returned host bank
}

#[test]
fn new_lower_maximum_input_has_its_own_header() {
    assert_eq!(
        original_initial_literal_shape_counter_scratch_data()
            .checked_sub(adapter_scope_without_maximum()),
        Some(size_of::<usize>())
    );
}
