//! Compares private Fields shapes with independent full-input original bodies.

use super::*;
use crucible_node_format::Bytes;
use serde_json::json;

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
        .map(|data| {
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
        })
        .map_err(|error| format!("{error:?};{error}"))
}

#[test]
fn private_shapes_preserve_original_components_ids_and_optional_rows()
-> Result<(), Box<dyn std::error::Error>> {
    for capture in [false, true] {
        for fresh in [false, true] {
            for restore in [false, true] {
                let mut launch = launch()?;
                launch.capture_allocation_selection = capture.then_some(crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12);
                launch.fresh_restore_allocation_selection = fresh.then_some(crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13);
                launch.complete_restore_selection = restore.then_some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12);
                for text in ["private", "private:long/identity-7"] {
                    let private = crucible_node_format::Id::new(text)?;
                    let input = PacketNativeBirthStartupInputs {
                        launch: &launch,
                        private_launch: &private,
                        encoded_launch: b"",
                        source_birth: b"",
                        host_registration: b"",
                    };
                    // The pure shapes do not parse or bless these unused raw banks.
                    for maximum in [0, 1, 64, 65_536, usize::MAX] {
                        assert_eq!(
                            outcome(source_additions(&input, maximum)),
                            outcome(original::source_additions(&input, maximum))
                        );
                        assert_eq!(
                            outcome(boot_fields(&input, maximum)),
                            outcome(original::boot_fields(&input, maximum))
                        );
                    }
                }
            }
        }
    }
    assert!(
        original_native_birth_startup_counter_scratch_data()
            >= literal_shape_counter_scratch_data()
    );
    Ok(())
}

// Actual defining getter family before the separate lower maximum input.
const fn adapter_scope_without_maximum() -> usize {
    2 * size_of::<Fields<'static>>() // actual defining getter return
        + size_of::<&Fields<'static>>() // lower Fields loan
        + size_of::<&PacketNative5SourceLaunch>() // actual getter input loan
        + size_of::<&crucible_node_format::Id>() // actual private Id input loan
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>() // direct return
}

#[test]
fn new_lower_maximum_input_has_its_own_header() {
    assert_eq!(
        literal_shape_counter_scratch_data().checked_sub(adapter_scope_without_maximum()),
        Some(size_of::<usize>())
    );
}

#[path = "fold_tests.rs"]
mod fold_tests;
