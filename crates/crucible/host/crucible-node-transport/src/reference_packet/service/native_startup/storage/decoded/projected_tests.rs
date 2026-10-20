//! Compares actual canonical launch banks with their secret-free field projection.

use super::*;
use crate::reference_packet::service::{
    PacketNative5AckEmitterSelection, PacketNative5CaptureProfile,
    PacketNative5ConfirmationSelection, PacketNative5LaunchValidationProjection,
    PacketNative5PathSerializationData, PacketNative5ProtocolMetadataLimits,
    capture_allocation::PacketNative5CaptureAllocationSelection,
    complete_restore::{
        PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
    },
    fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
};
use crucible_node_format::{Bytes, U64, canonical};
use crucible_source_birth_data::decoded_occurrences::quote_projected_launch;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn geometry_launch() -> Result<PacketNative5SourceLaunch, serde_json::Error> {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // This real DTO fixture exercises geometry only: its empty event model is
    // deliberately not a successful native launch or Source authority.
    serde_json::from_value(json!({
        "schema_version":5,"selection":selection,
        "program":{"kind":"producer","program":{"schema":"source-owned.packet-program.v1","events":[]}},
        "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
        "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
        "limits":{"frame_bytes":"65536","nesting":"64","requests":"64","journal_entries":"256","blob_chunk_bytes":"1024"},
        "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192","protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536","frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
        "effects":"/not-opened-by-geometry-control"
    }))
}

fn selected(launch: &mut PacketNative5SourceLaunch) {
    launch.capture_profile = PacketNative5CaptureProfile::OwnedProtocol11 {
        native_before_protocol_bytes: U64::new(65_536),
        native_after_protocol_bytes: U64::new(65_536),
        host_protocol_bytes: U64::new(65_536),
    };
    launch.confirmation_selection = Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5);
    launch.ack_emitter_selection = Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5);
    launch.native_codec_metadata_extent =
        Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB);
    launch.protocol_metadata_limits = Some(PacketNative5ProtocolMetadataLimits {
        native_before_rows: U64::new(64),
        native_after_rows: U64::new(64),
    });
    launch.complete_restore_selection =
        Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12);
    launch.restore_input_emitter_selection =
        Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12);
    launch.capture_allocation_selection =
        Some(PacketNative5CaptureAllocationSelection::OriginalObserve12);
    launch.fresh_restore_allocation_selection =
        Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13);
}

#[test]
fn original_typed_launches_project_exact_canonical_occurrences_for_both_programs_and_skips()
-> TestResult {
    for include_optional in [false, true] {
        for reactive in [false, true] {
            let mut launch = geometry_launch()?;
            if include_optional {
                selected(&mut launch);
            }
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
            launch.selection.realize.extensions.insert(
                "occurrences".into(),
                json!({
                    "numbers":[1.0,-0.0,1e-7,u64::MAX,i64::MIN,9_007_199_254_740_993u64],
                    "$serde_json::private::RawValue":"[1,2]",
                    "$serde_json::private::Number":"1.000",
                    "strings":["é𝄞\u{0}\"\\",{},[]]
                }),
            );
            for path in ["/tmp/plain", "/tmp/é𝄞\"\n\\"] {
                launch.effects = path.into();
                let raw = canonical::canonical_json(&serde_json::to_value(&launch)?)?;
                let expected = quote(
                    &raw,
                    size_of::<PacketNative5SourceLaunch>(),
                    native_element_slot(),
                    usize::MAX,
                )?;
                let projection = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
                let actual = quote_projected_launch(
                    &projection,
                    size_of::<PacketNative5SourceLaunch>(),
                    native_element_slot(),
                    usize::MAX,
                )?;
                assert_eq!(actual, expected);
                let exact = expected.total(usize::MAX)?;
                assert_eq!(
                    quote_projected_launch(
                        &projection,
                        size_of::<PacketNative5SourceLaunch>(),
                        native_element_slot(),
                        exact
                    )?,
                    expected
                );
                assert!(
                    quote_projected_launch(
                        &projection,
                        size_of::<PacketNative5SourceLaunch>(),
                        native_element_slot(),
                        exact - 1
                    )
                    .is_err()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn secret_tokens_are_not_reconstructed_and_actual_bank_hashes_remain_independent() -> TestResult {
    let mut launch = geometry_launch()?;
    let first = canonical::canonical_json(&serde_json::to_value(&launch)?)?;
    let first_row = quote_projected_launch(
        &PacketNative5LaunchValidationProjection::from_launch_data(&launch),
        size_of::<PacketNative5SourceLaunch>(),
        native_element_slot(),
        usize::MAX,
    )?;
    launch.admission_token = Bytes::new(vec![99; 32]);
    let second = canonical::canonical_json(&serde_json::to_value(&launch)?)?;
    let second_row = quote_projected_launch(
        &PacketNative5LaunchValidationProjection::from_launch_data(&launch),
        size_of::<PacketNative5SourceLaunch>(),
        native_element_slot(),
        usize::MAX,
    )?;

    assert_eq!(first_row, second_row);
    assert_ne!(blake3::hash(&first), blake3::hash(&second));
    Ok(())
}

#[test]
fn invalid_opaque_path_and_unsupported_layout_keep_explicit_refusals() -> TestResult {
    let launch = geometry_launch()?;
    let original = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
    for path in [
        PacketNative5PathSerializationData::InvalidUtf8,
        PacketNative5PathSerializationData::Unrepresentable,
        PacketNative5PathSerializationData::QuotedUtf8 { bytes: 1 },
    ] {
        let invalid = PacketNative5LaunchValidationProjection::from_parts_data(
            original.fields_data(),
            original.token_length_data(),
            path,
        );
        assert!(matches!(
            quote_projected_launch(
                &invalid,
                size_of::<PacketNative5SourceLaunch>(),
                native_element_slot(),
                usize::MAX
            ),
            Err(ProviderError::ResourceExhausted(
                "prepared whole frame bytes"
            ))
        ));
    }
    assert!(quote_projected_launch(&original, 0, native_element_slot(), usize::MAX).is_err());
    Ok(())
}
