//! Checks inert prebirth geometry without issuing a ticket, boot or action.

use super::*;
use crate::reference_packet::service::*;
use crucible_node_contract::{Bytes, U64, canonical};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn model() -> PacketCompleteRestoreOwnerValidationStorage {
    PacketCompleteRestoreOwnerValidationStorage {
        snapshot_bytes: 10,
        journal_bytes: 20,
        control_bytes: 30,
        model_vector_backing_bytes: 40,
        anchor_bytes: 50,
        capture_comparison_bytes: 60,
        declared_scanner_bytes: 70,
        total_bytes: 280,
    }
}

fn launch() -> Result<PacketNative5SourceLaunch, Box<dyn std::error::Error>> {
    let (_, _, mut selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();

    // Only full DATA schemas are added. This fixture never creates the genuine
    // Source declaration, registered holder, private ticket or native scope.
    for schema in [
        restoration_suffix_schema()?,
        restoration_observe::restoration_observe_schema()?,
        activation::restoration_activation_schema()?,
        activation::upload::restoration_activation_upload_schema()?,
    ] {
        selection
            .provider
            .extensions_supported
            .push(schema.id.clone());
        selection
            .provider
            .implementation
            .formats
            .push(schema.clone());
        for binding in &mut selection.realization.bindings {
            binding
                .compatibility
                .implementation
                .formats
                .push(schema.clone());
        }
    }
    let value = json!({
        "schema_version": 5,
        "selection": selection,
        "program": {
            "kind": "producer",
            "program": {
                "schema": "source-owned.packet-program.v1",
                "events": []
            }
        },
        "controller_pid": "1",
        "controller_uid": "0",
        "controller_executable": coordinator.reference,
        "admission_token": Bytes::new(vec![7;32]),
        "initial_coordinator": coordinator,
        "limits": {
            "frame_bytes": "65536",
            "nesting": "64",
            "requests": "64",
            "journal_entries": "256",
            "blob_chunk_bytes": "1024"
        },
        "storage": {
            "snapshot_bytes": "16384",
            "control_snapshot_bytes": "8192",
            "protocol_snapshot_bytes": "65536",
            "frame_bank_bytes": "65536",
            "frames_per_direction": "256",
            "hello_bytes": "131080",
            "settlement_bytes": "65536"
        },
        "effects": "/not-opened-by-data-control"
    });
    let mut launch: PacketNative5SourceLaunch = serde_json::from_value(value)?;
    launch.capture_profile = PacketNative5CaptureProfile::OwnedProtocol11 {
        native_before_protocol_bytes: U64::new(65536),
        native_after_protocol_bytes: U64::new(65536),
        host_protocol_bytes: U64::new(65536),
    };
    launch.protocol_metadata_limits = Some(PacketNative5ProtocolMetadataLimits {
        native_before_rows: U64::new(256),
        native_after_rows: U64::new(256),
    });
    launch.native_codec_metadata_extent =
        Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB);
    launch.ack_emitter_selection = Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5);
    launch.complete_restore_selection =
        Some(complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12);
    launch.restore_input_emitter_selection = Some(
        complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12,
    );
    launch.confirmation_selection = Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5);
    launch.fresh_restore_allocation_selection = Some(
        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13,
    );
    launch.capture_allocation_selection =
        Some(capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12);

    Ok(launch)
}

#[test]
fn independent_rows_use_exact_admitted_count_and_refuse_one_short_total() -> TestResult {
    let launch = launch()?;
    let raw = canonical::canonical_json(&serde_json::to_value(&launch)?)?;
    let cached = model();
    let row = original_native_restored_suffix_startup_storage_data(
        &launch,
        &raw,
        &cached,
        2,
        usize::MAX,
    )?;
    let requested = row.requested_bytes_data();
    let exact =
        original_native_restored_suffix_startup_storage_data(&launch, &raw, &cached, 2, requested)?;
    exact.authenticate_same_quote_data(&row)?;
    exact.authenticate_same_inputs_data(&launch, &raw, &cached, 2, requested)?;
    assert!(
        original_native_restored_suffix_startup_storage_data(
            &launch,
            &raw,
            &cached,
            2,
            requested - 1
        )
        .is_err()
    );
    let one = original_native_restored_suffix_startup_storage_data(
        &launch,
        &raw,
        &cached,
        1,
        usize::MAX,
    )?;
    assert_eq!(row.reservation_data().maximum_originals.get(), 2);
    assert_eq!(
        row.reservation_data()
            .ingress
            .retained_requested_bytes
            .get(),
        2 * one
            .reservation_data()
            .ingress
            .retained_requested_bytes
            .get()
    );
    assert_eq!(
        row.reservation_data()
            .actions
            .retained_requested_bytes
            .get(),
        2 * one
            .reservation_data()
            .actions
            .retained_requested_bytes
            .get()
    );
    assert_eq!(
        row.reservation_data()
            .ingress
            .maximum_simultaneous_transient_bytes,
        one.reservation_data()
            .ingress
            .maximum_simultaneous_transient_bytes
    );
    assert!(row.native_counter_scratch_bytes_data() > 0);
    for count in [0, 65, 257] {
        assert!(
            original_native_restored_suffix_startup_storage_data(
                &launch,
                &raw,
                &cached,
                count,
                usize::MAX
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn correspondence_binds_all_eight_cached_fields_raw_bank_and_no_old_codec_inference() -> TestResult
{
    let mut launch = launch()?;
    let raw = canonical::canonical_json(&serde_json::to_value(&launch)?)?;
    let cached = model();
    let row = original_native_restored_suffix_startup_storage_data(
        &launch,
        &raw,
        &cached,
        1,
        usize::MAX,
    )?;
    let mut changed = cached;
    changed.snapshot_bytes += 1;
    changed.journal_bytes -= 1; // Same total and unchanged model_work are insufficient.
    assert_eq!(changed.total_bytes, cached.total_bytes);
    assert!(
        row.authenticate_same_inputs_data(&launch, &raw, &changed, 1, usize::MAX)
            .is_err()
    );
    assert!(
        row.authenticate_same_inputs_data(&launch, b"{}", &cached, 1, usize::MAX)
            .is_err()
    );
    assert!(
        row.authenticate_same_inputs_data(&launch, &raw, &cached, 2, usize::MAX)
            .is_err()
    );
    changed.total_bytes += 1;
    assert!(
        original_native_restored_suffix_startup_storage_data(
            &launch,
            &raw,
            &changed,
            1,
            usize::MAX
        )
        .is_err()
    );
    changed.control_bytes = usize::MAX;
    assert!(
        original_native_restored_suffix_startup_storage_data(
            &launch,
            &raw,
            &changed,
            1,
            usize::MAX
        )
        .is_err()
    );
    launch.capture_profile = PacketNative5CaptureProfile::OriginalArrays6;
    assert!(
        original_native_restored_suffix_startup_storage_data(&launch, &raw, &cached, 1, usize::MAX)
            .is_err()
    );
    Ok(())
}

#[test]
fn missing_duplicate_or_altered_full_suffix_schema_refuses_before_any_native_owner() -> TestResult {
    let mut launch = launch()?;
    let raw = b"inert canonical-bank identity fixture";
    let cached = model();
    let index = launch
        .selection
        .provider
        .implementation
        .formats
        .iter()
        .position(|schema| schema.id.as_str() == PACKET_RESTORATION_SUFFIX_FEATURE)
        .ok_or("missing schema fixture")?;
    let original = launch
        .selection
        .provider
        .implementation
        .formats
        .remove(index);
    assert!(
        original_native_restored_suffix_startup_storage_data(&launch, raw, &cached, 1, usize::MAX)
            .is_err()
    );
    launch
        .selection
        .provider
        .implementation
        .formats
        .push(original.clone());
    launch
        .selection
        .provider
        .implementation
        .formats
        .push(original.clone());
    assert!(
        original_native_restored_suffix_startup_storage_data(&launch, raw, &cached, 1, usize::MAX)
            .is_err()
    );
    launch.selection.provider.implementation.formats.pop();
    let last = launch
        .selection
        .provider
        .implementation
        .formats
        .last_mut()
        .ok_or("missing restored schema")?;
    last.definition.media_type = "text/plain".into();
    assert!(
        original_native_restored_suffix_startup_storage_data(&launch, raw, &cached, 1, usize::MAX)
            .is_err()
    );
    Ok(())
}
