//! Checks inert prebirth geometry without issuing a ticket, boot or action.

use super::*;
use crate::reference_packet::service::native_startup::{
    PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA, PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA,
    PacketNativeBirthStartupInputs, PacketNativeInvocationPurposeData,
    original_native_birth_startup_storage_data, original_native_invocation_baseline_storage_data,
    original_native_invocation_ingress_storage_data,
};
use crate::reference_packet::service::*;
use crucible_node_format::{Bytes, U64, canonical};
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

#[test]
fn recurring_quote_recomputes_independent_axes_and_binds_raw_launch_and_closed_body() -> TestResult
{
    use super::super::observation::original_native_restored_suffix_observation_storage_data;
    let launch = launch()?;
    let raw = canonical::canonical_json(&serde_json::to_value(&launch)?)?;
    let startup = original_native_restored_suffix_startup_storage_data(
        &launch,
        &raw,
        &model(),
        2,
        usize::MAX,
    )?;
    let binding = &launch.selection.realization.bindings[0];
    let observe = crate::bodies::ObserveRequest {
        binding_hash: launch.selection.realization.owner_bindings[0].identity()?,
        owner_generation: binding.authority.owner_generation,
        after_observation_sequence: U64::new(0),
        maximum_items: U64::new(1),
        extensions: Default::default(),
    };
    let quote = original_native_restored_suffix_observation_storage_data(
        &startup,
        &launch,
        &raw,
        &observe,
        usize::MAX,
    )?;
    let exact = original_native_restored_suffix_observation_storage_data(
        &startup,
        &launch,
        &raw,
        &observe,
        quote.requested_bytes_data(),
    )?;
    exact.authenticate_same_quote_data(&quote)?;
    assert!(
        original_native_restored_suffix_observation_storage_data(
            &startup,
            &launch,
            &raw,
            &observe,
            quote.requested_bytes_data() - 1
        )
        .is_err()
    );
    assert!(
        original_native_restored_suffix_observation_storage_data(
            &startup,
            &launch,
            b"{}",
            &observe,
            usize::MAX
        )
        .is_err()
    );
    let mut changed = observe.clone();
    changed.maximum_items = U64::new(2);
    assert!(
        original_native_restored_suffix_observation_storage_data(
            &startup,
            &launch,
            &raw,
            &changed,
            usize::MAX
        )
        .is_err()
    );
    assert_eq!(
        startup
            .reservation_data()
            .actions
            .retained_requested_bytes
            .get(),
        2 * quote
            .native_allocation_data()
            .retained_requested_bytes
            .get()
    );
    assert!(quote.host_retained_requested_bytes_data() > 0);
    assert!(quote.source_evidence_retained_requested_bytes_data() > 0);
    assert!(quote.maximum_restored_record_bytes_data() > 0);
    assert_eq!(quote.maximum_underlying_record_bytes_data(), 65_536);
    Ok(())
}

#[test]
fn original_invocation_declared_restore_grammars_have_no_fresh_ingress() -> TestResult {
    let launch = launch()?;
    let purpose = PacketNativeInvocationPurposeData::original_execution_data(&launch)?;
    // Full immutable grammars remain advertised, but DATA never turns them
    // into fresh permissions or reachable fresh-only attempt allocations.
    for feature in [
        activation::PACKET_RESTORATION_ACTIVATION_FEATURE,
        restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE,
    ] {
        assert!(
            launch
                .selection
                .provider
                .extensions_supported
                .iter()
                .any(|one| one.as_str() == feature)
        );
    }
    assert!(original_native_invocation_ingress_storage_data(&launch, &purpose, 0)?.is_none());

    let mut foreign = launch;
    foreign.selection.admission = crucible_node_format::Id::new("foreign-ingress-admission")?;
    assert!(
        original_native_invocation_ingress_storage_data(&foreign, &purpose, usize::MAX).is_err()
    );
    Ok(())
}

#[test]
fn fresh_invocation_ingress_keeps_independent_feature_rows_and_exact_ceiling() -> TestResult {
    use crate::reference_packet::service::ack_emitter::{
        original_native_restoration_activation_ingress_row_data,
        original_native_restoration_observation_ingress_row_data,
    };

    let mut launch = launch()?;
    let runtime = canonical::content_ref(b"actual inert runtime bytes", "application/runtime")?;
    let native = canonical::content_ref(b"actual inert native bytes", "application/native")?;
    let owner = &launch.selection.realization.owner_bindings[0].owner.id;
    let purpose = PacketNativeInvocationPurposeData::restoration_target_data(
        &launch, &runtime, &native, owner,
    )?;
    let frame = usize::try_from(launch.limits.frame_bytes.get())?;
    let activation_row = original_native_restoration_activation_ingress_row_data(frame)?;
    let observation_row = original_native_restoration_observation_ingress_row_data(frame)?;
    let features = launch.selection.provider.extensions_supported.clone();

    for (activation_selected, observation_selected) in
        [(true, true), (true, false), (false, true), (false, false)]
    {
        launch.selection.provider.extensions_supported = features
            .iter()
            .filter(|feature| {
                (activation_selected
                    || feature.as_str() != activation::PACKET_RESTORATION_ACTIVATION_FEATURE)
                    && (observation_selected
                        || feature.as_str()
                            != restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE)
            })
            .cloned()
            .collect();
        let quoted =
            original_native_invocation_ingress_storage_data(&launch, &purpose, usize::MAX)?;
        let Some(row) = quoted else {
            assert!(!activation_selected && !observation_selected);
            assert!(
                original_native_invocation_ingress_storage_data(&launch, &purpose, 0)?.is_none()
            );
            continue;
        };
        match (activation_selected, observation_selected) {
            (true, false) => assert_eq!(row, activation_row),
            (false, true) => assert_eq!(row, observation_row),
            (true, true) => {
                assert_eq!(
                    row.retained_requested_bytes.get(),
                    activation_row.retained_requested_bytes.get()
                        + observation_row.retained_requested_bytes.get()
                );
                assert_eq!(
                    row.maximum_simultaneous_transient_bytes.get(),
                    activation_row
                        .maximum_simultaneous_transient_bytes
                        .get()
                        .max(observation_row.maximum_simultaneous_transient_bytes.get())
                );
                assert_eq!(
                    row.declared_counter_scratch_bytes.get(),
                    activation_row
                        .declared_counter_scratch_bytes
                        .get()
                        .max(observation_row.declared_counter_scratch_bytes.get())
                );
            }
            (false, false) => return Err("unselected fresh ingress returned an owner row".into()),
        }
        let exact = usize::try_from(row.requested_peak_data()?)?;
        assert_eq!(
            original_native_invocation_ingress_storage_data(&launch, &purpose, exact)?,
            Some(row)
        );
        assert!(
            original_native_invocation_ingress_storage_data(&launch, &purpose, exact - 1).is_err()
        );
    }
    launch.selection.admission = crucible_node_format::Id::new("foreign-fresh-ingress-admission")?;
    assert!(
        original_native_invocation_ingress_storage_data(&launch, &purpose, usize::MAX).is_err()
    );
    Ok(())
}

#[test]
fn original_invocation_native_recount_matches_the_unmodified_host_baseline() -> TestResult {
    let launch = launch()?;
    let purpose = PacketNativeInvocationPurposeData::original_execution_data(&launch)?;
    let raw_launch = canonical::canonical_json(&serde_json::to_value(&launch)?)?;
    let private_launch = crucible_node_format::Id::new("inert-original-private-launch")?;
    // These are full typed launch occurrences in a closed prospective binding,
    // not a Source/key/ticket or permission to enter the inherited constructor.
    let mut source = json!({
        "schema": PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA,
        "selection": launch.selection,
        "program": launch.program,
        "coordinator": launch.initial_coordinator,
        "limits": launch.limits,
        "storage": launch.storage,
        "capture_profile": launch.capture_profile,
        "confirmation_selection": launch.confirmation_selection,
        "ack_emitter_selection": launch.ack_emitter_selection,
        "codec_metadata_extent": launch.native_codec_metadata_extent,
        "native_codec_metadata_extent": launch.native_codec_metadata_extent,
        "protocol_metadata_limits": launch.protocol_metadata_limits,
        "complete_restore_selection": launch.complete_restore_selection,
        "restore_input_emitter_selection": launch.restore_input_emitter_selection,
        "capture_allocation_selection": launch.capture_allocation_selection,
        "fresh_restore_allocation_selection": launch.fresh_restore_allocation_selection,
        "report_startup_allocation": null,
        "native_startup_allocation": null,
    });
    let raw_source14 = canonical::canonical_json(&source)?;
    let registration = canonical::canonical_json(&json!({
        "schema": "source-owned.packet-canonical-ack-registration/5",
        "role": "controller",
        "session_id": launch.selection.realization.bindings[0].authority.session_id,
        "incarnation_id": launch.selection.realization.bindings[0].authority.incarnation_id,
        "limits": launch.limits,
        "features": launch.selection.provider.extensions_supported,
        "extensions": [],
        "envelope_extensions": {},
    }))?;
    let host_inputs = PacketNativeBirthStartupInputs {
        launch: &launch,
        private_launch: &private_launch,
        encoded_launch: &raw_launch,
        source_birth: &raw_source14,
        host_registration: &registration,
    };
    let host = original_native_birth_startup_storage_data(&host_inputs, usize::MAX)?;
    let native_peak = host
        .retained_requested_bytes()
        .checked_add(host.maximum_simultaneous_transient_bytes())
        .and_then(|bytes| bytes.checked_add(host.declared_counter_scratch_bytes()))
        .ok_or("native baseline extent")?;
    let private_peak = host
        .private_bootstrap_retained_requested_bytes()
        .checked_add(host.private_bootstrap_maximum_simultaneous_transient_bytes())
        .and_then(|bytes| bytes.checked_add(host.declared_counter_scratch_bytes()))
        .ok_or("private baseline extent")?;
    let sealed_baseline_maximum = native_peak.max(private_peak);
    source["schema"] = json!(PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA);
    source["invocation"] = serde_json::to_value(purpose)?;
    let raw_source15 = canonical::canonical_json(&source)?;
    let native_inputs = PacketNativeBirthStartupInputs {
        source_birth: &raw_source15,
        ..host_inputs
    };

    let native = original_native_invocation_baseline_storage_data(
        &native_inputs,
        &purpose,
        sealed_baseline_maximum,
    )?;

    assert_eq!(
        native.retained_requested_bytes(),
        host.retained_requested_bytes()
    );
    assert_eq!(
        native.maximum_simultaneous_transient_bytes(),
        host.maximum_simultaneous_transient_bytes()
    );
    assert_eq!(
        native.declared_counter_scratch_bytes(),
        host.declared_counter_scratch_bytes()
    );
    assert_eq!(
        native.private_bootstrap_retained_requested_bytes(),
        host.private_bootstrap_retained_requested_bytes()
    );
    assert_eq!(
        native.private_bootstrap_maximum_simultaneous_transient_bytes(),
        host.private_bootstrap_maximum_simultaneous_transient_bytes()
    );
    assert!(
        native_inputs
            .launch
            .selection
            .provider
            .extensions_supported
            .iter()
            .any(|feature| feature.as_str() == activation::PACKET_RESTORATION_ACTIVATION_FEATURE)
    );
    Ok(())
}
