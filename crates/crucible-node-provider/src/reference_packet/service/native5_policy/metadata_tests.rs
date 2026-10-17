//! Exercises independent native metadata selection using a modeled declaration.

use super::*;

#[test]
fn selected_native_metadata_extent_preserves_none_and_refuses_legacy_undercredit() {
    let (_handshake, _authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let profile = super::super::PacketNative5CaptureProfile::OriginalArrays6;
    let confirmation = super::super::PacketNative5ConfirmationSelection::AfterProtocolPoll5;
    let emitter = super::super::PacketNative5AckEmitterSelection::CanonicalSdkBlob5;

    let legacy_data = Native5Policy::prepare_original_profile(
        selection.clone(),
        coordinator.clone(),
        profile.clone(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(&legacy_data).unwrap(),
        serde_json::to_vec(&legacy_data.protocol_view()).unwrap(),
        "None preserves the complete old policy object"
    );
    assert!(
        Native5Policy::from_original_launch_with_ack_emitter(
            selection.clone(),
            coordinator.clone(),
            profile.clone(),
            confirmation,
            emitter,
        )
        .is_err(),
        "the old 262144 ceiling remains enforced"
    );

    let selected = Native5Policy::from_original_launch_with_ack_emitter_metadata_extent(
        selection.clone(),
        coordinator.clone(),
        profile.clone(),
        confirmation,
        emitter,
        crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
    )
    .unwrap();
    let count = serialized_credit(&selected.protocol_view(), 512 * 1024).unwrap();
    eprintln!("native selected metadata bytes={count}");
    assert!(count > 256 * 1024 && count <= 512 * 1024);
    let encoded = serde_json::to_value(selected.protocol_view()).unwrap();
    assert_eq!(encoded[0], "source-private.native5-policy-metadata/12");
    assert_eq!(encoded[1], "CanonicalAck512KiB");
    assert_eq!(
        encoded[2]["native_codec_metadata_extent"],
        "CanonicalAck512KiB"
    );
    assert_eq!(
        serde_json::to_value(selected.compact_protocol_view()).unwrap()[0],
        "source-private.native5-policy-compact-metadata/12"
    );
    assert!(
        serde_json::from_str::<crate::client::CanonicalAckCodecMetadataExtent>("\"unbounded\"")
            .is_err()
    );

    let mut foreign = selection;
    foreign.provider.implementation.implementation_id = Id::new("foreign-native-source").unwrap();
    assert!(
        Native5Policy::from_original_launch_with_ack_emitter_metadata_extent(
            foreign,
            coordinator,
            profile,
            confirmation,
            emitter,
            crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
        )
        .is_err(),
        "the selected extent cannot replace source authentication"
    );
}

#[test]
fn original_arrays_policy_matches_the_four_field_wire_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let (_handshake, _authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let policy = Native5Policy::prepare_original_profile(
        selection,
        coordinator,
        super::super::PacketNative5CaptureProfile::OriginalArrays6,
    )?;

    // Freeze the original field order independently of Native5Policy's evolving
    // derived serializer. Comparing two new views would miss a shared null leak.
    #[derive(Serialize)]
    struct OriginalWirePolicy<'a> {
        selection: &'a PacketControlSelection,
        coordinator: &'a InstalledContent,
        definition: &'a ContentRef,
        connected: &'a PacketNative5CoordinatorInstallation,
    }

    let original = OriginalWirePolicy {
        selection: &policy.selection,
        coordinator: &policy.coordinator,
        definition: &policy.definition,
        connected: &policy.connected,
    };
    let expected = serde_json::to_vec(&original)?;

    assert_eq!(serde_json::to_vec(&policy)?, expected);
    assert_eq!(serde_json::to_vec(&policy.protocol_view())?, expected);
    assert_eq!(
        serde_json::to_value(&policy)?
            .as_object()
            .map(|map| map.len()),
        Some(4)
    );
    Ok(())
}

#[test]
fn selected_restore_definitions_survive_each_policy_view() -> Result<(), Box<dyn std::error::Error>>
{
    let (_handshake, _authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let mut policy = Native5Policy::prepare_original_profile(
        selection,
        coordinator,
        super::super::PacketNative5CaptureProfile::OriginalArrays6,
    )?;
    policy.complete_restore_selection = Some(
        super::super::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
    );
    policy.bind_complete_restore_transfer_definitions()?;
    let expected = serde_json::to_value(
        Native5Policy::complete_restore_transfer_schemas()?.map(|schema| schema.definition),
    )?;

    let derived = serde_json::to_value(&policy)?;
    let full = serde_json::to_value(policy.protocol_view())?;
    let compact = serde_json::to_value(policy.compact_protocol_view())?;
    let owned = serde_json::to_value(policy.borrowed_owned11_protocol_view())?;

    assert_eq!(derived["complete_restore_transfer_definitions"], expected);
    for (view, tag) in [
        (&full, "source-private.native5-policy-restore-transfer/15"),
        (
            &compact,
            "source-private.native5-policy-compact-restore-transfer/15",
        ),
        (
            &owned,
            "source-private.native5-policy-owned-restore-transfer/15",
        ),
    ] {
        assert_eq!(view[0], tag);
        assert_eq!(view[1], expected);
    }

    // These are serialization data controls. Selecting an enum in a test cannot
    // install its schemas into the immutable original arrays-six declaration.
    assert!(policy.validate_immutable_content().is_err());
    Ok(())
}
