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
