//! Exercises explicit historical journal editions without constructing authority.

use super::*;
use crucible_node_transport::reference_packet::service::confirmation::PacketNativeAfterConfirmationRequest;

fn journal() -> PacketCompleteSettledJournal {
    fn reference(bytes: &[u8]) -> ContentRef {
        canonical::content_ref(bytes, "application/json").unwrap()
    }
    let snapshot = reference(b"snapshot");
    let control = reference(b"control");
    let anchor = reference(b"anchor");
    let after = reference(b"after");
    PacketCompleteSettledJournal {
        schema: PACKET_COMPLETE_SETTLED_JOURNAL_SCHEMA.into(),
        owner: Id::new("owner").unwrap(),
        participants: vec![Id::new("node").unwrap()],
        cut: Position::new(
            U64::new(0),
            U64::new(0),
            crucible_node_format::Phase::BoundaryControl,
        ),
        ordinal: U64::new(0),
        runtime: reference(b"runtime"),
        backend_implementation: reference(b"backend"),
        semantic: reference(b"semantic"),
        ancestry: reference(b"ancestry"),
        native_snapshot: snapshot.clone(),
        native_control: control.clone(),
        native_anchor: anchor.clone(),
        native_after_protocol: after.clone(),
        host_protocol: reference(b"host"),
        host_extension_registry: None,
        confirmation_request: Id::new("confirmation").unwrap(),
        confirmation: PacketNativeAfterConfirmationReceipt {
            schema: "source-owned.packet-native-after-confirmation-receipt/5".into(),
            capture: PacketNativeAfterConfirmationRequest {
                schema: "source-owned.packet-native-after-confirmation-request/5".into(),
                capture_request_id: Id::new("capture").unwrap(),
                capture_operation_id: Id::new("capture-operation").unwrap(),
                capture_request_hash: canonical::hash("cnp.request.v1", b"request").unwrap(),
                capture_terminal_hash: canonical::hash(
                    "source-owned.packet-native-capture-terminal/5",
                    b"terminal",
                )
                .unwrap(),
                capture_terminal_sequence: U64::new(1),
                native_snapshot_ref: snapshot,
                native_control_ref: control,
                native_anchor_ref: anchor,
            },
            native_after_capacity: after.length,
            native_after_ref: after,
        },
    }
}

fn decode(value: &serde_json::Value) -> Result<PacketCompleteSettledJournal, OperationFailure> {
    let bytes = serde_json::to_vec(value).unwrap();
    PacketCompleteSettledJournal::decode_data(&bytes, bytes.len())
}

#[test]
fn historical11_stays_exact_and_refuses_the_complete_registry_class() {
    let original = journal();
    let value = serde_json::to_value(&original).unwrap();
    assert!(value.get("host_extension_registry").is_none());
    let restored = decode(&value).unwrap();
    assert_eq!(restored.dependencies().count(), 9);
    assert!(restored.require_complete_registry_data().is_err());
    assert_eq!(serde_json::to_value(&restored).unwrap(), value);
}

#[test]
fn journal12_requires_the_full_registry_reference_and_preserves_all_other_fields() {
    let mut complete = journal();
    let original = serde_json::to_value(&complete).unwrap();
    complete.schema = PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA.into();
    complete.host_extension_registry =
        Some(canonical::content_ref(b"registry", registry_capture::HOST_REGISTRY_MEDIA).unwrap());
    let value = serde_json::to_value(&complete).unwrap();
    let restored = decode(&value).unwrap();
    assert_eq!(
        restored.require_complete_registry_data().unwrap(),
        complete.host_extension_registry.as_ref().unwrap()
    );
    assert_eq!(restored.dependencies().count(), 10);
    let mut preserved = serde_json::to_value(&restored).unwrap();
    preserved
        .as_object_mut()
        .unwrap()
        .remove("host_extension_registry");
    preserved["schema"] = original["schema"].clone();
    assert_eq!(preserved, original);
}

#[test]
fn nullable_or_cross_edition_registry_fields_never_supply_complete_data() {
    let mut value = serde_json::to_value(journal()).unwrap();
    value["host_extension_registry"] = serde_json::Value::Null;
    assert!(decode(&value).is_err());
    value["host_extension_registry"] = serde_json::to_value(
        canonical::content_ref(b"registry", registry_capture::HOST_REGISTRY_MEDIA).unwrap(),
    )
    .unwrap();
    assert!(decode(&value).is_err());
    value["schema"] = PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA.into();
    assert!(decode(&value).is_ok());
    value["host_extension_registry"] = serde_json::Value::Null;
    assert!(decode(&value).is_err());
    value
        .as_object_mut()
        .unwrap()
        .remove("host_extension_registry");
    assert!(decode(&value).is_err());
}

#[test]
fn journal12_refuses_wrong_media_and_unknown_fields() {
    let mut value = serde_json::to_value(journal()).unwrap();
    value["schema"] = PACKET_COMPLETE_SETTLED_REGISTRY_JOURNAL_SCHEMA.into();
    value["host_extension_registry"] =
        serde_json::to_value(canonical::content_ref(b"registry", "application/json").unwrap())
            .unwrap();
    assert!(decode(&value).is_err());
    value["host_extension_registry"] = serde_json::to_value(
        canonical::content_ref(b"registry", registry_capture::HOST_REGISTRY_MEDIA).unwrap(),
    )
    .unwrap();
    value["unknown_registry_state"] = true.into();
    assert!(decode(&value).is_err());
}
