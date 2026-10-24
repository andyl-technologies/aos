//! Checks native closed journal editions without issuing restoration authority.

// crucible-lint: allow panic-shortcut -- Closed historical journal controls intentionally panic on invalid data.
#![expect(clippy::unwrap_used, reason = "checks exact historical journal data")]

use super::*;
use crate::reference_packet::service::confirmation::PacketNativeAfterConfirmationRequest;

fn historical() -> SettledJournalData {
    fn reference(body: &[u8]) -> ContentRef {
        canonical::content_ref(body, "application/json").unwrap()
    }
    let snapshot = reference(b"snapshot");
    let control = reference(b"control");
    let anchor = reference(b"anchor");
    let after = reference(b"after");
    SettledJournalData {
        schema: SETTLED_JOURNAL_11.into(),
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
                capture_operation_id: Id::new("operation").unwrap(),
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

fn registry() -> Value {
    serde_json::to_value(canonical::content_ref(b"registry", SETTLED_REGISTRY_MEDIA).unwrap())
        .unwrap()
}

#[test]
fn native_historical_journal11_preserves_exact_omission_and_cannot_close_complete_restore() {
    let value = serde_json::to_value(historical()).unwrap();
    assert!(value.get("host_extension_registry").is_none());

    let decoded = decode_settled_journal_data(&value).unwrap();

    assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
    assert!(decoded.require_complete_registry_data().is_err());
}

#[test]
fn native_journal12_requires_full_registry_and_preserves_the_complete_old_roster() {
    let original = serde_json::to_value(historical()).unwrap();
    let mut value = original.clone();
    value["schema"] = SETTLED_JOURNAL_12.into();
    value["host_extension_registry"] = registry();

    let decoded = decode_settled_journal_data(&value).unwrap();

    assert_eq!(
        serde_json::to_value(decoded.require_complete_registry_data().unwrap()).unwrap(),
        registry()
    );
    let mut roundtrip = serde_json::to_value(decoded).unwrap();
    assert_eq!(roundtrip, value);
    roundtrip
        .as_object_mut()
        .unwrap()
        .remove("host_extension_registry");
    roundtrip["schema"] = SETTLED_JOURNAL_11.into();
    assert_eq!(roundtrip, original);
}

#[test]
fn native_journal_editions_refuse_null_missing_cross_edition_and_unknown_fields() {
    let mut value = serde_json::to_value(historical()).unwrap();
    value["host_extension_registry"] = Value::Null;
    assert!(decode_settled_journal_data(&value).is_err());
    value["host_extension_registry"] = registry();
    assert!(decode_settled_journal_data(&value).is_err());
    value["schema"] = SETTLED_JOURNAL_12.into();
    assert!(decode_settled_journal_data(&value).is_ok());
    value["unknown_registry_state"] = true.into();
    assert!(decode_settled_journal_data(&value).is_err());
    value
        .as_object_mut()
        .unwrap()
        .remove("unknown_registry_state");
    value["host_extension_registry"] = Value::Null;
    assert!(decode_settled_journal_data(&value).is_err());
    value
        .as_object_mut()
        .unwrap()
        .remove("host_extension_registry");
    assert!(decode_settled_journal_data(&value).is_err());
}

#[test]
fn native_journal12_refuses_wrong_media_and_malformed_full_reference() {
    let mut value = serde_json::to_value(historical()).unwrap();
    value["schema"] = SETTLED_JOURNAL_12.into();
    value["host_extension_registry"] =
        serde_json::to_value(canonical::content_ref(b"registry", "application/json").unwrap())
            .unwrap();
    assert!(decode_settled_journal_data(&value).is_err());

    value["host_extension_registry"] = registry();
    value["host_extension_registry"]["length"] = "-1".into();
    assert!(decode_settled_journal_data(&value).is_err());
}
