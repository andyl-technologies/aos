//! Checks actual envelope allocation, complete correspondence and spent failures.

use super::*;
use crucible_node_format::{Bytes, ExtensionSelection, Id, SemanticVersion, U64, canonical};
use serde_json::json;
use std::time::Duration;

fn fixture() -> Value {
    let selected = crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures::initial_selected_launch(false);
    json!({
        "protocol":"CNP/1", "message":"request", "sequence":"1", "method":"hello",
        "session_id":null, "incarnation_id":null, "node_id":null,
        "execution_owner_id":null, "capture_owner_id":null, "operation_id":null,
        "request_id":"hello/original",
        "body": {
            "versions":["CNP/2", "CNP/1"], "session_id":"session/original",
            "controller_nonce":Bytes::new(vec![19;32]),
            "required_features":["cnp.core/1"], "optional_features":["vendor.maybe/1"],
            "limits":selected["launch"]["limits"],
            "admission_token":Bytes::new(vec![7;32]), "extensions":{},
        },
        "extensions": {"cnp.extension-negotiation/1": {
            "format":"1", "required":[], "optional":[],
        }},
    })
}

fn quoted(value: &Value, cut: OperationalDeadline) -> (Attempt, [usize; 3]) {
    let bytes = serde_json::to_vec(value).unwrap();
    let row = super::super::storage::construction_data(bytes.len(), 268_435_456).unwrap();
    let mut attempt = Attempt::empty_data();
    assert_eq!(attempt.retained_backing_data().unwrap(), 0);
    attempt.start_data(cut).unwrap();
    attempt.quote_data(row).unwrap();
    (attempt, row)
}

#[test]
fn actual_envelope_preserves_all_original_fields_and_owns_fresh_body_allocations() {
    let value = fixture();
    let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let (mut attempt, row) = quoted(&value, cut);

    attempt.construct_data(&value, cut).unwrap();
    let actual = attempt.retained_backing_data().unwrap();
    assert!(actual > 0 && actual <= row[0]);
    let envelope = attempt.envelope.as_ref().unwrap();
    assert_eq!(serde_json::to_value(envelope).unwrap(), value);
    assert_eq!(envelope.body["versions"], json!(["CNP/2", "CNP/1"]));
    assert_ne!(
        envelope.body["controller_nonce"].as_str().unwrap().as_ptr(),
        value["body"]["controller_nonce"].as_str().unwrap().as_ptr()
    );
    assert_ne!(
        envelope.body["versions"].as_array().unwrap().as_ptr(),
        value["body"]["versions"].as_array().unwrap().as_ptr()
    );
    let pointer = std::ptr::from_ref(envelope);

    attempt.complete_data().unwrap();
    assert_eq!(std::ptr::from_ref(attempt.data(cut).unwrap()), pointer);
    assert!(attempt.start_data(cut).is_err());
    assert_eq!(attempt.retained_backing_data().unwrap(), actual);
}

#[test]
fn correspondence_checks_each_header_and_the_complete_original_body_and_extensions() {
    let value = fixture();
    let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let (mut attempt, _) = quoted(&value, cut);
    attempt.construct_data(&value, cut).unwrap();
    attempt.complete_data().unwrap();
    let before = attempt.retained_backing_data().unwrap();

    for field in [
        "protocol",
        "message",
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
        "sequence",
        "method",
        "body",
        "extensions",
    ] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(attempt.authenticate_data(&changed, cut).is_err(), "{field}");
    }
    for pointer in [
        "/body/versions/0",
        "/body/session_id",
        "/body/controller_nonce",
        "/body/required_features/0",
        "/body/optional_features/0",
        "/body/limits/requests",
        "/body/admission_token",
        "/body/extensions",
        "/extensions/cnp.extension-negotiation~11/optional",
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("changed");
        assert!(
            attempt.authenticate_data(&changed, cut).is_err(),
            "{pointer}"
        );
    }
    assert_eq!(attempt.retained_backing_data().unwrap(), before);
    attempt.authenticate_data(&value, cut).unwrap();
}

#[test]
fn decoder_and_terminal_failures_keep_original_output_and_spent_attempts() {
    for decoded in [false, true] {
        let mut value = fixture();
        if decoded {
            value["protocol"] = json!("CNP/other");
        } else {
            value["message"] = json!("unknown");
        }
        let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
        let (mut attempt, _) = quoted(&value, cut);

        assert!(attempt.construct_data(&value, cut).is_err());
        assert_eq!(attempt.envelope.is_some(), decoded);
        assert_eq!(attempt.failure.is_some(), !decoded);
        let retained = attempt.retained_backing_data().unwrap();
        if let Some(failure) = &attempt.failure {
            assert!(matches!(
                failure.category,
                serde_json::error::Category::Data
            ));
            assert_eq!((failure.line, failure.column), (0, 0));
        }
        assert!(attempt.data(cut).is_err());
        assert!(attempt.complete_data().is_err());
        assert!(attempt.start_data(cut).is_err());
        assert_eq!(attempt.retained_backing_data().unwrap(), retained);
    }
}

#[test]
fn stale_and_substituted_cuts_refuse_before_decoder_allocation() {
    for expired in [false, true] {
        let value = fixture();
        let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
        let (mut attempt, _) = quoted(&value, cut);
        let substituted = if expired {
            OperationalDeadline::expired_fixture()
        } else {
            OperationalDeadline::after(Duration::from_secs(4)).unwrap()
        };

        assert!(attempt.construct_data(&value, substituted).is_err());
        assert!(attempt.envelope.is_none());
        assert!(attempt.failure.is_none());
        assert_eq!(attempt.retained_backing_data().unwrap(), 0);
        assert!(attempt.start_data(cut).is_err());
    }
}

#[test]
fn future_row_covers_all_selection_objects_and_large_array_growth() {
    let mut value = fixture();
    for field in ["versions", "required_features", "optional_features"] {
        value["body"][field] = json!(
            (0..513)
                .map(|index| format!("vendor.{field}/{index}"))
                .collect::<Vec<_>>()
        );
    }
    let declaration =
        canonical::content_ref(b"optional envelope definition", "application/json").unwrap();
    let offer = value["extensions"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    offer["optional"] = serde_json::to_value(
        (0..crate::handshake::MAXIMUM_NEGOTIATED_EXTENSIONS)
            .map(|index| ExtensionSelection {
                schema_digest: declaration.hash.clone(),
                declaration: declaration.clone(),
                identifier: Id::new(format!("vendor.definition/{index}")).unwrap(),
                semantic_version: SemanticVersion {
                    major: U64::new(1),
                    minor: U64::new(2),
                    patch: U64::new(3),
                    prerelease: Some("rc.1".into()),
                    build: Some("source.1".into()),
                },
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let (mut attempt, row) = quoted(&value, cut);

    attempt.construct_data(&value, cut).unwrap();
    assert!(attempt.retained_backing_data().unwrap() <= row[0]);
    assert_eq!(
        serde_json::to_value(attempt.envelope.as_ref().unwrap()).unwrap(),
        value
    );
}

#[test]
fn complete_peak_is_exact_and_short_zero_and_overflow_restrictions_refuse() {
    let bytes = serde_json::to_vec(&fixture()).unwrap().len();
    let row = super::super::storage::construction_data(bytes, usize::MAX).unwrap();
    let peak = row.into_iter().sum();

    assert_eq!(
        super::super::storage::construction_data(bytes, peak).unwrap(),
        row
    );
    assert!(super::super::storage::construction_data(bytes, peak - 1).is_err());
    assert!(super::super::storage::construction_data(bytes, 0).is_err());
    assert!(super::super::storage::construction_data(0, usize::MAX).is_err());
    assert!(super::super::storage::construction_data(usize::MAX, usize::MAX).is_err());
}
