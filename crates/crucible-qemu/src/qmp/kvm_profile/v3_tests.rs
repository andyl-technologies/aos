//! Wire-model tests for disjoint component editions, never native qualification.

// crucible-lint: allow rust-allow -- closed wire-model setup and refusals deliberately panic on failure.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::qmp::QmpKvmClockOperation;
use serde_json::json;

fn frozen_request() -> QmpKvmClockRequest {
    QmpKvmClockRequest {
        operation: QmpKvmClockOperation::Freeze,
        window_generation: 9,
        start_ns: 0,
        end_ns: 0,
        stop_budget_ns: 1_000_000,
    }
}

fn response() -> serde_json::Value {
    json!({
        "schema-version": 3, "window-generation": 9,
        "current-ns": 20, "start-ns": 10, "end-ns": 30,
        "numerator": 1, "denominator": 1, "kernel-components": 159,
        "run-owners": 0, "active": false,
        "native-owners-stopped": true, "profile-qualified": false,
    })
}

#[test]
fn new_namespace_preserves_original_encoding_and_uses_distinct_command_kind() {
    let request = frozen_request();
    let original = QmpCommand::KvmClockComponent { request: &request };
    let edition_three = QmpCommand::KvmClockComponentV3 { request: &request };

    assert_eq!(original.kind(), QmpCommandKind::KvmClockComponent);
    assert_eq!(edition_three.kind(), QmpCommandKind::KvmClockComponentV3);
    assert_eq!(
        original.request(),
        json!({"execute":"x-crucible-kvm-clock","arguments":request})
    );
    assert_eq!(
        edition_three.request(),
        json!({"execute":"x-crucible-kvm-clock-v3","arguments":request})
    );
}

#[test]
fn component_editions_refuse_each_others_schema_and_coverage() {
    let request = frozen_request();
    let mut value = response();
    assert_eq!(
        parse_v3_component(&request, &value)
            .unwrap()
            .observed()
            .schema_version,
        3
    );
    assert!(super::super::parse_clock_component(&request, &value).is_err());

    value["schema-version"] = json!(1);
    value["kernel-components"] = json!(7);
    assert!(super::super::parse_clock_component(&request, &value).is_ok());
    assert!(parse_v3_component(&request, &value).is_err());

    value["schema-version"] = json!(3);
    assert!(parse_v3_component(&request, &value).is_err());
    value["schema-version"] = json!(1);
    value["kernel-components"] = json!(159);
    assert!(parse_v3_component(&request, &value).is_err());
}

#[test]
fn v3_component_cannot_claim_full_profile_or_changed_native_ownership() {
    let request = frozen_request();
    let value = response();

    for (field, replacement) in [
        ("profile-qualified", json!(true)),
        ("window-generation", json!(10)),
        ("run-owners", json!(1)),
        ("active", json!(true)),
        ("kernel-components", json!(191)),
        ("denominator", json!(0)),
        ("current-ns", json!(u64::MAX)),
        ("unknown-qualified-owner", json!(true)),
    ] {
        let mut forged = value.clone();
        forged[field] = replacement;
        assert!(parse_v3_component(&request, &forged).is_err(), "{field}");
    }
}

#[test]
fn v3_begin_and_step_retain_original_coordinate_and_ceiling() {
    let request = QmpKvmClockRequest {
        operation: QmpKvmClockOperation::Begin,
        window_generation: 9,
        start_ns: 10,
        end_ns: 30,
        stop_budget_ns: 0,
    };
    let mut value = response();
    value["active"] = json!(true);
    value["native-owners-stopped"] = json!(false);
    assert!(parse_v3_component(&request, &value).is_ok());

    value["end-ns"] = json!(31);
    assert!(parse_v3_component(&request, &value).is_err());
    let step = QmpKvmClockRequest {
        operation: QmpKvmClockOperation::Step,
        start_ns: 40,
        ..request
    };
    value = response();
    assert!(parse_v3_component(&step, &value).is_err());
    value["current-ns"] = json!(40);
    assert!(parse_v3_component(&step, &value).is_ok());
}

#[test]
fn v3_invalid_bounds_keep_distinct_diagnostics_before_any_io() {
    let mut request = frozen_request();
    request.stop_budget_ns = 5_000_000_001;
    assert!(matches!(
        validate_clock_request_for(&request, QmpCommandKind::KvmClockComponentV3),
        Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::KvmClockComponentV3,
            ..
        })
    ));
    request.stop_budget_ns = 1_000_000;
    request.start_ns = u64::MAX;
    assert!(validate_clock_request_for(&request, QmpCommandKind::KvmClockComponentV3).is_err());
}
