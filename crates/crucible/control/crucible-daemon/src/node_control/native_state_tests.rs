//! Portable native control preflight; no installed qualification is issued here.

// Panics identify an incorrectly accepted edition or operator-policy boundary.
// crucible-lint: allow panic-shortcut -- These native state tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::node_observed_executor::{InstalledGem5Isa, NativeCapturePoint, NativeWorldRequest};

#[test]
fn native_state_selects_a_distinct_control_edition() {
    let native = NativeWorldRequest::Capture {
        execution: "192939495969798999a9b9c9d9e9f909".into(),
        isa: InstalledGem5Isa::X86_64,
        point: NativeCapturePoint::Pending,
    };
    let request = NodeControlRequest::native_state("operator/native", native.clone()).unwrap();
    assert_eq!(request.version, 3);
    assert!(
        NodeControlRequest::new(
            "operator/native",
            NodeControlCommand::NativeState {
                request: Box::new(native)
            }
        )
        .is_err()
    );
    let mut wrong = request;
    wrong.version = 2;
    assert!(wrong.validate().is_err());
}

#[test]
fn native_selection_cannot_carry_paths_certificates_or_replacement_grants() {
    let request = serde_json::json!({
        "operation":"capture", "execution":"192939495969798999a9b9c9d9e9f909",
        "isa":"x86_64", "point":"pending",
    });
    for (field, value) in [
        ("executable", serde_json::json!("/private/provider")),
        ("certificate", serde_json::json!("caller-proof")),
        ("horizon_ps", serde_json::json!("2000000000")),
        ("qualification", serde_json::json!(true)),
    ] {
        let mut changed = request.clone();
        changed[field] = value;
        assert!(serde_json::from_value::<NativeWorldRequest>(changed).is_err());
    }
}

#[test]
fn native_actor_requires_explicit_private_policy_edition_and_request_capacity() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let expected =
        canonical::content_ref(b"installed companion", "application/octet-stream").unwrap();
    let mut policy = serde_json::json!({
        "format":"crucible.node-daemon-policy", "version":1,
        "state_directory":directory.path(), "socket":directory.path().join("node.sock"),
        "device_executable":directory.path().join("device"), "expected_device":expected,
        "control_timeout_ms":3000, "maximum_worlds":2,"maximum_pending_requests":2,
    });
    let decode = |value: &serde_json::Value| {
        NodeDaemonPolicy::from_json(&serde_json::to_vec(value).unwrap())
    };
    let original = decode(&policy).unwrap();
    assert!(original.maximum_native_state_requests.is_none());
    assert_eq!(serde_json::to_value(original).unwrap(), policy);
    policy["maximum_native_state_requests"] = 2.into();
    assert!(decode(&policy).is_err());
    policy["version"] = 3.into();
    assert!(decode(&policy).is_ok());
    policy["maximum_native_state_requests"] = 0.into();
    assert!(decode(&policy).is_err());
    policy["maximum_native_state_requests"] = 65.into();
    assert!(decode(&policy).is_err());
    policy["maximum_native_state_requests"] = 2.into();
    policy["maximum_host_state_worlds"] = 1.into();
    assert!(decode(&policy).is_err());
    policy["maximum_host_state_worlds"] = 2.into();
    assert!(decode(&policy).is_ok());
}
