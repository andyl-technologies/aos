//! Wire adversaries that must refuse before actor or native admission.

// crucible-lint: allow rust-allow -- test setup and exact authority regressions deliberately panic on failure.
// crucible-lint: allow panic-shortcut -- These node control tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{io::Write, os::unix::net::UnixStream};

use super::*;

#[test]
fn declared_oversized_frame_refuses_without_waiting_for_body() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    sender.write_all(&u32::MAX.to_be_bytes()).unwrap();

    let result = transport::read::<NodeControlRequest>(
        &mut receiver,
        transport::operational_now() + transport::EXCHANGE_TIMEOUT,
    );

    assert!(matches!(result, Err(NodeControlError::Refused(_))));
}

#[test]
fn duplicate_keys_noncanonical_frames_and_unknown_editions_refuse() {
    for body in [
        br#"{"format":"crucible.node-control","format":"crucible.node-control"}"#.as_slice(),
        br#"{ "command":{"execution":"29292929292929292929292929292929","operation":"status"},"format":"crucible.node-control","request_id":"probe","version":1}"#,
        br#"{"command":{"execution":"29292929292929292929292929292929","operation":"status"},"format":"crucible.node-control","request_id":"probe","version":2}"#,
    ] {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        sender.write_all(body).unwrap();

        let result = transport::read::<NodeControlRequest>(
            &mut receiver, transport::operational_now() + transport::EXCHANGE_TIMEOUT,
        ).and_then(|request| request.validate());

        assert!(result.is_err(), "wire adversary reached actor admission");
    }
}

#[test]
fn closed_selection_and_execution_nonce_rules_refuse_before_connect() {
    assert!(decode_node_selections(br#"[{"node":"clock","owner":"clock-owner","kind":{"implementation":"host_clock","qemu":true}}]"#).is_err());
    for execution in [
        "",
        "00000000000000000000000000000000",
        "2929292929292929292929292929292A",
    ] {
        assert!(
            NodeControlRequest::new(
                "probe",
                NodeControlCommand::Status {
                    execution: execution.into()
                }
            )
            .is_err()
        );
    }
    assert!(
        NodeControlRequest::new(
            "probe",
            NodeControlCommand::Status {
                execution: "29292929292929292929292929292929".into(),
            }
        )
        .is_ok()
    );
}

#[test]
fn exact_state_control_requires_explicit_edition_without_relabeling_old_status() {
    let state = NodeHostStateRequest::status("29292929292929292929292929292929".into()).unwrap();
    let request = NodeControlRequest::host_state("probe/state", state.clone()).unwrap();
    assert_eq!(request.version, 2);
    assert!(
        NodeControlRequest::new(
            "probe/state",
            NodeControlCommand::HostState {
                request: Box::new(state)
            }
        )
        .is_err()
    );

    let mut old = NodeControlRequest::new(
        "probe/old",
        NodeControlCommand::Status {
            execution: "29292929292929292929292929292929".into(),
        },
    )
    .unwrap();
    old.version = 2;
    assert!(old.validate().is_err());
}

#[test]
fn exact_state_quota_and_artifact_registry_are_private_operator_policy() {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let expected = canonical::content_ref(b"installed bytes", "application/octet-stream").unwrap();
    let original = serde_json::json!({
        "format":"crucible.node-daemon-policy", "version":1,
        "state_directory":temporary.path(), "socket":temporary.path().join("node.sock"),
        "device_executable":temporary.path().join("device"), "expected_device":expected,
        "control_timeout_ms":3000, "maximum_worlds":2,"maximum_pending_requests":2
    });
    let decode = |value: &serde_json::Value| {
        NodeDaemonPolicy::from_json(&serde_json::to_vec(value).unwrap())
    };
    let legacy = decode(&original).unwrap();
    assert!(legacy.maximum_host_state_worlds.is_none());
    assert!(legacy.immutable_artifacts.is_empty());
    assert_eq!(
        serde_json::to_value(legacy).unwrap(),
        original,
        "edition-one canonical policy stays unchanged"
    );

    let mut exact = original.clone();
    exact["version"] = 2.into();
    assert!(
        decode(&exact).is_err(),
        "exact custody needs its own explicit quota"
    );
    exact["maximum_host_state_worlds"] = 2.into();
    assert!(decode(&exact).is_ok());
    exact["version"] = 1.into();
    assert!(
        decode(&exact).is_err(),
        "old policy cannot silently allocate another actor"
    );
    exact["version"] = 2.into();
    exact["immutable_artifacts"] = serde_json::json!([{"path":"relative.img","expected":expected}]);
    assert!(decode(&exact).is_err());
    exact["immutable_artifacts"][0]["path"] = serde_json::json!(temporary.path().join("base.img"));
    assert!(decode(&exact).is_ok());
    exact["immutable_artifacts"][0]["qualification"] = true.into();
    assert!(
        decode(&exact).is_err(),
        "operator DTO cannot invent authority fields"
    );

    exact["immutable_artifacts"] = serde_json::json!([{"mode":"archive_only","expected":expected}]);
    assert!(decode(&exact).is_ok());
    exact["immutable_artifacts"][0]["path"] = serde_json::json!(temporary.path().join("base.img"));
    assert!(
        decode(&exact).is_err(),
        "archive-only never falls back to a path"
    );
    exact["immutable_artifacts"][0]
        .as_object_mut()
        .unwrap()
        .remove("path");
    exact["version"] = 1.into();
    exact
        .as_object_mut()
        .unwrap()
        .remove("maximum_host_state_worlds");
    assert!(
        decode(&exact).is_err(),
        "archive-only is explicitly edition two"
    );
}
