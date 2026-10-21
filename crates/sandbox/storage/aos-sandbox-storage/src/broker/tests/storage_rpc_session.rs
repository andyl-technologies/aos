//! Invokes the independently built signed client inside the Controller unit.
//!
//! Security owns handshake, traffic reservation, verification and terminal
//! commits. This effect-owner fixture consumes only its child's bounded test
//! output; it never constructs a session or depends on application assembly.

use std::fs;
use std::io::Read as _;
use std::process::Command;

use aos_sandbox_api::aos::sandbox::local::v1::{
    BrokerMethod, BrokerRequestEnvelope, BrokerResponseEnvelope,
};
use buffa::Message as _;

fn invoke(action: &str, method: BrokerMethod, packet: &[u8]) -> Vec<u8> {
    assert!(packet.len() <= super::STORAGE_RPC_RESPONSE_BYTES as usize);
    let executable = std::env::var_os("AOS_STORAGE_RPC_CLIENT").unwrap();
    let directory = tempfile::Builder::new()
        .prefix("aos-storage-rpc-client-")
        .tempdir()
        .unwrap();
    let input = directory.path().join("request.pb");
    let output = directory.path().join("result.pb");
    fs::write(&input, packet).unwrap();

    // Inheriting this genuine unit's uid, cgroup and confinement preserves the
    // endpoint identity. No credential, journal or socket descriptor is passed.
    let status = Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            "handshake::storage_rpc_qualification::installed_storage_rpc_client",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("AOS_STORAGE_RPC_CLIENT_ACTION", action)
        .env("AOS_STORAGE_RPC_CLIENT_METHOD", format!("{method:?}"))
        .env("AOS_STORAGE_RPC_CLIENT_INPUT", input)
        .env("AOS_STORAGE_RPC_CLIENT_OUTPUT", &output)
        .status()
        .unwrap();
    assert!(status.success(), "installed signed client failed: {status}");

    let mut result = Vec::new();
    fs::File::open(output)
        .unwrap()
        .take(u64::from(super::STORAGE_RPC_RESPONSE_BYTES) + 1)
        .read_to_end(&mut result)
        .unwrap();
    assert!(result.len() <= super::STORAGE_RPC_RESPONSE_BYTES as usize);
    result
}

pub(super) fn exchange(
    method: BrokerMethod,
    envelope: BrokerRequestEnvelope,
) -> BrokerResponseEnvelope {
    let result = invoke("exchange", method, &envelope.encode_to_vec());
    let outcome = BrokerResponseEnvelope::decode_from_slice(&result).unwrap();
    assert_eq!(outcome.method, method);
    assert!(!outcome.signed_session_outcome.is_empty());
    outcome
}

pub(super) fn reject_downgrade(method: BrokerMethod) {
    assert_eq!(
        invoke("reject-downgrade", method, &[]),
        b"downgrade-rejected-v1"
    );
}

pub(super) fn reject_missing_authority(packet: &[u8]) {
    let method = BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN;
    assert_eq!(
        invoke("reject-missing-authority", method, packet),
        b"missing-authority-rejected-v1",
    );
}

/// Checks durable inventory equality independently of the broker incarnation.
pub(super) fn assert_inventory_unchanged(previous: &[u8], current: &[u8], restarted: bool) {
    use aos_sandbox_protocol::decode_storage_resource_inventory_response_with_model;

    let (_, previous) = decode_storage_resource_inventory_response_with_model(
        previous,
        super::STORAGE_RPC_RESPONSE_BYTES,
    )
    .unwrap();
    let (_, mut current) = decode_storage_resource_inventory_response_with_model(
        current,
        super::STORAGE_RPC_RESPONSE_BYTES,
    )
    .unwrap();

    if restarted {
        assert_ne!(current.broker_instance_id, previous.broker_instance_id);
    } else {
        assert_eq!(current.broker_instance_id, previous.broker_instance_id);
    }

    // Each signed response describes its actual emitting process. Restart
    // replaces that process, while every workspace, publication, lifecycle
    // record, repair receipt and durable catalog boundary must remain exact.
    current.broker_instance_id = previous.broker_instance_id.clone();
    assert_eq!(current, previous);
}
