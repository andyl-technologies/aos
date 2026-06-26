//! Checks the RPC third of `gate:abi-conformance`.

#![forbid(unsafe_code)]

use crucible_api::{
    GOLDEN_RPC_VECTORS, GOLDEN_VECTOR_RPC_PROTOCOL_VERSION, GOLDEN_VECTOR_RPC_REGENERATION_RULE,
    ProtocolVersion, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_BUILD, RPC_PROTOCOL_MAJOR,
    RPC_PROTOCOL_MINOR, RPC_PROTOCOL_PATCH, RPC_PROTOCOL_VERSION, RpcAbiError, RpcGoldenVector,
    RpcGoldenVectorMessage, encode_rpc_message, negotiate_rpc_protocol,
};

#[test]
fn rpc_protocol_version_is_explicit_and_rejects_major_mismatch() {
    assert_eq!(RPC_PROTOCOL_MAJOR, 1);
    assert_eq!(RPC_PROTOCOL_MINOR, 0);
    assert_eq!(RPC_PROTOCOL_PATCH, 0);
    assert_eq!(RPC_PROTOCOL_BUILD, "crucible-rpc-abi-v1");
    assert_eq!(RPC_PROTOCOL_VERSION, GOLDEN_VECTOR_RPC_PROTOCOL_VERSION);
    assert!(GOLDEN_VECTOR_RPC_REGENERATION_RULE.contains("RPC_PROTOCOL_VERSION"));

    let compatible_minor = ProtocolVersion {
        major: RPC_PROTOCOL_MAJOR,
        minor: RPC_PROTOCOL_MINOR + 1,
        patch: RPC_PROTOCOL_PATCH,
        build: RPC_PROTOCOL_BUILD,
    };
    assert_eq!(
        negotiate_rpc_protocol(compatible_minor),
        Ok(RPC_PROTOCOL_VERSION)
    );

    let incompatible_major = ProtocolVersion {
        major: RPC_PROTOCOL_MAJOR + 1,
        minor: RPC_PROTOCOL_MINOR,
        patch: RPC_PROTOCOL_PATCH,
        build: RPC_PROTOCOL_BUILD,
    };
    assert_eq!(
        negotiate_rpc_protocol(incompatible_major),
        Err(RpcAbiError::MajorVersionMismatch {
            expected: RPC_PROTOCOL_MAJOR,
            actual: RPC_PROTOCOL_MAJOR + 1,
        })
    );
}

#[test]
fn rpc_golden_vectors_cover_requests_responses_events_and_payload_kinds() {
    assert_eq!(
        GOLDEN_RPC_VECTORS.map(|vector| vector.name),
        [
            "hello-request",
            "hello-response",
            "attached",
            "send-command-request",
            "send-command-response",
            "event-fault-injected",
        ],
    );
    assert_eq!(
        RPC_OPEN_SET_PAYLOAD_KINDS,
        &[
            "command.continue",
            "event.fault-injected",
            "state.update",
            "session.closed",
        ],
    );

    let mut saw_request = false;
    let mut saw_response = false;
    let mut saw_event = false;
    let mut saw_attached_version = false;

    for vector in GOLDEN_RPC_VECTORS {
        assert_eq!(vector.protocol_version, GOLDEN_VECTOR_RPC_PROTOCOL_VERSION);
        match vector.message {
            RpcGoldenVectorMessage::HelloRequest { .. }
            | RpcGoldenVectorMessage::CommandRequest { .. } => saw_request = true,
            RpcGoldenVectorMessage::HelloResponse { payload_kinds, .. } => {
                saw_response = true;
                assert_eq!(payload_kinds, RPC_OPEN_SET_PAYLOAD_KINDS);
            }
            RpcGoldenVectorMessage::CommandResponse { .. } => saw_response = true,
            RpcGoldenVectorMessage::Event { .. } => saw_event = true,
            RpcGoldenVectorMessage::Attached { version, .. } => {
                saw_attached_version = true;
                assert_eq!(version, RPC_PROTOCOL_VERSION);
            }
        }
    }

    assert!(saw_request);
    assert!(saw_response);
    assert!(saw_event);
    assert!(saw_attached_version);
}

#[test]
fn rpc_golden_vectors_match_live_encoder() {
    for vector in GOLDEN_RPC_VECTORS {
        assert_eq!(encode_rpc_message(vector.message), vector.bytes);
    }
}

#[test]
fn rpc_golden_vectors_freeze_literal_wire_bytes() {
    assert_vector_bytes(
        "hello-request",
        b"crucible.rpc/hello-request\nversion=1.0.0+crucible-rpc-abi-v1\nclient=crucible-api-golden-client\n",
    );
    assert_vector_bytes(
        "hello-response",
        b"crucible.rpc/hello-response\nversion=1.0.0+crucible-rpc-abi-v1\nserver=crucible-session\npayload-kinds=command.continue,event.fault-injected,state.update,session.closed\n",
    );
    assert_vector_bytes(
        "attached",
        b"crucible.rpc/attached\nversion=1.0.0+crucible-rpc-abi-v1\nsession-id=42\nsession-epoch=7\nmode=control\n",
    );
    assert_vector_bytes(
        "send-command-request",
        b"crucible.rpc/send-command-request\nrequest-id=9001\nsession-epoch=7\ncommand-kind=command.continue\n",
    );
    assert_vector_bytes(
        "send-command-response",
        b"crucible.rpc/send-command-response\nrequest-id=9001\nstatus=ok\n",
    );
    assert_vector_bytes(
        "event-fault-injected",
        b"crucible.rpc/event\nseq=1234\nclass=fault\npayload-kind=event.fault-injected\n",
    );
}

#[test]
fn rpc_golden_vector_negative_control_detects_wire_drift() {
    let vector = vector_by_name("hello-response");
    let mut drifted = encode_rpc_message(vector.message);
    drifted.extend_from_slice(b"extra-field=unexpected\n");
    assert_ne!(drifted, vector.bytes);
}

fn assert_vector_bytes(name: &str, expected: &[u8]) {
    let vector = vector_by_name(name);
    assert_eq!(vector.bytes, expected);
}

fn vector_by_name(name: &str) -> RpcGoldenVector {
    for vector in GOLDEN_RPC_VECTORS {
        if vector.name == name {
            return vector;
        }
    }
    panic!("missing RPC golden vector {name}");
}
