//! Checks the RPC third of `gate:abi-conformance`.

#![forbid(unsafe_code)]

use crucible_api::{
    GOLDEN_RPC_VECTORS, GOLDEN_VECTOR_RPC_PROTOCOL_VERSION, GOLDEN_VECTOR_RPC_REGENERATION_RULE,
    ProtocolVersion, RPC_OPEN_SET_PAYLOAD_KINDS, RPC_PROTOCOL_BUILD, RPC_PROTOCOL_MAJOR,
    RPC_PROTOCOL_MINOR, RPC_PROTOCOL_PATCH, RPC_PROTOCOL_VERSION, RpcAbiError, RpcGoldenVector,
    RpcGoldenVectorMessage, encode_rpc_message, negotiate_rpc_protocol,
};

#[test]
fn rpc_abi_conformance_runs_named_checks() {
    assert_frozen_golden_vectors();
    assert_decode_encode_roundtrip();
    assert_abi_version_field();
    assert_version_bump_regenerates_vectors();
    assert_structure_aware_fuzz_corpus();
}

#[test]
fn rpc_protocol_version_is_explicit_and_rejects_major_mismatch() {
    assert_abi_version_field();
}

fn assert_abi_version_field() {
    assert_eq!(RPC_PROTOCOL_MAJOR, 1);
    assert_eq!(RPC_PROTOCOL_MINOR, 2);
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
    assert_frozen_golden_vectors();
}

fn assert_frozen_golden_vectors() {
    assert_eq!(
        GOLDEN_RPC_VECTORS.map(|vector| vector.name),
        [
            "hello-request",
            "hello-response",
            "attached",
            "attached-with-reproduction",
            "get-reproduction-request",
            "get-reproduction-response",
            "send-request",
            "send-response",
            "send-response-rejected-not-found",
            "rpc-error-invalid-state",
            "event-fault-activated",
        ],
    );
    assert_eq!(
        RPC_OPEN_SET_PAYLOAD_KINDS,
        &[
            "crucible.cmd.*",
            "crucible.bp.*",
            "crucible.fault.*",
            "crucible.event.*",
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
            | RpcGoldenVectorMessage::CommandRequest { .. }
            | RpcGoldenVectorMessage::GetReproductionRequest { .. } => saw_request = true,
            RpcGoldenVectorMessage::HelloResponse { payload_kinds, .. } => {
                saw_response = true;
                assert_eq!(payload_kinds, RPC_OPEN_SET_PAYLOAD_KINDS);
            }
            RpcGoldenVectorMessage::CommandResponse { .. }
            | RpcGoldenVectorMessage::GetReproductionResponse { .. }
            | RpcGoldenVectorMessage::RpcError { .. } => saw_response = true,
            RpcGoldenVectorMessage::Event { .. } => saw_event = true,
            RpcGoldenVectorMessage::Attached { version, .. } => {
                saw_attached_version = true;
                assert_eq!(version, RPC_PROTOCOL_VERSION);
            }
            RpcGoldenVectorMessage::AttachedWithReproduction {
                version,
                command_payload,
                ..
            } => {
                saw_attached_version = true;
                assert_eq!(version, RPC_PROTOCOL_VERSION);
                assert!(!command_payload.is_empty());
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
    assert_decode_encode_roundtrip();
}

fn assert_decode_encode_roundtrip() {
    for vector in GOLDEN_RPC_VECTORS {
        assert_eq!(encode_rpc_message(vector.message), vector.bytes);
    }
}

#[test]
fn rpc_golden_vectors_freeze_literal_wire_bytes() {
    assert_structure_aware_fuzz_corpus();
}

fn assert_structure_aware_fuzz_corpus() {
    assert_vector_bytes(
        "hello-request",
        b"crucible.rpc/hello-request\nversion=1.2.0+crucible-rpc-abi-v1\nclient=crucible-api-golden-client\n",
    );
    assert_vector_bytes(
        "hello-response",
        b"crucible.rpc/hello-response\nversion=1.2.0+crucible-rpc-abi-v1\nserver=crucible-session\npayload-kinds=crucible.cmd.*,crucible.bp.*,crucible.fault.*,crucible.event.*\n",
    );
    assert_vector_bytes(
        "attached",
        b"crucible.rpc/attached\nversion=1.2.0+crucible-rpc-abi-v1\nsession-id=42\nsession-epoch=7\nmode=control\n",
    );
    assert_vector_bytes(
        "attached-with-reproduction",
        b"crucible.rpc/attached-with-reproduction\nversion=1.2.0+crucible-rpc-abi-v1\nsession-id=42\nsession-epoch=7\nmode=control\nreproduction-sequence=1\nreproduction-command-kind=crucible.cmd.pause\nreproduction-command-payload=7061796c6f61643d636f6d6d616e642d6b696e640a636f6d6d616e643d50617573650a\nreproduction-scheduler-control=none\n",
    );
    assert_vector_bytes(
        "get-reproduction-request",
        b"crucible.rpc/get-reproduction-request\nsession-id=42\nsession-epoch=7\nexpected-epoch=7\n",
    );
    assert_vector_bytes(
        "get-reproduction-response",
        b"crucible.rpc/get-reproduction-response\nsession-id=42\nsession-epoch=7\ncommand-sequence=1\ncommand-kind=crucible.cmd.pause\ncommand-payload=7061796c6f61643d636f6d6d616e642d6b696e640a636f6d6d616e643d50617573650a\nscheduler-control=none\nresult=accepted\n",
    );
    assert_vector_bytes(
        "send-request",
        b"crucible.rpc/send-request\nsession-id=42\nepoch=7\nseed=000000000000000000000000000000000000000000000000000000000000004d\nexpected-epoch=7\ncommand-id=9001\ncommand=crucible.cmd.continue\n",
    );
    assert_vector_bytes(
        "send-response",
        b"crucible.rpc/send-response\ncommand-id=9001\ncommand=crucible.cmd.continue\nstatus=accepted\nstate-update=none\n",
    );
    assert_vector_bytes(
        "send-response-rejected-not-found",
        b"crucible.rpc/send-response\ncommand-id=9002\ncommand=crucible.cmd.remove-breakpoint\nstatus=rejected:not-found\nstate-update=none\n",
    );
    assert_vector_bytes(
        "rpc-error-invalid-state",
        b"crucible.rpc/error\nstatus=invalid-state\nreason=streaming-epoch-mismatch\nexpected=8\nactual=7\n",
    );
    assert_vector_bytes(
        "event-fault-activated",
        b"crucible.rpc/event\nseq=1234\nclass=fault\npayload-kind=crucible.event.fault_activated\n",
    );

    for vector in regression_corpus() {
        assert!(vector.bytes.starts_with(b"crucible.rpc/"));
        assert!(vector.bytes.ends_with(b"\n"));
        assert_eq!(encode_rpc_message(vector.message), vector.bytes);
    }
}

#[test]
fn rpc_golden_vector_negative_control_detects_wire_drift() {
    assert_version_bump_regenerates_vectors();
}

fn assert_version_bump_regenerates_vectors() {
    let vector = vector_by_name("hello-response");
    let mut drifted = encode_rpc_message(vector.message);
    drifted.extend_from_slice(b"extra-field=unexpected\n");
    assert_ne!(drifted, vector.bytes);

    let bumped = encode_rpc_message(RpcGoldenVectorMessage::HelloRequest {
        client_name: "crucible-api-golden-client",
        version: ProtocolVersion {
            major: RPC_PROTOCOL_MAJOR,
            minor: RPC_PROTOCOL_MINOR + 1,
            patch: RPC_PROTOCOL_PATCH,
            build: RPC_PROTOCOL_BUILD,
        },
    });
    assert_ne!(bumped, vector_by_name("hello-request").bytes);
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

fn regression_corpus() -> &'static [RpcGoldenVector] {
    &GOLDEN_RPC_VECTORS
}
