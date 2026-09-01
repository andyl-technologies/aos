//! Frozen control-plane RPC golden-vector corpus.

use super::*;

/// Frozen RPC golden-vector corpus in stable ABI-conformance order.
pub const GOLDEN_RPC_VECTORS: [RpcGoldenVector; 15] = [
    RpcGoldenVector {
        name: "hello-request",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::HelloRequest {
            client_name: "crucible-api-golden-client",
            version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        },
        bytes: b"crucible.rpc/hello-request\nversion=5.1.0+crucible-rpc-abi-v5\nclient=crucible-api-golden-client\n",
    },
    RpcGoldenVector {
        name: "hello-response",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::HelloResponse {
            server_name: "crucible-session",
            version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
            payload_kinds: RPC_OPEN_SET_PAYLOAD_KINDS,
        },
        bytes: b"crucible.rpc/hello-response\nversion=5.1.0+crucible-rpc-abi-v5\nserver=crucible-session\npayload-kinds=crucible.cmd.*,crucible.bp.*,crucible.event.*\n",
    },
    RpcGoldenVector {
        name: "attached",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::Attached {
            session_id: 42,
            session_epoch: 7,
            mode: RpcAttachMode::Control,
            version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        },
        bytes: b"crucible.rpc/attached\nversion=5.1.0+crucible-rpc-abi-v5\nsession-id=42\nsession-epoch=7\nmode=control\n",
    },
    RpcGoldenVector {
        name: "attached-with-reproduction",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::AttachedWithReproduction {
            session_id: 42,
            session_epoch: 7,
            mode: RpcAttachMode::Control,
            version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
            command_sequence: 1,
            command_kind: "crucible.cmd.pause",
            command_payload:
                "7061796c6f61643d636f6d6d616e642d6b696e640a636f6d6d616e643d50617573650a",
            scheduler_control: "none",
        },
        bytes: b"crucible.rpc/attached-with-reproduction\nversion=5.1.0+crucible-rpc-abi-v5\nsession-id=42\nsession-epoch=7\nmode=control\nreproduction-sequence=1\nreproduction-command-kind=crucible.cmd.pause\nreproduction-command-payload=7061796c6f61643d636f6d6d616e642d6b696e640a636f6d6d616e643d50617573650a\nreproduction-scheduler-control=none\n",
    },
    RpcGoldenVector {
        name: "get-reproduction-request",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::GetReproductionRequest {
            session_id: 42,
            session_epoch: 7,
            expected_epoch: 7,
        },
        bytes: b"crucible.rpc/get-reproduction-request\nsession-id=42\nsession-epoch=7\nexpected-epoch=7\n",
    },
    RpcGoldenVector {
        name: "get-reproduction-response",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::GetReproductionResponse {
            session_id: 42,
            session_epoch: 7,
            command_sequence: 1,
            command_kind: "crucible.cmd.pause",
            command_payload:
                "7061796c6f61643d636f6d6d616e642d6b696e640a636f6d6d616e643d50617573650a",
            scheduler_control: "none",
        },
        bytes: b"crucible.rpc/get-reproduction-response\nsession-id=42\nsession-epoch=7\ncommand-sequence=1\ncommand-kind=crucible.cmd.pause\ncommand-payload=7061796c6f61643d636f6d6d616e642d6b696e640a636f6d6d616e643d50617573650a\nscheduler-control=none\nresult=accepted\n",
    },
    RpcGoldenVector {
        name: "send-request",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::CommandRequest {
            session_id: 42,
            session_epoch: 7,
            seed: "000000000000000000000000000000000000000000000000000000000000004d",
            expected_epoch: 7,
            command_id: 9001,
            command_kind: "crucible.cmd.continue",
        },
        bytes: b"crucible.rpc/send-request\nsession-id=42\nepoch=7\nseed=000000000000000000000000000000000000000000000000000000000000004d\nexpected-epoch=7\ncommand-id=9001\ncommand=crucible.cmd.continue\n",
    },
    RpcGoldenVector {
        name: "send-request-set-breakpoint",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::CommandRequestWithPayload {
            session_id: 42,
            session_epoch: 7,
            seed: "000000000000000000000000000000000000000000000000000000000000004d",
            expected_epoch: 7,
            command_id: 9003,
            command_kind: "crucible.cmd.set-breakpoint",
            payload_lines: &[
                "breakpoint-predicate=6372756369626c652e7072656469636174652e76310010",
                "breakpoint-disposition=action:6372756369626c652e616374696f6e2e76310008",
                "breakpoint-policy=repeatable",
            ],
        },
        bytes: b"crucible.rpc/send-request\nsession-id=42\nepoch=7\nseed=000000000000000000000000000000000000000000000000000000000000004d\nexpected-epoch=7\ncommand-id=9003\ncommand=crucible.cmd.set-breakpoint\nbreakpoint-predicate=6372756369626c652e7072656469636174652e76310010\nbreakpoint-disposition=action:6372756369626c652e616374696f6e2e76310008\nbreakpoint-policy=repeatable\n",
    },
    RpcGoldenVector {
        name: "send-response",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::CommandResponse {
            command_id: 9001,
            command_kind: "crucible.cmd.continue",
            status: RpcStatusCode::Ok,
            state_update: "none",
        },
        bytes: b"crucible.rpc/send-response\ncommand-id=9001\ncommand=crucible.cmd.continue\nstatus=accepted\nstate-update=none\nquery-result=none\nbreakpoint-id=none\nsavepoint-info=none\n",
    },
    RpcGoldenVector {
        name: "send-response-set-breakpoint",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::CommandResponseWithPayload {
            command_id: 9003,
            command_kind: "crucible.cmd.set-breakpoint",
            status: RpcStatusCode::Ok,
            state_update: "none",
            query_result: "none",
            breakpoint_id: "44",
            savepoint_info: "none",
        },
        bytes: b"crucible.rpc/send-response\ncommand-id=9003\ncommand=crucible.cmd.set-breakpoint\nstatus=accepted\nstate-update=none\nquery-result=none\nbreakpoint-id=44\nsavepoint-info=none\n",
    },
    RpcGoldenVector {
        name: "send-response-breakpoint-firings",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::CommandResponseWithPayload {
            command_id: 9004,
            command_kind: "crucible.cmd.query",
            status: RpcStatusCode::Ok,
            state_update: "none",
            query_result: "breakpoint-firings|1|7|44|5|9|6372756369626c652e7072656469636174652e76310010|action:6372756369626c652e616374696f6e2e76310008|1|6372756369626c652e636f6e74726f6c2d6f7065726174696f6e2d6b696e642e76310000",
            breakpoint_id: "none",
            savepoint_info: "none",
        },
        bytes: b"crucible.rpc/send-response\ncommand-id=9004\ncommand=crucible.cmd.query\nstatus=accepted\nstate-update=none\nquery-result=breakpoint-firings|1|7|44|5|9|6372756369626c652e7072656469636174652e76310010|action:6372756369626c652e616374696f6e2e76310008|1|6372756369626c652e636f6e74726f6c2d6f7065726174696f6e2d6b696e642e76310000\nbreakpoint-id=none\nsavepoint-info=none\n",
    },
    RpcGoldenVector {
        name: "send-response-rejected-not-found",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::CommandResponse {
            command_id: 9002,
            command_kind: "crucible.cmd.remove-breakpoint",
            status: RpcStatusCode::NotFound,
            state_update: "none",
        },
        bytes: b"crucible.rpc/send-response\ncommand-id=9002\ncommand=crucible.cmd.remove-breakpoint\nstatus=rejected:not-found\nstate-update=none\nquery-result=none\nbreakpoint-id=none\nsavepoint-info=none\n",
    },
    RpcGoldenVector {
        name: "rpc-error-invalid-state",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::RpcError {
            status: RpcStatusCode::InvalidState,
            reason: "streaming-epoch-mismatch",
            details: &["expected=8", "actual=7"],
        },
        bytes: b"crucible.rpc/error\nstatus=invalid-state\nreason=streaming-epoch-mismatch\nexpected=8\nactual=7\n",
    },
    RpcGoldenVector {
        name: "rpc-error-resource-limit",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::RpcError {
            status: RpcStatusCode::Internal,
            reason: "resource-limit",
            details: &[
                "field=event_log_bytes",
                "current=1024",
                "requested=512",
                "configured=1280",
                "hard=274877906944",
            ],
        },
        bytes: b"crucible.rpc/error\nstatus=internal\nreason=resource-limit\nfield=event_log_bytes\ncurrent=1024\nrequested=512\nconfigured=1280\nhard=274877906944\n",
    },
    RpcGoldenVector {
        name: "event-effect-applied",
        protocol_version: GOLDEN_VECTOR_RPC_PROTOCOL_VERSION,
        message: RpcGoldenVectorMessage::Event {
            seq: 1234,
            class: RpcEventClass::Fault,
            payload_kind: "crucible.event.effect_applied",
        },
        bytes: b"crucible.rpc/event\nseq=1234\nclass=fault\npayload-kind=crucible.event.effect_applied\n",
    },
];
