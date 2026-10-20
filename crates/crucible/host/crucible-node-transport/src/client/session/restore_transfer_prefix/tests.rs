//! Exercises the closed data grammar without constructing SDK or native authority.

use super::*;
use crate::envelope::{Method, Nullable};
use crucible_node_format::{Bytes, HashRef};

fn original() -> Envelope {
    serde_json::from_value(serde_json::json!({
        "protocol":"CNP/1","message":"request","session_id":"session",
        "incarnation_id":"incarnation","node_id":"node","execution_owner_id":"owner",
        "capture_owner_id":null,"request_id":"commit-id","operation_id":null,
        "sequence":"8","method":"begin","body":{},"extensions":{}
    }))
    .unwrap()
}

fn request(sequence: u64, method: Method, body: &impl serde::Serialize) -> Envelope {
    let mut result = original();
    result.node_id = Nullable(None);
    result.execution_owner_id = Nullable(None);
    result.sequence = U64::new(sequence);
    result.method = method;
    result.request_id = Nullable(Some(
        Id::new(format!("packet-restore-held-proof-{sequence}")).unwrap(),
    ));
    result.body = serde_json::to_value(body)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    result
}

fn guard(phase: PacketCompleteRestoreTransferPhase) -> HeldPrefix {
    // A private protocol-data fixture; no live guard constructor or permission.
    HeldPrefix {
        phase,
        chunk: 3,
        maximum: 5,
        first: None,
        next: None,
        length: 0,
        received: 0,
        digest: [0; 64],
        finished: false,
    }
}

fn begin() -> (BlobBeginRequest, Envelope) {
    let body = BlobBeginRequest {
        transfer_id: Id::new("packet-restore-held-transfer-20").unwrap(),
        content: canonical::content_ref(b"abcde", "application/json").unwrap(),
        extensions: Extensions::new(),
    };
    let envelope = request(20, Method::BlobBegin, &body);
    (body, envelope)
}

fn terminal(reference: ContentRef) -> ResponseBody {
    ResponseBody {
        shape: ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: Map::new(),
            extensions: Extensions::new(),
        },
        result: Some(MethodResult::PrepareRestore(PrepareRestoreResult {
            transaction_id: Id::new("transaction-distinct-from-request").unwrap(),
            prepared_token: Id::new("prepared-token").unwrap(),
            world_binding_hash: HashRef {
                algorithm: "blake3-256".into(),
                domain: "cnp.world-binding.v1".into(),
                digest: "0".repeat(64),
            },
            owner_binding_hash: HashRef {
                algorithm: "blake3-256".into(),
                domain: "cnp.owner-binding.v1".into(),
                digest: "0".repeat(64),
            },
            staged_owner_ids: vec![Id::new("owner").unwrap()],
            closed_gate_receipt: reference.clone(),
            validated_manifest: reference,
        })),
    }
}

#[test]
fn prepare_refuses_any_prefix_and_commit_requires_full_contiguous_object() {
    let (begin, envelope) = begin();
    let mut prepare = guard(PacketCompleteRestoreTransferPhase::Prepare);
    assert!(
        prepare
            .authenticate_request(
                &original(),
                &envelope,
                &RequestBody::BlobBegin(begin.clone())
            )
            .is_err()
    );
    assert!(prepare.first.is_none());

    let mut commit = guard(PacketCompleteRestoreTransferPhase::Commit);
    assert!(
        commit
            .authenticate_terminal(&terminal(begin.content.clone()))
            .is_err()
    );
    commit
        .authenticate_request(
            &original(),
            &envelope,
            &RequestBody::BlobBegin(begin.clone()),
        )
        .unwrap();
    let premature = BlobFinishRequest {
        transfer_id: begin.transfer_id.clone(),
        extensions: Extensions::new(),
    };
    assert!(
        commit
            .authenticate_request(
                &original(),
                &request(21, Method::BlobFinish, &premature),
                &RequestBody::BlobFinish(premature)
            )
            .is_err()
    );
    let short = BlobChunkRequest {
        transfer_id: begin.transfer_id.clone(),
        offset: U64::new(0),
        bytes: Bytes::new(b"a".to_vec()),
        extensions: Extensions::new(),
    };
    assert!(
        commit
            .authenticate_request(
                &original(),
                &request(21, Method::BlobChunk, &short),
                &RequestBody::BlobChunk(short)
            )
            .is_err()
    );
    assert_eq!(commit.received, 0);

    for (sequence, offset, bytes) in [(21, 0, &b"abc"[..]), (22, 3, &b"de"[..])] {
        let body = BlobChunkRequest {
            transfer_id: begin.transfer_id.clone(),
            offset: U64::new(offset),
            bytes: Bytes::new(bytes.to_vec()),
            extensions: Extensions::new(),
        };
        commit
            .authenticate_request(
                &original(),
                &request(sequence, Method::BlobChunk, &body),
                &RequestBody::BlobChunk(body),
            )
            .unwrap();
    }
    let finish = BlobFinishRequest {
        transfer_id: begin.transfer_id.clone(),
        extensions: Extensions::new(),
    };
    commit
        .authenticate_request(
            &original(),
            &request(23, Method::BlobFinish, &finish),
            &RequestBody::BlobFinish(finish),
        )
        .unwrap();
    commit
        .authenticate_terminal(&terminal(begin.content.clone()))
        .unwrap();
    let other = canonical::content_ref(b"xxxxx", "application/json").unwrap();
    assert!(commit.authenticate_terminal(&terminal(other)).is_err());
    assert!(
        commit
            .authenticate_request(&original(), &envelope, &RequestBody::BlobBegin(begin))
            .is_err()
    );
}

#[test]
fn changed_transfer_header_order_and_noncanonical_sequence_names_refuse() {
    let (body, envelope) = begin();
    for mutation in 0..4 {
        let mut changed = envelope.clone();
        match mutation {
            0 => changed.session_id = Nullable(Some(Id::new("foreign-session").unwrap())),
            1 => changed.node_id = Nullable(Some(Id::new("foreign-node").unwrap())),
            2 => {
                changed.request_id =
                    Nullable(Some(Id::new("packet-restore-held-proof-020").unwrap()))
            }
            _ => {
                changed
                    .extensions
                    .insert("foreign".into(), Value::Bool(true));
            }
        }
        let mut current = guard(PacketCompleteRestoreTransferPhase::Commit);
        assert!(
            current
                .authenticate_request(&original(), &changed, &RequestBody::BlobBegin(body.clone()))
                .is_err()
        );
        assert!(current.first.is_none());
    }
    let mut current = guard(PacketCompleteRestoreTransferPhase::Commit);
    current
        .authenticate_request(
            &original(),
            &envelope,
            &RequestBody::BlobBegin(body.clone()),
        )
        .unwrap();
    assert!(
        current
            .authenticate_request(
                &original(),
                &envelope,
                &RequestBody::BlobBegin(body.clone())
            )
            .is_err()
    );
    let chunk = BlobChunkRequest {
        transfer_id: Id::new("packet-restore-held-transfer-21").unwrap(),
        offset: U64::new(0),
        bytes: Bytes::new(b"abc".to_vec()),
        extensions: Extensions::new(),
    };
    assert!(
        current
            .authenticate_request(
                &original(),
                &request(21, Method::BlobChunk, &chunk),
                &RequestBody::BlobChunk(chunk)
            )
            .is_err()
    );
    assert_eq!(current.received, 0);
}
