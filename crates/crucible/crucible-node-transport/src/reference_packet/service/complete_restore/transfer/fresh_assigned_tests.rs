//! Exercises assigned data only, without a Source grant or live SDK controller.

use super::*;
use crate::reference_packet::service::fresh_restore_allocation::*;
use crate::{
    bodies::{BeginKind, BeginRequest, PrepareRestoreArguments},
    envelope::Nullable,
};
use crucible_node_format::{Bytes, Id, U64, canonical};

fn original() -> Envelope {
    let owner = canonical::hash("cnp.owner-binding.v1", b"owner").unwrap();
    let arguments = PrepareRestoreArguments {
        transaction_id: Id::new("restore/transaction").unwrap(),
        capture_manifest: canonical::content_ref(b"{}", "application/json").unwrap(),
        expected_world_binding_hash: canonical::hash("cnp.world-binding.v1", b"world").unwrap(),
        expected_owner_binding_hash: owner.clone(),
        destination_owner_ids: [Id::new("owner/0").unwrap()].into_iter().collect(),
    };
    let baseline = BeginRequest {
        kind: BeginKind::PrepareRestore,
        binding_hash: owner,
        owner_generation: U64::new(1),
        activation_id: Nullable(None),
        world_generation: U64::new(1),
        arguments: serde_json::to_value(arguments)
            .unwrap()
            .as_object()
            .unwrap()
            .clone(),
        extensions: Default::default(),
    };
    let binding = PacketNativeFreshRestoreAllocationPrepareBinding {
        schema: PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.into(),
        assigned_query: Bytes::new(vec![1; 32]),
        completed_query_response: Bytes::new(vec![2; 32]),
        allocation: canonical::content_ref(b"{}", PACKET_FRESH_RESTORE_ALLOCATION_MEDIA).unwrap(),
    };
    let present = || Nullable(Some(Id::new("actual/scope").unwrap()));
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: present(),
        incarnation_id: present(),
        node_id: present(),
        execution_owner_id: present(),
        capture_owner_id: Nullable(None),
        request_id: present(),
        operation_id: Nullable(None),
        sequence: U64::new(7),
        method: Method::Begin,
        body: serde_json::to_value(baseline)
            .unwrap()
            .as_object()
            .unwrap()
            .clone(),
        // The phase payload is inert DATA: these digest controls intentionally
        // exercise no typed phase proof, installed mode or keyed Source right.
        extensions: [
            (
                PacketCompleteRestoreTransferPhase::Prepare
                    .request_extension()
                    .into(),
                serde_json::json!({"data": 1}),
            ),
            (
                PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.into(),
                serde_json::to_value(binding).unwrap(),
            ),
        ]
        .into_iter()
        .collect(),
    }
}

#[test]
fn selected_digest_preserves_binding_assigned_sequence_and_request_identity() {
    let original = original();
    let digest = complete_restore_fresh_prepare_assigned_request_digest(&original, 65536).unwrap();
    let mut changed = original.clone();
    changed.sequence = U64::new(8);
    assert_ne!(
        digest,
        complete_restore_fresh_prepare_assigned_request_digest(&changed, 65536).unwrap()
    );
    changed = original.clone();
    changed.request_id = Nullable(Some(Id::new("other/request").unwrap()));
    assert_ne!(
        digest,
        complete_restore_fresh_prepare_assigned_request_digest(&changed, 65536).unwrap()
    );
    for key in ["assigned_query", "completed_query_response"] {
        changed = original.clone();
        changed
            .extensions
            .get_mut(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
            .unwrap()[key] = serde_json::to_value(Bytes::new(vec![3; 32])).unwrap();
        assert_ne!(
            digest,
            complete_restore_fresh_prepare_assigned_request_digest(&changed, 65536).unwrap()
        );
    }
}

#[test]
fn selected_digest_removes_only_own_proof_and_response_receipt() {
    let original = original();
    let phase = PacketCompleteRestoreTransferPhase::Prepare;
    let expected =
        complete_restore_fresh_prepare_assigned_request_digest(&original, 65536).unwrap();
    let mut sealed = original.clone();
    sealed.extensions.insert(
        phase.proof_extension().into(),
        serde_json::json!({"proof": 1}),
    );
    assert_eq!(
        expected,
        complete_restore_fresh_prepare_assigned_request_digest(&sealed, 65536).unwrap()
    );
    assert!(authenticate_fresh_prepare_shape(&sealed, false).is_err());

    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.sequence = U64::new(11);
    response.body.clear();
    response.extensions.clear();
    let expected =
        complete_restore_fresh_prepare_assigned_response_digest(&sealed, &response, 65536).unwrap();
    response.extensions.insert(
        phase.receipt_extension().into(),
        serde_json::json!({"receipt": 1}),
    );
    assert_eq!(
        expected,
        complete_restore_fresh_prepare_assigned_response_digest(&sealed, &response, 65536).unwrap()
    );
    response.sequence = U64::new(12);
    assert_ne!(
        expected,
        complete_restore_fresh_prepare_assigned_response_digest(&sealed, &response, 65536).unwrap()
    );
    response.request_id = Nullable(Some(Id::new("foreign/request").unwrap()));
    assert!(
        complete_restore_fresh_prepare_assigned_response_digest(&sealed, &response, 65536).is_err()
    );
}

#[test]
fn selected_grammar_refuses_missing_null_foreign_and_commit_extensions() {
    let original = original();
    for value in [serde_json::Value::Null, serde_json::json!({})] {
        let mut changed = original.clone();
        changed.extensions.insert(
            PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.into(),
            value,
        );
        assert!(complete_restore_fresh_prepare_assigned_request_digest(&changed, 65536).is_err());
    }
    let mut changed = original.clone();
    changed
        .extensions
        .remove(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING);
    assert!(complete_restore_fresh_prepare_assigned_request_digest(&changed, 65536).is_err());
    for key in [
        "foreign/extension",
        PacketCompleteRestoreTransferPhase::Commit.request_extension(),
    ] {
        changed = original.clone();
        changed.extensions.insert(key.into(), serde_json::json!({}));
        assert!(complete_restore_fresh_prepare_assigned_request_digest(&changed, 65536).is_err());
    }
}

#[test]
fn legacy_digest_keeps_exact_phase_only_encoding_and_refuses_selected_binding() {
    let mut original = original();
    let phase = PacketCompleteRestoreTransferPhase::Prepare;
    assert!(
        super::super::complete_restore_transfer_assigned_request_digest(&original, phase, 65536)
            .is_err()
    );
    original
        .extensions
        .remove(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING);
    let legacy =
        super::super::complete_restore_transfer_assigned_request_digest(&original, phase, 65536)
            .unwrap();
    let raw = serde_json::to_value(&original).unwrap();
    let encoded = canonical::canonical_json(&raw).unwrap();
    assert_eq!(legacy, *blake3::hash(&encoded).as_bytes());
    assert_eq!(
        serde_json::to_string(&original.extensions).unwrap(),
        r#"{"source-owned.packet-complete-restore-prepare/12":{"data":1}}"#
    );
    assert!(complete_restore_fresh_prepare_assigned_request_digest(&original, 65536).is_err());
}
