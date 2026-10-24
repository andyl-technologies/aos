//! Exercises restore proof data independently from any authority fixture.

use super::*;

fn restoration_request() -> PacketCompleteRestoreRequest {
    let body = canonical::content_ref(b"{}", "application/json").unwrap();
    PacketCompleteRestoreRequest {
        schema: PACKET_COMPLETE_RESTORE_FEATURE.to_owned(),
        archive_index: body.clone(),
        capture_manifest: body.clone(),
        owner_state: body.clone(),
        journal: body.clone(),
        source_runtime: body.clone(),
        backend_implementation: body.clone(),
        backend_schema: complete_restore_request_schema().unwrap(),
        archived_cut: Position::new(
            crucible_node_format::Tick::new(0),
            U64::new(0),
            crucible_node_format::Phase::BoundaryControl,
        ),
        archived_ordinal: 0.into(),
        target_world: canonical::hash("cnp.world-binding.v1", b"fresh").unwrap(),
        target_owner: Id::new("owner/0").unwrap(),
        target_owner_binding: canonical::hash("cnp.owner-binding.v1", b"fresh").unwrap(),
        target_activation: Id::new("activation/fresh").unwrap(),
        target_generation: 1.into(),
        target_owner_generation: 1.into(),
        mapping: body,
        nonce: Bytes::new(vec![1; 32]),
    }
}

fn restoration_context(request: &PacketCompleteRestoreRequest) -> PacketCompleteRestoreContext {
    let bindings = request.context_bindings(b"{}").unwrap();
    PacketCompleteRestoreContext {
        schema: PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA.to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        source_birth: Bytes::new(vec![1; 32]),
        kernel_binding: Bytes::new(vec![2; 32]),
        policy_binding: Bytes::new(vec![3; 32]),
        host_registration: Bytes::new(vec![4; 32]),
        native_registration: Bytes::new(vec![5; 32]),
        hello_request: Bytes::new(vec![6; 32]),
        hello_response: Bytes::new(vec![7; 32]),
        assigned_restore: Bytes::new(vec![8; 32]),
        archive_binding: bindings.archive_binding,
        target_binding: bindings.target_binding,
        mapping_binding: bindings.mapping_binding,
        request_binding: bindings.request_binding,
    }
}

pub(in crate::reference_packet::service::complete_restore) fn prepare()
-> PacketCompleteRestorePrepareRequest {
    let reference = canonical::content_ref(b"{}", "application/json").unwrap();
    PacketCompleteRestorePrepareRequest {
        schema: PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION.to_owned(),
        restoration: restoration_request(),
        host_protocol: reference.clone(),
        native_protocol: reference.clone(),
        native_control: reference.clone(),
        native_anchor: reference,
        transaction_id: Id::new("restore/transaction").unwrap(),
        generation: 1.into(),
        allocation: PacketCompleteRestoreInputAllocation {
            maximum_known_requested_bytes: (64 * 1024 * 1024).into(),
            maximum_input_bytes: (8 * 1024 * 1024).into(),
            maximum_nodes: 65536.into(),
            maximum_depth: 32.into(),
            maximum_owned_backing_bytes: (8 * 1024 * 1024).into(),
            maximum_tree_entries: 4096.into(),
            maximum_metadata_rows: 16384.into(),
            maximum_literal_backing_bytes: (8 * 1024 * 1024).into(),
            maximum_content_transfers: 1024.into(),
            maximum_content_objects: 1024.into(),
            maximum_content_groups: 1024.into(),
            maximum_content_bytes: (8 * 1024 * 1024).into(),
            maximum_content_metadata_bytes: (1024 * 1024).into(),
            maximum_model_bytes: (1024 * 1024).into(),
        },
    }
}

fn prepare_context(
    request: &PacketCompleteRestorePrepareRequest,
) -> PacketCompleteRestorePrepareContext {
    PacketCompleteRestorePrepareContext {
        schema: "source-owned.packet-complete-restore-prepare-context/12".to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        source_birth: Bytes::new(vec![1; 32]),
        kernel_binding: Bytes::new(vec![2; 32]),
        policy_binding: Bytes::new(vec![3; 32]),
        host_registration: Bytes::new(vec![4; 32]),
        native_registration: Bytes::new(vec![5; 32]),
        hello_request: Bytes::new(vec![6; 32]),
        hello_response: Bytes::new(vec![7; 32]),
        assigned_prepare: Bytes::new(vec![8; 32]),
        prepare_request: digest(
            &bounded_canonical(request, MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES).unwrap(),
        ),
        input_roster: request.input_roster_digest_data().unwrap(),
    }
}

fn commit(request: PacketCompleteRestorePrepareRequest) -> PacketCompleteRestoreCommitRequest {
    PacketCompleteRestoreCommitRequest {
        schema: PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION.to_owned(),
        prepare: request,
        capture_terminal: terminal(),
        prepare_request_id: Id::new("restore/prepare/1").unwrap(),
        prepare_request_sequence: 3.into(),
        prepare_request_digest: Bytes::new(vec![9; 32]),
        prepare_response_sequence: 4.into(),
        prepare_response_digest: Bytes::new(vec![10; 32]),
        transfer_token: Bytes::new(vec![11; 32]),
    }
}

fn commit_context(
    request: &PacketCompleteRestoreCommitRequest,
) -> PacketCompleteRestoreCommitContext {
    PacketCompleteRestoreCommitContext {
        schema: "source-owned.packet-complete-restore-commit-context/12".to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        restoration: restoration_context(&request.prepare.restoration),
        commit_request: digest(
            &bounded_canonical(request, MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES).unwrap(),
        ),
        prepare_request: Bytes::new(request.prepare_request_digest.as_slice().to_vec()),
        prepare_response: Bytes::new(request.prepare_response_digest.as_slice().to_vec()),
        transfer_token: Bytes::new(request.transfer_token.as_slice().to_vec()),
        input_roster: request.prepare.input_roster_digest_data().unwrap(),
    }
}

#[test]
fn prepare_mac_binds_full_roster_budget_and_fresh_original() {
    let mut request = prepare();
    let context = prepare_context(&request);
    let proof = complete_restore_prepare_proof_data(&[12; 32], &context).unwrap();

    context.authenticate_request_data(&request).unwrap();
    verify_complete_restore_prepare_proof_data(&[12; 32], &context, &proof).unwrap();
    assert!(verify_complete_restore_prepare_proof_data(&[13; 32], &context, &proof).is_err());
    request.allocation.maximum_model_bytes = (2 * 1024 * 1024).into();
    assert!(context.authenticate_request_data(&request).is_err());
    assert!(
        verify_complete_restore_prepare_proof_data(&[12; 32], &prepare_context(&request), &proof)
            .is_err()
    );

    request = prepare();
    request.native_protocol = canonical::content_ref(b"foreign", "application/json").unwrap();
    assert!(context.authenticate_request_data(&request).is_err());
    request = prepare();
    request.restoration.nonce = Bytes::new(vec![14; 32]);
    assert!(context.authenticate_request_data(&request).is_err());
    request = prepare();
    request.generation = 2.into();
    assert!(context.authenticate_request_data(&request).is_err());
}

#[test]
fn prepare_receipt_is_input_only_and_binds_actual_response() {
    let request = prepare();
    let context = prepare_context(&request);
    let receipt =
        complete_restore_prepare_receipt_data(&[12; 32], &request, &context, 5.into(), &[13; 32])
            .unwrap();

    verify_complete_restore_prepare_receipt_data(
        &[12; 32],
        &request,
        &context,
        5.into(),
        &[13; 32],
        &receipt,
    )
    .unwrap();
    assert!(
        verify_complete_restore_prepare_receipt_data(
            &[12; 32],
            &request,
            &context,
            6.into(),
            &[13; 32],
            &receipt
        )
        .is_err()
    );
    assert!(
        verify_complete_restore_prepare_receipt_data(
            &[12; 32],
            &request,
            &context,
            5.into(),
            &[14; 32],
            &receipt
        )
        .is_err()
    );
    assert!(
        verify_complete_restore_prepare_receipt_data(
            &[14; 32],
            &request,
            &context,
            5.into(),
            &[13; 32],
            &receipt
        )
        .is_err()
    );
}

#[test]
fn commit_mac_requires_exact_prepare_chain_and_verified_mapping() {
    let mut request = commit(prepare());
    let context = commit_context(&request);
    let proof = complete_restore_commit_proof_data(&[12; 32], &context).unwrap();

    context.authenticate_request_data(&request, b"{}").unwrap();
    verify_complete_restore_commit_proof_data(&[12; 32], &context, &proof).unwrap();
    assert!(context.authenticate_request_data(&request, b"{ }").is_err());
    request.prepare_response_sequence = 5.into();
    assert!(context.authenticate_request_data(&request, b"{}").is_err());
    request = commit(prepare());
    request.transfer_token = Bytes::new(vec![15; 32]);
    assert!(context.authenticate_request_data(&request, b"{}").is_err());
    assert!(
        verify_complete_restore_commit_proof_data(&[12; 32], &commit_context(&request), &proof)
            .is_err()
    );
    request = commit(prepare());
    request.prepare.restoration.archived_ordinal = 1.into();
    assert!(context.authenticate_request_data(&request, b"{}").is_err());
}

#[test]
fn commit_receipt_refuses_replay_mapping_response_and_foreign_key() {
    let request = commit(prepare());
    let context = commit_context(&request);
    let mut receipt =
        complete_restore_commit_receipt_data(&[12; 32], &request, &context, 7.into(), &[13; 32])
            .unwrap();

    verify_complete_restore_commit_receipt_data(
        &[12; 32],
        &request,
        &context,
        7.into(),
        &[13; 32],
        &receipt,
    )
    .unwrap();
    assert!(
        verify_complete_restore_commit_receipt_data(
            &[12; 32],
            &request,
            &context,
            8.into(),
            &[13; 32],
            &receipt
        )
        .is_err()
    );
    assert!(
        verify_complete_restore_commit_receipt_data(
            &[14; 32],
            &request,
            &context,
            7.into(),
            &[13; 32],
            &receipt
        )
        .is_err()
    );
    receipt.installed_mapping = canonical::content_ref(b"other", "application/json").unwrap();
    assert!(
        verify_complete_restore_commit_receipt_data(
            &[12; 32],
            &request,
            &context,
            7.into(),
            &[13; 32],
            &receipt
        )
        .is_err()
    );
}

#[test]
fn phase_domains_truncation_unknown_fields_and_underbound_plans_refuse() {
    let request = prepare();
    let context = prepare_context(&request);
    let mut proof = complete_restore_prepare_proof_data(&[12; 32], &context).unwrap();

    assert!(
        proof
            .validate_data(PacketCompleteRestoreTransferPhase::Commit)
            .is_err()
    );
    proof.schema = PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION.to_owned();
    assert!(
        verify_complete_restore_commit_proof_data(
            &[12; 32],
            &commit_context(&commit(prepare())),
            &proof
        )
        .is_err()
    );
    proof.mac = Bytes::new(vec![0; 31]);
    assert!(
        proof
            .validate_data(PacketCompleteRestoreTransferPhase::Commit)
            .is_err()
    );

    let mut value = serde_json::to_value(&request).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unregistered".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<PacketCompleteRestorePrepareRequest>(value).is_err());
    let mut request = prepare();
    request.allocation.maximum_known_requested_bytes = 1.into();
    assert!(request.validate_data().is_err());
    request = prepare();
    request.allocation.maximum_depth = 65.into();
    assert!(request.validate_data().is_err());
    request = prepare();
    request.allocation.maximum_metadata_rows = 131073.into();
    assert!(request.validate_data().is_err());
}

fn terminal() -> Envelope {
    use crate::envelope::Nullable;
    use crate::envelope::{MessageKind, Method};
    let present = || Nullable(Some(Id::new("captured/scope").unwrap()));
    Envelope {
        protocol: "CNP/1".to_owned(),
        message: MessageKind::Response,
        session_id: present(),
        incarnation_id: present(),
        node_id: present(),
        execution_owner_id: present(),
        capture_owner_id: present(),
        request_id: present(),
        operation_id: present(),
        sequence: 9.into(),
        method: Method::Begin,
        body: Default::default(),
        extensions: Default::default(),
    }
}

#[test]
fn exact_captured_terminal_is_part_of_signed_commit() {
    let mut request = commit(prepare());
    let context = commit_context(&request);
    let proof = complete_restore_commit_proof_data(&[12; 32], &context).unwrap();

    request.capture_terminal.sequence = 10.into();
    assert!(context.authenticate_request_data(&request, b"{}").is_err());
    assert!(
        verify_complete_restore_commit_proof_data(&[12; 32], &commit_context(&request), &proof)
            .is_err()
    );
}

#[test]
fn changed_owner_body_refuses_before_any_model_owner_can_be_constructed() {
    let request = commit(prepare());
    let data = PacketCompleteRestoreOwnerStateData {
        request: &request,
        owner_state_bytes: b"foreign",
        journal_bytes: b"{}",
        control_bytes: b"{}",
        anchor_bytes: b"{}",
    };
    assert!(authenticate_complete_restore_owner_state_data(data).is_err());
}
