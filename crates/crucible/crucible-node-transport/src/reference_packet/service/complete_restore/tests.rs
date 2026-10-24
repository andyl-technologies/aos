//! Exercises restore proof data independently from any authority fixture.

use super::*;

fn request() -> PacketCompleteRestoreRequest {
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

fn context(request: &PacketCompleteRestoreRequest) -> PacketCompleteRestoreContext {
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

#[test]
fn exact_restore_proof_refuses_foreign_key_and_changed_context() {
    let request = request();
    let mut context = context(&request);
    let proof = complete_restore_proof_data(&[9; 32], &context).unwrap();

    verify_complete_restore_proof_data(&[9; 32], &context, &proof).unwrap();
    assert!(verify_complete_restore_proof_data(&[10; 32], &context, &proof).is_err());
    context.assigned_restore = Bytes::new(vec![0; 32]);
    assert!(verify_complete_restore_proof_data(&[9; 32], &context, &proof).is_err());
}

#[test]
fn archived_cut_backend_world_mapping_and_nonce_change_signed_inputs() {
    let mut request = request();
    let original = context(&request);
    let proof = complete_restore_proof_data(&[9; 32], &original).unwrap();

    request.archived_ordinal = 1.into();
    assert!(verify_complete_restore_proof_data(&[9; 32], &context(&request), &proof).is_err());
    request = self::request();
    request.backend_implementation =
        canonical::content_ref(b"backend", "application/json").unwrap();
    assert!(verify_complete_restore_proof_data(&[9; 32], &context(&request), &proof).is_err());
    request = self::request();
    request.target_world = canonical::hash("cnp.world-binding.v1", b"another").unwrap();
    assert!(verify_complete_restore_proof_data(&[9; 32], &context(&request), &proof).is_err());
    request = self::request();
    request.nonce = Bytes::new(vec![2; 32]);
    assert!(verify_complete_restore_proof_data(&[9; 32], &context(&request), &proof).is_err());
    assert!(request.context_bindings(b"{ }").is_err());
}

#[test]
fn actual_response_receipt_refuses_sequence_body_and_context_changes() {
    let request = request();
    let context = context(&request);
    let response = [11; 32];
    let receipt =
        complete_restore_receipt_data(&[9; 32], &request, &context, 12.into(), &response).unwrap();

    verify_complete_restore_receipt_data(
        &[9; 32],
        &request,
        &context,
        12.into(),
        &response,
        &receipt,
    )
    .unwrap();
    assert!(
        verify_complete_restore_receipt_data(
            &[9; 32],
            &request,
            &context,
            13.into(),
            &response,
            &receipt
        )
        .is_err()
    );
    assert!(
        verify_complete_restore_receipt_data(
            &[9; 32],
            &request,
            &context,
            12.into(),
            &[12; 32],
            &receipt
        )
        .is_err()
    );
    assert!(
        verify_complete_restore_receipt_data(
            &[10; 32],
            &request,
            &context,
            12.into(),
            &response,
            &receipt
        )
        .is_err()
    );
}

#[test]
fn closed_restore_data_refuses_truncation_and_wrong_domains() {
    let request = request();
    let context = context(&request);
    let mut proof = complete_restore_proof_data(&[9; 32], &context).unwrap();
    proof.mac = Bytes::new(vec![0; 31]);
    assert!(proof.validate_data().is_err());
    proof.mac = Bytes::new(vec![0; 32]);
    proof.schema = "source-owned.packet-canonical-ack-admission/5".to_owned();
    assert!(proof.validate_data().is_err());

    let mut value = serde_json::to_value(&context).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unregistered".to_owned(), true.into());
    assert!(serde_json::from_value::<PacketCompleteRestoreContext>(value).is_err());
    assert_ne!(
        complete_restore_request_schema().unwrap().id,
        complete_restore_proof_schema().unwrap().id
    );
}
