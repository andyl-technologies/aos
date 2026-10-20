//! Exercises DATA separation without constructing a Source or native owner.

use super::*;

fn context() -> PacketNativeImport18BootstrapAckContext {
    PacketNativeImport18BootstrapAckContext {
        schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_CONTEXT.into(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        source_birth: Bytes::new(vec![1; 32]),
        kernel_binding: Bytes::new(vec![2; 32]),
        policy_binding: Bytes::new(vec![3; 32]),
        host_registration: Bytes::new(vec![4; 32]),
        native_registration: Bytes::new(vec![5; 32]),
        hello_request: Bytes::new(vec![6; 32]),
        hello_response: Bytes::new(vec![7; 32]),
        assigned_request: Bytes::new(vec![8; 32]),
        recipe_identity: Bytes::new(vec![9; 32]),
        initial_funding: PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(10),
            maximum_simultaneous_transient_bytes: U64::new(20),
            declared_counter_scratch_bytes: U64::new(30),
        },
    }
}

#[test]
fn bootstrap_proof_binds_original_recipe_and_initial_row() {
    let key = [11; 32];
    let mut actual = context();
    let proof = native_import18_bootstrap_ack_proof_data(&key, &actual).unwrap();
    verify_native_import18_bootstrap_ack_proof_data(&key, &actual, &proof).unwrap();
    assert!(verify_native_import18_bootstrap_ack_proof_data(&[12; 32], &actual, &proof).is_err());

    actual.initial_funding.retained_requested_bytes = U64::new(11);
    assert!(verify_native_import18_bootstrap_ack_proof_data(&key, &actual, &proof).is_err());
    actual = context();
    actual.recipe_identity = Bytes::new(vec![10; 32]);
    assert!(verify_native_import18_bootstrap_ack_proof_data(&key, &actual, &proof).is_err());
}

#[test]
fn receipt_is_only_bootstrap_and_binds_the_exact_response() {
    let actual = context();
    let key = [11; 32];
    let response = [12; 32];
    let receipt = native_import18_bootstrap_ack_receipt_data(&key, &actual, &response).unwrap();
    verify_native_import18_bootstrap_ack_receipt_data(&key, &actual, &response, &receipt).unwrap();
    assert!(
        verify_native_import18_bootstrap_ack_receipt_data(&key, &actual, &[13; 32], &receipt)
            .is_err()
    );
    assert_eq!(
        serde_json::to_value(receipt.state).unwrap(),
        "bootstrap_only"
    );
    for state in ["\"ready\"", "\"admitted\"", "\"prepared\""] {
        assert!(serde_json::from_str::<PacketNativeImport18BootstrapAckState>(state).is_err());
    }
}

#[test]
fn maximal_valid_decimal_width_matches_the_defining_context_bound() {
    let mut actual = context();
    // Each coordinate is finite and positive; requested_peak must remain checked.
    actual.initial_funding.retained_requested_bytes = U64::new(10_000_000_000_000_000_000);
    actual.initial_funding.maximum_simultaneous_transient_bytes = U64::new(1);
    actual.initial_funding.declared_counter_scratch_bytes = U64::new(1);
    let bytes = canonical::canonical_json(&serde_json::to_value(&actual).unwrap()).unwrap();
    assert!(bytes.len() <= 873);

    actual.schema = "source-owned.packet-canonical-ack-admission-context/5".into();
    assert!(actual.validate_data().is_err());
}
