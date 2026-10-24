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

fn assert_crypto_matches_independent_canonical_context(
    actual: &PacketNativeImport18BootstrapAckContext,
) {
    let canonical = canonical::canonical_json(&serde_json::to_value(actual).unwrap()).unwrap();
    let context_digest = blake3::hash(&canonical);
    let key = [37; 32];
    let assigned_response = [83; 32];

    let proof_key = blake3::derive_key(
        "source-owned.packet-native-import-bootstrap-ack-key/18",
        &key,
    );
    let expected_proof = blake3::keyed_hash(&proof_key, &canonical);
    let mut receipt_material = [0; 64];
    receipt_material[..32].copy_from_slice(context_digest.as_bytes());
    receipt_material[32..].copy_from_slice(&assigned_response);
    let receipt_key = blake3::derive_key(
        "source-owned.packet-native-import-bootstrap-ack-receipt-key/18",
        &key,
    );
    let expected_receipt = blake3::keyed_hash(&receipt_key, &receipt_material);

    assert_eq!(
        native_import18_bootstrap_ack_context_digest_data(actual).unwrap(),
        *context_digest.as_bytes()
    );
    let proof = native_import18_bootstrap_ack_proof_data(&key, actual).unwrap();
    assert_eq!(proof.context_digest.as_slice(), context_digest.as_bytes());
    assert_eq!(proof.mac.as_slice(), expected_proof.as_bytes());
    verify_native_import18_bootstrap_ack_proof_data(&key, actual, &proof).unwrap();

    let receipt =
        native_import18_bootstrap_ack_receipt_data(&key, actual, &assigned_response).unwrap();
    assert_eq!(receipt.context_digest.as_slice(), context_digest.as_bytes());
    assert_eq!(receipt.mac.as_slice(), expected_receipt.as_bytes());
    verify_native_import18_bootstrap_ack_receipt_data(&key, actual, &assigned_response, &receipt)
        .unwrap();
}

#[test]
fn fixed_context_encoder_matches_canonical_json_for_every_byte_and_binding() {
    for seed in 0..=u8::MAX {
        let mut actual = context();
        let digest = Bytes::new((0..32).map(|offset| seed.wrapping_add(offset)).collect());
        actual.source_birth = digest.clone();
        actual.kernel_binding = digest.clone();
        actual.policy_binding = digest.clone();
        actual.host_registration = digest.clone();
        actual.native_registration = digest.clone();
        actual.hello_request = digest.clone();
        actual.hello_response = digest.clone();
        actual.assigned_request = digest.clone();
        actual.recipe_identity = digest;
        assert_crypto_matches_independent_canonical_context(&actual);
    }

    // Each field also changes alone, so omission or reuse of another binding
    // cannot pass merely because all digest contents happen to be equal.
    macro_rules! check_binding {
        ($($field:ident),+ $(,)?) => {
            $(
                let mut actual = context();
                actual.$field = Bytes::new(vec![201; 32]);
                assert_crypto_matches_independent_canonical_context(&actual);
            )+
        };
    }
    check_binding!(
        source_birth,
        kernel_binding,
        policy_binding,
        host_registration,
        native_registration,
        hello_request,
        hello_response,
        assigned_request,
        recipe_identity,
    );
}

#[test]
fn fixed_context_encoder_matches_every_decimal_width_and_largest_valid_row() {
    let mut values = vec![1, u64::MAX - 2];
    let mut power = 10u64;
    loop {
        values.extend([power - 1, power]);
        let Some(next) = power.checked_mul(10) else {
            break;
        };
        power = next;
    }

    for value in values {
        for axis in 0..3 {
            let mut actual = context();
            let mut axes = [1; 3];
            axes[axis] = value;
            actual.initial_funding = PacketNativeStartupAllocationRow {
                retained_requested_bytes: U64::new(axes[0]),
                maximum_simultaneous_transient_bytes: U64::new(axes[1]),
                declared_counter_scratch_bytes: U64::new(axes[2]),
            };
            assert_crypto_matches_independent_canonical_context(&actual);
        }
    }
}

#[test]
fn fixed_context_encoder_refuses_invalid_ascii_digest_and_funding_inputs() {
    let mut invalid_contexts = Vec::new();
    let mut schema = context();
    schema.schema.push('"');
    invalid_contexts.push(schema);
    let mut algorithm = context();
    algorithm.algorithm.push('\\');
    invalid_contexts.push(algorithm);

    macro_rules! malformed_binding {
        ($($field:ident),+ $(,)?) => {
            $(
                let mut short = context();
                short.$field = Bytes::new(vec![0; 31]);
                invalid_contexts.push(short);
                let mut long = context();
                long.$field = Bytes::new(vec![0; 33]);
                invalid_contexts.push(long);
            )+
        };
    }
    malformed_binding!(
        source_birth,
        kernel_binding,
        policy_binding,
        host_registration,
        native_registration,
        hello_request,
        hello_response,
        assigned_request,
        recipe_identity,
    );
    for axes in [[0, 1, 1], [1, 0, 1], [1, 1, 0], [u64::MAX, 1, 1]] {
        let mut actual = context();
        actual.initial_funding = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(axes[0]),
            maximum_simultaneous_transient_bytes: U64::new(axes[1]),
            declared_counter_scratch_bytes: U64::new(axes[2]),
        };
        invalid_contexts.push(actual);
    }

    let valid = context();
    let key = [37; 32];
    let response = [83; 32];
    let proof = native_import18_bootstrap_ack_proof_data(&key, &valid).unwrap();
    let receipt = native_import18_bootstrap_ack_receipt_data(&key, &valid, &response).unwrap();
    for actual in invalid_contexts {
        assert!(native_import18_bootstrap_ack_context_digest_data(&actual).is_err());
        assert!(native_import18_bootstrap_ack_proof_data(&key, &actual).is_err());
        assert!(native_import18_bootstrap_ack_receipt_data(&key, &actual, &response).is_err());
        assert!(verify_native_import18_bootstrap_ack_proof_data(&key, &actual, &proof).is_err());
        assert!(
            verify_native_import18_bootstrap_ack_receipt_data(&key, &actual, &response, &receipt)
                .is_err()
        );
    }
}
