//! Exercises actual retained DATA materialization without Source authority.

use super::*;

fn inputs() -> (
    Option<PacketNativeImport18BootstrapAssignmentData>,
    Option<PacketNativeImport18BootstrapAckProof>,
) {
    let ids = ["s", "i", "r"]
        .map(|s| Id::new(s.repeat(crucible_node_format::values::MAX_ID_BYTES)).unwrap());
    let request = PacketNativeImport18BootstrapRequest {
        schema: NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.into(),
        recipe_identity: Bytes::new(vec![19; 32]),
        initial_funding: PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(u64::MAX - 2),
            maximum_simultaneous_transient_bytes: U64::new(1),
            declared_counter_scratch_bytes: U64::new(1),
        },
    };
    let mut assignment = None;
    native_import18_bootstrap_assignment_into_data(
        ids.each_ref(),
        &request,
        &native_import18_bootstrap_assignment_quote_data(usize::MAX).unwrap(),
        usize::MAX,
        &mut assignment,
    )
    .unwrap();
    let mut context_digest = Vec::with_capacity(4096);
    context_digest.extend_from_slice(&[23; 32]);
    let mut schema = String::with_capacity(2048);
    schema.push_str(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF);
    // Fixed bytes are explicitly inert DATA; no Source producer or MAC is used.
    let proof = PacketNativeImport18BootstrapAckProof {
        schema,
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        context_digest: Bytes::new(context_digest),
        mac: Bytes::new(vec![29; 32]),
    };
    (assignment, Some(proof))
}

fn quote(
    assignment: &Option<PacketNativeImport18BootstrapAssignmentData>,
    proof: &Option<PacketNativeImport18BootstrapAckProof>,
) -> PacketNativeImport18BootstrapSealingRowData {
    native_import18_bootstrap_sealing_quote_data(
        assignment.as_ref().unwrap(),
        proof.as_ref().unwrap(),
        usize::MAX,
    )
    .unwrap()
}

#[test]
fn sealing_moves_actual_inputs_and_keeps_independent_dom_and_literal_banks() {
    let (mut assignment, mut proof) = inputs();
    let row = quote(&assignment, &proof);
    let original_id = assignment
        .as_ref()
        .unwrap()
        .borrowed_history_data()
        .original
        .unwrap()
        .request_id
        .0
        .as_ref()
        .unwrap()
        .as_str()
        .as_ptr();
    let proof_pointer = proof.as_ref().unwrap().context_digest.as_slice().as_ptr();
    let proof_schema_pointer = proof.as_ref().unwrap().schema.as_ptr();
    let mut oracle = assignment
        .as_ref()
        .unwrap()
        .borrowed_history_data()
        .original
        .unwrap()
        .clone();
    oracle.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        serde_json::to_value(proof.as_ref().unwrap()).unwrap(),
    );
    let oracle_dom = serde_json::to_value(&oracle).unwrap();
    let oracle_literal = canonical::canonical_json(&oracle_dom).unwrap();
    let mut output = None;

    native_import18_bootstrap_sealing_into_data(
        &mut assignment,
        &mut proof,
        &row,
        usize::MAX,
        &mut output,
    )
    .unwrap();

    assert!(assignment.is_none());
    assert!(proof.is_none());
    let owner = output.as_ref().unwrap();
    let history = owner.borrowed_history_data();
    assert!(history.sealed);
    assert!(!history.failed);
    assert!(history.failure.is_none());
    assert_eq!(
        history.step,
        Some(PacketNativeImport18BootstrapSealingStep::Literal)
    );
    assert_eq!(history.proof_value, Some(&Value::Null));
    assert_eq!(history.envelope_value, Some(&oracle_dom));
    assert_eq!(history.literal.unwrap(), &oracle_literal);
    let original = history.assignment.unwrap().original.unwrap();
    assert_eq!(original, &oracle);
    assert_eq!(
        original.request_id.0.as_ref().unwrap().as_str().as_ptr(),
        original_id
    );
    let proof = history.proof.unwrap();
    assert_eq!(proof.context_digest.as_slice().as_ptr(), proof_pointer);
    assert_eq!(proof.context_digest.allocation_capacity(), 4096);
    assert_eq!(proof.schema.as_ptr(), proof_schema_pointer);
    assert_eq!(proof.schema.capacity(), 2048);
    let envelope_digest = history.envelope_value.unwrap()["extensions"]
        [NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF]["context_digest"]
        .as_str()
        .unwrap();
    let original_digest =
        original.extensions[NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF]["context_digest"]
            .as_str()
            .unwrap();
    assert_ne!(envelope_digest.as_ptr(), original_digest.as_ptr());
    assert!(owner.retained_requested_bytes_data().unwrap() <= row.axes[0]);
    let projection = native_import18_bootstrap_envelope_projection_data(usize::MAX).unwrap();
    assert!(oracle_literal.len() <= projection.maximum_encoded_bytes_data()[0]);
    assert!(
        history.literal.unwrap().capacity()
            <= projection.serialization_requested_bytes_data()[0][2]
    );
}

#[test]
fn actual_spare_proof_capacity_changes_the_independent_retained_quote() {
    let (assignment, proof) = inputs();
    let row = quote(&assignment, &proof);
    let proof = proof.unwrap();
    let compact = PacketNativeImport18BootstrapAckProof {
        schema: proof.schema.as_str().into(),
        algorithm: proof.algorithm.clone(),
        context_digest: Bytes::new(proof.context_digest.as_slice().to_vec()),
        mac: Bytes::new(proof.mac.as_slice().to_vec()),
    };
    let compact_row = native_import18_bootstrap_sealing_quote_data(
        assignment.as_ref().unwrap(),
        &compact,
        usize::MAX,
    )
    .unwrap();

    assert_eq!(
        row.axes[0] - compact_row.axes[0],
        (2048 - compact.schema.capacity()) + (4096 - compact.context_digest.allocation_capacity())
    );
    assert_eq!(row.axes[1..], compact_row.axes[1..]);
    let exact = sum(&row.axes).unwrap();
    assert_eq!(
        native_import18_bootstrap_sealing_quote_data(assignment.as_ref().unwrap(), &proof, exact,)
            .unwrap(),
        row
    );
    assert!(
        native_import18_bootstrap_sealing_quote_data(
            assignment.as_ref().unwrap(),
            &proof,
            exact - 1,
        )
        .is_err()
    );
}

#[test]
fn refused_materialization_keeps_both_moved_inputs_before_any_output_construction() {
    for fault in 0..4 {
        let (mut assignment, mut proof) = inputs();
        let mut row = quote(&assignment, &proof);
        let mut maximum = usize::MAX;
        match fault {
            0 => proof.as_mut().unwrap().schema.push('x'),
            1 => proof.as_mut().unwrap().mac = Bytes::new(vec![29; 31]),
            2 => row.axes[0] += 1,
            _ => maximum = 0,
        }
        let pointer = proof.as_ref().unwrap().context_digest.as_slice().as_ptr();
        let mut output = None;

        assert!(
            native_import18_bootstrap_sealing_into_data(
                &mut assignment,
                &mut proof,
                &row,
                maximum,
                &mut output,
            )
            .is_err()
        );

        assert!(assignment.is_none());
        assert!(proof.is_none());
        let owner = output.as_ref().unwrap();
        let history = owner.borrowed_history_data();
        assert!(history.failed);
        assert!(!history.sealed);
        assert!(history.step.is_none());
        assert!(history.literal.is_none());
        assert!(history.proof_value.is_none());
        assert!(history.envelope_value.is_none());
        assert!(
            history
                .assignment
                .unwrap()
                .original
                .unwrap()
                .extensions
                .is_empty()
        );
        assert_eq!(
            history.proof.unwrap().context_digest.as_slice().as_ptr(),
            pointer
        );
        assert!(owner.retained_requested_bytes_data().unwrap() > 4096 + 2048);
    }
}

#[test]
fn occupied_or_missing_destinations_preserve_the_actual_input_owners() {
    let (mut assignment, mut proof) = inputs();
    let row = quote(&assignment, &proof);
    let mut output = None;
    native_import18_bootstrap_sealing_into_data(
        &mut assignment,
        &mut proof,
        &row,
        usize::MAX,
        &mut output,
    )
    .unwrap();
    let saved_literal = output
        .as_ref()
        .unwrap()
        .borrowed_history_data()
        .literal
        .unwrap()
        .as_ptr();
    let (mut assignment, mut proof) = inputs();
    let input_proof = proof.as_ref().unwrap().context_digest.as_slice().as_ptr();

    assert!(
        native_import18_bootstrap_sealing_into_data(
            &mut assignment,
            &mut proof,
            &row,
            0,
            &mut output,
        )
        .is_err()
    );

    assert!(assignment.is_some());
    assert_eq!(
        proof.as_ref().unwrap().context_digest.as_slice().as_ptr(),
        input_proof
    );
    assert_eq!(
        output
            .as_ref()
            .unwrap()
            .borrowed_history_data()
            .literal
            .unwrap()
            .as_ptr(),
        saved_literal
    );
    let mut absent = None;
    let mut empty_output = None;
    assert!(
        native_import18_bootstrap_sealing_into_data(
            &mut absent,
            &mut proof,
            &row,
            usize::MAX,
            &mut empty_output,
        )
        .is_err()
    );
    assert!(proof.is_some());
    assert!(empty_output.is_none());
    let mut absent_proof = None;
    assert!(
        native_import18_bootstrap_sealing_into_data(
            &mut assignment,
            &mut absent_proof,
            &row,
            usize::MAX,
            &mut empty_output,
        )
        .is_err()
    );
    assert!(assignment.is_some());
    assert!(empty_output.is_none());
}

#[test]
fn canonical_writer_refusal_keeps_actual_prefix_and_all_independent_banks() {
    let (assignment, proof) = inputs();
    let row = quote(&assignment, &proof);
    let mut owner = PacketNativeImport18BootstrapSealingData {
        row,
        assignment,
        proof,
        proof_value: None,
        envelope_value: Some(serde_json::json!({"a": "kept prefix", "b": "later"})),
        literal: None,
        step: None,
        failure: None,
        sealed: false,
        failed: true,
    };

    assert!(write_literal(&mut owner, 8).is_err());

    let history = owner.borrowed_history_data();
    assert_eq!(
        history.failure,
        Some(PacketNativeImport18BootstrapSealingFailure::Literal)
    );
    assert_eq!(
        history.step,
        Some(PacketNativeImport18BootstrapSealingStep::Literal)
    );
    assert_eq!(history.literal.unwrap(), b"{\"a\":");
    assert!(history.failed);
    assert!(history.assignment.is_some());
    assert!(history.proof.is_some());
    let retained = owner.retained_requested_bytes_data().unwrap();
    let capacity = owner.literal.as_ref().unwrap().capacity();
    owner.literal = None;
    assert_eq!(
        retained - owner.retained_requested_bytes_data().unwrap(),
        capacity
    );
}
