//! Tests immutable original evidence custody across native ACK and corrupt readout.

// crucible-lint: allow panic-shortcut -- These runtime evidence tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_scheduling::InputPayload;

fn completed_evidence() -> (
    NodeRuntime,
    Rc<RefCell<NativeState>>,
    OperationToken,
    ContentRef,
) {
    let (mut runtime, states) = runtime(OperatingMode::Quantized);
    let activation = activate(&mut runtime);
    let token = quantum(&mut runtime, &activation);
    let bytes = b"original native stop inventory".to_vec();
    let reference =
        crucible_node_contract::canonical::content_ref(&bytes, "application/octet-stream").unwrap();
    states[0].borrow_mut().evidence_objects = vec![InputPayload {
        reference: reference.clone(),
        bytes,
    }];
    states[0].borrow_mut().progress_override = Some(ProgressEvidence::Quantized {
        window: id("window"),
        publication: position(1000),
        physical: PhysicalState::Active,
        closure: Box::new(QuantumClosureEvidence {
            input_batch: id("closed-input-batch"),
            close_receipt: reference.clone(),
            output_inventory: reference.clone(),
            pending_inventory: reference.clone(),
            clock_evidence: reference.clone(),
        }),
    });
    runtime.close_quantum(&token).unwrap();
    assert!(matches!(poll(&mut runtime, &token), Poll::Ready(Ok(_))));
    (runtime, Rc::clone(&states[0]), token, reference)
}

#[test]
fn evidence_remains_same_original_bytes_after_acknowledgment() {
    let (mut runtime, state, token, reference) = completed_evidence();
    let before = runtime
        .operation_evidence(&token, std::slice::from_ref(&reference), 4096.into())
        .unwrap();
    runtime.acknowledge(&token, &[]).unwrap();
    drop(token);

    let recovered = runtime.recover(&id("quantum")).unwrap();
    let after = runtime
        .operation_evidence(&recovered, &[reference], 4096.into())
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(state.borrow().begin_calls, 1);
    assert_eq!(state.borrow().close_calls, 1);
    assert_eq!(state.borrow().ack_calls, 1);
    assert_eq!(state.borrow().evidence_reads, 2);
}

#[test]
fn unrelated_repeated_and_oversized_references_refuse_before_native_read() {
    let (mut runtime, state, token, reference) = completed_evidence();
    let unrelated =
        crucible_node_contract::canonical::content_ref(b"unrelated", "application/octet-stream")
            .unwrap();
    for references in [vec![unrelated], vec![reference.clone(), reference.clone()]] {
        assert!(
            runtime
                .operation_evidence(&token, &references, 4096.into())
                .is_err()
        );
    }
    assert!(
        runtime
            .operation_evidence(&token, &[reference], 1.into())
            .is_err()
    );
    assert!(
        runtime
            .operation_evidence(&token, &[], 0.into())
            .unwrap()
            .is_empty()
    );
    assert_eq!(state.borrow().evidence_reads, 0);
    assert_eq!(state.borrow().quarantine_calls, 0);
}

#[test]
fn corrupt_or_unauthenticated_original_bytes_quarantine_native_custody() {
    for corrupt_bytes in [true, false] {
        let (mut runtime, state, token, reference) = completed_evidence();
        if corrupt_bytes {
            state.borrow_mut().evidence_corrupt = true;
        } else {
            state.borrow_mut().invalid_evidence = true;
        }
        assert!(matches!(
            runtime.operation_evidence(&token, &[reference], 4096.into()),
            Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))
        ));
        assert_eq!(state.borrow().evidence_reads, 1);
        assert!(state.borrow().quarantine_calls > 0);
        assert_eq!(
            runtime.owner_lifecycle(&id("shared-owner")),
            Some(Lifecycle::Quarantined)
        );
    }
}

#[test]
fn quarantined_original_domain_blocks_distinct_writer_after_old_ack() {
    let (graph, _) = crate::node_admission::test_fixture_with_execution(true);
    let (graph, nodes, states, record) = admitted_parts_from_graph(graph);
    let mut runtime = NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .unwrap_or_else(|failure| panic!("valid graph refused: {}", failure.error));
    let activation = activate(&mut runtime);
    let token = match runtime
        .begin(
            &activation,
            &id("a"),
            id("original-observe"),
            OperationRequest::Observe,
        )
        .unwrap()
    {
        BeginResult::Accepted(token) => token,
        other => panic!("original model observation refused: {other:?}"),
    };
    assert!(matches!(poll(&mut runtime, &token), Poll::Ready(Ok(_))));
    runtime.acknowledge(&token, &[]).unwrap();
    assert!(
        runtime
            .owners
            .get(&id("owner/a"))
            .unwrap()
            .operation
            .is_none()
    );

    // A failed retained-evidence read after ACK must keep the authoritative
    // shared domain unavailable even though its old busy reservation is clear.
    runtime.contain_roster(token.route());
    assert!(matches!(
        runtime.begin(
            &activation,
            &id("z"),
            id("conflicting-writer"),
            OperationRequest::Observe,
        ),
        Err(RuntimeError::OwnerUnavailable)
    ));
    assert_eq!(states[0].borrow().quarantine_calls, 1);
    assert_eq!(states[1].borrow().quarantine_calls, 1);
    assert_eq!(states[1].borrow().begin_calls, 0);
}

#[test]
fn original_completion_borrows_actual_permission_and_retained_ack_without_effects() {
    let (mut runtime, state, token, _) = completed_evidence();
    let cached = match poll(&mut runtime, &token) {
        Poll::Ready(Ok(outcome)) => outcome,
        other => panic!("completed fixture lost original outcome: {other:?}"),
    };
    {
        let original = runtime.original_completed_operation(&token).unwrap();
        assert_eq!(original.admission().token().operation(), token.operation());
        assert_eq!(original.outcome(), &cached);
        assert!(!original.acknowledged());
        assert!(original.staged_inputs().unwrap().is_none());
    }

    runtime.acknowledge(&token, &[]).unwrap();
    let original = runtime.original_completed_operation(&token).unwrap();
    assert_eq!(original.outcome(), &cached);
    assert!(original.acknowledged());
    assert!(original.staged_inputs().unwrap().is_none());
    assert_eq!(state.borrow().evidence_reads, 0);
    assert_eq!(state.borrow().begin_calls, 1);
    assert_eq!(state.borrow().close_calls, 1);
    assert_eq!(state.borrow().ack_calls, 1);
}

#[test]
fn original_input_evidence_requires_source_reader_beyond_matching_ack_root() {
    let (mut runtime, state, token, reference) = completed_evidence();
    assert!(
        runtime
            .original_input_evidence(&token, OriginalInputLineageLimits::default())
            .unwrap()
            .is_none()
    );
    let admission = &runtime.operations[token.operation()].admission;
    // The completion token is runtime-issued; this empty staging journal is a
    // synthetic model fixture, not a source-installed native input certificate.
    let batch = crate::node_scheduling::RuntimeInputBatch {
        activation: admission.activation().clone(),
        node: token.route().node.clone(),
        stage_operation: id("original-stage"),
        batch: id("original-input"),
        owners: token.route().owners.clone(),
        cutoff: position(0),
        inventory: reference.clone(),
        deliveries: vec![],
        payloads: vec![],
    };
    let acknowledgement = crate::node_scheduling::NativeInputAcknowledgement {
        stage_operation: batch.stage_operation().clone(),
        batch: batch.batch().clone(),
        node: batch.node().clone(),
        owners: batch.owners().to_vec(),
        cutoff: batch.cutoff(),
        inventory: batch.inventory().clone(),
        proof_ref: reference,
    };
    runtime
        .operations
        .get_mut(token.operation())
        .unwrap()
        .admission
        .inputs = Some(Rc::new(batch.retained_copy()));
    runtime.input_batches.insert(
        batch.stage_operation().clone(),
        super::inputs::RetainedInput {
            batch,
            acknowledgement: Some(acknowledgement),
            provenance: None,
            lineage: None,
            failure: None,
            committed: false,
            commit: None,
        },
    );

    assert!(matches!(
        runtime.original_input_evidence(&token, OriginalInputLineageLimits::default()),
        Err(RuntimePollFailure::Native(OperationFailure {
            effects: EffectKnowledge::None,
            ..
        }))
    ));
    assert!(matches!(
        runtime.original_input_evidence(
            &token,
            OriginalInputLineageLimits {
                maximum_bytes: 1,
                ..OriginalInputLineageLimits::default()
            }
        ),
        Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))
    ));
    let original = runtime.original_completed_operation(&token).unwrap();
    assert!(original.staged_inputs().unwrap().is_some());
    assert_eq!(state.borrow().evidence_reads, 0);
    assert_eq!(state.borrow().begin_calls, 1);
    assert_eq!(state.borrow().close_calls, 1);
    assert_eq!(state.borrow().quarantine_calls, 0);
}

#[test]
fn original_completion_refuses_foreign_and_pending_tokens_without_native_reads() {
    let (mut runtime, states) = runtime(OperatingMode::Quantized);
    let activation = activate(&mut runtime);
    let pending = quantum(&mut runtime, &activation);
    assert!(matches!(
        runtime.original_completed_operation(&pending),
        Err(RuntimeError::OutstandingObligations)
    ));

    let (mut other, _, token, _) = completed_evidence();
    assert!(matches!(
        runtime.original_completed_operation(&token),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert!(matches!(
        other.original_completed_operation(&pending),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert_eq!(states[0].borrow().evidence_reads, 0);
    assert_eq!(states[0].borrow().close_calls, 0);
    assert_eq!(states[0].borrow().ack_calls, 0);
}

#[test]
fn restricted_original_witness_keeps_native_custody_and_refusal_boundaries() {
    let (mut runtime, state, token, reference) = completed_evidence();
    let unrelated = crucible_node_contract::canonical::content_ref(
        b"foreign witness",
        "application/octet-stream",
    )
    .unwrap();

    {
        let mut witness = runtime.original_witness();
        assert!(
            !witness
                .original_completed_operation(&token)
                .unwrap()
                .acknowledged()
        );
        assert!(
            witness
                .operation_evidence(&token, &[unrelated], 4096.into())
                .is_err()
        );
        assert_eq!(state.borrow().evidence_reads, 0);
        assert!(
            witness
                .original_input_evidence(&token, OriginalInputLineageLimits::default())
                .unwrap()
                .is_none()
        );
        let bodies = witness
            .operation_evidence(&token, std::slice::from_ref(&reference), 4096.into())
            .unwrap();
        assert_eq!(bodies, state.borrow().evidence_objects);
        assert_eq!(state.borrow().ack_calls, 0);
    }

    runtime.acknowledge(&token, &[]).unwrap();
    let mut witness = runtime.original_witness();
    assert!(
        witness
            .original_completed_operation(&token)
            .unwrap()
            .acknowledged()
    );
    assert_eq!(state.borrow().begin_calls, 1);
    assert_eq!(state.borrow().close_calls, 1);
    assert_eq!(state.borrow().ack_calls, 1);
    assert_eq!(state.borrow().evidence_reads, 1);
}
