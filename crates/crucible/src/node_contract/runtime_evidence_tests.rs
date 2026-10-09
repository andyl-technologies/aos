//! Tests immutable original evidence custody across native ACK and corrupt readout.

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
        .operation_evidence(&token, &[reference.clone()], 4096.into())
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
