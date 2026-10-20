//! Models adversarial deferred validation while retaining original runtime custody.
//!
//! The fixture explicitly seeds overlapping prior windows and test-local commits.
//! It does not qualify a native source or mint production scheduling authority.

use super::*;
use crate::node_scheduling::{NativePublication, NativeSchedulingObservation, SchedulingCommit};

struct DeferredFixture {
    runtime: NodeRuntime,
    state: Rc<RefCell<NativeState>>,
    current: OperationToken,
    original_scheduler: crate::node_scheduling::SchedulingSnapshot,
}

fn fixture() -> DeferredFixture {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
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
    drop(runtime.scheduler(&graph, &activation).unwrap());

    // These are genuine runtime admissions/completions/ACKs. The deliberately
    // overlapping modeled windows exercise defensive candidate selection;
    // test-local commits do not pretend to be source-issued native evidence.
    for name in ["prior-0", "prior-1"] {
        let token = exact(&mut runtime, &activation, name);
        assert!(matches!(poll(&mut runtime, &token), Poll::Ready(Ok(_))));
        runtime.acknowledge(&token, &[]).unwrap();
        runtime
            .operations
            .get_mut(token.operation())
            .unwrap()
            .scheduling_commit = Some(SchedulingCommit {
            activation: activation.clone(),
            node: id("a"),
            operation: token.operation().clone(),
            retained_outputs: Vec::new(),
        });
    }
    let current = match runtime
        .begin(
            &activation,
            &id("a"),
            id("current"),
            OperationRequest::ExactRun {
                start: position(10),
                limit: position(20),
                boundary_policy: ExactBoundaryPolicy::HorizonPark,
            },
        )
        .unwrap()
    {
        BeginResult::Accepted(token) => token,
        result => panic!("unexpected modeled submission: {result:?}"),
    };
    assert!(matches!(poll(&mut runtime, &current), Poll::Ready(Ok(_))));
    let publication = NativePublication {
        publication_id: id("deferred-output"),
        endpoint: crucible_node_format::Endpoint {
            node_id: id("a"),
            port_id: id("out"),
            lane_id: id("bytes"),
        },
        native_sequence: U64::new(1),
        publication: Position::new(U64::new(12), U64::new(1), Phase::Publication),
        evaluation: Some(Position::new(U64::new(2), U64::new(0), Phase::Reaction)),
        causal_parents: Vec::new(),
        payload: crucible_node_format::canonical::content_ref(
            b"deferred",
            "application/octet-stream",
        )
        .unwrap(),
        payload_bytes: b"deferred".to_vec(),
    };
    let entry = runtime.operations.get_mut(current.operation()).unwrap();
    let RetainedResult::Complete(outcome) = &mut entry.result else {
        panic!("modeled original completion was not retained");
    };
    outcome.retained_outputs = vec![publication.publication_id.clone()];
    outcome.scheduling = Some(NativeSchedulingObservation {
        node: outcome.node.clone(),
        owners: outcome.owners.clone(),
        reached: position(20),
        closed_prefix: position(20),
        bounds: Vec::new(),
        publications: vec![publication],
        input_progress: None,
        external_inputs: Vec::new(),
        proof_ref: blob(),
    });
    let original_scheduler = runtime
        .scheduler
        .as_ref()
        .unwrap()
        .snapshot(position(0), U64::new(0))
        .unwrap();
    DeferredFixture {
        runtime,
        state: Rc::clone(&states[0]),
        current,
        original_scheduler,
    }
}

#[test]
fn uncertain_prior_revokes_original_scheduler_before_later_success_or_repeat_read() {
    for effects in [
        EffectKnowledge::Unknown,
        EffectKnowledge::MayHaveProgressed,
        EffectKnowledge::CommittedPrefix(vec![id("original-prefix")]),
    ] {
        let fixture = fixture();
        fixture.state.borrow_mut().deferred_results = [
            Err(OperationFailure {
                effects,
                reason: "original native validation uncertain".into(),
            }),
            Ok(()),
        ]
        .into();
        let operations = fixture.runtime.operations.len();
        let result = fixture.runtime.scheduling_receipt(&fixture.current);
        assert!(matches!(result, Err(RuntimeError::InvalidReceipt)));
        assert_eq!(fixture.state.borrow().deferred_calls, [id("prior-0")]);
        assert_eq!(fixture.state.borrow().deferred_results.len(), 1);
        assert!(matches!(
            fixture.runtime.scheduling_receipt(&fixture.current),
            Err(RuntimeError::OutstandingObligations)
        ));
        assert_eq!(fixture.state.borrow().deferred_calls, [id("prior-0")]);

        let slot = fixture.runtime.scheduler.as_ref().unwrap();
        assert_eq!(slot.current(), Err(RuntimeError::OutstandingObligations));
        assert_eq!(
            slot.snapshot(position(0), U64::new(0)).unwrap(),
            fixture.original_scheduler
        );
        assert_eq!(fixture.runtime.operations.len(), operations);
        assert!(matches!(
            fixture.runtime.operations[fixture.current.operation()].result,
            RetainedResult::Complete(_)
        ));
        assert!(
            fixture
                .runtime
                .owners
                .values()
                .any(|owner| owner.operation.as_ref() == Some(fixture.current.operation()))
        );
    }
}

#[test]
fn no_effect_candidate_miss_can_select_a_later_valid_original() {
    let fixture = fixture();
    fixture.state.borrow_mut().deferred_results = [
        Err(OperationFailure {
            effects: EffectKnowledge::None,
            reason: "candidate does not own this publication".into(),
        }),
        Ok(()),
    ]
    .into();
    assert!(fixture.runtime.scheduling_receipt(&fixture.current).is_ok());
    assert_eq!(
        fixture.state.borrow().deferred_calls,
        [id("prior-0"), id("prior-1")]
    );
    assert_eq!(
        fixture.runtime.scheduler.as_ref().unwrap().current(),
        Ok(())
    );
}

#[test]
fn unsupported_default_does_not_revoke_original_scheduler() {
    let fixture = fixture();
    assert!(matches!(
        fixture.runtime.scheduling_receipt(&fixture.current),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert_eq!(
        fixture.state.borrow().deferred_calls,
        [id("prior-0"), id("prior-1")]
    );
    assert_eq!(
        fixture.runtime.scheduler.as_ref().unwrap().current(),
        Ok(())
    );
}
