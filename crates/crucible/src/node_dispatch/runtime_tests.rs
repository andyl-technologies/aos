//! Executes real runtime dispatch while controlling native completion readiness.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_dispatch::{DispatchError, DispatchRound};

fn independent_round() -> (NodeRuntime, DispatchRound, Vec<Rc<RefCell<NativeState>>>) {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let (graph, nodes, states, record) = admitted_parts_from_graph(graph);
    let mut runtime = NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .unwrap_or_else(|failure| panic!("test runtime rejected: {:?}", failure.error));
    let activation = activate(&mut runtime);
    let scheduler = runtime.scheduler(&graph, &activation).unwrap();
    let a = scheduler
        .admit_exact(&id("a"), id("run/a"), U64::new(100))
        .unwrap();
    let z = scheduler
        .admit_exact(&id("z"), id("run/z"), U64::new(100))
        .unwrap();
    let round = DispatchRound::start(&mut runtime, vec![z, a], 2).unwrap();
    (runtime, round, states)
}

fn poll_round(
    round: &mut DispatchRound,
    runtime: &mut NodeRuntime,
) -> Poll<Result<(), DispatchError>> {
    let mut context = Context::from_waker(Waker::noop());
    round.poll(runtime, &mut context)
}

#[test]
fn host_completion_order_does_not_change_canonical_publication() {
    let mut publications = Vec::new();
    for first_ready in [0usize, 1usize] {
        let (mut runtime, mut round, states) = independent_round();
        states[1 - first_ready].borrow_mut().pending = true;

        assert!(matches!(
            poll_round(&mut round, &mut runtime),
            Poll::Pending
        ));
        assert!(matches!(
            round.publish(&mut runtime),
            Err(DispatchError::Incomplete)
        ));
        assert!(matches!(
            round.ready_outcomes(),
            Err(DispatchError::Incomplete)
        ));
        assert_eq!(states[0].borrow().ack_calls, 0);
        assert_eq!(states[1].borrow().ack_calls, 0);
        assert_eq!(states[first_ready].borrow().poll_calls, 1);

        states[1 - first_ready].borrow_mut().pending = false;
        assert!(matches!(
            poll_round(&mut round, &mut runtime),
            Poll::Ready(Ok(()))
        ));
        let ready = round.ready_outcomes().unwrap();
        assert_eq!(
            ready
                .iter()
                .map(|outcome| outcome.operation.clone())
                .collect::<Vec<_>>(),
            vec![id("run/a"), id("run/z")]
        );
        assert_eq!(states[0].borrow().ack_calls, 0);
        assert_eq!(states[1].borrow().ack_calls, 0);
        let publication = round.publish(&mut runtime).unwrap().clone();
        assert_eq!(publication.outcomes, ready);
        assert_eq!(publication.operations, vec![id("run/a"), id("run/z")]);
        assert_eq!(states[first_ready].borrow().poll_calls, 1);
        assert_eq!(states[0].borrow().ack_calls, 1);
        assert_eq!(states[1].borrow().ack_calls, 1);
        assert_eq!(round.publish(&mut runtime).unwrap(), &publication);
        assert_eq!(states[0].borrow().ack_calls, 1);
        assert_eq!(states[1].borrow().ack_calls, 1);
        publications.push(publication);
    }

    assert_eq!(publications[0], publications[1]);
}

#[test]
fn dropping_pending_round_keeps_every_original_owner_reserved() {
    let (mut runtime, round, states) = independent_round();
    states[0].borrow_mut().pending = true;
    states[1].borrow_mut().pending = true;
    let tokens: Vec<_> = round.tokens().cloned().collect();
    drop(round);

    for token in &tokens {
        assert_eq!(
            runtime.recover(token.operation()).unwrap().operation(),
            token.operation()
        );
        assert_eq!(
            runtime.owner_lifecycle(&token.route().owners[0].owner),
            Some(Lifecycle::Executing)
        );
        assert_eq!(runtime.cancel(token).unwrap(), CancelStatus::Requested);
        assert_eq!(
            runtime.owner_lifecycle(&token.route().owners[0].owner),
            Some(Lifecycle::Executing)
        );
    }
    assert_eq!(states[0].borrow().begin_calls, 1);
    assert_eq!(states[1].borrow().begin_calls, 1);
}

#[test]
fn uncertain_second_submission_retains_the_first_and_never_retries() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let (graph, nodes, states, record) = admitted_parts_from_graph(graph);
    states[1].borrow_mut().uncertain = true;
    let mut runtime = NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .unwrap_or_else(|failure| panic!("test runtime rejected: {:?}", failure.error));
    let activation = activate(&mut runtime);
    let scheduler = runtime.scheduler(&graph, &activation).unwrap();
    let a = scheduler
        .admit_exact(&id("a"), id("run/a"), U64::new(100))
        .unwrap();
    let z = scheduler
        .admit_exact(&id("z"), id("run/z"), U64::new(100))
        .unwrap();

    let failure = DispatchRound::start(&mut runtime, vec![z, a], 2)
        .err()
        .unwrap();

    assert_eq!(failure.accepted.len(), 2);
    assert!(failure.undispatched.is_empty());
    assert_eq!(states[0].borrow().begin_calls, 1);
    assert_eq!(states[1].borrow().begin_calls, 1);
    assert!(runtime.recover(&id("run/a")).is_ok());
    assert!(runtime.recover(&id("run/z")).is_ok());
    assert_eq!(
        runtime.owner_lifecycle(&id("owner/a")),
        Some(Lifecycle::Executing)
    );
    assert_eq!(
        runtime.owner_lifecycle(&id("owner/z")),
        Some(Lifecycle::Quarantined)
    );
}

#[test]
fn later_invalid_causal_receipt_prevents_the_entire_round_publication() {
    let (mut runtime, mut round, states) = independent_round();
    states[1].borrow_mut().retained_outputs = vec![id("output/without-coordinates")];
    assert!(matches!(
        poll_round(&mut round, &mut runtime),
        Poll::Ready(Ok(()))
    ));

    assert!(matches!(
        round.publish(&mut runtime),
        Err(DispatchError::Runtime(_))
    ));
    assert_eq!(states[0].borrow().ack_calls, 0);
    assert_eq!(states[1].borrow().ack_calls, 0);
    let scheduler = runtime.scheduler.as_ref().unwrap();
    assert_eq!(
        scheduler.position(&id("a")).unwrap(),
        Position::new(0.into(), 0.into(), Phase::BoundaryControl)
    );
    assert_eq!(
        scheduler.position(&id("z")).unwrap(),
        Position::new(0.into(), 0.into(), Phase::BoundaryControl)
    );
    assert!(runtime.recover(&id("run/a")).is_ok());
    assert!(runtime.recover(&id("run/z")).is_ok());
}
