//! Model-only supervisor tests for finite reservation and surviving complete ACK custody.

use super::*;
use crate::node_contract::{BeginResult, RetainedOperationObservation};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn position(time: u64) -> Position {
    Position::new(
        time.into(),
        0.into(),
        crucible_node_contract::Phase::BoundaryControl,
    )
}

struct Publisher;

impl ActivationPublisher for Publisher {
    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Committed
    }
    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Committed
    }
}

fn record(graph: &crate::node_admission::AdmittedGraph) -> ActivationRecord {
    ActivationRecord {
        generation: 1.into(),
        activation_id: id("original/activation"),
        world_binding_hash: graph.world_binding_hash().clone(),
        boundary: position(0),
        owners: graph
            .owners()
            .map(|owner| {
                let binding = graph.binding(&owner.owner.participant_ids[0]).unwrap();
                OwnerIdentity {
                    owner: owner.owner.id.clone(),
                    incarnation: binding.authority.incarnation_id.clone(),
                    generation: binding.authority.owner_generation,
                }
            })
            .collect(),
    }
}

#[test]
fn reservation_is_finite_bound_to_exact_world_and_released_before_native_allocation() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let record = record(&graph);
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let slot = queue
        .reserve_world(&record, RuntimeLimits::default())
        .unwrap();
    assert_eq!(queue.reserved_worlds(), 1);
    assert!(
        queue
            .reserve_world(&record, RuntimeLimits::default())
            .is_err()
    );
    let mut different = record.clone();
    different.activation_id = id("replacement/activation");
    assert_eq!(
        slot.validate_world(&different, RuntimeLimits::default()),
        Err(RuntimeError::ForeignAuthority)
    );
    let changed = RuntimeLimits {
        maximum_operations: 1,
        ..RuntimeLimits::default()
    };
    assert_eq!(
        slot.validate_world(&record, changed),
        Err(RuntimeError::ForeignAuthority)
    );

    drop(slot);

    assert_eq!(queue.reserved_worlds(), 0);
    assert!(
        queue
            .reserve_world(&record, RuntimeLimits::default())
            .is_ok()
    );
}

#[test]
fn dropping_all_borrowers_retains_native_handles_committed_ack_and_scheduler_until_reclamation() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let record = record(&graph);
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let slot = queue
        .reserve_world(&record, RuntimeLimits::default())
        .unwrap();
    let weak = Rc::downgrade(&queue.inner);
    let mut runtime = NodeRuntime::new(
        &graph,
        crate::node_contract::test_nodes(&graph),
        record.clone(),
        RuntimeLimits::default(),
        slot,
    )
    .unwrap_or_else(|failure| panic!("model runtime admission failed: {}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime.activate(&mut Publisher).unwrap();
    let grant = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&id("a"), id("original/run"), 100.into())
        .unwrap();
    let token = match runtime.begin_admitted(grant).unwrap() {
        BeginResult::Accepted(token) => token,
        _ => panic!("model original operation refused"),
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        runtime.poll(&token, &mut context),
        Poll::Ready(Ok(_))
    ));
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    drop(commit);
    drop(queue);

    drop(runtime);

    let queue = RuntimeCustodyQueue {
        inner: weak
            .upgrade()
            .expect("complete custody disappeared with borrowers"),
    };
    assert_eq!(queue.retained_worlds(), 1);
    assert!(
        queue
            .reserve_world(&record, RuntimeLimits::default())
            .is_err()
    );
    {
        let custody = queue.inner.mailboxes[0].custody.borrow();
        let custody = custody.as_ref().unwrap();
        assert_eq!(custody.activation(), &record);
        assert_eq!(
            custody.publication_status(),
            Some(PublicationStatus::Committed)
        );
        assert_eq!(custody.native_handle_count(), 2);
        assert_eq!(custody.operation_count(), 1);
        assert!(matches!(
            custody.operation(&token),
            Some(RetainedOperationObservation::Complete {
                acknowledged: false,
                ..
            })
        ));
        assert!(
            custody
                .scheduler_snapshot(position(100), 7.into())
                .unwrap()
                .used_operations
                .contains(&id("original/run"))
        );
    }
    assert!(matches!(
        queue.poll_reclamation(&mut context),
        Poll::Pending
    ));
    assert_eq!(queue.reserved_worlds(), 1);
    assert!(matches!(
        queue.poll_reclamation(&mut context),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(queue.reserved_worlds(), 0);
    drop(queue);
    assert!(weak.upgrade().is_none());
}

#[test]
fn incompatible_prepared_nodes_preserve_every_handle_and_original_record_in_supervision() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let record = record(&graph);
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let slot = queue
        .reserve_world(&record, RuntimeLimits::default())
        .unwrap();
    let nodes = crate::node_contract::test_nodes(&graph);
    let mut malformed = record.clone();
    malformed.owners[0].incarnation = id("unrelated/owner");
    let failure = match NodeRuntime::new(
        &graph,
        nodes,
        malformed.clone(),
        RuntimeLimits::default(),
        slot,
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("foreign reservation admitted"),
    };
    assert_eq!(failure.nodes.len(), 2);

    drop(failure);

    {
        let retained = queue.inner.mailboxes[0].custody.borrow();
        let retained = retained.as_ref().unwrap();
        assert_eq!(retained.native_handle_count(), 2);
        assert_eq!(retained.activation(), &malformed);
        assert_eq!(retained.publication_status(), None);
    }

    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        queue.poll_reclamation(&mut context),
        Poll::Pending
    ));
    assert!(matches!(
        queue.poll_reclamation(&mut context),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(queue.reserved_worlds(), 0);
}

#[test]
fn cleanup_unwind_preserves_complete_custody_and_allows_authentic_reclamation() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let record = record(&graph);
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let slot = queue
        .reserve_world(&record, RuntimeLimits::default())
        .unwrap();
    let runtime = NodeRuntime::new(
        &graph,
        crate::node_contract::test_nodes(&graph),
        record.clone(),
        RuntimeLimits::default(),
        slot,
    )
    .unwrap_or_else(|failure| panic!("model admission failed: {}", failure.error));
    drop(runtime);
    let mailbox = Rc::clone(&queue.inner.mailboxes[0]);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let custody = mailbox.custody.borrow_mut().take();
        mailbox.polling.set(true);
        let _guard = PollingCustody {
            mailbox: Rc::clone(&mailbox),
            custody,
        };
        panic!("model native cleanup callback unwound");
    }));

    assert!(result.is_err());
    assert_eq!(queue.retained_worlds(), 1);
    assert!(!mailbox.polling.get());
    {
        let custody = mailbox.custody.borrow();
        let custody = custody.as_ref().unwrap();
        assert_eq!(custody.activation(), &record);
        assert_eq!(custody.native_handle_count(), 2);
    }
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        queue.poll_reclamation(&mut context),
        Poll::Pending
    ));
    assert!(matches!(
        queue.poll_reclamation(&mut context),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(queue.reserved_worlds(), 0);
}
