//! Model-only supervisor tests for finite reservation and surviving complete ACK custody.

// Test panics expose discarded native handles, original ACK state or reservations.
// crucible-lint: allow panic-shortcut -- These supervisor tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_contract::{BeginResult, RetainedOperationObservation};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn position(time: u64) -> Position {
    Position::new(
        time.into(),
        0.into(),
        crucible_node_format::Phase::BoundaryControl,
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
fn unknown_complete_publication_survives_drop_and_contained_reconciliation() {
    use crate::node_contract::PreparedWorldPublication;
    use crucible_node_format::{Extensions, PreparedOwner, canonical};

    struct CompletePublisher(bool);

    impl ActivationPublisher for CompletePublisher {
        fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
            panic!("complete publication cannot use scalar custody")
        }

        fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
            panic!("complete reconciliation cannot use scalar custody")
        }

        fn prepare_coordinator(
            &mut self,
            _: &ActivationRecord,
            _: &[crate::node_contract::ValidatedNodePreparation],
        ) -> Result<InputPayload, RuntimeError> {
            let bytes = b"{\"model_coordinator\":\"original\"}".to_vec();
            Ok(InputPayload {
                reference: canonical::content_ref(&bytes, "application/json").unwrap(),
                bytes,
            })
        }

        fn publish_complete(
            &mut self,
            _: &ActivationRecord,
            _: &PreparedWorldPublication,
        ) -> PublicationStatus {
            assert!(!self.0, "model commit followed by callback unwind");
            PublicationStatus::Unknown
        }

        fn reconcile_complete(
            &mut self,
            _: &ActivationRecord,
            _: &PreparedWorldPublication,
        ) -> PublicationStatus {
            PublicationStatus::Committed
        }
    }

    for (reconcile, unwind) in [(false, false), (true, false), (false, true)] {
        let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
        let record = record(&graph);
        let queue = RuntimeCustodyQueue::new(1).unwrap();
        let slot = queue
            .reserve_world(&record, RuntimeLimits::default())
            .unwrap();
        let mut runtime = NodeRuntime::new(
            &graph,
            crate::node_contract::test_nodes(&graph),
            record.clone(),
            RuntimeLimits::default(),
            slot,
        )
        .unwrap_or_else(|failure| panic!("model admission failed: {}", failure.error));
        runtime.arm_all().unwrap();

        // Install model-only public records into the barrier to exercise whole
        // supervisor transfer independently of any native qualification claim.
        let mut nodes = runtime.prepared_node_records().unwrap().to_vec();
        for node in &mut nodes {
            node.prepared_owners = Some(
                node.readiness
                    .owners
                    .iter()
                    .map(|owner| PreparedOwner {
                        owner_id: owner.owner.clone(),
                        incarnation_id: owner.incarnation.clone(),
                        owner_generation: owner.generation,
                        prepared_token: id("original/model-preparation"),
                        binding_hashes: vec![
                            graph.binding(&node.node).unwrap().identity().unwrap(),
                        ],
                        ready_receipt: node.readiness.ready_receipt.clone(),
                        extensions: Extensions::new(),
                    })
                    .collect(),
            );
        }
        runtime.barrier = super::super::ActivationBarrier::new(record.clone()).unwrap();
        runtime.barrier.ready(nodes.clone()).unwrap();
        let mut publisher = CompletePublisher(unwind);
        if unwind {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    runtime.activate(&mut publisher)
                }))
                .is_err()
            );
        } else {
            assert!(runtime.activate(&mut publisher).is_err());
        }
        assert_eq!(runtime.arm_all(), Err(RuntimeError::ForeignAuthority));
        let original = runtime.barrier.retained_preparation().unwrap();
        let mut quarantined = runtime.into_quarantine();
        let expected_status = if reconcile {
            assert_eq!(
                quarantined
                    .reconcile_publication(&record, &mut publisher)
                    .unwrap(),
                PublicationStatus::Committed
            );
            PublicationStatus::Committed
        } else {
            PublicationStatus::Unknown
        };

        drop(quarantined);

        let retained = queue.inner.mailboxes[0].custody.borrow();
        let retained = retained.as_ref().unwrap();
        assert_eq!(retained.activation(), &record);
        assert_eq!(retained.publication_status(), Some(expected_status));
        assert_eq!(retained.native_handle_count(), 2);
        assert_eq!(retained.node_preparations(), nodes);
        assert_eq!(
            retained.prepared_world_publication(),
            Some(original.as_ref())
        );
        assert_eq!(
            retained
                .prepared_world_publication()
                .unwrap()
                .coordinator_snapshot()
                .bytes,
            b"{\"model_coordinator\":\"original\"}"
        );
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

#[test]
fn actual_reserved_runtime_slot_reports_all_empty_mailbox_backing_and_refuses_one_short()
-> Result<(), RuntimeError> {
    let (runtime, _) = crate::node_contract::runtime::tests::capture_ticket_fixture();
    let queue = RuntimeCustodyQueue::new(3)?;
    let slot = queue.reserve_world(runtime.barrier.record(), RuntimeLimits::default())?;
    let aliases = Rc::strong_count(&queue.inner);
    let bytes = slot
        .retained_requested_storage_data(4 * 1024 * 1024)?
        .ok_or(RuntimeError::UnsupportedFacet)?;
    assert!(
        bytes
            >= std::mem::size_of::<QueueInner>()
                + queue.inner.mailboxes.capacity() * std::mem::size_of::<Rc<Mailbox>>()
                + queue.inner.mailboxes.len() * std::mem::size_of::<Mailbox>()
    );
    assert_eq!(
        slot.retained_requested_storage_data(bytes - 1),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(slot.retained_requested_storage_data(bytes)?, Some(bytes));
    assert_eq!(Rc::strong_count(&queue.inner), aliases);
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(queue.retained_worlds(), 0);
    Ok(())
}

#[test]
fn runtime_slot_does_not_assign_zero_storage_to_an_opaque_waker_or_busy_custody()
-> Result<(), RuntimeError> {
    let (runtime, _) = crate::node_contract::runtime::tests::capture_ticket_fixture();
    let queue = RuntimeCustodyQueue::new(1)?;
    let slot = queue.reserve_world(runtime.barrier.record(), RuntimeLimits::default())?;
    *queue.inner.waker.borrow_mut() = Some(Waker::noop().clone());
    assert_eq!(slot.retained_requested_storage_data(4 * 1024 * 1024)?, None);
    assert!(queue.inner.waker.borrow().is_some());
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(queue.retained_worlds(), 0);

    let busy_queue = RuntimeCustodyQueue::new(1)?;
    let busy_slot = busy_queue.reserve_world(runtime.barrier.record(), RuntimeLimits::default())?;
    busy_queue.inner.mailboxes[0].polling.set(true);
    assert_eq!(
        busy_slot.retained_requested_storage_data(4 * 1024 * 1024)?,
        None
    );
    assert!(busy_queue.inner.mailboxes[0].polling.get());
    Ok(())
}

#[test]
fn runtime_slot_data_observer_refuses_foreign_origin_before_borrowing_mailbox_state()
-> Result<(), RuntimeError> {
    let (runtime, source) = crate::node_contract::runtime::tests::capture_ticket_fixture();
    let mut queue = RuntimeCustodyQueue::new(1)?;
    Rc::get_mut(&mut queue.inner)
        .ok_or(RuntimeError::OutstandingObligations)?
        .process = std::process::id().wrapping_add(1);
    let activation = ActivationRecord {
        generation: source.source_activation.generation,
        activation_id: source.source_activation.activation_id,
        world_binding_hash: source.source_activation.world_binding_hash,
        owners: source.source_activation.owners,
        boundary: source.source_activation.boundary,
    };
    let slot = queue.reserve_world(&activation, runtime.limits)?;
    let held = queue.inner.waker.borrow_mut();
    assert_eq!(
        slot.retained_requested_storage_data(4 * 1024 * 1024),
        Err(RuntimeError::ForeignAuthority)
    );
    assert_eq!(queue.reserved_worlds(), 1);
    assert!(held.is_none());
    Ok(())
}

#[test]
fn selected_bounded_wake_drives_same_modeled_runtime_from_pending_to_authentic_reclamation() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let record = record(&graph);
    let (queue, wake) = RuntimeCustodyQueue::new_with_bounded_wake(1).unwrap();
    let slot = queue
        .reserve_world(&record, RuntimeLimits::default())
        .unwrap();
    let mut runtime = NodeRuntime::new(
        &graph,
        crate::node_contract::test_nodes(&graph),
        record,
        RuntimeLimits::default(),
        slot,
    )
    .unwrap_or_else(|failure| panic!("modeled runtime admission failed: {}", failure.error));
    runtime.arm_all().unwrap();
    runtime.activate(&mut Publisher).unwrap();
    // An active runtime is still owned here, never falsely reclaimed by an empty queue.
    assert!(matches!(
        queue.poll_reclamation_with_original_wake(&wake).unwrap(),
        Poll::Pending
    ));
    assert_eq!(queue.reserved_worlds(), 1);
    drop(runtime);
    assert_eq!(queue.retained_worlds(), 1);
    assert!(matches!(
        queue.poll_reclamation_with_original_wake(&wake).unwrap(),
        Poll::Pending
    ));
    assert_eq!(queue.retained_worlds(), 1);
    assert!(matches!(
        queue.poll_reclamation_with_original_wake(&wake).unwrap(),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(queue.retained_worlds(), 0);
    assert_eq!(queue.reserved_worlds(), 0);
}

#[test]
fn same_proposal_does_not_substitute_a_foreign_original_custody_queue() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let record = record(&graph);
    let (original, _wake) = RuntimeCustodyQueue::new_with_bounded_wake(1).unwrap();
    let (foreign, _foreign_wake) = RuntimeCustodyQueue::new_with_bounded_wake(1).unwrap();
    let slot = original
        .reserve_world(&record, RuntimeLimits::default())
        .unwrap();
    let original_aliases = Rc::strong_count(&original.inner);
    original.authenticate_original_slot(slot.as_ref()).unwrap();
    assert_eq!(
        foreign.authenticate_original_slot(slot.as_ref()),
        Err(RuntimeError::ForeignAuthority)
    );
    assert_eq!(
        original.authenticate_original_slot(&TestCustodySlot),
        Err(RuntimeError::UnsupportedFacet)
    );
    assert_eq!(Rc::strong_count(&original.inner), original_aliases);
    assert_eq!(original.reserved_worlds(), 1);
    assert_eq!(foreign.reserved_worlds(), 0);
}
