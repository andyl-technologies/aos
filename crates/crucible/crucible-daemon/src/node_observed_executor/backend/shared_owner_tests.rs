//! Exercises public alias selection through the sealed common model runtime.
//!
//! Installed Host profiles remain single-participant. These synthetic native
//! journals test executor scheduling without claiming a new native qualification.

// crucible-lint: allow panic-shortcut -- Regression assertions deliberately panic on broken model custody.
#![allow(clippy::unwrap_used)]

#[path = "shared_owner_fixture.rs"]
mod fixture;
#[path = "shared_owner_model.rs"]
mod model;

use std::{cell::RefCell, rc::Rc};

use crucible_engine::node_contract::{
    ActivationRecord, PreparedRealization, RuntimeCustodyQueue, RuntimeCustodySupervisor,
    RuntimeLimits,
};
use crucible_store::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, MutableRefBackend, RefName,
};

use super::*;
use fixture::Topology;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn position(time: u64) -> Position {
    Position::new(U64::new(time), U64::new(0), Phase::BoundaryControl)
}

struct Harness {
    backend: NodeObservedBackend,
    journals: Vec<Rc<RefCell<model::Journal>>>,
    queue: RuntimeCustodyQueue,
    _storage: tempfile::TempDir,
}

impl Harness {
    fn new(topology: Topology) -> Self {
        let (graph, scenario) = fixture::graph(topology);
        let (nodes, journals) = model::nodes(&graph);
        let owners = graph
            .node_ids()
            .flat_map(|node| {
                let binding = graph.binding(node).unwrap();
                [
                    binding.compatibility.execution_owner.id.clone(),
                    binding.compatibility.capture_owner.id.clone(),
                ]
                .map(|owner| crucible_engine::node_contract::OwnerIdentity {
                    owner,
                    incarnation: binding.authority.incarnation_id.clone(),
                    generation: binding.authority.owner_generation,
                })
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let record = ActivationRecord {
            generation: U64::new(1),
            activation_id: id("model-activation"),
            world_binding_hash: graph.world_binding_hash().clone(),
            owners,
            boundary: position(0),
        };
        let queue = RuntimeCustodyQueue::new(1).unwrap();
        let limits = RuntimeLimits::default();
        let slot = queue.reserve_world(&record, limits).unwrap();
        let realization = PreparedRealization::new(nodes, record, limits, slot);
        let storage = tempfile::tempdir().unwrap();
        let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "shared-owner-model",
            storage.path().join("blobs"),
        ));
        let refs: Arc<dyn MutableRefBackend> =
            Arc::new(DirectoryRefBackend::new(storage.path().join("refs")));
        let publisher = StoredWorldActivationPublisher::new(
            blobs.clone(),
            refs,
            RefName::new("node-world-activations/shared-owner-model").unwrap(),
        )
        .unwrap();
        let configuration = NodeRunConfiguration {
            format: "crucible.node-run-configuration".into(),
            version: 1,
            horizon_ps: U64::new(100),
            maximum_rounds: U64::new(4),
        };
        let bytes = input_context_bytes(&scenario, &configuration).unwrap();
        let inputs = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        blobs
            .put_if_absent(inputs, &BlobHandle::from_bytes(bytes))
            .unwrap();
        let mut backend = NodeObservedBackend::from_prepared(
            InstalledPreparedWorld {
                scenario,
                graph,
                realization,
            },
            configuration,
            Box::new(publisher),
            blobs,
            inputs,
            ExecutionId::from_bytes([77; 16]).unwrap(),
        )
        .unwrap();
        let runtime = backend.runtime.as_mut().unwrap();
        runtime.arm_all().unwrap();
        backend.activation = Some(runtime.activate(backend.publisher.as_mut()).unwrap());
        Self {
            backend,
            journals,
            queue,
            _storage: storage,
        }
    }

    fn finish_round(&mut self) {
        let runtime = self.backend.runtime.as_mut().unwrap();
        let active = self.backend.round.as_mut().unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            active.round.poll(runtime, &mut context),
            Poll::Ready(Ok(()))
        ));
        active.round.publish(runtime).unwrap();
        self.backend.round = None;
        self.backend.rounds += 1;
    }

    fn clean(self) {
        let owners = self.backend.graph.owners().count();
        drop(self.backend);
        let mut context = Context::from_waker(Waker::noop());
        // Reclamation deliberately processes one original owner per invocation.
        for remaining in (0..owners).rev() {
            let disposition = self.queue.poll_reclamation(&mut context);
            if remaining == 0 {
                assert!(matches!(disposition, Poll::Ready(Ok(()))));
            } else {
                assert!(disposition.is_pending());
            }
        }
        assert_eq!(self.queue.reserved_worlds(), 0);
    }
}

#[test]
fn backpressured_first_alias_does_not_starve_its_runnable_consumer_sibling() {
    let mut harness = Harness::new(Topology::SharedTransfer);
    let runtime = harness.backend.runtime.as_mut().unwrap();
    let activation = harness.backend.activation.as_ref().unwrap();
    let grant = runtime
        .scheduler(&harness.backend.graph, activation)
        .unwrap()
        .admit_exact(&id("a"), id("fill-credit"), U64::new(5))
        .unwrap();
    let mut fill = DispatchRound::start(runtime, vec![grant], 2).unwrap();
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        fill.poll(runtime, &mut context),
        Poll::Ready(Ok(()))
    ));
    fill.publish(runtime).unwrap();

    let scheduler = runtime
        .scheduler(&harness.backend.graph, activation)
        .unwrap();
    assert!(scheduler.output_backpressure(&id("a")).unwrap());
    assert!(!scheduler.output_backpressure(&id("z")).unwrap());
    let pending = scheduler.pending_inputs(&id("z")).unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(
        pending
            .iter()
            .map(|delivery| delivery.source_sequence.get())
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(
        harness.journals[0].borrow().acknowledgements,
        vec![id("fill-credit")]
    );

    drop(scheduler);

    assert!(harness.backend.begin_round().unwrap());
    let tokens = harness
        .backend
        .round
        .as_ref()
        .unwrap()
        .round
        .tokens()
        .collect::<Vec<_>>();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].route().node, id("z"));
    assert_eq!(harness.journals[0].borrow().begins, vec![id("fill-credit")]);
    assert_eq!(harness.journals[1].borrow().stages, vec![id("stage/0/z")]);
    assert_eq!(harness.journals[1].borrow().begins, vec![id("observe/0/z")]);

    assert_eq!(
        harness.journals[1].borrow().input_commitments,
        vec![id("stage/0/z")]
    );
    assert!(harness.journals[1].borrow().semantic_inputs.is_empty());
    harness.finish_round();
    assert_eq!(
        harness.journals[1].borrow().semantic_inputs,
        vec![vec![0], vec![1]]
    );
    let runtime = harness.backend.runtime.as_mut().unwrap();
    let scheduler = runtime
        .scheduler(
            &harness.backend.graph,
            harness.backend.activation.as_ref().unwrap(),
        )
        .unwrap();
    assert!(scheduler.pending_inputs(&id("z")).unwrap().is_empty());
    assert!(!scheduler.output_backpressure(&id("a")).unwrap());
    assert_eq!(scheduler.position(&id("a")).unwrap(), position(100));
    assert_eq!(scheduler.position(&id("z")).unwrap(), position(100));
    assert_eq!(
        harness.journals[1].borrow().acknowledgements,
        vec![id("observe/0/z")]
    );
    drop(scheduler);

    assert!(!harness.backend.begin_round().unwrap());
    harness.clean();
}

#[test]
fn runnable_aliases_still_dispatch_one_original_operation_per_owner() {
    let mut harness = Harness::new(Topology::SharedIsolated);
    harness.journals[0].borrow_mut().pending = true;
    assert!(harness.backend.begin_round().unwrap());
    assert_eq!(
        harness
            .backend
            .round
            .as_ref()
            .unwrap()
            .round
            .tokens()
            .count(),
        1
    );
    assert_eq!(harness.journals[0].borrow().begins, vec![id("observe/0/a")]);
    assert!(harness.journals[1].borrow().begins.is_empty());
    let runtime = harness.backend.runtime.as_mut().unwrap();
    let activation = harness.backend.activation.as_ref().unwrap();
    assert!(matches!(
        runtime
            .scheduler(&harness.backend.graph, activation)
            .unwrap()
            .admit_exact(&id("z"), id("second-owner-operation"), U64::new(100)),
        Err(SchedulingError::OwnerBusy)
    ));
    let mut context = Context::from_waker(Waker::noop());
    assert!(
        harness
            .backend
            .round
            .as_mut()
            .unwrap()
            .round
            .poll(runtime, &mut context)
            .is_pending()
    );
    harness.journals[0].borrow_mut().pending = false;
    harness.finish_round();
    assert!(!harness.backend.begin_round().unwrap());
    harness.clean();
}

#[test]
fn shared_domain_conflicts_remain_serialized_after_alias_selection() {
    let mut harness = Harness::new(Topology::Conflicting);
    assert!(
        harness
            .backend
            .graph
            .owner_conflicts(&id("owner/a"))
            .unwrap()
            .contains(&id("owner/z"))
    );
    assert!(harness.backend.begin_round().unwrap());
    assert_eq!(
        harness
            .backend
            .round
            .as_ref()
            .unwrap()
            .round
            .tokens()
            .count(),
        1
    );
    assert!(harness.journals[1].borrow().begins.is_empty());
    harness.finish_round();

    assert!(harness.backend.begin_round().unwrap());
    assert_eq!(
        harness
            .backend
            .round
            .as_ref()
            .unwrap()
            .round
            .tokens()
            .next()
            .unwrap()
            .route()
            .node,
        id("z")
    );
    harness.finish_round();
    assert!(!harness.backend.begin_round().unwrap());
    harness.clean();
}

#[test]
fn disjoint_owners_remain_concurrently_dispatchable() {
    let mut harness = Harness::new(Topology::Disjoint);
    harness.journals[0].borrow_mut().pending = true;
    assert!(harness.backend.begin_round().unwrap());
    assert_eq!(
        harness
            .backend
            .round
            .as_ref()
            .unwrap()
            .round
            .tokens()
            .count(),
        2
    );
    let runtime = harness.backend.runtime.as_mut().unwrap();
    let mut context = Context::from_waker(Waker::noop());
    assert!(
        harness
            .backend
            .round
            .as_mut()
            .unwrap()
            .round
            .poll(runtime, &mut context)
            .is_pending()
    );
    assert_eq!(harness.journals[1].borrow().begins, vec![id("observe/0/z")]);
    assert!(harness.journals[1].borrow().acknowledgements.is_empty());
    harness.journals[0].borrow_mut().pending = false;
    harness.finish_round();
    assert!(!harness.backend.begin_round().unwrap());
    harness.clean();
}

// These operational deadline controls never mint model/native authority or move
// a logical cut. Actual grants, tokens, polling and publication use the common
// admitted model runtime; host scheduling and sleeping do not select the cases.
impl Harness {
    fn set_close_deadline(&mut self, selected: usize, expired: bool) {
        // crucible-lint: allow clippy-disallowed-method -- Test-only monotonic deadlines select controller close requests, never modeled time.
        #[allow(clippy::disallowed_methods)]
        let now = std::time::Instant::now();
        let at = if expired {
            now
        } else {
            now.checked_add(Duration::from_secs(3_600)).unwrap()
        };
        self.backend.round.as_mut().unwrap().closures.rows[selected].deadline =
            crate::supervision::ProcessDeadline::at(at);
    }

    fn request_due_closes(&mut self) -> Result<(), NodeObservedError> {
        let active = self.backend.round.as_mut().unwrap();
        let runtime = self.backend.runtime.as_mut().unwrap();
        active
            .closures
            .request_due(|operation| active.round.close_pending_quantum(runtime, operation))
    }

    fn poll_current_round(
        &mut self,
    ) -> Poll<Result<(), crucible_engine::node_dispatch::DispatchError>> {
        let active = self.backend.round.as_mut().unwrap();
        let runtime = self.backend.runtime.as_mut().unwrap();
        active
            .round
            .poll(runtime, &mut Context::from_waker(Waker::noop()))
    }
}

#[test]
fn unequal_quantized_budgets_close_only_the_due_original_and_do_not_settle_the_round() {
    let mut harness = Harness::new(Topology::DisjointQuantized);
    let repeatability = harness.backend.graph.world_repeatability();
    assert!(harness.backend.begin_round().unwrap());
    let schedule = &harness.backend.round.as_ref().unwrap().closures;
    assert!(
        schedule.rows[0]
            .deadline
            .checked_add(Duration::from_secs(1_000))
            == Some(schedule.rows[1].deadline)
    );
    let operations = harness
        .backend
        .round
        .as_ref()
        .unwrap()
        .round
        .tokens()
        .map(|token| token.operation().clone())
        .collect::<Vec<_>>();
    assert_eq!(operations.len(), 2);
    for journal in &harness.journals {
        assert_eq!(journal.borrow().begins.len(), 1);
        assert!(journal.borrow().closes.is_empty());
        journal.borrow_mut().pending = true;
    }
    harness.set_close_deadline(0, true);
    harness.set_close_deadline(1, false);

    harness.request_due_closes().unwrap();
    assert_eq!(
        harness.journals[0].borrow().closes,
        vec![operations[0].clone()]
    );
    assert!(harness.journals[1].borrow().closes.is_empty());
    assert!(harness.poll_current_round().is_pending());
    let runtime = harness.backend.runtime.as_mut().unwrap();
    let active = harness.backend.round.as_mut().unwrap();
    assert!(matches!(
        active.round.publish(runtime),
        Err(crucible_engine::node_dispatch::DispatchError::Incomplete)
    ));
    for node in harness.backend.graph.node_ids() {
        assert_eq!(
            runtime
                .scheduler(
                    &harness.backend.graph,
                    harness.backend.activation.as_ref().unwrap()
                )
                .unwrap()
                .position(node)
                .unwrap(),
            position(0)
        );
    }
    assert_eq!(harness.backend.graph.world_repeatability(), repeatability);

    harness.set_close_deadline(1, true);
    harness.request_due_closes().unwrap();
    harness.request_due_closes().unwrap();
    assert_eq!(harness.journals[0].borrow().closes.len(), 1);
    assert_eq!(
        harness.journals[1].borrow().closes,
        vec![operations[1].clone()]
    );
    assert!(harness.poll_current_round().is_pending());
    for journal in &harness.journals {
        journal.borrow_mut().pending = false;
    }
    assert!(matches!(harness.poll_current_round(), Poll::Ready(Ok(()))));
    let parked = Position::new(U64::new(50), U64::new(0), Phase::BoundaryControl);
    let publication = Position::new(U64::new(50), U64::new(0), Phase::Publication);
    for outcome in harness
        .backend
        .round
        .as_ref()
        .unwrap()
        .round
        .ready_outcomes()
        .unwrap()
    {
        let crucible_engine::node_contract::ProgressEvidence::Quantized {
            publication: actual,
            ..
        } = outcome.progress
        else {
            panic!("original quantum returned another progress class");
        };
        assert_eq!(actual, publication);
        let observation = outcome.scheduling.unwrap();
        assert_eq!(observation.reached, parked);
        assert_eq!(observation.closed_prefix, parked);
        assert!(observation.bounds.iter().all(|bound| {
            bound.bound == crucible_engine::node_scheduling::NativeOutputBound::At(publication)
        }));
    }
    harness.finish_round();
    let runtime = harness.backend.runtime.as_mut().unwrap();
    for node in harness.backend.graph.node_ids() {
        assert_eq!(
            runtime
                .scheduler(
                    &harness.backend.graph,
                    harness.backend.activation.as_ref().unwrap()
                )
                .unwrap()
                .position(node)
                .unwrap(),
            parked
        );
    }
    harness.clean();
}

#[test]
fn a_later_original_close_failure_retains_prior_once_state_and_every_token() {
    for submission in [
        crucible_engine::node_contract::Submission::Refused(
            crucible_engine::node_contract::Refusal {
                reason: "model original close refused".into(),
            },
        ),
        crucible_engine::node_contract::Submission::Uncertain(
            crucible_engine::node_contract::EffectKnowledge::Unknown,
        ),
    ] {
        let mut harness = Harness::new(Topology::DisjointQuantized);
        harness.journals[1].borrow_mut().close_submission = Some(submission);
        assert!(harness.backend.begin_round().unwrap());
        harness.set_close_deadline(0, true);
        harness.set_close_deadline(1, true);
        let tokens = harness
            .backend
            .round
            .as_ref()
            .unwrap()
            .round
            .tokens()
            .cloned()
            .collect::<Vec<_>>();

        let first = harness.request_due_closes().unwrap_err().to_string();
        let repeated = harness.request_due_closes().unwrap_err().to_string();
        assert_eq!(first, repeated);
        for (index, token) in tokens.iter().enumerate() {
            assert_eq!(
                harness.journals[index].borrow().closes,
                vec![token.operation().clone()]
            );
            assert_eq!(harness.journals[index].borrow().begins.len(), 1);
            assert!(
                harness
                    .backend
                    .runtime
                    .as_ref()
                    .unwrap()
                    .recover(token.operation())
                    .is_ok()
            );
            assert!(harness.journals[index].borrow().acknowledgements.is_empty());
        }
        harness.clean();
    }
}

#[test]
fn native_quantized_completion_before_controller_deadline_is_not_closed_again() {
    let mut harness = Harness::new(Topology::DisjointQuantized);
    harness.journals[1].borrow_mut().pending = true;
    assert!(harness.backend.begin_round().unwrap());
    let polled = harness.poll_current_round();
    assert!(
        polled.is_pending(),
        "original quantum round poll: {polled:?}"
    );
    let operations = harness
        .backend
        .round
        .as_ref()
        .unwrap()
        .round
        .tokens()
        .map(|token| token.operation().clone())
        .collect::<Vec<_>>();
    // The runtime requires a genuine original close submission before accepting
    // a terminal quantum. Another close trigger may precede this controller's
    // deadline, but completed work alone cannot bypass that retained request.
    let original = harness
        .backend
        .runtime
        .as_ref()
        .unwrap()
        .recover(&operations[0])
        .unwrap();
    assert!(matches!(
        harness
            .backend
            .runtime
            .as_mut()
            .unwrap()
            .close_quantum(&original)
            .unwrap(),
        crucible_engine::node_contract::Submission::Accepted
    ));
    let polled = harness.poll_current_round();
    assert!(
        polled.is_pending(),
        "original quantum round poll: {polled:?}"
    );
    assert!(
        harness
            .backend
            .runtime
            .as_mut()
            .unwrap()
            .original_completed_operation(&original)
            .is_ok()
    );
    let completed = harness
        .backend
        .runtime
        .as_ref()
        .unwrap()
        .recover(&operations[0])
        .unwrap()
        .clone();
    assert!(matches!(
        harness
            .backend
            .runtime
            .as_mut()
            .unwrap()
            .close_quantum(&completed),
        Err(RuntimeError::InvalidTiming)
    ));
    assert!(completed.same_authority(&original));
    assert_eq!(
        harness.journals[0].borrow().closes,
        vec![operations[0].clone()]
    );
    harness.set_close_deadline(0, true);
    harness.set_close_deadline(1, false);

    harness.request_due_closes().unwrap();
    harness.request_due_closes().unwrap();
    assert_eq!(
        harness.journals[0].borrow().closes,
        vec![operations[0].clone()]
    );
    assert!(harness.journals[1].borrow().closes.is_empty());
    assert!(
        harness
            .backend
            .round
            .as_ref()
            .unwrap()
            .round
            .tokens()
            .any(|token| token.same_authority(&original))
    );

    let polled = harness.poll_current_round();
    assert!(
        polled.is_pending(),
        "original quantum round poll: {polled:?}"
    );
    assert!(matches!(
        harness
            .backend
            .round
            .as_ref()
            .unwrap()
            .round
            .ready_outcomes(),
        Err(crucible_engine::node_dispatch::DispatchError::Incomplete)
    ));
    harness.clean();
}

#[test]
fn uncertain_sequential_start_retains_original_close_schedule_and_cannot_restart() {
    for failed in 0..2 {
        let mut harness = Harness::new(Topology::DisjointQuantized);
        harness.journals[failed].borrow_mut().begin_submission =
            Some(crucible_engine::node_contract::Submission::Uncertain(
                crucible_engine::node_contract::EffectKnowledge::Unknown,
            ));

        assert!(harness.backend.begin_round().is_err());
        assert!(harness.backend.round.is_none());
        let starting = harness.backend.starting_round.as_ref().unwrap();
        let failure = starting.failure.as_ref().unwrap();
        assert_eq!(failure.accepted.len(), failed + 1);
        assert_eq!(failure.undispatched.len(), 1 - failed);
        assert_eq!(starting.closures.rows.len(), 2);
        assert_eq!(
            starting
                .closures
                .rows
                .iter()
                .filter(|row| row.started)
                .count(),
            failed + 1
        );
        let operations = failure
            .accepted
            .iter()
            .map(|token| token.operation().clone())
            .collect::<Vec<_>>();
        let unused = failure
            .undispatched
            .iter()
            .map(|grant| grant.operation().clone())
            .collect::<Vec<_>>();
        assert!(
            harness
                .backend
                .begin_round()
                .unwrap_err()
                .to_string()
                .contains("partial round start")
        );
        for (index, operation) in operations.iter().enumerate() {
            assert_eq!(
                harness.journals[index].borrow().begins,
                vec![operation.clone()]
            );
            assert!(harness.journals[index].borrow().closes.is_empty());
            assert!(
                harness
                    .backend
                    .runtime
                    .as_ref()
                    .unwrap()
                    .recover(operation)
                    .is_ok()
            );
        }
        if failed == 0 {
            assert_eq!(unused, vec![id("observe/0/z")]);
            assert!(harness.journals[1].borrow().begins.is_empty());
        }
        harness.clean();
    }
}

#[test]
fn retained_native_failure_is_propagated_without_a_later_close_request() {
    let mut harness = Harness::new(Topology::DisjointQuantized);
    assert!(harness.backend.begin_round().unwrap());
    harness.journals[0].borrow_mut().poll_failure =
        Some(crucible_engine::node_contract::OperationFailure {
            effects: crucible_engine::node_contract::EffectKnowledge::Unknown,
            reason: "original model terminal failure".into(),
        });
    assert!(matches!(harness.poll_current_round(), Poll::Ready(Err(_))));
    harness.set_close_deadline(0, true);
    harness.set_close_deadline(1, false);

    let error = harness.request_due_closes().unwrap_err().to_string();
    assert!(error.contains("original model terminal failure"));
    assert_eq!(harness.request_due_closes().unwrap_err().to_string(), error);
    assert!(
        harness
            .journals
            .iter()
            .all(|journal| journal.borrow().closes.is_empty())
    );
    harness.clean();
}

#[test]
fn unwinding_native_close_cannot_be_issued_again() {
    let mut harness = Harness::new(Topology::DisjointQuantized);
    assert!(harness.backend.begin_round().unwrap());
    harness.journals[0].borrow_mut().close_panics = true;
    harness.set_close_deadline(0, true);
    harness.set_close_deadline(1, false);

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        harness.request_due_closes()
    }));
    assert!(unwind.is_err());
    assert!(
        harness
            .request_due_closes()
            .unwrap_err()
            .to_string()
            .contains("remains uncertain")
    );
    assert_eq!(harness.journals[0].borrow().closes.len(), 1);
    assert!(harness.journals[1].borrow().closes.is_empty());
    assert!(
        harness
            .journals
            .iter()
            .all(|journal| journal.borrow().acknowledgements.is_empty())
    );
    harness.clean();
}
