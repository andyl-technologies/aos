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

use crucible::node_contract::{
    ActivationRecord, PreparedRealization, RuntimeCustodyQueue, RuntimeCustodySupervisor,
    RuntimeLimits,
};
use crucible_cas::content_store::{
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
                .map(|owner| crucible::node_contract::OwnerIdentity {
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
