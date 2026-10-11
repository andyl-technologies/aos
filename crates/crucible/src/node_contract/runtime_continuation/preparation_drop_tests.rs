//! Exercises preparation Drop with original queue ownership across callback faults.
//!
//! Participants and receipts are inert source fixtures. The original world slot,
//! preparation Drop and reclamation queue are production implementations.

use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    task::{Context, Poll, Waker},
};

use super::*;
use crate::node_contract::{
    EffectKnowledge, FacetKind, NativeReclamationReceipt, NodeFacet, NodeRoute, NodeStatus,
    PreparedRealization, ReadyAttestation, Refusal, RuntimeCustodySupervisor, ThreadAffinity,
};
use crucible_node_contract::{NodeBinding, NodeDescriptor, Phase};

fn fixture() -> Result<(Vec<Box<dyn SimulationNode>>, ActivationRecord), RuntimeError> {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let mut owners = Vec::new();
    for owner in graph.owners() {
        let binding = graph
            .binding(&owner.owner.participant_ids[0])
            .ok_or(RuntimeError::InvalidRoute)?;
        owners.push(OwnerIdentity {
            owner: owner.owner.id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        });
    }
    let record = ActivationRecord {
        generation: 1.into(),
        activation_id: Id::new("retirement/model-original")
            .map_err(|_| RuntimeError::InvalidRoute)?,
        world_binding_hash: graph.world_binding_hash().clone(),
        boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        owners,
    };
    Ok((crate::node_contract::test_nodes(&graph), record))
}

fn finish_model_queue(queue: &super::super::RuntimeCustodyQueue) {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    for _ in 0..64 {
        match queue.poll_reclamation(&mut context) {
            Poll::Ready(Ok(())) => {
                assert_eq!(queue.reserved_worlds(), 0);
                return;
            }
            Poll::Pending => {}
            Poll::Ready(Err(error)) => panic!("original model receipt refused: {error:?}"),
        }
    }
    panic!("finite original model cleanup did not finish");
}

struct FaultNode {
    inner: Box<dyn SimulationNode>,
    panic_once: Rc<Cell<bool>>,
    route_once: Cell<bool>,
    validate_once: Cell<bool>,
    pending_once: Cell<bool>,
    error_once: Cell<bool>,
    poll_once: Cell<bool>,
    callbacks: Rc<Cell<usize>>,
    successful_polls: Rc<Cell<usize>>,
    validations: Rc<Cell<usize>>,
}

impl SimulationNode for FaultNode {
    fn descriptor(&self) -> &NodeDescriptor {
        self.inner.descriptor()
    }

    fn binding(&self) -> &NodeBinding {
        self.inner.binding()
    }

    fn route(&self) -> &NodeRoute {
        assert!(
            !self.route_once.replace(false),
            "original route callback panic"
        );
        self.inner.route()
    }

    fn thread_affinity(&self) -> ThreadAffinity {
        self.inner.thread_affinity()
    }

    fn facets(&self) -> &[FacetKind] {
        self.inner.facets()
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        self.inner.status()
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        self.inner.arm(world)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        readiness: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.inner.validate_readiness(world, readiness)
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        self.inner.begin_operation(admission)
    }

    fn poll_operation(
        &mut self,
        operation: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        self.inner.poll_operation(operation, context)
    }

    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.inner.validate_outcome(original, outcome)
    }

    fn request_cancel(
        &mut self,
        operation: &OperationToken,
    ) -> Result<CancelStatus, OperationFailure> {
        self.inner.request_cancel(operation)
    }

    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission {
        self.inner.close_quantum(original)
    }

    fn acknowledge_publication(
        &mut self,
        operation: &OperationToken,
        outputs: &[crucible_node_contract::Id],
    ) -> Result<(), OperationFailure> {
        self.inner.acknowledge_publication(operation, outputs)
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        self.inner.facet(kind)
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        assert!(
            !self.validate_once.replace(false),
            "original validation callback panic"
        );
        self.inner.validate_reclamation(receipt)?;
        self.validations.set(self.validations.get() + 1);
        Ok(())
    }

    fn quarantine_resources(&mut self) {
        self.callbacks.set(self.callbacks.get() + 1);
        assert!(
            !self.panic_once.replace(false),
            "original quarantine callback panic"
        );
        self.inner.quarantine_resources();
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        assert!(
            !self.poll_once.replace(false),
            "original native cleanup callback panic"
        );
        if self.pending_once.replace(false) {
            return Poll::Pending;
        }
        if self.error_once.replace(false) {
            return Poll::Ready(Err(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: "inert original cleanup refusal".into(),
            }));
        }
        let result = self.inner.poll_reclamation(owner, context);
        if matches!(&result, Poll::Ready(Ok(_))) {
            self.successful_polls.set(self.successful_polls.get() + 1);
        }
        result
    }
}

#[test]
fn preparation_drop_transfers_before_all_cleanup_callbacks() -> Result<(), RuntimeError> {
    let (mut nodes, record) = fixture()?;
    assert!(nodes.len() > 1, "a sibling owner must also be reclaimed");
    let callbacks = Rc::new(Cell::new(0));
    let successful_polls = Rc::new(Cell::new(0));
    let validations = Rc::new(Cell::new(0));
    let inner = nodes.remove(0);
    nodes.insert(
        0,
        Box::new(FaultNode {
            inner,
            panic_once: Rc::new(Cell::new(true)),
            route_once: Cell::new(true),
            poll_once: Cell::new(true),
            validate_once: Cell::new(true),
            pending_once: Cell::new(true),
            error_once: Cell::new(true),
            callbacks: Rc::clone(&callbacks),
            successful_polls: Rc::clone(&successful_polls),
            validations: Rc::clone(&validations),
        }),
    );
    let sibling_polls = Rc::new(Cell::new(0));
    let sibling_validations = Rc::new(Cell::new(0));
    let sibling = nodes.remove(1);
    nodes.insert(
        1,
        Box::new(FaultNode {
            inner: sibling,
            panic_once: Rc::new(Cell::new(false)),
            route_once: Cell::new(false),
            validate_once: Cell::new(false),
            pending_once: Cell::new(false),
            error_once: Cell::new(false),
            poll_once: Cell::new(false),
            callbacks: Rc::new(Cell::new(0)),
            successful_polls: Rc::clone(&sibling_polls),
            validations: Rc::clone(&sibling_validations),
        }),
    );
    let queue = RuntimeCustodyQueue::new(1)?;
    let slot = queue.reserve_world(&record, RuntimeLimits::default())?;
    let original = PreparedRealization::new(nodes, record, RuntimeLimits::default(), slot);

    drop(original);
    assert_eq!(
        callbacks.get(),
        0,
        "no callback before complete slot transfer"
    );
    assert_eq!(queue.retained_worlds(), 1);
    let waker = Waker::noop();
    let mut panics = 0;
    let mut refusals = 0;
    let mut pending = 0;
    let mut completed = false;
    for _ in 0..64 {
        let result = catch_unwind(AssertUnwindSafe(|| {
            queue.poll_reclamation(&mut Context::from_waker(waker))
        }));
        match result {
            Err(_) => panics += 1,
            Ok(Poll::Pending) => pending += 1,
            Ok(Poll::Ready(Err(_))) => refusals += 1,
            Ok(Poll::Ready(Ok(()))) => {
                completed = true;
                break;
            }
        }
        assert_eq!(queue.reserved_worlds(), 1);
        assert_eq!(queue.retained_worlds(), 1);
    }

    assert!(completed);
    assert_eq!(
        panics, 4,
        "quarantine, route, poll and validation each unwind once"
    );
    assert_eq!(refusals, 1);
    assert!(pending > 0);
    assert!(
        successful_polls.get() >= 2,
        "the affected front is polled again after validation unwind"
    );
    assert_eq!(
        validations.get(),
        1,
        "the same original owner validates before release"
    );
    assert!(
        sibling_polls.get() > 0,
        "the sibling actual owner must also be polled"
    );
    assert!(
        sibling_validations.get() > 0,
        "the sibling original proof is mandatory"
    );
    assert_eq!(queue.reserved_worlds(), 0);
    Ok(())
}

#[test]
fn unused_preparation_releases_only_its_empty_native_custody() -> Result<(), RuntimeError> {
    let (_, record) = fixture()?;
    let queue = RuntimeCustodyQueue::new(1)?;
    let slot = queue.reserve_world(&record, RuntimeLimits::default())?;

    drop(PreparedRealization::new(
        Vec::new(),
        record,
        RuntimeLimits::default(),
        slot,
    ));
    assert_eq!(queue.retained_worlds(), 1);
    finish_model_queue(&queue);
    Ok(())
}

struct BuilderModel {
    nodes: Vec<Box<dyn SimulationNode>>,
    plan: crate::node_contract::ProviderPreparationPlan,
    activation: ActivationRecord,
    ids: Vec<Id>,
    resources: crucible_node_contract::ResourceLimits,
}

fn builder_model() -> Result<BuilderModel, RuntimeError> {
    let (nodes, activation) = fixture()?;
    let descriptors: Vec<_> = nodes.iter().map(|node| node.descriptor().clone()).collect();
    let bindings = nodes
        .iter()
        .map(|node| node.binding().compatibility.clone())
        .collect();
    let ids = descriptors
        .iter()
        .map(|descriptor| descriptor.id.clone())
        .collect();
    Ok(BuilderModel {
        nodes,
        plan: crate::node_contract::ProviderPreparationPlan {
            descriptors,
            bindings,
        },
        activation,
        ids,
        resources: crucible_node_contract::ResourceLimits {
            memory_bytes: 1_048_576.into(),
            processes: 8.into(),
            descriptors: 32.into(),
            pending_events: 8.into(),
            content_bytes: 1_048_576.into(),
            maximum_operations: 8.into(),
            writable_bytes: 1_048_576.into(),
            cpu_budget_ns: 1_000_000.into(),
            extensions: Default::default(),
        },
    })
}

fn start_builder<'a>(
    model: &'a BuilderModel,
    queue: &RuntimeCustodyQueue,
) -> Result<crate::node_contract::ProviderWorldPreparation<'a>, RuntimeError> {
    let descriptor = model
        .plan
        .descriptors
        .first()
        .ok_or(RuntimeError::InvalidRoute)?;
    let request = crate::node_contract::OriginalRealizationRequest {
        selection: crate::node_contract::ProviderPlanningRequest {
            profile: &descriptor.id,
            configuration: &descriptor.configuration_ref,
            nodes: &model.ids,
            resources: &model.resources,
            limits: Default::default(),
        },
        plan: &model.plan,
        activation: &model.activation,
        runtime_limits: RuntimeLimits::default(),
        custody_slot: queue.reserve_world(&model.activation, RuntimeLimits::default())?,
    };
    crate::node_contract::ProviderWorldPreparation::new(request)
        .map_err(|failure| RuntimeError::SchedulerRefused(failure.reason))
}

#[test]
fn partial_provider_builder_reclaims_only_constructed_originals() -> Result<(), RuntimeError> {
    let mut model = builder_model()?;
    assert!(model.nodes.len() > 1);
    let first = model.nodes.remove(0);
    let queue = RuntimeCustodyQueue::new(1)?;
    let builder = start_builder(&model, &queue)?;

    let builder = builder
        .append(first)
        .map_err(|failure| RuntimeError::SchedulerRefused(failure.reason))?;
    let failure = match builder.finish() {
        Ok(_) => panic!("missing participant cannot finish original preparation"),
        Err(failure) => failure,
    };
    assert_eq!(
        failure
            .retained
            .as_ref()
            .map(|original| original.participants().len()),
        Some(1)
    );
    assert_eq!(queue.reserved_worlds(), 1);
    drop(failure);

    // Other activation owners were never constructed under this slot. Only
    // the original adopted participant supplies a cleanup obligation here.
    finish_model_queue(&queue);
    Ok(())
}

#[test]
fn complete_provider_builder_keeps_same_global_slot_until_drop() -> Result<(), RuntimeError> {
    let mut model = builder_model()?;
    let nodes = std::mem::take(&mut model.nodes);
    let queue = RuntimeCustodyQueue::new(1)?;
    let mut builder = start_builder(&model, &queue)?;
    for node in nodes {
        builder = builder
            .append(node)
            .map_err(|failure| RuntimeError::SchedulerRefused(failure.reason))?;
    }

    let original = builder
        .finish()
        .map_err(|failure| RuntimeError::SchedulerRefused(failure.reason))?;
    assert_eq!(original.activation_record(), &model.activation);
    assert_eq!(original.participants().len(), model.plan.descriptors.len());
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(queue.retained_worlds(), 0);
    drop(original);
    assert_eq!(queue.retained_worlds(), 1);
    finish_model_queue(&queue);
    Ok(())
}

#[test]
fn rejected_provider_append_stays_in_complete_failure_capsule() -> Result<(), RuntimeError> {
    let mut model = builder_model()?;
    let foreign = model.nodes.remove(1);
    let queue = RuntimeCustodyQueue::new(1)?;
    let builder = start_builder(&model, &queue)?;

    let failure = match builder.append(foreign) {
        Ok(_) => panic!("changed original order must refuse"),
        Err(failure) => failure,
    };
    assert_eq!(
        failure
            .retained
            .as_ref()
            .map(|original| original.participants().len()),
        Some(1)
    );
    assert_eq!(queue.reserved_worlds(), 1);
    drop(failure);
    finish_model_queue(&queue);
    Ok(())
}

#[test]
fn provider_append_getter_unwind_preserves_adopted_original_and_world() -> Result<(), RuntimeError>
{
    let mut model = builder_model()?;
    let callbacks = Rc::new(Cell::new(0));
    let validations = Rc::new(Cell::new(0));
    let node = Box::new(FaultNode {
        inner: model.nodes.remove(0),
        panic_once: Rc::new(Cell::new(false)),
        route_once: Cell::new(true),
        poll_once: Cell::new(false),
        validate_once: Cell::new(false),
        pending_once: Cell::new(false),
        error_once: Cell::new(false),
        callbacks: Rc::clone(&callbacks),
        successful_polls: Rc::new(Cell::new(0)),
        validations: Rc::clone(&validations),
    });
    let queue = RuntimeCustodyQueue::new(1)?;
    let builder = start_builder(&model, &queue)?;

    assert!(catch_unwind(AssertUnwindSafe(|| builder.append(node))).is_err());
    assert_eq!(
        callbacks.get(),
        0,
        "unwinding append transfers before native cleanup"
    );
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(queue.retained_worlds(), 1);
    finish_model_queue(&queue);
    assert_eq!(validations.get(), 1);
    Ok(())
}
