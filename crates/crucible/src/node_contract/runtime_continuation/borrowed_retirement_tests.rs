//! Faults real borrowed preparation and queue custody with existing inert node fixtures.
//!
//! The queue/slot/preparation code is production code. Nodes and receipts are
//! explicit model fixtures: no SDK process, registrar or native cleanup claim.

use std::{
    cell::{Cell, RefCell},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use super::*;
use crate::node_contract::{
    NativeReclamationReceipt, NodeStatus, ReadyAttestation, Refusal, ThreadAffinity,
};
use crucible_node_contract::{NodeBinding, NodeDescriptor, Phase};

struct PanicWake(AtomicBool);

impl Wake for PanicWake {
    fn wake(self: Arc<Self>) {
        assert!(
            !self.0.swap(false, Ordering::SeqCst),
            "original post-store wake panic"
        );
    }
}

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

#[test]
fn post_store_wake_unwind_keeps_world_in_exact_prior_queue() -> Result<(), RuntimeError> {
    let (nodes, record) = fixture()?;
    let queue = super::super::RuntimeCustodyQueue::new(1)?;
    let slot = queue.reserve_world(&record, RuntimeLimits::default())?;
    let mut original = PreparedRealization::new(nodes, record, RuntimeLimits::default(), slot);
    let waker = Waker::from(Arc::new(PanicWake(AtomicBool::new(true))));
    assert!(
        queue
            .poll_reclamation(&mut Context::from_waker(&waker))
            .is_pending()
    );

    assert_eq!(
        original.retire_original(),
        Err(RuntimeError::OutstandingObligations)
    );
    assert_eq!(queue.retained_worlds(), 1);
    assert_eq!(queue.reserved_worlds(), 1);
    assert!(original.nodes.is_empty());
    // Retry reads the same retained slot marker; no second world is installed.
    original.retire_original()?;
    assert_eq!(queue.retained_worlds(), 1);
    finish_model_queue(&queue);
    Ok(())
}

struct FaultNode {
    inner: Box<dyn SimulationNode>,
    panic_once: Rc<Cell<bool>>,
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
        let result = self.inner.poll_reclamation(owner, context);
        if matches!(&result, Poll::Ready(Ok(_))) {
            self.successful_polls.set(self.successful_polls.get() + 1);
        }
        result
    }
}

#[test]
fn native_cleanup_unwinds_restore_same_complete_world_and_owner_front() -> Result<(), RuntimeError>
{
    let (mut nodes, record) = fixture()?;
    let panic_once = Rc::new(Cell::new(true));
    let callbacks = Rc::new(Cell::new(0));
    let successful_polls = Rc::new(Cell::new(0));
    let validations = Rc::new(Cell::new(0));
    let inner = nodes.remove(0);
    nodes.insert(
        0,
        Box::new(FaultNode {
            inner,
            panic_once,
            poll_once: Cell::new(true),
            callbacks: Rc::clone(&callbacks),
            successful_polls: Rc::clone(&successful_polls),
            validations: Rc::clone(&validations),
        }),
    );
    let queue = super::super::RuntimeCustodyQueue::new(1)?;
    let slot = queue.reserve_world(&record, RuntimeLimits::default())?;
    let mut original = PreparedRealization::new(nodes, record, RuntimeLimits::default(), slot);
    original.retire_original()?;
    assert_eq!(
        callbacks.get(),
        0,
        "no native callback before world transfer"
    );

    let waker = Waker::noop();
    assert!(
        catch_unwind(AssertUnwindSafe(
            || queue.poll_reclamation(&mut Context::from_waker(waker))
        ))
        .is_err()
    );
    assert_eq!(queue.retained_worlds(), 1);
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(callbacks.get(), 1);
    // This second unwind occurs after quarantine and original owner-list
    // creation, inside the native cleanup callback. Its front must survive.
    assert!(
        catch_unwind(AssertUnwindSafe(
            || queue.poll_reclamation(&mut Context::from_waker(waker))
        ))
        .is_err()
    );
    assert_eq!(queue.retained_worlds(), 1);
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(successful_polls.get(), 0);
    assert_eq!(validations.get(), 0);
    finish_model_queue(&queue);
    assert!(callbacks.get() >= 2);
    assert!(
        successful_polls.get() > 0,
        "same affected owner was polled successfully after unwind"
    );
    assert!(
        validations.get() > 0,
        "same affected owner original receipt was validated after unwind"
    );
    Ok(())
}

struct RefusingSlot(Rc<RefCell<Option<WholeRuntimeCustody>>>);

impl RuntimeCustodySlot for RefusingSlot {
    fn validate_world(&self, _: &ActivationRecord, _: RuntimeLimits) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn retain(self: Box<Self>, original: WholeRuntimeCustody) {
        *self.0.borrow_mut() = Some(original);
    }
}

#[test]
fn default_refusing_borrowed_slot_keeps_exact_original_prepared_nodes() -> Result<(), RuntimeError>
{
    let (nodes, record) = fixture()?;
    let identity = nodes.as_ptr();
    let length = nodes.len();
    let retained = Rc::new(RefCell::new(None));
    let slot = Box::new(RefusingSlot(Rc::clone(&retained)));
    let mut original = PreparedRealization::new(nodes, record, RuntimeLimits::default(), slot);

    assert_eq!(
        original.retire_original(),
        Err(RuntimeError::OutstandingObligations)
    );
    assert_eq!(original.nodes.as_ptr(), identity);
    assert_eq!(original.nodes.len(), length);
    assert!(retained.borrow().is_none());
    drop(original);
    assert!(
        retained.borrow().is_some(),
        "legacy consuming original retained separately"
    );
    Ok(())
}
