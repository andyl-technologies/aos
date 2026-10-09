//! Synthetic sealed-world tests of original native input-buffer custody.

// crucible-lint: allow panic-shortcut -- These runtime input tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    cell::RefCell,
    rc::Rc,
    task::{Context, Poll},
};

use crate::node_contract::*;
use crate::node_scheduling::{NativeInputAcknowledgement, RuntimeInputBatch};
use crucible_node_contract::{Id, NodeBinding, NodeDescriptor, Phase, Position, canonical};

#[derive(Clone, Copy)]
enum Behavior {
    Accept,
    NoEffect,
    Uncertain,
    WrongAcknowledgement,
}

#[derive(Default)]
struct Buffer {
    calls: usize,
    original: Option<RuntimeInputBatch>,
    acknowledgement: Option<NativeInputAcknowledgement>,
}

struct InputNode {
    inner: Box<dyn SimulationNode>,
    buffer: Rc<RefCell<Buffer>>,
    behavior: Behavior,
}

impl SimulationNode for InputNode {
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
    fn arm(&mut self, record: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        self.inner.arm(record)
    }
    fn validate_readiness(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.inner.validate_readiness(record, ready)
    }
    fn begin_operation(&mut self, operation: &OperationAdmission) -> Submission {
        self.inner.begin_operation(operation)
    }
    fn poll_operation(
        &mut self,
        token: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        self.inner.poll_operation(token, context)
    }
    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.inner.validate_outcome(original, outcome)
    }
    fn request_cancel(&mut self, token: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        self.inner.request_cancel(token)
    }
    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission {
        self.inner.close_quantum(original)
    }
    fn acknowledge_publication(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        self.inner.acknowledge_publication(token, outputs)
    }
    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        self.inner.facet(kind)
    }
    fn quarantine_resources(&mut self) {
        self.inner.quarantine_resources();
    }
    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        self.inner.poll_reclamation(owner, context)
    }
    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        self.inner.validate_reclamation(receipt)
    }

    fn stage_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        let mut buffer = self.buffer.borrow_mut();
        buffer.calls += 1;
        if matches!(self.behavior, Behavior::NoEffect) {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "test buffer unavailable before copying".into(),
            });
        }
        buffer.original = Some(batch.retained_copy());
        if matches!(self.behavior, Behavior::Uncertain) {
            return Err(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: "test partial native custody remains".into(),
            });
        }
        let mut acknowledgement = NativeInputAcknowledgement {
            stage_operation: batch.stage_operation().clone(),
            batch: batch.batch().clone(),
            node: batch.node().clone(),
            owners: batch.owners().to_vec(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory().clone(),
            proof_ref: canonical::content_ref(
                b"test copied native immutable input buffer",
                "application/octet-stream",
            )
            .unwrap(),
        };
        if matches!(self.behavior, Behavior::WrongAcknowledgement) {
            acknowledgement.batch = Id::new("wrong/batch").unwrap();
        }
        buffer.acknowledgement = Some(acknowledgement.clone());
        Ok(acknowledgement)
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &RuntimeInputBatch,
        acknowledgement: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        let buffer = self.buffer.borrow();
        let native = buffer.original.as_ref().ok_or(OperationFailure {
            effects: EffectKnowledge::Unknown,
            reason: "test original native buffer lost".into(),
        })?;
        if native.node() != batch.node()
            || native.batch() != batch.batch()
            || native.cutoff() != batch.cutoff()
            || native.deliveries() != batch.deliveries()
            || native.payloads() != batch.payloads()
            || buffer.acknowledgement.as_ref() != Some(acknowledgement)
        {
            return Err(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: "test native buffer no longer matches".into(),
            });
        }
        Ok(())
    }
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

fn fixture(behavior: Behavior) -> (super::NodeRuntime, WorldActivation, Rc<RefCell<Buffer>>) {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let mut nodes = crate::node_contract::test_nodes(&graph);
    let buffer = Rc::new(RefCell::new(Buffer::default()));
    let original = nodes.remove(0);
    nodes.insert(
        0,
        Box::new(InputNode {
            inner: original,
            buffer: Rc::clone(&buffer),
            behavior,
        }),
    );
    let owners = nodes
        .iter()
        .flat_map(|node| node.route().owners.clone())
        .collect();
    let record = ActivationRecord {
        generation: 1.into(),
        activation_id: Id::new("activation/input-tests").unwrap(),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners,
        boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
    };
    let mut runtime = super::NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .ok()
    .unwrap();
    runtime.arm_all().unwrap();
    let activation = runtime.activate(&mut Publisher).unwrap();
    (runtime, activation, buffer)
}

fn batch(
    runtime: &super::NodeRuntime,
    activation: &WorldActivation,
    stage: &str,
    batch: &str,
) -> RuntimeInputBatch {
    let node = Id::new("a").unwrap();
    RuntimeInputBatch {
        activation: activation.clone(),
        owners: runtime.nodes.get(&node).unwrap().route().owners.clone(),
        node,
        stage_operation: Id::new(stage).unwrap(),
        batch: Id::new(batch).unwrap(),
        cutoff: Position::new(0.into(), 1.into(), Phase::Reaction),
        inventory: canonical::content_ref(b"[]", "application/json").unwrap(),
        deliveries: Vec::new(),
        payloads: Vec::new(),
    }
}

#[test]
fn original_native_ack_and_lost_response_recovery_do_not_restage_inputs() {
    let (mut runtime, activation, buffer) = fixture(Behavior::Accept);
    let original = batch(&runtime, &activation, "stage/a", "batch/a");
    let acknowledgement = runtime.stage_inputs(original).unwrap();
    assert_eq!(acknowledgement.batch().as_str(), "batch/a");
    assert_eq!(
        runtime
            .owners
            .get(&Id::new("owner/a").unwrap())
            .unwrap()
            .operation
            .as_ref()
            .unwrap()
            .as_str(),
        "stage/a"
    );
    runtime
        .recover_input_staging(&activation, &Id::new("stage/a").unwrap())
        .unwrap();
    assert_eq!(buffer.borrow().calls, 1);
    let repeated = batch(&runtime, &activation, "stage/retry", "batch/a");
    assert!(matches!(
        runtime.stage_inputs(repeated),
        Err(RuntimePollFailure::Admission(
            RuntimeError::DuplicateOperation
        ))
    ));
    assert_eq!(buffer.borrow().calls, 1);
}

#[test]
fn no_effect_refusal_releases_lock_but_retains_used_original_identity() {
    let (mut runtime, activation, buffer) = fixture(Behavior::NoEffect);
    let original = batch(&runtime, &activation, "stage/a", "batch/a");
    assert!(matches!(
        runtime.stage_inputs(original),
        Err(RuntimePollFailure::Native(_))
    ));
    let owner = runtime.owners.get(&Id::new("owner/a").unwrap()).unwrap();
    assert!(owner.operation.is_none());
    assert_eq!(owner.lifecycle, Lifecycle::Stopped);
    assert!(buffer.borrow().original.is_none());
    assert_eq!(
        runtime
            .retained_input_batch(&Id::new("stage/a").unwrap())
            .unwrap()
            .batch()
            .as_str(),
        "batch/a"
    );
    assert!(
        runtime
            .recover_input_staging(&activation, &Id::new("stage/a").unwrap())
            .is_err()
    );
}

#[test]
fn uncertain_partial_staging_keeps_original_batch_and_quarantines_owner() {
    let (mut runtime, activation, buffer) = fixture(Behavior::Uncertain);
    let original = batch(&runtime, &activation, "stage/a", "batch/a");
    assert!(matches!(
        runtime.stage_inputs(original),
        Err(RuntimePollFailure::Native(_))
    ));
    let owner = runtime.owners.get(&Id::new("owner/a").unwrap()).unwrap();
    assert_eq!(owner.lifecycle, Lifecycle::Quarantined);
    assert_eq!(owner.operation.as_ref().unwrap().as_str(), "stage/a");
    assert!(buffer.borrow().original.is_some());
    assert!(
        runtime
            .retained_input_batch(&Id::new("stage/a").unwrap())
            .is_ok()
    );
}

#[test]
fn wrong_cut_or_lost_native_buffer_cannot_release_staging_custody() {
    let (mut runtime, activation, _) = fixture(Behavior::WrongAcknowledgement);
    let original = batch(&runtime, &activation, "stage/a", "batch/a");
    assert!(matches!(
        runtime.stage_inputs(original),
        Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))
    ));
    assert_eq!(
        runtime
            .owners
            .get(&Id::new("owner/a").unwrap())
            .unwrap()
            .lifecycle,
        Lifecycle::Quarantined
    );

    let (mut runtime, activation, buffer) = fixture(Behavior::Accept);
    let original = batch(&runtime, &activation, "stage/a", "batch/a");
    runtime.stage_inputs(original).unwrap();
    buffer.borrow_mut().original.take();
    assert!(matches!(
        runtime.recover_input_staging(&activation, &Id::new("stage/a").unwrap()),
        Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))
    ));
    assert_eq!(buffer.borrow().calls, 1);
}
