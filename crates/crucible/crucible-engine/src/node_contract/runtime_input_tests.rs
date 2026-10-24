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
use crucible_node_format::{Id, NodeBinding, NodeDescriptor, Phase, Position, canonical};

#[derive(Clone, Copy)]
enum Behavior {
    Accept,
    NoEffect,
    Uncertain,
    WrongAcknowledgement,
    CommitPending,
    StagingOnly,
}

#[derive(Default)]
struct Buffer {
    calls: usize,
    original: Option<RuntimeInputBatch>,
    acknowledgement: Option<NativeInputAcknowledgement>,
    commit_calls: usize,
    original_commit: Option<crate::node_scheduling::InputCustodyCommit>,
    native_commit_consumed: bool,
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

    fn commit_input_custody(
        &mut self,
        commit: &crate::node_scheduling::InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        if !matches!(self.behavior, Behavior::CommitPending) {
            return Ok(());
        }
        let mut buffer = self.buffer.borrow_mut();
        buffer.commit_calls += 1;
        if let Some(original) = &buffer.original_commit {
            assert!(original.activation().same_authority(commit.activation()));
            assert_eq!(original.node(), commit.node());
            assert_eq!(original.stage_operation(), commit.stage_operation());
            assert_eq!(original.batch(), commit.batch());
            assert_eq!(original.inventory(), commit.inventory());
            assert_eq!(original.cutoff(), commit.cutoff());
        } else {
            buffer.original_commit = Some(commit.retained_copy());
        }
        if !buffer.native_commit_consumed {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "same original native commit acknowledgement remains pending".into(),
            });
        }
        Ok(())
    }

    fn validate_input_custody_commit(
        &self,
        commit: &crate::node_scheduling::InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        if !matches!(self.behavior, Behavior::CommitPending) {
            return Ok(());
        }
        let buffer = self.buffer.borrow();
        if !buffer.native_commit_consumed
            || buffer.original_commit.as_ref().is_none_or(|original| {
                !original.activation().same_authority(commit.activation())
                    || original.node() != commit.node()
                    || original.stage_operation() != commit.stage_operation()
                    || original.batch() != commit.batch()
                    || original.inventory() != commit.inventory()
                    || original.cutoff() != commit.cutoff()
            })
        {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "original native consumed-commit journal is unavailable".into(),
            });
        }
        Ok(())
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

// An external adapter can prove retained staging without implementing the
// separate commit transition. Both new trait defaults must keep it closed.
struct StagingOnlyNode(InputNode);

impl SimulationNode for StagingOnlyNode {
    fn descriptor(&self) -> &NodeDescriptor {
        self.0.descriptor()
    }
    fn binding(&self) -> &NodeBinding {
        self.0.binding()
    }
    fn route(&self) -> &NodeRoute {
        self.0.route()
    }
    fn thread_affinity(&self) -> ThreadAffinity {
        self.0.thread_affinity()
    }
    fn facets(&self) -> &[FacetKind] {
        self.0.facets()
    }
    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        self.0.status()
    }
    fn arm(&mut self, record: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        self.0.arm(record)
    }
    fn validate_readiness(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.0.validate_readiness(record, ready)
    }
    fn begin_operation(&mut self, operation: &OperationAdmission) -> Submission {
        self.0.begin_operation(operation)
    }
    fn poll_operation(
        &mut self,
        token: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        self.0.poll_operation(token, context)
    }
    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.0.validate_outcome(original, outcome)
    }
    fn request_cancel(&mut self, token: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        self.0.request_cancel(token)
    }
    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission {
        self.0.close_quantum(original)
    }
    fn acknowledge_publication(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        self.0.acknowledge_publication(token, outputs)
    }
    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        self.0.facet(kind)
    }
    fn quarantine_resources(&mut self) {
        self.0.quarantine_resources();
    }
    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        self.0.poll_reclamation(owner, context)
    }
    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        self.0.validate_reclamation(receipt)
    }

    fn stage_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.0.stage_inputs(batch)
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &RuntimeInputBatch,
        acknowledgement: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        self.0
            .validate_input_acknowledgement(batch, acknowledgement)
    }
}

fn fixture(behavior: Behavior) -> (super::NodeRuntime, WorldActivation, Rc<RefCell<Buffer>>) {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let mut nodes = crate::node_contract::test_nodes(&graph);
    let buffer = Rc::new(RefCell::new(Buffer::default()));
    let original = nodes.remove(0);
    let input = InputNode {
        inner: original,
        buffer: Rc::clone(&buffer),
        behavior,
    };
    let input: Box<dyn SimulationNode> = if matches!(behavior, Behavior::StagingOnly) {
        Box::new(StagingOnlyNode(input))
    } else {
        Box::new(input)
    };
    nodes.insert(0, input);
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

fn observed_admission(runtime: &NodeRuntime, original: &RuntimeInputBatch) -> OperationAdmission {
    OperationAdmission {
        token: OperationToken {
            authority: Rc::clone(&runtime.authority),
            operation: Id::new("observed-completion").unwrap(),
            route: runtime.nodes[original.node()].route().clone(),
        },
        activation: original.activation().clone(),
        request: OperationRequest::BoundarySettle {
            start: original.cutoff(),
            limit: Position::new(1.into(), 0.into(), Phase::Reaction),
        },
        inputs: Some(Rc::new(original.retained_copy())),
    }
}

#[test]
fn original_stage_projection_borrows_native_ack_without_restage_or_commit() {
    let (mut runtime, activation, buffer) = fixture(Behavior::Accept);
    let original = batch(&runtime, &activation, "stage/a", "batch/a");
    let admission = observed_admission(&runtime, &original);
    runtime.stage_inputs(original).unwrap();

    let view = runtime
        .observe_original_staged_input(&admission)
        .unwrap()
        .unwrap();
    let retained = &runtime.input_batches[&Id::new("stage/a").unwrap()];
    assert!(std::ptr::eq(view.batch(), &retained.batch));
    assert!(std::ptr::eq(
        view.acknowledgement(),
        retained.acknowledgement.as_ref().unwrap()
    ));
    assert!(view.provenance().is_none());
    assert!(view.lineage().is_none());
    assert!(view.coordinator_commit().is_none());
    assert!(!view.committed());
    assert_eq!(buffer.borrow().calls, 1);
    assert!(!retained.committed);
}

#[test]
fn original_stage_projection_refuses_changed_scope_and_missing_ack() {
    let (mut runtime, activation, buffer) = fixture(Behavior::Accept);
    let original = batch(&runtime, &activation, "stage/a", "batch/a");
    let mut admission = observed_admission(&runtime, &original);
    runtime.stage_inputs(original).unwrap();
    let before = buffer.borrow().acknowledgement.clone();

    let mut changed = admission.inputs().unwrap().retained_copy();
    changed.inventory = canonical::content_ref(b"foreign", "application/json").unwrap();
    admission.inputs = Some(Rc::new(changed));
    assert!(matches!(
        runtime.observe_original_staged_input(&admission),
        Err(RuntimeError::ForeignAuthority)
    ));
    admission.inputs = Some(Rc::new(
        runtime.input_batches[&Id::new("stage/a").unwrap()]
            .batch
            .retained_copy(),
    ));
    runtime
        .input_batches
        .get_mut(&Id::new("stage/a").unwrap())
        .unwrap()
        .acknowledgement = None;
    assert!(matches!(
        runtime.observe_original_staged_input(&admission),
        Err(RuntimeError::OutstandingObligations)
    ));

    assert_eq!(buffer.borrow().calls, 1);
    assert_eq!(buffer.borrow().acknowledgement, before);
}

#[test]
fn original_stage_projection_preserves_refused_failure_custody() {
    let (mut runtime, activation, buffer) = fixture(Behavior::Uncertain);
    let original = batch(&runtime, &activation, "stage/a", "batch/a");
    let admission = observed_admission(&runtime, &original);
    assert!(runtime.stage_inputs(original).is_err());
    let before = runtime.input_batches[&Id::new("stage/a").unwrap()]
        .failure
        .clone();

    assert!(matches!(
        runtime.observe_original_staged_input(&admission),
        Err(RuntimeError::OutstandingObligations)
    ));
    assert_eq!(
        runtime.input_batches[&Id::new("stage/a").unwrap()].failure,
        before
    );
    assert_eq!(buffer.borrow().calls, 1);
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
        runtime.original_witness().original_error_site(&activation),
        Ok(Some("input/native-acknowledgement"))
    );
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
    assert_eq!(
        runtime.original_witness().original_error_site(&activation),
        Ok(Some("input/recovered-native-acknowledgement"))
    );
    assert_eq!(buffer.borrow().calls, 1);
}

#[test]
fn source_consumed_commit_blocks_grant_and_retry_preserves_original_stage() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let (mut runtime, activation, buffer) = fixture(Behavior::CommitPending);
    let node = Id::new("a").unwrap();
    let stage = Id::new("stage/native-commit").unwrap();
    let batch = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .prepare_input_batch(
            &node,
            stage.clone(),
            Id::new("batch/native-commit").unwrap(),
            Position::new(1.into(), 0.into(), Phase::BoundaryControl),
        )
        .unwrap();
    let acknowledgement = runtime.stage_inputs(batch).unwrap();
    let commit = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();

    assert!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .admit_exact(&node, Id::new("run/before-commit").unwrap(), 10.into())
            .is_err()
    );
    assert!(matches!(
        runtime.commit_input_staging(&commit),
        Err(RuntimePollFailure::Native(OperationFailure {
            effects: EffectKnowledge::None,
            ..
        }))
    ));
    assert!(!runtime.input_batches[&stage].committed);
    assert_eq!(
        runtime.owners[&Id::new("owner/a").unwrap()]
            .operation
            .as_ref(),
        Some(&stage)
    );
    assert_eq!(buffer.borrow().calls, 1);
    assert_eq!(buffer.borrow().commit_calls, 1);
    assert!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .admit_exact(&node, Id::new("run/pending-commit").unwrap(), 10.into())
            .is_err()
    );

    buffer.borrow_mut().native_commit_consumed = true;
    runtime.commit_input_staging(&commit).unwrap();
    runtime.commit_input_staging(&commit).unwrap();
    assert!(runtime.input_batches[&stage].committed);
    assert!(
        runtime.owners[&Id::new("owner/a").unwrap()]
            .operation
            .is_none()
    );
    assert_eq!(buffer.borrow().calls, 1);
    assert_eq!(buffer.borrow().commit_calls, 2);
    let grant = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&node, Id::new("run/after-commit").unwrap(), 10.into())
        .unwrap();
    assert!(runtime.begin_admitted(grant).is_ok());
}

#[test]
fn capture_preserves_pending_and_consumed_commit_and_rejects_cross_state_restore() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let (mut runtime, activation, buffer) = fixture(Behavior::CommitPending);
    let node = Id::new("a").unwrap();
    let stage = Id::new("stage/capture-commit").unwrap();
    let batch = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .prepare_input_batch(
            &node,
            stage.clone(),
            Id::new("batch/capture-commit").unwrap(),
            Position::new(1.into(), 0.into(), Phase::BoundaryControl),
        )
        .unwrap();
    let acknowledgement = runtime.stage_inputs(batch).unwrap();
    let commit = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();
    assert!(runtime.commit_input_staging(&commit).is_err());
    let cut = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
    let pending_runtime = runtime
        .runtime_snapshot(cut, 1.into(), 1024 * 1024)
        .unwrap();
    let pending_scheduler = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .snapshot(cut, 1.into())
        .unwrap();
    assert_eq!(pending_scheduler.input_batches[0].custody_edition, Some(1));
    assert!(!pending_scheduler.input_batches[0].consumer_committed);
    PreparedRuntimeRestore::validate_source(
        &graph,
        &pending_scheduler,
        &pending_runtime,
        RuntimeLimits::default(),
        1024 * 1024,
    )
    .unwrap();

    // A source-consumed bit is historical data, never proof. Source preflight
    // requires runtime and scheduler knowledge to agree before native install.
    let mut forged = pending_scheduler.clone();
    forged.input_batches[0].consumer_committed = true;
    assert!(
        PreparedRuntimeRestore::validate_source(
            &graph,
            &forged,
            &pending_runtime,
            RuntimeLimits::default(),
            1024 * 1024
        )
        .is_err()
    );

    buffer.borrow_mut().native_commit_consumed = true;
    runtime.commit_input_staging(&commit).unwrap();
    let consumed_runtime = runtime
        .runtime_snapshot(cut, 2.into(), 1024 * 1024)
        .unwrap();
    let consumed_scheduler = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .snapshot(cut, 2.into())
        .unwrap();
    assert!(consumed_scheduler.input_batches[0].consumer_committed);
    PreparedRuntimeRestore::validate_source(
        &graph,
        &consumed_scheduler,
        &consumed_runtime,
        RuntimeLimits::default(),
        1024 * 1024,
    )
    .unwrap();
    let mut forgotten = consumed_scheduler.clone();
    forgotten.input_batches[0].consumer_committed = false;
    assert!(
        PreparedRuntimeRestore::validate_source(
            &graph,
            &forgotten,
            &consumed_runtime,
            RuntimeLimits::default(),
            1024 * 1024
        )
        .is_err()
    );
    let mut legacy = consumed_scheduler;
    legacy.input_batches[0].custody_edition = None;
    assert!(crate::node_scheduling::validate_saved_source(&graph, &legacy).is_err());

    assert_eq!(buffer.borrow().calls, 1);
    assert_eq!(buffer.borrow().commit_calls, 2);
}

#[test]
fn authenticated_staging_ack_without_commit_implementation_cannot_grant_or_capture_consumed() {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let (mut runtime, activation, buffer) = fixture(Behavior::StagingOnly);
    let node = Id::new("a").unwrap();
    let stage = Id::new("stage/unimplemented-commit").unwrap();
    let batch = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .prepare_input_batch(
            &node,
            stage.clone(),
            Id::new("batch/unimplemented-commit").unwrap(),
            Position::new(1.into(), 0.into(), Phase::BoundaryControl),
        )
        .unwrap();
    let acknowledgement = runtime.stage_inputs(batch).unwrap();
    let commit = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();

    assert!(
        runtime.nodes[&node]
            .validate_input_custody_commit(&commit)
            .is_err()
    );
    assert!(matches!(
        runtime.commit_input_staging(&commit),
        Err(RuntimePollFailure::Native(OperationFailure {
            effects: EffectKnowledge::None,
            ..
        }))
    ));
    assert!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .admit_exact(
                &node,
                Id::new("run/unimplemented-commit").unwrap(),
                10.into()
            )
            .is_err()
    );
    assert!(!runtime.input_batches[&stage].committed);
    assert_eq!(
        runtime.owners[&Id::new("owner/a").unwrap()]
            .operation
            .as_ref(),
        Some(&stage)
    );
    assert_eq!(buffer.borrow().calls, 1);
    assert_eq!(buffer.borrow().commit_calls, 0);

    let cut = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
    let saved_runtime = runtime
        .runtime_snapshot(cut, 1.into(), 1024 * 1024)
        .unwrap();
    let saved_scheduler = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .snapshot(cut, 1.into())
        .unwrap();
    assert!(!saved_scheduler.input_batches[0].consumer_committed);
    PreparedRuntimeRestore::validate_source(
        &graph,
        &saved_scheduler,
        &saved_runtime,
        RuntimeLimits::default(),
        1024 * 1024,
    )
    .unwrap();
}
