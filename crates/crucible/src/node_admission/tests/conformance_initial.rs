//! Models actual initial extraction ordering under retained collection custody.
//!
//! The native participant is an explicit model, not a provider/class witness.
//! Publisher refusals retain the same preparation set without ordinary authority.

#![cfg(test)]

use super::*;
use crate::node_contract::*;
use crate::node_scheduling::InputPayload;
use std::{
    cell::RefCell,
    task::{Context, Poll},
};

#[path = "conformance_dispatch.rs"]
pub(super) mod dispatch;

struct CollectionNode {
    native: Box<dyn SimulationNode>,
    plan: InstalledConformancePlan,
    initial_current: Rc<Cell<bool>>,
    scope_revoke: Rc<Cell<bool>>,
    authority: Rc<Authority>,
}

impl SimulationNode for CollectionNode {
    fn collection_scope(&self) -> Option<&InstalledConformancePlan> {
        Some(&self.plan)
    }

    fn validate_collection_scope(
        &self,
        plan: &InstalledConformancePlan,
    ) -> Result<(), OperationFailure> {
        if !self.plan.same_original(plan) || plan.reauthenticate().is_err() {
            return Err(native_refusal());
        }
        self.authority
            .dispatch
            .validations
            .set(self.authority.dispatch.validations.get() + 1);
        if self.scope_revoke.replace(false) {
            self.authority.current.set(false);
        }
        Ok(())
    }

    fn prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<crucible_node_contract::PreparedOwner>>, OperationFailure> {
        self.native.validate_readiness(world, ready)?;
        Ok(Some(
            ready
                .owners
                .iter()
                .map(|owner| crucible_node_contract::PreparedOwner {
                    owner_id: owner.owner.clone(),
                    incarnation_id: owner.incarnation.clone(),
                    owner_generation: owner.generation,
                    prepared_token: id("initial/model-owner-preparation"),
                    binding_hashes: vec![self.binding().identity().unwrap()],
                    ready_receipt: ready.ready_receipt.clone(),
                    extensions: Extensions::new(),
                })
                .collect(),
        ))
    }

    fn validate_prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[crucible_node_contract::PreparedOwner],
    ) -> Result<(), OperationFailure> {
        if self.prepared_owners(world, ready)?.as_deref() != Some(owners) {
            return Err(native_refusal());
        }
        Ok(())
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if !self.initial_current.get() {
            return Err(native_refusal());
        }
        self.native.validate_readiness(world, ready)
    }

    fn descriptor(&self) -> &NodeDescriptor {
        self.authority.dispatch.getter(&self.authority);
        self.native.descriptor()
    }

    fn binding(&self) -> &NodeBinding {
        self.authority.dispatch.getter(&self.authority);
        self.native.binding()
    }

    fn route(&self) -> &NodeRoute {
        self.native.route()
    }

    fn thread_affinity(&self) -> ThreadAffinity {
        self.native.thread_affinity()
    }

    fn facets(&self) -> &[FacetKind] {
        if self.native.binding().compatibility.operating_contract.mode == OperatingMode::Quantized {
            &[FacetKind::QuantizedExecution]
        } else {
            self.native.facets()
        }
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        self.native.status()
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        self.native.arm(world)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.native.validate_readiness(world, ready)
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        self.authority
            .dispatch
            .begin
            .set(self.authority.dispatch.begin.get() + 1);
        self.native.begin_operation(admission)
    }

    fn poll_operation(
        &mut self,
        token: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        self.authority
            .dispatch
            .poll
            .set(self.authority.dispatch.poll.get() + 1);
        let result = self.native.poll_operation(token, context);
        match result {
            Poll::Ready(Ok(mut outcome)) => {
                dispatch::attach_model_scheduling(&mut outcome, &self.authority);
                Poll::Ready(Ok(outcome))
            }
            other => other,
        }
    }

    fn validate_outcome(
        &self,
        admission: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.native.validate_outcome(admission, outcome)
    }

    fn request_cancel(&mut self, token: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        self.native.request_cancel(token)
    }

    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission {
        self.authority
            .dispatch
            .close
            .set(self.authority.dispatch.close.get() + 1);
        self.native.close_quantum(original)
    }

    fn acknowledge_publication(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        self.authority
            .dispatch
            .ack
            .set(self.authority.dispatch.ack.get() + 1);
        self.native.acknowledge_publication(token, outputs)
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        self.authority.dispatch.facet(&self.authority);
        if kind == FacetKind::QuantizedExecution
            && self.native.binding().compatibility.operating_contract.mode
                == OperatingMode::Quantized
        {
            Ok(NodeFacet::QuantizedExecution(self))
        } else {
            self.native.facet(kind)
        }
    }

    fn stage_inputs(
        &mut self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<crate::node_scheduling::NativeInputAcknowledgement, OperationFailure> {
        self.authority
            .dispatch
            .stage
            .set(self.authority.dispatch.stage.get() + 1);
        Ok(dispatch::model_ack(batch))
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
        ack: &crate::node_scheduling::NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        if batch.deliveries().is_empty()
            && batch.payloads().is_empty()
            && ack == &dispatch::model_ack(batch)
        {
            Ok(())
        } else {
            Err(native_refusal())
        }
    }

    fn quarantine_resources(&mut self) {
        self.native.quarantine_resources()
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        self.native.poll_reclamation(owner, context)
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        self.native.validate_reclamation(receipt)
    }
}

fn native_refusal() -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: "original model source changed".into(),
    }
}

struct Slot(Rc<RefCell<Vec<WholeRuntimeCustody>>>);

impl RuntimeCustodySlot for Slot {
    fn validate_world(&self, _: &ActivationRecord, _: RuntimeLimits) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn retain(self: Box<Self>, custody: WholeRuntimeCustody) {
        let mut retained = self.0.borrow_mut();
        assert!(retained.is_empty());
        assert_eq!(retained.capacity(), 1);
        retained.push(custody);
    }
}

struct Publisher {
    authority: Rc<Authority>,
    retained: usize,
    published: usize,
    revoke: bool,
    revoke_prepare: bool,
    revoke_publish: bool,
    prepared: usize,
    refuse: bool,
    original: Option<InputPayload>,
}

impl ActivationPublisher for Publisher {
    fn retain_initial_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: Vec<ValidatedNodePreparation>,
        body: InputPayload,
    ) -> Result<(), RuntimeError> {
        assert_eq!(nodes.len(), self.authority.fixture.descriptors.len());
        body.reference.verify(&body.bytes).unwrap();
        let object = canonical::parse_json(&body.bytes, 16 * 1024 * 1024).unwrap();
        assert_eq!(
            object["activation"],
            serde_json::to_value(SavedRuntimeActivation::from(record)).unwrap()
        );
        assert_eq!(
            object["preparations"],
            serde_json::to_value(&nodes).unwrap()
        );
        self.original = Some(body);
        self.retained += 1;
        if self.revoke {
            self.authority.current.set(false);
        }
        if self.refuse {
            return Err(RuntimeError::PublicationFailed);
        }
        Ok(())
    }

    fn prepare_coordinator(
        &mut self,
        _: &ActivationRecord,
        _: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        self.prepared += 1;
        if self.revoke_prepare {
            self.authority.current.set(false);
        }
        Ok(self.original.as_ref().unwrap().clone())
    }

    fn publish_complete(
        &mut self,
        _: &ActivationRecord,
        _: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.published += 1;
        if self.revoke_publish {
            self.authority.current.set(false);
        }
        PublicationStatus::Committed
    }

    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        self.published += 1;
        PublicationStatus::Committed
    }

    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::NotCommitted
    }
}

fn runtime(
    authority: &Rc<Authority>,
    current: Rc<Cell<bool>>,
) -> (ConformanceRuntime, Rc<RefCell<Vec<WholeRuntimeCustody>>>) {
    runtime_with_scope(authority, current, Rc::new(Cell::new(false)))
}

fn runtime_with_scope(
    authority: &Rc<Authority>,
    current: Rc<Cell<bool>>,
    scope_revoke: Rc<Cell<bool>>,
) -> (ConformanceRuntime, Rc<RefCell<Vec<WholeRuntimeCustody>>>) {
    runtime_with_mode(authority, current, scope_revoke, false)
}

fn runtime_with_mode(
    authority: &Rc<Authority>,
    current: Rc<Cell<bool>>,
    scope_revoke: Rc<Cell<bool>>,
    quantized: bool,
) -> (ConformanceRuntime, Rc<RefCell<Vec<WholeRuntimeCustody>>>) {
    let plan = authority.plan();
    let graph =
        admit_conformance_graph(authority.request(), &plan, AdmissionLimits::default()).unwrap();
    let nodes = crate::node_contract::test_nodes(&graph.graph)
        .into_iter()
        .map(|native| {
            Box::new(CollectionNode {
                native,
                plan: plan.retained(),
                initial_current: current.clone(),
                scope_revoke: scope_revoke.clone(),
                authority: authority.clone(),
            }) as Box<dyn SimulationNode>
        })
        .collect::<Vec<_>>();
    let owners = nodes
        .iter()
        .flat_map(|node| node.route().owners.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let retained = Rc::new(RefCell::new(Vec::with_capacity(1)));
    let record = ActivationRecord {
        generation: U64::new(1),
        activation_id: id("original-initial-model"),
        world_binding_hash: graph.world().identity().unwrap(),
        owners,
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
    };
    let prepared = PreparedRealization::new(
        nodes,
        record,
        RuntimeLimits::default(),
        Box::new(Slot(retained.clone())),
    );
    let prepared_runtime = if quantized {
        ConformanceRuntime::from_prepared_quantized(graph, prepared)
    } else {
        ConformanceRuntime::from_prepared(graph, prepared)
    };
    let mut runtime = prepared_runtime
        .unwrap_or_else(|failure| panic!("initial model construction refused: {}", failure.reason));
    runtime.arm_all().unwrap();
    (runtime, retained)
}

fn initial_authority() -> Rc<Authority> {
    let mut authority = Authority::new();
    let original = Rc::get_mut(&mut authority).unwrap();
    for descriptor in &mut original.fixture.descriptors {
        descriptor.ports.clear();
    }
    original.fixture.world.connections.clear();
    original.fixture.coordinator.external_inputs.clear();
    original.fixture.refresh();
    authority
}

fn publisher(authority: Rc<Authority>) -> Publisher {
    Publisher {
        authority,
        retained: 0,
        published: 0,
        revoke: false,
        revoke_prepare: false,
        revoke_publish: false,
        prepared: 0,
        refuse: false,
        original: None,
    }
}

fn retained_ready(custody: &Rc<RefCell<Vec<WholeRuntimeCustody>>>, nodes: usize) {
    let original = custody.borrow();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].native_handle_count(), nodes);
    assert_eq!(original[0].node_preparations().len(), nodes);
    assert_eq!(original[0].operation_count(), 0);
    assert!(original[0].publication_status().is_none());
}

#[test]
fn callback_revocation_cannot_activate_after_original_coordinator_retention() {
    let authority = initial_authority();
    let nodes = authority.fixture.descriptors.len();
    let (mut runtime, custody) = runtime(&authority, Rc::new(Cell::new(true)));
    let mut publisher = publisher(authority.clone());
    publisher.revoke = true;
    assert!(
        runtime
            .activate_initial(&mut publisher, 16 * 1024 * 1024)
            .is_err()
    );
    assert_eq!(publisher.retained, 1);
    assert_eq!(publisher.published, 0);
    assert!(publisher.original.is_some());
    drop(runtime);
    retained_ready(&custody, nodes);
}

#[test]
fn failed_publisher_keeps_same_original_ready_set_without_activation() {
    let authority = initial_authority();
    let nodes = authority.fixture.descriptors.len();
    let (mut runtime, custody) = runtime(&authority, Rc::new(Cell::new(true)));
    let mut publisher = publisher(authority);
    publisher.refuse = true;
    assert!(
        runtime
            .activate_initial(&mut publisher, 16 * 1024 * 1024)
            .is_err()
    );
    assert_eq!(publisher.retained, 1);
    assert_eq!(publisher.published, 0);
    drop(runtime);
    retained_ready(&custody, nodes);
}

#[test]
fn tiny_coordinator_credit_refuses_before_publisher_with_original_custody() {
    let authority = initial_authority();
    let nodes = authority.fixture.descriptors.len();
    let (mut runtime, custody) = runtime(&authority, Rc::new(Cell::new(true)));
    let mut publisher = publisher(authority);
    assert!(runtime.activate_initial(&mut publisher, 1).is_err());
    assert_eq!(publisher.retained, 0);
    assert_eq!(publisher.published, 0);
    drop(runtime);
    retained_ready(&custody, nodes);
}

#[test]
fn stale_native_initial_scope_refuses_before_any_publisher_effect() {
    let authority = initial_authority();
    let nodes = authority.fixture.descriptors.len();
    let current = Rc::new(Cell::new(true));
    let (mut runtime, custody) = runtime(&authority, current.clone());
    current.set(false);
    let mut publisher = publisher(authority);
    assert!(
        runtime
            .activate_initial(&mut publisher, 16 * 1024 * 1024)
            .is_err()
    );
    assert_eq!(publisher.retained, 0);
    assert_eq!(publisher.published, 0);
    drop(runtime);
    retained_ready(&custody, nodes);
}

#[test]
fn coordinator_preparation_revocation_refuses_before_durable_publish() {
    let authority = initial_authority();
    let nodes = authority.fixture.descriptors.len();
    let (mut runtime, custody) = runtime(&authority, Rc::new(Cell::new(true)));
    let mut publisher = publisher(authority);
    publisher.revoke_prepare = true;

    assert!(
        runtime
            .activate_initial(&mut publisher, 16 * 1024 * 1024)
            .is_err()
    );
    assert_eq!(publisher.retained, 1);
    assert_eq!(publisher.prepared, 1);
    assert_eq!(publisher.published, 0);

    drop(runtime);
    retained_ready(&custody, nodes);
}

#[test]
fn native_scope_callback_revocation_refuses_before_retention() {
    let authority = initial_authority();
    let nodes = authority.fixture.descriptors.len();
    let revoke = Rc::new(Cell::new(false));
    let (mut runtime, custody) =
        runtime_with_scope(&authority, Rc::new(Cell::new(true)), revoke.clone());
    let mut publisher = publisher(authority);
    revoke.set(true);

    assert!(
        runtime
            .activate_initial(&mut publisher, 16 * 1024 * 1024)
            .is_err()
    );
    assert_eq!(publisher.retained, 0);
    assert_eq!(publisher.prepared, 0);
    assert_eq!(publisher.published, 0);

    drop(runtime);
    retained_ready(&custody, nodes);
}

#[test]
fn committed_callback_revocation_retains_uncertain_original_without_activation() {
    let authority = initial_authority();
    let nodes = authority.fixture.descriptors.len();
    let (mut runtime, custody) = runtime(&authority, Rc::new(Cell::new(true)));
    let mut publisher = publisher(authority);
    publisher.revoke_publish = true;

    assert!(
        runtime
            .activate_initial(&mut publisher, 16 * 1024 * 1024)
            .is_err()
    );
    assert_eq!(publisher.retained, 1);
    assert_eq!(publisher.prepared, 1);
    assert_eq!(publisher.published, 1);

    drop(runtime);
    let original = custody.borrow();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].native_handle_count(), nodes);
    assert_eq!(original[0].node_preparations().len(), nodes);
    assert_eq!(
        original[0].publication_status(),
        Some(PublicationStatus::Unknown)
    );
    assert_eq!(original[0].operation_count(), 0);
}

#[test]
fn last_world_authority_callback_revocation_refuses_before_retention() {
    let authority = initial_authority();
    let nodes = authority.fixture.descriptors.len();
    let (mut runtime, custody) = runtime(&authority, Rc::new(Cell::new(true)));
    let mut publisher = publisher(authority.clone());
    authority.revoke_last_node.set(true);

    assert!(
        runtime
            .activate_initial(&mut publisher, 16 * 1024 * 1024)
            .is_err()
    );
    assert_eq!(publisher.retained, 0);
    assert_eq!(publisher.prepared, 0);
    assert_eq!(publisher.published, 0);

    drop(runtime);
    retained_ready(&custody, nodes);
}

#[test]
fn original_grant_callback_revocation_refuses_before_native_begin() {
    let mut authority = initial_authority();
    Rc::get_mut(&mut authority).unwrap().fixture = super::super::execution_fixture(false, true);
    let nodes = authority.fixture.descriptors.len();
    let node = authority.fixture.descriptors[0].id.clone();
    let (mut runtime, custody) = runtime(&authority, Rc::new(Cell::new(true)));
    let mut publisher = publisher(authority.clone());
    runtime
        .activate_initial(&mut publisher, 16 * 1024 * 1024)
        .unwrap();
    authority.revoke_operation.set(true);

    assert!(
        runtime
            .begin_exact(&node, id("original/model-case"), U64::new(1))
            .is_err()
    );
    assert!(!authority.current.get());
    drop(runtime);
    let original = custody.borrow();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].native_handle_count(), nodes);
    assert_eq!(original[0].operation_count(), 0);
    assert_eq!(original[0].input_batch_count(), 0);
}

#[test]
fn original_input_callback_revocation_refuses_before_native_stage() {
    let mut authority = initial_authority();
    Rc::get_mut(&mut authority).unwrap().fixture = super::super::execution_fixture(false, true);
    authority.authorized_quantized.set(true);
    let node = authority.fixture.descriptors[0].id.clone();
    let (mut runtime, custody) = runtime_with_mode(
        &authority,
        Rc::new(Cell::new(true)),
        Rc::new(Cell::new(false)),
        true,
    );
    let mut publisher = publisher(authority.clone());
    runtime
        .activate_initial(&mut publisher, 16 * 1024 * 1024)
        .unwrap();
    authority.revoke_inputs.set(true);

    let refused = runtime
        .stage_quantized_inputs(
            &node,
            id("original/model-stage"),
            id("original/model-batch"),
            Position::new(U64::new(1), U64::new(0), Phase::BoundaryControl),
        )
        .unwrap_err();
    assert!(
        matches!(refused, RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(message))
        if message == failure().message)
    );
    assert!(!authority.current.get());
    drop(runtime);
    let original = custody.borrow();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].operation_count(), 0);
    assert_eq!(original[0].input_batch_count(), 0);
}

#[test]
fn original_grant_world_revocation_refuses_with_live_plan() {
    original_grant_independent_revocation(0);
}

#[test]
fn original_grant_node_revocation_refuses_with_live_plan() {
    original_grant_independent_revocation(1);
}

#[test]
fn original_grant_native_revocation_refuses_with_live_plan() {
    original_grant_independent_revocation(2);
}

fn original_grant_independent_revocation(scope: usize) {
    let mut authority = initial_authority();
    Rc::get_mut(&mut authority).unwrap().fixture = super::super::execution_fixture(false, true);
    let node = authority.fixture.descriptors[0].id.clone();
    let native_current = Rc::new(Cell::new(true));
    *authority.native_current.borrow_mut() = Some(native_current.clone());
    let (mut runtime, custody) = runtime(&authority, native_current);
    let mut publisher = publisher(authority.clone());
    runtime
        .activate_initial(&mut publisher, 16 * 1024 * 1024)
        .unwrap();
    match scope {
        0 => authority.revoke_operation_world.set(true),
        1 => authority.revoke_operation_node.set(true),
        2 => authority.revoke_operation_native.set(true),
        _ => unreachable!(),
    }

    assert!(
        runtime
            .begin_exact(&node, id("original/model-case"), U64::new(1))
            .is_err()
    );
    assert!(authority.plan().reauthenticate().is_ok());
    assert!(authority.current.get());
    drop(runtime);
    let original = custody.borrow();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].operation_count(), 0);
    assert_eq!(original[0].input_batch_count(), 0);
}

#[test]
fn original_input_native_revocation_refuses_with_live_plan() {
    let mut authority = initial_authority();
    Rc::get_mut(&mut authority).unwrap().fixture = super::super::execution_fixture(false, true);
    authority.authorized_quantized.set(true);
    let node = authority.fixture.descriptors[0].id.clone();
    let native_current = Rc::new(Cell::new(true));
    *authority.native_current.borrow_mut() = Some(native_current.clone());
    let (mut runtime, custody) =
        runtime_with_mode(&authority, native_current, Rc::new(Cell::new(false)), true);
    let mut publisher = publisher(authority.clone());
    runtime
        .activate_initial(&mut publisher, 16 * 1024 * 1024)
        .unwrap();
    authority.revoke_inputs_native.set(true);

    assert!(
        runtime
            .stage_quantized_inputs(
                &node,
                id("original/model-stage"),
                id("original/model-batch"),
                Position::new(U64::new(1), U64::new(0), Phase::BoundaryControl),
            )
            .is_err()
    );
    assert!(authority.plan().reauthenticate().is_ok());
    assert!(authority.current.get());
    drop(runtime);
    let original = custody.borrow();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].operation_count(), 0);
    assert_eq!(original[0].input_batch_count(), 0);
}

impl FacetDescription for CollectionNode {
    fn profile(&self) -> &Id {
        &self
            .native
            .binding()
            .compatibility
            .operating_contract
            .facets[0]
            .id
    }
}
