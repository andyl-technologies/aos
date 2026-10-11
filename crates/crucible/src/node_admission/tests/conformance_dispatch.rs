//! Models the last collecting-source read after native getters and before dispatch.
//!
//! Empty input acknowledgements and scheduling observations are explicit models.
//! These controls prove callback ordering and original custody, not native classes.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These explicit dispatch models panic when original getter ordering or retained custody differs.

use super::*;
use crate::node_scheduling::{
    NativeInputAcknowledgement, NativeOutputBound, NativeProducerBound,
    NativeSchedulingObservation, RuntimeInputBatch,
};
use std::task::Waker;

#[derive(Default)]
pub(in super::super) struct Probe {
    pub(super) validations: Cell<usize>,
    getter_after: Cell<Option<usize>>,
    facet_revoke: Cell<bool>,
    revoked_getters: Cell<usize>,
    pub(super) begin: Cell<usize>,
    pub(super) stage: Cell<usize>,
    pub(super) poll: Cell<usize>,
    pub(super) close: Cell<usize>,
    pub(super) ack: Cell<usize>,
}

impl Probe {
    pub(super) fn getter(&self, authority: &Authority) {
        if self
            .getter_after
            .get()
            .is_some_and(|after| self.validations.get() >= after)
        {
            self.getter_after.set(None);
            self.revoke(authority);
        }
    }

    pub(super) fn facet(&self, authority: &Authority) {
        if self.facet_revoke.replace(false) {
            self.revoke(authority);
        }
    }

    fn revoke(&self, authority: &Authority) {
        self.revoked_getters.set(self.revoked_getters.get() + 1);
        authority
            .native_current
            .borrow()
            .as_ref()
            .unwrap()
            .set(false);
    }
}

pub(super) fn model_ack(batch: &RuntimeInputBatch) -> NativeInputAcknowledgement {
    NativeInputAcknowledgement {
        stage_operation: batch.stage_operation().clone(),
        batch: batch.batch().clone(),
        node: batch.node().clone(),
        owners: batch.owners().to_vec(),
        cutoff: batch.cutoff(),
        inventory: batch.inventory().clone(),
        proof_ref: canonical::content_ref(b"empty model input custody", "application/octet-stream")
            .unwrap(),
    }
}

pub(super) fn attach_model_scheduling(outcome: &mut OperationOutcome, authority: &Authority) {
    let reached = match &outcome.progress {
        ProgressEvidence::Exact { reached, .. } => *reached,
        _ => return,
    };
    let proof = authority.fixture.ownership.inventory_proof_ref.clone();
    outcome.scheduling = Some(NativeSchedulingObservation {
        node: outcome.node.clone(),
        owners: outcome.owners.clone(),
        reached,
        closed_prefix: reached,
        bounds: vec![NativeProducerBound {
            producer: outcome.node.clone(),
            bound: NativeOutputBound::AfterInstant(reached.time_ps),
            proof_ref: proof.clone(),
        }],
        publications: vec![],
        input_progress: None,
        external_inputs: vec![],
        proof_ref: proof,
    });
}

fn execution_authority(quantized: bool) -> Rc<Authority> {
    let mut authority = initial_authority();
    let original = Rc::get_mut(&mut authority).unwrap();
    original.fixture = super::super::super::execution_fixture(false, true);
    if quantized {
        let proof = original.fixture.ownership.inventory_proof_ref.clone();
        let policy =
            original
                .fixture
                .evidence
                .put(&crate::node_scheduling::ExecutionPolicy::Quantized {
                    schema_version: 1,
                    quantum_ps: U64::new(100),
                    phase_ps: U64::new(0),
                    host_budget_ns: U64::new(1_000_000_000),
                    window_proof_ref: proof,
                });
        for binding in &mut original.fixture.bindings {
            binding.compatibility.operating_contract.mode = OperatingMode::Quantized;
            binding.compatibility.operating_contract.policy_ref = policy.clone();
        }
        original.fixture.requirements.accepted_quantized_nodes = original
            .fixture
            .descriptors
            .iter()
            .map(|node| node.id.clone())
            .collect();
        original.fixture.refresh();
        original.authorized_quantized.set(true);
    }
    *authority.native_current.borrow_mut() = Some(Rc::new(Cell::new(true)));
    authority
}

fn activated(
    authority: &Rc<Authority>,
    quantized: bool,
) -> (ConformanceRuntime, Rc<RefCell<Vec<WholeRuntimeCustody>>>) {
    let (mut runtime, custody) = runtime_with_mode(
        authority,
        authority.native_current.borrow().as_ref().unwrap().clone(),
        Rc::new(Cell::new(false)),
        quantized,
    );
    let mut publisher = publisher(authority.clone());
    runtime
        .activate_initial(&mut publisher, 16 * 1024 * 1024)
        .unwrap();
    assert_eq!(publisher.published, 1);
    (runtime, custody)
}

fn exact_token(runtime: &mut ConformanceRuntime, authority: &Authority) -> OperationToken {
    match runtime
        .begin_exact(
            &authority.fixture.descriptors[0].id,
            id("original/model-case"),
            U64::new(1),
        )
        .unwrap()
    {
        BeginResult::Accepted(token) => token,
        _ => panic!("model original grant must be accepted"),
    }
}

fn assert_revoked_original(
    authority: &Rc<Authority>,
    custody: &Rc<RefCell<Vec<WholeRuntimeCustody>>>,
    operations: usize,
    inputs: usize,
) {
    assert_eq!(authority.dispatch.revoked_getters.get(), 1);
    assert!(authority.current.get());
    assert!(authority.world_current.get());
    assert!(authority.node_current.get());
    assert!(authority.plan().reauthenticate().is_ok());
    assert!(!authority.native_current.borrow().as_ref().unwrap().get());
    let retained = custody.borrow();
    assert_eq!(retained.len(), 1);
    assert_eq!(
        retained[0].native_handle_count(),
        authority.fixture.descriptors.len()
    );
    assert_eq!(retained[0].operation_count(), operations);
    assert_eq!(retained[0].input_batch_count(), inputs);
}

#[test]
fn acquired_facet_revocation_refuses_before_original_native_begin() {
    let authority = execution_authority(false);
    let (mut runtime, custody) = activated(&authority, false);
    authority.dispatch.facet_revoke.set(true);

    assert!(
        runtime
            .begin_exact(
                &authority.fixture.descriptors[0].id,
                id("original/model-case"),
                U64::new(1)
            )
            .is_err()
    );
    assert_eq!(authority.dispatch.begin.get(), 0);

    drop(runtime);
    assert_revoked_original(&authority, &custody, 0, 0);
}

#[test]
fn staged_route_getter_revocation_refuses_before_original_native_stage() {
    let authority = execution_authority(true);
    let (mut runtime, custody) = activated(&authority, true);
    // Both wrapper custody checks have finished when generic Stage reads its route.
    authority.dispatch.getter_after.set(Some(
        authority.dispatch.validations.get() + 2 * authority.fixture.descriptors.len(),
    ));

    assert!(
        runtime
            .stage_quantized_inputs(
                &authority.fixture.descriptors[0].id,
                id("original/model-stage"),
                id("original/model-batch"),
                Position::new(U64::new(1), U64::new(0), Phase::BoundaryControl),
            )
            .is_err()
    );
    assert_eq!(authority.dispatch.stage.get(), 0);
    assert_eq!(authority.dispatch.begin.get(), 0);

    drop(runtime);
    assert_revoked_original(&authority, &custody, 0, 0);
}

#[test]
fn pending_original_poll_getter_revocation_retains_token_without_native_poll() {
    let authority = execution_authority(false);
    let (mut runtime, custody) = activated(&authority, false);
    let token = exact_token(&mut runtime, &authority);
    authority
        .dispatch
        .getter_after
        .set(Some(authority.dispatch.validations.get()));
    let mut context = Context::from_waker(Waker::noop());

    assert!(matches!(
        runtime.poll(&token, &mut context),
        Poll::Ready(Err(_))
    ));
    assert_eq!(authority.dispatch.begin.get(), 1);
    assert_eq!(authority.dispatch.poll.get(), 0);

    drop(runtime);
    assert_revoked_original(&authority, &custody, 1, 0);
}

#[test]
fn pending_original_close_getter_revocation_retains_window_without_native_close() {
    let authority = execution_authority(true);
    let (mut runtime, custody) = activated(&authority, true);
    let node = &authority.fixture.descriptors[0].id;
    runtime
        .stage_quantized_inputs(
            node,
            id("original/model-stage"),
            id("original/model-batch"),
            Position::new(U64::new(1), U64::new(0), Phase::BoundaryControl),
        )
        .unwrap();
    let token = match runtime
        .begin_quantized(
            node,
            id("original/model-case"),
            id("original/model-window"),
            id("original/model-batch"),
        )
        .unwrap()
    {
        BeginResult::Accepted(token) => token,
        _ => panic!("same staged model window must begin once"),
    };
    authority
        .dispatch
        .getter_after
        .set(Some(authority.dispatch.validations.get()));

    assert!(runtime.close_quantum(&token).is_err());
    assert_eq!(authority.dispatch.stage.get(), 1);
    assert_eq!(authority.dispatch.begin.get(), 1);
    assert_eq!(authority.dispatch.close.get(), 0);

    drop(runtime);
    assert_revoked_original(&authority, &custody, 1, 1);
}

struct ResultPublisher {
    authority: Rc<Authority>,
    calls: usize,
}

impl ConformanceResultPublisher for ResultPublisher {
    fn publish_original(
        &mut self,
        _: ConformancePlanEvidence<'_>,
        original: &OriginalCompletedOperation<'_>,
    ) -> Result<PublicationStatus, RuntimeError> {
        assert_eq!(
            original.admission().token().operation(),
            &id("original/model-case")
        );
        self.calls += 1;
        self.authority
            .dispatch
            .getter_after
            .set(Some(self.authority.dispatch.validations.get()));
        // This is a publication-order model, not durable native body authentication.
        Ok(PublicationStatus::Committed)
    }
}

#[test]
fn completed_original_ack_getter_revocation_retains_result_without_native_ack() {
    let authority = execution_authority(false);
    let (mut runtime, custody) = activated(&authority, false);
    let token = exact_token(&mut runtime, &authority);
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        runtime.poll(&token, &mut context),
        Poll::Ready(Ok(_))
    ));
    let mut publisher = ResultPublisher {
        authority: authority.clone(),
        calls: 0,
    };

    assert!(
        runtime
            .publish_and_acknowledge(&token, &mut publisher)
            .is_err()
    );
    assert_eq!(publisher.calls, 1);
    assert_eq!(authority.dispatch.begin.get(), 1);
    assert_eq!(authority.dispatch.poll.get(), 1);
    assert_eq!(authority.dispatch.ack.get(), 0);

    drop(runtime);
    assert_revoked_original(&authority, &custody, 1, 0);
}
