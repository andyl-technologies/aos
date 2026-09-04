//! Bounded activation and reconciliation loop for the unprivileged node controller.
//!
//! The controller accepts one bounded candidate request at a time. An injected
//! compiler must prove endpoint-specific canonical encoding and owns parsing,
//! authentication, authorization, compare-and-swap checks, and desired/effect
//! planning. This module binds the endpoint scope into the request digest,
//! applies durable pending-work backpressure, and advances the existing
//! reconciler in fixed fair quanta.
//! It deliberately owns no signing key, privileged catalog, broker transport,
//! or volatile work queue.

use aos_sandbox_core::{
    BrokerAudience, ObjectDigest, OperationId, RawPairedClockSample, SandboxId,
};
use sha2::{Digest as _, Sha256};

use crate::{
    AcceptOutcome, AuthorityPublicationError, AuthorityPublicationStore, BrokerDispatchAttemptV1,
    OperationPlan, ReconcileOutcome, Reconciler, ReconcilerError, SingleNodeEffectExecutor,
};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-request.v1\0";
const MAXIMUM_ACTIVATION_BYTES: usize = 1024 * 1024;
const MAXIMUM_PENDING_OPERATIONS: usize = 1_000_000;
const MAXIMUM_RECONCILIATION_QUANTUM: usize = 4096;

/// Identifies one closed activated service method in request digests.
///
/// The value is a registry-assigned portable digest, not a socket path or
/// systemd unit name. Requests must separately include their normalized
/// principal, project, and semantic fields in the canonical request bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerRequestScopeV1(ObjectDigest);

impl ControllerRequestScopeV1 {
    /// Constructs a nonzero registry-assigned request scope.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError::InvalidConfiguration`] when the
    /// digest is all zeroes, which is reserved to detect missing configuration.
    pub fn new(digest: ObjectDigest) -> Result<Self, ControllerServiceError> {
        if digest.as_bytes() == &[0; 32] {
            return Err(ControllerServiceError::InvalidConfiguration);
        }
        Ok(Self(digest))
    }

    /// Returns the portable endpoint-scope digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Bounds synchronous admission and each reconciliation activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeControllerLimits {
    maximum_request_bytes: usize,
    maximum_pending_operations: usize,
    reconciliation_quantum: usize,
}

impl NodeControllerLimits {
    /// Constructs fixed controller work limits.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError::InvalidConfiguration`] when a value
    /// is zero or exceeds its V1 hard ceiling.
    pub fn new(
        maximum_request_bytes: usize,
        maximum_pending_operations: usize,
        reconciliation_quantum: usize,
    ) -> Result<Self, ControllerServiceError> {
        if maximum_request_bytes == 0
            || maximum_request_bytes > MAXIMUM_ACTIVATION_BYTES
            || maximum_pending_operations == 0
            || maximum_pending_operations > MAXIMUM_PENDING_OPERATIONS
            || reconciliation_quantum == 0
            || reconciliation_quantum > MAXIMUM_RECONCILIATION_QUANTUM
        {
            return Err(ControllerServiceError::InvalidConfiguration);
        }
        Ok(Self {
            maximum_request_bytes,
            maximum_pending_operations,
            reconciliation_quantum,
        })
    }
}

impl Default for NodeControllerLimits {
    fn default() -> Self {
        Self {
            maximum_request_bytes: MAXIMUM_ACTIVATION_BYTES,
            maximum_pending_operations: 65_536,
            reconciliation_quantum: 64,
        }
    }
}

/// Classifies an endpoint compiler rejection without reflecting private detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OperationCompilationError {
    /// Canonical request bytes do not satisfy the endpoint schema.
    #[error("activated controller request is malformed")]
    Malformed,
    /// Authentication, authorization, preconditions, or policy reject it.
    #[error("activated controller request was rejected")]
    Rejected,
}

/// Compiles one canonical service request into a complete operation plan.
///
/// Implementations remain unprivileged. They must validate the endpoint's
/// closed schema and include normalized method, principal, project, and
/// authority context in `canonical_request`. The supplied digest is the exact
/// service-computed value that the returned plan must retain.
pub trait ActivatedOperationCompiler {
    /// Compiles one bounded canonical request without performing effects.
    ///
    /// # Errors
    ///
    /// Returns [`OperationCompilationError`] for malformed input or rejected
    /// authentication, authorization, policy, or compare-and-swap checks.
    fn compile(
        &mut self,
        canonical_request: &[u8],
        request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError>;
}

/// Reports one attempted durable reconciliation transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerReconciliationStep {
    operation_id: OperationId,
    outcome: ReconcileOutcome,
}

impl ControllerReconciliationStep {
    /// Returns the fairly selected durable operation.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the outcome of its single transition.
    #[must_use]
    pub const fn outcome(self) -> ReconcileOutcome {
        self.outcome
    }
}

/// Summarizes one bounded controller activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerQuantumReport {
    steps: Vec<ControllerReconciliationStep>,
    idle: bool,
}

impl ControllerQuantumReport {
    /// Returns attempted transitions in scheduling order.
    #[must_use]
    pub fn steps(&self) -> &[ControllerReconciliationStep] {
        &self.steps
    }

    /// Reports that the durable ledger had no nonterminal operation.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.idle
    }
}

/// Owns the synchronous unprivileged controller admission and work loop.
pub struct NodeController<C, E> {
    scope: ControllerRequestScopeV1,
    limits: NodeControllerLimits,
    compiler: C,
    reconciler: Reconciler<E>,
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Constructs a controller around the sole journal writer.
    #[must_use]
    pub const fn new(
        scope: ControllerRequestScopeV1,
        limits: NodeControllerLimits,
        compiler: C,
        reconciler: Reconciler<E>,
    ) -> Self {
        Self {
            scope,
            limits,
            compiler,
            reconciler,
        }
    }

    /// Compiles and atomically admits one canonical activated request.
    ///
    /// The call has no volatile queue: success means the desired mutation,
    /// operation, effects, and idempotency decision are durable. Exact replay
    /// remains available when pending-work capacity is exhausted.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError`] for empty or oversized input,
    /// compiler rejection or contract violation, durable backpressure,
    /// idempotency conflict, journal failure, or corrupt recovered state.
    pub fn admit(
        &mut self,
        canonical_request: &[u8],
    ) -> Result<AcceptOutcome, ControllerServiceError> {
        if canonical_request.is_empty() {
            return Err(ControllerServiceError::EmptyRequest);
        }
        if canonical_request.len() > self.limits.maximum_request_bytes {
            return Err(ControllerServiceError::RequestTooLarge);
        }
        let request_digest = controller_request_digest(self.scope, canonical_request);
        let plan = self.compiler.compile(canonical_request, request_digest)?;
        if plan.request_digest() != request_digest {
            return Err(ControllerServiceError::CompilerDigestMismatch);
        }
        self.reconciler
            .accept_bounded(&plan, self.limits.maximum_pending_operations)
            .map_err(ControllerServiceError::Reconciler)
    }

    /// Advances at most the configured number of fair durable transitions.
    ///
    /// Retryable executor failures consume one step, so a backpressured broker
    /// cannot monopolize the activation. Calling this method again resumes from
    /// durable state; its in-memory scheduling cursor affects fairness only.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError::Reconciler`] for journal, recovered
    /// ledger, or executor-contract failure.
    pub fn reconcile_quantum(&mut self) -> Result<ControllerQuantumReport, ControllerServiceError> {
        let mut steps = Vec::with_capacity(self.limits.reconciliation_quantum);
        let mut idle = false;
        for _ in 0..self.limits.reconciliation_quantum {
            let Some((operation_id, outcome)) = self.reconciler.reconcile_next()? else {
                idle = true;
                break;
            };
            steps.push(ControllerReconciliationStep {
                operation_id,
                outcome,
            });
        }
        Ok(ControllerQuantumReport { steps, idle })
    }

    /// Selects a lease-bound attempt from the exact durable current publication.
    ///
    /// This composed path temporarily borrows the reconciler's sole journal
    /// writer, preventing an independently opened publication writer. It does
    /// not send the packet or access a privileged descriptor catalog.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityPublicationError`] for absent, stale, corrupt, or
    /// substituted current authority and for invalid clock attenuation.
    #[allow(clippy::too_many_arguments)]
    pub fn select_current_broker_attempt(
        &mut self,
        sandbox: SandboxId,
        expected_publication: ObjectDigest,
        audience: BrokerAudience,
        template_digest: ObjectDigest,
        deadline_boottime_nanoseconds: u64,
        clock: RawPairedClockSample,
    ) -> Result<BrokerDispatchAttemptV1, AuthorityPublicationError> {
        AuthorityPublicationStore::new(self.reconciler.journal_mut()).select_current_attempt(
            sandbox,
            expected_publication,
            audience,
            template_digest,
            deadline_boottime_nanoseconds,
            clock,
        )
    }
}

/// Reports activation configuration, request, compiler, or ledger failure.
#[derive(Debug, thiserror::Error)]
pub enum ControllerServiceError {
    /// A configured bound is zero or exceeds its fixed V1 ceiling.
    #[error("invalid node-controller service configuration")]
    InvalidConfiguration,
    /// The activated request body is empty.
    #[error("activated controller request is empty")]
    EmptyRequest,
    /// The activated request exceeds its configured pre-parser ceiling.
    #[error("activated controller request exceeds its fixed bound")]
    RequestTooLarge,
    /// The endpoint-specific compiler rejected the request.
    #[error(transparent)]
    Compilation(#[from] OperationCompilationError),
    /// The compiler substituted the service-computed request identity.
    #[error("operation compiler returned a substituted request digest")]
    CompilerDigestMismatch,
    /// Durable admission or reconciliation failed.
    #[error(transparent)]
    Reconciler(#[from] ReconcilerError),
}

fn controller_request_digest(
    scope: ControllerRequestScopeV1,
    canonical_request: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(REQUEST_DIGEST_DOMAIN);
    digest.update(scope.digest().as_bytes());
    digest.update(
        u64::try_from(canonical_request.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(canonical_request);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    use crate::{
        EffectDomain, EffectFailure, EffectObservation, EffectPlan, EffectReceipt, IdempotencyKey,
        Journal, JournalLimits,
    };

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-sandbox-controller-{}-{}",
                std::process::id(),
                OperationId::new()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("state.journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    struct ExternalEffects {
        applied: BTreeMap<(OperationId, u32), EffectReceipt>,
        apply_calls: usize,
        retry_once: BTreeMap<OperationId, bool>,
    }

    #[derive(Clone, Default)]
    struct Executor(Rc<RefCell<ExternalEffects>>);

    impl SingleNodeEffectExecutor for Executor {
        fn observe(
            &mut self,
            operation_id: OperationId,
            step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            Ok(self
                .0
                .borrow()
                .applied
                .get(&(operation_id, step))
                .cloned()
                .map_or(EffectObservation::Absent, EffectObservation::Applied))
        }

        fn apply(
            &mut self,
            operation_id: OperationId,
            step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            let mut state = self.0.borrow_mut();
            if state.retry_once.remove(&operation_id).is_some() {
                return Err(EffectFailure::Retryable("broker busy".to_owned()));
            }
            let receipt = EffectReceipt::new(vec![step as u8 + 1]).unwrap();
            state.apply_calls += 1;
            state.applied.insert((operation_id, step), receipt.clone());
            Ok(receipt)
        }
    }

    #[derive(Default)]
    struct Compiler;

    impl ActivatedOperationCompiler for Compiler {
        fn compile(
            &mut self,
            request: &[u8],
            request_digest: [u8; 32],
        ) -> Result<OperationPlan, OperationCompilationError> {
            let discriminator = *request
                .first()
                .ok_or(OperationCompilationError::Malformed)?;
            if discriminator == 0xff {
                return Err(OperationCompilationError::Malformed);
            }
            let digest = if discriminator == 0xfe {
                [0x99; 32]
            } else {
                request_digest
            };
            OperationPlan::new(
                OperationId::from_bytes([discriminator; 16]),
                IdempotencyKey::new(request.to_vec())
                    .map_err(|_| OperationCompilationError::Malformed)?,
                digest,
                vec![discriminator],
                b"desired".to_vec(),
                vec![
                    EffectPlan::new(EffectDomain::Host, b"apply".to_vec())
                        .map_err(|_| OperationCompilationError::Rejected)?,
                ],
            )
            .map_err(|_| OperationCompilationError::Rejected)
        }
    }

    fn scope() -> ControllerRequestScopeV1 {
        ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0x42; 32])).unwrap()
    }

    fn controller(
        path: &Path,
        executor: Executor,
        limits: NodeControllerLimits,
    ) -> NodeController<Compiler, Executor> {
        let (journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        NodeController::new(
            scope(),
            limits,
            Compiler,
            Reconciler::new(journal, executor),
        )
    }

    #[test]
    fn malformed_and_oversized_requests_fail_before_durable_admission() {
        let directory = TestDirectory::new();
        let limits = NodeControllerLimits::new(8, 4, 2).unwrap();
        let mut controller = controller(&directory.journal(), Executor::default(), limits);

        assert!(matches!(
            controller.admit(&[]),
            Err(ControllerServiceError::EmptyRequest)
        ));
        assert!(matches!(
            controller.admit(&[1; 9]),
            Err(ControllerServiceError::RequestTooLarge)
        ));
        assert!(matches!(
            controller.admit(&[0xff]),
            Err(ControllerServiceError::Compilation(
                OperationCompilationError::Malformed
            ))
        ));
        assert!(matches!(
            controller.admit(&[0xfe]),
            Err(ControllerServiceError::CompilerDigestMismatch)
        ));
        assert!(controller.reconcile_quantum().unwrap().is_idle());
    }

    #[test]
    fn backpressure_preserves_replay_and_releases_after_terminal_state() {
        let directory = TestDirectory::new();
        let limits = NodeControllerLimits::new(8, 1, 4).unwrap();
        let mut controller = controller(&directory.journal(), Executor::default(), limits);

        let accepted = controller.admit(&[1]).unwrap();
        assert_eq!(
            accepted,
            AcceptOutcome::Accepted(OperationId::from_bytes([1; 16]))
        );
        assert_eq!(
            controller.admit(&[1]).unwrap(),
            AcceptOutcome::Replay(OperationId::from_bytes([1; 16]))
        );
        assert!(matches!(
            controller.admit(&[2]),
            Err(ControllerServiceError::Reconciler(
                ReconcilerError::AdmissionBackpressure
            ))
        ));

        let report = controller.reconcile_quantum().unwrap();
        assert_eq!(report.steps().len(), 3);
        assert!(report.is_idle());
        assert!(matches!(
            controller.admit(&[2]),
            Ok(AcceptOutcome::Accepted(_))
        ));
    }

    #[test]
    fn restart_resumes_durable_intent_without_a_volatile_queue() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let limits = NodeControllerLimits::new(8, 4, 1).unwrap();
        let executor = Executor::default();
        {
            let mut controller = controller(&path, executor.clone(), limits);
            controller.admit(&[3]).unwrap();
            let report = controller.reconcile_quantum().unwrap();
            assert_eq!(report.steps()[0].outcome(), ReconcileOutcome::Progressed);
            assert_eq!(executor.0.borrow().apply_calls, 0);
        }

        let mut controller = controller(&path, executor.clone(), limits);
        assert_eq!(
            controller.admit(&[3]).unwrap(),
            AcceptOutcome::Replay(OperationId::from_bytes([3; 16]))
        );
        assert_eq!(
            controller.reconcile_quantum().unwrap().steps()[0].outcome(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(executor.0.borrow().apply_calls, 1);
        assert_eq!(
            controller.reconcile_quantum().unwrap().steps()[0].outcome(),
            ReconcileOutcome::Succeeded
        );
    }

    #[test]
    fn quantum_is_bounded_and_fair_across_pending_operations() {
        let directory = TestDirectory::new();
        let limits = NodeControllerLimits::new(8, 4, 2).unwrap();
        let mut controller = controller(&directory.journal(), Executor::default(), limits);
        controller.admit(&[1]).unwrap();
        controller.admit(&[2]).unwrap();

        let report = controller.reconcile_quantum().unwrap();
        assert_eq!(report.steps().len(), 2);
        assert!(!report.is_idle());
        assert_eq!(
            report.steps()[0].operation_id(),
            OperationId::from_bytes([1; 16])
        );
        assert_eq!(
            report.steps()[1].operation_id(),
            OperationId::from_bytes([2; 16])
        );
    }

    #[test]
    fn retryable_broker_backpressure_cannot_monopolize_a_quantum() {
        let directory = TestDirectory::new();
        let limits = NodeControllerLimits::new(8, 4, 2).unwrap();
        let executor = Executor::default();
        executor
            .0
            .borrow_mut()
            .retry_once
            .insert(OperationId::from_bytes([1; 16]), true);
        let mut controller = controller(&directory.journal(), executor, limits);
        controller.admit(&[1]).unwrap();
        controller.admit(&[2]).unwrap();
        controller.reconcile_quantum().unwrap();

        let report = controller.reconcile_quantum().unwrap();
        assert_eq!(report.steps().len(), 2);
        assert_eq!(report.steps()[0].outcome(), ReconcileOutcome::RetryPending);
        assert_eq!(report.steps()[1].outcome(), ReconcileOutcome::EffectApplied);
    }
}
