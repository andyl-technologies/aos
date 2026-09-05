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

use aos_sandbox_core::{ObjectDigest, OperationId, RawPairedClockSample};
use sha2::{Digest as _, Sha256};

use crate::publisher_authority::{
    PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
};
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};
use crate::{
    AcceptOutcome, OperationPlan, OwnershipAuthoritySessionClient, OwnershipAuthorityVerifier,
    OwnershipClockObservationError, OwnershipResumeError, OwnershipResumeOutcomeV1,
    ReconcileOutcome, Reconciler, ReconcilerError, SingleNodeEffectExecutor,
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

    /// Borrows the protected publisher capability registry for controller administration.
    ///
    /// The borrow excludes admission and reconciliation through this controller
    /// until the registry is dropped. Loading validates the entire bounded
    /// registry against the sole journal writer; no second database or cached
    /// authority snapshot is introduced.
    ///
    /// This is a trusted controller administration interface, not a service
    /// endpoint. Its caller must authorize installation and revocation. Resolving
    /// a stored capability alone does not authenticate a holder or authorize a
    /// publication effect.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError`] if the journal lacks protected storage
    /// provenance, has an ambiguous prior write, or contains malformed or
    /// over-limit publisher authority records.
    pub fn publisher_capabilities(
        &mut self,
        limits: PublisherAuthorityLimits,
    ) -> Result<PublisherCapabilityRegistry<'_>, PublisherAuthorityError> {
        PublisherCapabilityRegistry::load(self.reconciler.journal_mut(), limits)
    }

    /// Borrows current publisher policies and resource mappings for controller administration.
    ///
    /// The exclusive borrow serializes policy-head changes with the controller's
    /// other journal users. It is not a network endpoint: callers must authorize
    /// administration, and reads alone do not authorize a publication effect.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherPolicyError`] if protected journal provenance or health
    /// cannot be established, or bounded replay rejects the retained policy state.
    pub fn publisher_policies(
        &mut self,
        limits: PublisherPolicyLimits,
    ) -> Result<PublisherPolicyStore<'_>, PublisherPolicyError> {
        PublisherPolicyStore::load(self.reconciler.journal_mut(), limits)
    }

    /// Provisions a channel for an explicitly authorized local holder assignment.
    ///
    /// This trusted administration interface requires its caller to authorize
    /// the principal, sandbox incarnation, assignment epoch, and retained cgroup
    /// together. Neither guest UIDs nor incoming packet claims supply that mapping.
    /// The clock callback must be the protected paired-clock adapter identified
    /// by configuration, never a request-provided timestamp. Successful issuance
    /// is not source admission or permission to publish; every use needs current
    /// capability, policy, revocation, assignment, and resource checks.
    ///
    /// The returned descriptor must be delivered only to the intended execution
    /// scope. On delivery failure, invalidate its session. Restart creates an
    /// empty session table even when issued capability records survive.
    ///
    /// # Errors
    ///
    /// Returns an error on capacity, scope, policy, time, or protected commit
    /// failure. No endpoint escapes on failure; post-commit failures may retain
    /// an audited capability that has no live session.
    #[cfg(target_os = "linux")]
    pub fn provision_local_ingress<T>(
        &mut self,
        sessions: &mut crate::local_sessions::LocalSessionRegistry,
        scope: crate::local_sessions::LocalSessionScope,
        anchor: aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        config: crate::local_provisioning::LocalProvisioningPolicy,
        clock: &mut T,
    ) -> Result<
        crate::local_sessions::LocalSessionEndpoint,
        crate::local_provisioning::LocalProvisioningError,
    >
    where
        T: FnMut() -> Result<
            aos_sandbox_core::ownership_lease::RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::local_provisioning::provision(
            self.reconciler.journal_mut(),
            sessions,
            scope,
            anchor,
            config,
            clock,
        )
    }

    /// Registers an explicitly authorized publisher service's exact execution.
    ///
    /// Trusted administration must bind the configured principal and node to
    /// this listener and retained service cgroup. A UID or incoming request is
    /// not that authorization. The clock must come from the configured protected
    /// adapter. Registration commits audit facts before greeting the peer; it
    /// grants no admission, root access, signing, or completion authority.
    ///
    /// # Errors
    ///
    /// Rejects exhausted capacity, invalid execution identity, stale policy or
    /// clock, and protected storage failures. A failed or ambiguous commit may
    /// retain a retired execution pin until its original process exits.
    #[cfg(target_os = "linux")]
    pub fn register_publisher_execution<T>(
        &mut self,
        sessions: &mut crate::publisher_sessions::PublisherSessionRegistry,
        listener: &mut aos_sandbox_linux::seqpacket::RecordSubjectListener,
        service: crate::publisher_control::PublisherServiceRegistration,
        config: crate::publisher_control::PublisherControlPolicy,
        clock: &mut T,
    ) -> Result<
        crate::publisher_ingress::PublisherExecutionRegistrationV1,
        crate::publisher_control::PublisherControlError,
    >
    where
        T: FnMut() -> Result<
            aos_sandbox_core::ownership_lease::RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::publisher_control::register(
            self.reconciler.journal_mut(),
            sessions,
            listener,
            service.scope,
            service.anchor,
            config,
            clock,
        )
    }

    /// Registers a pending challenge received from its exact publisher execution.
    ///
    /// The request is read from the live authenticated session, never supplied as
    /// caller-authorized bytes. Current policy, resource, controller, revocation,
    /// and time checks constrain the immutable audit record. Its root-registry
    /// generation and holder/source authority remain unverified prerequisites
    /// for future admission. This receipt permits no publication or signing.
    ///
    /// # Errors
    ///
    /// Rejects invalid transport identity or encoding, stale protected heads,
    /// expired or changed challenges, exhausted audit limits, and storage failure.
    /// Post-commit failure can leave an inert pending record without a receipt.
    #[cfg(target_os = "linux")]
    pub fn register_publisher_challenge<T>(
        &mut self,
        sessions: &mut crate::publisher_sessions::PublisherSessionRegistry,
        instance: aos_sandbox_core::PublisherInstanceId,
        config: crate::publisher_control::PublisherControlPolicy,
        clock: &mut T,
    ) -> Result<
        crate::publisher_control::PendingPublisherChallengeReceipt,
        crate::publisher_control::PublisherControlError,
    >
    where
        T: FnMut() -> Result<
            aos_sandbox_core::ownership_lease::RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::publisher_control::register_challenge(
            self.reconciler.journal_mut(),
            sessions,
            instance,
            config,
            clock,
        )
    }

    /// Releases a retired volatile publisher slot after its pinned process exits.
    ///
    /// This does not erase audit records, release durable publication accounting,
    /// transfer old completion permits, or restore a session after restart.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy protected storage, unknown or active sessions, and an
    /// original publisher process that remains alive or cannot be observed.
    #[cfg(target_os = "linux")]
    pub fn release_exited_publisher(
        &mut self,
        sessions: &mut crate::publisher_sessions::PublisherSessionRegistry,
        instance: aos_sandbox_core::PublisherInstanceId,
    ) -> Result<
        aos_sandbox_core::PublisherInstanceId,
        crate::publisher_control::PublisherControlError,
    > {
        crate::publisher_control::release_exited(self.reconciler.journal_mut(), sessions, instance)
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

    /// Explicitly resumes one operation held behind durable ownership.
    ///
    /// An already activated gate is validated and replayed without consulting
    /// the session client or clock. A pending gate always queries its exact
    /// authority transaction before beginning or completing it. Ordinary
    /// reconciliation never invokes this path.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipResumeError`] for an absent or corrupt gate, a
    /// mismatched negotiated session, hostile response substitution, local
    /// clock-observation failure, invalid authority artifacts, publication
    /// conflict, or durable activation failure.
    pub fn resume_ownership<A, T>(
        &mut self,
        operation_id: OperationId,
        client: &mut A,
        verifier: &OwnershipAuthorityVerifier,
        observe_clock: &mut T,
    ) -> Result<OwnershipResumeOutcomeV1, OwnershipResumeError>
    where
        A: OwnershipAuthoritySessionClient,
        T: FnMut() -> Result<RawPairedClockSample, OwnershipClockObservationError>,
    {
        crate::ownership_resume::resume_ownership(
            &mut self.reconciler,
            operation_id,
            client,
            verifier,
            observe_clock,
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
    fn capability_administration_borrows_only_protected_controller_storage() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let directory = TestDirectory::new();
        let mut unprotected = controller(
            &directory.journal(),
            Executor::default(),
            NodeControllerLimits::default(),
        );
        assert!(matches!(
            unprotected.publisher_capabilities(PublisherAuthorityLimits::default()),
            Err(PublisherAuthorityError::Journal(
                crate::JournalError::ProtectedBoundary
            )),
        ));
        assert!(matches!(
            unprotected.publisher_policies(PublisherPolicyLimits::default()),
            Err(PublisherPolicyError::Journal(
                crate::JournalError::ProtectedBoundary
            )),
        ));

        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(
            &directory.0,
            "protected.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let mut protected = NodeController::new(
            scope(),
            NodeControllerLimits::default(),
            Compiler,
            Reconciler::new(journal, Executor::default()),
        );
        {
            let registry = protected
                .publisher_capabilities(PublisherAuthorityLimits::default())
                .unwrap();
            assert!(matches!(
                registry.resolve_current(aos_sandbox_core::CapabilityId::new()),
                Err(PublisherAuthorityError::UnknownCapability),
            ));
        }
        assert!(protected.reconcile_quantum().unwrap().is_idle());
        assert!(
            protected
                .publisher_policies(PublisherPolicyLimits::default())
                .is_ok()
        );
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
