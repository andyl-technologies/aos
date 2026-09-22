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
use buffa::Message as _;
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};

use crate::cli_model::{
    AuthorizedOperatorRecoveryV1, DormantPublicApiClientV1, InvalidObservationClientAdapter,
    OperatorRecoveryRequestV1,
};
use crate::controller_query::{
    CheckedOperationPhaseV1, CheckedOperationResourceV1, CheckedRetryClassV1,
    CheckedSandboxResourceV1, PublicConditionCodeV1,
};
use crate::{JournalRecord, JournalTransaction, RecordNamespace};

#[cfg(target_os = "linux")]
use crate::cli_model::authorization_adapter::{
    AuthenticatedCliChannelEvidenceV1, AuthenticatedCliIdentityEvidenceV1,
    AuthenticatedCliSessionEvidenceV1, CliAuthorizationAdapterError,
    CurrentProtectedCliAuthorizationV1, DecodedAuthenticatedCliRequestV1,
    DormantAuthenticatedCliRequestV1,
};
#[cfg(target_os = "linux")]
use crate::cli_model::{
    AuditAuthorizationV1, AuthorizedResolvedMutationV1, DormantClientStatePlanV1,
    DormantSandboxOutputV1, DormantSandboxRequestV1, PublicApiAuditMethodV1, RequestProvenanceV1,
    ResolvedPublicMutationV1,
};
use crate::publisher_authority::{
    PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
};
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};
use crate::{
    AcceptOutcome, OperationPlan, OwnershipAuthoritySessionClient, OwnershipAuthorityVerifier,
    OwnershipClockObservationError, OwnershipResumeError, OwnershipResumeOutcomeV1,
    ReconcileOutcome, Reconciler, ReconcilerError, SingleNodeEffectExecutor,
    ValidatedUnfinishedOperationV1,
};

#[cfg(target_os = "linux")]
mod destination_slot;

#[cfg(target_os = "linux")]
mod public_api_authorization;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-request.v1\0";
#[cfg(target_os = "linux")]
const PUBLIC_REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-public-request.v1\0";
const MAXIMUM_ACTIVATION_BYTES: usize = 1024 * 1024;
const MAXIMUM_PENDING_OPERATIONS: usize = 1_000_000;
const MAXIMUM_RECONCILIATION_QUANTUM: usize = 4096;
#[cfg(target_os = "linux")]
const DORMANT_CLI_OBSERVATION_SCHEMA_V1: &[u8] = b"aos.sandbox.cli.observation-schema.v1\0";

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
/// The controller lends its sole journal writer for current authorization and
/// precondition checks. Implementations must not retain a second journal owner,
/// commit desired-state/effect admission themselves, or perform external effects.
/// Authorization maintenance such as advancing the protected time floor may
/// commit before admission; it must never represent acceptance of the request.
pub trait ActivatedOperationCompiler {
    /// Compiles one bounded canonical request without performing effects.
    ///
    /// # Errors
    ///
    /// Returns [`OperationCompilationError`] for malformed input or rejected
    /// authentication, authorization, policy, or compare-and-swap checks.
    fn compile(
        &mut self,
        journal: &mut crate::Journal,
        canonical_request: &[u8],
        request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError>;

    /// Compiles a public request using live transport evidence and current protected state.
    ///
    /// The peer is transport evidence, not authority. Implementations must
    /// resolve `capability_id` in `journal`, authorize the exact method/body,
    /// enforce the peer's principal and project, and derive all required current
    /// resource fences. The default rejects; public requests never fall back
    /// to the byte-only compiler entry point.
    ///
    /// # Errors
    ///
    /// Rejects unsupported public admission or failed authentication,
    /// authorization, canonical encoding, policy, or preconditions.
    #[cfg(target_os = "linux")]
    fn compile_public(
        &mut self,
        _journal: &mut crate::Journal,
        _peer: &crate::public_api_session::PublicApiPeer,
        _capability_id: aos_sandbox_core::CapabilityId,
        _canonical_request: &[u8],
        _request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError> {
        Err(OperationCompilationError::Rejected)
    }
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

/// Composes real injected controller and public-client dependencies without activation.
///
/// Construction registers no RPC service, opens no socket, and grants no
/// mutation authority. It exists so source integration can supply a concrete
/// compiler, effect executor, and public API wire transport without replacing
/// them with production's deliberately unavailable implementations.
pub struct DormantControllerCompositionV1<C, E, T> {
    controller: NodeController<C, E>,
    public_api_client: DormantPublicApiClientV1<T>,
}

impl<C, E, T> DormantControllerCompositionV1<C, E, T>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Rechecks every protected owner after first-root commit and returns the root.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecyclePhase6ErrorV1`] unless the newly
    /// committed root exactly matches a fresh all-domain join under one boot.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_lifecycle_boot_inventory_bootstrap<'current>(
        &mut self,
        lifecycle: &'current crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        runtime: &crate::lifecycle::LifecycleAuthenticatedRuntimeInventorySuccessorV1,
        mounts: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventorySuccessorV1,
        storage: &crate::DurableStorageResourceInventorySnapshotV1,
        storage_inventory: &crate::lifecycle::LifecycleAuthenticatedStorageInventorySuccessorV1,
        network: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventorySuccessorV1,
        cache: &mut crate::cache_residency::CacheResidencyProtectedOwnerV1,
        transfer: &mut crate::multi_node::ProtectedMultiNodeAuthorityOwnerV1,
        transfer_inventory: &crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1,
    ) -> Result<
        crate::lifecycle::CurrentLifecycleBootInventoryV1<'current>,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    > {
        let checked = self.controller.current_lifecycle_boot_domains(
            lifecycle,
            operation_key,
            boot_inventory_key,
            runtime,
            mounts,
            storage,
            storage_inventory,
            network,
            cache,
            transfer,
            transfer_inventory,
        )?;
        drop(checked);
        lifecycle
            .current_boot_inventory(boot_inventory_key)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .ok_or(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)
    }

    /// Publishes the absent first lifecycle boot root from protected owners.
    ///
    /// Host, Mount, Storage, and Network must be challenge-authenticated by
    /// their fixed BSA sessions. Cache and Transfer are reread through their
    /// concrete protected owners around derivation. On an applied commit,
    /// callers must issue four new broker pairs and run the standard joined
    /// boot-domain query before using any recovery observation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecyclePhase6ErrorV1`] for a stale
    /// challenge, an existing root, changed owner state, boot rollover, or a
    /// protected append failure. Indeterminate commits retain their recovery
    /// token in the returned progress value.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn publish_lifecycle_boot_inventory_bootstrap(
        &mut self,
        lifecycle: &mut crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        challenge: crate::lifecycle::LifecycleBootInventoryBootstrapChallengeV1,
        runtime: &crate::lifecycle::LifecycleAuthenticatedRuntimeInventoryBootstrapV1,
        mounts: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        storage: &crate::DurableStorageResourceInventorySnapshotV1,
        storage_inventory: &crate::lifecycle::LifecycleAuthenticatedStorageInventoryBootstrapV1,
        network: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        cache: &mut crate::cache_residency::CacheResidencyProtectedOwnerV1,
        transfer: &mut crate::multi_node::ProtectedMultiNodeAuthorityOwnerV1,
        transfer_inventory: &crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1,
        transaction_id: [u8; 16],
        atomic_join: aos_sandbox_core::ResourceId,
        operation_lineage: aos_sandbox_core::ResourceId,
        inventory_lineage: aos_sandbox_core::ResourceId,
    ) -> Result<
        crate::lifecycle::LifecycleProgressCommitOutcomeV1,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    > {
        let boot_before = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != challenge.host_boot() {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        storage
            .recheck(self.controller.reconciler.journal_mut())
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let cache_inventory = cache
            .lifecycle_boot_inventory()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        transfer
            .recheck_lifecycle_transfer_inventory(transfer_inventory)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let source =
            crate::lifecycle::LifecycleBootInventoryBootstrapSourceV1::from_protected_join(
                challenge,
                runtime,
                mounts,
                storage_inventory,
                storage,
                network,
                &cache_inventory,
                transfer_inventory,
            )?;
        storage
            .recheck(self.controller.reconciler.journal_mut())
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        if cache
            .lifecycle_boot_inventory()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            != cache_inventory
        {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        transfer
            .recheck_lifecycle_transfer_inventory(transfer_inventory)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let boot_after = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != boot_after {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        self.controller
            .commit_lifecycle_boot_inventory_bootstrap(
                lifecycle,
                operation_key,
                boot_inventory_key,
                source,
                transaction_id,
                atomic_join,
                operation_lineage,
                inventory_lineage,
            )
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)
    }

    /// Publishes a refreshed lifecycle boot root from all protected domain owners.
    ///
    /// This dormant callsite performs the first phase only: it joins and
    /// rechecks every owner, consumes that capability internally, and commits
    /// the derived root. The caller must then obtain fresh Host and Storage
    /// successors and perform the ordinary boot-domain join; pre-publication
    /// observations cannot be reused as post-publication currentness.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecyclePhase6ErrorV1`] when any domain is
    /// stale or incomplete, the protected clock rolls over, or root preparation
    /// fails. An indeterminate commit is returned with its recovery token.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn publish_lifecycle_boot_inventory_refresh(
        &mut self,
        lifecycle: &mut crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        challenge: crate::lifecycle::LifecycleBootInventoryBootstrapChallengeV1,
        runtime: &crate::lifecycle::LifecycleAuthenticatedRuntimeInventoryBootstrapV1,
        mounts: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        storage: &crate::DurableStorageResourceInventorySnapshotV1,
        storage_inventory: &crate::lifecycle::LifecycleAuthenticatedStorageInventoryBootstrapV1,
        network: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        cache: &mut crate::cache_residency::CacheResidencyProtectedOwnerV1,
        transfer: &mut crate::multi_node::ProtectedMultiNodeAuthorityOwnerV1,
        transfer_inventory: &crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1,
        transaction_id: [u8; 16],
        atomic_join: aos_sandbox_core::ResourceId,
        operation_lineage: aos_sandbox_core::ResourceId,
        inventory_lineage: aos_sandbox_core::ResourceId,
    ) -> Result<
        crate::lifecycle::LifecycleProgressCommitOutcomeV1,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    > {
        let boot_before = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != challenge.host_boot() {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        storage
            .recheck(self.controller.reconciler.journal_mut())
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let cache_inventory = cache
            .lifecycle_boot_inventory()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        transfer
            .recheck_lifecycle_transfer_inventory(transfer_inventory)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let source =
            crate::lifecycle::LifecycleBootInventoryBootstrapSourceV1::from_protected_join(
                challenge,
                runtime,
                mounts,
                storage_inventory,
                storage,
                network,
                &cache_inventory,
                transfer_inventory,
            )?
            .into_refresh_source();
        storage
            .recheck(self.controller.reconciler.journal_mut())
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        if cache
            .lifecycle_boot_inventory()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            != cache_inventory
        {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        transfer
            .recheck_lifecycle_transfer_inventory(transfer_inventory)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let boot_after = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != boot_after {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        self.controller
            .commit_lifecycle_boot_inventory_refresh(
                lifecycle,
                operation_key,
                boot_inventory_key,
                source,
                transaction_id,
                atomic_join,
                operation_lineage,
                inventory_lineage,
            )
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)
    }

    /// Constructs a dormant composition around explicitly supplied real dependencies.
    #[must_use]
    pub fn new(
        scope: ControllerRequestScopeV1,
        limits: NodeControllerLimits,
        journal: crate::Journal,
        compiler: C,
        executor: E,
        public_api_transport: T,
    ) -> Self {
        Self {
            controller: NodeController::new(
                scope,
                limits,
                compiler,
                Reconciler::new(journal, executor),
            ),
            public_api_client: DormantPublicApiClientV1::new(public_api_transport),
        }
    }

    /// Borrows the supplied controller composition without admitting work.
    #[must_use]
    pub fn controller_mut(&mut self) -> &mut NodeController<C, E> {
        &mut self.controller
    }

    /// Constructs the dormant public recovery handler from explicit dependencies.
    ///
    /// The returned handler remains unregistered and borrows the sole controller
    /// journal through this composition.
    #[must_use]
    pub(crate) fn operator_recovery_service<A, S, O>(
        &mut self,
        authorizer: A,
        current_observer: S,
        effect_observer: O,
    ) -> DormantOperatorRecoveryPublicServiceV1<'_, C, E, A, S, O>
    where
        A: DormantOperatorRecoveryPublicAuthorizerV1,
        S: DormantOperatorRecoveryCurrentObserverV1,
        O: DormantOperatorRecoveryEffectObserverV1,
    {
        DormantOperatorRecoveryPublicServiceV1::new(
            &mut self.controller,
            authorizer,
            current_observer,
            effect_observer,
        )
    }

    /// Borrows the supplied public API client without choosing an endpoint.
    #[must_use]
    pub fn public_api_client_mut(&mut self) -> &mut DormantPublicApiClientV1<T> {
        &mut self.public_api_client
    }

    /// Dismantles the dormant composition into its controller and API client.
    #[must_use]
    pub fn into_parts(self) -> (NodeController<C, E>, DormantPublicApiClientV1<T>) {
        (self.controller, self.public_api_client)
    }
}

/// Borrows the controller's protected journal for a dormant recovery transition.
///
/// This owner registers no route and dispatches no runtime effect. It owns the
/// protected current-head, idempotency, and canonical transition records.
pub(crate) struct DormantOperatorRecoveryOwnerV1<'controller> {
    journal: &'controller mut crate::Journal,
}

/// Maximum dispatch attempts retained for one operator-recovery effect.
pub const MAXIMUM_OPERATOR_RECOVERY_EFFECT_ATTEMPTS_V1: u32 = 3;
/// Maximum consecutive unknown observer classifications retained before escalation.
pub const MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1: u32 = 3;
/// Maximum nonterminal operator-recovery rows returned by one startup scan.
pub const MAXIMUM_PENDING_OPERATOR_RECOVERIES_V1: usize = 4_096;

/// Reports durable admission, restart recovery, ambiguity, or exact terminal replay.
pub(crate) enum DormantOperatorRecoveryAdmissionV1 {
    /// A durable issued effect must be handed to the recovery executor.
    Issued(DormantOperatorRecoveryEffectHandoffV1),
    /// A previously issued effect must be observed before any redispatch.
    RecoveryRequired(DormantOperatorRecoveryPendingV1),
    /// Observation remains ambiguous and no redispatch is permitted.
    Ambiguous(DormantOperatorRecoveryPendingV1),
    /// The bounded observer ambiguity budget is exhausted without classification.
    AmbiguityExhausted(DormantOperatorRecoveryPendingV1),
    /// Absence was proven, but the bounded dispatch-attempt budget is exhausted.
    DispatchBudgetExhausted(DormantOperatorRecoveryPendingV1),
    /// The same authorized request already reached a durable terminal result.
    Terminal(aos_proto::aos::sandbox::v1::OperatorRecoveryResult),
    /// A terminal observation is retained while its atomic journal commit is ambiguous.
    TerminalCommitAmbiguous(DormantOperatorRecoveryTerminalV1),
}

/// Seals one durably issued recovery effect for a future typed executor.
#[must_use = "an issued operator-recovery effect must reach a terminal observation"]
pub(crate) struct DormantOperatorRecoveryEffectHandoffV1 {
    issued: DormantOperatorRecoveryIssuedStateV1,
    reservation_key: Vec<u8>,
}

/// Seals a checked executor terminal observation before durable reduction.
#[must_use = "a checked operator-recovery terminal must be durably recorded"]
pub(crate) struct DormantOperatorRecoveryTerminalV1 {
    handoff: DormantOperatorRecoveryEffectHandoffV1,
    result: aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
}

/// Retains either a durable terminal result or exact custody after commit ambiguity.
pub(crate) enum DormantOperatorRecoveryTerminalCommitV1 {
    /// The terminal result and successor current head are durably committed.
    Complete(aos_proto::aos::sandbox::v1::OperatorRecoveryResult),
    /// Commit outcome is uncertain; the terminal token must be retried, never redispatched.
    Ambiguous(DormantOperatorRecoveryTerminalV1),
}

/// Retains a restart-enumerated issued effect without granting redispatch authority.
#[must_use = "a pending recovery must be classified through its effect observer"]
pub(crate) struct DormantOperatorRecoveryPendingV1 {
    issued: DormantOperatorRecoveryIssuedStateV1,
    reservation_key: Vec<u8>,
}

/// Carries the exact issued identity to an injected effect observer.
pub(crate) struct DormantOperatorRecoveryEffectQueryV1 {
    effect_id: ObjectDigest,
    attempt: u32,
    current_generation: u64,
    request: aos_proto::aos::sandbox::v1::OperatorRecoveryRequest,
}

impl DormantOperatorRecoveryEffectQueryV1 {
    /// Returns the stable durable effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> ObjectDigest {
        self.effect_id
    }

    /// Returns the exact one-based dispatch attempt under observation.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Returns the exact desired generation retained at initial issuance.
    #[must_use]
    pub const fn current_generation(&self) -> u64 {
        self.current_generation
    }

    /// Returns the canonical request retained before the first dispatch.
    #[must_use]
    pub const fn request(&self) -> &aos_proto::aos::sandbox::v1::OperatorRecoveryRequest {
        &self.request
    }
}

/// Classifies one exact issued effect from an authoritative receipt/inventory query.
pub(crate) enum DormantOperatorRecoveryEffectDispositionV1 {
    /// A terminal executor result is authoritatively retained.
    Terminal(aos_proto::aos::sandbox::v1::OperatorRecoveryResult),
    /// The observer proves this exact attempt did not apply an effect.
    NotObserved,
    /// The observer cannot distinguish absent, in-flight, or completed state.
    Unknown,
}

/// Seals an observer classification to the queried effect and attempt.
pub(crate) struct DormantOperatorRecoveryEffectReceiptV1 {
    effect_id: ObjectDigest,
    attempt: u32,
    current_generation: u64,
    disposition: DormantOperatorRecoveryEffectDispositionV1,
}

impl DormantOperatorRecoveryEffectReceiptV1 {
    /// Constructs a receipt proving an exact attempt did not apply an effect.
    #[must_use]
    pub(crate) const fn not_observed(query: &DormantOperatorRecoveryEffectQueryV1) -> Self {
        Self {
            effect_id: query.effect_id,
            attempt: query.attempt,
            current_generation: query.current_generation,
            disposition: DormantOperatorRecoveryEffectDispositionV1::NotObserved,
        }
    }

    /// Constructs a receipt retaining an authoritative terminal result.
    #[must_use]
    pub(crate) fn terminal(
        query: &DormantOperatorRecoveryEffectQueryV1,
        result: aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
    ) -> Self {
        Self {
            effect_id: query.effect_id,
            attempt: query.attempt,
            current_generation: query.current_generation,
            disposition: DormantOperatorRecoveryEffectDispositionV1::Terminal(result),
        }
    }

    /// Constructs an explicitly unknown classification that never permits redispatch.
    #[must_use]
    pub(crate) const fn unknown(query: &DormantOperatorRecoveryEffectQueryV1) -> Self {
        Self {
            effect_id: query.effect_id,
            attempt: query.attempt,
            current_generation: query.current_generation,
            disposition: DormantOperatorRecoveryEffectDispositionV1::Unknown,
        }
    }
}

/// Queries authoritative effect receipts or independently enumerated effect inventory.
pub(crate) trait DormantOperatorRecoveryEffectObserverV1 {
    /// Classifies exactly one durable issued attempt without performing it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] when the observer cannot
    /// authenticate or bound its response.
    fn classify(
        &mut self,
        query: &DormantOperatorRecoveryEffectQueryV1,
    ) -> Result<DormantOperatorRecoveryEffectReceiptV1, InvalidObservationClientAdapter>;
}

/// Performs one checked recovery effect while the protected journal is exclusively borrowed.
pub(crate) trait DormantOperatorRecoveryEffectExecutorV1 {
    /// Executes the exact durably issued attempt and returns its terminal observation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] when dispatch or its authenticated
    /// terminal observation cannot be completed.
    fn execute(
        &mut self,
        query: &DormantOperatorRecoveryEffectQueryV1,
    ) -> Result<aos_proto::aos::sandbox::v1::OperatorRecoveryResult, InvalidObservationClientAdapter>;
}

/// Reports a rejected dormant public operator-recovery service request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DormantOperatorRecoveryServiceErrorV1 {
    /// The public request or authorization binding is malformed.
    #[error("dormant operator-recovery request is invalid")]
    InvalidRequest,
    /// The explicitly injected authorizer rejected the public context.
    #[error("dormant operator-recovery authorization was rejected")]
    AuthorizationRejected,
    /// Protected durable recovery state rejected the transition.
    #[error("dormant operator-recovery state rejected the transition")]
    RecoveryState,
}

/// Carries the principal and exact request binding proven by an injected authorizer.
pub(crate) struct DormantOperatorRecoveryPublicAuthorizationV1 {
    principal: ObjectDigest,
    request_binding: ObjectDigest,
}

impl DormantOperatorRecoveryPublicAuthorizationV1 {
    /// Constructs a decision bound to one already checked recovery request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::InvalidRequest`] for a
    /// zero principal.
    pub(crate) fn for_request(
        principal: ObjectDigest,
        request: &OperatorRecoveryRequestV1,
    ) -> Result<Self, DormantOperatorRecoveryServiceErrorV1> {
        Self::new(principal, request.authority_binding())
    }

    /// Constructs an explicit public-service authorization decision.
    ///
    /// This constructor is for an injected authenticated transport authorizer;
    /// the dormant service independently checks the request binding before it
    /// reaches protected durable state.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::InvalidRequest`] for a
    /// zero principal or request commitment.
    pub(crate) fn new(
        principal: ObjectDigest,
        request_binding: ObjectDigest,
    ) -> Result<Self, DormantOperatorRecoveryServiceErrorV1> {
        if principal.as_bytes() == &[0; 32] || request_binding.as_bytes() == &[0; 32] {
            Err(DormantOperatorRecoveryServiceErrorV1::InvalidRequest)
        } else {
            Ok(Self {
                principal,
                request_binding,
            })
        }
    }
}

/// Authorizes one exact public recovery request from opaque transport context.
pub(crate) trait DormantOperatorRecoveryPublicAuthorizerV1 {
    /// Consumes the opaque context and returns its proven principal/request binding.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::AuthorizationRejected`]
    /// when authentication, authorization, or current policy rejects the request.
    fn authorize(
        &mut self,
        authorization: crate::cli_model::DormantPublicApiAuthorizationV1,
        request: &aos_proto::aos::sandbox::v1::OperatorRecoveryRequest,
    ) -> Result<DormantOperatorRecoveryPublicAuthorizationV1, DormantOperatorRecoveryServiceErrorV1>;
}

/// Binds a current-state observation to an authorized recovery request.
pub(crate) struct DormantOperatorRecoveryCurrentQueryV1 {
    principal: ObjectDigest,
    request_binding: ObjectDigest,
    request: aos_proto::aos::sandbox::v1::OperatorRecoveryRequest,
}

impl DormantOperatorRecoveryCurrentQueryV1 {
    /// Returns the authenticated principal commitment.
    #[must_use]
    pub const fn principal(&self) -> ObjectDigest {
        self.principal
    }

    /// Returns the exact authorized request commitment.
    #[must_use]
    pub const fn request_binding(&self) -> ObjectDigest {
        self.request_binding
    }

    /// Returns the exact public request requiring a current observation.
    #[must_use]
    pub const fn request(&self) -> &aos_proto::aos::sandbox::v1::OperatorRecoveryRequest {
        &self.request
    }
}

enum DormantOperatorRecoveryCurrentResourceV1 {
    Sandbox(CheckedSandboxResourceV1),
    Operation(CheckedOperationResourceV1),
}

/// Seals a fully checked current resource to its authorized observation query.
pub(crate) struct DormantOperatorRecoveryCurrentObservationV1 {
    principal: ObjectDigest,
    request_binding: ObjectDigest,
    resource: DormantOperatorRecoveryCurrentResourceV1,
}

impl DormantOperatorRecoveryCurrentObservationV1 {
    /// Constructs an exact checked sandbox observation receipt.
    #[must_use]
    pub(crate) fn sandbox(
        query: &DormantOperatorRecoveryCurrentQueryV1,
        resource: CheckedSandboxResourceV1,
    ) -> Self {
        Self {
            principal: query.principal,
            request_binding: query.request_binding,
            resource: DormantOperatorRecoveryCurrentResourceV1::Sandbox(resource),
        }
    }

    /// Constructs an exact checked operation observation receipt.
    #[must_use]
    pub(crate) fn operation(
        query: &DormantOperatorRecoveryCurrentQueryV1,
        resource: CheckedOperationResourceV1,
    ) -> Self {
        Self {
            principal: query.principal,
            request_binding: query.request_binding,
            resource: DormantOperatorRecoveryCurrentResourceV1::Operation(resource),
        }
    }
}

/// Obtains current public state through an explicitly injected authorized adapter.
pub(crate) trait DormantOperatorRecoveryCurrentObserverV1 {
    /// Returns one checked current sandbox or operation observation.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::RecoveryState`] when a
    /// current authenticated observation cannot be obtained or bounded.
    fn observe_current(
        &mut self,
        query: &DormantOperatorRecoveryCurrentQueryV1,
    ) -> Result<DormantOperatorRecoveryCurrentObservationV1, DormantOperatorRecoveryServiceErrorV1>;
}

/// Retains authorization only after current state is durably synchronized.
#[must_use = "synchronized recovery authority must be consumed by begin"]
pub(crate) struct DormantOperatorRecoverySynchronizedV1 {
    principal: ObjectDigest,
    request: OperatorRecoveryRequestV1,
}

/// Composes a callable dormant public recovery handler without route registration.
pub(crate) struct DormantOperatorRecoveryPublicServiceV1<'controller, C, E, A, S, O> {
    controller: &'controller mut NodeController<C, E>,
    authorizer: A,
    current_observer: S,
    effect_observer: O,
}

impl<'controller, C, E, A, S, O> DormantOperatorRecoveryPublicServiceV1<'controller, C, E, A, S, O>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
    A: DormantOperatorRecoveryPublicAuthorizerV1,
    S: DormantOperatorRecoveryCurrentObserverV1,
    O: DormantOperatorRecoveryEffectObserverV1,
{
    /// Constructs a callable handler around explicit dependencies.
    #[must_use]
    pub(crate) const fn new(
        controller: &'controller mut NodeController<C, E>,
        authorizer: A,
        current_observer: S,
        effect_observer: O,
    ) -> Self {
        Self {
            controller,
            authorizer,
            current_observer,
            effect_observer,
        }
    }

    /// Authorizes and durably begins or exactly replays one public request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1`] when request parsing,
    /// authorization, exact binding, or protected durable admission fails.
    pub(crate) fn begin(
        &mut self,
        authorization: crate::cli_model::DormantPublicApiAuthorizationV1,
        request: aos_proto::aos::sandbox::v1::OperatorRecoveryRequest,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, DormantOperatorRecoveryServiceErrorV1> {
        let synchronized = self.synchronize_current(authorization, request)?;
        self.begin_synchronized(synchronized)
    }

    /// Authorizes, observes, and durably synchronizes current public state.
    ///
    /// No recovery effect can be issued by this method. The returned sealed
    /// authority is the only public-service input accepted by
    /// [`Self::begin_synchronized`].
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1`] when request parsing,
    /// authorization, observation binding, or durable synchronization fails.
    pub(crate) fn synchronize_current(
        &mut self,
        authorization: crate::cli_model::DormantPublicApiAuthorizationV1,
        request: aos_proto::aos::sandbox::v1::OperatorRecoveryRequest,
    ) -> Result<DormantOperatorRecoverySynchronizedV1, DormantOperatorRecoveryServiceErrorV1> {
        let checked = OperatorRecoveryRequestV1::try_from(request.clone())
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::InvalidRequest)?;
        let authorized = self.authorizer.authorize(authorization, &request)?;
        if authorized.request_binding != checked.authority_binding() {
            return Err(DormantOperatorRecoveryServiceErrorV1::AuthorizationRejected);
        }
        let query = DormantOperatorRecoveryCurrentQueryV1 {
            principal: authorized.principal,
            request_binding: authorized.request_binding,
            request,
        };
        let observation = self.current_observer.observe_current(&query)?;
        if observation.principal != query.principal
            || observation.request_binding != query.request_binding
        {
            return Err(DormantOperatorRecoveryServiceErrorV1::RecoveryState);
        }
        let mut owner = self.controller.dormant_operator_recovery();
        match observation.resource {
            DormantOperatorRecoveryCurrentResourceV1::Sandbox(resource)
                if resource.sandbox_id() == checked.resource_id()
                    && resource.as_proto().resource_version.as_slice()
                        == checked.expected_resource_version() =>
            {
                owner.synchronize_sandbox(&resource)
            }
            DormantOperatorRecoveryCurrentResourceV1::Operation(resource)
                if resource.operation_id() == checked.resource_id()
                    && resource.resource_version().as_bytes()
                        == checked.expected_resource_version() =>
            {
                owner.synchronize_operation(&resource)
            }
            DormantOperatorRecoveryCurrentResourceV1::Sandbox(_)
            | DormantOperatorRecoveryCurrentResourceV1::Operation(_) => {
                return Err(DormantOperatorRecoveryServiceErrorV1::RecoveryState);
            }
        }
        .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)?;
        let synchronized_evidence = owner
            .current_evidence(checked.resource_id())
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)?;
        if &synchronized_evidence != checked.evidence() {
            return Err(DormantOperatorRecoveryServiceErrorV1::RecoveryState);
        }
        Ok(DormantOperatorRecoverySynchronizedV1 {
            principal: authorized.principal,
            request: checked,
        })
    }

    /// Durably begins a recovery only after authorized current synchronization.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::RecoveryState`] when
    /// protected current state no longer admits the synchronized request.
    pub(crate) fn begin_synchronized(
        &mut self,
        synchronized: DormantOperatorRecoverySynchronizedV1,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, DormantOperatorRecoveryServiceErrorV1> {
        self.controller
            .dormant_operator_recovery()
            .begin_public_authorized(synchronized.principal, synchronized.request)
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)
    }

    /// Enumerates all durable nonterminal recoveries at a startup boundary.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::RecoveryState`] when
    /// protected provenance or a durable recovery record is invalid.
    pub(crate) fn pending_recoveries(
        &mut self,
    ) -> Result<Vec<DormantOperatorRecoveryPendingV1>, DormantOperatorRecoveryServiceErrorV1> {
        self.controller
            .dormant_operator_recovery()
            .pending_recoveries()
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)
    }

    /// Reconciles one startup-enumerated effect through the injected observer.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::RecoveryState`] when
    /// retained state or the authoritative observer receipt is invalid.
    pub(crate) fn reconcile(
        &mut self,
        pending: DormantOperatorRecoveryPendingV1,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, DormantOperatorRecoveryServiceErrorV1> {
        self.controller
            .dormant_operator_recovery()
            .recover_pending(pending, &mut self.effect_observer)
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)
    }

    /// Dispatches one sealed issuance under an exclusive protected-current borrow.
    pub(crate) fn dispatch<X>(
        &mut self,
        handoff: DormantOperatorRecoveryEffectHandoffV1,
        executor: &mut X,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, DormantOperatorRecoveryServiceErrorV1>
    where
        X: DormantOperatorRecoveryEffectExecutorV1,
    {
        self.controller
            .dormant_operator_recovery()
            .dispatch_effect(handoff, executor)
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)
    }

    /// Durably reduces one checked executor terminal returned by an issued handoff.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::RecoveryState`] when
    /// the issued record, current head, or terminal result no longer matches.
    pub(crate) fn record_terminal(
        &mut self,
        terminal: DormantOperatorRecoveryTerminalV1,
    ) -> Result<DormantOperatorRecoveryTerminalCommitV1, DormantOperatorRecoveryServiceErrorV1>
    {
        self.controller
            .dormant_operator_recovery()
            .record_terminal(terminal)
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)
    }

    /// Dismantles the dormant service into its explicit dependencies.
    #[must_use]
    pub(crate) fn into_parts(self) -> (&'controller mut NodeController<C, E>, A, S, O) {
        (
            self.controller,
            self.authorizer,
            self.current_observer,
            self.effect_observer,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DormantOperatorRecoveryIssuedStateV1 {
    principal: ObjectDigest,
    binding: ObjectDigest,
    effect_id: ObjectDigest,
    request: OperatorRecoveryRequestV1,
    current: Vec<u8>,
    current_generation: u64,
    attempt: u32,
    ambiguity_queries: u32,
    recovery_state: DormantOperatorRecoveryDurableStateV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DormantOperatorRecoveryDurableStateV1 {
    InitialIssue,
    ReissuedAfterAbsence,
    ObservationUnknown,
}

impl DormantOperatorRecoveryDurableStateV1 {
    const fn to_wire(self) -> u32 {
        match self {
            Self::InitialIssue => 1,
            Self::ReissuedAfterAbsence => 2,
            Self::ObservationUnknown => 3,
        }
    }

    const fn from_wire(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::InitialIssue),
            2 => Some(Self::ReissuedAfterAbsence),
            3 => Some(Self::ObservationUnknown),
            _ => None,
        }
    }
}

impl DormantOperatorRecoveryEffectHandoffV1 {
    /// Returns the stable effect identity committed by durable issuance.
    #[must_use]
    pub const fn effect_id(&self) -> ObjectDigest {
        self.issued.effect_id
    }

    /// Returns the exact one-based dispatch attempt.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.issued.attempt
    }

    /// Returns the desired generation retained before effect issuance.
    #[must_use]
    pub const fn current_generation(&self) -> u64 {
        self.issued.current_generation
    }

    fn check_terminal(
        self,
        result: aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
    ) -> Result<DormantOperatorRecoveryTerminalV1, InvalidObservationClientAdapter> {
        validate_recovery_terminal(&self.issued.request, &result)?;
        Ok(DormantOperatorRecoveryTerminalV1 {
            handoff: self,
            result,
        })
    }
}

impl DormantOperatorRecoveryPendingV1 {
    /// Returns the stable effect identity that must be observed.
    #[must_use]
    pub const fn effect_id(&self) -> ObjectDigest {
        self.issued.effect_id
    }

    /// Returns the last durably issued attempt.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.issued.attempt
    }

    /// Returns the number of consecutive durable unknown classifications.
    #[must_use]
    pub const fn ambiguity_queries(&self) -> u32 {
        self.issued.ambiguity_queries
    }

    /// Returns the desired generation retained with the original current head.
    #[must_use]
    pub const fn current_generation(&self) -> u64 {
        self.issued.current_generation
    }

    /// Returns the canonical request retained before the first dispatch.
    #[must_use]
    pub fn request(&self) -> aos_proto::aos::sandbox::v1::OperatorRecoveryRequest {
        self.issued.request.to_proto()
    }
}

impl DormantOperatorRecoveryOwnerV1<'_> {
    /// Executes one sealed attempt only while its durable issuance and current head are exact.
    pub(crate) fn dispatch_effect<X>(
        &mut self,
        handoff: DormantOperatorRecoveryEffectHandoffV1,
        executor: &mut X,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, InvalidObservationClientAdapter>
    where
        X: DormantOperatorRecoveryEffectExecutorV1,
    {
        self.recheck_effect_handoff(&handoff)?;
        let query = DormantOperatorRecoveryEffectQueryV1 {
            effect_id: handoff.issued.effect_id,
            attempt: handoff.issued.attempt,
            current_generation: handoff.issued.current_generation,
            request: handoff.issued.request.to_proto(),
        };
        let result = executor.execute(&query)?;
        self.recheck_effect_handoff(&handoff)?;
        let terminal = handoff.check_terminal(result)?;
        match self.record_terminal(terminal)? {
            DormantOperatorRecoveryTerminalCommitV1::Complete(result) => {
                Ok(DormantOperatorRecoveryAdmissionV1::Terminal(result))
            }
            DormantOperatorRecoveryTerminalCommitV1::Ambiguous(terminal) => Ok(
                DormantOperatorRecoveryAdmissionV1::TerminalCommitAmbiguous(terminal),
            ),
        }
    }

    fn recheck_effect_handoff(
        &self,
        handoff: &DormantOperatorRecoveryEffectHandoffV1,
    ) -> Result<(), InvalidObservationClientAdapter> {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let retained = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &handoff.reservation_key)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let DormantOperatorRecoveryReservationV1::Issued(retained) =
            decode_recovery_reservation(retained)?
        else {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        };
        let current = self
            .journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(retained.request.resource_id()),
            )
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        if retained != handoff.issued || current != retained.current {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        validate_recovery_reservation_key(&retained, &handoff.reservation_key)?;
        validate_recovery_current(&retained.request, current)
    }

    /// Returns sealed evidence for the protected current head of one resource.
    pub(crate) fn current_evidence(
        &self,
        resource_id: [u8; 16],
    ) -> Result<aos_proto::aos::sandbox::v1::ObjectDescriptor, InvalidObservationClientAdapter>
    {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let current = self
            .journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(resource_id),
            )
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let digest: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.operator-recovery-current-evidence.v1\0")
            .chain_update(resource_id)
            .chain_update((current.len() as u64).to_be_bytes())
            .chain_update(current)
            .finalize()
            .into();
        Ok(aos_proto::aos::sandbox::v1::ObjectDescriptor {
            media_type: "application/vnd.aos.sandbox.operator-recovery-evidence.v1".into(),
            sha256: digest.to_vec(),
            encoded_size: (16 + current.len()) as u64,
            ..Default::default()
        })
    }

    /// Reserves a transition after checking protected journal provenance.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] when protected provenance is absent.
    pub(crate) fn begin(
        &mut self,
        authorized: AuthorizedOperatorRecoveryV1,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, InvalidObservationClientAdapter> {
        let (request, provenance) = authorized.into_parts();
        self.begin_with_authority(provenance.commitments().0.digest(), request)
    }

    fn begin_public_authorized(
        &mut self,
        principal: ObjectDigest,
        request: OperatorRecoveryRequestV1,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, InvalidObservationClientAdapter> {
        self.begin_with_authority(principal, request)
    }

    fn begin_with_authority(
        &mut self,
        principal: ObjectDigest,
        request: OperatorRecoveryRequestV1,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, InvalidObservationClientAdapter> {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        if principal.as_bytes() == &[0; 32] {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        let reservation_key =
            recovery_reservation_key(principal.as_bytes(), request.idempotency_key());
        let binding = request.authority_binding();
        let effect_id = recovery_effect_id(principal, &request);
        if let Some(existing) = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &reservation_key)
            .map(<[u8]>::to_vec)
        {
            return match decode_recovery_reservation(&existing)? {
                DormantOperatorRecoveryReservationV1::Issued(issued) => {
                    validate_recovery_replay(
                        &issued,
                        principal,
                        binding,
                        effect_id,
                        &request,
                        &reservation_key,
                    )?;
                    let pending = DormantOperatorRecoveryPendingV1 {
                        issued,
                        reservation_key,
                    };
                    if pending.issued.ambiguity_queries
                        == MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1
                    {
                        Ok(DormantOperatorRecoveryAdmissionV1::AmbiguityExhausted(
                            pending,
                        ))
                    } else {
                        Ok(DormantOperatorRecoveryAdmissionV1::RecoveryRequired(
                            pending,
                        ))
                    }
                }
                DormantOperatorRecoveryReservationV1::Complete { issued, result } => {
                    validate_recovery_replay(
                        &issued,
                        principal,
                        binding,
                        effect_id,
                        &request,
                        &reservation_key,
                    )?;
                    validate_recovery_terminal(&request, &result)?;
                    Ok(DormantOperatorRecoveryAdmissionV1::Terminal(result))
                }
            };
        }
        let current_key = recovery_current_key(request.resource_id());
        let current = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &current_key)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?
            .to_vec();
        validate_recovery_current(&request, &current)?;
        let current_generation = decode_recovery_current(&current)?.desired_generation;
        let issued = DormantOperatorRecoveryIssuedStateV1 {
            principal,
            binding,
            effect_id,
            request,
            current,
            current_generation,
            attempt: 1,
            ambiguity_queries: 0,
            recovery_state: DormantOperatorRecoveryDurableStateV1::InitialIssue,
        };
        commit_recovery_records(
            self.journal,
            recovery_issued_commit_id(&issued),
            vec![JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                reservation_key.clone(),
                encode_issued_recovery_reservation(&issued)?,
            )],
        )?;
        Ok(DormantOperatorRecoveryAdmissionV1::Issued(
            DormantOperatorRecoveryEffectHandoffV1 {
                issued,
                reservation_key,
            },
        ))
    }

    /// Enumerates every nonterminal recovery row from protected startup state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] for unhealthy provenance,
    /// foreign/corrupt records, or more than the bounded pending-row ceiling.
    pub fn pending_recoveries(
        &self,
    ) -> Result<Vec<DormantOperatorRecoveryPendingV1>, InvalidObservationClientAdapter> {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let mut pending = Vec::new();
        for (key, encoded) in self.journal.records(RecordNamespace::OperatorRecovery) {
            if !key.starts_with(b"idempotency/") {
                continue;
            }
            match decode_recovery_reservation(encoded)? {
                DormantOperatorRecoveryReservationV1::Issued(issued) => {
                    validate_recovery_reservation_key(&issued, key)?;
                    if pending.len() == MAXIMUM_PENDING_OPERATOR_RECOVERIES_V1 {
                        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
                    }
                    pending.push(DormantOperatorRecoveryPendingV1 {
                        issued,
                        reservation_key: key.to_vec(),
                    });
                }
                DormantOperatorRecoveryReservationV1::Complete { issued, result } => {
                    validate_recovery_reservation_key(&issued, key)?;
                    validate_recovery_terminal(&issued.request, &result)?;
                }
            }
        }
        Ok(pending)
    }

    /// Classifies a restart-enumerated effect before deciding whether to redispatch.
    ///
    /// A positive `NotObserved` receipt is the only state that can produce a new
    /// issued handoff. `Unknown` consumes a bounded durable ambiguity query and
    /// never grants effect authority.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] when the pending token is no
    /// longer current or the injected observer returns a mismatched receipt.
    pub fn recover_pending<O>(
        &mut self,
        pending: DormantOperatorRecoveryPendingV1,
        observer: &mut O,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, InvalidObservationClientAdapter>
    where
        O: DormantOperatorRecoveryEffectObserverV1,
    {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        if pending.issued.ambiguity_queries == MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1 {
            return Ok(DormantOperatorRecoveryAdmissionV1::AmbiguityExhausted(
                pending,
            ));
        }
        let retained = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &pending.reservation_key)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let DormantOperatorRecoveryReservationV1::Issued(retained) =
            decode_recovery_reservation(retained)?
        else {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        };
        if retained != pending.issued {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        validate_recovery_reservation_key(&retained, &pending.reservation_key)?;
        let current = self
            .journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(retained.request.resource_id()),
            )
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        if current != retained.current {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        let query = DormantOperatorRecoveryEffectQueryV1 {
            effect_id: retained.effect_id,
            attempt: retained.attempt,
            current_generation: retained.current_generation,
            request: retained.request.to_proto(),
        };
        let receipt = observer.classify(&query)?;
        if receipt.effect_id != retained.effect_id
            || receipt.attempt != retained.attempt
            || receipt.current_generation != retained.current_generation
        {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        match receipt.disposition {
            DormantOperatorRecoveryEffectDispositionV1::Terminal(result) => {
                let handoff = DormantOperatorRecoveryEffectHandoffV1 {
                    issued: retained,
                    reservation_key: pending.reservation_key,
                };
                let terminal = handoff.check_terminal(result)?;
                match self.record_terminal(terminal)? {
                    DormantOperatorRecoveryTerminalCommitV1::Complete(result) => {
                        Ok(DormantOperatorRecoveryAdmissionV1::Terminal(result))
                    }
                    DormantOperatorRecoveryTerminalCommitV1::Ambiguous(terminal) => Ok(
                        DormantOperatorRecoveryAdmissionV1::TerminalCommitAmbiguous(terminal),
                    ),
                }
            }
            DormantOperatorRecoveryEffectDispositionV1::NotObserved => {
                if retained.attempt == MAXIMUM_OPERATOR_RECOVERY_EFFECT_ATTEMPTS_V1 {
                    return Ok(DormantOperatorRecoveryAdmissionV1::DispatchBudgetExhausted(
                        DormantOperatorRecoveryPendingV1 {
                            issued: retained,
                            reservation_key: pending.reservation_key,
                        },
                    ));
                }
                let mut reissued = retained;
                reissued.attempt += 1;
                reissued.ambiguity_queries = 0;
                reissued.recovery_state =
                    DormantOperatorRecoveryDurableStateV1::ReissuedAfterAbsence;
                commit_recovery_records(
                    self.journal,
                    recovery_issued_commit_id(&reissued),
                    vec![JournalRecord::put(
                        RecordNamespace::OperatorRecovery,
                        pending.reservation_key.clone(),
                        encode_issued_recovery_reservation(&reissued)?,
                    )],
                )?;
                Ok(DormantOperatorRecoveryAdmissionV1::Issued(
                    DormantOperatorRecoveryEffectHandoffV1 {
                        issued: reissued,
                        reservation_key: pending.reservation_key,
                    },
                ))
            }
            DormantOperatorRecoveryEffectDispositionV1::Unknown => {
                let mut ambiguous = retained;
                ambiguous.ambiguity_queries = ambiguous
                    .ambiguity_queries
                    .checked_add(1)
                    .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
                ambiguous.recovery_state =
                    DormantOperatorRecoveryDurableStateV1::ObservationUnknown;
                if ambiguous.ambiguity_queries > MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1 {
                    return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
                }
                commit_recovery_records(
                    self.journal,
                    recovery_issued_commit_id(&ambiguous),
                    vec![JournalRecord::put(
                        RecordNamespace::OperatorRecovery,
                        pending.reservation_key.clone(),
                        encode_issued_recovery_reservation(&ambiguous)?,
                    )],
                )?;
                let pending = DormantOperatorRecoveryPendingV1 {
                    issued: ambiguous,
                    reservation_key: pending.reservation_key,
                };
                if pending.issued.ambiguity_queries
                    == MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1
                {
                    Ok(DormantOperatorRecoveryAdmissionV1::AmbiguityExhausted(
                        pending,
                    ))
                } else {
                    Ok(DormantOperatorRecoveryAdmissionV1::Ambiguous(pending))
                }
            }
        }
    }

    /// Records one executor-supplied terminal result and resulting recovery head.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] when protected provenance is
    /// absent or the result fails semantic, identity, or exact binding checks.
    pub(crate) fn record_terminal(
        &mut self,
        terminal: DormantOperatorRecoveryTerminalV1,
    ) -> Result<DormantOperatorRecoveryTerminalCommitV1, InvalidObservationClientAdapter> {
        let handoff = &terminal.handoff;
        let result = &terminal.result;
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let retained_bytes = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &handoff.reservation_key)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?
            .to_vec();
        let retained = match decode_recovery_reservation(&retained_bytes)? {
            DormantOperatorRecoveryReservationV1::Issued(retained) => retained,
            DormantOperatorRecoveryReservationV1::Complete {
                issued,
                result: completed,
            } => {
                if issued != handoff.issued || completed != *result {
                    return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
                }
                let (next_current, completed_reservation) =
                    recovery_terminal_records(&issued, result)?;
                let transition_key =
                    recovery_transition_key(issued.request.resource_id(), &result.resource_version);
                if self.journal.get(
                    RecordNamespace::OperatorRecovery,
                    &recovery_current_key(issued.request.resource_id()),
                ) != Some(next_current.as_slice())
                    || self
                        .journal
                        .get(RecordNamespace::OperatorRecovery, &transition_key)
                        != Some(completed_reservation.as_slice())
                {
                    return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
                }
                return Ok(DormantOperatorRecoveryTerminalCommitV1::Complete(
                    terminal.result,
                ));
            }
        };
        if retained != handoff.issued {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        let current_key = recovery_current_key(handoff.issued.request.resource_id());
        let protected_current = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &current_key)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?
            .to_vec();
        validate_recovery_current(&handoff.issued.request, &protected_current)?;
        validate_recovery_terminal(&handoff.issued.request, result)?;
        if protected_current != handoff.issued.current {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        let (next_current, completed_reservation) =
            recovery_terminal_records(&handoff.issued, result)?;
        let records = vec![
            JournalRecord::put(RecordNamespace::OperatorRecovery, current_key, next_current),
            JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                handoff.reservation_key.clone(),
                completed_reservation.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                recovery_transition_key(
                    handoff.issued.request.resource_id(),
                    &result.resource_version,
                ),
                completed_reservation,
            ),
        ];
        if commit_recovery_records(
            self.journal,
            recovery_terminal_commit_id(&handoff.issued, result),
            records,
        )
        .is_err()
        {
            return Ok(DormantOperatorRecoveryTerminalCommitV1::Ambiguous(terminal));
        }
        Ok(DormantOperatorRecoveryTerminalCommitV1::Complete(
            terminal.result,
        ))
    }

    /// Synchronizes a fully checked current sandbox head into protected authority.
    pub(crate) fn synchronize_sandbox(
        &mut self,
        resource: &CheckedSandboxResourceV1,
    ) -> Result<(), InvalidObservationClientAdapter> {
        let allowed = (u8::from(resource.has_true_condition(PublicConditionCodeV1::Blocked))
            | u8::from(resource.has_true_condition(PublicConditionCodeV1::Degraded))
            | u8::from(resource.has_true_condition(PublicConditionCodeV1::ResidualState))
            | u8::from(resource.has_true_condition(PublicConditionCodeV1::OwnershipPending)))
            * 4
            | (u8::from(resource.has_true_condition(PublicConditionCodeV1::Fenced))
                | u8::from(resource.has_true_condition(PublicConditionCodeV1::Blocked)))
                * 8;
        synchronize_recovery_current(
            self.journal,
            resource.sandbox_id(),
            &resource.as_proto().resource_version,
            1,
            allowed,
            resource.desired_generation(),
            resource.observation_sequence(),
            latest_recovery_transition(
                resource.conditions(),
                resource
                    .as_proto()
                    .updated_at
                    .as_option()
                    .map(|timestamp| (timestamp.seconds, timestamp.nanoseconds)),
            )?,
        )
    }

    /// Synchronizes a fully checked current operation head into protected authority.
    pub(crate) fn synchronize_operation(
        &mut self,
        resource: &CheckedOperationResourceV1,
    ) -> Result<(), InvalidObservationClientAdapter> {
        let retry = resource.phase() == CheckedOperationPhaseV1::FailedBeforeCommit
            && resource.retry() != CheckedRetryClassV1::Never;
        let abandon = matches!(
            resource.phase(),
            CheckedOperationPhaseV1::PermanentlyBlocked
                | CheckedOperationPhaseV1::CommittedWithResidualCleanup
        );
        synchronize_recovery_current(
            self.journal,
            resource.operation_id(),
            resource.resource_version().as_bytes(),
            2,
            u8::from(retry) | u8::from(abandon) * 2,
            resource.as_proto().accepted_generation,
            resource
                .conditions()
                .iter()
                .map(|condition| condition.as_proto().observation_sequence)
                .max()
                .filter(|sequence| *sequence != 0)
                .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
            latest_recovery_transition(
                resource.conditions(),
                resource
                    .as_proto()
                    .accepted_at
                    .as_option()
                    .map(|timestamp| (timestamp.seconds, timestamp.nanoseconds)),
            )?,
        )
    }
}

fn recovery_current_key(resource_id: [u8; 16]) -> Vec<u8> {
    [b"current/".as_slice(), resource_id.as_slice()].concat()
}

fn recovery_reservation_key(principal: &[u8; 32], idempotency_key: &[u8]) -> Vec<u8> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.operator-recovery-idempotency.v1\0")
        .chain_update(principal)
        .chain_update((idempotency_key.len() as u64).to_be_bytes())
        .chain_update(idempotency_key)
        .finalize()
        .into();
    [b"idempotency/".as_slice(), digest.as_slice()].concat()
}

fn recovery_transition_key(resource_id: [u8; 16], next_version: &[u8]) -> Vec<u8> {
    let version_digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.operator-recovery-version-key.v1\0")
        .chain_update((next_version.len() as u64).to_be_bytes())
        .chain_update(next_version)
        .finalize()
        .into();
    [
        b"transition/".as_slice(),
        resource_id.as_slice(),
        b"/".as_slice(),
        version_digest.as_slice(),
    ]
    .concat()
}

const RECOVERY_ISSUED_MAGIC: &[u8; 8] = b"AOSORI1\0";
const RECOVERY_COMPLETE_MAGIC: &[u8; 8] = b"AOSORC1\0";
const MAXIMUM_OPERATOR_RECOVERY_RECORD_BYTES_V1: usize = 128 * 1024;

enum DormantOperatorRecoveryReservationV1 {
    Issued(DormantOperatorRecoveryIssuedStateV1),
    Complete {
        issued: DormantOperatorRecoveryIssuedStateV1,
        result: aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
    },
}

fn recovery_effect_id(
    principal: ObjectDigest,
    request: &OperatorRecoveryRequestV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.operator-recovery-effect.v1\0")
            .chain_update(principal.as_bytes())
            .chain_update(request.authority_binding().as_bytes())
            .finalize()
            .into(),
    )
}

fn recovery_issued_commit_id(issued: &DormantOperatorRecoveryIssuedStateV1) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.operator-recovery-issued-commit.v1\0")
            .chain_update(issued.effect_id.as_bytes())
            .chain_update(issued.attempt.to_be_bytes())
            .chain_update(issued.ambiguity_queries.to_be_bytes())
            .finalize()
            .into(),
    )
}

fn recovery_terminal_commit_id(
    issued: &DormantOperatorRecoveryIssuedStateV1,
    result: &aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.operator-recovery-terminal-commit.v1\0")
            .chain_update(issued.effect_id.as_bytes())
            .chain_update(issued.attempt.to_be_bytes())
            .chain_update((result.resource_version.len() as u64).to_be_bytes())
            .chain_update(&result.resource_version)
            .finalize()
            .into(),
    )
}

fn encode_issued_recovery_reservation(
    issued: &DormantOperatorRecoveryIssuedStateV1,
) -> Result<Vec<u8>, InvalidObservationClientAdapter> {
    let request = issued.request.to_proto().encode_to_vec();
    let request_length = u32::try_from(request.len())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let current_length = u32::try_from(issued.current.len())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let current_head = decode_recovery_current(&issued.current)?;
    if issued.binding != issued.request.authority_binding()
        || issued.effect_id != recovery_effect_id(issued.principal, &issued.request)
        || issued.current_generation != current_head.desired_generation
        || issued.attempt == 0
        || issued.attempt > MAXIMUM_OPERATOR_RECOVERY_EFFECT_ATTEMPTS_V1
        || issued.ambiguity_queries > MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1
        || !matches!(
            (
                issued.recovery_state,
                issued.attempt,
                issued.ambiguity_queries
            ),
            (DormantOperatorRecoveryDurableStateV1::InitialIssue, 1, 0)
                | (
                    DormantOperatorRecoveryDurableStateV1::ReissuedAfterAbsence,
                    2..=MAXIMUM_OPERATOR_RECOVERY_EFFECT_ATTEMPTS_V1,
                    0
                )
                | (
                    DormantOperatorRecoveryDurableStateV1::ObservationUnknown,
                    _,
                    1..=MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1
                )
        )
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    validate_recovery_current(&issued.request, &issued.current)?;
    let encoded_length = 136_usize
        .checked_add(request.len())
        .and_then(|length| length.checked_add(issued.current.len()))
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if encoded_length > MAXIMUM_OPERATOR_RECOVERY_RECORD_BYTES_V1 {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let mut encoded = Vec::with_capacity(encoded_length);
    encoded.extend_from_slice(RECOVERY_ISSUED_MAGIC);
    encoded.extend_from_slice(issued.principal.as_bytes());
    encoded.extend_from_slice(issued.binding.as_bytes());
    encoded.extend_from_slice(issued.effect_id.as_bytes());
    encoded.extend_from_slice(&issued.attempt.to_be_bytes());
    encoded.extend_from_slice(&issued.ambiguity_queries.to_be_bytes());
    encoded.extend_from_slice(&issued.recovery_state.to_wire().to_be_bytes());
    encoded.extend_from_slice(&issued.request.action().to_be_bytes());
    encoded.extend_from_slice(&issued.current_generation.to_be_bytes());
    encoded.extend_from_slice(&request_length.to_be_bytes());
    encoded.extend_from_slice(&current_length.to_be_bytes());
    encoded.extend_from_slice(&request);
    encoded.extend_from_slice(&issued.current);
    Ok(encoded)
}

fn encode_completed_recovery_reservation(
    issued: &DormantOperatorRecoveryIssuedStateV1,
    result: &aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
) -> Result<Vec<u8>, InvalidObservationClientAdapter> {
    validate_recovery_terminal(&issued.request, result)?;
    let issued = encode_issued_recovery_reservation(issued)?;
    let result = result.encode_to_vec();
    let issued_length = u32::try_from(issued.len())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let result_length = u32::try_from(result.len())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let encoded_length = 16_usize
        .checked_add(issued.len())
        .and_then(|length| length.checked_add(result.len()))
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if encoded_length > MAXIMUM_OPERATOR_RECOVERY_RECORD_BYTES_V1 {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let mut encoded = Vec::with_capacity(encoded_length);
    encoded.extend_from_slice(RECOVERY_COMPLETE_MAGIC);
    encoded.extend_from_slice(&issued_length.to_be_bytes());
    encoded.extend_from_slice(&issued);
    encoded.extend_from_slice(&result_length.to_be_bytes());
    encoded.extend_from_slice(&result);
    Ok(encoded)
}

fn decode_recovery_reservation(
    encoded: &[u8],
) -> Result<DormantOperatorRecoveryReservationV1, InvalidObservationClientAdapter> {
    if encoded.len() > MAXIMUM_OPERATOR_RECOVERY_RECORD_BYTES_V1 {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    if encoded.get(..8) == Some(RECOVERY_ISSUED_MAGIC.as_slice()) {
        return decode_issued_recovery_reservation(encoded)
            .map(DormantOperatorRecoveryReservationV1::Issued);
    }
    if encoded.len() < 16 || encoded.get(..8) != Some(RECOVERY_COMPLETE_MAGIC.as_slice()) {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let issued_length = u32::from_be_bytes(
        encoded[8..12]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ) as usize;
    let issued_end = 12_usize
        .checked_add(issued_length)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let result_length_end = issued_end
        .checked_add(4)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if encoded.len() < result_length_end {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let result_length = u32::from_be_bytes(
        encoded[issued_end..result_length_end]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ) as usize;
    let result_end = result_length_end
        .checked_add(result_length)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if result_end != encoded.len() {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let issued = decode_issued_recovery_reservation(&encoded[12..issued_end])?;
    let result = aos_proto::aos::sandbox::v1::OperatorRecoveryResult::decode_from_slice(
        &encoded[result_length_end..result_end],
    )
    .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if result.encode_to_vec() != encoded[result_length_end..result_end] {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    validate_recovery_terminal(&issued.request, &result)?;
    Ok(DormantOperatorRecoveryReservationV1::Complete { issued, result })
}

fn decode_issued_recovery_reservation(
    encoded: &[u8],
) -> Result<DormantOperatorRecoveryIssuedStateV1, InvalidObservationClientAdapter> {
    if encoded.len() < 136 || encoded.get(..8) != Some(RECOVERY_ISSUED_MAGIC.as_slice()) {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let principal = ObjectDigest::from_bytes(
        encoded[8..40]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let binding = ObjectDigest::from_bytes(
        encoded[40..72]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let effect_id = ObjectDigest::from_bytes(
        encoded[72..104]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let attempt = u32::from_be_bytes(
        encoded[104..108]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let ambiguity_queries = u32::from_be_bytes(
        encoded[108..112]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let recovery_state = DormantOperatorRecoveryDurableStateV1::from_wire(u32::from_be_bytes(
        encoded[112..116]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ))
    .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let action = i32::from_be_bytes(
        encoded[116..120]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let current_generation = u64::from_be_bytes(
        encoded[120..128]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let request_length = u32::from_be_bytes(
        encoded[128..132]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ) as usize;
    let current_length = u32::from_be_bytes(
        encoded[132..136]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ) as usize;
    let request_end = 136_usize
        .checked_add(request_length)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let current_end = request_end
        .checked_add(current_length)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if current_end != encoded.len() {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let request_proto = aos_proto::aos::sandbox::v1::OperatorRecoveryRequest::decode_from_slice(
        &encoded[136..request_end],
    )
    .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if request_proto.encode_to_vec() != encoded[136..request_end] {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let request = OperatorRecoveryRequestV1::try_from(request_proto)?;
    let issued = DormantOperatorRecoveryIssuedStateV1 {
        principal,
        binding,
        effect_id,
        request,
        current: encoded[request_end..current_end].to_vec(),
        current_generation,
        attempt,
        ambiguity_queries,
        recovery_state,
    };
    if action != issued.request.action() || encode_issued_recovery_reservation(&issued)? != encoded
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    Ok(issued)
}

fn validate_recovery_reservation_key(
    issued: &DormantOperatorRecoveryIssuedStateV1,
    key: &[u8],
) -> Result<(), InvalidObservationClientAdapter> {
    if key
        != recovery_reservation_key(
            issued.principal.as_bytes(),
            issued.request.idempotency_key(),
        )
    {
        Err(InvalidObservationClientAdapter::InvalidOperatorRecovery)
    } else {
        Ok(())
    }
}

fn validate_recovery_replay(
    issued: &DormantOperatorRecoveryIssuedStateV1,
    principal: ObjectDigest,
    binding: ObjectDigest,
    effect_id: ObjectDigest,
    request: &OperatorRecoveryRequestV1,
    reservation_key: &[u8],
) -> Result<(), InvalidObservationClientAdapter> {
    validate_recovery_reservation_key(issued, reservation_key)?;
    if issued.principal != principal
        || issued.binding != binding
        || issued.effect_id != effect_id
        || &issued.request != request
    {
        Err(InvalidObservationClientAdapter::InvalidOperatorRecovery)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveryCurrentHeadV1 {
    kind: u8,
    allowed_actions: u8,
    version: Vec<u8>,
    desired_generation: u64,
    observation_sequence: u64,
    transition: (i64, u32),
}

fn latest_recovery_transition(
    conditions: &[crate::controller_query::CheckedConditionV1],
    fallback: Option<(i64, u32)>,
) -> Result<(i64, u32), InvalidObservationClientAdapter> {
    conditions
        .iter()
        .map(crate::controller_query::CheckedConditionV1::transition)
        .chain(fallback)
        .max()
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)
}

fn encode_recovery_current(
    kind: u8,
    allowed_actions: u8,
    version: &[u8],
    desired_generation: u64,
    observation_sequence: u64,
    transition: (i64, u32),
) -> Result<Vec<u8>, InvalidObservationClientAdapter> {
    if !matches!(kind, 1 | 2)
        || version.is_empty()
        || desired_generation == 0
        || observation_sequence == 0
        || transition.1 >= 1_000_000_000
        || !(-62_135_596_800..=253_402_300_799).contains(&transition.0)
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let version_len = u32::try_from(version.len())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let mut value = Vec::with_capacity(34 + version.len());
    value.extend_from_slice(&[kind, allowed_actions]);
    value.extend_from_slice(&version_len.to_be_bytes());
    value.extend_from_slice(version);
    value.extend_from_slice(&desired_generation.to_be_bytes());
    value.extend_from_slice(&observation_sequence.to_be_bytes());
    value.extend_from_slice(&transition.0.to_be_bytes());
    value.extend_from_slice(&transition.1.to_be_bytes());
    Ok(value)
}

fn decode_recovery_current(
    current: &[u8],
) -> Result<RecoveryCurrentHeadV1, InvalidObservationClientAdapter> {
    if current.len() < 35 {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let version_len = u32::from_be_bytes(
        current[2..6]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ) as usize;
    let version_end = 6_usize
        .checked_add(version_len)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if current.len() != version_end + 28 {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let desired_generation = u64::from_be_bytes(
        current[version_end..version_end + 8]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let observation_sequence = u64::from_be_bytes(
        current[version_end + 8..version_end + 16]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let seconds = i64::from_be_bytes(
        current[version_end + 16..version_end + 24]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let nanoseconds = u32::from_be_bytes(
        current[version_end + 24..version_end + 28]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    encode_recovery_current(
        current[0],
        current[1],
        &current[6..version_end],
        desired_generation,
        observation_sequence,
        (seconds, nanoseconds),
    )?;
    Ok(RecoveryCurrentHeadV1 {
        kind: current[0],
        allowed_actions: current[1],
        version: current[6..version_end].to_vec(),
        desired_generation,
        observation_sequence,
        transition: (seconds, nanoseconds),
    })
}

fn synchronize_recovery_current(
    journal: &mut crate::Journal,
    resource_id: [u8; 16],
    version: &[u8],
    kind: u8,
    allowed_actions: u8,
    desired_generation: u64,
    observation_sequence: u64,
    transition: (i64, u32),
) -> Result<(), InvalidObservationClientAdapter> {
    journal
        .ensure_protected_authority()
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let value = encode_recovery_current(
        kind,
        allowed_actions,
        version,
        desired_generation,
        observation_sequence,
        transition,
    )?;
    let current_key = recovery_current_key(resource_id);
    if let Some(existing) = journal.get(RecordNamespace::OperatorRecovery, &current_key) {
        if existing == value.as_slice() {
            return Ok(());
        }
        let existing = decode_recovery_current(existing)?;
        if existing.kind != kind
            || observation_sequence <= existing.observation_sequence
            || desired_generation < existing.desired_generation
            || transition < existing.transition
        {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
    }
    let digest = ObjectDigest::from_bytes(Sha256::digest(&value).into());
    commit_recovery_records(
        journal,
        digest,
        vec![JournalRecord::put(
            RecordNamespace::OperatorRecovery,
            current_key,
            value,
        )],
    )
}

fn validate_recovery_current(
    request: &OperatorRecoveryRequestV1,
    current: &[u8],
) -> Result<(), InvalidObservationClientAdapter> {
    let head = decode_recovery_current(current)?;
    if head.version.as_slice() != request.expected_resource_version()
        || head.allowed_actions & (1_u8 << (request.action() - 1)) == 0
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let evidence = request.evidence();
    let expected_digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.operator-recovery-current-evidence.v1\0")
        .chain_update(request.resource_id())
        .chain_update((current.len() as u64).to_be_bytes())
        .chain_update(current)
        .finalize()
        .into();
    if evidence.media_type != "application/vnd.aos.sandbox.operator-recovery-evidence.v1"
        || evidence.sha256 != expected_digest
        || evidence.encoded_size != (16 + current.len()) as u64
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    Ok(())
}

fn validate_recovery_terminal(
    request: &OperatorRecoveryRequestV1,
    result: &aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
) -> Result<(), InvalidObservationClientAdapter> {
    if result.resource_id.as_slice() != request.resource_id()
        || result.action.to_i32() != request.action()
        || result.resource_version.is_empty()
        || result.resource_version.len() > crate::cli_model::MAXIMUM_CLI_OPAQUE_BYTES
        || result.resource_version == request.expected_resource_version()
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    crate::cli_model::CheckedOperatorRecoveryResultV1::try_from(result.clone())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    Ok(())
}

fn recovery_terminal_records(
    issued: &DormantOperatorRecoveryIssuedStateV1,
    result: &aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
) -> Result<(Vec<u8>, Vec<u8>), InvalidObservationClientAdapter> {
    validate_recovery_terminal(&issued.request, result)?;
    let current_head = decode_recovery_current(&issued.current)?;
    let desired_generation = result
        .conditions
        .iter()
        .map(|condition| condition.desired_generation)
        .max()
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let observation_sequence = result
        .conditions
        .iter()
        .map(|condition| condition.observation_sequence)
        .max()
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let transition = result
        .conditions
        .iter()
        .filter_map(|condition| condition.transition_time.as_option())
        .map(|timestamp| (timestamp.seconds, timestamp.nanoseconds))
        .max()
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if result.resource_version == current_head.version
        || desired_generation < current_head.desired_generation
        || observation_sequence <= current_head.observation_sequence
        || transition < current_head.transition
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let next_current = encode_recovery_current(
        current_head.kind,
        0,
        &result.resource_version,
        desired_generation,
        observation_sequence,
        transition,
    )?;
    let completed = encode_completed_recovery_reservation(issued, result)?;
    Ok((next_current, completed))
}

fn commit_recovery_records(
    journal: &mut crate::Journal,
    binding: ObjectDigest,
    records: Vec<JournalRecord>,
) -> Result<(), InvalidObservationClientAdapter> {
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&binding.as_bytes()[..16]);
    if transaction_id == [0; 16] {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let transaction = JournalTransaction::new(transaction_id, records)
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    match journal.commit(&transaction) {
        Ok(_) => Ok(()),
        Err(_)
            if transaction
                .records()
                .iter()
                .all(|record| journal.get(record.namespace(), record.key()) == record.value()) =>
        {
            Ok(())
        }
        Err(_) => Err(InvalidObservationClientAdapter::InvalidOperatorRecovery),
    }
}

/// Borrows the controller's sole protected journal for dormant CLI authorization.
///
/// Only [`NodeController::dormant_cli_authorization`] constructs this owner.
/// It cannot be redirected to a caller-selected journal and exposes no journal
/// accessor, command registration, route, or effect-dispatch operation. Its
/// fixed clock owner reads only kernel realtime, BOOTTIME, and boot identity;
/// callers cannot supply samples or replace its source.
#[cfg(target_os = "linux")]
#[must_use = "the dormant CLI authorization owner must be used while borrowed"]
pub(crate) struct DormantCliAuthorizationOwnerV1<'controller> {
    journal: &'controller mut crate::Journal,
    protected_clock: ControllerProtectedClockV1,
}

#[cfg(target_os = "linux")]
impl DormantCliAuthorizationOwnerV1<'_> {
    /// Authenticates and routes one mutation with retained sealed authority.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError`] unless the authenticated payload,
    /// protected authorization head, resolver result, and routed protobuf agree.
    pub(crate) fn authorize_routed_mutation<F>(
        &mut self,
        authenticated: &crate::local_sessions::AuthenticatedLocalRecord<'_>,
        output: DormantSandboxOutputV1,
        client_state: DormantClientStatePlanV1,
        resolve: F,
    ) -> Result<DormantSandboxRequestV1, CliAuthorizationAdapterError>
    where
        F: FnOnce(
            &DecodedAuthenticatedCliRequestV1,
            &RequestProvenanceV1,
        ) -> ResolvedPublicMutationV1,
    {
        let authorized = self.authorize_mutation(authenticated, resolve)?;
        DormantSandboxRequestV1::from_authorized_mutation(authorized, output, client_state)
            .map_err(|_| CliAuthorizationAdapterError::MutationBindingMismatch)
    }

    /// Authenticates and authorizes one exact protected operator-recovery request.
    pub(crate) fn authorize_operator_recovery(
        &mut self,
        authenticated: &crate::local_sessions::AuthenticatedLocalRecord<'_>,
        request: OperatorRecoveryRequestV1,
    ) -> Result<AuthorizedOperatorRecoveryV1, CliAuthorizationAdapterError> {
        self.authenticate_request(authenticated)?
            .authorize_operator_recovery(request)
    }

    /// Authenticates, currently authorizes, resolves, and seals one CLI mutation.
    ///
    /// The authenticated local record supplies every transport identity. The
    /// resolver receives only the nonforgeable provenance created after exact
    /// request and protected-state binding, allowing it to construct required
    /// action-specific fences before the same one-shot authority is consumed.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError`] when live transport rechecking,
    /// protected current authorization, exact binding, or mutation fencing fails.
    pub(crate) fn authorize_mutation<F>(
        &mut self,
        authenticated: &crate::local_sessions::AuthenticatedLocalRecord<'_>,
        resolve: F,
    ) -> Result<AuthorizedResolvedMutationV1, CliAuthorizationAdapterError>
    where
        F: FnOnce(
            &DecodedAuthenticatedCliRequestV1,
            &RequestProvenanceV1,
        ) -> ResolvedPublicMutationV1,
    {
        let request = self.authenticate_request(authenticated)?;
        let mutation = resolve(request.decoded_request(), request.mutation_provenance()?);
        request.authorize_mutation(mutation)
    }

    /// Authenticates and currently authorizes one exact CLI audit request.
    ///
    /// # Errors
    ///
    /// Returns [`CliAuthorizationAdapterError`] when live transport rechecking,
    /// protected current authorization, exact binding, or surface checks fail.
    pub(crate) fn authorize_audit(
        &mut self,
        authenticated: &crate::local_sessions::AuthenticatedLocalRecord<'_>,
    ) -> Result<AuditAuthorizationV1, CliAuthorizationAdapterError> {
        self.authenticate_request(authenticated)?.authorize_audit()
    }

    fn authenticate_request(
        &mut self,
        authenticated: &crate::local_sessions::AuthenticatedLocalRecord<'_>,
    ) -> Result<DormantAuthenticatedCliRequestV1, CliAuthorizationAdapterError> {
        authenticated
            .recheck_execution_scope()
            .map_err(|_| CliAuthorizationAdapterError::InvalidAuthenticatedEvidence)?;

        let principal = authenticated.scope().holder;
        let session_id = authenticated.session_id();
        let decoded =
            DecodedAuthenticatedCliRequestV1::decode_authenticated(authenticated.payload())?;
        let identity =
            AuthenticatedCliIdentityEvidenceV1::from_verified_transport_identity(principal)?;
        let session = AuthenticatedCliSessionEvidenceV1::from_verified_session(
            principal,
            session_id.as_bytes(),
        )?;
        let channel = AuthenticatedCliChannelEvidenceV1::from_verified_channel(
            principal,
            session_id.as_bytes(),
            authenticated.channel_binding(),
            authenticated.payload(),
            DORMANT_CLI_OBSERVATION_SCHEMA_V1,
        )?;
        let authorization = CurrentProtectedCliAuthorizationV1::from_current_protected_capability(
            self.journal,
            PublisherAuthorityLimits::default(),
            PublisherPolicyLimits::default(),
            authenticated.capability_id(),
            authenticated.scope().project,
            &mut self.protected_clock,
            &decoded,
            &identity,
            &channel,
        )?;

        DormantAuthenticatedCliRequestV1::bind(decoded, identity, session, channel, authorization)
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct ControllerProtectedClockV1 {
    provenance: aos_sandbox_core::RawClockProvenance,
    host_boot_id: [u8; 16],
}

#[cfg(target_os = "linux")]
impl ControllerProtectedClockV1 {
    fn open_fixed() -> Result<Self, crate::ProtectedOwnershipClockError> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|_| crate::ProtectedOwnershipClockError)?;
        let compact = boot_id.trim().replace('-', "");
        if compact.len() != 32 {
            return Err(crate::ProtectedOwnershipClockError);
        }
        let mut host_boot_id = [0_u8; 16];
        for (target, pair) in host_boot_id
            .iter_mut()
            .zip(compact.as_bytes().chunks_exact(2))
        {
            let high = fixed_hex_nibble(pair[0]).ok_or(crate::ProtectedOwnershipClockError)?;
            let low = fixed_hex_nibble(pair[1]).ok_or(crate::ProtectedOwnershipClockError)?;
            *target = (high << 4) | low;
        }
        let provenance = aos_sandbox_core::RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1")
            .map_err(|_| crate::ProtectedOwnershipClockError)?;

        Ok(Self {
            provenance,
            host_boot_id,
        })
    }

    pub(crate) fn sample(
        &mut self,
    ) -> Result<RawPairedClockSample, crate::ProtectedOwnershipClockError> {
        let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        let boottime_nanoseconds = u64::try_from(boottime.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|value| {
                u64::try_from(boottime.tv_nsec)
                    .ok()
                    .and_then(|nanoseconds| value.checked_add(nanoseconds))
            })
            .ok_or(crate::ProtectedOwnershipClockError)?;

        RawPairedClockSample::new_untrusted(
            self.provenance,
            self.host_boot_id,
            realtime.tv_sec,
            boottime_nanoseconds,
        )
        .map_err(|_| crate::ProtectedOwnershipClockError)
    }
}

#[cfg(target_os = "linux")]
const fn fixed_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Borrows the sole protected journal for a dormant operator-recovery transition.
    ///
    /// The returned owner dispatches no runtime action and registers no route;
    /// it may only maintain protected recovery authority and transition records.
    pub(crate) fn dormant_operator_recovery(&mut self) -> DormantOperatorRecoveryOwnerV1<'_> {
        DormantOperatorRecoveryOwnerV1 {
            journal: self.reconciler.journal_mut(),
        }
    }

    /// Borrows protected effect progress for the dormant observability producer seam.
    pub(crate) fn dormant_observability(
        &mut self,
    ) -> crate::controller_query::observability::DormantObservabilityProtectedOwnerV1<'_> {
        crate::controller_query::observability::DormantObservabilityProtectedOwnerV1::new(
            self.reconciler.journal_mut(),
        )
    }

    /// Constructs the unregistered protected observability service from selected sinks.
    pub(crate) fn dormant_observability_service<R, X, H, I>(
        &mut self,
        recorder: R,
        exporter: X,
        health: H,
        inventory: I,
    ) -> crate::controller_query::observability::DormantObservabilityServiceV1<'_, R, X, H, I>
    where
        R: crate::controller_query::observability::DormantObservationRecorderV1,
        X: crate::controller_query::observability::DormantMetricExporterV1,
        H: crate::controller_query::observability::DormantHealthApiV1,
        I: crate::controller_query::observability::DormantResidualInventoryApiV1,
    {
        crate::controller_query::observability::DormantObservabilityServiceV1::new(
            self.reconciler.journal_mut(),
            recorder,
            exporter,
            health,
            inventory,
        )
    }

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

    /// Borrows the sole controller journal for dormant authenticated CLI requests.
    ///
    /// This source-only factory registers no public command or route and grants
    /// no effect authority. The returned owner derives CLI provenance from
    /// an authenticated local-session record or a live registered public TLS
    /// peer, the fixed controller-owned paired clock, and current protected
    /// state. Both paths bind the capability to the authenticated project.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedOwnershipClockError`](crate::ProtectedOwnershipClockError)
    /// when the fixed kernel boot identity cannot be read or validated.
    #[cfg(target_os = "linux")]
    pub(crate) fn dormant_cli_authorization(
        &mut self,
    ) -> Result<DormantCliAuthorizationOwnerV1<'_>, crate::ProtectedOwnershipClockError> {
        Ok(DormantCliAuthorizationOwnerV1 {
            journal: self.reconciler.journal_mut(),
            protected_clock: ControllerProtectedClockV1::open_fixed()?,
        })
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

    /// Acquires current assignment authority without requiring a live payload.
    ///
    /// This pre-launch target derives its sandbox, incarnation, namespace
    /// generation, specification, lease, and node from protected current state.
    /// It carries no process, root, or namespace descriptor and cannot establish
    /// runtime readiness. Destination-slot preparation uses it before Host starts
    /// the payload.
    ///
    /// # Errors
    ///
    /// Rejects absent, revoked, rebound, or malformed holder state, invalid
    /// signatures or clocks, an unavailable current publication, and an empty
    /// fixed validity window.
    #[cfg(target_os = "linux")]
    pub(crate) fn acquire_current_assignment_target<T>(
        &mut self,
        holder: crate::runtime_scope::RuntimeScopeHolder,
        policy: crate::runtime_scope::CurrentRuntimeScopePolicy,
        clock: &mut T,
    ) -> Result<
        crate::runtime_scope::CurrentAssignmentTarget,
        crate::runtime_scope::CurrentRuntimeScopeError,
    >
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::runtime_scope::acquire_current_assignment(
            self.reconciler.journal_mut(),
            holder,
            policy,
            clock,
        )
    }

    /// Observes the protected current runtime of an authenticated holder.
    ///
    /// Trusted deployment supplies the Host connection, trust anchors, and
    /// protected paired-clock adapter. The selector supplies no assignment,
    /// lease, plan, or cgroup facts; these derive from current protected state
    /// and a kernel-subject-correlated Host exchange under one exclusive journal
    /// borrow.
    /// Success does not issue a channel or authorize publication.
    ///
    /// # Errors
    ///
    /// Rejects absent/revoked/substituted holders, corrupt current state,
    /// invalid signatures or clocks, missing Host grants, broker denial, and
    /// stale or substituted kernel execution observations.
    #[cfg(target_os = "linux")]
    pub(crate) fn observe_current_runtime<T>(
        &mut self,
        holder: crate::runtime_scope::RuntimeScopeHolder,
        client: crate::runtime_scope::RuntimeScopeClient,
        policy: crate::runtime_scope::CurrentRuntimeScopePolicy,
        clock: &mut T,
    ) -> Result<
        crate::runtime_scope::CurrentRuntimeScope,
        crate::runtime_scope::CurrentRuntimeScopeError,
    >
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::runtime_scope::acquire_current_runtime(
            self.reconciler.journal_mut(),
            holder,
            client,
            policy,
            clock,
        )
    }

    /// Rechecks an acquired runtime against current authority and its fixed deadline.
    ///
    /// The callback must read the same protected paired-clock adapter used at
    /// acquisition. Renewal or any holder revision change requires a new Host
    /// observation; successful rechecks never extend the original lifetime.
    /// This read-only operation grants no endpoint or publication permission.
    ///
    /// # Errors
    ///
    /// Rejects current-state changes, signature or clock failures, elapsed
    /// deadlines, and stale retained Host or payload executions.
    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_current_runtime<T>(
        &mut self,
        scope: &crate::runtime_scope::CurrentRuntimeScope,
        clock: &mut T,
    ) -> Result<(), crate::runtime_scope::CurrentRuntimeScopeError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        scope.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Joins current controller assignment authority to one lifecycle rebuild.
    ///
    /// The returned evidence borrows this controller, the fixed lifecycle
    /// owner, and the acquired assignment. Controller currentness and the
    /// paired clock are checked on both sides of lifecycle binding, so a
    /// caller cannot substitute a boot-inventory scalar for the actual current
    /// assignment head.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecyclePhase6ErrorV1`] when assignment
    /// currentness changes, the clock expires, or the lifecycle operation does
    /// not bind the exact assignment and target.
    #[cfg(target_os = "linux")]
    pub(crate) fn current_lifecycle_target_assignment<'current, T>(
        &'current mut self,
        lifecycle: &'current crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        assignment: &'current crate::runtime_scope::CurrentAssignmentTarget,
        target: aos_sandbox_core::SandboxId,
        clock: &mut T,
    ) -> Result<
        crate::lifecycle::CurrentLifecycleTargetAssignmentV1<'current>,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    >
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        assignment
            .recheck(self.reconciler.journal_mut(), clock)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let current = lifecycle
            .bind_current_target_assignment(operation_key, assignment, target)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        assignment
            .recheck(self.reconciler.journal_mut(), clock)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        Ok(current)
    }

    /// Joins a freshly sampled kernel boot and live Host runtime to Resume.
    ///
    /// This boundary samples the fixed kernel boot identity around two full
    /// protected runtime rechecks. The lifetime-bound result therefore cannot
    /// be reconstructed from a caller-selected historical boot inventory.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecyclePhase6ErrorV1`] for boot rollover,
    /// expired or replaced runtime authority, failed Host liveness, or an
    /// operation/fence mismatch.
    #[cfg(target_os = "linux")]
    pub(crate) fn current_lifecycle_runtime_liveness<'current, T>(
        &'current mut self,
        lifecycle: &'current crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        runtime: &'current crate::runtime_scope::CurrentRuntimeScope,
        clock: &mut T,
    ) -> Result<
        crate::lifecycle::CurrentLifecycleRuntimeLivenessV1<'current>,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    >
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        let boot_before = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        runtime
            .recheck(self.reconciler.journal_mut(), clock)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let current = lifecycle
            .bind_current_runtime_liveness(operation_key, runtime, boot_before)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        runtime
            .recheck(self.reconciler.journal_mut(), clock)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let boot_after = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != boot_after {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(current)
    }

    /// Joins all six protected current inventories for LIFE-06 planning.
    ///
    /// Runtime, Mount, Storage, and Network arrive as opaque adjacent outcome
    /// pairs minted from their fixed protected broker-session exchanges. Each
    /// pair preserves complete state and advances both traffic sequences by
    /// exactly one; retained historical or no-op rechecks are rejected.
    /// Storage's signed body includes its complete
    /// dataset/snapshot/clone/hold/quota projection. Cache and the complete
    /// zero-or-many transfer set are replayed by their fixed protected owners.
    /// The fixed kernel boot is sampled around the join and every commitment
    /// must match the lifecycle boot record.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecyclePhase6ErrorV1`] when any inventory
    /// is incomplete, stale, foreign to the current boot, replaced during the
    /// join, or mismatched with the operation-bound lifecycle aggregate.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn current_lifecycle_boot_domains<'current>(
        &'current mut self,
        lifecycle: &'current crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        runtime: &'current crate::lifecycle::LifecycleAuthenticatedRuntimeInventorySuccessorV1,
        mounts: &'current crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventorySuccessorV1,
        storage: &'current crate::DurableStorageResourceInventorySnapshotV1,
        storage_inventory: &'current crate::lifecycle::LifecycleAuthenticatedStorageInventorySuccessorV1,
        network: &'current crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventorySuccessorV1,
        cache: &'current mut crate::cache_residency::CacheResidencyProtectedOwnerV1,
        transfer: &'current mut crate::multi_node::ProtectedMultiNodeAuthorityOwnerV1,
        transfer_inventory: &'current crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1,
    ) -> Result<
        crate::lifecycle::CurrentLifecycleBootDomainInventoriesV1<'current>,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    > {
        let boot_before = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        let runtime_inventory = runtime.initial();
        let runtime_inventory_after = runtime.current();
        if runtime.boot_binding() != storage_inventory.boot_binding()
            || runtime.boot_binding() != mounts.boot_binding()
            || runtime.boot_binding() != network.boot_binding()
            || mounts.initial().endpoint()
                != crate::lifecycle::LifecycleBootBootstrapEndpointV1::Mount
            || network.initial().endpoint()
                != crate::lifecycle::LifecycleBootBootstrapEndpointV1::Network
        {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        runtime_inventory.recheck_boot(boot_before)?;
        runtime_inventory_after.recheck_boot(boot_before)?;
        storage
            .recheck(self.reconciler.journal_mut())
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let storage_inventory_after = storage_inventory.current();
        let storage_inventory = storage_inventory.initial();
        storage_inventory.recheck_launch_snapshot(storage)?;
        storage_inventory_after.recheck_launch_snapshot(storage)?;
        if storage.inventory().kernel_boot_id() != &boot_before {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }

        let cache_inventory = cache
            .lifecycle_boot_inventory()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        transfer
            .recheck_lifecycle_transfer_inventory(transfer_inventory)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        storage
            .recheck(self.reconciler.journal_mut())
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        storage_inventory_after.recheck_launch_snapshot(storage)?;
        let cache_after = cache
            .lifecycle_boot_inventory()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        transfer
            .recheck_lifecycle_transfer_inventory(transfer_inventory)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let boot_after = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        let boot_final = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        runtime_inventory.recheck_boot(boot_final)?;
        runtime_inventory_after.recheck_boot(boot_final)?;
        if boot_before != boot_after || boot_after != boot_final || cache_after != cache_inventory {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let commitments = [
            runtime_inventory.commitment(),
            mounts.initial().commitment(),
            storage_inventory.commitment(),
            network.initial().commitment(),
            cache_after.root(),
            transfer_inventory.commitment(),
        ];
        let physical = crate::lifecycle::fresh_physical_inventory(
            &runtime_inventory,
            mounts.initial(),
            &storage_inventory,
            network.initial(),
            &cache_after,
            transfer_inventory,
        )?;
        let current = lifecycle
            .bind_current_boot_domains(
                operation_key,
                boot_inventory_key,
                boot_final,
                commitments,
                physical,
            )
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        if current.boot_binding() != runtime.boot_binding() {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(current)
    }

    /// Commits a new boot inventory root from a consumed protected six-domain join.
    ///
    /// This is the publication half of the dormant two-phase boot protocol.
    /// Callers first consume the current joined inventories into `source`; this
    /// method then derives every domain commitment from that opaque value and
    /// derives time and boot identity from the controller-owned kernel clock.
    /// After commit, callers must query Host and Storage again and run the
    /// ordinary current-domain join before using the new boot capability.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecycleProtectedJournalErrorV1`] for a
    /// stale operation/root, clock or boot rollover, malformed lineage, or a
    /// protected commit failure. Outcome-unknown retains its exact recovery
    /// token in the returned progress value.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_lifecycle_boot_inventory_refresh(
        &mut self,
        lifecycle: &mut crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        source: crate::lifecycle::LifecycleBootInventoryRefreshSourceV1,
        transaction_id: [u8; 16],
        atomic_join: aos_sandbox_core::ResourceId,
        operation_lineage: aos_sandbox_core::ResourceId,
        inventory_lineage: aos_sandbox_core::ResourceId,
    ) -> Result<
        crate::lifecycle::LifecycleProgressCommitOutcomeV1,
        crate::lifecycle::LifecycleProtectedJournalErrorV1,
    > {
        let mut clock = ControllerProtectedClockV1::open_fixed()
            .map_err(|_| crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let sample = clock
            .sample()
            .map_err(|_| crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let current_boot = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
            .into_bytes();
        if sample.host_boot_id() != current_boot || sample.wall_seconds() <= 0 {
            return Err(crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let observed_at = u64::try_from(sample.wall_seconds())
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|value| value.checked_add(sample.boottime_nanoseconds() % 1_000_000_000))
            .and_then(|value| crate::lifecycle::LifecycleTimeV1::new(value).ok())
            .ok_or(crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let prepared = lifecycle.prepare_boot_inventory_refresh(
            operation_key,
            boot_inventory_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            inventory_lineage,
            current_boot,
            source,
            observed_at,
        )?;
        lifecycle.commit_auxiliary_append(prepared)
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_lifecycle_boot_inventory_bootstrap(
        &mut self,
        lifecycle: &mut crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        source: crate::lifecycle::LifecycleBootInventoryBootstrapSourceV1,
        transaction_id: [u8; 16],
        atomic_join: aos_sandbox_core::ResourceId,
        operation_lineage: aos_sandbox_core::ResourceId,
        inventory_lineage: aos_sandbox_core::ResourceId,
    ) -> Result<
        crate::lifecycle::LifecycleProgressCommitOutcomeV1,
        crate::lifecycle::LifecycleProtectedJournalErrorV1,
    > {
        let mut clock = ControllerProtectedClockV1::open_fixed()
            .map_err(|_| crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let sample = clock
            .sample()
            .map_err(|_| crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if sample.host_boot_id() != source.challenge().host_boot() || sample.wall_seconds() <= 0 {
            return Err(crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let observed_at = u64::try_from(sample.wall_seconds())
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|value| value.checked_add(sample.boottime_nanoseconds() % 1_000_000_000))
            .and_then(|value| crate::lifecycle::LifecycleTimeV1::new(value).ok())
            .ok_or(crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let prepared = lifecycle.prepare_boot_inventory_bootstrap(
            operation_key,
            boot_inventory_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            inventory_lineage,
            source,
            observed_at,
        )?;
        lifecycle.commit_auxiliary_append(prepared)
    }

    /// Tracks a freshly observed runtime in the protected generation ledger.
    ///
    /// Consumes the validated Host observation. A new execution advances the
    /// incarnation's generation atomically; another observation of the same
    /// execution keeps its number. Neither case proves attachment replay or
    /// grants readiness.
    /// The clock must be the protected adapter used for scope acquisition.
    ///
    /// # Errors
    ///
    /// Rejects corrupt or exhausted history, reused scope handles, stale live
    /// authority, and failed protected commits. A post-commit failure can leave
    /// an inert generation record without returning any live proof.
    #[cfg(target_os = "linux")]
    pub(crate) fn track_current_runtime_generation<T>(
        &mut self,
        scope: crate::runtime_scope::CurrentRuntimeScope,
        clock: &mut T,
    ) -> Result<
        crate::runtime_scope::CurrentRuntimeGeneration,
        crate::runtime_scope::RuntimeGenerationError,
    >
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::runtime_scope::CurrentRuntimeGeneration::track(
            scope,
            self.reconciler.journal_mut(),
            clock,
        )
    }

    /// Rechecks a generation's current head, original deadline, and live scope.
    ///
    /// The callback must use the same protected clock adapter as acquisition.
    /// Successful validation does not extend the proof or attest replay.
    ///
    /// # Errors
    ///
    /// Rejects changed generation heads, corrupt history, stale authority,
    /// expired observations, and unavailable retained kernel executions.
    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_current_runtime_generation<T>(
        &mut self,
        generation: &crate::runtime_scope::CurrentRuntimeGeneration,
        clock: &mut T,
    ) -> Result<(), crate::runtime_scope::RuntimeGenerationError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        generation.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Allocates or verifies the signed namespace target for a live runtime.
    ///
    /// The first observed execution seeds its target from the current signed
    /// manifest. A later execution advances the durable target monotonically.
    /// If current authority still names the prior target, the result carries an
    /// inert advancement proposal; callers must publish the authorized
    /// assignment successor, reacquire the live proof, and call this method
    /// again. Only a `Current` result may proceed to mount preparation.
    ///
    /// # Errors
    ///
    /// Rejects corrupt or exhausted allocation history, stale runtime proofs,
    /// incompatible signed target changes, and failed protected commits.
    #[cfg(target_os = "linux")]
    pub(crate) fn bind_current_namespace_target<T>(
        &mut self,
        generation: crate::runtime_scope::CurrentRuntimeGeneration,
        clock: &mut T,
    ) -> Result<
        crate::runtime_scope::NamespaceTargetOutcome,
        crate::runtime_scope::NamespaceTargetError,
    >
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::runtime_scope::CurrentNamespaceTarget::bind(
            generation,
            self.reconciler.journal_mut(),
            clock,
        )
    }

    /// Rechecks a live namespace target against both protected audit heads.
    ///
    /// Successful validation does not extend the original Host observation or
    /// prove that any attachment has been replayed.
    ///
    /// # Errors
    ///
    /// Rejects changed current authority, runtime or allocation heads, expired
    /// live evidence, corrupt history, and signed-target substitution.
    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_current_namespace_target<T>(
        &mut self,
        target: &crate::runtime_scope::CurrentNamespaceTarget,
        clock: &mut T,
    ) -> Result<(), crate::runtime_scope::NamespaceTargetError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        target.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Publishes one canonical portable sandbox specification by content identity.
    ///
    /// Publication retains the exact canonical bytes needed to prove later
    /// destination-slot declarations. It does not create a sandbox, select an
    /// assignment, or grant runtime or broker authority.
    ///
    /// # Errors
    ///
    /// Rejects invalid publication metadata, content or operation conflicts,
    /// corrupt or exhausted history, and failed durable commits.
    pub fn publish_sandbox_spec(
        &mut self,
        publication: crate::SandboxSpecPublicationV1,
    ) -> Result<
        (
            crate::DurableSandboxSpecV1,
            crate::SandboxSpecCommitOutcomeV1,
        ),
        crate::SandboxSpecStateError,
    > {
        crate::sandbox_spec_state::commit(self.reconciler.journal_mut(), publication)
    }

    /// Loads one validated canonical sandbox specification by exact descriptor.
    ///
    /// # Errors
    ///
    /// Rejects an invalid descriptor, corrupt or exhausted specification
    /// history, and journal health failures observed before lookup.
    pub fn sandbox_spec(
        &mut self,
        descriptor: &aos_sandbox_core::ObjectDescriptor,
    ) -> Result<Option<crate::DurableSandboxSpecV1>, crate::SandboxSpecStateError> {
        let journal = self.reconciler.journal_mut();
        journal.ensure_healthy()?;
        crate::sandbox_spec_state::get(journal, descriptor)
    }

    /// Commits a destination-slot creation or release before payload launch.
    ///
    /// The controller derives the immutable sandbox, incarnation, reserved
    /// namespace generation, and portable specification from current signed
    /// assignment authority. Creation requires the published specification to
    /// declare the slot. No live Host observation is required or implied.
    ///
    /// # Errors
    ///
    /// Rejects stale assignment authority, sentinel mutation metadata, a stale
    /// resource version, operation equivocation, undrained attachment or Mount
    /// state, corrupt history, capacity exhaustion, and failed commits.
    #[cfg(target_os = "linux")]
    pub(crate) fn commit_current_assignment_attachment_slot<T>(
        &mut self,
        target: crate::runtime_scope::CurrentAssignmentTarget,
        mutation: crate::AttachmentSlotMutationV1,
        clock: &mut T,
    ) -> Result<crate::CommittedCurrentAssignmentAttachmentSlotV1, crate::AttachmentSlotStateError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_slot_state::commit_current_assignment(
            self.reconciler.journal_mut(),
            target,
            mutation,
            clock,
        )
    }

    /// Commits one destination-slot creation or release while its target is current.
    ///
    /// The controller derives the immutable sandbox, incarnation, namespace,
    /// and portable specification binding from the retained target. Creation
    /// requires that exact published specification to declare the slot. The
    /// slot carries no path or OS descriptor and grants no Mount authority.
    /// Release is permanent and waits for attachment intent and validated
    /// Mount inventory to prove the slot drained.
    ///
    /// # Errors
    ///
    /// Rejects stale namespace authority, sentinel mutation metadata, a stale
    /// resource version, target substitution, operation equivocation, undrained
    /// attachment or Mount state, corrupt history, capacity exhaustion, and
    /// failed protected commits.
    #[cfg(target_os = "linux")]
    pub(crate) fn commit_current_attachment_slot<T>(
        &mut self,
        target: crate::runtime_scope::CurrentNamespaceTarget,
        mutation: crate::AttachmentSlotMutationV1,
        clock: &mut T,
    ) -> Result<crate::CommittedCurrentAttachmentSlotV1, crate::AttachmentSlotStateError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_slot_state::commit_current(
            self.reconciler.journal_mut(),
            target,
            mutation,
            clock,
        )
    }

    /// Loads the validated current revision for one logical destination slot.
    ///
    /// Released slots remain visible as permanent tombstones. The result does
    /// not contain a host destination path or broker descriptor authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed, discontinuous, conflicting, or over-limit slot
    /// history and journal health failures observed during replay.
    #[cfg(target_os = "linux")]
    pub fn attachment_slot(
        &mut self,
        slot_id: aos_sandbox_core::AttachmentSlotId,
    ) -> Result<Option<crate::DurableAttachmentSlotV1>, crate::AttachmentSlotStateError> {
        let journal = self.reconciler.journal_mut();
        journal.ensure_healthy()?;
        crate::attachment_slot_state::get_current(journal, slot_id)
    }

    /// Commits one generation-fenced attachment intent while its target is current.
    ///
    /// The desired generation and its normalized operation digest become
    /// durable before any Mount effect may be prepared or dispatched. The
    /// retained target is checked on both sides of the commit. Success records
    /// intent only; it does not authorize Mount or claim attachment readiness.
    ///
    /// # Errors
    ///
    /// Rejects stale namespace authority, a target/intent mismatch, a stale
    /// resource version, attachment or slot conflicts, corrupt history,
    /// capacity exhaustion, and failed protected commits.
    #[cfg(target_os = "linux")]
    pub(crate) fn commit_current_attachment_desired_state<T>(
        &mut self,
        target: crate::runtime_scope::CurrentNamespaceTarget,
        mutation: crate::AttachmentDesiredMutationV1,
        clock: &mut T,
    ) -> Result<crate::CommittedCurrentAttachmentDesiredStateV1, crate::AttachmentDesiredStateError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_state::commit_current(
            self.reconciler.journal_mut(),
            target,
            mutation,
            clock,
        )
    }

    /// Loads the validated current desired generation for one attachment.
    ///
    /// Released attachments remain visible as tombstones. The result is
    /// durable intent only and carries no live namespace or broker authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed, discontinuous, conflicting, or over-limit attachment
    /// history and journal health failures observed while replaying it.
    #[cfg(target_os = "linux")]
    pub fn attachment_desired_state(
        &mut self,
        attachment_id: aos_sandbox_core::AttachmentId,
    ) -> Result<Option<crate::DurableAttachmentDesiredStateV1>, crate::AttachmentDesiredStateError>
    {
        let journal = self.reconciler.journal_mut();
        journal.ensure_healthy()?;
        crate::attachment_state::get(journal, attachment_id)
    }

    /// Commits one immutable filesystem-view revision or release tombstone.
    ///
    /// Revision one creates a logical view. Each later revision is linked to
    /// the exact prior record digest, and release permanently closes the view
    /// identity without changing its last source semantics. This records
    /// portable intent only; it does not resolve a host path or authorize a
    /// broker effect.
    ///
    /// # Errors
    ///
    /// Rejects invalid source handles, stale revisions or resource versions,
    /// operation equivocation, resurrection after release, corrupt history,
    /// capacity exhaustion, and failed protected commits.
    pub fn commit_filesystem_view_revision(
        &mut self,
        mutation: crate::FilesystemViewRevisionMutationV1,
    ) -> Result<
        (
            crate::DurableFilesystemViewRevisionV1,
            crate::FilesystemViewRevisionCommitOutcomeV1,
        ),
        crate::FilesystemViewRevisionStateError,
    > {
        crate::filesystem_view_state::commit(self.reconciler.journal_mut(), mutation)
    }

    /// Loads the validated current revision for one logical filesystem view.
    ///
    /// A released view remains visible as its terminal tombstone.
    ///
    /// # Errors
    ///
    /// Rejects malformed, discontinuous, conflicting, or over-limit revision
    /// history and journal health failures observed during replay.
    pub fn current_filesystem_view_revision(
        &mut self,
        view_id: aos_sandbox_core::ViewId,
    ) -> Result<
        Option<crate::DurableFilesystemViewRevisionV1>,
        crate::FilesystemViewRevisionStateError,
    > {
        let journal = self.reconciler.journal_mut();
        journal.ensure_healthy()?;
        crate::filesystem_view_state::get_current(journal, view_id)
    }

    /// Loads one exact immutable filesystem-view revision.
    ///
    /// Historical available revisions remain addressable after publication of
    /// successors so already-authorized attachments can retain exact sources.
    ///
    /// # Errors
    ///
    /// Rejects malformed, discontinuous, conflicting, or over-limit revision
    /// history and journal health failures observed during replay.
    pub fn filesystem_view_revision(
        &mut self,
        view_id: aos_sandbox_core::ViewId,
        revision: aos_sandbox_core::Revision,
    ) -> Result<
        Option<crate::DurableFilesystemViewRevisionV1>,
        crate::FilesystemViewRevisionStateError,
    > {
        let journal = self.reconciler.journal_mut();
        journal.ensure_healthy()?;
        crate::filesystem_view_state::get_revision(journal, view_id, revision)
    }

    /// Resolves one fence-free Mount intent against a live payload scope.
    ///
    /// The controller derives the current assignment and namespace generation,
    /// verifies that current Host authority grants the exact RootMount query,
    /// and sends no descriptors to Mount. Mount acquires and checks the payload
    /// root and namespaces directly from Host. The returned commitment remains
    /// volatile and is not effect authority; callers must obtain a separately
    /// signed Mount Apply plan before dispatch.
    ///
    /// # Errors
    ///
    /// Rejects caller-supplied fence context, stale runtime or assignment
    /// authority, a missing exact Host grant, substituted service responses,
    /// expired deadlines, invalid Mount semantics, and transport failures.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_current_mount_catalog<T>(
        &mut self,
        target: crate::runtime_scope::CurrentNamespaceTarget,
        intent: &crate::mount_preparation::MountCatalogIntentV1,
        client: crate::mount_preparation::MountCatalogClient,
        clock: &mut T,
    ) -> Result<
        crate::mount_preparation::PreparedCurrentMountCatalogV1,
        crate::mount_preparation::MountCatalogPreparationError,
    >
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::mount_preparation::prepare_current(
            self.reconciler.journal_mut(),
            target,
            intent,
            client,
            clock,
        )
    }

    /// Rechecks a prepared Mount catalog against live authority and its deadline.
    ///
    /// Successful validation neither extends the preparation nor proves that a
    /// signed Apply was admitted or that an attachment is installed.
    ///
    /// # Errors
    ///
    /// Rejects changed current authority, runtime or namespace heads, expired
    /// live evidence, and unavailable retained kernel executions.
    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_current_mount_catalog<T>(
        &mut self,
        prepared: &crate::mount_preparation::PreparedCurrentMountCatalogV1,
        clock: &mut T,
    ) -> Result<(), crate::mount_preparation::MountCatalogPreparationError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        prepared.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Verifies and binds the separately signed Mount plan for a prepared catalog.
    ///
    /// The plan must use the pinned controller trust anchor, current assignment
    /// and ownership authority, Mount audience, authority protocol 2.0, and the
    /// exact catalog-dependent semantics returned by preparation. Success still
    /// performs no broker effect and writes no durable operation.
    ///
    /// # Errors
    ///
    /// Rejects stale live authority, signature or assignment substitution,
    /// wrong audience/protocol/ownership authority, an absent exact grant, and
    /// an expired preparation.
    #[cfg(target_os = "linux")]
    pub(crate) fn bind_current_mount_plan<T>(
        &mut self,
        catalog: crate::mount_preparation::PreparedCurrentMountCatalogV1,
        signed_plan: crate::SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<
        crate::mount_preparation::PreparedCurrentMountDispatchV1,
        crate::mount_preparation::MountCatalogPreparationError,
    >
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::mount_preparation::bind_signed_mount_plan(
            self.reconciler.journal_mut(),
            catalog,
            signed_plan,
            clock,
        )
    }

    /// Rechecks a signed Mount preparation without dispatching it.
    ///
    /// # Errors
    ///
    /// Rejects changed current authority, runtime or namespace heads, expired
    /// live evidence, and unavailable retained kernel executions.
    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_current_mount_dispatch<T>(
        &mut self,
        prepared: &crate::mount_preparation::PreparedCurrentMountDispatchV1,
        clock: &mut T,
    ) -> Result<(), crate::mount_preparation::MountCatalogPreparationError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        prepared.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Durably admits one exact current Mount attempt before packet dispatch.
    ///
    /// The attempt binds the prepared catalog and signed plan to the current
    /// ownership lease and a caller-selected local deadline no later than the
    /// catalog's exclusive deadline. The controller commits the exact body,
    /// authorized packet, catalog commitment, and immutable namespace audit
    /// reference before returning a live token. This method performs no broker
    /// I/O and does not claim that an attachment is installed.
    ///
    /// Restart cannot reconstruct the returned token because Mount's descriptor
    /// catalog and the retained namespace proof are memory-only. Recovery must
    /// validate broker inventory and repeat preparation before another
    /// effect attempt.
    ///
    /// # Errors
    ///
    /// Rejects stale live authority, expired or mismatched plan/lease bounds,
    /// a deadline beyond the catalog lifetime, conflicting request replay,
    /// corrupt cross-referenced history, capacity, and failed durable commits.
    #[cfg(target_os = "linux")]
    pub(crate) fn admit_current_mount_attempt<T>(
        &mut self,
        prepared: crate::mount_preparation::PreparedCurrentMountDispatchV1,
        deadline_boottime_nanoseconds: u64,
        clock: &mut T,
    ) -> Result<crate::mount_attempt::DurableCurrentMountAttemptV1, crate::MountAttemptError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::mount_attempt::admit_current(
            self.reconciler.journal_mut(),
            prepared,
            deadline_boottime_nanoseconds,
            clock,
        )
    }

    /// Rechecks an admitted Mount attempt without dispatching it.
    ///
    /// # Errors
    ///
    /// Rejects changed live authority, missing or substituted durable bytes,
    /// corrupt cross-references, expired preparation, and journal failures.
    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_current_mount_attempt<T>(
        &mut self,
        attempt: &crate::mount_attempt::DurableCurrentMountAttemptV1,
        clock: &mut T,
    ) -> Result<(), crate::MountAttemptError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        attempt.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Dispatches one already durable current Mount request and records success.
    ///
    /// The connected client validates Mount's kernel-nominated subjects but
    /// does not thereby prove the actual hello and response syscall writers. It
    /// still requires signed session/result authentication and deployment
    /// MAC/capability confinement. It sends either the admission packet or an
    /// exact-plan envelope with a current ownership lease and the admitted Apply
    /// body, and validates the result against that body. A successful receipt is
    /// committed before this method returns it. Broker rejection or transport
    /// loss is not treated as proof that no resource exists; recovery requires
    /// authoritative Mount inventory.
    ///
    /// # Errors
    ///
    /// Rejects stale live authority, substituted durable state, service-subject
    /// correlation or negotiation failure, malformed or mismatched results,
    /// conflicting completion replay, capacity, and failed durable commits.
    #[cfg(target_os = "linux")]
    pub(crate) fn dispatch_current_mount_attempt<T>(
        &mut self,
        attempt: crate::mount_attempt::DurableCurrentMountAttemptV1,
        client: crate::mount_attempt::MountDispatchClient,
        clock: &mut T,
    ) -> Result<crate::mount_attempt::CompletedCurrentMountAttemptV1, crate::MountAttemptError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::mount_attempt::dispatch_current(
            self.reconciler.journal_mut(),
            attempt,
            client,
            clock,
        )
    }

    /// Captures protected controller state before a fresh authenticated Mount query.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy or unprotected controller state and invalid prior inventory.
    #[cfg(target_os = "linux")]
    pub fn begin_authenticated_mount_inventory(
        &mut self,
    ) -> Result<crate::mount_attempt::MountInventoryObservationFenceV1, crate::MountAttemptError>
    {
        crate::mount_attempt::authenticated_inventory::begin_observation(
            self.reconciler.journal_mut(),
        )
    }

    /// Records a fresh authenticated Mount observation against its preceding state.
    ///
    /// The transport owner must recheck protected terminal currentness immediately
    /// before this call. The result is observation evidence, never effect authority.
    ///
    /// # Errors
    ///
    /// Rejects intervening journal changes, wrong method or direction, broker errors,
    /// invalid or regressing inventory, and failed durable persistence.
    #[cfg(target_os = "linux")]
    pub fn complete_authenticated_mount_inventory(
        &mut self,
        fence: crate::mount_attempt::MountInventoryObservationFenceV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<crate::DurableMountInventorySnapshotV1, crate::MountAttemptError> {
        crate::mount_attempt::authenticated_inventory::complete_observation(
            self.reconciler.journal_mut(),
            fence,
            outcome,
        )
    }

    /// Captures protected controller state before an authenticated destination-slot query.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy or unprotected controller state and invalid prior inventory.
    #[cfg(target_os = "linux")]
    pub fn begin_authenticated_destination_slot_inventory(
        &mut self,
    ) -> Result<
        crate::destination_slot_inventory::DestinationSlotInventoryObservationFenceV1,
        crate::MountAttemptError,
    > {
        crate::destination_slot_inventory::authenticated::begin_observation(
            self.reconciler.journal_mut(),
        )
    }

    /// Records a fresh authenticated destination-slot observation against its preceding state.
    ///
    /// The transport owner must recheck protected terminal currentness immediately
    /// before this call. The result is observation evidence, never effect authority.
    ///
    /// # Errors
    ///
    /// Rejects intervening journal changes, wrong method or direction, broker errors,
    /// invalid or regressing inventory, and failed durable persistence.
    #[cfg(target_os = "linux")]
    pub fn complete_authenticated_destination_slot_inventory(
        &mut self,
        fence: crate::destination_slot_inventory::DestinationSlotInventoryObservationFenceV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<crate::DurableDestinationSlotInventorySnapshotV1, crate::MountAttemptError> {
        crate::destination_slot_inventory::authenticated::complete_observation(
            self.reconciler.journal_mut(),
            fence,
            outcome,
        )
    }

    /// Queries and durably records one validated complete Mount inventory.
    ///
    /// The one-shot client validates kernel-nominated subjects, not proof of the
    /// actual syscall writers. Signed session/result authentication and
    /// deployment MAC/capability confinement remain required. It validates the
    /// closed resource table response and commits the exact request and response
    /// before returning the snapshot. The snapshot is observation evidence, not
    /// descriptor authority or attachment readiness.
    ///
    /// # Errors
    ///
    /// Rejects service-subject correlation or negotiation failure, malformed or
    /// non-monotonic broker inventory, capacity, and failed durable commits.
    #[cfg(target_os = "linux")]
    pub fn record_mount_inventory(
        &mut self,
        client: crate::mount_attempt::MountInventoryClient,
    ) -> Result<crate::mount_attempt::DurableMountInventorySnapshotV1, crate::MountAttemptError>
    {
        crate::mount_attempt::record_snapshot(self.reconciler.journal_mut(), client)
    }

    /// Queries and durably records Mount's complete source-acquisition inventory.
    ///
    /// The one-shot client requires the exact source-acquisition profile and
    /// rejects authorization artifacts and ancillary descriptors. It validates
    /// every lossless public row and commits the exact canonical request and
    /// response against current protected controller state. This observation
    /// carries no provider session, source descriptor, or effect authority.
    ///
    /// # Errors
    ///
    /// Rejects unsafe controller-journal provenance, service-subject or
    /// negotiation failure, malformed or nonmonotonic broker history, stale
    /// controller state, capacity exhaustion, and failed durable commits.
    #[cfg(target_os = "linux")]
    pub fn record_mount_source_acquisition_inventory(
        &mut self,
        client: crate::MountSourceAcquisitionInventoryClient,
    ) -> Result<
        crate::DurableMountSourceAcquisitionInventorySnapshotV1,
        crate::MountSourceAcquisitionInventoryError,
    > {
        crate::mount_source_acquisition_inventory::record_snapshot(
            self.reconciler.journal_mut(),
            client,
        )
    }

    /// Reconciles a fresh Mount snapshot with one current namespace target.
    ///
    /// The snapshot must still be the latest durable observation and must
    /// postdate the exact current Mount-attempt and completion set. The result
    /// retains the live target and classifies exact pending, faulted, completed,
    /// unacknowledged-success, superseded, and unobserved attempts without
    /// authorizing retry or cleanup.
    ///
    /// # Errors
    ///
    /// Rejects stale target or snapshot state, substituted resource identity,
    /// contradictory completion evidence, and corrupt durable cross-references.
    #[cfg(target_os = "linux")]
    pub(crate) fn reconcile_current_mount_inventory<T>(
        &mut self,
        target: crate::runtime_scope::CurrentNamespaceTarget,
        snapshot: crate::mount_attempt::DurableMountInventorySnapshotV1,
        clock: &mut T,
    ) -> Result<crate::mount_attempt::CurrentMountInventoryReconciliationV1, crate::MountAttemptError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::mount_attempt::reconcile_current_inventory(
            self.reconciler.journal_mut(),
            target,
            snapshot,
            clock,
        )
    }

    /// Queries and durably records Mount's complete destination-slot inventory.
    ///
    /// The one-shot client validates kernel-nominated subjects, not proof of the
    /// actual syscall writers. Signed session/result authentication and
    /// deployment MAC/capability confinement remain required. It validates the
    /// exact Mount 2.0 response and commits the exact query and response. The
    /// resulting snapshot is observation evidence only.
    ///
    /// # Errors
    ///
    /// Rejects service-subject correlation or negotiation failure, malformed or
    /// non-monotonic broker inventory, stale controller state, capacity, and
    /// failed durable commits.
    #[cfg(target_os = "linux")]
    pub fn record_destination_slot_inventory(
        &mut self,
        client: crate::DestinationSlotInventoryClient,
    ) -> Result<crate::DurableDestinationSlotInventorySnapshotV1, crate::MountAttemptError> {
        crate::destination_slot_inventory::record_snapshot(self.reconciler.journal_mut(), client)
    }

    /// Captures protected controller state before a fresh authenticated Storage query.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy or unprotected controller state and invalid prior inventory.
    #[cfg(target_os = "linux")]
    pub fn begin_authenticated_storage_inventory(
        &mut self,
    ) -> Result<
        crate::resource_inventory::StorageInventoryObservationFenceV1,
        crate::ResourceInventoryError,
    > {
        crate::resource_inventory::authenticated::begin_storage_observation(
            self.reconciler.journal_mut(),
        )
    }

    /// Records a fresh authenticated Storage observation against its preceding state.
    ///
    /// The transport owner must recheck protected terminal currentness immediately
    /// before this call. The result is observation evidence, never effect authority.
    ///
    /// # Errors
    ///
    /// Rejects intervening journal changes, wrong method or direction, broker errors,
    /// invalid or regressing inventory, and failed durable persistence.
    #[cfg(target_os = "linux")]
    pub fn complete_authenticated_storage_inventory(
        &mut self,
        fence: crate::resource_inventory::StorageInventoryObservationFenceV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<crate::DurableStorageResourceInventorySnapshotV1, crate::ResourceInventoryError>
    {
        crate::resource_inventory::authenticated::complete_storage_observation(
            self.reconciler.journal_mut(),
            fence,
            outcome,
        )
    }

    /// Queries and durably records Storage's complete workspace inventory.
    ///
    /// The one-shot client validates kernel-nominated subjects, not proof of the
    /// actual syscall writers. Signed session/result authentication and
    /// deployment MAC/capability confinement remain required. It validates the
    /// exact protocol 1.0 resource snapshot and commits the exact query and
    /// response. The resulting snapshot is non-authorizing evidence for a later
    /// whole-catalog projection.
    ///
    /// # Errors
    ///
    /// Rejects service-subject correlation or negotiation failure, malformed or
    /// non-monotonic broker inventory, stale controller state, capacity, and
    /// failed durable commits.
    #[cfg(target_os = "linux")]
    pub fn record_storage_resource_inventory(
        &mut self,
        client: crate::StorageResourceInventoryClient,
    ) -> Result<crate::DurableStorageResourceInventorySnapshotV1, crate::ResourceInventoryError>
    {
        crate::resource_inventory::record_storage_snapshot(self.reconciler.journal_mut(), client)
    }

    /// Captures protected controller state before a fresh authenticated Network query.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy or unprotected controller state and invalid prior inventory.
    #[cfg(target_os = "linux")]
    pub fn begin_authenticated_network_inventory(
        &mut self,
    ) -> Result<
        crate::resource_inventory::NetworkInventoryObservationFenceV1,
        crate::ResourceInventoryError,
    > {
        crate::resource_inventory::authenticated::begin_network_observation(
            self.reconciler.journal_mut(),
        )
    }

    /// Records a fresh authenticated Network observation against its preceding state.
    ///
    /// The transport owner must recheck protected terminal currentness immediately
    /// before this call. The result is observation evidence, never effect authority.
    ///
    /// # Errors
    ///
    /// Rejects intervening journal changes, wrong method or direction, broker errors,
    /// invalid or regressing inventory, and failed durable persistence.
    #[cfg(target_os = "linux")]
    pub fn complete_authenticated_network_inventory(
        &mut self,
        fence: crate::resource_inventory::NetworkInventoryObservationFenceV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<crate::DurableNetworkResourceInventorySnapshotV1, crate::ResourceInventoryError>
    {
        crate::resource_inventory::authenticated::complete_network_observation(
            self.reconciler.journal_mut(),
            fence,
            outcome,
        )
    }

    /// Queries and durably records Network's complete namespace inventory.
    ///
    /// The one-shot client validates kernel-nominated subjects, not proof of the
    /// actual syscall writers. Signed session/result authentication and
    /// deployment MAC/capability confinement remain required. It validates the
    /// exact protocol 1.0 resource snapshot and commits the exact query and
    /// response. The resulting snapshot is non-authorizing evidence for a later
    /// whole-catalog projection.
    ///
    /// # Errors
    ///
    /// Rejects service-subject correlation or negotiation failure, malformed or
    /// non-monotonic broker inventory, stale controller state, capacity, and
    /// failed durable commits.
    #[cfg(target_os = "linux")]
    pub fn record_network_resource_inventory(
        &mut self,
        client: crate::NetworkResourceInventoryClient,
    ) -> Result<crate::DurableNetworkResourceInventorySnapshotV1, crate::ResourceInventoryError>
    {
        crate::resource_inventory::record_network_snapshot(self.reconciler.journal_mut(), client)
    }

    /// Projects mutually current broker snapshots into a durable Host catalog.
    ///
    /// The complete protected current-assignment set is joined with exact
    /// Storage, Network, Mount, and destination-anchor observations. Unchanged
    /// resources return the confirmed catalog; a changed snapshot becomes a
    /// durable pending effect before any Host I/O. An existing pending effect
    /// must be recovered and dispatched first.
    ///
    /// # Errors
    ///
    /// Rejects stale or cross-boot snapshots, incomplete previously published
    /// assignments, unverified attachments, ambiguous broker resources,
    /// generation or durable-size exhaustion, corrupt protected state, and
    /// failed commits.
    #[cfg(target_os = "linux")]
    pub fn prepare_host_catalog(
        &mut self,
        storage: crate::DurableStorageResourceInventorySnapshotV1,
        network: crate::DurableNetworkResourceInventorySnapshotV1,
        mounts: crate::mount_attempt::DurableMountInventorySnapshotV1,
        destinations: crate::DurableDestinationSlotInventorySnapshotV1,
    ) -> Result<crate::HostCatalogReconciliationV1, crate::HostCatalogReconciliationError> {
        crate::host_catalog_reconciliation::prepare(
            self.reconciler.journal_mut(),
            storage,
            network,
            mounts,
            destinations,
        )
    }

    /// Recovers the exact durable Host catalog whose effect remains pending.
    ///
    /// Recovery returns the original canonical bytes without reconstructing
    /// them from newer controller or broker state. `None` means there is no
    /// indeterminate Host publication to resolve.
    ///
    /// # Errors
    ///
    /// Rejects malformed, conflicting, or unhealthy durable catalog state.
    #[cfg(target_os = "linux")]
    pub fn pending_host_catalog(
        &mut self,
    ) -> Result<Option<crate::DurablePendingHostCatalogV1>, crate::HostCatalogReconciliationError>
    {
        crate::host_catalog_reconciliation::recover_pending(self.reconciler.journal_mut())
    }

    /// Publishes one exact durable pending catalog and records Host confirmation.
    ///
    /// A lost or rejected exchange leaves the pending record unchanged. The
    /// caller may reacquire the configured Host channel and retry the recovered
    /// bytes; Host publication and exact replay are both successful outcomes.
    ///
    /// # Errors
    ///
    /// Rejects substituted pending state, Host identity or protocol failure,
    /// mismatched receipts, elapsed deadlines, and failed confirmation commits.
    #[cfg(target_os = "linux")]
    pub fn dispatch_host_catalog(
        &mut self,
        pending: crate::DurablePendingHostCatalogV1,
        client: crate::host_catalog_publication::HostCatalogPublicationClient,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<crate::DurableCurrentHostCatalogV1, crate::HostCatalogReconciliationError> {
        crate::host_catalog_reconciliation::dispatch(
            self.reconciler.journal_mut(),
            pending,
            client,
            deadline_boottime_nanoseconds,
        )
    }

    /// Confirms the exact pending catalog using a signed Host publication result.
    ///
    /// The transport owner must durably receive the result and revalidate its
    /// protected session currentness immediately before calling this method.
    /// Rejected or mismatched results leave the pending catalog unchanged.
    /// This method does not recover an outstanding transport request.
    ///
    /// # Errors
    ///
    /// Rejects unprotected journals, substituted pending state, wrong methods
    /// or outcome directions, mismatched publication bindings, Host rejection,
    /// and failed confirmation commits.
    #[cfg(target_os = "linux")]
    pub fn complete_authenticated_host_catalog_publication(
        &mut self,
        pending: crate::DurablePendingHostCatalogV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<crate::DurableCurrentHostCatalogV1, crate::HostCatalogReconciliationError> {
        crate::host_catalog_reconciliation::authenticated::complete_publication(
            self.reconciler.journal_mut(),
            pending,
            outcome,
        )
    }

    /// Reconciles one current logical slot with fresh complete broker state.
    ///
    /// Exact sandbox, incarnation, namespace, specification, and logical
    /// operation correlations are required. The returned action is descriptive
    /// and does not authorize a Mount request or retain namespace authority.
    ///
    /// # Errors
    ///
    /// Rejects stale snapshots or slot state, substituted broker bindings,
    /// conflicting operation correlations, and corrupt durable state.
    #[cfg(target_os = "linux")]
    pub fn reconcile_current_destination_slot(
        &mut self,
        slot: crate::DurableAttachmentSlotV1,
        snapshot: crate::DurableDestinationSlotInventorySnapshotV1,
    ) -> Result<crate::CurrentDestinationSlotReconciliationV1, crate::MountAttemptError> {
        crate::destination_slot_inventory::reconcile_current(
            self.reconciler.journal_mut(),
            slot,
            snapshot,
        )
    }

    /// Plans one attachment's next step from current intent and Mount inventory.
    ///
    /// The desired generation, complete validated inventory, exact durable
    /// attempt classifications, attachment lease time, and retained namespace
    /// target are rechecked before and after planning. The result is descriptive:
    /// prepare, install, replace, verify, ready, detach, release, wait, fault,
    /// conflict, and terminal observations do not authorize a broker effect.
    ///
    /// # Errors
    ///
    /// Rejects stale desired state, target or inventory evidence; corrupt
    /// cross-references; fixed-bound exhaustion; and protected-clock failure.
    #[cfg(target_os = "linux")]
    pub(crate) fn reconcile_current_attachment<T>(
        &mut self,
        desired: crate::DurableAttachmentDesiredStateV1,
        inventory: crate::CurrentMountInventoryReconciliationV1,
        clock: &mut T,
    ) -> Result<crate::CurrentAttachmentReconciliationV1, crate::AttachmentReconciliationError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_reconciliation::reconcile_current(
            self.reconciler.journal_mut(),
            desired,
            inventory,
            clock,
        )
    }

    /// Plans one attachment's source custody from an exact joined Mount snapshot.
    ///
    /// The plan binds current desired/view state, assignment and policy,
    /// namespace allocation, lease, pre-catalog Create semantics, logical source
    /// binding, and both Mount inventories. It contains no descriptor or effect
    /// authority and does not contact Mount.
    ///
    /// # Errors
    ///
    /// Rejects stale desired, target, or inventory state; source/resource
    /// substitution; faulted or abandoned custody; invalid bounds; and corrupt
    /// protected history.
    #[cfg(target_os = "linux")]
    pub(crate) fn plan_current_attachment_source<T>(
        &mut self,
        desired: crate::DurableAttachmentDesiredStateV1,
        inventory: crate::CurrentMountFilesystemInventoryV1,
        target: crate::runtime_scope::CurrentNamespaceTarget,
        bounds: crate::AttachmentSourceBoundsV1,
        clock: &mut T,
    ) -> Result<crate::CurrentAttachmentSourcePlanV1, crate::AttachmentSourceError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_source::plan_current(
            self.reconciler.journal_mut(),
            desired,
            inventory,
            target,
            bounds,
            clock,
        )
    }

    /// Persists one exact attachment-source custody attempt without dispatching it.
    ///
    /// Acquire and Release retain their exact canonical Mount request body.
    /// Consume retains an already durable successful detached-create completion.
    /// The predecessor must equal the last exact completion for this attachment.
    ///
    /// # Errors
    ///
    /// Rejects stale planning evidence, action/body mismatches, request-ID reuse,
    /// an open or substituted predecessor, and capacity or durability failure.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_current_attachment_source_attempt<T>(
        &mut self,
        plan: crate::CurrentAttachmentSourcePlanV1,
        kind: crate::AttachmentSourceAttemptKindV1,
        operation_id: OperationId,
        request_digest: ObjectDigest,
        exact_request_body: Vec<u8>,
        mount_completion: Option<&crate::CompletedCurrentAttachmentMountAttemptV1>,
        expected_predecessor: Option<ObjectDigest>,
        clock: &mut T,
    ) -> Result<crate::DurableAttachmentSourceAttemptV1, crate::AttachmentSourceError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_source::record_current_attempt(
            self.reconciler.journal_mut(),
            plan,
            kind,
            operation_id,
            request_digest,
            exact_request_body,
            mount_completion,
            expected_predecessor,
            clock,
        )
    }

    /// Commits exact current evidence that closes a source-custody attempt.
    ///
    /// Acquire requires the exact acquisition to become usable. Consume requires
    /// the retained Mount completion plus an exact installed-and-verified or
    /// safely released resource. Release requires authoritative terminal source
    /// inventory with no live resource.
    ///
    /// # Errors
    ///
    /// Rejects stale or substituted attempt, inventory, acquisition, resource,
    /// verification, predecessor, or desired-state evidence.
    #[cfg(target_os = "linux")]
    pub(crate) fn record_current_attachment_source_completion<T>(
        &mut self,
        attempt: crate::DurableAttachmentSourceAttemptV1,
        plan: crate::CurrentAttachmentSourcePlanV1,
        clock: &mut T,
    ) -> Result<crate::DurableAttachmentSourceCompletionV1, crate::AttachmentSourceError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_source::record_completion(
            self.reconciler.journal_mut(),
            attempt,
            plan,
            clock,
        )
    }

    /// Recovers the exact open source-custody attempt for an attachment.
    ///
    /// The returned record is audit and idempotency evidence only. Its exact
    /// request still requires fresh authorization, inventory, and transport
    /// currentness before any future resume adapter may issue it.
    ///
    /// # Errors
    ///
    /// Rejects malformed protected attempt/completion history.
    #[cfg(target_os = "linux")]
    pub fn recover_open_attachment_source_attempt(
        &mut self,
        attachment_id: aos_sandbox_core::AttachmentId,
    ) -> Result<Option<crate::DurableAttachmentSourceAttemptV1>, crate::AttachmentSourceError> {
        crate::attachment_source::recover_open_attempt(self.reconciler.journal_mut(), attachment_id)
    }

    /// Durably records exact post-attach kernel evidence for one generation.
    ///
    /// The input must be a current reconciliation whose closed action is
    /// `Verify`. The controller binds the desired record, current namespace
    /// allocation and assignment, complete installed Mount resource, and
    /// validated inventory snapshot in one immutable record. This commit
    /// makes that snapshot stale; a subsequent fresh inventory must reproduce
    /// the verified resource before reconciliation reports `Ready`.
    ///
    /// # Errors
    ///
    /// Rejects any non-verification action, stale desired, inventory, or live
    /// namespace evidence, a changed installed resource, conflicting durable
    /// verification, capacity exhaustion, and failed protected commits.
    #[cfg(target_os = "linux")]
    pub(crate) fn record_current_attachment_verification<T>(
        &mut self,
        reconciliation: crate::CurrentAttachmentReconciliationV1,
        clock: &mut T,
    ) -> Result<crate::DurableAttachmentVerificationV1, crate::AttachmentVerificationError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_verification::record_current(
            self.reconciler.journal_mut(),
            reconciliation,
            clock,
        )
    }

    /// Reacquires live Mount preparation for one exact pending attachment attempt.
    ///
    /// The reconciliation must report `Wait` for a validated broker-pending
    /// request. Recovery loads that request's immutable durable attempt, preserves
    /// its request ID, deadline, and Apply body, and reacquires the same catalog
    /// commitment. Release remains catalogless. The original deadline is never
    /// renewed, so elapsed or substituted work fails closed.
    ///
    /// # Errors
    ///
    /// Rejects non-pending or stale reconciliation, missing or mismatched durable
    /// attempt state, an action/input mismatch, expired authority, or a changed
    /// live catalog, request, namespace target, or broker identity.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_current_attachment_mount_resume<T>(
        &mut self,
        reconciliation: crate::CurrentAttachmentReconciliationV1,
        input: crate::AttachmentMountPreparationInputV1,
        clock: &mut T,
    ) -> Result<crate::PreparedCurrentAttachmentMountResumeV1, crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_mount::prepare_current_resume(
            self.reconciler.journal_mut(),
            reconciliation,
            input,
            clock,
        )
    }

    /// Rechecks exact pending-attempt preparation without binding fresh authority.
    ///
    /// # Errors
    ///
    /// Rejects changed desired state, inventory, durable attempt bytes, live
    /// target, reacquired catalog, or original deadline.
    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_current_attachment_mount_resume<T>(
        &mut self,
        prepared: &crate::PreparedCurrentAttachmentMountResumeV1,
        clock: &mut T,
    ) -> Result<(), crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        prepared.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Binds the exact original signed Mount plan to a pending request.
    ///
    /// The plan and signature must reproduce the original admission exactly and
    /// remain live under the current assignment. A current ownership lease is
    /// attached only when the resume token is constructed. Binding cannot change
    /// the original Apply bytes or deadline.
    ///
    /// # Errors
    ///
    /// Rejects stale replay evidence, a substituted or unauthorized plan,
    /// changed ownership authority, or an expired original deadline.
    #[cfg(target_os = "linux")]
    pub(crate) fn bind_current_attachment_mount_resume_plan<T>(
        &mut self,
        prepared: crate::PreparedCurrentAttachmentMountResumeV1,
        signed_plan: crate::SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<crate::PreparedCurrentAttachmentMountResumeDispatchV1, crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_mount::bind_resume_signed_plan(
            self.reconciler.journal_mut(),
            prepared,
            signed_plan,
            clock,
        )
    }

    /// Rechecks a signed pending-attempt resume without constructing its packet.
    ///
    /// # Errors
    ///
    /// Rejects changed desired, inventory, attempt, signed authority, catalog,
    /// live target, or deadline evidence.
    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_current_attachment_mount_resume_dispatch<T>(
        &mut self,
        prepared: &crate::PreparedCurrentAttachmentMountResumeDispatchV1,
        clock: &mut T,
    ) -> Result<(), crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        prepared.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Constructs a refreshed packet for an already durable pending attempt.
    ///
    /// This transition writes no second admission. It re-verifies the current
    /// ownership lease and exact signed plan, injects the original deadline into
    /// the immutable body, and requires the resulting Apply body to equal the
    /// admitted bytes exactly. The returned token uses the ordinary
    /// signed-plan-authorized dispatch and completion-recording path.
    ///
    /// # Errors
    ///
    /// Rejects stale or missing durable state, changed semantics, request bytes,
    /// catalog or namespace authority, expired plan/lease/deadline, and corrupt
    /// cross-referenced history.
    #[cfg(target_os = "linux")]
    pub(crate) fn resume_current_attachment_mount_attempt<T>(
        &mut self,
        prepared: crate::PreparedCurrentAttachmentMountResumeDispatchV1,
        clock: &mut T,
    ) -> Result<crate::DurableCurrentAttachmentMountAttemptV1, crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_mount::resume_current(self.reconciler.journal_mut(), prepared, clock)
    }

    /// Derives and prepares the exact Mount action selected by reconciliation.
    ///
    /// No protobuf intent comes from the caller. Create and publication fields
    /// derive from current desired state; teardown reproduces the inventoried
    /// physical recipe while carrying the current desired generation and lease.
    /// Catalog-backed actions require the supplied Mount channel, while release
    /// is explicitly catalogless. The result remains non-authorizing.
    ///
    /// # Errors
    ///
    /// Rejects a stale or non-effect reconciliation, an action/input mismatch,
    /// changed lease time, invalid derived semantics, or failed Mount catalog
    /// exchange and live-target validation.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_current_attachment_mount<T>(
        &mut self,
        reconciliation: crate::CurrentAttachmentReconciliationV1,
        input: crate::AttachmentMountPreparationInputV1,
        clock: &mut T,
    ) -> Result<crate::PreparedCurrentAttachmentMountV1, crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_mount::prepare_current(
            self.reconciler.journal_mut(),
            reconciliation,
            input,
            clock,
        )
    }

    /// Rechecks a plan-derived Mount preparation without binding authority.
    ///
    /// # Errors
    ///
    /// Rejects changed desired state, inventory, lease time, live target, or
    /// catalog lifetime.
    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_current_attachment_mount<T>(
        &mut self,
        prepared: &crate::PreparedCurrentAttachmentMountV1,
        clock: &mut T,
    ) -> Result<(), crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        prepared.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Binds a separately signed Mount plan to the exact reconciler-derived action.
    ///
    /// # Errors
    ///
    /// Rejects stale reconciliation evidence, a substituted or unauthorized
    /// plan, changed ownership authority, or an expired preparation.
    #[cfg(target_os = "linux")]
    pub(crate) fn bind_current_attachment_mount_plan<T>(
        &mut self,
        prepared: crate::PreparedCurrentAttachmentMountV1,
        signed_plan: crate::SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<crate::PreparedCurrentAttachmentMountDispatchV1, crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_mount::bind_signed_plan(
            self.reconciler.journal_mut(),
            prepared,
            signed_plan,
            clock,
        )
    }

    /// Durably admits the exact plan-derived Mount attempt before broker I/O.
    ///
    /// Admission rechecks desired state, the planning inventory, lease time,
    /// signed authority, and the live target before committing. The new attempt
    /// intentionally makes that older inventory snapshot stale. The returned
    /// token keeps the desired generation and lease as dispatch guards.
    ///
    /// # Errors
    ///
    /// Rejects stale evidence, deadline or authority mismatch, conflicting
    /// replay, corrupt cross-references, capacity, and failed durable commit.
    #[cfg(target_os = "linux")]
    pub(crate) fn admit_current_attachment_mount_attempt<T>(
        &mut self,
        prepared: crate::PreparedCurrentAttachmentMountDispatchV1,
        deadline_boottime_nanoseconds: u64,
        clock: &mut T,
    ) -> Result<crate::DurableCurrentAttachmentMountAttemptV1, crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_mount::admit_current(
            self.reconciler.journal_mut(),
            prepared,
            deadline_boottime_nanoseconds,
            clock,
        )
    }

    /// Rechecks an admitted or resumed attachment Mount attempt without dispatch.
    ///
    /// # Errors
    ///
    /// Rejects changed desired state or lease status, stale live authority,
    /// substituted durable bytes, and expired deadlines. A resumed token also
    /// requires its validated pending inventory evidence to remain current.
    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_current_attachment_mount_attempt<T>(
        &mut self,
        attempt: &crate::DurableCurrentAttachmentMountAttemptV1,
        clock: &mut T,
    ) -> Result<(), crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        attempt.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Dispatches one durable plan-derived Mount attempt and records its receipt.
    ///
    /// The desired generation and lease are rechecked around the existing
    /// validated Mount exchange. This does not establish the actual syscall
    /// writer without the separately required signed result and confined
    /// deployment. A successful effect is recorded before a
    /// concurrent stale guard can withhold the live completion token.
    ///
    /// # Errors
    ///
    /// Rejects stale desired or live authority, service-subject correlation and
    /// protocol failures, substituted results, conflicting completion, and
    /// journal errors.
    #[cfg(target_os = "linux")]
    pub(crate) fn dispatch_current_attachment_mount_attempt<T>(
        &mut self,
        attempt: crate::DurableCurrentAttachmentMountAttemptV1,
        client: crate::mount_attempt::MountDispatchClient,
        clock: &mut T,
    ) -> Result<crate::CompletedCurrentAttachmentMountAttemptV1, crate::AttachmentMountError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::attachment_mount::dispatch_current(
            self.reconciler.journal_mut(),
            attempt,
            client,
            clock,
        )
    }

    /// Issues a local holder channel from an acquired current-runtime scope.
    ///
    /// The complete Host and payload proof moves into the live session. Scope
    /// identities derive from its protected holder decision, while current
    /// publication policy determines the cache grant. Runtime issuance evidence
    /// commits before the endpoint escapes. Current authority and the
    /// original observation deadline are rechecked before and after commit.
    ///
    /// The clock must be the same protected adapter used at acquisition. The
    /// endpoint must be delivered only to the intended execution; invalidate
    /// its session if delivery fails. Successful issuance does not authorize
    /// publication, and later admission requires fresh runtime authority.
    ///
    /// # Errors
    ///
    /// Rejects changed or expired runtime authority, stale execution pins,
    /// denied policy, capacity, clock, encoding, or protected commit failures.
    /// Post-commit failure can retain an audited capability without a live session.
    #[cfg(target_os = "linux")]
    pub(crate) fn provision_current_runtime_ingress<T>(
        &mut self,
        sessions: &mut crate::local_sessions::LocalSessionRegistry,
        runtime: crate::runtime_scope::CurrentRuntimeScope,
        cache_resource: aos_sandbox_core::ResourceId,
        config: crate::local_provisioning::LocalProvisioningPolicy,
        clock: &mut T,
    ) -> Result<
        crate::local_sessions::LocalSessionEndpoint,
        crate::local_provisioning::LocalProvisioningError,
    >
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::local_provisioning::provision_runtime(
            self.reconciler.journal_mut(),
            sessions,
            runtime,
            cache_resource,
            config,
            clock,
        )
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
    pub(crate) fn provision_local_ingress<T>(
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
    pub(crate) fn register_publisher_execution<T>(
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
    pub(crate) fn register_publisher_challenge<T>(
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

    /// Joins the actual holder record to a pending challenge of a live publisher.
    ///
    /// The returned non-cloneable context retains both channel observations and
    /// exclusive journal access. It checks current protected issuance and policy
    /// consistency, but does not prove current runtime assignment, source release,
    /// root authority, reservation, or admission. No challenge is consumed and
    /// no signing or completion permit is issued.
    ///
    /// # Errors
    /// Rejects malformed or substituted requests, absent or dead channels,
    /// stale protected claims, revoked capabilities, unhealthy storage, and
    /// expired or inconsistent clocks. Failure after receiving a holder record
    /// closes its ingress; later receive or explicit invalidation removes the slot.
    #[cfg(target_os = "linux")]
    pub(crate) fn join_publisher_request<'a, T>(
        &'a mut self,
        holders: &'a mut crate::local_sessions::LocalSessionRegistry,
        publishers: &'a mut crate::publisher_sessions::PublisherSessionRegistry,
        holder_session: crate::local_sessions::LocalSessionId,
        config: crate::publisher_control::PublisherJoinPolicy,
        clock: &mut T,
    ) -> Result<
        crate::publisher_control::JoinedPublisherRequest<'a>,
        crate::publisher_control::PublisherJoinError,
    >
    where
        T: FnMut() -> Result<
            aos_sandbox_core::ownership_lease::RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::publisher_control::join_holder_request(
            self.reconciler.journal_mut(),
            holders,
            publishers,
            holder_session,
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
        let plan = self.compiler.compile(
            self.reconciler.journal_mut(),
            canonical_request,
            request_digest,
        )?;
        self.accept_compiled_plan(plan, request_digest)
    }

    /// Admits one public request with live TLS peer evidence and protected compilation.
    ///
    /// The RPC owner must supply the exact canonical method/body received on
    /// the stream owning `peer`. Principal and project are independently bound
    /// into the admission digest. Session exporters and capability handles are
    /// deliberately excluded from that digest so a freshly authorized reconnect
    /// can replay the same semantic request. Every attempt still requires current
    /// protected authorization; possession of a prior digest grants nothing.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized input, stale peer evidence, unsupported public
    /// compilation, authorization failure, digest mismatch, or durable admission
    /// failure. Compilation success is never reported as durable acceptance.
    #[cfg(target_os = "linux")]
    pub fn admit_public(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        canonical_request: &[u8],
    ) -> Result<AcceptOutcome, ControllerServiceError> {
        if canonical_request.is_empty() {
            return Err(ControllerServiceError::EmptyRequest);
        }
        if canonical_request.len() > self.limits.maximum_request_bytes {
            return Err(ControllerServiceError::RequestTooLarge);
        }
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;

        let request_digest = public_controller_request_digest(
            self.scope,
            peer.principal(),
            peer.project(),
            canonical_request,
        );
        let plan = self.compiler.compile_public(
            self.reconciler.journal_mut(),
            peer,
            capability_id,
            canonical_request,
            request_digest,
        )?;

        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        self.accept_compiled_plan(plan, request_digest)
    }

    fn accept_compiled_plan(
        &mut self,
        plan: OperationPlan,
        request_digest: [u8; 32],
    ) -> Result<AcceptOutcome, ControllerServiceError> {
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

    /// Advances one bounded quantum under a paired controller clock sample.
    ///
    /// The sample is used only for public observation timestamps. Authority
    /// checks continue to consume their own freshly rechecked protected clock
    /// observations at the effect boundary. The sample grants no authority;
    /// activated services must source it from their protected clock adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError::Reconciler`] for the same failures as
    /// [`Self::reconcile_quantum`] or for a nonmonotone public timestamp.
    pub fn reconcile_quantum_at(
        &mut self,
        clock: RawPairedClockSample,
    ) -> Result<ControllerQuantumReport, ControllerServiceError> {
        let mut steps = Vec::with_capacity(self.limits.reconciliation_quantum);
        let mut idle = false;
        for _ in 0..self.limits.reconciliation_quantum {
            let Some((operation_id, outcome)) =
                self.reconciler.reconcile_next_at(clock.wall_seconds())?
            else {
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

    /// Loads one established public operation resource from the durable ledger.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError::Reconciler`] when the operation or its
    /// effect ledger fails read-only validation.
    pub fn public_operation(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<aos_proto::aos::sandbox::v1::Operation>, ControllerServiceError> {
        self.reconciler
            .public_operation(operation_id)
            .map_err(ControllerServiceError::Reconciler)
    }

    /// Reauthorizes and loads one public operation over a live registered peer.
    ///
    /// Absence, legacy observations without an admitted authorization scope,
    /// project mismatch, revocation, expiry, and insufficient capability grants
    /// all return `None` so the caller can preserve concealment. The exact
    /// protobuf body is committed into current channel authorization.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError`] when durable operation state is
    /// corrupt or the fixed controller clock cannot be opened.
    #[cfg(target_os = "linux")]
    pub fn authorized_public_operation(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        operation_id: OperationId,
        protobuf_body: &[u8],
    ) -> Result<Option<aos_proto::aos::sandbox::v1::Operation>, ControllerServiceError> {
        let Some(scope) = self
            .reconciler
            .public_operation_authorization(operation_id)?
        else {
            return Ok(None);
        };
        if peer.project() != scope.project() {
            return Ok(None);
        }
        let authorization = self
            .dormant_cli_authorization()
            .map_err(|_| ControllerServiceError::PublicAuthorizationUnavailable)?
            .authorize_public_operation_read(peer, capability_id, &scope, protobuf_body);
        if authorization.is_err() {
            return Ok(None);
        }

        self.public_operation(operation_id)
    }

    /// Reauthorizes one exact public read over a live registered peer.
    ///
    /// The method, capability vocabulary, selector, and exact protobuf body
    /// must come from the generated service handler after decoding its closed
    /// request type. Authorization failure is concealed as `None`; it never
    /// creates read authority from the lookup header or caller identity fields.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError::PublicAuthorizationUnavailable`] when
    /// the fixed protected clock cannot be opened.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_public_read(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        method: PublicApiAuditMethodV1,
        resource_kind: aos_sandbox_core::ResourceKind,
        operation: aos_sandbox_core::Operation,
        selector: aos_sandbox_core::Selector,
        protobuf_body: &[u8],
    ) -> Result<Option<AuditAuthorizationV1>, ControllerServiceError> {
        let authorization = self
            .dormant_cli_authorization()
            .map_err(|_| ControllerServiceError::PublicAuthorizationUnavailable)?
            .authorize_public_read(
                peer,
                capability_id,
                method,
                resource_kind,
                operation,
                selector,
                protobuf_body,
            );

        Ok(authorization.ok())
    }

    /// Reauthorizes and executes one public projection read in the journal owner.
    ///
    /// Authorization and projection loading are sequenced in one controller
    /// command. The async service never receives journal access, and no row can
    /// cross the authenticated peer's project boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError`] when current authorization is
    /// unavailable or durable projection and operation state is corrupt.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn authorized_public_projection_read(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        method: PublicApiAuditMethodV1,
        resource_kind: aos_sandbox_core::ResourceKind,
        operation: aos_sandbox_core::Operation,
        selector: aos_sandbox_core::Selector,
        protobuf_body: &[u8],
        query: crate::controller_service::public_projection::PublicProjectionQueryV1,
    ) -> Result<
        Option<crate::controller_service::public_projection::AuthorizedPublicProjectionReadV1>,
        ControllerServiceError,
    > {
        let Some(authorization) = self.authorize_public_read(
            peer,
            capability_id,
            method,
            resource_kind,
            operation,
            selector,
            protobuf_body,
        )?
        else {
            return Ok(None);
        };
        let records = match query {
            crate::controller_service::public_projection::PublicProjectionQueryV1::One {
                kind,
                resource_id,
            } => {
                let Some(record) = self.public_projection(kind, resource_id)? else {
                    return Ok(None);
                };
                if record.project() != peer.project() {
                    return Ok(None);
                }
                vec![record]
            }
            crate::controller_service::public_projection::PublicProjectionQueryV1::List {
                kind,
                project,
            } => {
                if project != peer.project() {
                    return Ok(None);
                }
                self.public_projections(kind, project)?
            }
            crate::controller_service::public_projection::PublicProjectionQueryV1::Related {
                kind,
                scope_kind,
                scope_id,
            } => {
                let Some(scope) = self.public_projection(scope_kind, scope_id)? else {
                    return Ok(None);
                };
                if scope.project() != peer.project() {
                    return Ok(None);
                }
                self.public_projections(kind, scope.project())?
            }
        };

        Ok(Some(
            crate::controller_service::public_projection::AuthorizedPublicProjectionReadV1::new(
                authorization,
                records,
            ),
        ))
    }

    /// Loads one checked durable public resource projection.
    ///
    /// The linked public operation and its immutable project authorization are
    /// validated before the projection escapes the sole journal owner. Desired
    /// state alone therefore cannot manufacture a public observation.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError`] for a corrupt projection, operation
    /// ledger, or project linkage.
    pub fn public_projection(
        &mut self,
        kind: crate::controller_service::public_projection::PublicProjectionKindV1,
        resource_id: [u8; 16],
    ) -> Result<
        Option<crate::controller_service::public_projection::PublicProjectionRecordV1>,
        ControllerServiceError,
    > {
        let projection =
            crate::controller_service::public_projection::PublicProjectionStoreV1::new(
                self.reconciler.journal_mut(),
            )
            .get(kind, resource_id)?;
        let Some(projection) = projection else {
            return Ok(None);
        };
        self.validate_public_projection_operation(&projection)?;

        Ok(Some(projection))
    }

    /// Lists one checked durable public resource kind in stable identity order.
    ///
    /// Every retained row must link to a valid public operation admitted for
    /// the same project. A single corrupt row fails the complete immutable
    /// listing rather than silently changing visibility.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError`] for a corrupt projection, operation
    /// ledger, or project linkage.
    pub fn public_projections(
        &mut self,
        kind: crate::controller_service::public_projection::PublicProjectionKindV1,
        project: aos_sandbox_core::ProjectId,
    ) -> Result<
        Vec<crate::controller_service::public_projection::PublicProjectionRecordV1>,
        ControllerServiceError,
    > {
        let projections =
            crate::controller_service::public_projection::PublicProjectionStoreV1::new(
                self.reconciler.journal_mut(),
            )
            .list(kind, project)?;
        for projection in &projections {
            self.validate_public_projection_operation(projection)?;
        }

        Ok(projections)
    }

    fn validate_public_projection_operation(
        &mut self,
        projection: &crate::controller_service::public_projection::PublicProjectionRecordV1,
    ) -> Result<(), ControllerServiceError> {
        let operation = projection.operation();
        if self.reconciler.public_operation(operation)?.is_none() {
            return Err(crate::ReconcilerError::CorruptLedger(
                "public projection refers to an absent public operation",
            )
            .into());
        }
        let authorization = self
            .reconciler
            .public_operation_authorization(operation)?
            .ok_or(crate::ReconcilerError::CorruptLedger(
                "public projection operation has no authorization scope",
            ))?;
        if authorization.project() != projection.project() {
            return Err(crate::ReconcilerError::CorruptLedger(
                "public projection project differs from its operation scope",
            )
            .into());
        }

        Ok(())
    }

    /// Returns one validated durable operation that still requires active work.
    ///
    /// This audit performs no admission, durable transition, or executor call.
    /// It is suitable for a read-only controller activation that must refuse
    /// readiness rather than attempt recovery without installed authority.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError::Reconciler`] when journal health or
    /// any durable ledger relationship fails validation.
    pub fn validated_unfinished_operation(
        &mut self,
    ) -> Result<Option<ValidatedUnfinishedOperationV1>, ControllerServiceError> {
        self.reconciler
            .validated_unfinished_operation()
            .map_err(ControllerServiceError::Reconciler)
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
    pub(crate) fn resume_ownership<A, T>(
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
    /// The fixed controller clock required for current public authorization failed.
    #[error("current public authorization is unavailable")]
    PublicAuthorizationUnavailable,
    /// A durable public-resource projection is malformed or inconsistent.
    #[error(transparent)]
    PublicProjection(#[from] crate::controller_service::public_projection::PublicProjectionError),
    /// Durable admission or reconciliation failed.
    #[error(transparent)]
    Reconciler(#[from] ReconcilerError),
}

#[cfg(target_os = "linux")]
fn public_controller_request_digest(
    scope: ControllerRequestScopeV1,
    principal: aos_sandbox_core::PrincipalId,
    project: aos_sandbox_core::ProjectId,
    canonical_request: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(PUBLIC_REQUEST_DIGEST_DOMAIN)
        .chain_update(scope.digest().as_bytes())
        .chain_update(principal.as_bytes())
        .chain_update(project.as_bytes())
        .chain_update((canonical_request.len() as u64).to_be_bytes())
        .chain_update(canonical_request)
        .finalize()
        .into()
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

    use aos_proto::aos::sandbox::local::v1::BrokerMethod;

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
            _journal: &mut Journal,
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
                    EffectPlan::new(
                        EffectDomain::Host,
                        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                        b"apply".to_vec(),
                    )
                    .map_err(|_| OperationCompilationError::Rejected)?,
                ],
            )
            .map_err(|_| OperationCompilationError::Rejected)
        }
    }

    fn scope() -> ControllerRequestScopeV1 {
        ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0x42; 32])).unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn public_admission_digest_binds_authenticated_identity_scope_and_body() {
        use aos_sandbox_core::{PrincipalId, ProjectId};

        let principal = PrincipalId::from_bytes([1; 16]);
        let project = ProjectId::from_bytes([2; 16]);
        let request = b"canonical method and body";
        let digest = public_controller_request_digest(scope(), principal, project, request);

        assert_eq!(
            digest,
            public_controller_request_digest(scope(), principal, project, request)
        );
        assert_ne!(digest, controller_request_digest(scope(), request));
        assert_ne!(
            digest,
            public_controller_request_digest(
                scope(),
                PrincipalId::from_bytes([3; 16]),
                project,
                request
            )
        );
        assert_ne!(
            digest,
            public_controller_request_digest(
                scope(),
                principal,
                ProjectId::from_bytes([4; 16]),
                request
            )
        );
        assert_ne!(
            digest,
            public_controller_request_digest(
                ControllerRequestScopeV1::new(ObjectDigest::from_bytes([5; 32])).unwrap(),
                principal,
                project,
                request,
            )
        );
        assert_ne!(
            digest,
            public_controller_request_digest(
                scope(),
                principal,
                project,
                b"another method and body"
            )
        );
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
    fn compilation_observes_revocation_in_the_controllers_sole_journal() {
        use aos_sandbox_core::CapabilityId;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        struct CurrentRegistryCompiler(CapabilityId);

        impl ActivatedOperationCompiler for CurrentRegistryCompiler {
            fn compile(
                &mut self,
                journal: &mut Journal,
                request: &[u8],
                digest: [u8; 32],
            ) -> Result<OperationPlan, OperationCompilationError> {
                // This fixture checks journal plumbing, not complete request authorization.
                let registry =
                    PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
                        .map_err(|_| OperationCompilationError::Rejected)?;
                registry
                    .resolve_current(self.0)
                    .map_err(|_| OperationCompilationError::Rejected)?;
                drop(registry);
                Compiler.compile(journal, request, digest)
            }
        }

        let directory = TestDirectory::new();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            &directory.0,
            "protected.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let capability_id = CapabilityId::new();
        PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default())
            .unwrap()
            .install_from_trusted_controller(
                [1; 16],
                crate::publisher_authority::tests::capability(capability_id, 200),
            )
            .unwrap();
        let mut controller = NodeController::new(
            scope(),
            NodeControllerLimits::default(),
            CurrentRegistryCompiler(capability_id),
            Reconciler::new(journal, Executor::default()),
        );

        assert!(controller.admit(&[7]).is_ok());
        controller
            .publisher_capabilities(PublisherAuthorityLimits::default())
            .unwrap()
            .revoke_from_trusted_controller([2; 16], capability_id)
            .unwrap();

        assert!(matches!(
            controller.admit(&[8]),
            Err(ControllerServiceError::Compilation(
                OperationCompilationError::Rejected
            ))
        ));
        let journal = controller.reconciler.journal_mut();
        assert!(journal.get(RecordNamespace::DesiredState, &[8]).is_none());
        assert!(journal.get(RecordNamespace::Operation, &[8; 16]).is_none());
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
