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
//!
//! Private children keep operator-recovery ownership and its durable replay
//! state machine, original attach custody, destination-slot effects, lifecycle
//! boot-inventory joins, and live public authorization beside their invariants.
//! Their methods continue to borrow this controller's sole reconciler and Journal.

use aos_sandbox_core::{ObjectDigest, OperationId, RawPairedClockSample};
use aos_sandbox_ownership_protocol::protocol::session_client::OwnershipAuthoritySessionClient;
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};

use aos_sandbox_protocol::public_api::request::DormantPublicApiClientV1;
#[cfg(test)]
use crate::RecordNamespace;

#[cfg(target_os = "linux")]
use crate::cli_model::{
    AuditAuthorizationV1, PublicApiAuditMethodV1,
};
#[cfg(target_os = "linux")]
use aos_sandbox_protocol::public_api::proto_json::CheckedPolicyPlanV1;
#[cfg(target_os = "linux")]
use crate::public_policy_planner::{
    AuthorizedPublicPolicyPlanRequestV1, PublicPolicyPlanningErrorV1,
    ResolvedPublicPolicyPlanRequestV1,
};
use crate::publisher_authority::{
    PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
};
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};
use crate::{
    AcceptOutcome, OperationPlan, OwnershipAuthorityVerifier, OwnershipClockObservationError,
    OwnershipGateStatusV1, OwnershipResumeError,
    OwnershipResumeOutcomeV1, ReconcileOutcome, Reconciler, ReconcilerError,
    SingleNodeEffectExecutor, ValidatedUnfinishedOperationV1,
};

#[cfg(target_os = "linux")]
mod destination_slot;

#[cfg(target_os = "linux")]
mod lifecycle_boot_inventory;

mod operator_recovery;

pub use operator_recovery::{
    DormantOperatorRecoveryServiceErrorV1, MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1,
    MAXIMUM_OPERATOR_RECOVERY_EFFECT_ATTEMPTS_V1, MAXIMUM_PENDING_OPERATOR_RECOVERIES_V1,
};

pub(crate) use operator_recovery::{
    DormantOperatorRecoveryAdmissionV1, DormantOperatorRecoveryCurrentObservationV1,
    DormantOperatorRecoveryCurrentObserverV1, DormantOperatorRecoveryCurrentQueryV1,
    DormantOperatorRecoveryEffectDispositionV1, DormantOperatorRecoveryEffectExecutorV1,
    DormantOperatorRecoveryEffectHandoffV1, DormantOperatorRecoveryEffectObserverV1,
    DormantOperatorRecoveryEffectQueryV1, DormantOperatorRecoveryEffectReceiptV1,
    DormantOperatorRecoveryOwnerV1, DormantOperatorRecoveryPendingV1,
    DormantOperatorRecoveryPublicAuthorizationV1, DormantOperatorRecoveryPublicAuthorizerV1,
    DormantOperatorRecoveryPublicServiceV1, DormantOperatorRecoverySynchronizedV1,
    DormantOperatorRecoveryTerminalCommitV1, DormantOperatorRecoveryTerminalV1,
    PreparedOperatorRecoveryCurrentV1, operator_repair_successor_current_v1,
    prepare_operator_recovery_operation_current_v1, prepare_operator_recovery_sandbox_current_v1,
};

use operator_recovery::{decode_recovery_current, recovery_current_key, validate_recovery_current};

#[cfg(target_os = "linux")]
mod operator_recovery_issuance;

#[cfg(target_os = "linux")]
pub(crate) use operator_recovery_issuance::{
    RepairPublicTerminalV1,
    has_operator_storage_repair_settlement_debt_v1,
    verify_atomic_operator_storage_repair_terminal_v2,
    verify_operator_storage_repair_failure_v1,
};

#[cfg(target_os = "linux")]
pub use operator_recovery_issuance::{
    OperatorRecoveryIssuanceErrorV1 as OperatorStorageRepairErrorV1,
    OperatorStorageRepairBridgeV1, StorageRepairAdmissionV1, StorageRepairProgressV1,
    StorageRepairAdmissionDraftV1, StorageRepairAdmissionPreparationV1,
    OperatorStorageRepairTerminalV1,
};

#[cfg(target_os = "linux")]
mod original_attach_grant;
#[cfg(target_os = "linux")]
mod public_api_authorization;
#[cfg(target_os = "linux")]
mod protected_clock;
#[cfg(target_os = "linux")]
pub(crate) use protected_clock::ControllerProtectedClockV1;
#[cfg(target_os = "linux")]
pub(crate) use public_api_authorization::DormantCliAuthorizationOwnerV1;
#[cfg(target_os = "linux")]
pub(crate) use public_api_authorization::prepare_original_gateway_git_read_v1;
#[cfg(target_os = "linux")]
pub use original_attach_grant::{
    CurrentOriginalAttachConsumeCutV3, CurrentOriginalAttachHostConsumeDraftV3,
};
#[cfg(target_os = "linux")]
pub(crate) use public_api_authorization::{
    authorize_public_operator_recovery_v1, authorize_resolved_public_mutation_v1,
};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-request.v1\0";
#[cfg(target_os = "linux")]
const PUBLIC_REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-public-request.v1\0";
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

    /// Commits one authenticated public request under this controller scope.
    #[must_use]
    pub fn public_request_digest(
        self,
        principal: aos_sandbox_core::PrincipalId,
        project: aos_sandbox_core::ProjectId,
        canonical_request: &[u8],
    ) -> [u8; 32] {
        public_controller_request_digest(self, principal, project, canonical_request)
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

    /// Compiles one public operator-recovery request under current protected state.
    ///
    /// Operator recovery is separate because its request identifies either a
    /// sandbox or an operation without accepting a caller-selected resource
    /// kind. Implementations must decode the canonical envelope, require the
    /// `OperatorService/Recover` method, resolve the current resource kind from
    /// `journal`, authorize that exact kind, selector, method, and body against
    /// `peer`, and enforce the recovery evidence and resource-version fence.
    /// The default rejects and never falls back to ordinary public compilation.
    ///
    /// # Errors
    ///
    /// Returns [`OperationCompilationError`] for malformed input, unsupported
    /// recovery, or rejected current authentication, authorization, evidence,
    /// policy, and concurrency checks.
    #[cfg(target_os = "linux")]
    fn compile_public_operator_recovery(
        &mut self,
        _journal: &mut crate::Journal,
        _peer: &crate::public_api_session::PublicApiPeer,
        _capability_id: aos_sandbox_core::CapabilityId,
        _canonical_request: &[u8],
        _request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError> {
        Err(OperationCompilationError::Rejected)
    }

    /// Computes one pure policy plan from a currently authorized public request.
    ///
    /// The controller constructs `request` only after exact request validation,
    /// live-peer checks, and current protected authorization. The lent journal
    /// lets an implementation resolve current policy inputs without retaining a
    /// second owner. Implementations must not commit desired state or perform
    /// effects. The default remains fail-closed for deployments without an
    /// installed policy input resolver.
    ///
    /// # Errors
    ///
    /// Returns [`PublicPolicyPlanningErrorV1`] when policy inputs are unavailable
    /// or the currently authorized request cannot produce a plan.
    #[cfg(target_os = "linux")]
    fn plan_public_policy(
        &mut self,
        _journal: &mut crate::Journal,
        _request: AuthorizedPublicPolicyPlanRequestV1,
    ) -> Result<aos_proto::aos::sandbox::v1::PolicyPlan, PublicPolicyPlanningErrorV1> {
        Err(PublicPolicyPlanningErrorV1::Unavailable)
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

/// Selects only an installed configured-project comparison recipe.
///
/// The actual pair and complete retained Controller histories select this
/// routing DATA; neither variant creates a Source owner or Root admission.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfiguredProjectStartupSelectionV3 {
    /// Preserves the same-global or absent ordinary startup recipe.
    Ordinary,
    /// Selects genuine configured B beside a different global predecessor.
    MixedProject,
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

// Recovery and physical Repair compare this same owned current-head DATA.
// Keeping it at their common ancestor preserves private fields across both.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveryCurrentHeadV1 {
    kind: u8,
    allowed_actions: u8,
    version: Vec<u8>,
    desired_generation: u64,
    observation_sequence: u64,
    transition: (i64, u32),
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Lists pending grouped Storage sources before broker-session rollover.
    ///
    /// # Errors
    ///
    /// Returns an error when the sole controller journal is not protected or
    /// one source record is corrupt.
    pub fn pending_atomic_snapshot_sources(
        &mut self,
    ) -> Result<
        Vec<(
            OperationId,
            crate::lifecycle::LifecycleAtomicSnapshotSourceRecoveryV1,
        )>,
        crate::lifecycle::LifecycleAtomicSnapshotSourceErrorV1,
    > {
        crate::lifecycle::LifecycleAtomicSnapshotSourceStoreV1::new(self.reconciler.journal_mut())
            .pending_reservations()
    }

    /// Lists completed Storage request IDs for authenticated archive cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error if protected source custody is unavailable or corrupt.
    pub fn completed_atomic_snapshot_source_request_ids(
        &mut self,
    ) -> Result<Vec<[u8; 16]>, crate::lifecycle::LifecycleAtomicSnapshotSourceErrorV1> {
        crate::lifecycle::LifecycleAtomicSnapshotSourceStoreV1::new(self.reconciler.journal_mut())
            .completed_request_ids()
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

    /// Inspects a provisioned genesis pair against its actual current writer.
    ///
    /// This read spends no epoch and creates no acceptance, Source append or
    /// Root proof. In particular, an absent actual authorization head remains
    /// unavailable rather than being synthesized from the delivered packets.
    ///
    /// # Errors
    ///
    /// Rejects changed delivery, fixed writer custody, missing current
    /// authorization or a pair that does not match actual protected heads.
    #[cfg(target_os = "linux")]
    pub fn inspect_provisioned_source_genesis_v1(
        &mut self,
        input: &crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
    ) -> Result<(), crate::hierarchy::controller_genesis_input::ControllerSourceGenesisInputErrorV1>
    {
        input.inspect_current(self.reconciler.journal_mut())
    }

    /// Reports only whether the exact provisioned attempt has retained records.
    ///
    /// This read-only startup selector permits historical recovery before an
    /// unrelated publisher bootstrap credential is reinstalled. It grants no
    /// admission, readiness, Root floor or read authority; the coordinator must
    /// still join the actual original Root peer and retained owner records.
    ///
    /// # Errors
    ///
    /// Rejects changed credentials, unsafe writer custody, malformed records
    /// or an original attempt different from the provisioned packet pair.
    #[cfg(target_os = "linux")]
    pub fn has_retained_provisioned_source_genesis_v1(
        &mut self,
        input: &crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
    ) -> Result<bool, crate::hierarchy::controller_genesis_input::ControllerSourceGenesisInputErrorV1>
    {
        input.has_retained_attempt(self.reconciler.journal_mut())
    }

    /// Borrows genuine provisioned genesis admission under the sole writer.
    ///
    /// Only an exact original-flight coordinator may use this trusted owner seam,
    /// after it can consume the original pair through the genuine Root flight.
    /// Startup deliberately does not call it: admission fences every unrelated
    /// mutation until Source ACK completion and cannot be accepted then dropped
    /// as an ordinary ready-controller bootstrap. No public API route is added.
    ///
    /// # Errors
    ///
    /// Rejects changed packet/pin delivery and the existing held producer's
    /// stale heads, epoch/input conflict, missing role or capacity conditions.
    #[cfg(target_os = "linux")]
    pub fn hold_provisioned_source_genesis_v1<'held>(
        &'held mut self,
        input: &'held crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
    ) -> Result<
        crate::hierarchy::controller_genesis::HeldControllerSourceGenesisV1<'held>,
        crate::hierarchy::controller_genesis_input::ControllerSourceGenesisInputErrorV1,
    > {
        input.hold(self.reconciler.journal_mut())
    }

    /// Completes a fixed provisioned genesis pair through the actual executor.
    ///
    /// The production owner joins its existing Source writer and protected
    /// signer to the independently selected Root profile. Completion includes
    /// Source ACK, Controller Complete and final Root Finish; a Root ACK alone
    /// cannot return success. This trusted startup path adds no public API and
    /// returns historical completion data, never read or ancestry authority.
    ///
    /// # Errors
    ///
    /// Rejects absent genuine owner support, changed protected inputs, stale
    /// current admission, conflicting original records or a lost/late phase.
    /// Durable partial progress remains fenced for exact restart recovery.
    #[cfg(target_os = "linux")]
    pub fn coordinate_provisioned_source_genesis_v1(
        &mut self,
        input: &crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<
        ObjectDigest,
        crate::hierarchy::controller_genesis_input::ControllerSourceGenesisInputErrorV1,
    > {
        self.reconciler
            .coordinate_provisioned_source_genesis_v1(input, profile)
    }

    /// Selects only the configured full-resource Global transport family.
    ///
    /// This original credential DATA check issues no current admission or payment.
    ///
    /// # Errors
    /// Rejects changed original credential custody, signatures or matched claims.
    #[cfg(target_os = "linux")]
    pub fn configured_resource_global_selection_v2(
        &self,
        input: &crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
    ) -> Result<bool, crate::hierarchy::controller_genesis_input::ControllerSourceGenesisInputErrorV1> {
        input.selects_resource_global_v2()
    }

    /// Prepares the once-only image-owned prefix before startup selectors.
    ///
    /// # Errors
    /// Rejects unavailable original executor custody or unsupported source
    /// shape; native and observation causes remain with the entered executor.
    #[cfg(target_os = "linux")]
    pub fn prepare_first_global_prefix_v1(
        &mut self,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1> {
        self.reconciler.prepare_first_global_prefix_v1(profile)
    }

    /// Completes resource-bearing Global genesis through the retained original owners.
    ///
    /// # Errors
    /// Returns the whole failed original loan for worker termination.
    #[cfg(target_os = "linux")]
    pub fn coordinate_configured_global_genesis_v2<'writers, 'profile>(
        &'writers mut self,
        input: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ObjectDigest, crate::policy_compiler::FailedConfiguredGlobalGenesisInvocationV2<'writers, 'profile>> {
        self.reconciler.coordinate_configured_global_genesis_v2(input, profile)
    }

    /// Completes approval-free configured initial B genesis through genuine owners.
    ///
    /// This internal selector produces no public Create/Delete admission.
    ///
    /// # Errors
    /// Returns the whole failed original loan, retained until worker termination.
    #[cfg(target_os = "linux")]
    pub fn coordinate_configured_project_genesis_v3<'writers, 'profile>(
        &'writers mut self,
        input: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ObjectDigest, crate::policy_compiler::FailedConfiguredProjectGenesisInvocationV3<'writers, 'profile>> {
        self.reconciler.coordinate_configured_project_genesis_v3(input, profile)
    }

    /// Compares the genuine configured pair with all retained issuance families.
    ///
    /// # Errors
    /// Rejects changed actual pair custody, malformed complete histories or an
    /// unjoined configured acceptance. This method admits no native mutation.
    #[cfg(target_os = "linux")]
    pub fn configured_project_startup_selection_v3(
        &mut self, input: &crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
    ) -> Result<ConfiguredProjectStartupSelectionV3, crate::hierarchy::controller_genesis_input::ControllerSourceGenesisInputErrorV1> {
        let journal = self.reconciler.journal_mut();
        input.recheck()?;
        let selected = crate::journal::controller_source_successor_issuance::retained_project_v3(journal, input.project())
            .map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from)?;
        let global = crate::journal::controller_source_successor_issuance::retained(journal)
            .map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from)?;
        let different_global = global.as_ref().map(|saved| saved.packet.intent())
            .transpose()?.is_some_and(|intent| intent.project() != input.project());
        if selected.is_some() || different_global {
            input.has_retained_attempt(journal)?;
            input.recheck()?;
            Ok(ConfiguredProjectStartupSelectionV3::MixedProject)
        } else {
            Ok(ConfiguredProjectStartupSelectionV3::Ordinary)
        }
    }

    /// Selects actual project history DATA after authentic configured-pair checks.
    ///
    /// # Errors
    /// Rejects changed pair custody, malformed whole histories or foreign rows.
    #[cfg(target_os = "linux")]
    pub fn retained_project_successor_selection_v3(
        &mut self, input: &crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
    ) -> Result<crate::policy_compiler::FirstSourceSuccessorSelectionV2, crate::hierarchy::controller_genesis_input::ControllerSourceGenesisInputErrorV1> {
        input.recheck()?;
        let journal = self.reconciler.journal_mut();
        input.has_retained_attempt(journal)?;
        let selected = crate::journal::controller_source_successor_issuance::retained_project_v3(journal, input.project())
            .map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from)?;
        input.recheck()?;
        Ok(if selected.is_some() {
            crate::policy_compiler::FirstSourceSuccessorSelectionV2::Selected
        } else {
            crate::policy_compiler::FirstSourceSuccessorSelectionV2::Absent
        })
    }

    /// Coordinates actual selected B history using independently held originals.
    ///
    /// # Errors
    /// Returns the whole failed original writer loan for deliberate termination.
    #[cfg(target_os = "linux")]
    pub fn coordinate_project_successor_v3<'writers, 'profile>(
        &'writers mut self, profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        project: aos_sandbox_core::ProjectId,
    ) -> Result<Option<ObjectDigest>, crate::policy_compiler::FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        self.reconciler.coordinate_project_successor_v3(profile, project)
    }

    /// Finishes global A with its exact keys before parking the configured B loan.
    ///
    /// # Errors
    /// Returns the resident failure; the genuine pair never substitutes A's floor.
    #[cfg(target_os = "linux")]
    pub fn coordinate_predecessor_successor_v3<'writers, 'profile>(
        &'writers mut self,
        input: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<ObjectDigest>, crate::policy_compiler::FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        self.reconciler.coordinate_predecessor_successor_v3(input, profile)
    }

    /// Selects only the project of the actual retained singleton obligation.
    ///
    /// This read-only projection supplies no currentness or mutation permit.
    ///
    /// # Errors
    /// Rejects unsafe Controller custody or malformed retained issuance state.
    #[cfg(target_os = "linux")]
    pub fn retained_first_source_successor_project_v2(&mut self) -> Result<Option<aos_sandbox_core::ProjectId>, crate::JournalError> {
        let journal = self.reconciler.journal_mut();
        let uid = journal.protected_owner_uid()?;
        crate::hierarchy::controller_genesis::require_controller(journal, uid)
            .map_err(|_| crate::JournalError::ProtectedBoundary)?;
        crate::journal::controller_source_successor_issuance::retained(journal)?
            .map(|saved| saved.packet.intent().map(|intent| intent.project()).map_err(|_| crate::JournalError::ProtectedBoundary))
            .transpose()
    }

    /// Coordinates the actual first successor under independently borrowed owners.
    ///
    /// # Errors
    /// Returns a must-use failed original owner, never an ordinary dropped error.
    #[cfg(target_os = "linux")]
    pub fn coordinate_retained_first_source_successor_v2<'writers, 'profile>(
        &'writers mut self, profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<ObjectDigest>, crate::policy_compiler::FailedOriginalFirstSourceSuccessorV2<'writers, 'profile>> {
        self.reconciler.coordinate_retained_first_source_successor_v2(profile)
    }

    /// Selects only the genuine original-gen1 Create policy-admission subgate.
    ///
    /// The installed selected caller retains this same Controller and its
    /// admitted profile before the first worker cycle. This neither opens the
    /// public Create gate nor completes its Applying Effect or backend method.
    ///
    /// # Errors
    /// Refuses unavailable original owner support or repeated/failed selection.
    #[cfg(target_os = "linux")]
    pub fn select_original_create_q04_policy_subgate_v1(
        &mut self,
        profile: std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
    ) -> Result<(), crate::reconciler::EffectFailure> {
        self.reconciler.select_original_create_q04_policy_subgate_v1(profile)
    }

    /// Issues fixed protected successor DATA through the SAME resident owners.
    ///
    /// This private administrative route opens no public mutation or readiness.
    /// Its packet requires a separate future current/funded Source consumer.
    ///
    /// # Errors
    /// Returns an original retaining failure; the installed caller must
    /// terminate while this Controller and credential owner remain resident.
    #[cfg(target_os = "linux")]
    pub fn issue_source_successor_v2<'writers, 'profile, 'credentials>(
        &'writers mut self,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut crate::normal_root::SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Result<
        crate::hierarchy::source_successor::SourceSuccessorApprovalDataV2,
        crate::policy_compiler::FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>,
    > {
        self.reconciler.issue_source_successor_v2(profile, credentials)
    }

    /// Issues a configured project's approval over fresh genuine originals.
    ///
    /// # Errors
    /// Retains an incomplete original issuer through deliberate termination.
    #[cfg(target_os = "linux")]
    pub fn issue_project_source_successor_v3<'writers, 'profile, 'credentials>(
        &'writers mut self, profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut crate::normal_root::SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Result<crate::hierarchy::source_successor::SourceSuccessorApprovalDataV2, crate::policy_compiler::FailedSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials>> {
        self.reconciler.issue_project_source_successor_v3(profile, credentials)
    }

    /// Borrows partition-local project Cache quantities from the actual executor.
    ///
    /// This fixed existing-owner hook creates no total project account, funding
    /// or public operation permission. It initializes before the selected
    /// worker's first cycle and refuses missing provisioning instead of repair.
    ///
    /// # Errors
    /// Returns unavailable on original custody, replay, currentness or a prior
    /// resident failure. The installed executor retains the actual typed cause.
    pub fn existing_cache_project_usage_v1(
        &mut self,
        project: aos_sandbox_core::ProjectId,
    ) -> Result<crate::cache_residency::CacheProjectUsageLoanV1<'_>, crate::cache_residency::CacheResidentUnavailableV1> {
        self.reconciler.existing_cache_project_usage_v1(project)
    }

    /// Inspects one genuinely received Gateway read scope without admitting Git.
    ///
    /// This uses the same exclusive Journal, holder-handle registry, evaluator
    /// and protected time-floor engine as public authorization. Actual crossing
    /// outcomes stay in the opaque request owner, including acknowledgement loss.
    /// No reservation, public effect permission or backend readiness follows.
    #[cfg(target_os = "linux")]
    pub fn inspect_original_gateway_git_read_v1(
        &mut self,
        original: &mut crate::git::delegated_read::GitReadRequestOwnerV1,
        acceptor: &crate::public_api_session::PublicApiSessionAcceptor,
    ) {
        public_api_authorization::inspect_original_gateway_git_read_v1(
            self.reconciler.journal_mut(), original, acceptor,
        );
    }

    /// Inspects the SAME original request under the enrolled same-writer cut.
    ///
    /// # Errors
    /// Refuses changed or incomplete resident owners; actual causes remain
    /// with the request, account attempt and installed Cache initialization.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn inspect_enrolled_gateway_git_read_v1(
        &mut self,
        original: &mut crate::git::delegated_read::GitReadRequestOwnerV1,
        acceptor: &crate::public_api_session::PublicApiSessionAcceptor,
        inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        account: &mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        let mut operation = crate::reconciler::GitCoverageReadMetadataOperationV1::inspect(
            original, acceptor, account,
        );
        self.reconciler.run_existing_git_coverage_read_metadata_v1(inputs, &mut operation)
    }

    /// Observes the actual stored enrollment nonce through the sole replay.
    ///
    /// This is correlation DATA only. Fresh Sessions, Root's original pair,
    /// current signed inputs and their independent bookends remain required.
    ///
    /// # Errors
    /// Retains the actual complete-prefix or final-name cause in the returned
    /// result; callers must park it before another fallible observation.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn existing_git_coverage_birth_nonce_v1(
        &mut self,
        catalog: &aos_sandbox_core::format::git_upload_enrollment::GitCoverageCatalogV1<'_>,
    ) -> Result<[u8; 16], crate::journal::GitCoverageNativeHistoryErrorV1> {
        self.reconciler.journal_mut().existing_controller_coverage_birth_nonce_v1(catalog)
    }

    /// Rechecks the same fixed initialization owners after a project usage loan.
    ///
    /// # Errors
    /// Returns unavailable for changed originals or a prior resident failure.
    /// This performs no reopen, mutation or operation admission.
    pub fn recheck_existing_cache_project_usage_v1(
        &mut self,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        self.reconciler.recheck_existing_cache_project_usage_v1()
    }

    /// Compares fixed exclusive-cohort Cache originals through the real executor.
    ///
    /// The actual fixed credential reservoir and resident owners remain with
    /// their installed callers. Returned native coordinates are DATA, not a
    /// currentness token, allocation permit, account or remote release proof.
    ///
    /// # Errors
    /// Retains original initialization, census, append or bookend failures in
    /// the concrete owner. The caller must park the whole Result and recheck
    /// its other original owners before using any returned coordinates.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn compare_existing_cache_git_coverage_v1(
        &mut self,
        original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        flight: aos_sandbox_core::format::git_upload_enrollment::GitCoverageFlightV1,
        original_nonce: [u8; 16],
        original_account: Option<&mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>>,
    ) -> Result<(
        aos_sandbox_core::format::git_upload_enrollment::GitCoverageBirthFieldsV1,
        aos_sandbox_core::format::git_upload_enrollment::GitCoverageFenceFieldsV1,
        [u8; 32],
        u64,
    ), crate::cache_residency::CacheResidentUnavailableV1> {
        self.reconciler.compare_existing_cache_git_coverage_v1(
            original_inputs, flight, original_nonce, original_account,
        )
    }

    /// Captures a fixed covered account cut through the original executor.
    ///
    /// Actual Source and Cache writers stay with the concrete executor; the
    /// external-profile attempt parks returned observations and typed causes.
    ///
    /// # Errors
    /// Refuses unavailable, changed or failed original owners. No account or
    /// effect permission is produced before the separate exact successor CAS.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn capture_existing_git_coverage_account_cut_v1(
        &mut self,
        original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &crate::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &crate::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        self.reconciler.capture_existing_git_coverage_account_cut_v1(
            original_inputs, original_bootstrap, original_source, original_capacity,
            original_bootstrap_credentials, attempt,
        )
    }

    /// Commits the exact original covered account through its same owners.
    ///
    /// # Errors
    /// Refuses changed predecessors, incomplete Root observations or failed
    /// original custody. Ambiguous native results stay resident in the attempt.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn commit_existing_git_coverage_account_v1(
        &mut self,
        original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &crate::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &crate::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        self.reconciler.commit_existing_git_coverage_account_v1(
            original_inputs, original_bootstrap, original_source, original_capacity,
            original_bootstrap_credentials, attempt,
        )
    }

    /// Issues or replays a first public capability from signed deployment entitlement.
    ///
    /// The request supplies only an idempotency key. Fixed protected credential
    /// custody supplies the signed principal-specific grants and verifier; the
    /// authenticated peer supplies holder and certificate-key custody.
    ///
    /// # Errors
    ///
    /// Rejects stale holder evidence, invalid approval, unavailable protected
    /// time or policy, or a failed durable capability commit.
    #[cfg(target_os = "linux")]
    pub fn bootstrap_initial_public_capability(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        idempotency_key: &[u8],
    ) -> Result<
        crate::public_capability_issuance::IssuedPublicCapabilityV1,
        crate::public_capability_issuance::InitialPublicCapabilityErrorV1,
    > {
        crate::public_capability_issuance::bootstrap(
            self.reconciler.journal_mut(),
            peer,
            idempotency_key,
        )
    }

    /// Runs selected first issuance through the same retained Cache/Controller cut.
    ///
    /// # Errors
    /// Refuses failed or changed original owners; all native results remain in
    /// the actual issuer capsule. This does not activate a Git backend.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn bootstrap_enrolled_git_public_capability_v1(
        &mut self,
        original: &mut crate::public_capability_issuance::RetainedGitInitialIssuanceV1,
        inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        account: &mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        let mut operation = crate::cli_model::authorization_adapter::GitCoverageReadMetadataOperationV1::bootstrap(
            original, account,
        );
        self.reconciler.run_existing_git_coverage_read_metadata_v1(inputs, &mut operation)
    }

    /// Resolves a protected public handle for the live authenticated TLS holder.
    ///
    /// This lookup does not authorize any operation. Callers must pass the
    /// returned UID through the ordinary current policy and grant checks.
    ///
    /// # Errors
    ///
    /// Rejects a stale peer, mismatched public UID, unknown or revoked handle,
    /// or unavailable protected authority.
    #[cfg(target_os = "linux")]
    pub fn resolve_public_capability_handle(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        claimed_uid: aos_sandbox_core::CapabilityId,
        handle: &[u8],
    ) -> Result<aos_sandbox_core::CapabilityId, ControllerServiceError> {
        let resolved = self.resolve_public_capability_target(peer, handle)?;
        if resolved != claimed_uid {
            return Err(OperationCompilationError::Rejected.into());
        }
        Ok(resolved)
    }

    /// Resolves a protected capability target handle for its authenticated TLS holder.
    ///
    /// This is only target identification. Callers must separately authorize the
    /// requested read or mutation using a current invoking capability.
    ///
    /// # Errors
    ///
    /// Rejects stale peer evidence, unknown or revoked handles, holder or
    /// project mismatch, and unavailable protected authority.
    #[cfg(target_os = "linux")]
    pub fn resolve_public_capability_target(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        handle: &[u8],
    ) -> Result<aos_sandbox_core::CapabilityId, ControllerServiceError> {
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        let registry = PublisherCapabilityRegistry::load(
            self.reconciler.journal_mut(),
            PublisherAuthorityLimits::default(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let resolved = registry
            .resolve_holder_handle(handle, peer.principal(), peer.key_binding())
            .map_err(|_| OperationCompilationError::Rejected)?;
        if peer.project()
            != registry
                .resolve_current(resolved)
                .map_err(|_| OperationCompilationError::Rejected)?
                .claims()
                .project
        {
            return Err(OperationCompilationError::Rejected.into());
        }
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        Ok(resolved)
    }

    /// Returns an issued handle only to its current authenticated TLS holder.
    ///
    /// # Errors
    ///
    /// Rejects stale peer evidence, a missing or revoked capability, or a
    /// holder/certificate binding mismatch.
    #[cfg(target_os = "linux")]
    pub fn public_holder_handle(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        id: aos_sandbox_core::CapabilityId,
    ) -> Result<[u8; 32], ControllerServiceError> {
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        let registry = PublisherCapabilityRegistry::load(
            self.reconciler.journal_mut(),
            PublisherAuthorityLimits::default(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        if registry
            .resolve_current(id)
            .map_err(|_| OperationCompilationError::Rejected)?
            .claims()
            .project
            != peer.project()
        {
            return Err(OperationCompilationError::Rejected.into());
        }
        let handle = registry
            .holder_handle(id, peer.principal(), peer.key_binding())
            .map_err(|_| OperationCompilationError::Rejected)?;
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        Ok(handle)
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
        signed_plan: aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan,
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

    /// Reserves one current workspace's separate guest-root publication.
    ///
    /// The operation is durable before method 31 can be sent. A repeated call
    /// reuses the exact prior operation, while already published roots require
    /// a matching physical proof in fresh authenticated Storage inventory.
    ///
    /// # Errors
    ///
    /// Rejects stale inventory, changed assignment, foreign proof, malformed
    /// prior reservation, or protected journal failure.
    #[cfg(target_os = "linux")]
    pub fn reserve_guest_root_publication(
        &mut self,
        snapshot: &crate::DurableStorageResourceInventorySnapshotV1,
        node: aos_sandbox_core::NodeId,
        pins: crate::guest_root_publication::GuestRootTemplatePinsV1,
    ) -> Result<
        Option<crate::guest_root_publication::GuestRootPublicationReservationV1>,
        crate::guest_root_publication::GuestRootPublicationErrorV1,
    > {
        crate::guest_root_publication::reserve_first_guest_root_v1(
            self.reconciler.journal_mut(),
            snapshot,
            node,
            pins,
        )
    }

    /// Builds a new method-31 plan from the current assignment and lease.
    ///
    /// # Errors
    ///
    /// Rejects a changed reservation, stale lease, or missing Storage template.
    #[cfg(target_os = "linux")]
    pub fn prepare_guest_root_publication_plan(
        &mut self,
        reservation: &crate::guest_root_publication::GuestRootPublicationReservationV1,
        node: aos_sandbox_core::NodeId,
        now_seconds: i64,
    ) -> Result<
        crate::guest_root_publication::GuestRootPublicationPlanDraftV1,
        crate::guest_root_publication::GuestRootPublicationErrorV1,
    > {
        crate::guest_root_publication::prepare_guest_root_plan_v1(
            self.reconciler.journal_mut(),
            reservation,
            node,
            now_seconds,
        )
    }

    /// Verifies a reserved root against a new authenticated Storage readback.
    ///
    /// # Errors
    ///
    /// Rejects a stale snapshot, changed workspace, or foreign proof.
    #[cfg(target_os = "linux")]
    pub fn verify_guest_root_publication_readback(
        &mut self,
        snapshot: &crate::DurableStorageResourceInventorySnapshotV1,
        reservation: &crate::guest_root_publication::GuestRootPublicationReservationV1,
    ) -> Result<bool, crate::guest_root_publication::GuestRootPublicationErrorV1> {
        crate::guest_root_publication::verify_guest_root_readback_v1(
            self.reconciler.journal_mut(),
            snapshot,
            reservation,
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
        signed_plan: aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan,
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
        signed_plan: aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan,
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
            Some(&service.expected_process),
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

    // Public entry points bind the same canonical request to the live peer.
    #[cfg(target_os = "linux")]
    fn checked_public_request_digest(
        &self,
        peer: &crate::public_api_session::PublicApiPeer,
        canonical_request: &[u8],
    ) -> Result<[u8; 32], ControllerServiceError> {
        if canonical_request.is_empty() {
            return Err(ControllerServiceError::EmptyRequest);
        }
        if canonical_request.len() > self.limits.maximum_request_bytes {
            return Err(ControllerServiceError::RequestTooLarge);
        }
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;

        Ok(public_controller_request_digest(
            self.scope,
            peer.principal(),
            peer.project(),
            canonical_request,
        ))
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
        let request_digest = self.checked_public_request_digest(peer, canonical_request)?;
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

    /// Replays a committed renewal after its invoking handle was retired.
    ///
    /// The request must identify the same retired handle and the protected
    /// idempotency entry must contain its exact caller-bound digest. This path
    /// cannot compile fresh authority or authorize another public method.
    ///
    /// # Errors
    ///
    /// Rejects stale TLS evidence, a mismatched holder, certificate, project,
    /// capability UID, handle, request, or committed operation record.
    #[cfg(target_os = "linux")]
    pub fn replay_committed_public_capability_renewal(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        capability_handle: &[u8; 32],
        canonical_request: &[u8],
    ) -> Result<AcceptOutcome, ControllerServiceError> {
        let request_digest = self.checked_public_request_digest(peer, canonical_request)?;
        let plan = crate::production_operation_compiler::replay_committed_capability_renewal_v1(
            self.reconciler.journal_mut(),
            peer.principal(),
            peer.project(),
            peer.key_binding(),
            capability_id,
            capability_handle,
            canonical_request,
            request_digest,
        )?;

        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        self.accept_compiled_plan(plan, request_digest)
    }

    /// Reserves an authorized public attach operation before Host gate readback.
    ///
    /// This durable record has no ordinary operation effect. Its identity must
    /// be installed and read back by the authenticated Host gate before final
    /// admission may publish an OpenSSH endpoint.
    ///
    /// # Errors
    ///
    /// Rejects stale peer evidence, invalid authorization or holder proof,
    /// stale execution state, conflicting identity, or journal failure.
    #[cfg(target_os = "linux")]
    pub fn reserve_public_attach(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        canonical_request: &[u8],
    ) -> Result<crate::public_attach_pending::PublicAttachPendingV1, ControllerServiceError> {
        let request_digest = self.checked_public_request_digest(peer, canonical_request)?;
        let pending = crate::production_operation_compiler::reserve_public_attach_v1(
            self.reconciler.journal_mut(),
            peer,
            capability_id,
            canonical_request,
            request_digest,
        )?;
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        Ok(pending)
    }

    /// Prepares a read-only authenticated Host readiness query before ATTACH CAS.
    ///
    /// # Errors
    ///
    /// Rejects stale peer authorization, holder proof, execution, or protected
    /// assignment state without reserving an attach operation.
    #[cfg(target_os = "linux")]
    pub fn prepare_public_attach_readiness(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        canonical_request: &[u8],
        node: aos_sandbox_core::NodeId,
        now_seconds: i64,
    ) -> Result<crate::public_attach_pending::PublicAttachHostQueryDraftV1, ControllerServiceError>
    {
        self.checked_public_request_digest(peer, canonical_request)?;
        let draft = crate::production_operation_compiler::prepare_public_attach_readiness_v1(
            self.reconciler.journal_mut(),
            peer,
            capability_id,
            canonical_request,
            node,
            now_seconds,
        )?;
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        Ok(draft)
    }

    /// Looks up an existing ATTACH and whether it was durably accepted.
    ///
    /// # Errors
    ///
    /// Rejects stale peer authorization or a conflicting protected request.
    #[cfg(target_os = "linux")]
    pub fn lookup_public_attach_existing(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        canonical_request: &[u8],
    ) -> Result<
        Option<(crate::public_attach_pending::PublicAttachPendingV1, bool)>,
        ControllerServiceError,
    > {
        let request_digest = self.checked_public_request_digest(peer, canonical_request)?;
        let pending = crate::production_operation_compiler::lookup_public_attach_existing_v1(
            self.reconciler.journal_mut(),
            peer,
            capability_id,
            canonical_request,
            request_digest,
        )?;
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        Ok(pending)
    }

    /// Prepares a fresh read-only Host query for an accepted ATTACH replay.
    ///
    /// # Errors
    ///
    /// Rejects mismatched public authorization, pending identity, durable
    /// admission, current execution, or Host assignment authority.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_public_attach_route_query(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        canonical_request: &[u8],
        pending: &crate::public_attach_pending::PublicAttachPendingV1,
        node: aos_sandbox_core::NodeId,
        now_seconds: i64,
    ) -> Result<crate::public_attach_pending::PublicAttachHostQueryDraftV1, ControllerServiceError>
    {
        let request_digest = self.checked_public_request_digest(peer, canonical_request)?;
        let rechecked = crate::production_operation_compiler::reserve_public_attach_v1(
            self.reconciler.journal_mut(),
            peer,
            capability_id,
            canonical_request,
            request_digest,
        )?;
        if rechecked != *pending {
            return Err(OperationCompilationError::Rejected.into());
        }
        let draft = crate::public_attach_pending::prepare_public_attach_host_query_v1(
            self.reconciler.journal_mut(),
            peer.project(),
            node,
            pending.execution_id(),
            Some(pending),
            now_seconds,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        Ok(draft)
    }

    /// Signs a protected pending attach for the separately authenticated Host.
    ///
    /// The signing key must be the externally provisioned attach-grant key;
    /// the Host pins its distinct public half. Trust and gate configuration
    /// digests must come from the Host's provisioned inputs. This step is not
    /// public operation admission or proof of an installed gate.
    ///
    /// # Errors
    ///
    /// Rejects stale authorization, a changed reservation or runtime binding,
    /// an expired reservation, or invalid grant inputs.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_public_attach_pending_grant(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        canonical_request: &[u8],
        pending: &crate::public_attach_pending::PublicAttachPendingV1,
        signing_key: &ed25519_dalek::SigningKey,
        trust_digest: [u8; 32],
        gate_config_digest: [u8; 32],
        now_seconds: i64,
    ) -> Result<
        [u8; aos_sandbox_core::public_attach_grant::PUBLIC_ATTACH_GRANT_BYTES],
        ControllerServiceError,
    > {
        let request_digest = self.checked_public_request_digest(peer, canonical_request)?;
        let rechecked = crate::production_operation_compiler::reserve_public_attach_v1(
            self.reconciler.journal_mut(),
            peer,
            capability_id,
            canonical_request,
            request_digest,
        )?;
        if rechecked != *pending {
            return Err(OperationCompilationError::Rejected.into());
        }
        let grant = crate::public_attach_pending::sign_reserved_public_attach_grant_v1(
            self.reconciler.journal_mut(),
            pending,
            signing_key,
            trust_digest,
            gate_config_digest,
            now_seconds,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        Ok(grant)
    }

    /// Prepares the exact signed Host-install plan for a protected ATTACH.
    ///
    /// This rechecks public authorization, pending custody, and current
    /// assignment before returning either signed-grant or broker-plan inputs.
    /// The caller must sign the plan under the separate broker-plan authority.
    ///
    /// # Errors
    ///
    /// Rejects a changed public request, expired pending identity, stale
    /// execution or lease, or missing current Host authority template.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_public_attach_host_install(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        canonical_request: &[u8],
        pending: &crate::public_attach_pending::PublicAttachPendingV1,
        node: aos_sandbox_core::NodeId,
        signing_key: &ed25519_dalek::SigningKey,
        trust_digest: [u8; 32],
        gate_config_digest: [u8; 32],
        now_seconds: i64,
    ) -> Result<crate::public_attach_pending::PublicAttachHostInstallDraftV1, ControllerServiceError>
    {
        let grant = self.sign_public_attach_pending_grant(
            peer,
            capability_id,
            canonical_request,
            pending,
            signing_key,
            trust_digest,
            gate_config_digest,
            now_seconds,
        )?;
        let grant_fields =
            aos_sandbox_core::public_attach_grant::verify_public_attach_pending_grant_v1(
                &grant,
                &signing_key.verifying_key(),
            )
            .map_err(|_| OperationCompilationError::Rejected)?;
        crate::public_attach_pending::prepare_public_attach_host_install_v1(
            self.reconciler.journal_mut(),
            pending,
            peer.project(),
            node,
            grant,
            grant_fields,
            now_seconds,
        )
        .map_err(|_| OperationCompilationError::Rejected.into())
    }

    /// Prepares immutable original ticket binding after durable issuance.
    ///
    /// # Errors
    /// Rejects changed original policy/revocation/TLS coordinates, missing
    /// retained receipt/decision/certificate, stale assignment, or substitution.
    /// This only installs custody data; trusted SSH monitor and held consume
    /// remain mandatory before public readiness or I/O can be enabled.
    #[cfg(target_os = "linux")]
    pub fn prepare_public_attach_ticket_binding_v2(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        canonical_request: &[u8],
        pending: &crate::public_attach_pending::PublicAttachPendingV1,
        route: &crate::attach_route_issuer::AuthenticatedOpenSshRouteV1,
        node: aos_sandbox_core::NodeId,
        now_seconds: i64,
    ) -> Result<
        (
            Vec<u8>,
            crate::public_attach_pending::PublicAttachHostInstallDraftV1,
        ),
        ControllerServiceError,
    > {
        let request_digest = self.checked_public_request_digest(peer, canonical_request)?;
        let authorized =
            crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1::authorize(
                self.reconciler.journal_mut(),
                peer,
                capability_id,
                canonical_request,
            )
            .map_err(|_| OperationCompilationError::Rejected)?;
        let journal = self.reconciler.journal_mut();
        crate::attach_decision::retained_decision_record(
            journal,
            pending.operation_id(),
            &authorized
                .original_attach_decision()
                .map_err(|_| OperationCompilationError::Rejected)?,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let access = crate::attach_route_issuer::load_public_attach_route_v1(
            journal,
            pending.operation_id(),
            request_digest,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        let line = std::str::from_utf8(&access.client_certificate)
            .map_err(|_| OperationCompilationError::Rejected)?;
        let certificate = ssh_key::Certificate::from_openssh(line)
            .map_err(|_| OperationCompilationError::Rejected)?;
        let holder = certificate
            .public_key()
            .ed25519()
            .ok_or(OperationCompilationError::Rejected)?
            .0;
        let original =
            crate::attach_decision::original_ticket_coordinates(journal, pending.operation_id())
                .map_err(|_| OperationCompilationError::Rejected)?;
        let original_grant =
            crate::attach_decision::original_grant(journal, pending.record_digest())
                .map_err(|_| OperationCompilationError::Rejected)?;
        if original.certificate_digest
            != <[u8; 32]>::from(sha2::Sha256::digest(&access.client_certificate))
            || original.holder_public_key != holder
            || original.valid_after != certificate.valid_after()
            || original.expires_at != certificate.valid_before()
            || original.base_route_digest != route.route_digest
            || original.pending_grant_digest
                != <[u8; 32]>::from(sha2::Sha256::digest(original_grant))
        {
            return Err(OperationCompilationError::Rejected.into());
        }
        let ticket = aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2 {
            operation_id: *pending.operation_id().as_bytes(),
            execution_id: pending.execution_id(),
            incarnation_id: pending.sandbox_incarnation_id(),
            principal_id: pending.principal_id(),
            audit_id: pending.audit_id(),
            assignment_epoch: pending.assignment_epoch(),
            valid_after: certificate.valid_after(),
            expires_at: certificate.valid_before(),
            holder_public_key: holder,
            request_digest,
            decision_digest: crate::attach_decision::decision_digest(
                journal,
                pending.operation_id(),
            )
            .map_err(|_| OperationCompilationError::Rejected)?,
            pending_grant: original_grant,
            base_route_digest: original.base_route_digest,
            certificate: access.client_certificate,
        }
        .encode()
        .map_err(|_| OperationCompilationError::Rejected)?;
        let draft = crate::public_attach_pending::prepare_original_ticket_binding_v2(
            journal,
            pending,
            authorized.project(),
            node,
            &ticket,
            now_seconds,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        Ok((ticket, draft))
    }

    /// Admits a public attach using current authenticated Host OpenSSH evidence.
    ///
    /// The protected issuer and route evidence must come from the controller's
    /// separate Host route readback. This path signs and retains the endpoint
    /// in the same journal transaction as the public operation. The caller
    /// must provide the exact earlier durable reservation used by the Host gate.
    ///
    /// # Errors
    ///
    /// Rejects stale peer evidence, invalid public authorization or holder
    /// proof, stale Host route evidence, issuance failure, or durable admission
    /// failure.
    #[cfg(target_os = "linux")]
    pub fn admit_public_attach_route(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        canonical_request: &[u8],
        pending: &crate::public_attach_pending::PublicAttachPendingV1,
        route: &crate::attach_route_issuer::AuthenticatedOpenSshRouteV1,
        issuer: &crate::attach_route_issuer::OpenSshAttachRouteIssuerV1,
    ) -> Result<
        (
            AcceptOutcome,
            aos_proto::aos::sandbox::v1::OpenSshAccessEndpoint,
        ),
        ControllerServiceError,
    > {
        let request_digest = self.checked_public_request_digest(peer, canonical_request)?;
        let plan = crate::production_operation_compiler::compile_public_attach_route_v1(
            self.reconciler.journal_mut(),
            peer,
            capability_id,
            canonical_request,
            request_digest,
            pending,
            route,
            issuer,
        )?;

        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        let outcome = self.accept_compiled_plan(plan, request_digest)?;
        let operation = match outcome {
            AcceptOutcome::Accepted(operation) | AcceptOutcome::Replay(operation) => operation,
        };
        let access = crate::attach_route_issuer::load_public_attach_route_v1(
            self.reconciler.journal_mut(),
            operation,
            request_digest,
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
        peer.recheck()
            .map_err(|_| OperationCompilationError::Rejected)?;
        Ok((outcome, access))
    }

    /// Admits one public operator-recovery request with live transport evidence.
    ///
    /// The specialized compiler hook must derive whether the target is a
    /// sandbox or operation from protected current state. This prevents an
    /// untrusted request from selecting the capability resource kind used for
    /// authorization. No ordinary public compiler fallback is permitted.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized input, stale peer evidence, unsupported
    /// recovery, authorization or fence failure, digest mismatch, and durable
    /// admission failure.
    #[cfg(target_os = "linux")]
    pub fn admit_public_operator_recovery(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        canonical_request: &[u8],
    ) -> Result<AcceptOutcome, ControllerServiceError> {
        let request_digest = self.checked_public_request_digest(peer, canonical_request)?;
        let plan = self.compiler.compile_public_operator_recovery(
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

    /// Computes one pure public policy plan under current protected authority.
    ///
    /// The exact registered method selects the protobuf type and closed
    /// capability semantics. The request is validated and authorized before the
    /// injected compiler receives it, and the returned public plan is validated
    /// before it crosses the controller boundary. No desired state, operation,
    /// idempotency record, or effect is admitted by this path.
    ///
    /// # Errors
    ///
    /// Returns [`PublicPolicyPlanningErrorV1`] for malformed input, stale peer
    /// evidence, rejected current authorization, an unavailable planner, or an
    /// invalid plan returned by the injected implementation.
    #[cfg(target_os = "linux")]
    pub fn plan_public_policy(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        method: PublicApiAuditMethodV1,
        protobuf_body: &[u8],
    ) -> Result<aos_proto::aos::sandbox::v1::PolicyPlan, PublicPolicyPlanningErrorV1> {
        if protobuf_body.is_empty() || protobuf_body.len() > self.limits.maximum_request_bytes {
            return Err(PublicPolicyPlanningErrorV1::Malformed);
        }
        peer.recheck()
            .map_err(|_| PublicPolicyPlanningErrorV1::Rejected)?;

        let request = ResolvedPublicPolicyPlanRequestV1::decode(method, protobuf_body)
            .map_err(|_| PublicPolicyPlanningErrorV1::Malformed)?;
        if request
            .target_project()
            .is_some_and(|project| project != peer.project())
        {
            return Err(PublicPolicyPlanningErrorV1::Rejected);
        }
        let authorization = self
            .authorize_public_read(
                peer,
                capability_id,
                request.method(),
                request.resource_kind(),
                request.operation(),
                request.selector().clone(),
                request.protobuf_body(),
            )
            .map_err(|_| PublicPolicyPlanningErrorV1::Unavailable)?
            .ok_or(PublicPolicyPlanningErrorV1::Rejected)?;
        let request = AuthorizedPublicPolicyPlanRequestV1::new(request, authorization);
        let plan = self
            .compiler
            .plan_public_policy(self.reconciler.journal_mut(), request)?;

        peer.recheck()
            .map_err(|_| PublicPolicyPlanningErrorV1::Rejected)?;
        CheckedPolicyPlanV1::try_from(plan.clone())
            .map_err(|_| PublicPolicyPlanningErrorV1::InvalidPlan)?;

        Ok(plan)
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

    /// Advances one selected operation before general fair reconciliation.
    ///
    /// The production controller uses this only for a protected pending
    /// Storage snapshot source. Its original group must reach terminal source
    /// custody before unrelated Storage mutations can change the post-head.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected operation or its durable ledger cannot
    /// be reconciled.
    pub fn reconcile_operation_once(
        &mut self,
        operation_id: OperationId,
    ) -> Result<ReconcileOutcome, ControllerServiceError> {
        self.reconciler
            .reconcile_once(operation_id)
            .map_err(ControllerServiceError::Reconciler)
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

    /// Loads every checked public projection linked to one operation.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerServiceError`] for corrupt projection or operation
    /// state, including any project mismatch.
    pub fn public_operation_projections(
        &mut self,
        operation: OperationId,
    ) -> Result<
        Vec<crate::controller_service::public_projection::PublicProjectionRecordV1>,
        ControllerServiceError,
    > {
        let projections =
            crate::controller_service::public_projection::PublicProjectionStoreV1::new(
                self.reconciler.journal_mut(),
            )
            .list_operation(operation)?;
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

    /// Returns one operation's validated durable ownership gate, when present.
    ///
    /// This query performs no authority I/O. A caller can use it to avoid
    /// connecting to the authority for an ungated or already activated
    /// operation.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] for an absent operation or corrupt ledger.
    pub fn ownership_gate(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
        self.reconciler.ownership_gate(operation_id)
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
    fn selected_operation_advances_before_fair_quantum() {
        let directory = TestDirectory::new();
        let limits = NodeControllerLimits::new(8, 4, 2).unwrap();
        let mut controller = controller(&directory.journal(), Executor::default(), limits);
        controller.admit(&[1]).unwrap();
        controller.admit(&[2]).unwrap();

        assert_eq!(
            controller
                .reconcile_operation_once(OperationId::from_bytes([2; 16]))
                .unwrap(),
            ReconcileOutcome::Progressed
        );
        let report = controller.reconcile_quantum().unwrap();
        assert_eq!(
            report.steps()[0].operation_id(),
            OperationId::from_bytes([1; 16])
        );
        assert_eq!(
            report.steps()[1].operation_id(),
            OperationId::from_bytes([2; 16])
        );
        assert_eq!(report.steps()[1].outcome(), ReconcileOutcome::EffectApplied);
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
