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

    /// Observes the protected current runtime of an authenticated holder.
    ///
    /// Trusted deployment supplies the Host connection, trust anchors, and
    /// protected paired-clock adapter. The selector supplies no assignment,
    /// lease, plan, or cgroup facts; these derive from current protected state
    /// and an authenticated Host exchange under one exclusive journal borrow.
    /// Success does not issue a channel or authorize publication.
    ///
    /// # Errors
    ///
    /// Rejects absent/revoked/substituted holders, corrupt current state,
    /// invalid signatures or clocks, missing Host grants, broker denial, and
    /// stale or substituted kernel execution observations.
    #[cfg(target_os = "linux")]
    pub fn observe_current_runtime<T>(
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
    pub fn recheck_current_runtime<T>(
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

    /// Tracks a freshly observed runtime in the protected generation ledger.
    ///
    /// Consumes the real Host proof. A new execution advances the incarnation's
    /// generation atomically; another observation of the same execution keeps
    /// its number. Neither case proves attachment replay or grants readiness.
    /// The clock must be the protected adapter used for scope acquisition.
    ///
    /// # Errors
    ///
    /// Rejects corrupt or exhausted history, reused scope handles, stale live
    /// authority, and failed protected commits. A post-commit failure can leave
    /// an inert generation record without returning any live proof.
    #[cfg(target_os = "linux")]
    pub fn track_current_runtime_generation<T>(
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
    pub fn recheck_current_runtime_generation<T>(
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
    pub fn bind_current_namespace_target<T>(
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
    pub fn recheck_current_namespace_target<T>(
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
    pub fn commit_current_attachment_desired_state<T>(
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
    pub fn prepare_current_mount_catalog<T>(
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
    pub fn recheck_current_mount_catalog<T>(
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
    /// and ownership authority, Mount audience, authority protocol 1.1, and the
    /// exact catalog-dependent semantics returned by preparation. Success still
    /// performs no broker effect and writes no durable operation.
    ///
    /// # Errors
    ///
    /// Rejects stale live authority, signature or assignment substitution,
    /// wrong audience/protocol/ownership authority, an absent exact grant, and
    /// an expired preparation.
    #[cfg(target_os = "linux")]
    pub fn bind_current_mount_plan<T>(
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
    pub fn recheck_current_mount_dispatch<T>(
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
    /// authenticate broker inventory and repeat preparation before another
    /// effect attempt.
    ///
    /// # Errors
    ///
    /// Rejects stale live authority, expired or mismatched plan/lease bounds,
    /// a deadline beyond the catalog lifetime, conflicting request replay,
    /// corrupt cross-referenced history, capacity, and failed durable commits.
    #[cfg(target_os = "linux")]
    pub fn admit_current_mount_attempt<T>(
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
    pub fn recheck_current_mount_attempt<T>(
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

    /// Dispatches one already durable current Mount attempt and records success.
    ///
    /// The connected client authenticates the actual Mount hello and response
    /// writers, sends the exact admitted packet, and validates the result
    /// against its byte-exact Apply body. A successful receipt is committed
    /// before this method returns it. Broker rejection or transport loss is not
    /// treated as proof that no resource exists; recovery requires authoritative
    /// Mount inventory.
    ///
    /// # Errors
    ///
    /// Rejects stale live authority, substituted durable state, service
    /// identity or negotiation failure, malformed or mismatched results,
    /// conflicting completion replay, capacity, and failed durable commits.
    #[cfg(target_os = "linux")]
    pub fn dispatch_current_mount_attempt<T>(
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

    /// Queries and durably records one authenticated complete Mount inventory.
    ///
    /// The one-shot client authenticates the actual hello and response writers,
    /// validates the closed resource-table response, and commits the exact
    /// request and response before returning the snapshot. The snapshot is
    /// observation evidence, not descriptor authority or attachment readiness.
    ///
    /// # Errors
    ///
    /// Rejects service identity or negotiation failure, malformed or
    /// non-monotonic broker inventory, capacity, and failed durable commits.
    #[cfg(target_os = "linux")]
    pub fn record_mount_inventory(
        &mut self,
        client: crate::mount_attempt::MountInventoryClient,
    ) -> Result<crate::mount_attempt::DurableMountInventorySnapshotV1, crate::MountAttemptError>
    {
        crate::mount_attempt::record_snapshot(self.reconciler.journal_mut(), client)
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
    pub fn reconcile_current_mount_inventory<T>(
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

    /// Plans one attachment's next step from current intent and Mount inventory.
    ///
    /// The desired generation, complete authenticated inventory, exact durable
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
    pub fn reconcile_current_attachment<T>(
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

    /// Durably records exact post-attach kernel evidence for one generation.
    ///
    /// The input must be a current reconciliation whose closed action is
    /// `Verify`. The controller binds the desired record, current namespace
    /// allocation and assignment, complete installed Mount resource, and
    /// authenticated inventory snapshot in one immutable record. This commit
    /// makes that snapshot stale; a subsequent fresh inventory must reproduce
    /// the verified resource before reconciliation reports `Ready`.
    ///
    /// # Errors
    ///
    /// Rejects any non-verification action, stale desired, inventory, or live
    /// namespace evidence, a changed installed resource, conflicting durable
    /// verification, capacity exhaustion, and failed protected commits.
    #[cfg(target_os = "linux")]
    pub fn record_current_attachment_verification<T>(
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
    pub fn prepare_current_attachment_mount<T>(
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
    pub fn recheck_current_attachment_mount<T>(
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
    pub fn bind_current_attachment_mount_plan<T>(
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
    pub fn admit_current_attachment_mount_attempt<T>(
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

    /// Rechecks an admitted attachment Mount attempt without dispatching it.
    ///
    /// # Errors
    ///
    /// Rejects changed desired state or lease status, stale live authority,
    /// substituted durable bytes, and expired deadlines.
    #[cfg(target_os = "linux")]
    pub fn recheck_current_attachment_mount_attempt<T>(
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
    /// authenticated Mount exchange. A successful effect is recorded before a
    /// concurrent stale guard can withhold the live completion token.
    ///
    /// # Errors
    ///
    /// Rejects stale desired or live authority, service identity and protocol
    /// failures, substituted results, conflicting completion, and journal errors.
    #[cfg(target_os = "linux")]
    pub fn dispatch_current_attachment_mount_attempt<T>(
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
    /// publication policy determines the cache grant. Version-three issuance
    /// evidence commits before the endpoint escapes. Current authority and the
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
    pub fn provision_current_runtime_ingress<T>(
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
    pub fn join_publisher_request<'a, T>(
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
