//! Typed trusted-adapter and resource-catalog boundaries.
//!
//! Plans describe logical resources and typed values. They never carry native
//! file descriptors, manager proxies, credential objects, or other privileged
//! handles. Fresh admission resolves each declared [`ResourceAccess`] through
//! a trusted catalog and passes only the resulting [`ResourceHandle`] values to
//! a compiled adapter.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use std::num::NonZeroU32;

use aos_ability_model::{
    AbilityValue, ArtifactReference, IncarnationId, LocalKey, Operation, OperationId,
    ProviderAssignment, ResourceAccess, ResourceId, RevisionId, TransactionId,
};
use aos_ability_model::{MethodReference, ProviderImplementationReference};
use aos_ability_validate::CheckedEffectPlan;
use aos_contract::Sha256Digest;

/// A cancellation signal shared with an in-flight trusted adapter.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Requests bounded cancellation of the current execution.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Reports whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Supplies monotonic elapsed time without coupling the executor to a platform clock.
pub trait MonotonicClock {
    /// Returns milliseconds since this clock's stable local origin.
    fn now_millis(&self) -> u64;
}

/// Measures live attempt time using [`Instant`].
#[derive(Clone, Debug)]
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl SystemMonotonicClock {
    /// Starts a monotonic clock at the current instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now_millis(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Exposes the bounded attempt controls available to a trusted adapter.
pub trait RuntimeControl {
    /// Reports whether the controller has requested cancellation.
    fn is_cancelled(&self) -> bool;

    /// Returns the elapsed transaction budget in milliseconds.
    fn elapsed_millis(&self) -> u64;

    /// Returns the remaining time in this attempt.
    fn attempt_remaining_millis(&self) -> u64;

    /// Returns the remaining total recovery budget.
    fn recovery_remaining_millis(&self) -> u64;
}

/// Proves that a trusted catalog resolved one declared logical resource.
///
/// Construction is restricted to this crate. A plan parameter containing the
/// same name or path cannot manufacture a handle or select a different native
/// resource.
#[derive(Debug)]
pub struct ResourceHandle<H> {
    resource: ResourceId,
    access: ResourceAccess,
    handle: H,
    evidence: ResourceAdmissionEvidence,
}

/// Records current assignment and state observed with a native reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceAdmissionEvidence {
    resource: ResourceId,
    provider_incarnation: Option<IncarnationId>,
    revision: Option<RevisionId>,
    observation: AbilityValue,
}

impl ResourceAdmissionEvidence {
    /// Constructs evidence returned by a trusted resource catalog.
    #[must_use]
    pub fn new(
        resource: ResourceId,
        provider_incarnation: Option<IncarnationId>,
        revision: Option<RevisionId>,
        observation: AbilityValue,
    ) -> Self {
        Self {
            resource,
            provider_incarnation,
            revision,
            observation,
        }
    }

    /// Returns the exact logical resource observed under reservation.
    #[must_use]
    pub const fn resource(&self) -> &ResourceId {
        &self.resource
    }

    /// Returns the current provider assignment incarnation, when established.
    #[must_use]
    pub const fn provider_incarnation(&self) -> Option<&IncarnationId> {
        self.provider_incarnation.as_ref()
    }

    /// Returns the current resource revision, when established.
    #[must_use]
    pub const fn revision(&self) -> Option<RevisionId> {
        self.revision
    }

    /// Returns bounded trusted evidence for the fresh observation.
    #[must_use]
    pub const fn observation(&self) -> &AbilityValue {
        &self.observation
    }
}

/// Couples a process-scoped native reservation with fresh trusted evidence.
#[derive(Debug)]
pub struct CatalogReservation<H> {
    handle: H,
    evidence: ResourceAdmissionEvidence,
}

impl<H> CatalogReservation<H> {
    /// Constructs a reservation returned by a trusted resource catalog.
    #[must_use]
    pub fn new(handle: H, evidence: ResourceAdmissionEvidence) -> Self {
        Self { handle, evidence }
    }
}

/// Couples an adapter-native request with its exact durable representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRequest<Request> {
    request: Request,
    durable: AbilityValue,
}

impl<Request> PreparedRequest<Request> {
    pub(crate) const fn new(request: Request, durable: AbilityValue) -> Self {
        Self { request, durable }
    }

    /// Returns the adapter-native request.
    #[must_use]
    pub const fn request(&self) -> &Request {
        &self.request
    }

    /// Returns the exact bounded value persisted before the effect.
    #[must_use]
    pub const fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

/// Exposes the exact bounded value retained as adapter evidence.
pub trait AdapterRecord {
    /// Returns the exact value stored in the protected execution journal.
    fn durable(&self) -> &AbilityValue;
}

/// Exposes independently typed outputs from a successful adapter call.
///
/// Completion evidence proves the external postcondition. Outputs are the
/// caller-visible values named by the checked method descriptor; the runtime
/// validates them separately before they can satisfy graph dependencies.
pub trait AdapterCompletion: AdapterRecord {
    /// Returns successful method outputs in exact port-name order.
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue>;
}

impl<H> ResourceHandle<H> {
    pub(crate) fn new(
        resource: ResourceId,
        access: ResourceAccess,
        reservation: CatalogReservation<H>,
    ) -> Self {
        Self {
            resource,
            access,
            handle: reservation.handle,
            evidence: reservation.evidence,
        }
    }

    /// Returns the logical resource authenticated by the catalog.
    #[must_use]
    pub const fn resource(&self) -> &ResourceId {
        &self.resource
    }

    /// Returns the exact access declaration used to acquire the handle.
    #[must_use]
    pub const fn access(&self) -> &ResourceAccess {
        &self.access
    }

    /// Returns the catalog-owned native handle.
    #[must_use]
    pub const fn native(&self) -> &H {
        &self.handle
    }

    /// Returns fresh assignment and precondition evidence for this reservation.
    #[must_use]
    pub const fn evidence(&self) -> &ResourceAdmissionEvidence {
        &self.evidence
    }

    pub(crate) fn native_mut(&mut self) -> &mut H {
        &mut self.handle
    }
}

/// Acquires fresh process-scoped handles independently from plan parameters.
///
/// Catalog reservations must disappear automatically when this executor
/// process exits. A lease, provider object, or other acquisition that survives
/// a crash is an external effect and must use an ordinary journaled provider
/// operation with explicit reconciliation semantics.
pub trait TrustedResourceCatalog {
    /// Native handle type passed to the selected adapter.
    type Handle;
    /// Structured acquisition failure type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Acquires one declared process-scoped resource under current policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the resource is unavailable, stale, outside the
    /// current authority, or cannot be locked under the requested access mode.
    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error>;

    /// Releases one acquired handle after the runtime establishes it is safe.
    ///
    /// # Errors
    ///
    /// Returns an error when the catalog cannot durably release or transfer
    /// ownership. An unresolved release remains recovery work.
    fn release(
        &mut self,
        resource: &ResourceId,
        handle: &mut Self::Handle,
    ) -> Result<(), Self::Error>;
}

/// Supplies stable ownership and deadline context for a process-scoped reservation.
#[derive(Clone, Copy, Debug)]
pub struct ReservationContext<'a> {
    /// Identifies the durable transaction acquiring ownership.
    pub transaction: &'a TransactionId,
    /// Identifies the exact checked plan operation.
    pub operation: &'a OperationId,
    /// Identifies the current durable attempt.
    pub attempt: NonZeroU32,
    /// Carries the exact durable assignment for a planned provider, when needed.
    pub expected_provider: Option<&'a ProviderAssignment>,
    /// Bounds admission work still available to this transaction.
    pub recovery_remaining_millis: u64,
}

/// Proves that a trusted store retained the exact recovery artifact closures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRetentionReceipt {
    transaction: TransactionId,
    roots: Vec<Sha256Digest>,
    evidence: AbilityValue,
}

impl RootRetentionReceipt {
    /// Constructs a receipt returned by a trusted root-store implementation.
    #[must_use]
    pub fn new(
        transaction: TransactionId,
        roots: Vec<Sha256Digest>,
        evidence: AbilityValue,
    ) -> Self {
        Self {
            transaction,
            roots,
            evidence,
        }
    }

    /// Returns the durable transaction whose recovery roots were retained.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }

    /// Returns exact retained closure identities in canonical order.
    #[must_use]
    pub fn roots(&self) -> &[Sha256Digest] {
        &self.roots
    }

    /// Returns trusted provider evidence for the retention operation.
    #[must_use]
    pub const fn evidence(&self) -> &AbilityValue {
        &self.evidence
    }
}

/// Retains exact artifact closures before a transaction can admit effects.
pub trait TrustedRootStore {
    /// Structured retention failure type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Idempotently retains every artifact required for execution and recovery.
    ///
    /// Implementations must use the production GC-root/closure ownership
    /// boundary and make the retention durable before returning a receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when any exact artifact closure cannot be retained for
    /// the supplied durable transaction.
    fn retain(
        &mut self,
        transaction: &TransactionId,
        artifacts: &[ArtifactReference],
    ) -> Result<RootRetentionReceipt, Self::Error>;
}

/// Proves that a trusted store durably retained a reloadable checked-plan bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanRetentionReceipt {
    transaction: TransactionId,
    plan: aos_ability_model::PlanId,
    bundle: Sha256Digest,
    evidence: AbilityValue,
}

impl PlanRetentionReceipt {
    /// Constructs a receipt returned by a trusted plan-store implementation.
    #[must_use]
    pub fn new(
        transaction: TransactionId,
        plan: aos_ability_model::PlanId,
        bundle: Sha256Digest,
        evidence: AbilityValue,
    ) -> Self {
        Self {
            transaction,
            plan,
            bundle,
            evidence,
        }
    }

    /// Returns the durable transaction whose plan bundle was retained.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }

    /// Returns the checked effect-plan identity carried by the bundle.
    #[must_use]
    pub const fn plan(&self) -> aos_ability_model::PlanId {
        self.plan
    }

    /// Returns the digest of the exact reloadable validation-input bundle.
    #[must_use]
    pub const fn bundle(&self) -> Sha256Digest {
        self.bundle
    }

    /// Returns trusted provider evidence for the durable plan operation.
    #[must_use]
    pub const fn evidence(&self) -> &AbilityValue {
        &self.evidence
    }
}

/// Persists exact checked-plan inputs before a transaction can admit effects.
pub trait TrustedPlanStore {
    /// Structured plan persistence failure type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Idempotently persists the exact plan and every input needed to revalidate it.
    ///
    /// The store must make the protected bundle durable and reloadable before
    /// returning. Repeated calls for the same transaction must return the same
    /// plan and bundle identities or fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the checked effect plan, binding plan, interface
    /// descriptors, environment, desired state, or package inputs cannot be
    /// persisted through the production retained-generation boundary.
    fn retain_plan(
        &mut self,
        transaction: &TransactionId,
        plan: &CheckedEffectPlan,
    ) -> Result<PlanRetentionReceipt, Self::Error>;
}

/// Distinguishes the separately authorized methods used by one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationPurpose {
    /// Performs the operation's declared external effect.
    Effect,
    /// Observes an ambiguous effect before any retry.
    Reconcile,
    /// Requests bounded cancellation of an admitted attempt.
    Cancel,
}

/// Reports the immediate disposition of one effect invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectDisposition<Completion, Observation> {
    /// Completion evidence establishes the adapter's promised postcondition.
    Completed(Completion),
    /// Evidence proves rejection occurred before any external effect.
    RejectedBeforeEffect(Observation),
    /// An external effect may have occurred and must be reconciled.
    Indeterminate(Observation),
}

/// Reports the result of observing an indeterminate effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileDisposition<Completion, Observation> {
    /// Observation establishes the original operation's completion.
    Completed(Completion),
    /// Observation establishes rejection before any effect.
    RejectedBeforeEffect(Observation),
    /// Observation proves a new attempt is safe under the declared retry policy.
    SafeToRetry(Observation),
    /// Observation remains inconclusive within the current bounded probe.
    StillIndeterminate(Observation),
    /// The provider cannot resolve the effect without operator intervention.
    InterventionRequired(Observation),
}

/// Reports the result of requesting cancellation from an in-flight adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancellationDisposition<Completion, Observation> {
    /// Cancellation established that the effect did not occur.
    RejectedBeforeEffect(Observation),
    /// Cancellation observed that the original effect completed.
    Completed(Completion),
    /// Cancellation could not determine whether the effect occurred.
    Indeterminate(Observation),
}

/// Defines one typed compiled adapter selected by an authenticated catalog entry.
///
/// Implementations translate a checked model operation into a concrete
/// `Request` only after fresh resource handles have been acquired. Completion
/// and observation types remain distinct so an inconclusive observation cannot
/// be mistaken for successful effect evidence.
pub trait TrustedAdapter {
    /// Concrete request understood by this adapter implementation.
    type Request;
    /// Typed evidence establishing the promised completion condition.
    type Completion: AdapterCompletion;
    /// Typed provider observation used for rejection and reconciliation.
    type Observation: AdapterRecord;
    /// Native resource handle type required by this adapter.
    type Handle;
    /// Structured request-preparation failure type.
    type PrepareError: std::error::Error + Send + Sync + 'static;

    /// Authenticates one exact implementation and method entry point.
    ///
    /// The default fails closed. An adapter must explicitly match the retained
    /// implementation descriptor, artifact, handler, interface, method, and
    /// invocation purpose before admission can select it.
    #[must_use]
    fn authenticates(
        &self,
        _implementation: &ProviderImplementationReference,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
    ) -> bool {
        false
    }

    /// Builds the exact bounded request value from a checked operation and handles.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation does not match this adapter's exact
    /// family, interface, method, handler, or handle requirements. This occurs
    /// before an effect intent is admitted.
    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError>;

    /// Reconstructs a typed request from its journaled value and fresh handles.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value is the exact supported request schema
    /// and every referenced native resource has been freshly reacquired.
    fn recover_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError>;

    /// Executes one intent that the runtime has already persisted durably.
    fn execute(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation>;

    /// Observes and reconciles a previously indeterminate logical operation.
    fn reconcile(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation>;

    /// Requests cancellation without asserting that an effect disappeared.
    fn cancel(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation>;
}
