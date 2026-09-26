//! Backend-neutral plans, operation fencing, typestates, and observations.

use std::marker::PhantomData;

use sha2::{Digest as _, Sha256};

use crate::{
    AssignmentEpoch, DesiredGeneration, ExecutionId, IncarnationId, NamespaceGeneration, NodeId,
    ObjectDigest, ObservationSequence, PayloadBootId, SandboxId,
};

use super::{BackendCapabilityViolation, RequiredBackendCapabilitiesV1};

const RUNTIME_PLAN_DOMAIN: &[u8] = b"aos-sandbox-runtime-plan-v1\0";

/// Identifies one idempotent backend operation without exposing journal keys.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackendOperationIdV1([u8; 16]);

impl BackendOperationIdV1 {
    /// Constructs a nonzero backend operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::Unspecified`] for the zero sentinel.
    pub const fn new(bytes: [u8; 16]) -> Result<Self, RuntimeModelError> {
        if u128::from_be_bytes(bytes) == 0 {
            Err(RuntimeModelError::Unspecified)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns the exact portable operation bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Orders operations within one exact runtime incarnation and backend session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackendOperationSequenceV1(u64);

impl BackendOperationSequenceV1 {
    /// Constructs a nonzero, non-exhausted operation sequence.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::InvalidSequence`] for zero or `u64::MAX`.
    pub const fn new(value: u64) -> Result<Self, RuntimeModelError> {
        if value == 0 || value == u64::MAX {
            Err(RuntimeModelError::InvalidSequence)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the portable unsigned sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next admissible sequence.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::SequenceExhausted`] before reaching the
    /// reserved `u64::MAX` sentinel.
    pub const fn checked_next(self) -> Result<Self, RuntimeModelError> {
        if self.0 >= u64::MAX - 1 {
            Err(RuntimeModelError::SequenceExhausted)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

/// Carries a nonzero relative deadline for a bounded backend stop operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackendStopDeadlineV1(u64);

impl BackendStopDeadlineV1 {
    /// Constructs a strictly positive relative deadline in nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::InvalidDeadline`] for the zero sentinel.
    pub const fn new(after_nanoseconds: u64) -> Result<Self, RuntimeModelError> {
        if after_nanoseconds == 0 {
            Err(RuntimeModelError::InvalidDeadline)
        } else {
            Ok(Self(after_nanoseconds))
        }
    }

    /// Returns the relative deadline in nanoseconds.
    #[must_use]
    pub const fn after_nanoseconds(self) -> u64 {
        self.0
    }
}

/// Binds an operation to exact current assignment and runtime generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCurrentnessV1 {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    node: NodeId,
    assignment_epoch: AssignmentEpoch,
    assignment_digest: ObjectDigest,
    desired_generation: DesiredGeneration,
    namespace_generation: NamespaceGeneration,
}

impl RuntimeCurrentnessV1 {
    /// Constructs an exact non-sentinel runtime fence.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::Unspecified`] for any zero field.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        node: NodeId,
        assignment_epoch: AssignmentEpoch,
        assignment_digest: ObjectDigest,
        desired_generation: DesiredGeneration,
        namespace_generation: NamespaceGeneration,
    ) -> Result<Self, RuntimeModelError> {
        if sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || node.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
            || assignment_digest.as_bytes() == &[0; 32]
            || desired_generation.get() == 0
            || namespace_generation.get() == 0
        {
            return Err(RuntimeModelError::Unspecified);
        }
        Ok(Self {
            sandbox,
            incarnation,
            node,
            assignment_epoch,
            assignment_digest,
            desired_generation,
            namespace_generation,
        })
    }

    /// Returns the logical sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact runtime incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the selected node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the signed assignment commitment.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the desired generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the payload namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> NamespaceGeneration {
        self.namespace_generation
    }
}

/// Stores a backend-neutral resolved runtime plan using only opaque commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedRuntimePlanV1 {
    currentness: RuntimeCurrentnessV1,
    required_capabilities: RequiredBackendCapabilitiesV1,
    storage_root: ObjectDigest,
    attachment_set: ObjectDigest,
    network: ObjectDigest,
    runtime_profile: ObjectDigest,
    plan_commitment: ObjectDigest,
}

impl ResolvedRuntimePlanV1 {
    /// Constructs and internally commits one complete resolved plan.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::Unspecified`] for a zero input commitment.
    pub fn new(
        currentness: RuntimeCurrentnessV1,
        required_capabilities: RequiredBackendCapabilitiesV1,
        storage_root: ObjectDigest,
        attachment_set: ObjectDigest,
        network: ObjectDigest,
        runtime_profile: ObjectDigest,
    ) -> Result<Self, RuntimeModelError> {
        if [storage_root, attachment_set, network, runtime_profile]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(RuntimeModelError::Unspecified);
        }
        let plan_commitment = commit_plan(
            &currentness,
            &required_capabilities,
            storage_root,
            attachment_set,
            network,
            runtime_profile,
        );
        Ok(Self {
            currentness,
            required_capabilities,
            storage_root,
            attachment_set,
            network,
            runtime_profile,
            plan_commitment,
        })
    }

    /// Returns the exact runtime fence.
    #[must_use]
    pub const fn currentness(&self) -> &RuntimeCurrentnessV1 {
        &self.currentness
    }

    /// Returns the hard semantic requirements.
    #[must_use]
    pub const fn required_capabilities(&self) -> &RequiredBackendCapabilitiesV1 {
        &self.required_capabilities
    }

    /// Returns the opaque storage-root commitment.
    #[must_use]
    pub const fn storage_root(&self) -> ObjectDigest {
        self.storage_root
    }

    /// Returns the complete attachment-set commitment.
    #[must_use]
    pub const fn attachment_set(&self) -> ObjectDigest {
        self.attachment_set
    }

    /// Returns the prepared network commitment.
    #[must_use]
    pub const fn network(&self) -> ObjectDigest {
        self.network
    }

    /// Returns the runtime-profile commitment.
    #[must_use]
    pub const fn runtime_profile(&self) -> ObjectDigest {
        self.runtime_profile
    }

    /// Returns the internally derived complete plan commitment.
    #[must_use]
    pub const fn plan_commitment(&self) -> ObjectDigest {
        self.plan_commitment
    }
}

/// Commits an opaque backend handle to its exact runtime generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeHandleCommitmentV1 {
    currentness: RuntimeCurrentnessV1,
    plan_commitment: ObjectDigest,
    handle: ObjectDigest,
}

impl RuntimeHandleCommitmentV1 {
    /// Constructs a non-sentinel handle commitment.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::Unspecified`] for a zero plan or handle digest.
    pub fn new(
        currentness: RuntimeCurrentnessV1,
        plan_commitment: ObjectDigest,
        handle: ObjectDigest,
    ) -> Result<Self, RuntimeModelError> {
        if plan_commitment.as_bytes() == &[0; 32] || handle.as_bytes() == &[0; 32] {
            return Err(RuntimeModelError::Unspecified);
        }
        Ok(Self {
            currentness,
            plan_commitment,
            handle,
        })
    }

    /// Returns the exact runtime fence.
    #[must_use]
    pub const fn currentness(&self) -> &RuntimeCurrentnessV1 {
        &self.currentness
    }

    /// Returns the exact resolved plan retained through runtime destruction.
    #[must_use]
    pub const fn plan_commitment(&self) -> ObjectDigest {
        self.plan_commitment
    }

    /// Returns the opaque handle commitment.
    #[must_use]
    pub const fn handle(&self) -> ObjectDigest {
        self.handle
    }
}

/// Owns a backend-prepared runtime that has not been started.
pub struct PreparedRuntime<H> {
    plan: ResolvedRuntimePlanV1,
    handle: H,
}

impl<H> PreparedRuntime<H> {
    /// Creates a prepared typestate after backend postcondition verification.
    #[must_use]
    pub fn new(plan: ResolvedRuntimePlanV1, handle: H) -> Self {
        Self { plan, handle }
    }

    /// Returns the exact resolved plan.
    #[must_use]
    pub const fn plan(&self) -> &ResolvedRuntimePlanV1 {
        &self.plan
    }

    /// Borrows the backend-private prepared handle for adapter validation.
    #[must_use]
    pub const fn handle(&self) -> &H {
        &self.handle
    }

    /// Separates the plan and opaque backend handle for an owning adapter.
    #[must_use]
    pub fn into_parts(self) -> (ResolvedRuntimePlanV1, H) {
        (self.plan, self.handle)
    }
}

/// Owns one started and currently runnable backend runtime.
pub struct RunningRuntime<H> {
    commitment: RuntimeHandleCommitmentV1,
    handle: H,
}

impl<H> RunningRuntime<H> {
    /// Creates a running typestate after authenticated start or thaw verification.
    #[must_use]
    pub fn new(commitment: RuntimeHandleCommitmentV1, handle: H) -> Self {
        Self { commitment, handle }
    }

    /// Returns the portable handle commitment.
    #[must_use]
    pub const fn commitment(&self) -> &RuntimeHandleCommitmentV1 {
        &self.commitment
    }

    /// Borrows the backend-private running handle for protected staging.
    #[must_use]
    pub const fn handle(&self) -> &H {
        &self.handle
    }

    /// Separates the commitment and opaque backend handle.
    #[must_use]
    pub fn into_parts(self) -> (RuntimeHandleCommitmentV1, H) {
        (self.commitment, self.handle)
    }
}

/// Owns one completely frozen backend runtime.
pub struct FrozenRuntime<H> {
    commitment: RuntimeHandleCommitmentV1,
    handle: H,
}

impl<H> FrozenRuntime<H> {
    /// Creates a frozen typestate after complete payload-cgroup observation.
    #[must_use]
    pub fn new(commitment: RuntimeHandleCommitmentV1, handle: H) -> Self {
        Self { commitment, handle }
    }

    /// Returns the portable handle commitment.
    #[must_use]
    pub const fn commitment(&self) -> &RuntimeHandleCommitmentV1 {
        &self.commitment
    }

    /// Borrows the backend-private frozen handle for protected staging.
    #[must_use]
    pub const fn handle(&self) -> &H {
        &self.handle
    }

    /// Separates the commitment and opaque backend handle.
    #[must_use]
    pub fn into_parts(self) -> (RuntimeHandleCommitmentV1, H) {
        (self.commitment, self.handle)
    }
}

/// Owns a runtime whose payload is stopped and safe for backend destruction.
pub struct StoppedRuntime<H> {
    commitment: RuntimeHandleCommitmentV1,
    handle: H,
}

impl<H> StoppedRuntime<H> {
    /// Creates a stopped typestate after terminal absence or exit verification.
    #[must_use]
    pub fn new(commitment: RuntimeHandleCommitmentV1, handle: H) -> Self {
        Self { commitment, handle }
    }

    /// Returns the portable handle commitment.
    #[must_use]
    pub const fn commitment(&self) -> &RuntimeHandleCommitmentV1 {
        &self.commitment
    }

    /// Borrows the backend-private stopped handle for protected staging.
    #[must_use]
    pub const fn handle(&self) -> &H {
        &self.handle
    }

    /// Separates the commitment and opaque backend handle.
    #[must_use]
    pub fn into_parts(self) -> (RuntimeHandleCommitmentV1, H) {
        (self.commitment, self.handle)
    }
}

/// Owns either runnable or frozen state accepted by the stop operation.
pub enum StoppableRuntime<H> {
    /// Stops a currently runnable payload.
    Running(RunningRuntime<H>),
    /// Stops a payload already held at the complete freeze barrier.
    Frozen(FrozenRuntime<H>),
}

/// Owns state whose payload is absent and which may be destroyed.
pub enum DestroyableRuntime<P, H> {
    /// Destroys resources that were prepared but never started.
    Prepared(PreparedRuntime<P>),
    /// Destroys resources after a verified terminal stop.
    Stopped(StoppedRuntime<H>),
}

impl<P, H> DestroyableRuntime<P, H> {
    /// Returns the exact plan commitment retained into destruction.
    #[must_use]
    pub fn plan_commitment(&self) -> ObjectDigest {
        match self {
            Self::Prepared(runtime) => runtime.plan().plan_commitment(),
            Self::Stopped(runtime) => runtime.commitment().plan_commitment(),
        }
    }
}

/// Names one runtime lifecycle effect that may require process-crash recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BackendLifecycleOperationV1 {
    /// Resolves and prepares protected runtime resources.
    Prepare = 1,
    /// Starts the exact prepared runtime.
    Start = 2,
    /// Freezes the complete payload.
    Freeze = 3,
    /// Thaws the complete payload.
    Thaw = 4,
    /// Stops the complete payload.
    Stop = 5,
    /// Forces complete-payload teardown after a protected stop deadline.
    Kill = 8,
    /// Destroys resources after payload absence.
    Destroy = 6,
    /// Reads one exact runtime generation without mutation.
    Inspect = 7,
}

/// Stores the protected binding for one crash-recoverable lifecycle effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendLifecycleRecoveryRecordV1 {
    authority_binding: ObjectDigest,
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    lifecycle_operation: BackendLifecycleOperationV1,
    currentness: RuntimeCurrentnessV1,
    plan_commitment: ObjectDigest,
    runtime_handle: Option<ObjectDigest>,
    request_commitment: ObjectDigest,
    journal_sequence: u64,
    provenance_commitment: ObjectDigest,
}

impl BackendLifecycleRecoveryRecordV1 {
    #[allow(clippy::too_many_arguments)]
    fn from_loaded(
        authority_binding: ObjectDigest,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        lifecycle_operation: BackendLifecycleOperationV1,
        currentness: RuntimeCurrentnessV1,
        plan_commitment: ObjectDigest,
        runtime_handle: Option<ObjectDigest>,
        request_commitment: ObjectDigest,
        journal_sequence: u64,
        provenance_commitment: ObjectDigest,
    ) -> Result<Self, RuntimeModelError> {
        let handle_shape_is_valid = match lifecycle_operation {
            BackendLifecycleOperationV1::Prepare
            | BackendLifecycleOperationV1::Start
            | BackendLifecycleOperationV1::Destroy => true,
            BackendLifecycleOperationV1::Freeze
            | BackendLifecycleOperationV1::Thaw
            | BackendLifecycleOperationV1::Stop
            | BackendLifecycleOperationV1::Kill
            | BackendLifecycleOperationV1::Inspect => runtime_handle.is_some(),
        };
        if authority_binding.as_bytes() == &[0; 32]
            || !handle_shape_is_valid
            || runtime_handle.is_some_and(|value| value.as_bytes() == &[0; 32])
            || plan_commitment.as_bytes() == &[0; 32]
            || request_commitment.as_bytes() == &[0; 32]
            || provenance_commitment.as_bytes() == &[0; 32]
            || journal_sequence == 0
        {
            return Err(RuntimeModelError::Unspecified);
        }
        Ok(Self {
            authority_binding,
            operation,
            sequence,
            lifecycle_operation,
            currentness,
            plan_commitment,
            runtime_handle,
            request_commitment,
            journal_sequence,
            provenance_commitment,
        })
    }

    /// Returns the exact protected evidence-verifier authority binding.
    #[must_use]
    pub const fn authority_binding(&self) -> ObjectDigest {
        self.authority_binding
    }

    /// Returns the exact idempotent operation identity.
    #[must_use]
    pub const fn operation(&self) -> BackendOperationIdV1 {
        self.operation
    }

    /// Returns the exact operation sequence.
    #[must_use]
    pub const fn sequence(&self) -> BackendOperationSequenceV1 {
        self.sequence
    }

    /// Returns the closed lifecycle operation.
    #[must_use]
    pub const fn lifecycle_operation(&self) -> BackendLifecycleOperationV1 {
        self.lifecycle_operation
    }

    /// Returns exact runtime currentness.
    #[must_use]
    pub const fn currentness(&self) -> &RuntimeCurrentnessV1 {
        &self.currentness
    }

    /// Returns the exact retained resolved-plan commitment.
    #[must_use]
    pub const fn plan_commitment(&self) -> ObjectDigest {
        self.plan_commitment
    }

    /// Returns the exact runtime handle when realization crossed Prepare.
    #[must_use]
    pub const fn runtime_handle(&self) -> Option<ObjectDigest> {
        self.runtime_handle
    }

    /// Returns the complete request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the protected journal sequence authenticating the record.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns protected store provenance for the exact record.
    #[must_use]
    pub const fn provenance_commitment(&self) -> ObjectDigest {
        self.provenance_commitment
    }
}

/// Carries lifecycle-recovery fields from an authenticated protected loader.
pub struct BackendLifecycleRecoveryInputV1 {
    /// Expected protected evidence-verifier authority binding.
    pub authority_binding: ObjectDigest,
    /// Exact idempotent lifecycle operation identity.
    pub operation: BackendOperationIdV1,
    /// Monotonic lifecycle operation sequence.
    pub sequence: BackendOperationSequenceV1,
    /// Closed lifecycle operation.
    pub lifecycle_operation: BackendLifecycleOperationV1,
    /// Exact assignment and runtime generation.
    pub currentness: RuntimeCurrentnessV1,
    /// Complete resolved plan commitment.
    pub plan_commitment: ObjectDigest,
    /// Runtime handle when the operation targets a started runtime.
    pub runtime_handle: Option<ObjectDigest>,
    /// Exact normalized lifecycle request commitment.
    pub request_commitment: ObjectDigest,
    /// Nonzero protected journal sequence.
    pub journal_sequence: u64,
    /// Authenticated protected-record provenance.
    pub provenance_commitment: ObjectDigest,
}

/// Loads lifecycle recovery state only after protected authentication.
///
/// This sealed TCB interface cannot be implemented by downstream callers.
#[allow(private_bounds)]
pub trait BackendLifecycleRecoveryLoaderV1:
    super::sealed::BackendLifecycleRecoveryLoaderV1
{
    /// Loader-specific authentication or storage error.
    type Error: From<RuntimeModelError>;

    /// Authenticates and returns one exact lifecycle recovery record input.
    ///
    /// # Errors
    ///
    /// Returns the loader error for unavailable, stale, malformed, or
    /// unauthenticated protected lifecycle state.
    fn load_authenticated_lifecycle_recovery(
        &mut self,
    ) -> Result<BackendLifecycleRecoveryInputV1, Self::Error>;
}

/// Mints an opaque lifecycle recovery record through a protected loader.
///
/// # Errors
///
/// Returns the loader error for failed authentication or invalid loaded fields.
pub fn load_backend_lifecycle_recovery_v1<L: BackendLifecycleRecoveryLoaderV1>(
    loader: &mut L,
) -> Result<BackendLifecycleRecoveryRecordV1, L::Error> {
    let input = loader.load_authenticated_lifecycle_recovery()?;
    BackendLifecycleRecoveryRecordV1::from_loaded(
        input.authority_binding,
        input.operation,
        input.sequence,
        input.lifecycle_operation,
        input.currentness,
        input.plan_commitment,
        input.runtime_handle,
        input.request_commitment,
        input.journal_sequence,
        input.provenance_commitment,
    )
    .map_err(Into::into)
}

/// Retains backend-private recovery state after an ambiguous effect boundary.
///
/// The value is move-only and has no public constructor. A backend creates it
/// through [`RuntimeRecoveryToken::from_backend`] and must require it when
/// resolving an ambiguous operation. Portable callers can inspect bindings but
/// cannot extract or duplicate the backend handle.
pub struct RuntimeRecoveryToken<H> {
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    currentness: RuntimeCurrentnessV1,
    plan_commitment: ObjectDigest,
    request_commitment: ObjectDigest,
    handle: H,
}

impl<H> RuntimeRecoveryToken<H> {
    /// Constructs a move-only token for a backend implementation.
    ///
    /// This API is public because backend implementations live in separate
    /// crates. The token is not authority by itself: durable recovery must
    /// independently match every projected binding before the handle is used.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::Unspecified`] for a zero plan or request commitment.
    pub fn from_backend(
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        currentness: RuntimeCurrentnessV1,
        plan_commitment: ObjectDigest,
        request_commitment: ObjectDigest,
        handle: H,
    ) -> Result<Self, RuntimeModelError> {
        if plan_commitment.as_bytes() == &[0; 32] || request_commitment.as_bytes() == &[0; 32] {
            return Err(RuntimeModelError::Unspecified);
        }
        Ok(Self {
            operation,
            sequence,
            currentness,
            plan_commitment,
            request_commitment,
            handle,
        })
    }

    /// Returns the exact idempotent operation identity.
    #[must_use]
    pub const fn operation(&self) -> BackendOperationIdV1 {
        self.operation
    }

    /// Returns the exact operation sequence.
    #[must_use]
    pub const fn sequence(&self) -> BackendOperationSequenceV1 {
        self.sequence
    }

    /// Returns the exact runtime currentness binding.
    #[must_use]
    pub const fn currentness(&self) -> &RuntimeCurrentnessV1 {
        &self.currentness
    }

    /// Returns the exact complete request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the exact resolved-plan commitment retained across ambiguity.
    #[must_use]
    pub const fn plan_commitment(&self) -> ObjectDigest {
        self.plan_commitment
    }

    /// Borrows backend-private recovery state without permitting extraction.
    ///
    /// Implementations use this to validate their own retained effect binding
    /// while every nonterminal branch returns the original move-only token.
    #[must_use]
    pub const fn backend_handle(&self) -> &H {
        &self.handle
    }

    /// Separates portable bindings and the backend-private recovery handle.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        BackendOperationIdV1,
        BackendOperationSequenceV1,
        RuntimeCurrentnessV1,
        ObjectDigest,
        ObjectDigest,
        H,
    ) {
        (
            self.operation,
            self.sequence,
            self.currentness,
            self.plan_commitment,
            self.request_commitment,
            self.handle,
        )
    }
}

/// Proves that the backend verified destruction of the exact prepared runtime.
pub struct DestroyedRuntime {
    plan_commitment: ObjectDigest,
    _closed: PhantomData<fn() -> ()>,
}

impl DestroyedRuntime {
    /// Creates terminal destruction evidence for the exact plan.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::Unspecified`] for a zero plan commitment.
    pub fn new(plan_commitment: ObjectDigest) -> Result<Self, RuntimeModelError> {
        if plan_commitment.as_bytes() == &[0; 32] {
            return Err(RuntimeModelError::Unspecified);
        }
        Ok(Self {
            plan_commitment,
            _closed: PhantomData,
        })
    }

    /// Returns the destroyed plan commitment.
    #[must_use]
    pub const fn plan_commitment(&self) -> ObjectDigest {
        self.plan_commitment
    }
}

/// Owns one running backend execution handle.
pub struct BackendExecutionHandle<H> {
    execution: ExecutionId,
    specification_digest: ObjectDigest,
    runtime: RuntimeHandleCommitmentV1,
    handle: H,
}

impl<H> BackendExecutionHandle<H> {
    /// Creates a handle after the backend verifies exact execution handoff.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::Unspecified`] for a zero execution identity
    /// or specification digest.
    pub fn new(
        execution: ExecutionId,
        specification_digest: ObjectDigest,
        runtime: RuntimeHandleCommitmentV1,
        handle: H,
    ) -> Result<Self, RuntimeModelError> {
        if execution.as_bytes() == &[0; 16] || specification_digest.as_bytes() == &[0; 32] {
            return Err(RuntimeModelError::Unspecified);
        }
        Ok(Self {
            execution,
            specification_digest,
            runtime,
            handle,
        })
    }

    /// Returns the execution identity.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact admitted specification digest.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }

    /// Returns the runtime commitment on which it executes.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeHandleCommitmentV1 {
        &self.runtime
    }

    /// Separates portable bindings and the opaque backend handle.
    #[must_use]
    pub fn into_parts(self) -> (ExecutionId, ObjectDigest, RuntimeHandleCommitmentV1, H) {
        (
            self.execution,
            self.specification_digest,
            self.runtime,
            self.handle,
        )
    }
}

/// Carries exact durable execution bytes into the effectful backend boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendExecutionRequestV1 {
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    specification_bytes: Vec<u8>,
    specification_digest: ObjectDigest,
    admission_commitment: ObjectDigest,
    effect_request_digest: ObjectDigest,
}

impl BackendExecutionRequestV1 {
    /// Constructs an exact bounded backend execution request.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError`] when bytes are empty or exceed 16 MiB, a
    /// digest is zero, or the spec bytes do not reproduce `specification_digest`.
    pub fn new(
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        specification_bytes: Vec<u8>,
        specification_digest: ObjectDigest,
        admission_commitment: ObjectDigest,
        effect_request_digest: ObjectDigest,
    ) -> Result<Self, RuntimeModelError> {
        if specification_bytes.is_empty() || specification_bytes.len() > 15 * 1_048_576 {
            return Err(RuntimeModelError::InvalidExecutionBytes);
        }
        if specification_digest.as_bytes() == &[0; 32]
            || admission_commitment.as_bytes() == &[0; 32]
            || effect_request_digest.as_bytes() == &[0; 32]
        {
            return Err(RuntimeModelError::Unspecified);
        }
        let specification = crate::decode_execution_spec_v1(
            &specification_bytes,
            crate::DecodeLimits {
                maximum_bytes: specification_bytes.len(),
                maximum_collection_items: 65_536,
                maximum_total_items: 262_144,
                maximum_byte_string_bytes: 15 * 1_048_576,
                maximum_text_bytes: 1_048_576,
                maximum_depth: 128,
            },
        )
        .map_err(|_| RuntimeModelError::InvalidExecutionBytes)?;
        if crate::execution_spec_digest_v1(&specification) != specification_digest {
            return Err(RuntimeModelError::InvalidExecutionBytes);
        }
        Ok(Self {
            operation,
            sequence,
            specification_bytes,
            specification_digest,
            admission_commitment,
            effect_request_digest,
        })
    }

    /// Returns the idempotent operation identity.
    #[must_use]
    pub const fn operation(&self) -> BackendOperationIdV1 {
        self.operation
    }

    /// Returns the exact operation sequence.
    #[must_use]
    pub const fn sequence(&self) -> BackendOperationSequenceV1 {
        self.sequence
    }

    /// Returns canonical execution-specification bytes.
    #[must_use]
    pub fn specification_bytes(&self) -> &[u8] {
        &self.specification_bytes
    }

    /// Returns the exact execution-specification digest.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }

    /// Returns the durable admission commitment.
    #[must_use]
    pub const fn admission_commitment(&self) -> ObjectDigest {
        self.admission_commitment
    }

    /// Returns the normalized durable effect-request digest.
    #[must_use]
    pub const fn effect_request_digest(&self) -> ObjectDigest {
        self.effect_request_digest
    }
}

/// Classifies whether repeating an operation can preserve idempotency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendRetryClassV1 {
    /// The backend proved that no externally visible effect began.
    SafeBeforeEffect,
    /// Repeating the exact operation ID and digest returns the same outcome.
    ExactIdempotentReplay,
    /// Effect status is ambiguous and requires authenticated inventory recovery.
    RecoveryRequired,
    /// The failure is permanent for this exact plan and generation.
    Permanent,
}

/// Defines the closed runtime lifecycle visible to portable reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendRuntimePhaseV1 {
    /// Resources exist, but no payload has started.
    Prepared,
    /// Payload startup has crossed the backend effect boundary.
    Starting,
    /// The complete payload is runnable.
    Running,
    /// The complete payload cgroup is frozen.
    Frozen,
    /// Payload termination has crossed the backend effect boundary.
    Stopping,
    /// Payload termination is verified and resources remain.
    Stopped,
    /// Runtime realization failed permanently.
    Failed,
    /// Protected inspection proves that the runtime is absent.
    Absent,
}

/// Defines the closed execution lifecycle visible to backend inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendExecutionPhaseV1 {
    /// The exact execution is authorized but has not started.
    Authorized,
    /// Execution handoff has crossed the guest-agent effect boundary.
    Starting,
    /// The command is running in the exact payload generation.
    Running,
    /// The command exited and has a terminal observation.
    Exited,
    /// Cancellation completed with a terminal observation.
    Canceled,
    /// The command failed permanently with a terminal observation.
    Failed,
    /// Recovery cannot establish a trustworthy terminal command outcome.
    Lost,
}

/// Stores an authenticated observation of one runtime generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendRuntimeInspectionV1 {
    authority_binding: ObjectDigest,
    operation: BackendOperationIdV1,
    operation_sequence: BackendOperationSequenceV1,
    lifecycle_operation: BackendLifecycleOperationV1,
    request_commitment: ObjectDigest,
    commitment: RuntimeHandleCommitmentV1,
    phase: BackendRuntimePhaseV1,
    sequence: ObservationSequence,
    observation_commitment: ObjectDigest,
}

impl BackendRuntimeInspectionV1 {
    fn from_loaded(
        authority_binding: ObjectDigest,
        operation: BackendOperationIdV1,
        operation_sequence: BackendOperationSequenceV1,
        lifecycle_operation: BackendLifecycleOperationV1,
        request_commitment: ObjectDigest,
        commitment: RuntimeHandleCommitmentV1,
        phase: BackendRuntimePhaseV1,
        sequence: ObservationSequence,
        observation_commitment: ObjectDigest,
    ) -> Result<Self, RuntimeModelError> {
        if authority_binding.as_bytes() == &[0; 32]
            || request_commitment.as_bytes() == &[0; 32]
            || sequence.get() == 0
            || observation_commitment.as_bytes() == &[0; 32]
        {
            return Err(RuntimeModelError::Unspecified);
        }
        Ok(Self {
            authority_binding,
            operation,
            operation_sequence,
            lifecycle_operation,
            request_commitment,
            commitment,
            phase,
            sequence,
            observation_commitment,
        })
    }

    /// Returns the exact protected evidence-verifier authority binding.
    #[must_use]
    pub const fn authority_binding(&self) -> ObjectDigest {
        self.authority_binding
    }

    /// Returns the exact lifecycle operation identity.
    #[must_use]
    pub const fn operation(&self) -> BackendOperationIdV1 {
        self.operation
    }

    /// Returns the exact lifecycle operation sequence.
    #[must_use]
    pub const fn operation_sequence(&self) -> BackendOperationSequenceV1 {
        self.operation_sequence
    }

    /// Returns the closed lifecycle action that produced this observation.
    #[must_use]
    pub const fn lifecycle_operation(&self) -> BackendLifecycleOperationV1 {
        self.lifecycle_operation
    }

    /// Returns the exact normalized lifecycle-request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the exact runtime commitment.
    #[must_use]
    pub const fn commitment(&self) -> &RuntimeHandleCommitmentV1 {
        &self.commitment
    }

    /// Returns the observed phase.
    #[must_use]
    pub const fn phase(&self) -> BackendRuntimePhaseV1 {
        self.phase
    }

    /// Returns the monotonic observation sequence.
    #[must_use]
    pub const fn sequence(&self) -> ObservationSequence {
        self.sequence
    }

    /// Returns the complete authenticated observation commitment.
    #[must_use]
    pub const fn observation_commitment(&self) -> ObjectDigest {
        self.observation_commitment
    }
}

/// Carries unauthenticated scalar runtime fields from a protected loader.
pub struct BackendRuntimeInspectionInputV1 {
    /// Expected protected evidence-verifier authority binding.
    pub authority_binding: ObjectDigest,
    /// Exact lifecycle operation identity.
    pub operation: BackendOperationIdV1,
    /// Exact lifecycle operation sequence.
    pub operation_sequence: BackendOperationSequenceV1,
    /// Closed lifecycle action being observed.
    pub lifecycle_operation: BackendLifecycleOperationV1,
    /// Complete normalized lifecycle-request commitment.
    pub request_commitment: ObjectDigest,
    /// Exact runtime handle commitment.
    pub commitment: RuntimeHandleCommitmentV1,
    /// Closed observed lifecycle phase.
    pub phase: BackendRuntimePhaseV1,
    /// Monotonic protected observation sequence.
    pub sequence: ObservationSequence,
    /// Authenticated observation-envelope commitment.
    pub observation_commitment: ObjectDigest,
}

/// Loads one runtime inspection after authenticating protected provenance.
///
/// This sealed TCB interface cannot be implemented by downstream callers.
#[allow(private_bounds)]
pub trait BackendRuntimeInspectionLoaderV1:
    super::sealed::BackendRuntimeInspectionLoaderV1
{
    /// Loader-specific authentication or storage error.
    type Error: From<RuntimeModelError>;

    /// Authenticates and returns exact scalar runtime observation fields.
    ///
    /// # Errors
    ///
    /// Returns the loader error when protected runtime evidence is unavailable,
    /// stale, incomplete, or unauthenticated.
    fn load_authenticated_runtime_inspection(
        &mut self,
    ) -> Result<BackendRuntimeInspectionInputV1, Self::Error>;
}

/// Mints one opaque runtime inspection through an authenticated loader.
///
/// # Errors
///
/// Returns the loader error for failed authentication or invalid loaded fields.
pub fn load_backend_runtime_inspection_v1<L: BackendRuntimeInspectionLoaderV1>(
    loader: &mut L,
) -> Result<BackendRuntimeInspectionV1, L::Error> {
    let input = loader.load_authenticated_runtime_inspection()?;
    BackendRuntimeInspectionV1::from_loaded(
        input.authority_binding,
        input.operation,
        input.operation_sequence,
        input.lifecycle_operation,
        input.request_commitment,
        input.commitment,
        input.phase,
        input.sequence,
        input.observation_commitment,
    )
    .map_err(Into::into)
}

/// Stores an authenticated observation of one backend execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendExecutionInspectionV1 {
    authority_binding: ObjectDigest,
    operation: BackendOperationIdV1,
    operation_sequence: BackendOperationSequenceV1,
    effect_request_digest: ObjectDigest,
    execution: ExecutionId,
    specification_digest: ObjectDigest,
    admission_commitment: ObjectDigest,
    runtime: RuntimeHandleCommitmentV1,
    payload_boot_id: PayloadBootId,
    phase: BackendExecutionPhaseV1,
    sequence: ObservationSequence,
    observation_commitment: ObjectDigest,
}

impl BackendExecutionInspectionV1 {
    fn from_loaded(
        authority_binding: ObjectDigest,
        operation: BackendOperationIdV1,
        operation_sequence: BackendOperationSequenceV1,
        effect_request_digest: ObjectDigest,
        execution: ExecutionId,
        specification_digest: ObjectDigest,
        admission_commitment: ObjectDigest,
        runtime: RuntimeHandleCommitmentV1,
        payload_boot_id: PayloadBootId,
        phase: BackendExecutionPhaseV1,
        sequence: ObservationSequence,
        observation_commitment: ObjectDigest,
    ) -> Result<Self, RuntimeModelError> {
        if authority_binding.as_bytes() == &[0; 32]
            || effect_request_digest.as_bytes() == &[0; 32]
            || execution.as_bytes() == &[0; 16]
            || specification_digest.as_bytes() == &[0; 32]
            || admission_commitment.as_bytes() == &[0; 32]
            || sequence.get() == 0
            || observation_commitment.as_bytes() == &[0; 32]
        {
            return Err(RuntimeModelError::Unspecified);
        }
        Ok(Self {
            authority_binding,
            operation,
            operation_sequence,
            effect_request_digest,
            execution,
            specification_digest,
            admission_commitment,
            runtime,
            payload_boot_id,
            phase,
            sequence,
            observation_commitment,
        })
    }

    /// Returns the exact protected evidence-verifier authority binding.
    #[must_use]
    pub const fn authority_binding(&self) -> ObjectDigest {
        self.authority_binding
    }

    /// Returns the exact durable operation identity observed.
    #[must_use]
    pub const fn operation(&self) -> BackendOperationIdV1 {
        self.operation
    }

    /// Returns the exact durable operation sequence observed.
    #[must_use]
    pub const fn operation_sequence(&self) -> BackendOperationSequenceV1 {
        self.operation_sequence
    }

    /// Returns the normalized effect-request digest observed.
    #[must_use]
    pub const fn effect_request_digest(&self) -> ObjectDigest {
        self.effect_request_digest
    }

    /// Returns the execution identity.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the execution-specification digest.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }

    /// Returns the exact durable admission commitment.
    #[must_use]
    pub const fn admission_commitment(&self) -> ObjectDigest {
        self.admission_commitment
    }

    /// Returns the exact runtime commitment.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeHandleCommitmentV1 {
        &self.runtime
    }

    /// Returns the exact observed payload boot identity.
    #[must_use]
    pub const fn payload_boot_id(&self) -> PayloadBootId {
        self.payload_boot_id
    }

    /// Returns the observed execution phase.
    #[must_use]
    pub const fn phase(&self) -> BackendExecutionPhaseV1 {
        self.phase
    }

    /// Returns the monotonic observation sequence.
    #[must_use]
    pub const fn sequence(&self) -> ObservationSequence {
        self.sequence
    }

    /// Returns the complete observation commitment.
    #[must_use]
    pub const fn observation_commitment(&self) -> ObjectDigest {
        self.observation_commitment
    }
}

/// Carries unauthenticated scalar inspection fields from a protected loader.
pub struct BackendExecutionInspectionInputV1 {
    /// Expected protected evidence-verifier authority binding.
    pub authority_binding: ObjectDigest,
    /// Exact durable operation identity.
    pub operation: BackendOperationIdV1,
    /// Exact durable operation sequence.
    pub operation_sequence: BackendOperationSequenceV1,
    /// Normalized effect request digest.
    pub effect_request_digest: ObjectDigest,
    /// Durable execution identity.
    pub execution: ExecutionId,
    /// Exact execution specification digest.
    pub specification_digest: ObjectDigest,
    /// Durable admission commitment.
    pub admission_commitment: ObjectDigest,
    /// Exact runtime handle commitment.
    pub runtime: RuntimeHandleCommitmentV1,
    /// Exact payload boot identity.
    pub payload_boot_id: PayloadBootId,
    /// Closed observed execution phase.
    pub phase: BackendExecutionPhaseV1,
    /// Monotonic protected observation sequence.
    pub sequence: ObservationSequence,
    /// Authenticated observation-envelope commitment.
    pub observation_commitment: ObjectDigest,
}

/// Loads one inspection only after authenticating its protected provenance.
///
/// This sealed TCB interface cannot be implemented by downstream callers.
#[allow(private_bounds)]
pub trait BackendExecutionInspectionLoaderV1:
    super::sealed::BackendExecutionInspectionLoaderV1
{
    /// Loader-specific authentication or storage error.
    type Error: From<RuntimeModelError>;

    /// Authenticates and returns exact scalar observation fields.
    ///
    /// # Errors
    ///
    /// Returns the loader error when provenance, signature, transport,
    /// currentness, or protected storage cannot be authenticated.
    fn load_authenticated_inspection(
        &mut self,
    ) -> Result<BackendExecutionInspectionInputV1, Self::Error>;
}

/// Mints one opaque inspection capability through an authenticated loader.
///
/// # Errors
///
/// Returns the loader error for failed authentication or invalid loaded fields.
pub fn load_backend_execution_inspection_v1<L: BackendExecutionInspectionLoaderV1>(
    loader: &mut L,
) -> Result<BackendExecutionInspectionV1, L::Error> {
    let input = loader.load_authenticated_inspection()?;
    BackendExecutionInspectionV1::from_loaded(
        input.authority_binding,
        input.operation,
        input.operation_sequence,
        input.effect_request_digest,
        input.execution,
        input.specification_digest,
        input.admission_commitment,
        input.runtime,
        input.payload_boot_id,
        input.phase,
        input.sequence,
        input.observation_commitment,
    )
    .map_err(Into::into)
}

/// Binds a read-only execution inspection to every protected identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendExecutionInspectionRequestV1 {
    evidence_authority_binding: ObjectDigest,
    operation: BackendOperationIdV1,
    operation_sequence: BackendOperationSequenceV1,
    effect_request_digest: ObjectDigest,
    execution: ExecutionId,
    specification_digest: ObjectDigest,
    admission_commitment: ObjectDigest,
    runtime: RuntimeHandleCommitmentV1,
    payload_boot_id: PayloadBootId,
}

impl BackendExecutionInspectionRequestV1 {
    /// Constructs one exact execution inspection request.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeModelError::Unspecified`] for a zero evidence authority,
    /// execution, specification, or admission commitment.
    pub fn new(
        evidence_authority_binding: ObjectDigest,
        operation: BackendOperationIdV1,
        operation_sequence: BackendOperationSequenceV1,
        effect_request_digest: ObjectDigest,
        execution: ExecutionId,
        specification_digest: ObjectDigest,
        admission_commitment: ObjectDigest,
        runtime: RuntimeHandleCommitmentV1,
        payload_boot_id: PayloadBootId,
    ) -> Result<Self, RuntimeModelError> {
        if evidence_authority_binding.as_bytes() == &[0; 32]
            || effect_request_digest.as_bytes() == &[0; 32]
            || execution.as_bytes() == &[0; 16]
            || specification_digest.as_bytes() == &[0; 32]
            || admission_commitment.as_bytes() == &[0; 32]
            || payload_boot_id.as_bytes() == &[0; 16]
        {
            return Err(RuntimeModelError::Unspecified);
        }
        Ok(Self {
            evidence_authority_binding,
            operation,
            operation_sequence,
            effect_request_digest,
            execution,
            specification_digest,
            admission_commitment,
            runtime,
            payload_boot_id,
        })
    }

    /// Returns the protected evidence-verifier authority required by this request.
    #[must_use]
    pub const fn evidence_authority_binding(&self) -> ObjectDigest {
        self.evidence_authority_binding
    }

    /// Returns the exact durable operation identity.
    #[must_use]
    pub const fn operation(&self) -> BackendOperationIdV1 {
        self.operation
    }

    /// Returns the exact durable operation sequence.
    #[must_use]
    pub const fn operation_sequence(&self) -> BackendOperationSequenceV1 {
        self.operation_sequence
    }

    /// Returns the normalized effect-request digest.
    #[must_use]
    pub const fn effect_request_digest(&self) -> ObjectDigest {
        self.effect_request_digest
    }

    /// Returns the exact execution identity.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact specification digest.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }

    /// Returns the exact admission commitment.
    #[must_use]
    pub const fn admission_commitment(&self) -> ObjectDigest {
        self.admission_commitment
    }

    /// Returns the exact runtime handle commitment.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeHandleCommitmentV1 {
        &self.runtime
    }

    /// Returns the exact payload boot identity.
    #[must_use]
    pub const fn payload_boot_id(&self) -> PayloadBootId {
        self.payload_boot_id
    }
}

/// Reports a verified successful start.
pub type BackendStartObservationV1 = BackendRuntimeInspectionV1;
/// Reports a verified complete payload freeze.
pub type BackendFreezeObservationV1 = BackendRuntimeInspectionV1;
/// Reports a verified terminal stop.
pub type BackendStopObservationV1 = BackendRuntimeInspectionV1;

/// Reports malformed portable backend input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeModelError {
    /// An identity, counter, or commitment uses its zero sentinel.
    #[error("runtime model contains an unspecified field")]
    Unspecified,
    /// An operation sequence is zero or uses the exhausted sentinel.
    #[error("runtime operation sequence is invalid")]
    InvalidSequence,
    /// The operation sequence cannot advance without entering the reserved sentinel.
    #[error("runtime operation sequence is exhausted")]
    SequenceExhausted,
    /// A relative stop deadline uses the zero sentinel.
    #[error("runtime stop deadline must be positive")]
    InvalidDeadline,
    /// Canonical execution bytes are empty or exceed the portable bound.
    #[error("runtime execution bytes are invalid")]
    InvalidExecutionBytes,
    /// A required capability set is invalid.
    #[error("runtime capability requirements are invalid: {0}")]
    Capability(#[from] BackendCapabilityViolation),
}

fn commit_plan(
    currentness: &RuntimeCurrentnessV1,
    capabilities: &RequiredBackendCapabilitiesV1,
    storage_root: ObjectDigest,
    attachment_set: ObjectDigest,
    network: ObjectDigest,
    runtime_profile: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RUNTIME_PLAN_DOMAIN);
    digest.update(currentness.sandbox().as_bytes());
    digest.update(currentness.incarnation().as_bytes());
    digest.update(currentness.node().as_bytes());
    digest.update(currentness.assignment_epoch().get().to_be_bytes());
    digest.update(currentness.assignment_digest().as_bytes());
    digest.update(currentness.desired_generation().get().to_be_bytes());
    digest.update(currentness.namespace_generation().get().to_be_bytes());
    digest.update((capabilities.as_slice().len() as u16).to_be_bytes());
    for capability in capabilities.as_slice() {
        digest.update([*capability as u8]);
    }
    digest.update(storage_root.as_bytes());
    digest.update(attachment_set.as_bytes());
    digest.update(network.as_bytes());
    digest.update(runtime_profile.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}
