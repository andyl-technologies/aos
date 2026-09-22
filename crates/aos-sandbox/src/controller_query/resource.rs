//! Checked internal views over the established `aos.sandbox.v1` resources.
//!
//! These wrappers do not define another serialized public schema. Successful
//! conversion retains the original generated protobuf value, whose existing
//! ProtoJSON implementation renders byte fields as base64 and enum fields by
//! their stable protobuf names.

use aos_proto::aos::sandbox::v1::{
    Condition, ConditionState, Operation, OperationPhase, ResourceReference, RetryClass, Sandbox,
    SandboxPhase,
};
use buffa::Message as _;

use super::model::{
    ClientStateItem, InvalidQueryModel, MAXIMUM_PUBLIC_RESOURCE_BYTES, OpaqueResponseBytesV1,
    OpaqueResponseKindV1,
};
use super::registry::{checked_timestamp, validate_descriptor_media, validate_features};

/// Maximum public conditions carried by one checked resource.
pub const MAXIMUM_RESOURCE_CONDITIONS: usize = 128;
/// Maximum result references carried by one operation.
pub const MAXIMUM_OPERATION_RESULTS: usize = 128;
/// Maximum UTF-8 bytes in one public safe message.
pub const MAXIMUM_SAFE_MESSAGE_BYTES: usize = 4 * 1024;
/// Maximum feature rows in one public condition.
pub const MAXIMUM_CONDITION_FEATURES: usize = 128;

/// Reports an invalid established public API resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidPublicResource {
    /// A required identity, version, nested resource, or generation is absent.
    #[error("public resource contains an unspecified field")]
    Unspecified,
    /// An open protobuf enum carries an unknown or unspecified value.
    #[error("public resource contains an unknown registry value")]
    UnknownRegistryValue,
    /// A public string is not in its closed registry or exceeds its byte bound.
    #[error("public resource contains an invalid registered code")]
    InvalidCode,
    /// A timestamp or progress value is invalid.
    #[error("public resource contains an invalid scalar value")]
    InvalidScalar,
    /// A bounded collection is oversized, unordered, or duplicated.
    #[error("public resource collection is not bounded and canonical")]
    CollectionNotCanonical,
    /// Placement fields or lifecycle state contradict one another.
    #[error("sandbox placement and lifecycle state are inconsistent")]
    InvalidPlacement,
    /// Terminal, retry, cancellation, result, or completion state is inconsistent.
    #[error("operation state is inconsistent")]
    InvalidOperationState,
    /// The encoded resource exceeds its checked byte ceiling.
    #[error("public resource exceeds its encoded byte ceiling")]
    ResourceTooLarge,
}

impl From<InvalidQueryModel> for InvalidPublicResource {
    fn from(value: InvalidQueryModel) -> Self {
        match value {
            InvalidQueryModel::ResourceTooLarge => Self::ResourceTooLarge,
            InvalidQueryModel::InvalidOpaqueValue
            | InvalidQueryModel::UnspecifiedCommitment
            | InvalidQueryModel::BindingMismatch
            | InvalidQueryModel::InvalidBindingEncoding => Self::Unspecified,
        }
    }
}

/// Identifies one closed public condition code.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PublicConditionCodeV1 {
    /// All required runtime and attachment enforcement is verified.
    Ready,
    /// Hard policy enforcement is verified.
    EnforcementReady,
    /// Requested filesystem-view attachments are verified.
    ViewsReady,
    /// The selected project environment is realized and pinned.
    EnvironmentReady,
    /// The sandbox has crossed its quiescence barrier.
    Quiesced,
    /// The sandbox is frozen.
    Frozen,
    /// An explicitly advisory feature is unavailable.
    Degraded,
    /// Reconciliation requires a dependency or operator action.
    Blocked,
    /// Lost authority has been contained.
    Fenced,
    /// Logical deletion completed with node-local cleanup remaining.
    ResidualState,
    /// Placement exists but ownership authority is not yet active.
    OwnershipPending,
}

impl PublicConditionCodeV1 {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "ready" => Some(Self::Ready),
            "enforcement-ready" => Some(Self::EnforcementReady),
            "views-ready" => Some(Self::ViewsReady),
            "environment-ready" => Some(Self::EnvironmentReady),
            "quiesced" => Some(Self::Quiesced),
            "frozen" => Some(Self::Frozen),
            "degraded" => Some(Self::Degraded),
            "blocked" => Some(Self::Blocked),
            "fenced" => Some(Self::Fenced),
            "residual-state" => Some(Self::ResidualState),
            "ownership-pending" => Some(Self::OwnershipPending),
            _ => None,
        }
    }
}

/// Identifies one closed public operation method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicOperationMethodV1 {
    /// Creates a sandbox.
    CreateSandbox = 0,
    /// Updates a sandbox policy.
    UpdatePolicy = 1,
    /// Starts a sandbox.
    StartSandbox = 2,
    /// Stops a sandbox.
    StopSandbox = 3,
    /// Suspends a sandbox.
    SuspendSandbox = 4,
    /// Resumes a sandbox.
    ResumeSandbox = 5,
    /// Deletes a sandbox.
    DeleteSandbox = 6,
    /// Creates an execution.
    CreateExecution = 7,
    /// Cancels an execution.
    CancelExecution = 8,
    /// Creates a filesystem view.
    CreateView = 9,
    /// Attaches a filesystem view.
    AttachView = 10,
    /// Replaces an attachment.
    ReplaceAttachment = 11,
    /// Detaches a filesystem view.
    DetachView = 12,
    /// Releases a filesystem view.
    ReleaseView = 13,
    /// Creates a snapshot.
    CreateSnapshot = 14,
    /// Restores a snapshot.
    RestoreSnapshot = 15,
    /// Forks a snapshot.
    ForkSnapshot = 16,
    /// Deletes a snapshot.
    DeleteSnapshot = 17,
    /// Renews a capability.
    RenewCapability = 18,
    /// Revokes a capability.
    RevokeCapability = 19,
    /// Requests cancellation of an accepted operation.
    CancelOperation = 20,
}

impl PublicOperationMethodV1 {
    const ALL: [Self; 21] = [
        Self::CreateSandbox,
        Self::UpdatePolicy,
        Self::StartSandbox,
        Self::StopSandbox,
        Self::SuspendSandbox,
        Self::ResumeSandbox,
        Self::DeleteSandbox,
        Self::CreateExecution,
        Self::CancelExecution,
        Self::CreateView,
        Self::AttachView,
        Self::ReplaceAttachment,
        Self::DetachView,
        Self::ReleaseView,
        Self::CreateSnapshot,
        Self::RestoreSnapshot,
        Self::ForkSnapshot,
        Self::DeleteSnapshot,
        Self::RenewCapability,
        Self::RevokeCapability,
        Self::CancelOperation,
    ];

    /// Returns the stable public registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateSandbox => "sandbox.create",
            Self::UpdatePolicy => "sandbox.update-policy",
            Self::StartSandbox => "sandbox.start",
            Self::StopSandbox => "sandbox.stop",
            Self::SuspendSandbox => "sandbox.suspend",
            Self::ResumeSandbox => "sandbox.resume",
            Self::DeleteSandbox => "sandbox.delete",
            Self::CreateExecution => "execution.create",
            Self::CancelExecution => "execution.cancel",
            Self::CreateView => "view.create",
            Self::AttachView => "view.attach",
            Self::ReplaceAttachment => "attachment.replace",
            Self::DetachView => "attachment.detach",
            Self::ReleaseView => "view.release",
            Self::CreateSnapshot => "snapshot.create",
            Self::RestoreSnapshot => "snapshot.restore",
            Self::ForkSnapshot => "snapshot.fork",
            Self::DeleteSnapshot => "snapshot.delete",
            Self::RenewCapability => "capability.renew",
            Self::RevokeCapability => "capability.revoke",
            Self::CancelOperation => "operation.cancel",
        }
    }

    pub(crate) const fn from_record_code(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CreateSandbox),
            1 => Some(Self::UpdatePolicy),
            2 => Some(Self::StartSandbox),
            3 => Some(Self::StopSandbox),
            4 => Some(Self::SuspendSandbox),
            5 => Some(Self::ResumeSandbox),
            6 => Some(Self::DeleteSandbox),
            7 => Some(Self::CreateExecution),
            8 => Some(Self::CancelExecution),
            9 => Some(Self::CreateView),
            10 => Some(Self::AttachView),
            11 => Some(Self::ReplaceAttachment),
            12 => Some(Self::DetachView),
            13 => Some(Self::ReleaseView),
            14 => Some(Self::CreateSnapshot),
            15 => Some(Self::RestoreSnapshot),
            16 => Some(Self::ForkSnapshot),
            17 => Some(Self::DeleteSnapshot),
            18 => Some(Self::RenewCapability),
            19 => Some(Self::RevokeCapability),
            20 => Some(Self::CancelOperation),
            _ => None,
        }
    }

    pub(crate) const fn record_code(self) -> u8 {
        self as u8
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|method| method.as_str() == value)
    }
}

/// Identifies one closed portable progress milestone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicMilestoneV1 {
    /// The durable operation was accepted.
    Accepted,
    /// Pre-commit resources are being prepared.
    Preparing,
    /// The operation is crossing its semantic commit boundary.
    Committing,
    /// Committed desired state is being reconciled.
    Reconciling,
    /// Residual resources are being cleaned up.
    Cleanup,
    /// Portable work is complete.
    Complete,
    /// Progress awaits a dependency or operator action.
    Blocked,
}

impl PublicMilestoneV1 {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "accepted" => Some(Self::Accepted),
            "preparing" => Some(Self::Preparing),
            "committing" => Some(Self::Committing),
            "reconciling" => Some(Self::Reconciling),
            "cleanup" => Some(Self::Cleanup),
            "complete" => Some(Self::Complete),
            "blocked" => Some(Self::Blocked),
            _ => None,
        }
    }
}

/// Identifies a closed public operation result resource type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PublicResourceTypeV1 {
    /// A sandbox resource.
    Sandbox,
    /// An execution resource.
    Execution,
    /// A snapshot resource.
    Snapshot,
    /// A filesystem-view resource.
    FilesystemView,
    /// An attachment resource.
    Attachment,
    /// A capability resource.
    Capability,
    /// An operation resource.
    Operation,
}

impl PublicResourceTypeV1 {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "sandbox" => Some(Self::Sandbox),
            "execution" => Some(Self::Execution),
            "snapshot" => Some(Self::Snapshot),
            "filesystem-view" => Some(Self::FilesystemView),
            "attachment" => Some(Self::Attachment),
            "capability" => Some(Self::Capability),
            "operation" => Some(Self::Operation),
            _ => None,
        }
    }
}

/// Stores a checked condition while retaining its exact public wire resource.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedConditionV1 {
    code: PublicConditionCodeV1,
    transition: (i64, u32),
    wire: Condition,
}

impl CheckedConditionV1 {
    /// Returns the closed condition code.
    #[must_use]
    pub const fn code(&self) -> PublicConditionCodeV1 {
        self.code
    }

    /// Returns the normalized transition timestamp.
    #[must_use]
    pub const fn transition(&self) -> (i64, u32) {
        self.transition
    }

    /// Returns the exact checked public condition.
    #[must_use]
    pub const fn as_proto(&self) -> &Condition {
        &self.wire
    }
}

/// Stores a checked operation result reference.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedResourceReferenceV1 {
    resource_type: PublicResourceTypeV1,
    resource_id: [u8; 16],
    wire: ResourceReference,
}

impl CheckedResourceReferenceV1 {
    /// Returns the closed resource type.
    #[must_use]
    pub const fn resource_type(&self) -> PublicResourceTypeV1 {
        self.resource_type
    }

    /// Returns the exact logical resource identity.
    #[must_use]
    pub const fn resource_id(&self) -> [u8; 16] {
        self.resource_id
    }

    /// Returns the checked public reference.
    #[must_use]
    pub const fn as_proto(&self) -> &ResourceReference {
        &self.wire
    }
}

/// Identifies a checked public operation phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckedOperationPhaseV1 {
    /// The operation is durably accepted.
    Accepted,
    /// The operation is preparing reversible resources.
    Preparing,
    /// The operation is entering its semantic commit point.
    Committing,
    /// The desired state is committed and reconciliation remains.
    Committed,
    /// The operation completed successfully.
    Succeeded,
    /// The operation failed before its semantic commit point.
    FailedBeforeCommit,
    /// Cancellation won before the semantic commit point.
    CanceledBeforeCommit,
    /// Desired state committed but residual cleanup remains.
    CommittedWithResidualCleanup,
    /// Reconciliation cannot progress without external intervention.
    PermanentlyBlocked,
}

impl CheckedOperationPhaseV1 {
    /// Reports whether no different later resource is valid.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::FailedBeforeCommit
                | Self::CanceledBeforeCommit
                | Self::CommittedWithResidualCleanup
                | Self::PermanentlyBlocked
        )
    }

    fn from_proto(value: OperationPhase) -> Result<Self, InvalidPublicResource> {
        match value {
            OperationPhase::OPERATION_PHASE_ACCEPTED => Ok(Self::Accepted),
            OperationPhase::OPERATION_PHASE_PREPARING => Ok(Self::Preparing),
            OperationPhase::OPERATION_PHASE_COMMITTING => Ok(Self::Committing),
            OperationPhase::OPERATION_PHASE_COMMITTED => Ok(Self::Committed),
            OperationPhase::OPERATION_PHASE_SUCCEEDED => Ok(Self::Succeeded),
            OperationPhase::OPERATION_PHASE_FAILED_BEFORE_COMMIT => Ok(Self::FailedBeforeCommit),
            OperationPhase::OPERATION_PHASE_CANCELED_BEFORE_COMMIT => {
                Ok(Self::CanceledBeforeCommit)
            }
            OperationPhase::OPERATION_PHASE_COMMITTED_WITH_RESIDUAL_CLEANUP => {
                Ok(Self::CommittedWithResidualCleanup)
            }
            OperationPhase::OPERATION_PHASE_PERMANENTLY_BLOCKED => Ok(Self::PermanentlyBlocked),
            OperationPhase::OPERATION_PHASE_UNSPECIFIED => {
                Err(InvalidPublicResource::UnknownRegistryValue)
            }
        }
    }
}

/// Reports whether a later poll may observe `next`, including skipped phases.
#[must_use]
pub fn operation_phase_can_follow(
    previous: CheckedOperationPhaseV1,
    next: CheckedOperationPhaseV1,
) -> bool {
    use CheckedOperationPhaseV1 as P;
    if previous == next {
        return true;
    }
    matches!(
        (previous, next),
        (P::Accepted, _)
            | (
                P::Preparing,
                P::Committing
                    | P::Committed
                    | P::Succeeded
                    | P::FailedBeforeCommit
                    | P::CanceledBeforeCommit
                    | P::CommittedWithResidualCleanup
                    | P::PermanentlyBlocked
            )
            | (
                P::Committing,
                P::Committed
                    | P::Succeeded
                    | P::FailedBeforeCommit
                    | P::CanceledBeforeCommit
                    | P::CommittedWithResidualCleanup
                    | P::PermanentlyBlocked
            )
            | (
                P::Committed,
                P::Succeeded | P::CommittedWithResidualCleanup | P::PermanentlyBlocked
            )
    )
}

/// Returns a monotone portable progress stage for a checked phase/milestone pair.
#[must_use]
pub const fn operation_progress_stage(
    phase: CheckedOperationPhaseV1,
    milestone: PublicMilestoneV1,
) -> u8 {
    use CheckedOperationPhaseV1 as P;
    use PublicMilestoneV1 as M;

    match milestone {
        M::Accepted => 0,
        M::Preparing => 1,
        M::Committing => 2,
        M::Reconciling => 3,
        M::Cleanup => 4,
        M::Complete => 5,
        M::Blocked => match phase {
            P::Accepted => 0,
            P::Preparing => 1,
            P::Committing => 2,
            P::Committed => 3,
            P::CommittedWithResidualCleanup => 4,
            P::PermanentlyBlocked
            | P::Succeeded
            | P::FailedBeforeCommit
            | P::CanceledBeforeCommit => 5,
        },
    }
}

/// Identifies checked retry advice ordered from permissive to terminal.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CheckedRetryClassV1 {
    /// Repeating the exact request may make progress.
    SameRequest,
    /// Retry requires an observed external state change.
    AfterStateChange,
    /// The client must obtain a fresh consistent baseline.
    ResyncRequired,
    /// Retrying cannot make progress.
    Never,
}

impl CheckedRetryClassV1 {
    fn from_proto(value: RetryClass) -> Result<Self, InvalidPublicResource> {
        match value {
            RetryClass::RETRY_CLASS_SAME_REQUEST => Ok(Self::SameRequest),
            RetryClass::RETRY_CLASS_AFTER_STATE_CHANGE => Ok(Self::AfterStateChange),
            RetryClass::RETRY_CLASS_RESYNC_REQUIRED => Ok(Self::ResyncRequired),
            RetryClass::RETRY_CLASS_NEVER => Ok(Self::Never),
            RetryClass::RETRY_CLASS_UNSPECIFIED => Err(InvalidPublicResource::UnknownRegistryValue),
        }
    }
}

/// Stores a fully checked established public operation resource.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedOperationResourceV1 {
    operation_id: [u8; 16],
    resource_version: OpaqueResponseBytesV1,
    method: PublicOperationMethodV1,
    phase: CheckedOperationPhaseV1,
    milestone: PublicMilestoneV1,
    progress: (u32, u32),
    retry: CheckedRetryClassV1,
    conditions: Vec<CheckedConditionV1>,
    results: Vec<CheckedResourceReferenceV1>,
    wire: Operation,
}

impl TryFrom<Operation> for CheckedOperationResourceV1 {
    type Error = InvalidPublicResource;

    fn try_from(wire: Operation) -> Result<Self, Self::Error> {
        validate_resource_size(&wire)?;
        let operation_id = exact_nonzero_id(&wire.operation_id)?;
        let resource_version = OpaqueResponseBytesV1::from_response(
            wire.resource_version.clone(),
            OpaqueResponseKindV1::ResourceVersion,
        )?;
        let method = PublicOperationMethodV1::parse(&wire.method)
            .ok_or(InvalidPublicResource::InvalidCode)?;
        let phase = CheckedOperationPhaseV1::from_proto(
            wire.phase
                .as_known()
                .ok_or(InvalidPublicResource::UnknownRegistryValue)?,
        )?;
        let retry = CheckedRetryClassV1::from_proto(
            wire.retry_class
                .as_known()
                .ok_or(InvalidPublicResource::UnknownRegistryValue)?,
        )?;
        if wire.accepted_generation == 0 {
            return Err(InvalidPublicResource::Unspecified);
        }
        exact_nonzero_id(&wire.audit_id)?;
        let progress = wire
            .progress
            .as_option()
            .ok_or(InvalidPublicResource::Unspecified)?;
        let milestone = PublicMilestoneV1::parse(&progress.milestone)
            .ok_or(InvalidPublicResource::InvalidCode)?;
        if progress.completed_units > progress.total_units {
            return Err(InvalidPublicResource::InvalidScalar);
        }
        let accepted_at = checked_timestamp(
            wire.accepted_at
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
        )?;
        let completed_at = wire
            .completed_at
            .as_option()
            .map(checked_timestamp)
            .transpose()?;
        if phase.is_terminal() != completed_at.is_some()
            || completed_at.is_some_and(|completed| completed < accepted_at)
            || ((phase.is_terminal() || phase == CheckedOperationPhaseV1::Committed)
                && wire.cancelable)
        {
            return Err(InvalidPublicResource::InvalidOperationState);
        }
        validate_operation_semantics(
            phase,
            milestone,
            retry,
            progress.completed_units,
            progress.total_units,
        )?;

        let conditions = checked_conditions(&wire.conditions)?;
        let results = checked_results(&wire.results)?;
        Ok(Self {
            operation_id,
            resource_version,
            method,
            phase,
            milestone,
            progress: (progress.completed_units, progress.total_units),
            retry,
            conditions,
            results,
            wire,
        })
    }
}

impl CheckedOperationResourceV1 {
    /// Returns the exact operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the checked opaque resource version.
    #[must_use]
    pub const fn resource_version(&self) -> &OpaqueResponseBytesV1 {
        &self.resource_version
    }

    /// Returns the closed public method.
    #[must_use]
    pub const fn method(&self) -> PublicOperationMethodV1 {
        self.method
    }

    /// Returns the checked public phase.
    #[must_use]
    pub const fn phase(&self) -> CheckedOperationPhaseV1 {
        self.phase
    }

    /// Returns the closed portable milestone.
    #[must_use]
    pub const fn milestone(&self) -> PublicMilestoneV1 {
        self.milestone
    }

    /// Returns completed and total progress units.
    #[must_use]
    pub const fn progress(&self) -> (u32, u32) {
        self.progress
    }

    /// Returns the ordered retry classification.
    #[must_use]
    pub const fn retry(&self) -> CheckedRetryClassV1 {
        self.retry
    }

    /// Returns whether cancellation can still win before commit.
    #[must_use]
    pub const fn cancelable(&self) -> bool {
        self.wire.cancelable
    }

    /// Returns checked conditions in canonical code order.
    #[must_use]
    pub fn conditions(&self) -> &[CheckedConditionV1] {
        &self.conditions
    }

    /// Returns checked result references in canonical resource order.
    #[must_use]
    pub fn results(&self) -> &[CheckedResourceReferenceV1] {
        &self.results
    }

    /// Returns the exact established protobuf resource for ProtoJSON rendering.
    #[must_use]
    pub const fn as_proto(&self) -> &Operation {
        &self.wire
    }

    /// Consumes the wrapper and returns the established protobuf resource.
    #[must_use]
    pub fn into_proto(self) -> Operation {
        self.wire
    }
}

impl ClientStateItem for CheckedOperationResourceV1 {
    fn encoded_byte_cost(&self) -> usize {
        self.wire.compute_size(&mut buffa::SizeCache::new()) as usize
    }
}

impl super::client_state_sealed::Sealed for CheckedOperationResourceV1 {}

/// Stores a fully checked established public sandbox resource.
#[derive(Clone, PartialEq)]
pub struct CheckedSandboxResourceV1 {
    sandbox_id: [u8; 16],
    desired_generation: u64,
    observation_sequence: u64,
    phase: SandboxPhase,
    placement: Option<CheckedPlacementV1>,
    conditions: Vec<CheckedConditionV1>,
    wire: Sandbox,
}

impl std::fmt::Debug for CheckedSandboxResourceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckedSandboxResourceV1")
            .field("sandbox_id", &"<redacted>")
            .field("desired_generation", &self.desired_generation)
            .field("observation_sequence", &self.observation_sequence)
            .field("phase", &self.phase)
            .field("placement", &self.placement)
            .field("conditions", &self.conditions.len())
            .finish_non_exhaustive()
    }
}

impl TryFrom<Sandbox> for CheckedSandboxResourceV1 {
    type Error = InvalidPublicResource;

    fn try_from(wire: Sandbox) -> Result<Self, Self::Error> {
        validate_resource_size(&wire)?;
        let sandbox_id = exact_nonzero_id(&wire.sandbox_id)?;
        exact_nonzero_id(&wire.project_id)?;
        if !wire.parent_sandbox_id.is_empty() {
            let parent = exact_nonzero_id(&wire.parent_sandbox_id)?;
            if parent == sandbox_id {
                return Err(InvalidPublicResource::InvalidPlacement);
            }
        }
        OpaqueResponseBytesV1::from_response(
            wire.resource_version.clone(),
            OpaqueResponseKindV1::ResourceVersion,
        )?;
        let desired = wire
            .desired
            .as_option()
            .ok_or(InvalidPublicResource::Unspecified)?;
        let observed = wire
            .observed
            .as_option()
            .ok_or(InvalidPublicResource::Unspecified)?;
        if desired.generation == 0
            || observed.desired_generation == 0
            || observed.observation_sequence == 0
            || observed.desired_generation > desired.generation
            || desired
                .lifecycle
                .as_known()
                .is_none_or(|value| value as i32 == 0)
        {
            return Err(InvalidPublicResource::Unspecified);
        }
        validate_descriptor_media(
            desired
                .specification
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
            "application/vnd.aos.sandbox.spec.v1+cbor",
        )?;
        validate_descriptor_media(
            desired
                .requested_policy
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
            "application/vnd.aos.sandbox.policy.v1+cbor",
        )?;
        let phase = observed
            .phase
            .as_known()
            .filter(|value| *value != SandboxPhase::SANDBOX_PHASE_UNSPECIFIED)
            .ok_or(InvalidPublicResource::UnknownRegistryValue)?;
        let placement = checked_placement(observed)?;
        if !phase_allows_placement(phase, placement.is_some()) {
            return Err(InvalidPublicResource::InvalidPlacement);
        }
        validate_descriptor_media(
            wire.effective_policy
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
            "application/vnd.aos.sandbox.policy.v1+cbor",
        )?;
        let created_at = checked_timestamp(
            wire.created_at
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
        )?;
        let updated_at = checked_timestamp(
            wire.updated_at
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
        )?;
        if updated_at < created_at {
            return Err(InvalidPublicResource::InvalidScalar);
        }
        let conditions = checked_conditions(&observed.conditions)?;
        Ok(Self {
            sandbox_id,
            desired_generation: observed.desired_generation,
            observation_sequence: observed.observation_sequence,
            phase,
            placement,
            conditions,
            wire,
        })
    }
}

impl CheckedSandboxResourceV1 {
    /// Returns the exact logical sandbox identity.
    #[must_use]
    pub const fn sandbox_id(&self) -> [u8; 16] {
        self.sandbox_id
    }

    /// Returns the desired generation correlated by this observation.
    #[must_use]
    pub const fn desired_generation(&self) -> u64 {
        self.desired_generation
    }

    /// Returns the producer-local monotone observation sequence.
    #[must_use]
    pub const fn observation_sequence(&self) -> u64 {
        self.observation_sequence
    }

    /// Returns the checked observed phase.
    #[must_use]
    pub const fn phase(&self) -> SandboxPhase {
        self.phase
    }

    /// Reports whether incarnation, node, and assignment epoch are all present.
    #[must_use]
    pub const fn has_placement(&self) -> bool {
        self.placement.is_some()
    }

    /// Returns the complete checked placement tuple, if assigned.
    #[must_use]
    pub const fn placement(&self) -> Option<&CheckedPlacementV1> {
        self.placement.as_ref()
    }

    /// Reports whether this resource carries the named public condition.
    #[must_use]
    pub fn has_condition(&self, code: PublicConditionCodeV1) -> bool {
        self.conditions
            .binary_search_by_key(&code, CheckedConditionV1::code)
            .is_ok()
    }

    /// Reports whether the named condition is explicitly true.
    #[must_use]
    pub fn has_true_condition(&self, code: PublicConditionCodeV1) -> bool {
        self.conditions
            .binary_search_by_key(&code, CheckedConditionV1::code)
            .ok()
            .is_some_and(|index| {
                self.conditions[index].wire.state.as_known()
                    == Some(ConditionState::CONDITION_STATE_TRUE)
            })
    }

    /// Returns checked conditions in canonical code order.
    #[must_use]
    pub fn conditions(&self) -> &[CheckedConditionV1] {
        &self.conditions
    }

    /// Returns the exact established protobuf resource for ProtoJSON rendering.
    #[must_use]
    pub const fn as_proto(&self) -> &Sandbox {
        &self.wire
    }

    /// Consumes the wrapper and returns the established protobuf resource.
    #[must_use]
    pub fn into_proto(self) -> Sandbox {
        self.wire
    }
}

impl ClientStateItem for CheckedSandboxResourceV1 {
    fn encoded_byte_cost(&self) -> usize {
        self.wire.compute_size(&mut buffa::SizeCache::new()) as usize
    }
}

impl super::client_state_sealed::Sealed for CheckedSandboxResourceV1 {}

pub(crate) fn checked_conditions(
    source: &[Condition],
) -> Result<Vec<CheckedConditionV1>, InvalidPublicResource> {
    if source.len() > MAXIMUM_RESOURCE_CONDITIONS {
        return Err(InvalidPublicResource::CollectionNotCanonical);
    }
    let mut conditions = Vec::with_capacity(source.len());
    for wire in source {
        let code =
            PublicConditionCodeV1::parse(&wire.code).ok_or(InvalidPublicResource::InvalidCode)?;
        if wire
            .state
            .as_known()
            .is_none_or(|value| value == ConditionState::CONDITION_STATE_UNSPECIFIED)
            || wire.safe_message.len() > MAXIMUM_SAFE_MESSAGE_BYTES
            || wire.safe_message.chars().any(char::is_control)
            || wire.unsatisfied_features.len() > MAXIMUM_CONDITION_FEATURES
        {
            return Err(InvalidPublicResource::InvalidScalar);
        }
        validate_features(&wire.unsatisfied_features)?;
        let transition = checked_timestamp(
            wire.transition_time
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
        )?;
        conditions.push(CheckedConditionV1 {
            code,
            transition,
            wire: wire.clone(),
        });
    }
    if !conditions
        .windows(2)
        .all(|pair| pair[0].code < pair[1].code)
    {
        return Err(InvalidPublicResource::CollectionNotCanonical);
    }
    Ok(conditions)
}

pub(crate) fn checked_results(
    source: &[ResourceReference],
) -> Result<Vec<CheckedResourceReferenceV1>, InvalidPublicResource> {
    if source.len() > MAXIMUM_OPERATION_RESULTS {
        return Err(InvalidPublicResource::CollectionNotCanonical);
    }
    let mut results = Vec::with_capacity(source.len());
    for wire in source {
        let resource_type = PublicResourceTypeV1::parse(&wire.resource_type)
            .ok_or(InvalidPublicResource::InvalidCode)?;
        let resource_id = exact_nonzero_id(&wire.resource_id)?;
        OpaqueResponseBytesV1::from_response(
            wire.resource_version.clone(),
            OpaqueResponseKindV1::ResourceVersion,
        )?;
        results.push(CheckedResourceReferenceV1 {
            resource_type,
            resource_id,
            wire: wire.clone(),
        });
    }
    if !results.windows(2).all(|pair| {
        (pair[0].resource_type, pair[0].resource_id) < (pair[1].resource_type, pair[1].resource_id)
    }) {
        return Err(InvalidPublicResource::CollectionNotCanonical);
    }
    Ok(results)
}

/// Stores a complete public placement tuple.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CheckedPlacementV1 {
    incarnation_id: [u8; 16],
    node_id: [u8; 16],
    assignment_epoch: u64,
}

impl CheckedPlacementV1 {
    /// Returns the sandbox incarnation identity.
    #[must_use]
    pub const fn incarnation_id(&self) -> [u8; 16] {
        self.incarnation_id
    }

    /// Returns the assigned node identity.
    #[must_use]
    pub const fn node_id(&self) -> [u8; 16] {
        self.node_id
    }

    /// Returns the assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }
}

impl std::fmt::Debug for CheckedPlacementV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckedPlacementV1")
            .field("incarnation_id", &"<redacted>")
            .field("node_id", &"<redacted>")
            .field("assignment_epoch", &self.assignment_epoch)
            .finish()
    }
}

fn checked_placement(
    observed: &aos_proto::aos::sandbox::v1::SandboxObservedState,
) -> Result<Option<CheckedPlacementV1>, InvalidPublicResource> {
    let none = observed.incarnation_id.is_empty()
        && observed.node_id.is_empty()
        && observed.assignment_epoch == 0;
    if none {
        return Ok(None);
    }

    let incarnation_id = exact_nonzero_id(&observed.incarnation_id)
        .map_err(|_| InvalidPublicResource::InvalidPlacement)?;
    let node_id =
        exact_nonzero_id(&observed.node_id).map_err(|_| InvalidPublicResource::InvalidPlacement)?;
    if observed.assignment_epoch == 0 {
        return Err(InvalidPublicResource::InvalidPlacement);
    }
    Ok(Some(CheckedPlacementV1 {
        incarnation_id,
        node_id,
        assignment_epoch: observed.assignment_epoch,
    }))
}

fn phase_allows_placement(phase: SandboxPhase, has_placement: bool) -> bool {
    use SandboxPhase as P;

    match phase {
        P::SANDBOX_PHASE_STARTING
        | P::SANDBOX_PHASE_READY
        | P::SANDBOX_PHASE_FREEZING
        | P::SANDBOX_PHASE_FROZEN
        | P::SANDBOX_PHASE_STOPPING
        | P::SANDBOX_PHASE_LOST => has_placement,
        P::SANDBOX_PHASE_STOPPED
        | P::SANDBOX_PHASE_HIBERNATED
        | P::SANDBOX_PHASE_DELETING
        | P::SANDBOX_PHASE_DELETED => !has_placement,
        P::SANDBOX_PHASE_REQUESTED | P::SANDBOX_PHASE_PREPARING | P::SANDBOX_PHASE_ERROR => true,
        P::SANDBOX_PHASE_UNSPECIFIED => false,
    }
}

fn validate_operation_semantics(
    phase: CheckedOperationPhaseV1,
    milestone: PublicMilestoneV1,
    retry: CheckedRetryClassV1,
    completed: u32,
    total: u32,
) -> Result<(), InvalidPublicResource> {
    use CheckedOperationPhaseV1 as P;
    use PublicMilestoneV1 as M;

    let milestone_matches = matches!(
        (phase, milestone),
        (P::Accepted, M::Accepted | M::Blocked)
            | (P::Preparing, M::Preparing | M::Blocked)
            | (P::Committing, M::Committing | M::Blocked)
            | (P::Committed, M::Reconciling | M::Cleanup | M::Blocked)
            | (P::Succeeded, M::Complete)
            | (P::FailedBeforeCommit | P::CanceledBeforeCommit, M::Complete)
            | (P::CommittedWithResidualCleanup, M::Cleanup | M::Complete)
            | (P::PermanentlyBlocked, M::Blocked)
    );
    if !milestone_matches
        || (phase.is_terminal() && retry != CheckedRetryClassV1::Never)
        || (milestone == M::Complete && completed != total)
    {
        Err(InvalidPublicResource::InvalidOperationState)
    } else {
        Ok(())
    }
}

pub(crate) fn exact_nonzero_id(value: &[u8]) -> Result<[u8; 16], InvalidPublicResource> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| InvalidPublicResource::Unspecified)?;
    if bytes == [0; 16] {
        Err(InvalidPublicResource::Unspecified)
    } else {
        Ok(bytes)
    }
}

pub(crate) fn validate_resource_size<T: buffa::Message>(
    value: &T,
) -> Result<(), InvalidPublicResource> {
    if value.compute_size(&mut buffa::SizeCache::new()) as usize > MAXIMUM_PUBLIC_RESOURCE_BYTES {
        Err(InvalidPublicResource::ResourceTooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PublicOperationMethodV1;

    #[test]
    fn public_operation_method_record_registry_round_trips() {
        for (code, method) in PublicOperationMethodV1::ALL.into_iter().enumerate() {
            assert_eq!(method.record_code() as usize, code);
            assert_eq!(
                PublicOperationMethodV1::from_record_code(method.record_code()),
                Some(method)
            );
            assert_eq!(
                PublicOperationMethodV1::parse(method.as_str()),
                Some(method)
            );
        }
        assert_eq!(PublicOperationMethodV1::from_record_code(21), None);
        assert_eq!(PublicOperationMethodV1::parse("sandbox.unknown"), None);
    }
}
