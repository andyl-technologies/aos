//! Method-specific lifecycle intent, fences, expectations, and typed observations.

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, ExecutionId, IncarnationId, NamespaceGeneration, ProjectId,
    ResourceId, Revision, SandboxId, SnapshotId, ViewId,
};

use super::attempt::MAXIMUM_LIFECYCLE_ATTEMPTS;
use super::model::{
    DesiredStateCasDigestV1, DesiredStateDocumentDigestV1, LifecycleFailureDigestV1,
    LifecycleResourceStateDigestV1,
};
use super::projection::LifecycleModelError;

/// Stores a nonzero Unix timestamp in nanoseconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleTimeV1(u64);

impl LifecycleTimeV1 {
    /// Constructs a durable wall-clock timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for zero or MAX.
    pub const fn new(value: u64) -> Result<Self, LifecycleModelError> {
        if value == 0 || value == u64::MAX {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns Unix nanoseconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(super) const fn from_stored(value: u64) -> Result<Self, LifecycleModelError> {
        if value == 0 || value == u64::MAX {
            Err(LifecycleModelError::CorruptEncoding)
        } else {
            Ok(Self(value))
        }
    }
}

/// Fences one exact logical resource and desired-state generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DesiredStateFenceV1 {
    resource: LifecycleResourceV1,
    expected_generation: DesiredGeneration,
    resource_revision: Revision,
    resource_state: LifecycleResourceStateDigestV1,
}

impl DesiredStateFenceV1 {
    /// Constructs a complete desired-resource fence.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel identities,
    /// revisions, or desired generations.
    pub fn new(
        resource: LifecycleResourceV1,
        expected_generation: DesiredGeneration,
        resource_revision: Revision,
        resource_state: LifecycleResourceStateDigestV1,
    ) -> Result<Self, LifecycleModelError> {
        if resource.as_bytes() == &[0; 16]
            || expected_generation.get() == 0
            || expected_generation.get() == u64::MAX
            || resource_revision.get() == 0
            || resource_revision.get() == u64::MAX
        {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self {
                resource,
                expected_generation,
                resource_revision,
                resource_state,
            })
        }
    }

    /// Returns the exact logical resource being fenced.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }

    /// Returns the desired generation admission must compare.
    #[must_use]
    pub const fn expected_generation(self) -> DesiredGeneration {
        self.expected_generation
    }

    /// Returns the exact resource revision checked at admission.
    #[must_use]
    pub const fn resource_revision(self) -> Revision {
        self.resource_revision
    }

    /// Returns the exact resource-state commitment checked at admission.
    #[must_use]
    pub const fn resource_state(self) -> LifecycleResourceStateDigestV1 {
        self.resource_state
    }
}

/// Fences one method-specific target to an exact absent or present state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleTargetFenceV1 {
    resource: LifecycleResourceV1,
    expected_generation: DesiredGeneration,
    expected: ResourceExpectedStateV1,
}

impl LifecycleTargetFenceV1 {
    /// Constructs an exact typed target-state fence.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for a sentinel identity or
    /// present-state revision.
    pub fn new(
        resource: LifecycleResourceV1,
        expected_generation: DesiredGeneration,
        expected: ResourceExpectedStateV1,
    ) -> Result<Self, LifecycleModelError> {
        let valid_present = match expected {
            ResourceExpectedStateV1::Absent => expected_generation.get() == 0,
            ResourceExpectedStateV1::Present { revision, .. } => {
                expected_generation.get() != 0
                    && expected_generation.get() != u64::MAX
                    && revision.get() != 0
                    && revision.get() != u64::MAX
            }
        };
        if resource.as_bytes() == &[0; 16] || !valid_present {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self {
                resource,
                expected_generation,
                expected,
            })
        }
    }

    /// Returns the exact typed target identity.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }

    /// Returns the exact target desired-state generation.
    #[must_use]
    pub const fn expected_generation(self) -> DesiredGeneration {
        self.expected_generation
    }

    /// Returns the exact admitted target state.
    #[must_use]
    pub const fn expected(self) -> ResourceExpectedStateV1 {
        self.expected
    }
}

/// Fences an operation to one exact live runtime incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveRuntimeFenceV1 {
    sandbox: SandboxId,
    desired: DesiredStateFenceV1,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    namespace_generation: NamespaceGeneration,
}

impl LiveRuntimeFenceV1 {
    /// Constructs an exact desired, incarnation, assignment, and namespace fence.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for any sentinel value.
    pub fn new(
        sandbox: SandboxId,
        desired: DesiredStateFenceV1,
        incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
        namespace_generation: NamespaceGeneration,
    ) -> Result<Self, LifecycleModelError> {
        if sandbox.as_bytes() == &[0; 16]
            || desired.resource != LifecycleResourceV1::Sandbox(sandbox)
            || incarnation.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
            || assignment_epoch.get() == u64::MAX
            || namespace_generation.get() == 0
            || namespace_generation.get() == u64::MAX
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            sandbox,
            desired,
            incarnation,
            assignment_epoch,
            namespace_generation,
        })
    }

    /// Returns the sandbox owning the exact active runtime.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the desired-state fence.
    #[must_use]
    pub const fn desired(self) -> DesiredStateFenceV1 {
        self.desired
    }
    /// Returns the exact incarnation identity.
    #[must_use]
    pub const fn incarnation(self) -> IncarnationId {
        self.incarnation
    }
    /// Returns the exact assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(self) -> AssignmentEpoch {
        self.assignment_epoch
    }
    /// Returns the exact namespace generation.
    #[must_use]
    pub const fn namespace_generation(self) -> NamespaceGeneration {
        self.namespace_generation
    }
}

/// Selects a logical resource with a type-preserving identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LifecycleResourceV1 {
    /// A durable sandbox.
    Sandbox(SandboxId),
    /// One admitted execution.
    Execution(ExecutionId),
    /// One durable snapshot.
    Snapshot(SnapshotId),
    /// One filesystem view.
    View(ViewId),
    /// One sandbox filesystem attachment.
    Attachment(ResourceId),
    /// One delegated capability.
    Capability(ResourceId),
    /// One immutable environment generation identity.
    Environment(ResourceId),
    /// One sandbox project authority domain.
    Project(ProjectId),
    /// Another registered controller resource.
    Other(ResourceId),
}

impl LifecycleResourceV1 {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Sandbox(_) => 1,
            Self::Execution(_) => 2,
            Self::Snapshot(_) => 3,
            Self::View(_) => 4,
            Self::Attachment(_) => 5,
            Self::Capability(_) => 6,
            Self::Environment(_) => 7,
            Self::Project(_) => 8,
            Self::Other(_) => 9,
        }
    }

    pub(super) fn from_code(code: u8, bytes: [u8; 16]) -> Result<Self, LifecycleModelError> {
        let resource = match code {
            1 => Self::Sandbox(SandboxId::from_bytes(bytes)),
            2 => Self::Execution(ExecutionId::from_bytes(bytes)),
            3 => Self::Snapshot(SnapshotId::from_bytes(bytes)),
            4 => Self::View(ViewId::from_bytes(bytes)),
            5 => Self::Attachment(ResourceId::from_bytes(bytes)),
            6 => Self::Capability(ResourceId::from_bytes(bytes)),
            7 => Self::Environment(ResourceId::from_bytes(bytes)),
            8 => Self::Project(ProjectId::from_bytes(bytes)),
            9 => Self::Other(ResourceId::from_bytes(bytes)),
            _ => return Err(LifecycleModelError::CorruptEncoding),
        };
        if resource.as_bytes() == &[0; 16] {
            Err(LifecycleModelError::CorruptEncoding)
        } else {
            Ok(resource)
        }
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 16] {
        match self {
            Self::Sandbox(v) => v.as_bytes(),
            Self::Execution(v) => v.as_bytes(),
            Self::Snapshot(v) => v.as_bytes(),
            Self::View(v) => v.as_bytes(),
            Self::Attachment(v) | Self::Capability(v) | Self::Environment(v) | Self::Other(v) => {
                v.as_bytes()
            }
            Self::Project(v) => v.as_bytes(),
        }
    }
}

/// Retains one exact desired-state compare-and-swap and its commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DesiredStateCasV1 {
    resource: LifecycleResourceV1,
    expected_generation: DesiredGeneration,
    expected_state: Option<DesiredStateDocumentDigestV1>,
    successor_generation: DesiredGeneration,
    successor_state: DesiredStateDocumentDigestV1,
    digest: DesiredStateCasDigestV1,
}

impl DesiredStateCasV1 {
    /// Constructs a checked single-generation desired-state CAS.
    ///
    /// Generation zero is admitted only as the expected absence generation;
    /// the successor is always the exact checked next generation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel identities,
    /// MAX generations, or a successor other than the checked next generation.
    pub fn new(
        resource: LifecycleResourceV1,
        expected_generation: DesiredGeneration,
        expected_state: Option<DesiredStateDocumentDigestV1>,
        successor_generation: DesiredGeneration,
        successor_state: DesiredStateDocumentDigestV1,
    ) -> Result<Self, LifecycleModelError> {
        let expected = expected_generation.get();
        let successor = successor_generation.get();
        if resource.as_bytes() == &[0; 16]
            || expected == u64::MAX
            || successor == 0
            || successor == u64::MAX
            || expected.checked_add(1) != Some(successor)
            || (expected == 0) != expected_state.is_none()
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        let digest = desired_state_cas_digest(
            resource,
            expected_generation,
            expected_state,
            successor_generation,
            successor_state,
        );
        Ok(Self {
            resource,
            expected_generation,
            expected_state,
            successor_generation,
            successor_state,
            digest,
        })
    }

    /// Returns the exact typed resource being mutated.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }

    /// Returns the exact generation required before commit.
    #[must_use]
    pub const fn expected_generation(self) -> DesiredGeneration {
        self.expected_generation
    }

    /// Returns the exact predecessor desired-state document, or absence.
    #[must_use]
    pub const fn expected_state(self) -> Option<DesiredStateDocumentDigestV1> {
        self.expected_state
    }

    /// Returns the exact generation published at commit.
    #[must_use]
    pub const fn successor_generation(self) -> DesiredGeneration {
        self.successor_generation
    }

    /// Returns the canonical desired-state document commitment.
    #[must_use]
    pub const fn desired_state(self) -> DesiredStateDocumentDigestV1 {
        self.successor_state
    }

    /// Returns the commitment to the complete typed compare-and-swap.
    #[must_use]
    pub const fn digest(self) -> DesiredStateCasDigestV1 {
        self.digest
    }
}

fn desired_state_cas_digest(
    resource: LifecycleResourceV1,
    expected: DesiredGeneration,
    expected_state: Option<DesiredStateDocumentDigestV1>,
    successor: DesiredGeneration,
    successor_state: DesiredStateDocumentDigestV1,
) -> DesiredStateCasDigestV1 {
    let mut bytes = [0_u8; 98];
    bytes[0] = resource.code();
    bytes[1..17].copy_from_slice(resource.as_bytes());
    bytes[17..25].copy_from_slice(&expected.get().to_be_bytes());
    bytes[25] = u8::from(expected_state.is_some());
    bytes[26..58].copy_from_slice(
        expected_state
            .map_or(ObjectDigest::from_bytes([0; 32]), |digest| digest.digest())
            .as_bytes(),
    );
    bytes[58..66].copy_from_slice(&successor.get().to_be_bytes());
    bytes[66..98].copy_from_slice(successor_state.digest().as_bytes());
    DesiredStateCasDigestV1::commit(&bytes)
}

/// Selects whether admission expects a resource to exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceExpectedStateV1 {
    /// Requires no durable resource under the identity.
    Absent,
    /// Requires an exact durable revision and state digest.
    Present {
        /// Expected resource revision.
        revision: Revision,
        /// Commitment to expected durable state.
        state_digest: LifecycleResourceStateDigestV1,
    },
}

/// Fences one logical resource used by an operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceExpectationV1 {
    resource: LifecycleResourceV1,
    expected: ResourceExpectedStateV1,
}

impl ResourceExpectationV1 {
    /// Requires the identity to be absent.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for a sentinel identity.
    pub fn absent(resource: LifecycleResourceV1) -> Result<Self, LifecycleModelError> {
        Self::new(resource, ResourceExpectedStateV1::Absent)
    }

    /// Requires an exact nonzero revision and state digest.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel fields.
    pub fn present(
        resource: LifecycleResourceV1,
        revision: Revision,
        state_digest: LifecycleResourceStateDigestV1,
    ) -> Result<Self, LifecycleModelError> {
        Self::new(
            resource,
            ResourceExpectedStateV1::Present {
                revision,
                state_digest,
            },
        )
    }

    fn new(
        resource: LifecycleResourceV1,
        expected: ResourceExpectedStateV1,
    ) -> Result<Self, LifecycleModelError> {
        let valid = match expected {
            ResourceExpectedStateV1::Absent => true,
            ResourceExpectedStateV1::Present {
                revision,
                state_digest,
            } => {
                revision.get() != 0
                    && revision.get() != u64::MAX
                    && state_digest.digest().as_bytes() != &[0; 32]
            }
        };
        if resource.as_bytes() == &[0; 16] || !valid {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self { resource, expected })
        }
    }

    /// Returns the typed resource identity.
    #[must_use]
    pub const fn resource(&self) -> LifecycleResourceV1 {
        self.resource
    }
    /// Returns the expected absence or exact present state.
    #[must_use]
    pub const fn expected(&self) -> ResourceExpectedStateV1 {
        self.expected
    }
}

/// Selects one closed RFC lifecycle operation with method-specific fencing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleIntentV1 {
    /// Creates a new absent sandbox.
    Create {
        /// New sandbox identity.
        sandbox: SandboxId,
    },
    /// Forks a committed snapshot into a new absent sandbox.
    Fork {
        /// Existing committed snapshot.
        source: SnapshotId,
        /// New sandbox identity.
        target: SandboxId,
    },
    /// Restores a committed snapshot into a new absent sandbox.
    Restore {
        /// Existing committed snapshot.
        snapshot: SnapshotId,
        /// New target sandbox.
        sandbox: SandboxId,
    },
    /// Selects a new immutable environment generation.
    UpdateEnvironment {
        /// Existing sandbox.
        sandbox: SandboxId,
        /// Immutable environment generation selected for admission.
        environment_generation: Revision,
        /// Expected desired-state generation.
        fence: DesiredStateFenceV1,
    },
    /// Publishes a newly resolved sandbox policy.
    UpdatePolicy {
        /// Existing sandbox.
        sandbox: SandboxId,
        /// Expected desired-state generation.
        fence: DesiredStateFenceV1,
    },
    /// Starts a stopped sandbox under a desired-state fence.
    Start {
        /// Existing stopped sandbox.
        sandbox: SandboxId,
        /// Expected desired-state generation.
        fence: DesiredStateFenceV1,
    },
    /// Stops one exact live incarnation.
    Stop {
        /// Existing running sandbox.
        sandbox: SandboxId,
        /// Exact live-runtime fence.
        fence: LiveRuntimeFenceV1,
    },
    /// Memory-suspends one exact live incarnation.
    SuspendMemory {
        /// Existing running sandbox.
        sandbox: SandboxId,
        /// Exact live-runtime fence.
        fence: LiveRuntimeFenceV1,
    },
    /// Resumes a memory-suspended or hibernated sandbox.
    Resume {
        /// Existing suspended sandbox.
        sandbox: SandboxId,
        /// Exact resume source and its method-specific fence.
        source: LifecycleResumeSourceV1,
    },
    /// Snapshots and releases one exact live incarnation.
    Hibernate {
        /// Existing running sandbox.
        sandbox: SandboxId,
        /// New hibernation snapshot.
        snapshot: SnapshotId,
        /// Exact live-runtime fence.
        fence: LiveRuntimeFenceV1,
        /// Exact absent snapshot target fence.
        target_fence: LifecycleTargetFenceV1,
    },
    /// Captures one exact live incarnation into a new snapshot.
    Snapshot {
        /// Existing running sandbox.
        sandbox: SandboxId,
        /// New snapshot identity.
        snapshot: SnapshotId,
        /// Exact live-runtime fence.
        fence: LiveRuntimeFenceV1,
        /// Exact absent snapshot target fence.
        target_fence: LifecycleTargetFenceV1,
    },
    /// Tombstones a sandbox graph under a desired-state fence.
    DeleteSandbox {
        /// Existing sandbox.
        sandbox: SandboxId,
        /// Expected desired-state generation.
        fence: DesiredStateFenceV1,
    },
    /// Releases one existing snapshot and retained dependencies.
    DeleteSnapshot {
        /// Existing snapshot.
        snapshot: SnapshotId,
        /// Exact present desired-state generation of the snapshot.
        fence: DesiredStateFenceV1,
    },
    /// Admits a new execution to one exact live sandbox runtime.
    CreateExecution {
        /// Existing running sandbox.
        sandbox: SandboxId,
        /// New execution identity.
        execution: ExecutionId,
        /// Exact live-runtime fence.
        fence: LiveRuntimeFenceV1,
        /// Exact absent execution target fence.
        target_fence: LifecycleTargetFenceV1,
    },
    /// Cancels one admitted execution under its exact runtime fence.
    CancelExecution {
        /// Existing execution.
        execution: ExecutionId,
        /// Exact live-runtime fence.
        fence: LiveRuntimeFenceV1,
        /// Exact present execution target fence.
        target_fence: LifecycleTargetFenceV1,
    },
    /// Creates a new immutable filesystem view.
    CreateView {
        /// New view identity.
        view: ViewId,
    },
    /// Attaches a view to one exact live namespace.
    AttachView {
        /// Existing running sandbox.
        sandbox: SandboxId,
        /// Existing immutable view.
        view: ViewId,
        /// New attachment identity.
        attachment: ResourceId,
        /// Exact live-runtime fence.
        fence: LiveRuntimeFenceV1,
        /// Exact absent attachment target fence.
        target_fence: LifecycleTargetFenceV1,
    },
    /// Replaces an attachment's selected immutable view.
    ReplaceAttachment {
        /// Existing attachment.
        attachment: ResourceId,
        /// Replacement immutable view.
        view: ViewId,
        /// Exact live-runtime fence.
        fence: LiveRuntimeFenceV1,
        /// Exact present attachment target fence.
        target_fence: LifecycleTargetFenceV1,
    },
    /// Detaches one attachment from an exact live namespace.
    DetachView {
        /// Existing attachment.
        attachment: ResourceId,
        /// Exact live-runtime fence.
        fence: LiveRuntimeFenceV1,
        /// Exact present attachment target fence.
        target_fence: LifecycleTargetFenceV1,
    },
    /// Releases one immutable view under its desired-state fence.
    ReleaseView {
        /// Existing view.
        view: ViewId,
        /// Expected desired-state generation.
        fence: DesiredStateFenceV1,
    },
    /// Attenuates an existing capability into a new child capability.
    AttenuateCapability {
        /// Existing parent capability.
        parent: ResourceId,
        /// New child capability.
        child: ResourceId,
    },
    /// Renews one capability under its desired-state fence.
    RenewCapability {
        /// Existing capability.
        capability: ResourceId,
        /// Expected desired-state generation.
        fence: DesiredStateFenceV1,
    },
    /// Revokes one capability under its desired-state fence.
    RevokeCapability {
        /// Existing capability.
        capability: ResourceId,
        /// Expected desired-state generation.
        fence: DesiredStateFenceV1,
    },
}

/// Selects the exact durable source and fence used to resume a sandbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleResumeSourceV1 {
    /// Resumes the exact still-live memory-suspended incarnation.
    Memory {
        /// Exact live-runtime fence retained across memory suspension.
        fence: LiveRuntimeFenceV1,
    },
    /// Restores a committed hibernation snapshot under a desired-state fence.
    Hibernated {
        /// Existing committed hibernation snapshot.
        snapshot: SnapshotId,
        /// Expected desired-state generation.
        fence: DesiredStateFenceV1,
    },
}

/// Names the closed lifecycle intent variant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleMethodV1 {
    /// Creates a sandbox.
    Create = 1,
    /// Forks a snapshot.
    Fork = 2,
    /// Restores a snapshot.
    Restore = 3,
    /// Updates an environment generation.
    UpdateEnvironment = 4,
    /// Starts a sandbox.
    Start = 5,
    /// Stops a sandbox.
    Stop = 6,
    /// Memory-suspends a sandbox.
    SuspendMemory = 7,
    /// Resumes a memory-suspended or hibernated sandbox.
    Resume = 8,
    /// Hibernates a sandbox.
    Hibernate = 9,
    /// Captures a snapshot.
    Snapshot = 10,
    /// Deletes a sandbox.
    DeleteSandbox = 11,
    /// Deletes a snapshot.
    DeleteSnapshot = 12,
    /// Updates resolved sandbox policy.
    UpdatePolicy = 13,
    /// Creates an execution.
    CreateExecution = 14,
    /// Cancels an execution.
    CancelExecution = 15,
    /// Creates a filesystem view.
    CreateView = 16,
    /// Attaches a filesystem view.
    AttachView = 17,
    /// Replaces a filesystem attachment.
    ReplaceAttachment = 18,
    /// Detaches a filesystem view.
    DetachView = 19,
    /// Releases a filesystem view.
    ReleaseView = 20,
    /// Attenuates a capability.
    AttenuateCapability = 21,
    /// Renews a capability.
    RenewCapability = 22,
    /// Revokes a capability.
    RevokeCapability = 23,
}

impl LifecycleIntentV1 {
    /// Returns the closed method discriminator.
    #[must_use]
    pub const fn method(&self) -> LifecycleMethodV1 {
        match self {
            Self::Create { .. } => LifecycleMethodV1::Create,
            Self::Fork { .. } => LifecycleMethodV1::Fork,
            Self::Restore { .. } => LifecycleMethodV1::Restore,
            Self::UpdateEnvironment { .. } => LifecycleMethodV1::UpdateEnvironment,
            Self::UpdatePolicy { .. } => LifecycleMethodV1::UpdatePolicy,
            Self::Start { .. } => LifecycleMethodV1::Start,
            Self::Stop { .. } => LifecycleMethodV1::Stop,
            Self::SuspendMemory { .. } => LifecycleMethodV1::SuspendMemory,
            Self::Resume { .. } => LifecycleMethodV1::Resume,
            Self::Hibernate { .. } => LifecycleMethodV1::Hibernate,
            Self::Snapshot { .. } => LifecycleMethodV1::Snapshot,
            Self::DeleteSandbox { .. } => LifecycleMethodV1::DeleteSandbox,
            Self::DeleteSnapshot { .. } => LifecycleMethodV1::DeleteSnapshot,
            Self::CreateExecution { .. } => LifecycleMethodV1::CreateExecution,
            Self::CancelExecution { .. } => LifecycleMethodV1::CancelExecution,
            Self::CreateView { .. } => LifecycleMethodV1::CreateView,
            Self::AttachView { .. } => LifecycleMethodV1::AttachView,
            Self::ReplaceAttachment { .. } => LifecycleMethodV1::ReplaceAttachment,
            Self::DetachView { .. } => LifecycleMethodV1::DetachView,
            Self::ReleaseView { .. } => LifecycleMethodV1::ReleaseView,
            Self::AttenuateCapability { .. } => LifecycleMethodV1::AttenuateCapability,
            Self::RenewCapability { .. } => LifecycleMethodV1::RenewCapability,
            Self::RevokeCapability { .. } => LifecycleMethodV1::RevokeCapability,
        }
    }
}

/// Classifies a step relative to semantic commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleStepClassV1 {
    /// Requires reverse compensation before semantic commit.
    PreCommitReversible = 1,
    /// Runs forward only after semantic commit.
    PostCommitForward = 2,
}

/// Identifies the future owner of a step without carrying authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleStepDomainV1 {
    /// Controller-only journal state.
    Controller = 1,
    /// Host runtime state.
    Host = 2,
    /// Storage catalog state.
    Storage = 3,
    /// Mount namespace state.
    Mount = 4,
    /// Network policy state.
    Network = 5,
    /// Immutable content state.
    Content = 6,
    /// Environment retention state.
    Environment = 7,
    /// Git repository or pack state.
    Git = 8,
    /// Guest quiesce state.
    Guest = 9,
}

/// Describes durable progress for one lifecycle step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleStepStateV1 {
    /// No attempt has been reserved.
    Planned = 1,
    /// A forward attempt is reserved or ambiguous.
    Applying = 2,
    /// Forward work has a retained result and inventory.
    Applied = 3,
    /// A compensation attempt is reserved or ambiguous.
    Compensating = 4,
    /// Compensation has a retained result and inventory.
    Compensated = 5,
    /// Retryable cleanup remains.
    Residual = 6,
    /// Automatic progress cannot proceed safely.
    PermanentlyBlocked = 7,
    /// A known failed forward attempt was abandoned by cancellation.
    Canceled = 8,
}

/// Classifies one failure without embedding mutable diagnostic text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleFailureClassV1 {
    /// An expectation no longer matches.
    Conflict = 1,
    /// Current authority cannot be acquired.
    AuthorityUnavailable = 2,
    /// Broker effect state is ambiguous.
    AmbiguousEffect = 3,
    /// A fixed resource or attempt ceiling was reached.
    Capacity = 4,
    /// A retained dependency prevents cleanup.
    DependencyHeld = 5,
    /// Durable state is corrupt.
    CorruptState = 6,
}

/// Retains a typed failure and purpose-specific diagnostic commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleFailureV1 {
    class: LifecycleFailureClassV1,
    detail: LifecycleFailureDigestV1,
    observed_at: LifecycleTimeV1,
}

impl LifecycleFailureV1 {
    /// Constructs a typed immutable failure observation.
    #[must_use]
    pub const fn new(
        class: LifecycleFailureClassV1,
        detail: LifecycleFailureDigestV1,
        observed_at: LifecycleTimeV1,
    ) -> Self {
        Self {
            class,
            detail,
            observed_at,
        }
    }
    /// Returns the failure class.
    #[must_use]
    pub const fn class(self) -> LifecycleFailureClassV1 {
        self.class
    }
    /// Returns the diagnostic commitment.
    #[must_use]
    pub const fn detail(self) -> LifecycleFailureDigestV1 {
        self.detail
    }
    /// Returns when failure was observed.
    #[must_use]
    pub const fn observed_at(self) -> LifecycleTimeV1 {
        self.observed_at
    }
}

/// Retains bounded retry scheduling independently of failure identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleRetryV1 {
    attempt: u32,
    not_before: LifecycleTimeV1,
}

impl LifecycleRetryV1 {
    /// Constructs a bounded retry schedule.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for an invalid attempt.
    pub const fn new(
        attempt: u32,
        not_before: LifecycleTimeV1,
    ) -> Result<Self, LifecycleModelError> {
        if attempt == 0 || attempt > MAXIMUM_LIFECYCLE_ATTEMPTS {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self {
                attempt,
                not_before,
            })
        }
    }
    /// Returns attempt number.
    #[must_use]
    pub const fn attempt(self) -> u32 {
        self.attempt
    }
    /// Returns earliest retry time.
    #[must_use]
    pub const fn not_before(self) -> LifecycleTimeV1 {
        self.not_before
    }
}
