//! Lossless resolved public-request fences for mutating CLI commands.

use std::fmt;

use aos_proto::aos::sandbox::v1::{self as wire, ObjectDescriptor};
use sha2::{Digest as _, Sha256};

use super::execution::{
    CliIdentityV1, CreateExecutionCommandV1, ExecutionControlCommandV1, ExecutionIoContractV1,
    ExecutionProgramV1,
};
use super::grammar::{
    CliIdempotencyKeyV1, CliResourceVersionV1, CliWaitDurationV1, CliWaitV1, InvalidCliGrammar,
};
use crate::controller_query::portable::{
    CheckedFeatureSetV1, CheckedFilesystemViewDescriptorV1, CheckedObjectDescriptorV1,
    CheckedPolicyDescriptorV1, CheckedSandboxSpecificationV1,
};

/// States fields that must enter the public request proto before CLI activation.
pub const PUBLIC_REQUEST_INTEGRATION_REQUIRED: &str = "public request integration is source-complete; transport activation and qualification remain deliberately deferred";

/// Stores an action-specific authenticated public mutation fence.
#[derive(Clone, Debug, PartialEq)]
pub struct MutationFenceV1 {
    expected_resource_version: CliResourceVersionV1,
    kind: MutationFenceKindV1,
    operation_timeout: CliWaitDurationV1,
    required_features: CheckedFeatureSetV1,
    idempotency_key: CliIdempotencyKeyV1,
    client_wait: CliWaitV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationFenceKindV1 {
    Resource,
    Incarnation(CliIdentityV1),
    Plan(CliPlanDigestV1),
}

impl MutationFenceV1 {
    /// Constructs a resource-only fence inside an authenticated adapter.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resource(
        _provenance: &super::provenance::RequestProvenanceV1,
        expected_resource_version: CliResourceVersionV1,
        operation_timeout: CliWaitDurationV1,
        required_features: CheckedFeatureSetV1,
        idempotency_key: CliIdempotencyKeyV1,
        client_wait: CliWaitV1,
    ) -> Self {
        Self {
            expected_resource_version,
            kind: MutationFenceKindV1::Resource,
            operation_timeout,
            required_features,
            idempotency_key,
            client_wait,
        }
    }

    /// Constructs an incarnation-specific fence inside an authenticated adapter.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn incarnation(
        _provenance: &super::provenance::RequestProvenanceV1,
        expected_resource_version: CliResourceVersionV1,
        expected_incarnation: CliIdentityV1,
        operation_timeout: CliWaitDurationV1,
        required_features: CheckedFeatureSetV1,
        idempotency_key: CliIdempotencyKeyV1,
        client_wait: CliWaitV1,
    ) -> Self {
        Self {
            expected_resource_version,
            kind: MutationFenceKindV1::Incarnation(expected_incarnation),
            operation_timeout,
            required_features,
            idempotency_key,
            client_wait,
        }
    }

    /// Constructs a reviewed-plan fence inside an authenticated adapter.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan(
        _provenance: &super::provenance::RequestProvenanceV1,
        expected_resource_version: CliResourceVersionV1,
        expected_plan_digest: CliPlanDigestV1,
        operation_timeout: CliWaitDurationV1,
        required_features: CheckedFeatureSetV1,
        idempotency_key: CliIdempotencyKeyV1,
        client_wait: CliWaitV1,
    ) -> Self {
        Self {
            expected_resource_version,
            kind: MutationFenceKindV1::Plan(expected_plan_digest),
            operation_timeout,
            required_features,
            idempotency_key,
            client_wait,
        }
    }

    /// Returns local return-or-wait behavior.
    #[must_use]
    pub const fn client_wait(&self) -> CliWaitV1 {
        self.client_wait
    }

    /// Returns the exact resource-version fence to the request adapter.
    #[must_use]
    pub(crate) const fn expected_resource_version(&self) -> &CliResourceVersionV1 {
        &self.expected_resource_version
    }

    /// Returns the incarnation fence only for incarnation-specific actions.
    #[must_use]
    pub(crate) const fn expected_incarnation(&self) -> Option<&CliIdentityV1> {
        match &self.kind {
            MutationFenceKindV1::Incarnation(value) => Some(value),
            MutationFenceKindV1::Resource | MutationFenceKindV1::Plan(_) => None,
        }
    }

    /// Returns the reviewed-plan fence only for planned actions.
    #[must_use]
    pub(crate) const fn expected_plan(&self) -> Option<CliPlanDigestV1> {
        match self.kind {
            MutationFenceKindV1::Plan(value) => Some(value),
            MutationFenceKindV1::Resource | MutationFenceKindV1::Incarnation(_) => None,
        }
    }

    /// Returns the bounded server operation timeout.
    #[must_use]
    pub(crate) const fn operation_timeout(&self) -> CliWaitDurationV1 {
        self.operation_timeout
    }

    /// Returns the canonical required feature set.
    #[must_use]
    pub(crate) const fn required_features(&self) -> &CheckedFeatureSetV1 {
        &self.required_features
    }

    /// Returns the idempotency key to the authenticated request adapter.
    #[must_use]
    pub(crate) const fn idempotency_key(&self) -> &CliIdempotencyKeyV1 {
        &self.idempotency_key
    }

    fn meets(&self, requirement: MutationFenceRequirementV1) -> bool {
        match (requirement, &self.kind) {
            (MutationFenceRequirementV1::Resource, MutationFenceKindV1::Resource)
            | (MutationFenceRequirementV1::Incarnation, MutationFenceKindV1::Incarnation(_)) => {
                true
            }
            (MutationFenceRequirementV1::Plan(expected), MutationFenceKindV1::Plan(actual)) => {
                expected == *actual
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationFenceRequirementV1 {
    Resource,
    Incarnation,
    Plan(CliPlanDigestV1),
}

macro_rules! define_digest {
    ($name:ident, $summary:literal) => {
        #[doc = $summary]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Checks an exact nonzero SHA-256 commitment.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidCliGrammar::InvalidOpaqueValue`] for the zero sentinel.
            pub fn new(value: [u8; 32]) -> Result<Self, InvalidCliGrammar> {
                if value == [0; 32] {
                    Err(InvalidCliGrammar::InvalidOpaqueValue)
                } else {
                    Ok(Self(value))
                }
            }

            /// Returns exact commitment bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

define_digest!(CliPlanDigestV1, "Stores an exact reviewed plan commitment.");
define_digest!(
    CliAttenuationDigestV1,
    "Stores the commitment to a canonical capability attenuation request."
);
define_digest!(
    CliChannelBindingDigestV1,
    "Stores the authenticated holder channel-binding commitment."
);

/// Models exact create-sandbox request fields after selector resolution.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedCreateSandboxV1 {
    /// Names the target project.
    pub project_id: CliIdentityV1,
    /// Selects a root or an exactly fenced parent.
    pub parent: OptionalParentFenceV1,
    /// Fences the target project.
    pub expected_project_version: CliResourceVersionV1,
    /// Supplies the checked specification descriptor.
    pub specification: CheckedSandboxSpecificationV1,
    /// Supplies the checked requested-policy descriptor.
    pub requested_policy: CheckedPolicyDescriptorV1,
    /// Supplies idempotency.
    pub idempotency_key: CliIdempotencyKeyV1,
    /// Supplies bounded server operation time.
    pub operation_timeout: CliWaitDurationV1,
    /// Declares canonical required features.
    pub required_features: CheckedFeatureSetV1,
    /// Selects independent local return-or-wait behavior.
    pub client_wait: CliWaitV1,
}

/// Selects root creation or a parent with its inseparable version fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OptionalParentFenceV1 {
    /// Creates a project root.
    Root,
    /// Creates beneath this exact parent version.
    Child {
        /// Names the parent.
        parent_id: CliIdentityV1,
        /// Fences the parent version.
        expected_parent_version: CliResourceVersionV1,
    },
}

/// Selects one closed sandbox lifecycle mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedLifecycleActionV1 {
    /// Starts the sandbox.
    Start,
    /// Stops the sandbox.
    Stop,
    /// Suspends the sandbox in memory.
    Suspend,
    /// Resumes an existing frozen incarnation.
    ResumeFrozen,
    /// Reconstructs a hibernated sandbox without an existing incarnation.
    ReconstructHibernated,
}

/// Selects one of the five registered filesystem-view mutation modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewMutationModeV1 {
    /// Exposes a read-only view.
    ReadOnly,
    /// Exposes a read-write view under its required exclusivity contract.
    ReadWrite,
    /// Exposes a private copy-on-write view.
    PrivateCow,
    /// Exposes append-only semantics.
    AppendOnly,
    /// Exposes the registered service-view semantics.
    Service,
}

/// Selects a reviewed single-resource or cascade delete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteScopeV1 {
    /// Deletes only the named sandbox.
    Single(CliPlanDigestV1),
    /// Applies the exact authorized post-order cascade plan.
    Cascade(CliPlanDigestV1),
}

impl DeleteScopeV1 {
    const fn expected_plan(self) -> CliPlanDigestV1 {
        match self {
            Self::Single(digest) | Self::Cascade(digest) => digest,
        }
    }
}

/// Selects requested portable snapshot availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedSnapshotAvailabilityV1 {
    /// Requires a self-contained portable snapshot.
    SelfContained,
    /// Permits explicitly recorded external dependencies.
    ExternalDependencies,
}

/// Models capability service commands without exposing bearer material in `Debug`.
#[derive(Clone, Debug, PartialEq)]
pub enum CapabilityCommandV1 {
    /// Attenuates a parent capability for an authenticated holder channel.
    Attenuate {
        /// Supplies the bearer handle only to the request adapter.
        parent_handle: CliCapabilityHandleV1,
        /// Commits canonical attenuation semantics.
        attenuation: CliAttenuationDigestV1,
        /// Binds the new holder.
        holder_channel: CliChannelBindingDigestV1,
        /// Fences the parent capability.
        expected_parent_version: CliResourceVersionV1,
        /// Supplies idempotency.
        idempotency_key: CliIdempotencyKeyV1,
    },
    /// Inspects a capability through its bearer handle.
    Inspect(CliCapabilityHandleV1),
    /// Renews a capability to a checked absolute expiry.
    Renew {
        /// Supplies the bearer handle.
        handle: CliCapabilityHandleV1,
        /// Supplies normalized Unix seconds and nanoseconds.
        requested_expiry: CliTimestampV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Revokes a capability by public identity.
    Revoke {
        /// Names the public capability.
        capability_id: CliIdentityV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
}

/// Stores bounded bearer capability bytes with redacted diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct CliCapabilityHandleV1(Vec<u8>);

impl CliCapabilityHandleV1 {
    /// Checks a bounded bearer handle.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidOpaqueValue`] for empty or oversized bytes.
    pub fn new(value: Vec<u8>) -> Result<Self, InvalidCliGrammar> {
        if value.is_empty() || value.len() > 64 * 1024 {
            Err(InvalidCliGrammar::InvalidOpaqueValue)
        } else {
            Ok(Self(value))
        }
    }

    /// Exposes bearer bytes only to an authorized request adapter.
    #[must_use]
    pub(crate) fn expose_to_request(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CliCapabilityHandleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliCapabilityHandleV1")
            .field("redacted_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Stores a normalized protobuf-compatible timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliTimestampV1 {
    /// Unix seconds.
    seconds: i64,
    /// Fractional nanoseconds below one billion.
    nanoseconds: u32,
}

impl CliTimestampV1 {
    /// Checks the protobuf timestamp range.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidBound`] outside the normalized range.
    pub const fn new(seconds: i64, nanoseconds: u32) -> Result<Self, InvalidCliGrammar> {
        if seconds < -62_135_596_800 || seconds > 253_402_300_799 || nanoseconds >= 1_000_000_000 {
            Err(InvalidCliGrammar::InvalidBound)
        } else {
            Ok(Self {
                seconds,
                nanoseconds,
            })
        }
    }

    /// Returns normalized Unix seconds.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns normalized fractional nanoseconds.
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}

/// Enumerates resolved effectful public requests with every concurrency fence.
#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedPublicMutationV1 {
    /// Creates a sandbox.
    CreateSandbox(ResolvedCreateSandboxV1),
    /// Updates policy using the reviewed plan digest.
    UpdatePolicy {
        /// Names the sandbox.
        sandbox_id: CliIdentityV1,
        /// Supplies the requested policy.
        requested_policy: CheckedPolicyDescriptorV1,
        /// Commits the reviewed plan.
        expected_plan: CliPlanDigestV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Changes lifecycle state.
    Lifecycle {
        /// Names the sandbox.
        sandbox_id: CliIdentityV1,
        /// Selects the transition.
        action: ResolvedLifecycleActionV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Deletes one sandbox or an exact reviewed subtree.
    DeleteSandbox {
        /// Names the deletion root.
        sandbox_id: CliIdentityV1,
        /// Selects single or cascade plan semantics.
        scope: DeleteScopeV1,
        /// Stops for hard revocation before cleanup without bypassing safety.
        force: bool,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Creates an execution with lossless execution semantics.
    CreateExecution(CreateExecutionCommandV1),
    /// Controls an existing execution.
    ExecutionControl(super::execution::ExecutionControlCommandV1),
    /// Cancels one accepted long-running operation.
    CancelOperation {
        /// Names the operation.
        operation_id: CliIdentityV1,
        /// Supplies the exact resource-only operation fence.
        mutation: MutationFenceV1,
    },
    /// Creates a filesystem view from an exact revision.
    CreateView {
        /// Names and fences the target project.
        project_id: CliIdentityV1,
        /// Supplies the exact portable revision.
        revision: CheckedFilesystemViewDescriptorV1,
        /// Fences the target project.
        expected_project_version: CliResourceVersionV1,
        /// Supplies idempotency.
        idempotency_key: CliIdempotencyKeyV1,
        /// Bounds server-side operation behavior.
        operation_timeout: CliWaitDurationV1,
        /// Declares canonical required features.
        required_features: CheckedFeatureSetV1,
        /// Selects independent local return-or-wait behavior.
        client_wait: CliWaitV1,
    },
    /// Attaches a view using one closed mutation mode.
    AttachView {
        /// Names the sandbox.
        sandbox_id: CliIdentityV1,
        /// Names the view.
        view_id: CliIdentityV1,
        /// Fences the exact view revision.
        view_revision: CheckedFilesystemViewDescriptorV1,
        /// Names the normalized destination slot.
        destination_slot_id: CliIdentityV1,
        /// Selects one registered mutation mode.
        mode: ViewMutationModeV1,
        /// Denies execution through this attachment independently of write mode.
        noexec: bool,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Atomically replaces an attachment.
    ReplaceAttachment {
        /// Names the attachment.
        attachment_id: CliIdentityV1,
        /// Names the replacement view.
        new_view_id: CliIdentityV1,
        /// Fences its exact portable revision.
        new_view_revision: CheckedFilesystemViewDescriptorV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Detaches an attachment.
    DetachView {
        /// Names the attachment.
        attachment_id: CliIdentityV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Releases a view.
    ReleaseView {
        /// Names the view.
        view_id: CliIdentityV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Creates a snapshot.
    CreateSnapshot {
        /// Names the source sandbox.
        sandbox_id: CliIdentityV1,
        /// Selects the requested availability contract.
        availability: RequestedSnapshotAvailabilityV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Restores a snapshot into a new caller-selected sandbox identity.
    RestoreSnapshot {
        /// Names the snapshot.
        snapshot_id: CliIdentityV1,
        /// Names the target sandbox.
        target_sandbox_id: CliIdentityV1,
        /// Supplies the requested policy.
        requested_policy: CheckedPolicyDescriptorV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Deletes a snapshot.
    DeleteSnapshot {
        /// Names the snapshot.
        snapshot_id: CliIdentityV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Forks a snapshot into a new sandbox.
    ForkSnapshot {
        /// Names the source snapshot.
        snapshot_id: CliIdentityV1,
        /// Names and fences the target project.
        target_project_id: CliIdentityV1,
        /// Fences the target project independently of an optional parent.
        expected_project_version: CliResourceVersionV1,
        /// Selects root creation or an exactly fenced parent.
        parent: OptionalParentFenceV1,
        /// Supplies the requested policy.
        requested_policy: CheckedPolicyDescriptorV1,
        /// Supplies idempotency.
        idempotency_key: CliIdempotencyKeyV1,
        /// Bounds server-side operation behavior.
        operation_timeout: CliWaitDurationV1,
        /// Declares canonical required features.
        required_features: CheckedFeatureSetV1,
        /// Selects independent local return-or-wait behavior.
        client_wait: CliWaitV1,
    },
    /// Pins one exact public object in its authorized cache domain.
    CachePin {
        /// Supplies the exact object descriptor.
        object: CheckedObjectDescriptorV1,
        /// Identifies the view holding the dependency.
        view: CliIdentityV1,
        /// Identifies an attached consumer when one exists.
        attachment: Option<CliIdentityV1>,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Removes one exact public object pin without invalidating active leases.
    CacheUnpin {
        /// Supplies the exact object descriptor.
        object: CheckedObjectDescriptorV1,
        /// Identifies the view holding the dependency.
        view: CliIdentityV1,
        /// Identifies an attached consumer when one exists.
        attachment: Option<CliIdentityV1>,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Performs a capability action.
    Capability(CapabilityCommandV1),
}

/// Retains the exact established protobuf request and method-discriminating semantics.
#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedPublicMutationProtoV1 {
    /// Creates a sandbox.
    CreateSandbox(aos_proto::aos::sandbox::v1::CreateSandboxRequest),
    /// Updates sandbox policy.
    UpdatePolicy(aos_proto::aos::sandbox::v1::UpdateSandboxPolicyRequest),
    /// Applies the named lifecycle transition.
    Lifecycle {
        /// Selects the service method without encoding it as an open string.
        action: ResolvedLifecycleActionV1,
        /// Carries the common lifecycle request.
        request: aos_proto::aos::sandbox::v1::SandboxLifecycleRequest,
    },
    /// Deletes a sandbox.
    DeleteSandbox(aos_proto::aos::sandbox::v1::DeleteSandboxRequest),
    /// Creates an execution.
    CreateExecution(aos_proto::aos::sandbox::v1::CreateExecutionRequest),
    /// Applies immediate execution control.
    ExecutionControl(aos_proto::aos::sandbox::v1::ExecutionControlRequest),
    /// Cancels an execution as an operation.
    CancelExecution(aos_proto::aos::sandbox::v1::CancelExecutionRequest),
    /// Cancels a long-running operation.
    CancelOperation(aos_proto::aos::sandbox::v1::CancelOperationRequest),
    /// Creates a filesystem view.
    CreateView(aos_proto::aos::sandbox::v1::CreateViewRequest),
    /// Attaches a filesystem view.
    AttachView(aos_proto::aos::sandbox::v1::AttachViewRequest),
    /// Replaces an attachment.
    ReplaceAttachment(aos_proto::aos::sandbox::v1::ReplaceAttachmentRequest),
    /// Detaches an attachment.
    DetachView(aos_proto::aos::sandbox::v1::DetachViewRequest),
    /// Releases a view.
    ReleaseView(aos_proto::aos::sandbox::v1::ReleaseViewRequest),
    /// Creates a snapshot.
    CreateSnapshot(aos_proto::aos::sandbox::v1::CreateSnapshotRequest),
    /// Restores a snapshot.
    RestoreSnapshot(aos_proto::aos::sandbox::v1::RestoreSnapshotRequest),
    /// Deletes a snapshot.
    DeleteSnapshot(aos_proto::aos::sandbox::v1::DeleteSnapshotRequest),
    /// Forks a snapshot.
    ForkSnapshot(aos_proto::aos::sandbox::v1::ForkSnapshotRequest),
    /// Pins a cache object.
    CachePin(aos_proto::aos::sandbox::v1::PinCacheObjectRequest),
    /// Unpins a cache object.
    CacheUnpin(aos_proto::aos::sandbox::v1::UnpinCacheObjectRequest),
    /// Applies a capability request.
    Capability(ResolvedCapabilityProtoV1),
}

/// Retains one closed capability protobuf request variant.
#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedCapabilityProtoV1 {
    /// Attenuates a capability.
    Attenuate(aos_proto::aos::sandbox::v1::AttenuateCapabilityRequest),
    /// Inspects a capability.
    Inspect(aos_proto::aos::sandbox::v1::InspectCapabilityRequest),
    /// Renews a capability.
    Renew(aos_proto::aos::sandbox::v1::RenewCapabilityRequest),
    /// Revokes a capability.
    Revoke(aos_proto::aos::sandbox::v1::RevokeCapabilityRequest),
}

impl ResolvedPublicMutationV1 {
    /// Converts every resolved mutation into its complete established protobuf request.
    #[must_use]
    pub fn to_proto(&self) -> ResolvedPublicMutationProtoV1 {
        use aos_proto::aos::sandbox::v1 as wire;

        match self {
            Self::CreateSandbox(value) => {
                let (parent_sandbox_id, expected_parent_resource_version) =
                    parent_proto(&value.parent);
                ResolvedPublicMutationProtoV1::CreateSandbox(wire::CreateSandboxRequest {
                    project_id: value.project_id.as_bytes().to_vec(),
                    parent_sandbox_id,
                    expected_parent_resource_version,
                    expected_project_resource_version: value
                        .expected_project_version
                        .as_bytes()
                        .to_vec(),
                    specification: value.specification.as_proto().clone().into(),
                    requested_policy: value.requested_policy.as_proto().clone().into(),
                    idempotency_key: value.idempotency_key.as_bytes().to_vec(),
                    operation_timeout: duration_proto(value.operation_timeout).into(),
                    required_features: value.required_features.as_slice().to_vec(),
                    ..Default::default()
                })
            }
            Self::UpdatePolicy {
                sandbox_id,
                requested_policy,
                expected_plan,
                mutation,
            } => ResolvedPublicMutationProtoV1::UpdatePolicy(wire::UpdateSandboxPolicyRequest {
                sandbox_id: sandbox_id.as_bytes().to_vec(),
                requested_policy: requested_policy.as_proto().clone().into(),
                expected_plan_digest: expected_plan.as_bytes().to_vec(),
                mutation: mutation_context_proto(mutation).into(),
                ..Default::default()
            }),
            Self::Lifecycle {
                sandbox_id,
                action,
                mutation,
            } => ResolvedPublicMutationProtoV1::Lifecycle {
                action: *action,
                request: wire::SandboxLifecycleRequest {
                    sandbox_id: sandbox_id.as_bytes().to_vec(),
                    mutation: mutation_context_proto(mutation).into(),
                    ..Default::default()
                },
            },
            Self::DeleteSandbox {
                sandbox_id,
                scope,
                force,
                mutation,
            } => ResolvedPublicMutationProtoV1::DeleteSandbox(wire::DeleteSandboxRequest {
                sandbox_id: sandbox_id.as_bytes().to_vec(),
                cascade: matches!(scope, DeleteScopeV1::Cascade(_)),
                expected_plan_digest: scope.expected_plan().as_bytes().to_vec(),
                mutation: mutation_context_proto(mutation).into(),
                force: *force,
                ..Default::default()
            }),
            Self::CreateExecution(value) => {
                let (arguments, sandbox_shell) = match &value.program {
                    ExecutionProgramV1::Direct(arguments) => {
                        (arguments.as_slice().to_vec(), Vec::new())
                    }
                    ExecutionProgramV1::SandboxShell(script) => {
                        (Vec::new(), script.as_bytes().to_vec())
                    }
                };
                let (
                    io_mode,
                    allocate_terminal,
                    terminal_rows,
                    terminal_columns,
                    detached_capture_bytes,
                ) = match value.io {
                    ExecutionIoContractV1::Stream => (1, false, 0, 0, 0),
                    ExecutionIoContractV1::Pty { initial_size } => (
                        2,
                        true,
                        u32::from(initial_size.rows()),
                        u32::from(initial_size.columns()),
                        0,
                    ),
                    ExecutionIoContractV1::Detached(limit) => (3, false, 0, 0, limit.bytes()),
                };
                ResolvedPublicMutationProtoV1::CreateExecution(wire::CreateExecutionRequest {
                    sandbox_id: value.sandbox_id.as_bytes().to_vec(),
                    command: wire::Command {
                        arguments,
                        environment: value
                            .environment
                            .as_slice()
                            .iter()
                            .map(|variable| wire::EnvironmentVariable {
                                name: variable.name().to_owned(),
                                value: variable.value().to_vec(),
                                ..Default::default()
                            })
                            .collect(),
                        working_directory: value
                            .working_directory
                            .as_ref()
                            .map_or_else(Vec::new, |directory| directory.as_bytes().to_vec()),
                        allocate_terminal,
                        sandbox_shell,
                        execution_timeout: duration_proto(value.execution_timeout).into(),
                        io_mode: io_mode.into(),
                        terminal_rows,
                        terminal_columns,
                        detached_capture_bytes,
                        stream_features: value.stream_features.as_slice().to_vec(),
                        ..Default::default()
                    }
                    .into(),
                    client_public_key: value.endpoint_proof.public_key().to_vec(),
                    proof_of_possession: value.endpoint_proof.proof().to_vec(),
                    mutation: execution_mutation_context_proto(&value.mutation).into(),
                    ..Default::default()
                })
            }
            Self::ExecutionControl(value) => match value {
                ExecutionControlCommandV1::Attach {
                    execution,
                    endpoint_proof,
                    mutation,
                } => {
                    ResolvedPublicMutationProtoV1::ExecutionControl(wire::ExecutionControlRequest {
                        execution_id: execution.as_bytes().to_vec(),
                        action: 1.into(),
                        client_public_key: endpoint_proof.public_key().to_vec(),
                        proof_of_possession: endpoint_proof.proof().to_vec(),
                        mutation: with_required_semantic_feature(
                            execution_mutation_context_proto(mutation),
                            crate::controller_query::EXECUTION_ATTACH_HOLDER_PROOF_FEATURE_V1,
                        )
                        .into(),
                        ..Default::default()
                    })
                }
                ExecutionControlCommandV1::Resize {
                    execution,
                    size,
                    mutation,
                } => {
                    ResolvedPublicMutationProtoV1::ExecutionControl(wire::ExecutionControlRequest {
                        execution_id: execution.as_bytes().to_vec(),
                        action: 2.into(),
                        terminal_rows: u32::from(size.rows()),
                        terminal_columns: u32::from(size.columns()),
                        mutation: execution_mutation_context_proto(mutation).into(),
                        ..Default::default()
                    })
                }
                ExecutionControlCommandV1::Signal {
                    execution,
                    signal,
                    mutation,
                } => {
                    ResolvedPublicMutationProtoV1::ExecutionControl(wire::ExecutionControlRequest {
                        execution_id: execution.as_bytes().to_vec(),
                        action: 3.into(),
                        signal: execution_signal_proto(*signal).into(),
                        mutation: execution_mutation_context_proto(mutation).into(),
                        ..Default::default()
                    })
                }
                ExecutionControlCommandV1::Cancel {
                    execution,
                    mutation,
                    ..
                } => ResolvedPublicMutationProtoV1::CancelExecution(wire::CancelExecutionRequest {
                    execution_id: execution.as_bytes().to_vec(),
                    mutation: execution_mutation_context_proto(mutation).into(),
                    ..Default::default()
                }),
            },
            Self::CancelOperation {
                operation_id,
                mutation,
            } => ResolvedPublicMutationProtoV1::CancelOperation(wire::CancelOperationRequest {
                operation_id: operation_id.as_bytes().to_vec(),
                mutation: mutation_context_proto(mutation).into(),
                ..Default::default()
            }),
            Self::CreateView {
                project_id,
                revision,
                expected_project_version,
                idempotency_key,
                operation_timeout,
                required_features,
                ..
            } => ResolvedPublicMutationProtoV1::CreateView(wire::CreateViewRequest {
                project_id: project_id.as_bytes().to_vec(),
                revision: revision.as_proto().clone().into(),
                expected_project_resource_version: expected_project_version.as_bytes().to_vec(),
                idempotency_key: idempotency_key.as_bytes().to_vec(),
                required_features: required_features.as_slice().to_vec(),
                operation_timeout: duration_proto(*operation_timeout).into(),
                ..Default::default()
            }),
            Self::AttachView {
                sandbox_id,
                view_id,
                view_revision,
                destination_slot_id,
                mode,
                noexec,
                mutation,
            } => ResolvedPublicMutationProtoV1::AttachView(wire::AttachViewRequest {
                sandbox_id: sandbox_id.as_bytes().to_vec(),
                view_id: view_id.as_bytes().to_vec(),
                view_revision: view_revision.as_proto().clone().into(),
                destination_slot_id: destination_slot_id.as_bytes().to_vec(),
                mutation_mode: (match mode {
                    ViewMutationModeV1::ReadOnly => 1,
                    ViewMutationModeV1::ReadWrite => 2,
                    ViewMutationModeV1::PrivateCow => 3,
                    ViewMutationModeV1::AppendOnly => 4,
                    ViewMutationModeV1::Service => 5,
                })
                .into(),
                mutation: mutation_context_proto(mutation).into(),
                noexec: *noexec,
                ..Default::default()
            }),
            Self::ReplaceAttachment {
                attachment_id,
                new_view_id,
                new_view_revision,
                mutation,
            } => ResolvedPublicMutationProtoV1::ReplaceAttachment(wire::ReplaceAttachmentRequest {
                attachment_id: attachment_id.as_bytes().to_vec(),
                new_view_id: new_view_id.as_bytes().to_vec(),
                new_view_revision: new_view_revision.as_proto().clone().into(),
                mutation: mutation_context_proto(mutation).into(),
                ..Default::default()
            }),
            Self::DetachView {
                attachment_id,
                mutation,
            } => ResolvedPublicMutationProtoV1::DetachView(wire::DetachViewRequest {
                attachment_id: attachment_id.as_bytes().to_vec(),
                mutation: mutation_context_proto(mutation).into(),
                ..Default::default()
            }),
            Self::ReleaseView { view_id, mutation } => {
                ResolvedPublicMutationProtoV1::ReleaseView(wire::ReleaseViewRequest {
                    view_id: view_id.as_bytes().to_vec(),
                    mutation: mutation_context_proto(mutation).into(),
                    ..Default::default()
                })
            }
            Self::CreateSnapshot {
                sandbox_id,
                availability,
                mutation,
            } => ResolvedPublicMutationProtoV1::CreateSnapshot(wire::CreateSnapshotRequest {
                sandbox_id: sandbox_id.as_bytes().to_vec(),
                requested_availability: (match availability {
                    RequestedSnapshotAvailabilityV1::SelfContained => 1,
                    RequestedSnapshotAvailabilityV1::ExternalDependencies => 2,
                })
                .into(),
                mutation: mutation_context_proto(mutation).into(),
                ..Default::default()
            }),
            Self::RestoreSnapshot {
                snapshot_id,
                target_sandbox_id,
                requested_policy,
                mutation,
            } => ResolvedPublicMutationProtoV1::RestoreSnapshot(wire::RestoreSnapshotRequest {
                snapshot_id: snapshot_id.as_bytes().to_vec(),
                target_sandbox_id: target_sandbox_id.as_bytes().to_vec(),
                requested_policy: requested_policy.as_proto().clone().into(),
                mutation: mutation_context_proto(mutation).into(),
                ..Default::default()
            }),
            Self::DeleteSnapshot {
                snapshot_id,
                mutation,
            } => ResolvedPublicMutationProtoV1::DeleteSnapshot(wire::DeleteSnapshotRequest {
                snapshot_id: snapshot_id.as_bytes().to_vec(),
                mutation: mutation_context_proto(mutation).into(),
                ..Default::default()
            }),
            Self::ForkSnapshot {
                snapshot_id,
                target_project_id,
                expected_project_version,
                parent,
                requested_policy,
                idempotency_key,
                operation_timeout,
                required_features,
                ..
            } => {
                let (parent_sandbox_id, expected_parent_resource_version) = parent_proto(parent);
                ResolvedPublicMutationProtoV1::ForkSnapshot(wire::ForkSnapshotRequest {
                    snapshot_id: snapshot_id.as_bytes().to_vec(),
                    target_project_id: target_project_id.as_bytes().to_vec(),
                    parent_sandbox_id,
                    expected_parent_resource_version,
                    requested_policy: requested_policy.as_proto().clone().into(),
                    idempotency_key: idempotency_key.as_bytes().to_vec(),
                    required_features: fork_snapshot_features(required_features),
                    expected_project_resource_version: expected_project_version.as_bytes().to_vec(),
                    operation_timeout: duration_proto(*operation_timeout).into(),
                    ..Default::default()
                })
            }
            Self::CachePin {
                object,
                view,
                attachment,
                mutation,
            } => ResolvedPublicMutationProtoV1::CachePin(wire::PinCacheObjectRequest {
                object: object.as_proto().clone().into(),
                mutation: with_required_semantic_feature(
                    mutation_context_proto(mutation),
                    crate::controller_query::CACHE_CONSUMER_PIN_FEATURE_V1,
                )
                .into(),
                view_id: view.as_bytes().to_vec(),
                attachment_id: attachment
                    .as_ref()
                    .map_or_else(Vec::new, |id| id.as_bytes().to_vec()),
                ..Default::default()
            }),
            Self::CacheUnpin {
                object,
                view,
                attachment,
                mutation,
            } => ResolvedPublicMutationProtoV1::CacheUnpin(wire::UnpinCacheObjectRequest {
                object: object.as_proto().clone().into(),
                mutation: with_required_semantic_feature(
                    mutation_context_proto(mutation),
                    crate::controller_query::CACHE_CONSUMER_PIN_FEATURE_V1,
                )
                .into(),
                view_id: view.as_bytes().to_vec(),
                attachment_id: attachment
                    .as_ref()
                    .map_or_else(Vec::new, |id| id.as_bytes().to_vec()),
                ..Default::default()
            }),
            Self::Capability(command) => ResolvedPublicMutationProtoV1::Capability(match command {
                CapabilityCommandV1::Attenuate {
                    parent_handle,
                    attenuation,
                    holder_channel,
                    expected_parent_version,
                    idempotency_key,
                } => ResolvedCapabilityProtoV1::Attenuate(wire::AttenuateCapabilityRequest {
                    parent_capability_handle: parent_handle.expose_to_request().to_vec(),
                    attenuation: attenuation.as_bytes().to_vec(),
                    holder_channel_binding: holder_channel.as_bytes().to_vec(),
                    idempotency_key: idempotency_key.as_bytes().to_vec(),
                    expected_parent_resource_version: expected_parent_version.as_bytes().to_vec(),
                    ..Default::default()
                }),
                CapabilityCommandV1::Inspect(handle) => {
                    ResolvedCapabilityProtoV1::Inspect(wire::InspectCapabilityRequest {
                        capability_handle: handle.expose_to_request().to_vec(),
                        ..Default::default()
                    })
                }
                CapabilityCommandV1::Renew {
                    handle,
                    requested_expiry,
                    mutation,
                } => ResolvedCapabilityProtoV1::Renew(wire::RenewCapabilityRequest {
                    capability_handle: handle.expose_to_request().to_vec(),
                    requested_expiry: wire::Timestamp {
                        seconds: requested_expiry.seconds(),
                        nanoseconds: requested_expiry.nanoseconds(),
                        ..Default::default()
                    }
                    .into(),
                    mutation: mutation_context_proto(mutation).into(),
                    ..Default::default()
                }),
                CapabilityCommandV1::Revoke {
                    capability_id,
                    mutation,
                } => ResolvedCapabilityProtoV1::Revoke(wire::RevokeCapabilityRequest {
                    capability_id: capability_id.as_bytes().to_vec(),
                    mutation: mutation_context_proto(mutation).into(),
                    ..Default::default()
                }),
            }),
        }
    }

    /// Converts a resolved create-view mutation to its established public request.
    #[must_use]
    pub fn create_view_proto(&self) -> Option<aos_proto::aos::sandbox::v1::CreateViewRequest> {
        let Self::CreateView {
            project_id,
            revision,
            expected_project_version,
            idempotency_key,
            operation_timeout,
            required_features,
            ..
        } = self
        else {
            return None;
        };
        Some(aos_proto::aos::sandbox::v1::CreateViewRequest {
            project_id: project_id.as_bytes().to_vec(),
            revision: revision.as_proto().clone().into(),
            expected_project_resource_version: expected_project_version.as_bytes().to_vec(),
            idempotency_key: idempotency_key.as_bytes().to_vec(),
            required_features: required_features.as_slice().to_vec(),
            operation_timeout: aos_proto::aos::sandbox::v1::Duration {
                nanoseconds: operation_timeout.as_nanos(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        })
    }

    /// Converts a resolved attach-view mutation to its established public request.
    #[must_use]
    pub fn attach_view_proto(&self) -> Option<aos_proto::aos::sandbox::v1::AttachViewRequest> {
        let Self::AttachView {
            sandbox_id,
            view_id,
            view_revision,
            destination_slot_id,
            mode,
            noexec,
            mutation,
        } = self
        else {
            return None;
        };
        Some(aos_proto::aos::sandbox::v1::AttachViewRequest {
            sandbox_id: sandbox_id.as_bytes().to_vec(),
            view_id: view_id.as_bytes().to_vec(),
            view_revision: view_revision.as_proto().clone().into(),
            destination_slot_id: destination_slot_id.as_bytes().to_vec(),
            mutation_mode: (match mode {
                ViewMutationModeV1::ReadOnly => 1,
                ViewMutationModeV1::ReadWrite => 2,
                ViewMutationModeV1::PrivateCow => 3,
                ViewMutationModeV1::AppendOnly => 4,
                ViewMutationModeV1::Service => 5,
            })
            .into(),
            mutation: mutation_context_proto(mutation).into(),
            noexec: *noexec,
            ..Default::default()
        })
    }

    /// Converts a resolved delete-sandbox mutation to its established public request.
    #[must_use]
    pub fn delete_sandbox_proto(
        &self,
    ) -> Option<aos_proto::aos::sandbox::v1::DeleteSandboxRequest> {
        let Self::DeleteSandbox {
            sandbox_id,
            scope,
            force,
            mutation,
        } = self
        else {
            return None;
        };
        Some(aos_proto::aos::sandbox::v1::DeleteSandboxRequest {
            sandbox_id: sandbox_id.as_bytes().to_vec(),
            cascade: matches!(scope, DeleteScopeV1::Cascade(_)),
            expected_plan_digest: scope.expected_plan().as_bytes().to_vec(),
            mutation: mutation_context_proto(mutation).into(),
            force: *force,
            ..Default::default()
        })
    }

    /// Converts a resolved fork-snapshot mutation to its established public request.
    #[must_use]
    pub fn fork_snapshot_proto(&self) -> Option<aos_proto::aos::sandbox::v1::ForkSnapshotRequest> {
        let Self::ForkSnapshot {
            snapshot_id,
            target_project_id,
            expected_project_version,
            parent,
            requested_policy,
            idempotency_key,
            operation_timeout,
            required_features,
            ..
        } = self
        else {
            return None;
        };
        let (parent_sandbox_id, expected_parent_resource_version) = match parent {
            OptionalParentFenceV1::Root => (Vec::new(), Vec::new()),
            OptionalParentFenceV1::Child {
                parent_id,
                expected_parent_version,
            } => (
                parent_id.as_bytes().to_vec(),
                expected_parent_version.as_bytes().to_vec(),
            ),
        };
        Some(aos_proto::aos::sandbox::v1::ForkSnapshotRequest {
            snapshot_id: snapshot_id.as_bytes().to_vec(),
            target_project_id: target_project_id.as_bytes().to_vec(),
            parent_sandbox_id,
            expected_parent_resource_version,
            requested_policy: requested_policy.as_proto().clone().into(),
            idempotency_key: idempotency_key.as_bytes().to_vec(),
            required_features: fork_snapshot_features(required_features),
            expected_project_resource_version: expected_project_version.as_bytes().to_vec(),
            operation_timeout: aos_proto::aos::sandbox::v1::Duration {
                nanoseconds: operation_timeout.as_nanos(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        })
    }

    /// Commits the exact mutation variant, resolved identities, and fences.
    ///
    /// This intentionally covers the authority-bearing projection rather than
    /// duplicating request-body semantics. It prevents a resolver from
    /// redirecting authenticated authority to another object, incarnation,
    /// plan, revision, idempotency scope, or concurrency fence.
    pub(crate) fn authority_binding(&self) -> aos_sandbox_core::ObjectDigest {
        let mut binding = MutationAuthorityBindingV1::new();

        match self {
            Self::CreateSandbox(value) => {
                binding.variant(0);
                binding.identity(&value.project_id);
                binding.parent(&value.parent);
                binding.bytes(value.expected_project_version.as_bytes());
                binding.descriptor(value.specification.as_proto());
                binding.descriptor(value.requested_policy.as_proto());
                binding.controls(
                    value.operation_timeout,
                    &value.required_features,
                    &value.idempotency_key,
                    value.client_wait,
                );
            }
            Self::UpdatePolicy {
                sandbox_id,
                requested_policy,
                expected_plan,
                mutation,
            } => {
                binding.variant(1);
                binding.identity(sandbox_id);
                binding.descriptor(requested_policy.as_proto());
                binding.bytes(expected_plan.as_bytes());
                binding.mutation_fence(mutation);
            }
            Self::Lifecycle {
                sandbox_id,
                action,
                mutation,
            } => {
                binding.variant(2);
                binding.identity(sandbox_id);
                binding.variant(match action {
                    ResolvedLifecycleActionV1::Start => 0,
                    ResolvedLifecycleActionV1::Stop => 1,
                    ResolvedLifecycleActionV1::Suspend => 2,
                    ResolvedLifecycleActionV1::ResumeFrozen => 3,
                    ResolvedLifecycleActionV1::ReconstructHibernated => 4,
                });
                binding.mutation_fence(mutation);
            }
            Self::DeleteSandbox {
                sandbox_id,
                scope,
                force,
                mutation,
            } => {
                binding.variant(3);
                binding.identity(sandbox_id);
                binding.variant(match scope {
                    DeleteScopeV1::Single(_) => 0,
                    DeleteScopeV1::Cascade(_) => 1,
                });
                binding.bytes(scope.expected_plan().as_bytes());
                binding.boolean(*force);
                binding.mutation_fence(mutation);
            }
            Self::CreateExecution(value) => {
                binding.variant(4);
                binding.identity(&value.sandbox_id);
                binding.execution_fence(&value.mutation);
                match &value.program {
                    ExecutionProgramV1::Direct(arguments) => {
                        binding.variant(0);
                        binding.byte_rows(arguments.as_slice());
                    }
                    ExecutionProgramV1::SandboxShell(script) => {
                        binding.variant(1);
                        binding.bytes(script.as_bytes());
                    }
                }
                binding
                    .0
                    .update((value.environment.as_slice().len() as u64).to_be_bytes());
                for variable in value.environment.as_slice() {
                    binding.bytes(variable.name().as_bytes());
                    binding.bytes(variable.value());
                }
                match &value.working_directory {
                    Some(directory) => {
                        binding.variant(1);
                        binding.bytes(directory.as_bytes());
                    }
                    None => binding.variant(0),
                }
                binding
                    .0
                    .update(value.execution_timeout.as_nanos().to_be_bytes());
                match value.io {
                    ExecutionIoContractV1::Stream => binding.variant(0),
                    ExecutionIoContractV1::Pty { initial_size } => {
                        binding.variant(1);
                        binding.0.update(initial_size.rows().to_be_bytes());
                        binding.0.update(initial_size.columns().to_be_bytes());
                    }
                    ExecutionIoContractV1::Detached(limit) => {
                        binding.variant(2);
                        binding.0.update(limit.bytes().to_be_bytes());
                    }
                }
                binding.features(&value.stream_features);
                binding.bytes(value.endpoint_proof.public_key());
                binding.bytes(value.endpoint_proof.proof());
            }
            Self::ExecutionControl(value) => {
                binding.variant(5);
                match value {
                    ExecutionControlCommandV1::Attach {
                        execution,
                        endpoint_proof,
                        mutation,
                    } => {
                        binding.variant(0);
                        binding.identity(execution);
                        binding.bytes(endpoint_proof.public_key());
                        binding.bytes(endpoint_proof.proof());
                        binding.execution_fence(mutation);
                    }
                    ExecutionControlCommandV1::Resize {
                        execution,
                        size,
                        mutation,
                    } => {
                        binding.variant(1);
                        binding.identity(execution);
                        binding.0.update(size.rows().to_be_bytes());
                        binding.0.update(size.columns().to_be_bytes());
                        binding.execution_fence(mutation);
                    }
                    ExecutionControlCommandV1::Signal {
                        execution,
                        signal,
                        mutation,
                    } => {
                        binding.variant(2);
                        binding.identity(execution);
                        binding.variant(signal.posix_number());
                        binding.execution_fence(mutation);
                    }
                    ExecutionControlCommandV1::Cancel {
                        execution,
                        sandbox_id,
                        mutation,
                    } => {
                        binding.variant(3);
                        binding.identity(execution);
                        binding.identity(sandbox_id);
                        binding.execution_fence(mutation);
                    }
                }
            }
            Self::CancelOperation {
                operation_id,
                mutation,
            } => {
                binding.variant(18);
                binding.identity(operation_id);
                binding.mutation_fence(mutation);
            }
            Self::CreateView {
                project_id,
                revision,
                expected_project_version,
                idempotency_key,
                operation_timeout,
                required_features,
                client_wait,
            } => {
                binding.variant(6);
                binding.identity(project_id);
                binding.descriptor(revision.as_proto());
                binding.bytes(expected_project_version.as_bytes());
                binding.controls(
                    *operation_timeout,
                    required_features,
                    idempotency_key,
                    *client_wait,
                );
            }
            Self::AttachView {
                sandbox_id,
                view_id,
                view_revision,
                destination_slot_id,
                mode,
                noexec,
                mutation,
            } => {
                binding.variant(7);
                binding.identity(sandbox_id);
                binding.identity(view_id);
                binding.descriptor(view_revision.as_proto());
                binding.identity(destination_slot_id);
                binding.variant(match mode {
                    ViewMutationModeV1::ReadOnly => 0,
                    ViewMutationModeV1::ReadWrite => 1,
                    ViewMutationModeV1::PrivateCow => 2,
                    ViewMutationModeV1::AppendOnly => 3,
                    ViewMutationModeV1::Service => 4,
                });
                binding.boolean(*noexec);
                binding.mutation_fence(mutation);
            }
            Self::ReplaceAttachment {
                attachment_id,
                new_view_id,
                new_view_revision,
                mutation,
            } => {
                binding.variant(8);
                binding.identity(attachment_id);
                binding.identity(new_view_id);
                binding.descriptor(new_view_revision.as_proto());
                binding.mutation_fence(mutation);
            }
            Self::DetachView {
                attachment_id,
                mutation,
            } => {
                binding.variant(9);
                binding.identity(attachment_id);
                binding.mutation_fence(mutation);
            }
            Self::ReleaseView { view_id, mutation } => {
                binding.variant(10);
                binding.identity(view_id);
                binding.mutation_fence(mutation);
            }
            Self::CreateSnapshot {
                sandbox_id,
                availability,
                mutation,
            } => {
                binding.variant(11);
                binding.identity(sandbox_id);
                binding.variant(match availability {
                    RequestedSnapshotAvailabilityV1::SelfContained => 0,
                    RequestedSnapshotAvailabilityV1::ExternalDependencies => 1,
                });
                binding.mutation_fence(mutation);
            }
            Self::RestoreSnapshot {
                snapshot_id,
                target_sandbox_id,
                requested_policy,
                mutation,
            } => {
                binding.variant(12);
                binding.identity(snapshot_id);
                binding.identity(target_sandbox_id);
                binding.descriptor(requested_policy.as_proto());
                binding.mutation_fence(mutation);
            }
            Self::DeleteSnapshot {
                snapshot_id,
                mutation,
            } => {
                binding.variant(13);
                binding.identity(snapshot_id);
                binding.mutation_fence(mutation);
            }
            Self::ForkSnapshot {
                snapshot_id,
                target_project_id,
                expected_project_version,
                parent,
                requested_policy,
                idempotency_key,
                operation_timeout,
                required_features,
                client_wait,
            } => {
                binding.variant(14);
                binding.identity(snapshot_id);
                binding.identity(target_project_id);
                binding.bytes(expected_project_version.as_bytes());
                binding.parent(parent);
                binding.descriptor(requested_policy.as_proto());
                binding.controls(
                    *operation_timeout,
                    required_features,
                    idempotency_key,
                    *client_wait,
                );
            }
            Self::CachePin {
                object,
                view,
                attachment,
                mutation,
            } => {
                binding.variant(15);
                binding.descriptor(object.as_proto());
                binding.identity(view);
                match attachment {
                    Some(attachment) => {
                        binding.variant(1);
                        binding.identity(attachment);
                    }
                    None => binding.variant(0),
                }
                binding.mutation_fence(mutation);
            }
            Self::CacheUnpin {
                object,
                view,
                attachment,
                mutation,
            } => {
                binding.variant(16);
                binding.descriptor(object.as_proto());
                binding.identity(view);
                match attachment {
                    Some(attachment) => {
                        binding.variant(1);
                        binding.identity(attachment);
                    }
                    None => binding.variant(0),
                }
                binding.mutation_fence(mutation);
            }
            Self::Capability(command) => {
                binding.variant(17);
                match command {
                    CapabilityCommandV1::Attenuate {
                        parent_handle,
                        attenuation,
                        holder_channel,
                        expected_parent_version,
                        idempotency_key,
                    } => {
                        binding.variant(0);
                        binding.bytes(parent_handle.expose_to_request());
                        binding.bytes(attenuation.as_bytes());
                        binding.bytes(holder_channel.as_bytes());
                        binding.bytes(expected_parent_version.as_bytes());
                        binding.bytes(idempotency_key.as_bytes());
                    }
                    CapabilityCommandV1::Inspect(handle) => {
                        binding.variant(1);
                        binding.bytes(handle.expose_to_request());
                    }
                    CapabilityCommandV1::Renew {
                        handle,
                        requested_expiry,
                        mutation,
                    } => {
                        binding.variant(2);
                        binding.bytes(handle.expose_to_request());
                        binding.0.update(requested_expiry.seconds().to_be_bytes());
                        binding
                            .0
                            .update(requested_expiry.nanoseconds().to_be_bytes());
                        binding.mutation_fence(mutation);
                    }
                    CapabilityCommandV1::Revoke {
                        capability_id,
                        mutation,
                    } => {
                        binding.variant(3);
                        binding.identity(capability_id);
                        binding.mutation_fence(mutation);
                    }
                }
            }
        }

        binding.finish()
    }

    /// Checks that each action carries exactly its required authenticated fence.
    pub(crate) fn has_action_specific_fences(&self) -> bool {
        use MutationFenceRequirementV1 as R;
        match self {
            Self::CreateSandbox(_)
            | Self::CreateView { .. }
            | Self::Capability(CapabilityCommandV1::Attenuate { .. })
            | Self::Capability(CapabilityCommandV1::Inspect(_)) => true,
            Self::ForkSnapshot {
                required_features, ..
            } => crate::controller_query::contains_semantic_features_v1(
                required_features.as_slice(),
                &[crate::controller_query::SNAPSHOT_PROJECT_VERSION_FENCE_FEATURE_V1],
            ),
            Self::CreateExecution(execution) => {
                let io_feature = match execution.io {
                    ExecutionIoContractV1::Stream => {
                        crate::controller_query::EXECUTION_STREAM_FEATURE_V1
                    }
                    ExecutionIoContractV1::Pty { .. } => {
                        crate::controller_query::EXECUTION_PTY_FEATURE_V1
                    }
                    ExecutionIoContractV1::Detached(_) => {
                        crate::controller_query::EXECUTION_DETACHED_CAPTURE_FEATURE_V1
                    }
                };
                let mut required = vec![
                    crate::controller_query::EXECUTION_TIMEOUT_FEATURE_V1,
                    io_feature,
                ];
                if matches!(&execution.program, ExecutionProgramV1::SandboxShell(_)) {
                    required.push(crate::controller_query::EXECUTION_SANDBOX_SHELL_FEATURE_V1);
                }
                crate::controller_query::contains_semantic_features_v1(
                    execution.mutation.required_features().as_slice(),
                    &required,
                ) && crate::controller_query::contains_semantic_features_v1(
                    execution.stream_features.as_slice(),
                    &[io_feature],
                )
            }
            Self::ExecutionControl(control) => match control {
                ExecutionControlCommandV1::Attach { mutation, .. }
                | ExecutionControlCommandV1::Resize { mutation, .. }
                | ExecutionControlCommandV1::Signal { mutation, .. }
                | ExecutionControlCommandV1::Cancel { mutation, .. } => {
                    mutation.expected_incarnation().as_bytes() != &[0; 16]
                }
            },
            Self::UpdatePolicy {
                expected_plan,
                mutation,
                ..
            } => mutation.meets(R::Plan(*expected_plan)),
            Self::Lifecycle {
                action, mutation, ..
            } => mutation.meets(match action {
                ResolvedLifecycleActionV1::Start
                | ResolvedLifecycleActionV1::ReconstructHibernated => R::Resource,
                ResolvedLifecycleActionV1::Stop
                | ResolvedLifecycleActionV1::Suspend
                | ResolvedLifecycleActionV1::ResumeFrozen => R::Incarnation,
            }),
            Self::DeleteSandbox {
                scope,
                force,
                mutation,
                ..
            } => {
                mutation.meets(R::Plan(scope.expected_plan()))
                    && (!*force
                        || crate::controller_query::contains_semantic_features_v1(
                            mutation.required_features().as_slice(),
                            &[crate::controller_query::FORCE_DELETE_FEATURE_V1],
                        ))
            }
            Self::AttachView {
                noexec, mutation, ..
            } => {
                mutation.meets(R::Incarnation)
                    && (!*noexec
                        || crate::controller_query::contains_semantic_features_v1(
                            mutation.required_features().as_slice(),
                            &[crate::controller_query::ATTACHMENT_NOEXEC_FEATURE_V1],
                        ))
            }
            Self::CreateSnapshot { mutation, .. } => mutation.meets(R::Incarnation),
            Self::ReplaceAttachment { mutation, .. }
            | Self::DetachView { mutation, .. }
            | Self::ReleaseView { mutation, .. }
            | Self::RestoreSnapshot { mutation, .. }
            | Self::DeleteSnapshot { mutation, .. }
            | Self::CancelOperation { mutation, .. }
            | Self::CachePin { mutation, .. }
            | Self::CacheUnpin { mutation, .. }
            | Self::Capability(CapabilityCommandV1::Renew { mutation, .. })
            | Self::Capability(CapabilityCommandV1::Revoke { mutation, .. }) => {
                mutation.meets(R::Resource)
            }
        }
    }

    /// Returns local wait behavior only for a command that actually carries it.
    #[must_use]
    pub fn client_wait(&self) -> Option<CliWaitV1> {
        match self {
            Self::CreateSandbox(value) => Some(value.client_wait),
            Self::CreateExecution(value) => Some(value.mutation.client_wait()),
            Self::UpdatePolicy { mutation, .. }
            | Self::Lifecycle { mutation, .. }
            | Self::DeleteSandbox { mutation, .. }
            | Self::AttachView { mutation, .. }
            | Self::ReplaceAttachment { mutation, .. }
            | Self::DetachView { mutation, .. }
            | Self::ReleaseView { mutation, .. }
            | Self::CreateSnapshot { mutation, .. }
            | Self::RestoreSnapshot { mutation, .. }
            | Self::DeleteSnapshot { mutation, .. }
            | Self::CancelOperation { mutation, .. }
            | Self::CachePin { mutation, .. }
            | Self::CacheUnpin { mutation, .. }
            | Self::Capability(CapabilityCommandV1::Renew { mutation, .. })
            | Self::Capability(CapabilityCommandV1::Revoke { mutation, .. }) => {
                Some(mutation.client_wait())
            }
            Self::CreateView { client_wait, .. } | Self::ForkSnapshot { client_wait, .. } => {
                Some(*client_wait)
            }
            Self::ExecutionControl(control) => Some(match control {
                super::execution::ExecutionControlCommandV1::Attach { mutation, .. }
                | super::execution::ExecutionControlCommandV1::Resize { mutation, .. }
                | super::execution::ExecutionControlCommandV1::Signal { mutation, .. }
                | super::execution::ExecutionControlCommandV1::Cancel { mutation, .. } => {
                    mutation.client_wait()
                }
            }),
            Self::Capability(CapabilityCommandV1::Attenuate { .. })
            | Self::Capability(CapabilityCommandV1::Inspect(_)) => None,
        }
    }
}

fn mutation_context_proto(
    mutation: &MutationFenceV1,
) -> aos_proto::aos::sandbox::v1::MutationContext {
    aos_proto::aos::sandbox::v1::MutationContext {
        idempotency_key: mutation.idempotency_key().as_bytes().to_vec(),
        expected_resource_version: mutation.expected_resource_version().as_bytes().to_vec(),
        expected_incarnation_id: mutation
            .expected_incarnation()
            .map_or_else(Vec::new, |value| value.as_bytes().to_vec()),
        operation_timeout: aos_proto::aos::sandbox::v1::Duration {
            nanoseconds: mutation.operation_timeout().as_nanos(),
            ..Default::default()
        }
        .into(),
        required_features: mutation.required_features().as_slice().to_vec(),
        ..Default::default()
    }
}

fn execution_mutation_context_proto(
    mutation: &super::execution::ExecutionMutationFenceV1,
) -> aos_proto::aos::sandbox::v1::MutationContext {
    aos_proto::aos::sandbox::v1::MutationContext {
        idempotency_key: mutation.idempotency_key().as_bytes().to_vec(),
        expected_resource_version: mutation.expected_resource_version().as_bytes().to_vec(),
        expected_incarnation_id: mutation.expected_incarnation().as_bytes().to_vec(),
        operation_timeout: duration_proto(mutation.operation_timeout()).into(),
        required_features: mutation.required_features().as_slice().to_vec(),
        ..Default::default()
    }
}

fn with_required_semantic_feature(
    mut mutation: wire::MutationContext,
    namespace: &str,
) -> wire::MutationContext {
    if mutation
        .required_features
        .binary_search_by(|feature| feature.namespace.as_str().cmp(namespace))
        .is_err()
    {
        mutation.required_features.push(wire::Feature {
            namespace: namespace.to_owned(),
            major: 1,
            minor: 0,
            ..Default::default()
        });
        mutation.required_features.sort_by(|left, right| {
            (&left.namespace, left.major, left.minor).cmp(&(
                &right.namespace,
                right.major,
                right.minor,
            ))
        });
    }
    mutation
}

fn fork_snapshot_features(required: &CheckedFeatureSetV1) -> Vec<wire::Feature> {
    let mut features = required.as_slice().to_vec();
    let namespace = crate::controller_query::SNAPSHOT_PROJECT_VERSION_FENCE_FEATURE_V1;
    if features
        .binary_search_by(|feature| feature.namespace.as_str().cmp(namespace))
        .is_err()
    {
        features.push(wire::Feature {
            namespace: namespace.to_owned(),
            major: 1,
            minor: 0,
            ..Default::default()
        });
        features.sort_by(|left, right| {
            (&left.namespace, left.major, left.minor).cmp(&(
                &right.namespace,
                right.major,
                right.minor,
            ))
        });
    }
    features
}

fn duration_proto(value: CliWaitDurationV1) -> aos_proto::aos::sandbox::v1::Duration {
    aos_proto::aos::sandbox::v1::Duration {
        nanoseconds: value.as_nanos(),
        ..Default::default()
    }
}

fn parent_proto(value: &OptionalParentFenceV1) -> (Vec<u8>, Vec<u8>) {
    match value {
        OptionalParentFenceV1::Root => (Vec::new(), Vec::new()),
        OptionalParentFenceV1::Child {
            parent_id,
            expected_parent_version,
        } => (
            parent_id.as_bytes().to_vec(),
            expected_parent_version.as_bytes().to_vec(),
        ),
    }
}

fn execution_signal_proto(value: super::execution::ExecutionSignalV1) -> i32 {
    use super::execution::ExecutionSignalV1 as Signal;
    match value {
        Signal::Hangup => 1,
        Signal::Interrupt => 2,
        Signal::Quit => 3,
        Signal::Terminate => 4,
        Signal::Kill => 5,
        Signal::User1 => 6,
        Signal::User2 => 7,
    }
}

struct MutationAuthorityBindingV1(Sha256);

impl MutationAuthorityBindingV1 {
    fn new() -> Self {
        Self(Sha256::new_with_prefix(
            b"aos.sandbox.cli.resolved-mutation-authority.v1\0",
        ))
    }

    fn variant(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value);
    }

    fn byte_rows(&mut self, values: &[Vec<u8>]) {
        self.0.update((values.len() as u64).to_be_bytes());
        for value in values {
            self.bytes(value);
        }
    }

    fn boolean(&mut self, value: bool) {
        self.variant(u8::from(value));
    }

    fn identity(&mut self, value: &CliIdentityV1) {
        self.bytes(value.as_bytes());
    }

    fn descriptor(&mut self, value: &ObjectDescriptor) {
        self.bytes(value.media_type.as_bytes());
        self.bytes(&value.sha256);
        self.0.update(value.encoded_size.to_be_bytes());
    }

    fn parent(&mut self, value: &OptionalParentFenceV1) {
        match value {
            OptionalParentFenceV1::Root => self.variant(0),
            OptionalParentFenceV1::Child {
                parent_id,
                expected_parent_version,
            } => {
                self.variant(1);
                self.identity(parent_id);
                self.bytes(expected_parent_version.as_bytes());
            }
        }
    }

    fn mutation_fence(&mut self, value: &MutationFenceV1) {
        self.bytes(value.expected_resource_version().as_bytes());
        match (value.expected_incarnation(), value.expected_plan()) {
            (Some(incarnation), None) => {
                self.variant(1);
                self.identity(incarnation);
            }
            (None, Some(plan)) => {
                self.variant(2);
                self.bytes(plan.as_bytes());
            }
            (None, None) => self.variant(0),
            (Some(incarnation), Some(plan)) => {
                self.variant(3);
                self.identity(incarnation);
                self.bytes(plan.as_bytes());
            }
        }
        self.0
            .update(value.operation_timeout().as_nanos().to_be_bytes());
        self.features(value.required_features());
        self.bytes(value.idempotency_key().as_bytes());
        self.wait(value.client_wait());
    }

    fn execution_fence(&mut self, value: &super::execution::ExecutionMutationFenceV1) {
        self.bytes(value.expected_resource_version().as_bytes());
        self.identity(&value.expected_incarnation());
        self.0
            .update(value.operation_timeout().as_nanos().to_be_bytes());
        self.features(value.required_features());
        self.bytes(value.idempotency_key().as_bytes());
        self.wait(value.client_wait());
    }

    fn controls(
        &mut self,
        operation_timeout: CliWaitDurationV1,
        required_features: &CheckedFeatureSetV1,
        idempotency_key: &CliIdempotencyKeyV1,
        client_wait: CliWaitV1,
    ) {
        self.0.update(operation_timeout.as_nanos().to_be_bytes());
        self.features(required_features);
        self.bytes(idempotency_key.as_bytes());
        self.wait(client_wait);
    }

    fn features(&mut self, value: &CheckedFeatureSetV1) {
        self.0.update((value.as_slice().len() as u64).to_be_bytes());
        for feature in value.as_slice() {
            self.bytes(feature.namespace.as_bytes());
            self.0.update(feature.major.to_be_bytes());
            self.0.update(feature.minor.to_be_bytes());
        }
    }

    fn wait(&mut self, value: CliWaitV1) {
        match value {
            CliWaitV1::ReturnOperation => self.variant(0),
            CliWaitV1::Bounded(duration) => {
                self.variant(1);
                self.0.update(duration.as_nanos().to_be_bytes());
            }
        }
    }

    fn finish(self) -> aos_sandbox_core::ObjectDigest {
        aos_sandbox_core::ObjectDigest::from_bytes(self.0.finalize().into())
    }
}
