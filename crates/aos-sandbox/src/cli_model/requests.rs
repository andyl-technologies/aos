//! Lossless resolved public-request fences for mutating CLI commands.

use std::fmt;

use super::execution::{CliIdentityV1, CreateExecutionCommandV1};
use super::grammar::{
    CliIdempotencyKeyV1, CliResourceVersionV1, CliWaitDurationV1, CliWaitV1, InvalidCliGrammar,
};
use crate::controller_query::portable::{
    CheckedFeatureSetV1, CheckedFilesystemViewDescriptorV1, CheckedObjectDescriptorV1,
    CheckedPolicyDescriptorV1, CheckedSandboxSpecificationV1,
};

/// States fields that must enter the public request proto before CLI activation.
pub const PUBLIC_REQUEST_INTEGRATION_REQUIRED: &str = "add create-view timeout, fork project/timeout fences, attachment noexec, and delete force semantics to aos.sandbox.v1 before activating these CLI request models";

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
            pub const fn new(value: [u8; 32]) -> Result<Self, InvalidCliGrammar> {
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
    /// Restores a snapshot into an existing sandbox.
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
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Removes one exact public object pin without invalidating active leases.
    CacheUnpin {
        /// Supplies the exact object descriptor.
        object: CheckedObjectDescriptorV1,
        /// Supplies complete mutation fences.
        mutation: MutationFenceV1,
    },
    /// Performs a capability action.
    Capability(CapabilityCommandV1),
}

impl ResolvedPublicMutationV1 {
    /// Checks that each action carries exactly its required authenticated fence.
    pub(crate) fn has_action_specific_fences(&self) -> bool {
        use MutationFenceRequirementV1 as R;
        match self {
            Self::CreateSandbox(_)
            | Self::CreateExecution(_)
            | Self::ExecutionControl(_)
            | Self::CreateView { .. }
            | Self::ForkSnapshot { .. }
            | Self::Capability(CapabilityCommandV1::Attenuate { .. })
            | Self::Capability(CapabilityCommandV1::Inspect(_)) => true,
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
                scope, mutation, ..
            } => mutation.meets(R::Plan(scope.expected_plan())),
            Self::AttachView { mutation, .. } | Self::CreateSnapshot { mutation, .. } => {
                mutation.meets(R::Incarnation)
            }
            Self::ReplaceAttachment { mutation, .. }
            | Self::DetachView { mutation, .. }
            | Self::ReleaseView { mutation, .. }
            | Self::RestoreSnapshot { mutation, .. }
            | Self::DeleteSnapshot { mutation, .. }
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
            | Self::CachePin { mutation, .. }
            | Self::CacheUnpin { mutation, .. }
            | Self::Capability(CapabilityCommandV1::Renew { mutation, .. })
            | Self::Capability(CapabilityCommandV1::Revoke { mutation, .. }) => {
                Some(mutation.client_wait())
            }
            Self::CreateView { client_wait, .. } | Self::ForkSnapshot { client_wait, .. } => {
                Some(*client_wait)
            }
            Self::ExecutionControl(super::execution::ExecutionControlCommandV1::Cancel {
                mutation,
                ..
            }) => Some(mutation.client_wait()),
            Self::ExecutionControl(
                super::execution::ExecutionControlCommandV1::Attach(_)
                | super::execution::ExecutionControlCommandV1::Resize { .. }
                | super::execution::ExecutionControlCommandV1::Signal { .. },
            )
            | Self::Capability(CapabilityCommandV1::Attenuate { .. })
            | Self::Capability(CapabilityCommandV1::Inspect(_)) => None,
        }
    }
}
