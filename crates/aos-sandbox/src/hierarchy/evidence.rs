//! Opaque evidence admitted by future trusted controller adapters.
//!
//! Public consumers can inspect these values but cannot construct them from
//! request scalars. Crate-internal journal, signature, and inventory adapters
//! are the only intended minting sites once the dormant integration is wired.

use aos_sandbox_core::{
    AssignmentEpoch, AttachmentId, AttachmentSlotId, DesiredGeneration, ExportId, IncarnationId,
    NamespaceGeneration, NodeId, ObjectDescriptor, ObjectDigest, ProjectId, Revision, SandboxId,
    SnapshotId, ViewId,
};

/// Selects the inspection semantics authorized by a verified grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionGrantModeV1 {
    /// Authorizes only a retained immutable snapshot.
    Stable,
    /// Authorizes a current node-local, kernel-coupled namespace inspection.
    LiveKernelCoupled,
}

/// Retains one verified descendant-inspection grant decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInspectionGrantV1 {
    project: ProjectId,
    observer: SandboxId,
    observer_generation: DesiredGeneration,
    descendant: SandboxId,
    mode: InspectionGrantModeV1,
    revocation_generation: Revision,
    grant_commitment: ObjectDigest,
}

impl VerifiedInspectionGrantV1 {
    /// Creates evidence only after a trusted adapter verifies current grant state.
    pub(crate) fn from_verified_parts(
        project: ProjectId,
        observer: SandboxId,
        observer_generation: DesiredGeneration,
        descendant: SandboxId,
        mode: InspectionGrantModeV1,
        revocation_generation: Revision,
        grant_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            observer,
            observer_generation,
            descendant,
            mode,
            revocation_generation,
            grant_commitment,
        }
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the inspecting ancestor.
    #[must_use]
    pub const fn observer(&self) -> SandboxId {
        self.observer
    }

    /// Returns the verified observer generation.
    #[must_use]
    pub const fn observer_generation(&self) -> DesiredGeneration {
        self.observer_generation
    }

    /// Returns the exact descendant covered by the grant.
    #[must_use]
    pub const fn descendant(&self) -> SandboxId {
        self.descendant
    }

    /// Returns the exact stable or live semantics authorized by the grant.
    #[must_use]
    pub const fn mode(&self) -> InspectionGrantModeV1 {
        self.mode
    }

    /// Returns the revocation generation checked by the trusted adapter.
    #[must_use]
    pub const fn revocation_generation(&self) -> Revision {
        self.revocation_generation
    }

    /// Returns the opaque verified grant commitment.
    #[must_use]
    pub const fn grant_commitment(&self) -> ObjectDigest {
        self.grant_commitment
    }
}

/// Retains one verified immutable snapshot manifest and its physical pin proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedSnapshotManifestV1 {
    project: ProjectId,
    sandbox: SandboxId,
    snapshot: SnapshotId,
    captured_generation: DesiredGeneration,
    manifest: ObjectDescriptor,
    export_closure_commitment: ObjectDigest,
    retention_plan_commitment: ObjectDigest,
    preparation_commitment: ObjectDigest,
    retention_proof_commitment: ObjectDigest,
}

impl RetainedSnapshotManifestV1 {
    /// Creates evidence only after manifest verification and retention pinning.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_parts(
        project: ProjectId,
        sandbox: SandboxId,
        snapshot: SnapshotId,
        captured_generation: DesiredGeneration,
        manifest: ObjectDescriptor,
        export_closure_commitment: ObjectDigest,
        retention_plan_commitment: ObjectDigest,
        preparation_commitment: ObjectDigest,
        retention_proof_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            sandbox,
            snapshot,
            captured_generation,
            manifest,
            export_closure_commitment,
            retention_plan_commitment,
            preparation_commitment,
            retention_proof_commitment,
        }
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the captured sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the immutable snapshot identity.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }

    /// Returns the sandbox generation captured by the manifest.
    #[must_use]
    pub const fn captured_generation(&self) -> DesiredGeneration {
        self.captured_generation
    }

    /// Returns the exact immutable manifest descriptor.
    #[must_use]
    pub const fn manifest(&self) -> &ObjectDescriptor {
        &self.manifest
    }

    /// Returns the commitment to the complete captured export closure.
    #[must_use]
    pub const fn export_closure_commitment(&self) -> ObjectDigest {
        self.export_closure_commitment
    }

    /// Returns the exact physical retention plan that was executed.
    #[must_use]
    pub const fn retention_plan_commitment(&self) -> ObjectDigest {
        self.retention_plan_commitment
    }

    /// Returns the exact logical preparation retained by the physical proof.
    #[must_use]
    pub const fn preparation_commitment(&self) -> ObjectDigest {
        self.preparation_commitment
    }

    /// Returns proof that all manifest objects remain physically retained.
    #[must_use]
    pub const fn retention_proof_commitment(&self) -> ObjectDigest {
        self.retention_proof_commitment
    }
}

/// Retains one authenticated current live-namespace observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentLiveInspectionObservationV1 {
    project: ProjectId,
    sandbox: SandboxId,
    desired_generation: DesiredGeneration,
    incarnation: IncarnationId,
    namespace_generation: NamespaceGeneration,
    assignment_epoch: AssignmentEpoch,
    node: NodeId,
    observation_set_commitment: ObjectDigest,
    observation_commitment: ObjectDigest,
}

impl CurrentLiveInspectionObservationV1 {
    /// Creates evidence only after current assignment and inventory validation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_parts(
        project: ProjectId,
        sandbox: SandboxId,
        desired_generation: DesiredGeneration,
        incarnation: IncarnationId,
        namespace_generation: NamespaceGeneration,
        assignment_epoch: AssignmentEpoch,
        node: NodeId,
        observation_set_commitment: ObjectDigest,
        observation_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            sandbox,
            desired_generation,
            incarnation,
            namespace_generation,
            assignment_epoch,
            node,
            observation_set_commitment,
            observation_commitment,
        }
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the observed sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the observed desired generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the observed runtime incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the observed payload namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> NamespaceGeneration {
        self.namespace_generation
    }

    /// Returns the observed assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the observed source node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the shared current-observation set commitment.
    #[must_use]
    pub const fn observation_set_commitment(&self) -> ObjectDigest {
        self.observation_set_commitment
    }

    /// Returns the authenticated observation commitment.
    #[must_use]
    pub const fn observation_commitment(&self) -> ObjectDigest {
        self.observation_commitment
    }
}

/// Retains current assignment facts used to compile one attachment recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentAssignmentEvidenceV1 {
    project: ProjectId,
    sandbox: SandboxId,
    desired_generation: DesiredGeneration,
    incarnation: IncarnationId,
    namespace_generation: NamespaceGeneration,
    assignment_epoch: AssignmentEpoch,
    node: NodeId,
    observation_set_commitment: ObjectDigest,
    assignment_commitment: ObjectDigest,
}

impl CurrentAssignmentEvidenceV1 {
    /// Creates evidence only after a trusted assignment observation is current.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_parts(
        project: ProjectId,
        sandbox: SandboxId,
        desired_generation: DesiredGeneration,
        incarnation: IncarnationId,
        namespace_generation: NamespaceGeneration,
        assignment_epoch: AssignmentEpoch,
        node: NodeId,
        observation_set_commitment: ObjectDigest,
        assignment_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            sandbox,
            desired_generation,
            incarnation,
            namespace_generation,
            assignment_epoch,
            node,
            observation_set_commitment,
            assignment_commitment,
        }
    }

    /// Returns the project identity.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the assigned sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the assigned desired generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the assigned incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the assigned namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> NamespaceGeneration {
        self.namespace_generation
    }

    /// Returns the assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the assigned node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the shared current-observation set commitment.
    #[must_use]
    pub const fn observation_set_commitment(&self) -> ObjectDigest {
        self.observation_set_commitment
    }

    /// Returns the current assignment commitment.
    #[must_use]
    pub const fn assignment_commitment(&self) -> ObjectDigest {
        self.assignment_commitment
    }
}

/// Retains verified logical source ownership and publication state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedViewSourceEvidenceV1 {
    project: ProjectId,
    owner: SandboxId,
    owner_generation: DesiredGeneration,
    export: ExportId,
    view: ViewId,
    view_revision: Revision,
    view_descriptor: ObjectDescriptor,
    source_handle_commitment: ObjectDigest,
    retention_proof_commitment: ObjectDigest,
    source_incarnation: Option<IncarnationId>,
    source_node: Option<NodeId>,
    source_namespace_generation: Option<NamespaceGeneration>,
    source_assignment_epoch: Option<AssignmentEpoch>,
    current_observation_set_commitment: Option<ObjectDigest>,
}

impl RetainedViewSourceEvidenceV1 {
    /// Creates evidence only after catalog, export, and retention verification.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_parts(
        project: ProjectId,
        owner: SandboxId,
        owner_generation: DesiredGeneration,
        export: ExportId,
        view: ViewId,
        view_revision: Revision,
        view_descriptor: ObjectDescriptor,
        source_handle_commitment: ObjectDigest,
        retention_proof_commitment: ObjectDigest,
        source_incarnation: Option<IncarnationId>,
        source_node: Option<NodeId>,
        source_namespace_generation: Option<NamespaceGeneration>,
        source_assignment_epoch: Option<AssignmentEpoch>,
        current_observation_set_commitment: Option<ObjectDigest>,
    ) -> Self {
        Self {
            project,
            owner,
            owner_generation,
            export,
            view,
            view_revision,
            view_descriptor,
            source_handle_commitment,
            retention_proof_commitment,
            source_incarnation,
            source_node,
            source_namespace_generation,
            source_assignment_epoch,
            current_observation_set_commitment,
        }
    }

    /// Returns the project identity.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the source owner sandbox.
    #[must_use]
    pub const fn owner(&self) -> SandboxId {
        self.owner
    }

    /// Returns the source owner's desired generation.
    #[must_use]
    pub const fn owner_generation(&self) -> DesiredGeneration {
        self.owner_generation
    }

    /// Returns the named source export.
    #[must_use]
    pub const fn export(&self) -> ExportId {
        self.export
    }

    /// Returns the logical view identity.
    #[must_use]
    pub const fn view(&self) -> ViewId {
        self.view
    }

    /// Returns the immutable view revision.
    #[must_use]
    pub const fn view_revision(&self) -> Revision {
        self.view_revision
    }

    /// Returns the exact portable view descriptor.
    #[must_use]
    pub const fn view_descriptor(&self) -> &ObjectDescriptor {
        &self.view_descriptor
    }

    /// Returns the exact source-handle commitment.
    #[must_use]
    pub const fn source_handle_commitment(&self) -> ObjectDigest {
        self.source_handle_commitment
    }

    /// Returns physical pin or retention proof for the source backing.
    #[must_use]
    pub const fn retention_proof_commitment(&self) -> ObjectDigest {
        self.retention_proof_commitment
    }

    /// Returns the live source incarnation, if the source is kernel coupled.
    #[must_use]
    pub const fn source_incarnation(&self) -> Option<IncarnationId> {
        self.source_incarnation
    }

    /// Returns the source node for a kernel-coupled live source.
    #[must_use]
    pub const fn source_node(&self) -> Option<NodeId> {
        self.source_node
    }

    /// Returns the live source namespace generation, when kernel coupled.
    #[must_use]
    pub const fn source_namespace_generation(&self) -> Option<NamespaceGeneration> {
        self.source_namespace_generation
    }

    /// Returns the live source assignment epoch, when kernel coupled.
    #[must_use]
    pub const fn source_assignment_epoch(&self) -> Option<AssignmentEpoch> {
        self.source_assignment_epoch
    }

    /// Returns the shared current-observation set for a live source.
    #[must_use]
    pub const fn current_observation_set_commitment(&self) -> Option<ObjectDigest> {
        self.current_observation_set_commitment
    }
}

/// Identifies the exact observed contents of a logical destination slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlotInventoryStateV1 {
    /// The destination is proven empty under the current namespace generation.
    Empty,
    /// The destination contains the immediate predecessor realization.
    ImmediatePredecessor {
        /// Logical predecessor attachment.
        attachment: AttachmentId,
        /// Exact predecessor generation.
        generation: DesiredGeneration,
        /// Commitment to the predecessor realization recipe.
        recipe_commitment: ObjectDigest,
    },
}

/// Retains one authenticated current destination-slot inventory observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentSlotInventoryEvidenceV1 {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    namespace_generation: NamespaceGeneration,
    node: NodeId,
    assignment_epoch: AssignmentEpoch,
    observation_set_commitment: ObjectDigest,
    destination_slot: AttachmentSlotId,
    state: SlotInventoryStateV1,
    inventory_commitment: ObjectDigest,
}

impl CurrentSlotInventoryEvidenceV1 {
    /// Creates evidence only after current descriptor-based inventory validation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_parts(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        namespace_generation: NamespaceGeneration,
        node: NodeId,
        assignment_epoch: AssignmentEpoch,
        observation_set_commitment: ObjectDigest,
        destination_slot: AttachmentSlotId,
        state: SlotInventoryStateV1,
        inventory_commitment: ObjectDigest,
    ) -> Self {
        Self {
            sandbox,
            incarnation,
            namespace_generation,
            node,
            assignment_epoch,
            observation_set_commitment,
            destination_slot,
            state,
            inventory_commitment,
        }
    }

    /// Returns the destination sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the destination incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the destination namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> NamespaceGeneration {
        self.namespace_generation
    }

    /// Returns the node whose destination slot was inventoried.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the assignment epoch under which the slot was inventoried.
    #[must_use]
    pub const fn assignment_epoch(&self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the shared current-observation set commitment.
    #[must_use]
    pub const fn observation_set_commitment(&self) -> ObjectDigest {
        self.observation_set_commitment
    }

    /// Returns the logical destination slot.
    #[must_use]
    pub const fn destination_slot(&self) -> AttachmentSlotId {
        self.destination_slot
    }

    /// Returns the exact observed predecessor state.
    #[must_use]
    pub const fn state(&self) -> &SlotInventoryStateV1 {
        &self.state
    }

    /// Returns the authenticated inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(&self) -> ObjectDigest {
        self.inventory_commitment
    }
}

/// Retains verified request authority for exactly one attachment intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAttachmentAuthorityV1 {
    attachment: AttachmentId,
    desired_generation: DesiredGeneration,
    request_commitment: ObjectDigest,
    policy_commitment: ObjectDigest,
    lease_commitment: ObjectDigest,
}

impl VerifiedAttachmentAuthorityV1 {
    /// Creates evidence only after policy, lease, and request authorization.
    pub(crate) fn from_verified_parts(
        attachment: AttachmentId,
        desired_generation: DesiredGeneration,
        request_commitment: ObjectDigest,
        policy_commitment: ObjectDigest,
        lease_commitment: ObjectDigest,
    ) -> Self {
        Self {
            attachment,
            desired_generation,
            request_commitment,
            policy_commitment,
            lease_commitment,
        }
    }

    /// Returns the authorized attachment.
    #[must_use]
    pub const fn attachment(&self) -> AttachmentId {
        self.attachment
    }

    /// Returns the authorized desired generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the normalized request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the policy decision commitment.
    #[must_use]
    pub const fn policy_commitment(&self) -> ObjectDigest {
        self.policy_commitment
    }

    /// Returns the verified lease commitment.
    #[must_use]
    pub const fn lease_commitment(&self) -> ObjectDigest {
        self.lease_commitment
    }
}

/// Retains verified authority for one exact attachment detach request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDetachAuthorityV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    request_commitment: ObjectDigest,
    policy_commitment: ObjectDigest,
}

impl VerifiedDetachAuthorityV1 {
    /// Creates evidence only after current detach authorization.
    pub(crate) fn from_verified_parts(
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        request_commitment: ObjectDigest,
        policy_commitment: ObjectDigest,
    ) -> Self {
        Self {
            attachment,
            attachment_generation,
            request_commitment,
            policy_commitment,
        }
    }

    /// Returns the authorized attachment.
    #[must_use]
    pub const fn attachment(&self) -> AttachmentId {
        self.attachment
    }

    /// Returns the authorized current attachment generation.
    #[must_use]
    pub const fn attachment_generation(&self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the normalized detach request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the exact detach policy decision commitment.
    #[must_use]
    pub const fn policy_commitment(&self) -> ObjectDigest {
        self.policy_commitment
    }
}

/// Retains verified terminal inventory for one completed detach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDetachCompletionV1 {
    project: ProjectId,
    tree_generation: Revision,
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    detach_commitment: ObjectDigest,
    detach_history_commitment: ObjectDigest,
    inventory_commitment: ObjectDigest,
    completion_commitment: ObjectDigest,
}

impl VerifiedDetachCompletionV1 {
    /// Creates evidence only after current inventory proves terminal absence.
    pub(crate) const fn from_verified_parts(
        project: ProjectId,
        tree_generation: Revision,
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        detach_commitment: ObjectDigest,
        detach_history_commitment: ObjectDigest,
        inventory_commitment: ObjectDigest,
        completion_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            tree_generation,
            attachment,
            attachment_generation,
            detach_commitment,
            detach_history_commitment,
            inventory_commitment,
            completion_commitment,
        }
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the exact project-tree generation of the detach plan.
    #[must_use]
    pub const fn tree_generation(self) -> Revision {
        self.tree_generation
    }

    /// Returns the detached attachment identity.
    #[must_use]
    pub const fn attachment(self) -> AttachmentId {
        self.attachment
    }

    /// Returns the detached generation.
    #[must_use]
    pub const fn attachment_generation(self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the exact detach plan commitment.
    #[must_use]
    pub const fn detach_commitment(self) -> ObjectDigest {
        self.detach_commitment
    }

    /// Returns the exact durable detach-progress head completed by this evidence.
    #[must_use]
    pub const fn detach_history_commitment(self) -> ObjectDigest {
        self.detach_history_commitment
    }

    /// Returns the terminal inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }

    /// Returns the canonical completion commitment.
    #[must_use]
    pub const fn completion_commitment(self) -> ObjectDigest {
        self.completion_commitment
    }
}

/// Retains verified terminal state for a complete multi-action transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRealizationTransactionCompletionV1 {
    project: ProjectId,
    tree_generation: Revision,
    plan_commitment: ObjectDigest,
    transaction_state_commitment: ObjectDigest,
    terminal_heads_commitment: ObjectDigest,
    completion_commitment: ObjectDigest,
}

impl VerifiedRealizationTransactionCompletionV1 {
    /// Creates evidence only after every action has a verified terminal head.
    pub(crate) const fn from_verified_parts(
        project: ProjectId,
        tree_generation: Revision,
        plan_commitment: ObjectDigest,
        transaction_state_commitment: ObjectDigest,
        terminal_heads_commitment: ObjectDigest,
        completion_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            tree_generation,
            plan_commitment,
            transaction_state_commitment,
            terminal_heads_commitment,
            completion_commitment,
        }
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the exact project-tree generation of the completed plan.
    #[must_use]
    pub const fn tree_generation(self) -> Revision {
        self.tree_generation
    }

    /// Returns the complete immutable plan commitment.
    #[must_use]
    pub const fn plan_commitment(self) -> ObjectDigest {
        self.plan_commitment
    }

    /// Returns the exact durable transaction state completed by this evidence.
    #[must_use]
    pub const fn transaction_state_commitment(self) -> ObjectDigest {
        self.transaction_state_commitment
    }

    /// Returns the exact canonical set of terminal action heads.
    #[must_use]
    pub const fn terminal_heads_commitment(self) -> ObjectDigest {
        self.terminal_heads_commitment
    }

    /// Returns the complete transaction completion commitment.
    #[must_use]
    pub const fn completion_commitment(self) -> ObjectDigest {
        self.completion_commitment
    }
}
