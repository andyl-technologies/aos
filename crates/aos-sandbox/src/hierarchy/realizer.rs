//! Evidence-derived attachment realization and detach transaction plans.
//!
//! Plans retain exact portable attachment intent, current assignment, source,
//! policy, lease, and destination inventory joins. They contain no host path,
//! namespace path, process identity, mount identifier, or file descriptor and
//! grant no broker authority.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::model::{AttachmentConsistency, AttachmentIntent};
use aos_sandbox_core::{
    AssignmentEpoch, AttachmentId, AttachmentSlotId, DesiredGeneration, ExportId, IncarnationId,
    NamespaceGeneration, NodeId, ObjectDigest, ProjectId, Revision, SandboxId,
};
use sha2::{Digest as _, Sha256};

use super::evidence::{
    CurrentAssignmentEvidenceV1, CurrentSlotInventoryEvidenceV1, RetainedViewSourceEvidenceV1,
    SlotInventoryStateV1, VerifiedAttachmentAuthorityV1, VerifiedDetachAuthorityV1,
};
use super::graph::SandboxTreeV1;

/// Maximum attachment publications or detaches in one transaction.
pub const MAXIMUM_REALIZATION_ACTIONS: usize = 16_384;
/// Maximum ordering edges in one realization transaction.
pub const MAXIMUM_REALIZATION_DEPENDENCIES: usize = 65_536;

/// Retains a durable transaction fact authorizing an exact slot replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplacementTransactionV1 {
    predecessor: AttachmentId,
    successor: AttachmentId,
    predecessor_generation: DesiredGeneration,
    predecessor_recipe_commitment: ObjectDigest,
    transaction_commitment: ObjectDigest,
}

impl ReplacementTransactionV1 {
    /// Creates a replacement fact for verified durable-transaction admission.
    pub(crate) fn from_durable_parts(
        predecessor: AttachmentId,
        successor: AttachmentId,
        predecessor_generation: DesiredGeneration,
        predecessor_recipe_commitment: ObjectDigest,
        transaction_commitment: ObjectDigest,
    ) -> Self {
        Self {
            predecessor,
            successor,
            predecessor_generation,
            predecessor_recipe_commitment,
            transaction_commitment,
        }
    }

    /// Returns the attachment currently occupying the destination.
    #[must_use]
    pub const fn predecessor(self) -> AttachmentId {
        self.predecessor
    }

    /// Returns the replacement attachment.
    #[must_use]
    pub const fn successor(self) -> AttachmentId {
        self.successor
    }

    /// Returns the exact predecessor generation.
    #[must_use]
    pub const fn predecessor_generation(self) -> DesiredGeneration {
        self.predecessor_generation
    }

    /// Returns the predecessor recipe commitment observed in the slot.
    #[must_use]
    pub const fn predecessor_recipe_commitment(self) -> ObjectDigest {
        self.predecessor_recipe_commitment
    }

    /// Returns the durable replacement transaction commitment.
    #[must_use]
    pub const fn transaction_commitment(self) -> ObjectDigest {
        self.transaction_commitment
    }
}

/// Describes one evidence-derived attachment publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentRealizationV1 {
    project: ProjectId,
    tree_generation: Revision,
    intent: AttachmentIntent,
    consumer_node: NodeId,
    assignment_epoch: AssignmentEpoch,
    observation_set_commitment: ObjectDigest,
    assignment_commitment: ObjectDigest,
    source_owner: SandboxId,
    source_owner_generation: DesiredGeneration,
    source_export: ExportId,
    source_node: Option<NodeId>,
    source_namespace_generation: Option<NamespaceGeneration>,
    source_assignment_epoch: Option<AssignmentEpoch>,
    source_handle_commitment: ObjectDigest,
    source_retention_commitment: ObjectDigest,
    request_commitment: ObjectDigest,
    policy_commitment: ObjectDigest,
    lease_commitment: ObjectDigest,
    inventory_commitment: ObjectDigest,
    replacement: Option<ReplacementTransactionV1>,
    dependencies: Vec<AttachmentId>,
    recipe_commitment: ObjectDigest,
}

impl AttachmentRealizationV1 {
    /// Joins exact intent with opaque current assignment, source, authority,
    /// lease, policy, and destination inventory evidence.
    ///
    /// An occupied destination is accepted only when it is the exact immediate
    /// predecessor named by a durable replacement transaction. Empty slots may
    /// not carry a replacement fact. Assignment, live source, and inventory
    /// evidence must share one current observation set. Local-live intent also
    /// binds the source-owner incarnation and node.
    ///
    /// # Errors
    ///
    /// Returns [`RealizationPlanError`] for stale or conflicting evidence,
    /// incomplete replacement proof, or a noncanonical dependency set.
    #[allow(clippy::too_many_arguments)]
    pub fn from_intent(
        tree: &SandboxTreeV1,
        intent: AttachmentIntent,
        assignment: CurrentAssignmentEvidenceV1,
        source: RetainedViewSourceEvidenceV1,
        authority: VerifiedAttachmentAuthorityV1,
        inventory: CurrentSlotInventoryEvidenceV1,
        replacement: Option<ReplacementTransactionV1>,
        dependencies: Vec<AttachmentId>,
    ) -> Result<Self, RealizationPlanError> {
        validate_dependencies(intent.id(), &dependencies)?;
        validate_intent_evidence(tree, &intent, &assignment, &source, &authority, &inventory)?;
        validate_replacement(&intent, &inventory, replacement)?;

        let recipe_commitment = commit_recipe(
            tree.tree_generation(),
            &intent,
            &assignment,
            &source,
            &authority,
            &inventory,
            replacement,
            &dependencies,
        )?;
        Ok(Self {
            project: assignment.project(),
            tree_generation: tree.tree_generation(),
            consumer_node: assignment.node(),
            assignment_epoch: assignment.assignment_epoch(),
            observation_set_commitment: assignment.observation_set_commitment(),
            assignment_commitment: assignment.assignment_commitment(),
            source_owner: source.owner(),
            source_owner_generation: source.owner_generation(),
            source_export: source.export(),
            source_node: source.source_node(),
            source_namespace_generation: source.source_namespace_generation(),
            source_assignment_epoch: source.source_assignment_epoch(),
            source_handle_commitment: source.source_handle_commitment(),
            source_retention_commitment: source.retention_proof_commitment(),
            request_commitment: authority.request_commitment(),
            policy_commitment: authority.policy_commitment(),
            lease_commitment: authority.lease_commitment(),
            inventory_commitment: inventory.inventory_commitment(),
            replacement,
            dependencies,
            recipe_commitment,
            intent,
        })
    }

    /// Reconstructs one canonical durable recipe without promoting its
    /// commitments back into live evidence authority.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_canonical_parts(
        project: ProjectId,
        tree_generation: Revision,
        intent: AttachmentIntent,
        consumer_node: NodeId,
        assignment_epoch: AssignmentEpoch,
        observation_set_commitment: ObjectDigest,
        assignment_commitment: ObjectDigest,
        source_owner: SandboxId,
        source_owner_generation: DesiredGeneration,
        source_export: ExportId,
        source_node: Option<NodeId>,
        source_namespace_generation: Option<NamespaceGeneration>,
        source_assignment_epoch: Option<AssignmentEpoch>,
        source_handle_commitment: ObjectDigest,
        source_retention_commitment: ObjectDigest,
        request_commitment: ObjectDigest,
        policy_commitment: ObjectDigest,
        stored_lease_commitment: ObjectDigest,
        inventory_commitment: ObjectDigest,
        replacement: Option<ReplacementTransactionV1>,
        dependencies: Vec<AttachmentId>,
        recipe_commitment: ObjectDigest,
    ) -> Result<Self, RealizationPlanError> {
        validate_dependencies(intent.id(), &dependencies)?;
        let local_live = intent.consistency() == AttachmentConsistency::LocalLive;
        let complete_live_source = source_node.is_some()
            && source_namespace_generation.is_some()
            && source_assignment_epoch.is_some();
        if project.as_bytes() == &[0; 16]
            || tree_generation.get() == 0
            || consumer_node.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
            || observation_set_commitment.as_bytes() == &[0; 32]
            || assignment_commitment.as_bytes() == &[0; 32]
            || source_owner.as_bytes() == &[0; 16]
            || source_owner_generation.get() == 0
            || source_export.as_bytes() == &[0; 16]
            || source_handle_commitment.as_bytes() == &[0; 32]
            || source_retention_commitment.as_bytes() == &[0; 32]
            || request_commitment.as_bytes() == &[0; 32]
            || policy_commitment.as_bytes() == &[0; 32]
            || stored_lease_commitment.as_bytes() == &[0; 32]
            || inventory_commitment.as_bytes() == &[0; 32]
            || recipe_commitment.as_bytes() == &[0; 32]
            || request_commitment != intent_commitment(&intent)?
            || stored_lease_commitment != lease_commitment(&intent)
            || source_node.is_some_and(|value| value.as_bytes() == &[0; 16])
            || source_namespace_generation.is_some_and(|value| value.get() == 0)
            || source_assignment_epoch.is_some_and(|value| value.get() == 0)
            || local_live != complete_live_source
            || (!local_live
                && (source_node.is_some()
                    || source_namespace_generation.is_some()
                    || source_assignment_epoch.is_some()))
            || (local_live && source_node != Some(consumer_node))
        {
            return Err(RealizationPlanError::UnspecifiedIdentity);
        }
        if let Some(replacement) = replacement {
            if replacement.predecessor().as_bytes() == &[0; 16]
                || replacement.successor() != intent.id()
                || replacement.predecessor_generation().get() == 0
                || replacement.predecessor_recipe_commitment().as_bytes() == &[0; 32]
                || replacement.transaction_commitment().as_bytes() == &[0; 32]
                || !replacement_generation_is_valid(&intent, replacement)
            {
                return Err(RealizationPlanError::EvidenceConflict);
            }
        }

        let action = Self {
            project,
            tree_generation,
            intent,
            consumer_node,
            assignment_epoch,
            observation_set_commitment,
            assignment_commitment,
            source_owner,
            source_owner_generation,
            source_export,
            source_node,
            source_namespace_generation,
            source_assignment_epoch,
            source_handle_commitment,
            source_retention_commitment,
            request_commitment,
            policy_commitment,
            lease_commitment: stored_lease_commitment,
            inventory_commitment,
            replacement,
            dependencies,
            recipe_commitment,
        };
        if canonical_recipe_commitment(&action)? != recipe_commitment {
            return Err(RealizationPlanError::EvidenceConflict);
        }
        Ok(action)
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the exact project-tree snapshot used to derive this action.
    #[must_use]
    pub const fn tree_generation(&self) -> Revision {
        self.tree_generation
    }

    /// Returns the complete portable attachment intent.
    #[must_use]
    pub const fn intent(&self) -> &AttachmentIntent {
        &self.intent
    }

    /// Returns the attachment identity.
    #[must_use]
    pub const fn attachment(&self) -> AttachmentId {
        self.intent.id()
    }

    /// Returns the current consumer node bound by assignment evidence.
    #[must_use]
    pub const fn consumer_node(&self) -> NodeId {
        self.consumer_node
    }

    /// Returns the exact assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the shared assignment, source, and inventory observation set.
    #[must_use]
    pub const fn observation_set_commitment(&self) -> ObjectDigest {
        self.observation_set_commitment
    }

    /// Returns the current assignment commitment.
    #[must_use]
    pub const fn assignment_commitment(&self) -> ObjectDigest {
        self.assignment_commitment
    }

    /// Returns the logical source owner.
    #[must_use]
    pub const fn source_owner(&self) -> SandboxId {
        self.source_owner
    }

    /// Returns the exact source-owner generation.
    #[must_use]
    pub const fn source_owner_generation(&self) -> DesiredGeneration {
        self.source_owner_generation
    }

    /// Returns the named source export.
    #[must_use]
    pub const fn source_export(&self) -> ExportId {
        self.source_export
    }

    /// Returns the source node required by local-live consistency.
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

    /// Returns the exact logical source-handle commitment.
    #[must_use]
    pub const fn source_handle_commitment(&self) -> ObjectDigest {
        self.source_handle_commitment
    }

    /// Returns source-backing pin or retention evidence.
    #[must_use]
    pub const fn source_retention_commitment(&self) -> ObjectDigest {
        self.source_retention_commitment
    }

    /// Returns the normalized authorized request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the exact policy decision commitment.
    #[must_use]
    pub const fn policy_commitment(&self) -> ObjectDigest {
        self.policy_commitment
    }

    /// Returns the verified lease commitment.
    #[must_use]
    pub const fn lease_commitment(&self) -> ObjectDigest {
        self.lease_commitment
    }

    /// Returns the current slot inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(&self) -> ObjectDigest {
        self.inventory_commitment
    }

    /// Returns the exact replacement fact, if the slot was occupied.
    #[must_use]
    pub const fn replacement(&self) -> Option<ReplacementTransactionV1> {
        self.replacement
    }

    /// Returns attachment dependencies in canonical identity order.
    #[must_use]
    pub fn dependencies(&self) -> &[AttachmentId] {
        &self.dependencies
    }

    /// Returns the canonical commitment to the complete joined recipe.
    #[must_use]
    pub const fn recipe_commitment(&self) -> ObjectDigest {
        self.recipe_commitment
    }

    fn destination_key(&self) -> (SandboxId, AttachmentSlotId) {
        let (sandbox, _) = self.intent.consumer();
        (sandbox, self.intent.destination_slot())
    }
}

/// Describes one explicit detach of an exact currently inventoried attachment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentDetachV1 {
    project: ProjectId,
    tree_generation: Revision,
    attachment: AttachmentId,
    generation: DesiredGeneration,
    consumer: SandboxId,
    consumer_incarnation: IncarnationId,
    consumer_node: NodeId,
    assignment_epoch: AssignmentEpoch,
    observation_set_commitment: ObjectDigest,
    namespace_generation: NamespaceGeneration,
    destination_slot: AttachmentSlotId,
    recipe_commitment: ObjectDigest,
    assignment_commitment: ObjectDigest,
    request_commitment: ObjectDigest,
    policy_commitment: ObjectDigest,
    inventory_commitment: ObjectDigest,
    detach_after: Vec<AttachmentId>,
    detach_commitment: ObjectDigest,
}

impl AttachmentDetachV1 {
    /// Derives one detach from current assignment, authority, and slot evidence.
    ///
    /// # Errors
    ///
    /// Returns [`RealizationPlanError`] unless inventory names the exact current
    /// attachment generation and recipe or dependencies are noncanonical.
    pub fn from_current(
        tree: &SandboxTreeV1,
        assignment: &CurrentAssignmentEvidenceV1,
        authority: &VerifiedDetachAuthorityV1,
        inventory: &CurrentSlotInventoryEvidenceV1,
        detach_after: Vec<AttachmentId>,
    ) -> Result<Self, RealizationPlanError> {
        validate_dependencies(authority.attachment(), &detach_after)?;
        let SlotInventoryStateV1::ImmediatePredecessor {
            attachment,
            generation,
            recipe_commitment,
        } = inventory.state()
        else {
            return Err(RealizationPlanError::MissingImmediatePredecessor);
        };
        if *attachment != authority.attachment()
            || *generation != authority.attachment_generation()
            || assignment.sandbox() != inventory.sandbox()
            || assignment.incarnation() != inventory.incarnation()
            || assignment.namespace_generation() != inventory.namespace_generation()
            || assignment.node() != inventory.node()
            || assignment.assignment_epoch() != inventory.assignment_epoch()
            || assignment.observation_set_commitment() != inventory.observation_set_commitment()
            || assignment.node().as_bytes() == &[0; 16]
            || assignment.assignment_epoch().get() == 0
            || assignment.observation_set_commitment().as_bytes() == &[0; 32]
            || assignment.assignment_commitment().as_bytes() == &[0; 32]
            || authority.request_commitment().as_bytes() == &[0; 32]
            || authority.policy_commitment().as_bytes() == &[0; 32]
            || inventory.inventory_commitment().as_bytes() == &[0; 32]
        {
            return Err(RealizationPlanError::EvidenceConflict);
        }
        let consumer = tree
            .record(assignment.sandbox())
            .ok_or(RealizationPlanError::UnknownSandbox)?;
        if tree.project() != assignment.project()
            || consumer.desired_generation() != assignment.desired_generation()
            || consumer.incarnation() != Some(assignment.incarnation())
        {
            return Err(RealizationPlanError::StaleEvidence);
        }

        let detach_commitment = commit_detach(
            tree.tree_generation(),
            assignment,
            authority,
            inventory,
            *recipe_commitment,
            &detach_after,
        )?;
        Ok(Self {
            project: assignment.project(),
            tree_generation: tree.tree_generation(),
            attachment: *attachment,
            generation: *generation,
            consumer: assignment.sandbox(),
            consumer_incarnation: assignment.incarnation(),
            consumer_node: assignment.node(),
            assignment_epoch: assignment.assignment_epoch(),
            observation_set_commitment: assignment.observation_set_commitment(),
            namespace_generation: assignment.namespace_generation(),
            destination_slot: inventory.destination_slot(),
            recipe_commitment: *recipe_commitment,
            assignment_commitment: assignment.assignment_commitment(),
            request_commitment: authority.request_commitment(),
            policy_commitment: authority.policy_commitment(),
            inventory_commitment: inventory.inventory_commitment(),
            detach_after,
            detach_commitment,
        })
    }

    /// Reconstructs one canonical durable detach without fabricating its live
    /// assignment, policy, or inventory evidence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_canonical_parts(
        project: ProjectId,
        tree_generation: Revision,
        attachment: AttachmentId,
        generation: DesiredGeneration,
        consumer: SandboxId,
        consumer_incarnation: IncarnationId,
        consumer_node: NodeId,
        assignment_epoch: AssignmentEpoch,
        observation_set_commitment: ObjectDigest,
        namespace_generation: NamespaceGeneration,
        destination_slot: AttachmentSlotId,
        recipe_commitment: ObjectDigest,
        assignment_commitment: ObjectDigest,
        request_commitment: ObjectDigest,
        policy_commitment: ObjectDigest,
        inventory_commitment: ObjectDigest,
        detach_after: Vec<AttachmentId>,
        detach_commitment: ObjectDigest,
    ) -> Result<Self, RealizationPlanError> {
        validate_dependencies(attachment, &detach_after)?;
        if project.as_bytes() == &[0; 16]
            || tree_generation.get() == 0
            || attachment.as_bytes() == &[0; 16]
            || generation.get() == 0
            || consumer.as_bytes() == &[0; 16]
            || consumer_incarnation.as_bytes() == &[0; 16]
            || consumer_node.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
            || observation_set_commitment.as_bytes() == &[0; 32]
            || namespace_generation.get() == 0
            || destination_slot.as_bytes() == &[0; 16]
            || recipe_commitment.as_bytes() == &[0; 32]
            || assignment_commitment.as_bytes() == &[0; 32]
            || request_commitment.as_bytes() == &[0; 32]
            || policy_commitment.as_bytes() == &[0; 32]
            || inventory_commitment.as_bytes() == &[0; 32]
            || detach_commitment.as_bytes() == &[0; 32]
        {
            return Err(RealizationPlanError::UnspecifiedIdentity);
        }

        let detach = Self {
            project,
            tree_generation,
            attachment,
            generation,
            consumer,
            consumer_incarnation,
            consumer_node,
            assignment_epoch,
            observation_set_commitment,
            namespace_generation,
            destination_slot,
            recipe_commitment,
            assignment_commitment,
            request_commitment,
            policy_commitment,
            inventory_commitment,
            detach_after,
            detach_commitment,
        };
        if canonical_detach_commitment(&detach)? != detach_commitment {
            return Err(RealizationPlanError::EvidenceConflict);
        }
        Ok(detach)
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the exact project-tree snapshot used to derive this action.
    #[must_use]
    pub const fn tree_generation(&self) -> Revision {
        self.tree_generation
    }

    /// Returns the detached attachment.
    #[must_use]
    pub const fn attachment(&self) -> AttachmentId {
        self.attachment
    }

    /// Returns the exact detached generation.
    #[must_use]
    pub const fn generation(&self) -> DesiredGeneration {
        self.generation
    }

    /// Returns the consumer sandbox.
    #[must_use]
    pub const fn consumer(&self) -> SandboxId {
        self.consumer
    }

    /// Returns the consumer incarnation.
    #[must_use]
    pub const fn consumer_incarnation(&self) -> IncarnationId {
        self.consumer_incarnation
    }

    /// Returns the current consumer node bound by assignment evidence.
    #[must_use]
    pub const fn consumer_node(&self) -> NodeId {
        self.consumer_node
    }

    /// Returns the current consumer assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the shared assignment and inventory observation set.
    #[must_use]
    pub const fn observation_set_commitment(&self) -> ObjectDigest {
        self.observation_set_commitment
    }

    /// Returns the namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> NamespaceGeneration {
        self.namespace_generation
    }

    /// Returns the destination slot.
    #[must_use]
    pub const fn destination_slot(&self) -> AttachmentSlotId {
        self.destination_slot
    }

    /// Returns the current recipe commitment.
    #[must_use]
    pub const fn recipe_commitment(&self) -> ObjectDigest {
        self.recipe_commitment
    }

    /// Returns the assignment evidence commitment.
    #[must_use]
    pub const fn assignment_commitment(&self) -> ObjectDigest {
        self.assignment_commitment
    }

    /// Returns the authorized detach request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the detach policy evidence commitment.
    #[must_use]
    pub const fn policy_commitment(&self) -> ObjectDigest {
        self.policy_commitment
    }

    /// Returns the inventory evidence commitment.
    #[must_use]
    pub const fn inventory_commitment(&self) -> ObjectDigest {
        self.inventory_commitment
    }

    /// Returns attachments that must detach before this attachment.
    #[must_use]
    pub fn detach_after(&self) -> &[AttachmentId] {
        &self.detach_after
    }

    /// Returns the complete detach-plan commitment.
    #[must_use]
    pub const fn detach_commitment(&self) -> ObjectDigest {
        self.detach_commitment
    }

    fn destination_key(&self) -> (SandboxId, AttachmentSlotId) {
        (self.consumer, self.destination_slot)
    }
}

/// Names the durable monotonic stages of one realization effect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RealizationStageV1 {
    /// Desired recipe and operation commitment are durable.
    Planned = 0,
    /// New realization exists but is not exposed.
    Prepared = 1,
    /// New realization is the namespace top for new path resolution.
    Published = 2,
    /// Post-publication identity and attributes were observed.
    Verified = 3,
    /// Previous realization is no longer selected and may retain open users.
    Draining = 4,
    /// Previous realization was authoritatively reclaimed.
    Reaped = 5,
    /// An unpublished realization was authoritatively abandoned.
    Aborted = 6,
    /// A published realization entered a terminal fail-closed state.
    Faulted = 7,
}

/// Names one action in the committed global transaction execution order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RealizationTransactionActionV1 {
    /// Publishes one attachment recipe.
    Publish(AttachmentId),
    /// Detaches one exact current attachment.
    Detach(AttachmentId),
}

impl RealizationTransactionActionV1 {
    /// Returns the stable canonical action discriminant.
    #[must_use]
    pub const fn discriminant(self) -> u8 {
        match self {
            Self::Publish(_) => 0,
            Self::Detach(_) => 1,
        }
    }

    /// Returns the action attachment identity.
    #[must_use]
    pub const fn attachment(self) -> AttachmentId {
        match self {
            Self::Publish(attachment) | Self::Detach(attachment) => attachment,
        }
    }
}

/// Stores a complete immutable realization transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewRealizationPlanV1 {
    project: ProjectId,
    tree_generation: Revision,
    observation_set_commitment: ObjectDigest,
    publications: Vec<AttachmentRealizationV1>,
    detaches: Vec<AttachmentDetachV1>,
    publication_postorder: Vec<AttachmentId>,
    detach_postorder: Vec<AttachmentId>,
    execution_order: Vec<RealizationTransactionActionV1>,
    plan_commitment: ObjectDigest,
}

impl ViewRealizationPlanV1 {
    /// Validates a complete cross-attachment transaction and derives orderings.
    ///
    /// Publications are dependency-first. Detaches are prerequisite-first using
    /// explicit `detach_after` edges. A destination may appear only once across
    /// both action sets, except that an occupied publication carries its prior
    /// detach inside the atomic replacement recipe.
    ///
    /// # Errors
    ///
    /// Returns [`RealizationPlanError`] for mixed projects, noncanonical sets,
    /// duplicate destinations, absent ordering edges, cycles, or excessive size.
    pub fn new(
        project: ProjectId,
        publications: Vec<AttachmentRealizationV1>,
        detaches: Vec<AttachmentDetachV1>,
    ) -> Result<Self, RealizationPlanError> {
        if project.as_bytes() == &[0; 16] {
            return Err(RealizationPlanError::UnspecifiedIdentity);
        }
        let (tree_generation, observation_set_commitment) =
            validate_action_sets(project, &publications, &detaches)?;

        let publication_edges: BTreeMap<_, _> = publications
            .iter()
            .map(|action| (action.attachment(), action.dependencies()))
            .collect();
        let detach_edges: BTreeMap<_, _> = detaches
            .iter()
            .map(|action| (action.attachment(), action.detach_after()))
            .collect();
        let publication_postorder = topological_order(&publication_edges)?;
        let detach_postorder = topological_order(&detach_edges)?;
        let action_count = publication_postorder
            .len()
            .checked_add(detach_postorder.len())
            .ok_or(RealizationPlanError::Capacity)?;
        let mut execution_order = Vec::new();
        execution_order
            .try_reserve_exact(action_count)
            .map_err(|_| RealizationPlanError::Capacity)?;
        execution_order.extend(
            publication_postorder
                .iter()
                .copied()
                .map(RealizationTransactionActionV1::Publish),
        );
        execution_order.extend(
            detach_postorder
                .iter()
                .copied()
                .map(RealizationTransactionActionV1::Detach),
        );
        let plan_commitment = commit_plan(
            project,
            tree_generation,
            observation_set_commitment,
            &publications,
            &detaches,
            &publication_postorder,
            &detach_postorder,
            &execution_order,
        )?;

        Ok(Self {
            project,
            tree_generation,
            observation_set_commitment,
            publications,
            detaches,
            publication_postorder,
            detach_postorder,
            execution_order,
            plan_commitment,
        })
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the one tree generation shared by every action.
    #[must_use]
    pub const fn tree_generation(&self) -> Revision {
        self.tree_generation
    }

    /// Returns the one current observation set shared by every action.
    #[must_use]
    pub const fn observation_set_commitment(&self) -> ObjectDigest {
        self.observation_set_commitment
    }

    /// Returns publication recipes in canonical attachment order.
    #[must_use]
    pub fn publications(&self) -> &[AttachmentRealizationV1] {
        &self.publications
    }

    /// Returns detach recipes in canonical attachment order.
    #[must_use]
    pub fn detaches(&self) -> &[AttachmentDetachV1] {
        &self.detaches
    }

    /// Returns dependency-first publication order.
    #[must_use]
    pub fn publication_postorder(&self) -> &[AttachmentId] {
        &self.publication_postorder
    }

    /// Returns prerequisite-first explicit detach order.
    #[must_use]
    pub fn detach_postorder(&self) -> &[AttachmentId] {
        &self.detach_postorder
    }

    /// Returns the globally committed effect order.
    ///
    /// Publication dependencies and detach prerequisites occur first. The
    /// exact reverse order is therefore safe for stage-valid compensation.
    #[must_use]
    pub fn execution_order(&self) -> &[RealizationTransactionActionV1] {
        &self.execution_order
    }

    /// Returns the canonical complete transaction commitment.
    #[must_use]
    pub const fn plan_commitment(&self) -> ObjectDigest {
        self.plan_commitment
    }
}

fn validate_intent_evidence(
    tree: &SandboxTreeV1,
    intent: &AttachmentIntent,
    assignment: &CurrentAssignmentEvidenceV1,
    source: &RetainedViewSourceEvidenceV1,
    authority: &VerifiedAttachmentAuthorityV1,
    inventory: &CurrentSlotInventoryEvidenceV1,
) -> Result<(), RealizationPlanError> {
    let (consumer, consumer_incarnation) = intent.consumer();
    let (view, view_revision) = intent.source_view();
    if intent_commitment(intent)? != authority.request_commitment()
        || lease_commitment(intent) != authority.lease_commitment()
        || tree.project() != assignment.project()
        || assignment.project() != source.project()
        || assignment.sandbox() != consumer
        || assignment.incarnation() != consumer_incarnation
        || assignment.namespace_generation() != intent.expected_namespace_generation()
        || authority.attachment() != intent.id()
        || authority.desired_generation() != intent.desired_generation()
        || source.view() != view
        || source.view_revision() != view_revision
        || source.view_descriptor() != intent.view()
        || inventory.sandbox() != consumer
        || inventory.incarnation() != consumer_incarnation
        || inventory.namespace_generation() != intent.expected_namespace_generation()
        || inventory.node() != assignment.node()
        || inventory.assignment_epoch() != assignment.assignment_epoch()
        || inventory.observation_set_commitment() != assignment.observation_set_commitment()
        || inventory.destination_slot() != intent.destination_slot()
    {
        return Err(RealizationPlanError::EvidenceConflict);
    }
    let consumer_record = tree
        .record(consumer)
        .ok_or(RealizationPlanError::UnknownSandbox)?;
    let source_record = tree
        .record(source.owner())
        .ok_or(RealizationPlanError::UnknownSandbox)?;
    if consumer_record.desired_generation() != assignment.desired_generation()
        || consumer_record.incarnation() != Some(consumer_incarnation)
        || source_record.desired_generation() != source.owner_generation()
    {
        return Err(RealizationPlanError::StaleEvidence);
    }
    let live = intent.consistency() == AttachmentConsistency::LocalLive;
    if live {
        if intent.source_incarnation() != source.source_incarnation()
            || source_record.incarnation() != source.source_incarnation()
            || source.source_node() != Some(assignment.node())
            || source
                .source_namespace_generation()
                .is_none_or(|generation| generation.get() == 0)
            || source
                .source_assignment_epoch()
                .is_none_or(|epoch| epoch.get() == 0)
            || source.current_observation_set_commitment()
                != Some(assignment.observation_set_commitment())
        {
            return Err(RealizationPlanError::StaleEvidence);
        }
    } else if source.source_incarnation().is_some()
        || source.source_node().is_some()
        || source.source_namespace_generation().is_some()
        || source.source_assignment_epoch().is_some()
        || source.current_observation_set_commitment().is_some()
    {
        return Err(RealizationPlanError::EvidenceConflict);
    }
    if assignment.assignment_epoch().get() == 0
        || assignment.node().as_bytes() == &[0; 16]
        || assignment.observation_set_commitment().as_bytes() == &[0; 32]
        || assignment.assignment_commitment().as_bytes() == &[0; 32]
        || source.export().as_bytes() == &[0; 16]
        || source.source_handle_commitment().as_bytes() == &[0; 32]
        || source.retention_proof_commitment().as_bytes() == &[0; 32]
        || authority.request_commitment().as_bytes() == &[0; 32]
        || authority.policy_commitment().as_bytes() == &[0; 32]
        || authority.lease_commitment().as_bytes() == &[0; 32]
        || inventory.inventory_commitment().as_bytes() == &[0; 32]
    {
        return Err(RealizationPlanError::UnspecifiedIdentity);
    }
    Ok(())
}

fn intent_commitment(intent: &AttachmentIntent) -> Result<ObjectDigest, RealizationPlanError> {
    let encoded = aos_sandbox_core::encode_attachment_intent_v1(intent)
        .map_err(|_| RealizationPlanError::UnspecifiedIdentity)?;
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.attachment-intent.v1\0");
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn lease_commitment(intent: &AttachmentIntent) -> ObjectDigest {
    let lease = intent.lease();
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.attachment-lease.v1\0");
    hasher.update(lease.id().as_bytes());
    hasher.update(lease.issued_seconds().to_be_bytes());
    hasher.update(lease.expires_seconds().to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn validate_replacement(
    intent: &AttachmentIntent,
    inventory: &CurrentSlotInventoryEvidenceV1,
    replacement: Option<ReplacementTransactionV1>,
) -> Result<(), RealizationPlanError> {
    match inventory.state() {
        SlotInventoryStateV1::ImmediatePredecessor {
            attachment,
            generation,
            recipe_commitment,
        } if attachment.as_bytes() == &[0; 16]
            || generation.get() == 0
            || recipe_commitment.as_bytes() == &[0; 32] =>
        {
            return Err(RealizationPlanError::UnspecifiedIdentity);
        }
        _ => {}
    }
    match (inventory.state(), replacement) {
        (SlotInventoryStateV1::Empty, None) => Ok(()),
        (SlotInventoryStateV1::Empty, Some(_)) => Err(RealizationPlanError::UnexpectedReplacement),
        (
            SlotInventoryStateV1::ImmediatePredecessor {
                attachment,
                generation,
                recipe_commitment,
            },
            Some(transaction),
        ) if transaction.predecessor() == *attachment
            && transaction.successor() == intent.id()
            && transaction.predecessor_generation() == *generation
            && transaction.predecessor_recipe_commitment() == *recipe_commitment
            && replacement_generation_is_valid(intent, transaction)
            && transaction.transaction_commitment().as_bytes() != &[0; 32] =>
        {
            Ok(())
        }
        (SlotInventoryStateV1::ImmediatePredecessor { .. }, _) => {
            Err(RealizationPlanError::MissingImmediatePredecessor)
        }
    }
}

fn replacement_generation_is_valid(
    intent: &AttachmentIntent,
    transaction: ReplacementTransactionV1,
) -> bool {
    if transaction.predecessor() == intent.id() {
        return transaction
            .predecessor_generation()
            .checked_next()
            .is_ok_and(|generation| generation == intent.desired_generation());
    }

    intent.desired_generation().get() == 1
}

fn validate_dependencies(
    subject: AttachmentId,
    dependencies: &[AttachmentId],
) -> Result<(), RealizationPlanError> {
    if subject.as_bytes() == &[0; 16]
        || dependencies.len() > MAXIMUM_REALIZATION_DEPENDENCIES
        || dependencies
            .iter()
            .any(|dependency| dependency.as_bytes() == &[0; 16])
        || dependencies.contains(&subject)
        || !dependencies.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(RealizationPlanError::DependenciesNotCanonical);
    }
    Ok(())
}

fn validate_action_sets(
    project: ProjectId,
    publications: &[AttachmentRealizationV1],
    detaches: &[AttachmentDetachV1],
) -> Result<(Revision, ObjectDigest), RealizationPlanError> {
    let action_count = publications
        .len()
        .checked_add(detaches.len())
        .ok_or(RealizationPlanError::Capacity)?;
    let edge_count = publications
        .iter()
        .map(|action| action.dependencies().len())
        .chain(detaches.iter().map(|action| action.detach_after().len()))
        .try_fold(0_usize, |total, count| total.checked_add(count))
        .ok_or(RealizationPlanError::Capacity)?;
    if action_count == 0
        || action_count > MAXIMUM_REALIZATION_ACTIONS
        || edge_count > MAXIMUM_REALIZATION_DEPENDENCIES
        || !publications
            .windows(2)
            .all(|pair| pair[0].attachment() < pair[1].attachment())
        || !detaches
            .windows(2)
            .all(|pair| pair[0].attachment() < pair[1].attachment())
    {
        return Err(RealizationPlanError::ActionsNotCanonical);
    }

    let first_tree_generation = publications
        .first()
        .map(AttachmentRealizationV1::tree_generation)
        .or_else(|| detaches.first().map(AttachmentDetachV1::tree_generation))
        .ok_or(RealizationPlanError::ActionsNotCanonical)?;
    let first_observation_set = publications
        .first()
        .map(AttachmentRealizationV1::observation_set_commitment)
        .or_else(|| {
            detaches
                .first()
                .map(AttachmentDetachV1::observation_set_commitment)
        })
        .ok_or(RealizationPlanError::ActionsNotCanonical)?;
    let mut identities = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    for (identity, destination, action_project, tree_generation, observation_set) in publications
        .iter()
        .map(|action| {
            (
                action.attachment(),
                action.destination_key(),
                action.project(),
                action.tree_generation(),
                action.observation_set_commitment(),
            )
        })
        .chain(detaches.iter().map(|action| {
            (
                action.attachment(),
                action.destination_key(),
                action.project(),
                action.tree_generation(),
                action.observation_set_commitment(),
            )
        }))
    {
        if action_project != project {
            return Err(RealizationPlanError::ProjectMismatch);
        }
        if tree_generation != first_tree_generation || observation_set != first_observation_set {
            return Err(RealizationPlanError::MixedObservationSnapshot);
        }
        if !identities.insert(identity) {
            return Err(RealizationPlanError::DuplicateAttachment);
        }
        if !destinations.insert(destination) {
            return Err(RealizationPlanError::DuplicateDestination);
        }
    }
    Ok((first_tree_generation, first_observation_set))
}

fn topological_order(
    edges: &BTreeMap<AttachmentId, &[AttachmentId]>,
) -> Result<Vec<AttachmentId>, RealizationPlanError> {
    let mut pending_dependencies: BTreeMap<_, usize> =
        edges.keys().map(|attachment| (*attachment, 0)).collect();
    let mut dependents = BTreeMap::<AttachmentId, Vec<AttachmentId>>::new();
    for (attachment, dependencies) in edges {
        for dependency in *dependencies {
            if !edges.contains_key(dependency) {
                return Err(RealizationPlanError::MissingDependency);
            }
            let count = pending_dependencies
                .get_mut(attachment)
                .ok_or(RealizationPlanError::MissingDependency)?;
            *count = count.checked_add(1).ok_or(RealizationPlanError::Capacity)?;
            dependents.entry(*dependency).or_default().push(*attachment);
        }
    }
    let mut ready: BTreeSet<_> = pending_dependencies
        .iter()
        .filter_map(|(attachment, count)| (*count == 0).then_some(*attachment))
        .collect();
    let mut order = Vec::new();
    order
        .try_reserve_exact(edges.len())
        .map_err(|_| RealizationPlanError::Capacity)?;
    while let Some(attachment) = ready.pop_first() {
        order.push(attachment);
        if let Some(entries) = dependents.get(&attachment) {
            for dependent in entries {
                let count = pending_dependencies
                    .get_mut(dependent)
                    .ok_or(RealizationPlanError::MissingDependency)?;
                *count = count
                    .checked_sub(1)
                    .ok_or(RealizationPlanError::DependencyCycle)?;
                if *count == 0 {
                    ready.insert(*dependent);
                }
            }
        }
    }
    if order.len() != edges.len() {
        return Err(RealizationPlanError::DependencyCycle);
    }
    Ok(order)
}

fn commit_recipe(
    tree_generation: Revision,
    intent: &AttachmentIntent,
    assignment: &CurrentAssignmentEvidenceV1,
    source: &RetainedViewSourceEvidenceV1,
    authority: &VerifiedAttachmentAuthorityV1,
    inventory: &CurrentSlotInventoryEvidenceV1,
    replacement: Option<ReplacementTransactionV1>,
    dependencies: &[AttachmentId],
) -> Result<ObjectDigest, RealizationPlanError> {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.attachment-realization-recipe.v1\0");
    hasher.update(assignment.project().as_bytes());
    hasher.update(tree_generation.get().to_be_bytes());
    hasher.update(intent.id().as_bytes());
    hasher.update(intent.desired_generation().get().to_be_bytes());
    let (consumer, incarnation) = intent.consumer();
    hasher.update(consumer.as_bytes());
    hasher.update(incarnation.as_bytes());
    hasher.update(intent.expected_namespace_generation().get().to_be_bytes());
    hasher.update(intent.destination_slot().as_bytes());
    let (view, revision) = intent.source_view();
    hasher.update(view.as_bytes());
    hasher.update(revision.get().to_be_bytes());
    hasher.update(intent.view().digest().as_bytes());
    hasher.update(intent.view().encoded_size().to_be_bytes());
    hasher.update(assignment.node().as_bytes());
    hasher.update(assignment.assignment_epoch().get().to_be_bytes());
    hasher.update(assignment.observation_set_commitment().as_bytes());
    hasher.update(assignment.assignment_commitment().as_bytes());
    hasher.update(source.owner().as_bytes());
    hasher.update(source.owner_generation().get().to_be_bytes());
    hasher.update(source.export().as_bytes());
    match source.source_node() {
        Some(node) => {
            hasher.update([1]);
            hasher.update(node.as_bytes());
        }
        None => hasher.update([0]),
    }
    match source.source_namespace_generation() {
        Some(generation) => {
            hasher.update([1]);
            hasher.update(generation.get().to_be_bytes());
        }
        None => hasher.update([0]),
    }
    match source.source_assignment_epoch() {
        Some(epoch) => {
            hasher.update([1]);
            hasher.update(epoch.get().to_be_bytes());
        }
        None => hasher.update([0]),
    }
    match source.current_observation_set_commitment() {
        Some(commitment) => {
            hasher.update([1]);
            hasher.update(commitment.as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(source.source_handle_commitment().as_bytes());
    hasher.update(source.retention_proof_commitment().as_bytes());
    hasher.update(authority.request_commitment().as_bytes());
    hasher.update(authority.policy_commitment().as_bytes());
    hasher.update(authority.lease_commitment().as_bytes());
    hasher.update(inventory.inventory_commitment().as_bytes());
    match replacement {
        Some(transaction) => {
            hasher.update([1]);
            hasher.update(transaction.predecessor().as_bytes());
            hasher.update(transaction.predecessor_generation().get().to_be_bytes());
            hasher.update(transaction.predecessor_recipe_commitment().as_bytes());
            hasher.update(transaction.transaction_commitment().as_bytes());
        }
        None => hasher.update([0]),
    }
    hash_attachments(&mut hasher, dependencies)?;
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn canonical_recipe_commitment(
    action: &AttachmentRealizationV1,
) -> Result<ObjectDigest, RealizationPlanError> {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.attachment-realization-recipe.v1\0");
    hasher.update(action.project.as_bytes());
    hasher.update(action.tree_generation.get().to_be_bytes());
    hasher.update(action.intent.id().as_bytes());
    hasher.update(action.intent.desired_generation().get().to_be_bytes());
    let (consumer, incarnation) = action.intent.consumer();
    hasher.update(consumer.as_bytes());
    hasher.update(incarnation.as_bytes());
    hasher.update(
        action
            .intent
            .expected_namespace_generation()
            .get()
            .to_be_bytes(),
    );
    hasher.update(action.intent.destination_slot().as_bytes());
    let (view, revision) = action.intent.source_view();
    hasher.update(view.as_bytes());
    hasher.update(revision.get().to_be_bytes());
    hasher.update(action.intent.view().digest().as_bytes());
    hasher.update(action.intent.view().encoded_size().to_be_bytes());
    hasher.update(action.consumer_node.as_bytes());
    hasher.update(action.assignment_epoch.get().to_be_bytes());
    hasher.update(action.observation_set_commitment.as_bytes());
    hasher.update(action.assignment_commitment.as_bytes());
    hasher.update(action.source_owner.as_bytes());
    hasher.update(action.source_owner_generation.get().to_be_bytes());
    hasher.update(action.source_export.as_bytes());
    match action.source_node {
        Some(node) => {
            hasher.update([1]);
            hasher.update(node.as_bytes());
        }
        None => hasher.update([0]),
    }
    match action.source_namespace_generation {
        Some(generation) => {
            hasher.update([1]);
            hasher.update(generation.get().to_be_bytes());
        }
        None => hasher.update([0]),
    }
    match action.source_assignment_epoch {
        Some(epoch) => {
            hasher.update([1]);
            hasher.update(epoch.get().to_be_bytes());
        }
        None => hasher.update([0]),
    }
    if action.intent.consistency() == AttachmentConsistency::LocalLive {
        hasher.update([1]);
        hasher.update(action.observation_set_commitment.as_bytes());
    } else {
        hasher.update([0]);
    }
    hasher.update(action.source_handle_commitment.as_bytes());
    hasher.update(action.source_retention_commitment.as_bytes());
    hasher.update(action.request_commitment.as_bytes());
    hasher.update(action.policy_commitment.as_bytes());
    hasher.update(action.lease_commitment.as_bytes());
    hasher.update(action.inventory_commitment.as_bytes());
    match action.replacement {
        Some(transaction) => {
            hasher.update([1]);
            hasher.update(transaction.predecessor().as_bytes());
            hasher.update(transaction.predecessor_generation().get().to_be_bytes());
            hasher.update(transaction.predecessor_recipe_commitment().as_bytes());
            hasher.update(transaction.transaction_commitment().as_bytes());
        }
        None => hasher.update([0]),
    }
    hash_attachments(&mut hasher, &action.dependencies)?;
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn commit_detach(
    tree_generation: Revision,
    assignment: &CurrentAssignmentEvidenceV1,
    authority: &VerifiedDetachAuthorityV1,
    inventory: &CurrentSlotInventoryEvidenceV1,
    recipe_commitment: ObjectDigest,
    detach_after: &[AttachmentId],
) -> Result<ObjectDigest, RealizationPlanError> {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.attachment-detach.v1\0");
    hasher.update(assignment.project().as_bytes());
    hasher.update(tree_generation.get().to_be_bytes());
    hasher.update(authority.attachment().as_bytes());
    hasher.update(authority.attachment_generation().get().to_be_bytes());
    hasher.update(assignment.sandbox().as_bytes());
    hasher.update(assignment.incarnation().as_bytes());
    hasher.update(assignment.namespace_generation().get().to_be_bytes());
    hasher.update(inventory.destination_slot().as_bytes());
    hasher.update(assignment.node().as_bytes());
    hasher.update(assignment.assignment_epoch().get().to_be_bytes());
    hasher.update(assignment.observation_set_commitment().as_bytes());
    hasher.update(assignment.assignment_commitment().as_bytes());
    hasher.update(authority.request_commitment().as_bytes());
    hasher.update(authority.policy_commitment().as_bytes());
    hasher.update(inventory.inventory_commitment().as_bytes());
    hasher.update(recipe_commitment.as_bytes());
    hash_attachments(&mut hasher, detach_after)?;
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn canonical_detach_commitment(
    detach: &AttachmentDetachV1,
) -> Result<ObjectDigest, RealizationPlanError> {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.attachment-detach.v1\0");
    hasher.update(detach.project.as_bytes());
    hasher.update(detach.tree_generation.get().to_be_bytes());
    hasher.update(detach.attachment.as_bytes());
    hasher.update(detach.generation.get().to_be_bytes());
    hasher.update(detach.consumer.as_bytes());
    hasher.update(detach.consumer_incarnation.as_bytes());
    hasher.update(detach.namespace_generation.get().to_be_bytes());
    hasher.update(detach.destination_slot.as_bytes());
    hasher.update(detach.consumer_node.as_bytes());
    hasher.update(detach.assignment_epoch.get().to_be_bytes());
    hasher.update(detach.observation_set_commitment.as_bytes());
    hasher.update(detach.assignment_commitment.as_bytes());
    hasher.update(detach.request_commitment.as_bytes());
    hasher.update(detach.policy_commitment.as_bytes());
    hasher.update(detach.inventory_commitment.as_bytes());
    hasher.update(detach.recipe_commitment.as_bytes());
    hash_attachments(&mut hasher, &detach.detach_after)?;
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn commit_plan(
    project: ProjectId,
    tree_generation: Revision,
    observation_set_commitment: ObjectDigest,
    publications: &[AttachmentRealizationV1],
    detaches: &[AttachmentDetachV1],
    publication_order: &[AttachmentId],
    detach_order: &[AttachmentId],
    execution_order: &[RealizationTransactionActionV1],
) -> Result<ObjectDigest, RealizationPlanError> {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.view-realization-plan.v1\0");
    hasher.update(project.as_bytes());
    hasher.update(tree_generation.get().to_be_bytes());
    hasher.update(observation_set_commitment.as_bytes());
    hash_len(&mut hasher, publications.len())?;
    for action in publications {
        hasher.update(action.recipe_commitment().as_bytes());
    }
    hash_len(&mut hasher, detaches.len())?;
    for action in detaches {
        hasher.update(action.detach_commitment().as_bytes());
    }
    hash_attachments(&mut hasher, publication_order)?;
    hash_attachments(&mut hasher, detach_order)?;
    hash_len(&mut hasher, execution_order.len())?;
    for action in execution_order {
        hasher.update([action.discriminant()]);
        hasher.update(action.attachment().as_bytes());
    }
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn hash_attachments(
    hasher: &mut Sha256,
    attachments: &[AttachmentId],
) -> Result<(), RealizationPlanError> {
    hash_len(hasher, attachments.len())?;
    for attachment in attachments {
        hasher.update(attachment.as_bytes());
    }
    Ok(())
}

fn hash_len(hasher: &mut Sha256, length: usize) -> Result<(), RealizationPlanError> {
    let length = u32::try_from(length).map_err(|_| RealizationPlanError::Capacity)?;
    hasher.update(length.to_be_bytes());
    Ok(())
}

/// Reports malformed, stale, or incomplete realization planning input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RealizationPlanError {
    /// An identity, generation, or evidence commitment is zero.
    #[error("view realization contains an unspecified identity")]
    UnspecifiedIdentity,
    /// Evidence fields disagree about the exact request or resource.
    #[error("view realization evidence conflicts")]
    EvidenceConflict,
    /// Evidence no longer matches current tree state.
    #[error("view realization evidence is stale")]
    StaleEvidence,
    /// An evidence owner is absent from the current tree.
    #[error("view realization names an unknown sandbox")]
    UnknownSandbox,
    /// One action's dependencies are excessive, duplicated, or unordered.
    #[error("view realization dependencies are not canonical")]
    DependenciesNotCanonical,
    /// Action collections are excessive, duplicated, or unordered.
    #[error("view realization actions are not canonical")]
    ActionsNotCanonical,
    /// Action entries belong to different projects.
    #[error("view realization action belongs to another project")]
    ProjectMismatch,
    /// Actions were derived from different tree or current-inventory snapshots.
    #[error("view realization actions mix tree or observation snapshots")]
    MixedObservationSnapshot,
    /// An attachment identity occurs in more than one action.
    #[error("view realization repeats an attachment")]
    DuplicateAttachment,
    /// Two actions select the same current destination slot.
    #[error("view realization destination slots must be unique")]
    DuplicateDestination,
    /// A dependency does not have a matching action in this transaction.
    #[error("view realization dependency is absent")]
    MissingDependency,
    /// Attachment ordering edges contain a cycle.
    #[error("view realization dependencies contain a cycle")]
    DependencyCycle,
    /// An occupied slot lacks exact immediate-predecessor transaction evidence.
    #[error("view realization lacks exact immediate predecessor evidence")]
    MissingImmediatePredecessor,
    /// An empty slot unexpectedly carries replacement state.
    #[error("empty view realization slot carries replacement evidence")]
    UnexpectedReplacement,
    /// Checked size or allocation admission was exhausted.
    #[error("view realization capacity is exhausted")]
    Capacity,
}
