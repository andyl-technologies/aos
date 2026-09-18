//! Durable source-model snapshot and realization recovery reducers.
//!
//! Recovery outputs are diagnostics or inert work descriptions. They never
//! recreate an authority, infer a mount from a path, or perform an effect.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::model::Snapshot;
use aos_sandbox_core::{
    AttachmentId, DesiredGeneration, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId,
    Revision, SandboxId, SnapshotId, descriptor_for_bytes,
};
use sha2::{Digest as _, Sha256};

use super::codec::{HierarchyCodecError, tree_commitment_v1};
use super::evidence::RetainedSnapshotManifestV1;
use super::exports::SubtreeExportClosureV1;
use super::graph::SandboxTreeV1;
use super::protected_evidence::ProtectedCurrentEvidenceAuthorityV1;
use super::protected_journal::CurrentHierarchyProtectedEvidenceV1;
use super::realizer::{
    AttachmentDetachV1, AttachmentRealizationV1, RealizationStageV1, ReplacementTransactionV1,
    ViewRealizationPlanV1,
};

/// Maximum monotonic observations retained for one realization operation.
pub const MAXIMUM_REALIZATION_STAGE_HISTORY: usize = 64;

/// Records a prepared crash-consistent hierarchy snapshot manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedHierarchySnapshotV1 {
    project: ProjectId,
    snapshot: SnapshotId,
    subtree_root: SandboxId,
    captured_tree_generation: Revision,
    captured_sandbox_generation: DesiredGeneration,
    tree_commitment: ObjectDigest,
    export_closure_commitment: ObjectDigest,
    portable_snapshot: Snapshot,
    manifest: ObjectDescriptor,
    retention_plan_commitment: ObjectDigest,
    preparation_commitment: ObjectDigest,
}

impl PreparedHierarchySnapshotV1 {
    /// Prepares an immutable snapshot identity from exact tree and export state.
    ///
    /// Preparation proves logical completeness only. It is not committed or
    /// usable for stable inspection until [`CommittedHierarchySnapshotV1`]
    /// joins a verified physical retention proof.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError`] for absent roots, zero fields,
    /// closure mismatch, mutable reachable source, or canonical tree
    /// commitment failure.
    pub fn new(
        tree: &SandboxTreeV1,
        snapshot: SnapshotId,
        subtree_root: SandboxId,
        export_closure: &SubtreeExportClosureV1,
        portable_snapshot: Snapshot,
        manifest: ObjectDescriptor,
        retention_plan_commitment: ObjectDigest,
    ) -> Result<Self, HierarchyRecoveryError> {
        if snapshot.as_bytes() == &[0; 16]
            || subtree_root.as_bytes() == &[0; 16]
            || manifest.encoded_size() == 0
            || manifest.digest().as_bytes() == &[0; 32]
            || manifest.media_type().as_str() != PortableMediaType::Snapshot.as_str()
            || retention_plan_commitment.as_bytes() == &[0; 32]
        {
            return Err(HierarchyRecoveryError::UnspecifiedIdentity);
        }
        let sandbox = tree
            .record(subtree_root)
            .ok_or(HierarchyRecoveryError::UnknownSandbox)?;
        if export_closure.project() != tree.project()
            || export_closure.tree_generation() != tree.tree_generation()
            || export_closure.root() != subtree_root
        {
            return Err(HierarchyRecoveryError::ExportClosureMismatch);
        }
        if !export_closure.is_fully_immutable() {
            return Err(HierarchyRecoveryError::MutableSnapshotSource);
        }
        let source_assignment = portable_snapshot.source_assignment();
        let expected_ancestry = tree
            .ancestry(subtree_root)
            .map_err(|_| HierarchyRecoveryError::UnknownSandbox)?;
        let encoded_snapshot = aos_sandbox_core::format::encode_snapshot(&portable_snapshot);
        let reproduced_manifest =
            descriptor_for_bytes(manifest.media_type().clone(), &encoded_snapshot);
        if source_assignment.sandbox() != subtree_root
            || sandbox.incarnation() != Some(source_assignment.incarnation())
            || source_assignment.epoch().get() == 0
            || portable_snapshot.ancestry() != expected_ancestry
            || reproduced_manifest != manifest
        {
            return Err(HierarchyRecoveryError::PortableSnapshotMismatch);
        }
        let tree_commitment = tree_commitment_v1(tree)?;
        let preparation_commitment = commit_snapshot_preparation(
            tree.project(),
            snapshot,
            subtree_root,
            tree.tree_generation(),
            sandbox.desired_generation(),
            tree_commitment,
            export_closure.commitment(),
            &manifest,
            retention_plan_commitment,
        );
        Ok(Self {
            project: tree.project(),
            snapshot,
            subtree_root,
            captured_tree_generation: tree.tree_generation(),
            captured_sandbox_generation: sandbox.desired_generation(),
            tree_commitment,
            export_closure_commitment: export_closure.commitment(),
            portable_snapshot,
            manifest,
            retention_plan_commitment,
            preparation_commitment,
        })
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the snapshot identity.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }

    /// Returns the captured subtree root.
    #[must_use]
    pub const fn subtree_root(&self) -> SandboxId {
        self.subtree_root
    }

    /// Returns the captured project tree generation.
    #[must_use]
    pub const fn captured_tree_generation(&self) -> Revision {
        self.captured_tree_generation
    }

    /// Returns the captured subtree-root generation.
    #[must_use]
    pub const fn captured_sandbox_generation(&self) -> DesiredGeneration {
        self.captured_sandbox_generation
    }

    /// Returns the canonical complete tree commitment.
    #[must_use]
    pub const fn tree_commitment(&self) -> ObjectDigest {
        self.tree_commitment
    }

    /// Returns the complete export closure commitment.
    #[must_use]
    pub const fn export_closure_commitment(&self) -> ObjectDigest {
        self.export_closure_commitment
    }

    /// Returns the exact validated portable snapshot content.
    #[must_use]
    pub const fn portable_snapshot(&self) -> &Snapshot {
        &self.portable_snapshot
    }

    /// Returns the proposed immutable manifest descriptor.
    #[must_use]
    pub const fn manifest(&self) -> &ObjectDescriptor {
        &self.manifest
    }

    /// Returns the proposed physical retention plan commitment.
    #[must_use]
    pub const fn retention_plan_commitment(&self) -> ObjectDigest {
        self.retention_plan_commitment
    }

    /// Returns the complete preparation commitment.
    #[must_use]
    pub const fn preparation_commitment(&self) -> ObjectDigest {
        self.preparation_commitment
    }
}

/// Stores a snapshot only after exact manifest retention was verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedHierarchySnapshotV1 {
    prepared: PreparedHierarchySnapshotV1,
    retained: RetainedSnapshotManifestV1,
    commit_commitment: ObjectDigest,
}

impl CommittedHierarchySnapshotV1 {
    /// Commits matching retained-manifest evidence to a preparation.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError::RetentionEvidenceMismatch`] unless
    /// every project, sandbox, snapshot, generation, manifest, and closure
    /// identity matches exactly.
    pub fn commit(
        prepared: PreparedHierarchySnapshotV1,
        retained: RetainedSnapshotManifestV1,
    ) -> Result<Self, HierarchyRecoveryError> {
        if retained.project() != prepared.project
            || retained.sandbox() != prepared.subtree_root
            || retained.snapshot() != prepared.snapshot
            || retained.captured_generation() != prepared.captured_sandbox_generation
            || retained.manifest() != &prepared.manifest
            || retained.export_closure_commitment() != prepared.export_closure_commitment
            || retained.retention_plan_commitment() != prepared.retention_plan_commitment
            || retained.preparation_commitment() != prepared.preparation_commitment
            || retained.retention_proof_commitment().as_bytes() == &[0; 32]
        {
            return Err(HierarchyRecoveryError::RetentionEvidenceMismatch);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.hierarchy-snapshot-commit.v1\0");
        hasher.update(prepared.preparation_commitment.as_bytes());
        hasher.update(retained.retention_proof_commitment().as_bytes());
        let commit_commitment = ObjectDigest::from_bytes(hasher.finalize().into());
        Ok(Self {
            prepared,
            retained,
            commit_commitment,
        })
    }

    /// Returns the exact logical preparation.
    #[must_use]
    pub const fn prepared(&self) -> &PreparedHierarchySnapshotV1 {
        &self.prepared
    }

    /// Returns verified retained manifest evidence.
    #[must_use]
    pub const fn retained(&self) -> &RetainedSnapshotManifestV1 {
        &self.retained
    }

    /// Returns the final stable snapshot commitment.
    #[must_use]
    pub const fn commit_commitment(&self) -> ObjectDigest {
        self.commit_commitment
    }
}

/// Retains the durable preparation or committed-retention phase of a snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableHierarchySnapshotStateV1 {
    /// Logical manifest preparation is durable but retention is not committed.
    Prepared(Box<PreparedHierarchySnapshotV1>),
    /// Exact manifest retention proof is durable and inspection may use it.
    Committed(Box<CommittedHierarchySnapshotV1>),
}

/// Describes pure snapshot reconciliation after restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotReconciliationV1 {
    /// Prepared state requires a fresh continue-or-abort authority decision.
    AwaitFreshAuthority {
        /// Snapshot requiring a recovery decision.
        snapshot: SnapshotId,
        /// Exact preparation to which the decision must bind.
        preparation_commitment: ObjectDigest,
    },
    /// A prepared manifest must be checked against fresh retention inventory.
    AwaitRetentionObservation {
        /// Snapshot requiring observation.
        snapshot: SnapshotId,
        /// Exact preparation commitment to observe.
        preparation_commitment: ObjectDigest,
    },
    /// Matching retention evidence can be committed before inspection.
    ReadyToCommit(Box<CommittedHierarchySnapshotV1>),
    /// Fresh authority selected rollback of an uncommitted preparation.
    RollbackPrepared(PreparedSnapshotRollbackV1),
    /// The snapshot was already committed and remains available.
    Available(Box<CommittedHierarchySnapshotV1>),
    /// Supplied retention evidence conflicts; automatic use is forbidden.
    Conflict,
}

/// Selects the only two recovery outcomes for a durable snapshot preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedSnapshotRecoveryDecisionV1 {
    /// Continues retention observation and commit.
    Continue,
    /// Aborts the uncommitted preparation without publishing it.
    Rollback,
}

/// Carries a fresh verified decision for one exact snapshot preparation.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedSnapshotRecoveryAuthorityV1 {
    project: ProjectId,
    snapshot: SnapshotId,
    preparation_commitment: ObjectDigest,
    decision: PreparedSnapshotRecoveryDecisionV1,
    authority_commitment: ObjectDigest,
}

impl VerifiedSnapshotRecoveryAuthorityV1 {
    /// Creates evidence only after a trusted adapter verifies fresh authority.
    pub(super) const fn from_verified_parts(
        _authority: &ProtectedCurrentEvidenceAuthorityV1,
        project: ProjectId,
        snapshot: SnapshotId,
        preparation_commitment: ObjectDigest,
        decision: PreparedSnapshotRecoveryDecisionV1,
        authority_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            snapshot,
            preparation_commitment,
            decision,
            authority_commitment,
        }
    }

    pub(super) const fn project(&self) -> ProjectId {
        self.project
    }

    pub(super) const fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }

    pub(super) const fn preparation_commitment(&self) -> ObjectDigest {
        self.preparation_commitment
    }

    pub(super) const fn decision(&self) -> PreparedSnapshotRecoveryDecisionV1 {
        self.decision
    }

    pub(super) const fn authority_commitment(&self) -> ObjectDigest {
        self.authority_commitment
    }
}

/// Describes an authorized rollback of one unpublished snapshot preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedSnapshotRollbackV1 {
    snapshot: SnapshotId,
    preparation_commitment: ObjectDigest,
    authority_commitment: ObjectDigest,
}

impl PreparedSnapshotRollbackV1 {
    /// Returns the unpublished snapshot identity.
    #[must_use]
    pub const fn snapshot(self) -> SnapshotId {
        self.snapshot
    }

    /// Returns the exact preparation selected for rollback.
    #[must_use]
    pub const fn preparation_commitment(self) -> ObjectDigest {
        self.preparation_commitment
    }

    /// Returns the fresh rollback-authority commitment.
    #[must_use]
    pub const fn authority_commitment(self) -> ObjectDigest {
        self.authority_commitment
    }
}

/// Reconciles durable snapshot state with optional fresh retained-manifest evidence.
#[must_use]
pub fn reconcile_snapshot_after_reboot(
    state: &DurableHierarchySnapshotStateV1,
    retained: Option<RetainedSnapshotManifestV1>,
    authority: Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedSnapshotRecoveryAuthorityV1>>,
) -> SnapshotReconciliationV1 {
    let authority = authority.map(CurrentHierarchyProtectedEvidenceV1::into_evidence);
    match (state, retained, authority) {
        (DurableHierarchySnapshotStateV1::Prepared(prepared), _, None) => {
            SnapshotReconciliationV1::AwaitFreshAuthority {
                snapshot: prepared.snapshot(),
                preparation_commitment: prepared.preparation_commitment(),
            }
        }
        (DurableHierarchySnapshotStateV1::Prepared(prepared), retained, Some(authority))
            if authority.project == prepared.project()
                && authority.snapshot == prepared.snapshot()
                && authority.preparation_commitment == prepared.preparation_commitment()
                && authority.authority_commitment.as_bytes() != &[0; 32] =>
        {
            if authority.decision == PreparedSnapshotRecoveryDecisionV1::Rollback {
                return SnapshotReconciliationV1::RollbackPrepared(PreparedSnapshotRollbackV1 {
                    snapshot: prepared.snapshot(),
                    preparation_commitment: prepared.preparation_commitment(),
                    authority_commitment: authority.authority_commitment,
                });
            }
            let Some(retained) = retained else {
                return SnapshotReconciliationV1::AwaitRetentionObservation {
                    snapshot: prepared.snapshot(),
                    preparation_commitment: prepared.preparation_commitment(),
                };
            };
            match CommittedHierarchySnapshotV1::commit(prepared.as_ref().clone(), retained) {
                Ok(committed) => SnapshotReconciliationV1::ReadyToCommit(Box::new(committed)),
                Err(_) => SnapshotReconciliationV1::Conflict,
            }
        }
        (DurableHierarchySnapshotStateV1::Prepared(_), _, Some(_)) => {
            SnapshotReconciliationV1::Conflict
        }
        (DurableHierarchySnapshotStateV1::Committed(committed), None, _) => {
            SnapshotReconciliationV1::AwaitRetentionObservation {
                snapshot: committed.prepared().snapshot(),
                preparation_commitment: committed.prepared().preparation_commitment(),
            }
        }
        (DurableHierarchySnapshotStateV1::Committed(committed), Some(retained), _) => {
            match CommittedHierarchySnapshotV1::commit(committed.prepared().clone(), retained) {
                Ok(refreshed) => SnapshotReconciliationV1::Available(Box::new(refreshed)),
                Err(_) => SnapshotReconciliationV1::Conflict,
            }
        }
    }
}

/// Stores one monotonic realization-stage observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealizationStageObservationV1 {
    sequence: u64,
    stage: RealizationStageV1,
    inventory_commitment: ObjectDigest,
}

impl RealizationStageObservationV1 {
    /// Creates an observation only from the verified durable hierarchy decoder.
    pub(crate) const fn from_durable_parts(
        sequence: u64,
        stage: RealizationStageV1,
        inventory_commitment: ObjectDigest,
    ) -> Self {
        Self {
            sequence,
            stage,
            inventory_commitment,
        }
    }

    /// Returns the one-based transition sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the observed durable stage.
    #[must_use]
    pub const fn stage(self) -> RealizationStageV1 {
        self.stage
    }

    /// Returns the authenticated inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }
}

/// Retains a trusted current inventory proof for one exact stage transition.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedStageTransitionV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    from: RealizationStageV1,
    to: RealizationStageV1,
    inventory_commitment: ObjectDigest,
}

impl VerifiedStageTransitionV1 {
    /// Creates evidence only after a trusted inventory adapter verifies the transition.
    pub(super) fn from_verified_parts(
        _authority: &ProtectedCurrentEvidenceAuthorityV1,
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        recipe_commitment: ObjectDigest,
        from: RealizationStageV1,
        to: RealizationStageV1,
        inventory_commitment: ObjectDigest,
    ) -> Self {
        Self {
            attachment,
            attachment_generation,
            recipe_commitment,
            from,
            to,
            inventory_commitment,
        }
    }

    pub(super) const fn attachment(&self) -> AttachmentId {
        self.attachment
    }

    pub(super) const fn attachment_generation(&self) -> DesiredGeneration {
        self.attachment_generation
    }

    pub(super) const fn recipe_commitment(&self) -> ObjectDigest {
        self.recipe_commitment
    }

    pub(super) const fn from(&self) -> RealizationStageV1 {
        self.from
    }

    pub(super) const fn to(&self) -> RealizationStageV1 {
        self.to
    }

    pub(super) const fn inventory_commitment(&self) -> ObjectDigest {
        self.inventory_commitment
    }
}

/// Retains a protected head for rollback-resistant realization recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedRealizationHeadV1 {
    project: ProjectId,
    tree_generation: Revision,
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    plan_commitment: ObjectDigest,
    recipe_commitment: ObjectDigest,
    sequence: u64,
    stage: RealizationStageV1,
    inventory_commitment: ObjectDigest,
    history_commitment: ObjectDigest,
    protected_head_commitment: ObjectDigest,
}

impl RetainedRealizationHeadV1 {
    /// Creates a head for durable-adapter admission after protected verification.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_verified_parts(
        project: ProjectId,
        tree_generation: Revision,
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        plan_commitment: ObjectDigest,
        recipe_commitment: ObjectDigest,
        sequence: u64,
        stage: RealizationStageV1,
        inventory_commitment: ObjectDigest,
        history_commitment: ObjectDigest,
        protected_head_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            tree_generation,
            attachment,
            attachment_generation,
            plan_commitment,
            recipe_commitment,
            sequence,
            stage,
            inventory_commitment,
            history_commitment,
            protected_head_commitment,
        }
    }

    /// Returns the protected project identity.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the protected project-tree generation.
    #[must_use]
    pub const fn tree_generation(self) -> Revision {
        self.tree_generation
    }

    /// Returns the protected attachment identity.
    #[must_use]
    pub const fn attachment(self) -> AttachmentId {
        self.attachment
    }

    /// Returns the protected attachment generation.
    #[must_use]
    pub const fn attachment_generation(self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the immutable transaction commitment.
    #[must_use]
    pub const fn plan_commitment(self) -> ObjectDigest {
        self.plan_commitment
    }

    /// Returns the exact recipe commitment.
    #[must_use]
    pub const fn recipe_commitment(self) -> ObjectDigest {
        self.recipe_commitment
    }

    /// Returns the protected stage sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the protected durable stage.
    #[must_use]
    pub const fn stage(self) -> RealizationStageV1 {
        self.stage
    }

    /// Returns the inventory commitment at the protected stage.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }

    /// Returns the commitment to complete stage history.
    #[must_use]
    pub const fn history_commitment(self) -> ObjectDigest {
        self.history_commitment
    }

    /// Returns evidence that the head came from protected storage.
    #[must_use]
    pub const fn protected_head_commitment(self) -> ObjectDigest {
        self.protected_head_commitment
    }
}

/// Owns durable monotonic state for one attachment realization recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableRealizationProgressV1 {
    project: ProjectId,
    tree_generation: Revision,
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    plan_commitment: ObjectDigest,
    recipe_commitment: ObjectDigest,
    replacement: Option<ReplacementTransactionV1>,
    observations: Vec<RealizationStageObservationV1>,
}

impl DurableRealizationProgressV1 {
    /// Reconstructs canonical durable progress and verifies every transition
    /// and the complete history commitment without creating effect authority.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_canonical_parts(
        project: ProjectId,
        tree_generation: Revision,
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        plan_commitment: ObjectDigest,
        recipe_commitment: ObjectDigest,
        replacement: Option<ReplacementTransactionV1>,
        observations: Vec<RealizationStageObservationV1>,
        history_commitment: ObjectDigest,
    ) -> Result<Self, HierarchyRecoveryError> {
        if project.as_bytes() == &[0; 16]
            || tree_generation.get() == 0
            || attachment.as_bytes() == &[0; 16]
            || attachment_generation.get() == 0
            || plan_commitment.as_bytes() == &[0; 32]
            || recipe_commitment.as_bytes() == &[0; 32]
            || history_commitment.as_bytes() == &[0; 32]
            || observations.is_empty()
            || observations.len() > MAXIMUM_REALIZATION_STAGE_HISTORY
        {
            return Err(HierarchyRecoveryError::CorruptProgress);
        }
        if let Some(replacement) = replacement {
            if replacement.predecessor().as_bytes() == &[0; 16]
                || replacement.successor() != attachment
                || replacement.predecessor_generation().get() == 0
                || replacement.predecessor_recipe_commitment().as_bytes() == &[0; 32]
                || replacement.transaction_commitment().as_bytes() == &[0; 32]
            {
                return Err(HierarchyRecoveryError::CorruptProgress);
            }
        }
        for (index, observation) in observations.iter().copied().enumerate() {
            let sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(HierarchyRecoveryError::Capacity)?;
            if observation.sequence != sequence
                || observation.inventory_commitment.as_bytes() == &[0; 32]
                || (index == 0 && observation.stage != RealizationStageV1::Planned)
            {
                return Err(HierarchyRecoveryError::CorruptProgress);
            }
            if index != 0 {
                let prior = observations
                    .get(index - 1)
                    .ok_or(HierarchyRecoveryError::CorruptProgress)?;
                if !realization_transition_is_valid(
                    prior.stage,
                    observation.stage,
                    replacement.is_some(),
                ) {
                    return Err(HierarchyRecoveryError::InvalidTransition);
                }
            }
        }
        let progress = Self {
            project,
            tree_generation,
            attachment,
            attachment_generation,
            plan_commitment,
            recipe_commitment,
            replacement,
            observations,
        };
        if progress.history_commitment() != history_commitment {
            return Err(HierarchyRecoveryError::CorruptProgress);
        }
        Ok(progress)
    }

    /// Recovers and fully validates durable monotonic realization history.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError`] for an absent recipe, malformed or
    /// truncated observation history, invalid stage transition, or head mismatch.
    pub fn recover(
        plan: &ViewRealizationPlanV1,
        attachment: AttachmentId,
        observations: Vec<RealizationStageObservationV1>,
        retained_head: RetainedRealizationHeadV1,
    ) -> Result<Self, HierarchyRecoveryError> {
        let recipe = plan
            .publications()
            .binary_search_by_key(&attachment, AttachmentRealizationV1::attachment)
            .ok()
            .and_then(|index| plan.publications().get(index))
            .ok_or(HierarchyRecoveryError::PlanMismatch)?;
        if observations.is_empty() || observations.len() > MAXIMUM_REALIZATION_STAGE_HISTORY {
            return Err(HierarchyRecoveryError::CorruptProgress);
        }
        for (index, observation) in observations.iter().copied().enumerate() {
            let sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(HierarchyRecoveryError::Capacity)?;
            if observation.sequence != sequence
                || observation.inventory_commitment.as_bytes() == &[0; 32]
            {
                return Err(HierarchyRecoveryError::CorruptProgress);
            }
            if index == 0 {
                if observation.stage != RealizationStageV1::Planned {
                    return Err(HierarchyRecoveryError::CorruptProgress);
                }
                continue;
            }
            let prior = observations
                .get(index - 1)
                .ok_or(HierarchyRecoveryError::CorruptProgress)?;
            if !realization_transition_is_valid(
                prior.stage,
                observation.stage,
                recipe.replacement().is_some(),
            ) {
                return Err(HierarchyRecoveryError::InvalidTransition);
            }
        }
        let current = observations
            .last()
            .copied()
            .ok_or(HierarchyRecoveryError::CorruptProgress)?;
        let history_commitment = commit_realization_history(
            plan.project(),
            plan.tree_generation(),
            attachment,
            recipe.intent().desired_generation(),
            plan.plan_commitment(),
            recipe.recipe_commitment(),
            &observations,
        );
        if retained_head.project != plan.project()
            || retained_head.tree_generation != plan.tree_generation()
            || retained_head.attachment != attachment
            || retained_head.attachment_generation != recipe.intent().desired_generation()
            || retained_head.plan_commitment != plan.plan_commitment()
            || retained_head.recipe_commitment != recipe.recipe_commitment()
            || retained_head.sequence != current.sequence
            || retained_head.stage != current.stage
            || retained_head.inventory_commitment != current.inventory_commitment
            || retained_head.history_commitment != history_commitment
            || retained_head.protected_head_commitment.as_bytes() == &[0; 32]
        {
            return Err(HierarchyRecoveryError::ProtectedHeadMismatch);
        }
        Ok(Self {
            project: plan.project(),
            tree_generation: plan.tree_generation(),
            attachment,
            attachment_generation: recipe.intent().desired_generation(),
            plan_commitment: plan.plan_commitment(),
            recipe_commitment: recipe.recipe_commitment(),
            replacement: recipe.replacement(),
            observations,
        })
    }

    /// Creates planned progress from one exact immutable plan recipe.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError::PlanMismatch`] unless the recipe is
    /// present in the plan.
    pub fn planned(
        plan: &ViewRealizationPlanV1,
        attachment: AttachmentId,
        durable_plan_observation: ObjectDigest,
    ) -> Result<Self, HierarchyRecoveryError> {
        let recipe = plan
            .publications()
            .binary_search_by_key(&attachment, AttachmentRealizationV1::attachment)
            .ok()
            .and_then(|index| plan.publications().get(index))
            .ok_or(HierarchyRecoveryError::PlanMismatch)?;
        if durable_plan_observation.as_bytes() == &[0; 32] {
            return Err(HierarchyRecoveryError::UnspecifiedIdentity);
        }
        Ok(Self {
            project: plan.project(),
            tree_generation: plan.tree_generation(),
            attachment,
            attachment_generation: recipe.intent().desired_generation(),
            plan_commitment: plan.plan_commitment(),
            recipe_commitment: recipe.recipe_commitment(),
            replacement: recipe.replacement(),
            observations: vec![RealizationStageObservationV1 {
                sequence: 1,
                stage: RealizationStageV1::Planned,
                inventory_commitment: durable_plan_observation,
            }],
        })
    }

    /// Advances exactly one stage after compare-and-swap validation.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError`] for stale sequence/stage input,
    /// skipped or regressed stages, zero observation, or retained-history limits.
    pub fn advance(
        &mut self,
        expected_sequence: u64,
        evidence: CurrentHierarchyProtectedEvidenceV1<'_, VerifiedStageTransitionV1>,
    ) -> Result<(), HierarchyRecoveryError> {
        self.advance_verified(expected_sequence, evidence.into_evidence())
    }

    fn advance_verified(
        &mut self,
        expected_sequence: u64,
        evidence: VerifiedStageTransitionV1,
    ) -> Result<(), HierarchyRecoveryError> {
        let current = self
            .observations
            .last()
            .copied()
            .ok_or(HierarchyRecoveryError::CorruptProgress)?;
        if current.sequence != expected_sequence
            || current.stage != evidence.from
            || evidence.attachment != self.attachment
            || evidence.attachment_generation != self.attachment_generation
            || evidence.recipe_commitment != self.recipe_commitment
        {
            return Err(HierarchyRecoveryError::StaleProgress);
        }
        if !realization_transition_is_valid(evidence.from, evidence.to, self.replacement.is_some())
        {
            return Err(HierarchyRecoveryError::InvalidTransition);
        }
        if evidence.inventory_commitment.as_bytes() == &[0; 32] {
            return Err(HierarchyRecoveryError::UnspecifiedIdentity);
        }
        if self.observations.len() >= MAXIMUM_REALIZATION_STAGE_HISTORY {
            return Err(HierarchyRecoveryError::Capacity);
        }
        self.observations
            .try_reserve(1)
            .map_err(|_| HierarchyRecoveryError::Capacity)?;
        self.observations.push(RealizationStageObservationV1 {
            sequence: expected_sequence
                .checked_add(1)
                .ok_or(HierarchyRecoveryError::Capacity)?,
            stage: evidence.to,
            inventory_commitment: evidence.inventory_commitment,
        });
        Ok(())
    }

    /// Durably adopts one exact forward stage discovered during reboot inventory.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError`] when the recovery fact is stale,
    /// belongs to another recipe, or would violate monotonic stage rules.
    pub fn advance_observed(
        &mut self,
        expected_sequence: u64,
        observed: ObservedStageAdvanceV1,
    ) -> Result<(), HierarchyRecoveryError> {
        self.advance_verified(
            expected_sequence,
            VerifiedStageTransitionV1 {
                attachment: observed.attachment,
                attachment_generation: observed.attachment_generation,
                recipe_commitment: observed.recipe_commitment,
                from: observed.from,
                to: observed.to,
                inventory_commitment: observed.inventory_commitment,
            },
        )
    }

    /// Returns the attachment identity.
    #[must_use]
    pub const fn attachment(&self) -> AttachmentId {
        self.attachment
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the exact tree generation used by the plan.
    #[must_use]
    pub const fn tree_generation(&self) -> Revision {
        self.tree_generation
    }

    /// Returns the desired attachment generation.
    #[must_use]
    pub const fn attachment_generation(&self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the immutable plan commitment.
    #[must_use]
    pub const fn plan_commitment(&self) -> ObjectDigest {
        self.plan_commitment
    }

    /// Returns the realization recipe commitment.
    #[must_use]
    pub const fn recipe_commitment(&self) -> ObjectDigest {
        self.recipe_commitment
    }

    /// Returns the exact replacement transaction, if any.
    #[must_use]
    pub const fn replacement(&self) -> Option<ReplacementTransactionV1> {
        self.replacement
    }

    /// Returns complete monotonic stage history.
    #[must_use]
    pub fn observations(&self) -> &[RealizationStageObservationV1] {
        &self.observations
    }

    /// Returns the current durable stage.
    #[must_use]
    pub fn current_stage(&self) -> Option<RealizationStageV1> {
        self.observations.last().map(|entry| entry.stage)
    }

    /// Returns the commitment to complete monotonic observation history.
    #[must_use]
    pub fn history_commitment(&self) -> ObjectDigest {
        commit_realization_history(
            self.project,
            self.tree_generation,
            self.attachment,
            self.attachment_generation,
            self.plan_commitment,
            self.recipe_commitment,
            &self.observations,
        )
    }

    /// Returns the exact prior durable history head for a non-planned advance.
    #[must_use]
    pub fn predecessor_history_commitment(&self) -> Option<ObjectDigest> {
        let predecessor_length = self.observations.len().checked_sub(1)?;
        if predecessor_length == 0 {
            return None;
        }
        Some(commit_realization_history(
            self.project,
            self.tree_generation,
            self.attachment,
            self.attachment_generation,
            self.plan_commitment,
            self.recipe_commitment,
            &self.observations[..predecessor_length],
        ))
    }
}

fn realization_transition_is_valid(
    from: RealizationStageV1,
    to: RealizationStageV1,
    has_replacement: bool,
) -> bool {
    matches!(
        (from, to, has_replacement),
        (RealizationStageV1::Planned, RealizationStageV1::Prepared, _)
            | (
                RealizationStageV1::Prepared,
                RealizationStageV1::Published,
                _
            )
            | (
                RealizationStageV1::Published,
                RealizationStageV1::Verified,
                _
            )
            | (
                RealizationStageV1::Verified,
                RealizationStageV1::Draining,
                true
            )
            | (
                RealizationStageV1::Draining,
                RealizationStageV1::Reaped,
                true
            )
            | (
                RealizationStageV1::Verified,
                RealizationStageV1::Reaped,
                false
            )
            | (
                RealizationStageV1::Planned | RealizationStageV1::Prepared,
                RealizationStageV1::Aborted,
                _
            )
            | (
                RealizationStageV1::Published
                    | RealizationStageV1::Verified
                    | RealizationStageV1::Draining,
                RealizationStageV1::Faulted,
                _
            )
    )
}

fn commit_realization_history(
    project: ProjectId,
    tree_generation: Revision,
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    plan_commitment: ObjectDigest,
    recipe_commitment: ObjectDigest,
    observations: &[RealizationStageObservationV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.realization-history.v1\0");
    hasher.update(project.as_bytes());
    hasher.update(tree_generation.get().to_be_bytes());
    hasher.update(attachment.as_bytes());
    hasher.update(attachment_generation.get().to_be_bytes());
    hasher.update(plan_commitment.as_bytes());
    hasher.update(recipe_commitment.as_bytes());
    hasher.update((observations.len() as u64).to_be_bytes());
    for observation in observations {
        hasher.update(observation.sequence.to_be_bytes());
        hasher.update([observation.stage as u8]);
        hasher.update(observation.inventory_commitment.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Selects an authenticated reboot inventory state for one exact recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebootInventoryStateV1 {
    /// No realization with the recipe identity is present.
    Absent,
    /// A detached prepared realization is present but unpublished.
    Prepared,
    /// The recipe is published but not post-verified.
    Published,
    /// The recipe is published and post-verified.
    Verified,
    /// The replaced predecessor is draining.
    Draining,
    /// The replaced predecessor was reclaimed.
    Reaped,
    /// The unpublished realization was abandoned.
    Aborted,
    /// Published state is terminally faulted and requires operator review.
    Faulted,
}

/// Retains authenticated reboot inventory without exposing effect authority.
#[derive(Debug, Eq, PartialEq)]
pub struct RebootRealizationInventoryV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    state: RebootInventoryStateV1,
    recoverable_predecessor: Option<ReplacementTransactionV1>,
    inventory_commitment: ObjectDigest,
}

impl RebootRealizationInventoryV1 {
    /// Creates inventory only after a protected observation adapter verifies it.
    pub(super) fn from_verified_parts(
        _authority: &ProtectedCurrentEvidenceAuthorityV1,
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        recipe_commitment: ObjectDigest,
        state: RebootInventoryStateV1,
        recoverable_predecessor: Option<ReplacementTransactionV1>,
        inventory_commitment: ObjectDigest,
    ) -> Self {
        Self {
            attachment,
            attachment_generation,
            recipe_commitment,
            state,
            recoverable_predecessor,
            inventory_commitment,
        }
    }

    pub(super) const fn attachment(&self) -> AttachmentId {
        self.attachment
    }

    pub(super) const fn attachment_generation(&self) -> DesiredGeneration {
        self.attachment_generation
    }

    pub(super) const fn recipe_commitment(&self) -> ObjectDigest {
        self.recipe_commitment
    }

    pub(super) const fn state(&self) -> RebootInventoryStateV1 {
        self.state
    }

    pub(super) const fn recoverable_predecessor(&self) -> Option<ReplacementTransactionV1> {
        self.recoverable_predecessor
    }

    pub(super) const fn inventory_commitment(&self) -> ObjectDigest {
        self.inventory_commitment
    }
}

/// Carries fresh authority for one exact published rollback.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedPublishedRollbackAuthorityV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    authority_commitment: ObjectDigest,
}

impl VerifiedPublishedRollbackAuthorityV1 {
    /// Creates evidence only after a trusted adapter authorizes rollback.
    pub(super) const fn from_verified_parts(
        _authority: &ProtectedCurrentEvidenceAuthorityV1,
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        recipe_commitment: ObjectDigest,
        authority_commitment: ObjectDigest,
    ) -> Self {
        Self {
            attachment,
            attachment_generation,
            recipe_commitment,
            authority_commitment,
        }
    }

    pub(super) const fn attachment(&self) -> AttachmentId {
        self.attachment
    }

    pub(super) const fn attachment_generation(&self) -> DesiredGeneration {
        self.attachment_generation
    }

    pub(super) const fn recipe_commitment(&self) -> ObjectDigest {
        self.recipe_commitment
    }

    pub(super) const fn authority_commitment(&self) -> ObjectDigest {
        self.authority_commitment
    }
}

/// Carries a stage-typed prepared-generation rollback description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedRollbackV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    inventory_commitment: ObjectDigest,
    authority_commitment: ObjectDigest,
}

impl PreparedRollbackV1 {
    /// Returns the prepared attachment.
    #[must_use]
    pub const fn attachment(self) -> AttachmentId {
        self.attachment
    }

    /// Returns the exact prepared attachment generation.
    #[must_use]
    pub const fn attachment_generation(self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the exact prepared recipe.
    #[must_use]
    pub const fn recipe_commitment(self) -> ObjectDigest {
        self.recipe_commitment
    }

    /// Returns the authenticated prepared-inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }

    /// Returns the fresh recovery-authority commitment.
    #[must_use]
    pub const fn authority_commitment(self) -> ObjectDigest {
        self.authority_commitment
    }
}

/// Selects continuation or rollback for an unpublished prepared realization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedRealizationRecoveryDecisionV1 {
    /// Continues publication from the exact prepared recipe.
    Continue,
    /// Removes the unpublished prepared recipe.
    Rollback,
}

/// Carries fresh authority for one exact prepared realization.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedPreparedRealizationAuthorityV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    decision: PreparedRealizationRecoveryDecisionV1,
    authority_commitment: ObjectDigest,
}

impl VerifiedPreparedRealizationAuthorityV1 {
    /// Creates evidence only after a trusted recovery adapter authorizes it.
    pub(super) const fn from_verified_parts(
        _authority: &ProtectedCurrentEvidenceAuthorityV1,
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        recipe_commitment: ObjectDigest,
        decision: PreparedRealizationRecoveryDecisionV1,
        authority_commitment: ObjectDigest,
    ) -> Self {
        Self {
            attachment,
            attachment_generation,
            recipe_commitment,
            decision,
            authority_commitment,
        }
    }

    pub(super) const fn attachment(&self) -> AttachmentId {
        self.attachment
    }

    pub(super) const fn attachment_generation(&self) -> DesiredGeneration {
        self.attachment_generation
    }

    pub(super) const fn recipe_commitment(&self) -> ObjectDigest {
        self.recipe_commitment
    }

    pub(super) const fn decision(&self) -> PreparedRealizationRecoveryDecisionV1 {
        self.decision
    }

    pub(super) const fn authority_commitment(&self) -> ObjectDigest {
        self.authority_commitment
    }
}

/// Carries a fully fenced continuation of one unpublished prepared recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedContinueV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    inventory_commitment: ObjectDigest,
    authority_commitment: ObjectDigest,
}

impl PreparedContinueV1 {
    /// Returns the prepared attachment identity.
    #[must_use]
    pub const fn attachment(self) -> AttachmentId {
        self.attachment
    }

    /// Returns the exact prepared attachment generation.
    #[must_use]
    pub const fn attachment_generation(self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the exact prepared recipe commitment.
    #[must_use]
    pub const fn recipe_commitment(self) -> ObjectDigest {
        self.recipe_commitment
    }

    /// Returns the current prepared-inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }

    /// Returns the fresh continuation-authority commitment.
    #[must_use]
    pub const fn authority_commitment(self) -> ObjectDigest {
        self.authority_commitment
    }
}

/// Selects the authorized prepared-recovery operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedRealizationRecoveryV1 {
    /// Publishes the exact prepared recipe after subsequent revalidation.
    Continue(PreparedContinueV1),
    /// Removes the exact unpublished prepared recipe.
    Rollback(PreparedRollbackV1),
}

/// Joins fresh authority with exact current prepared inventory.
///
/// # Errors
///
/// Returns [`HierarchyRecoveryError`] unless progress, inventory, and authority
/// identify the same prepared recipe with nonzero commitments.
pub fn reconcile_prepared_realization(
    progress: &DurableRealizationProgressV1,
    inventory: CurrentHierarchyProtectedEvidenceV1<'_, RebootRealizationInventoryV1>,
    authority: CurrentHierarchyProtectedEvidenceV1<'_, VerifiedPreparedRealizationAuthorityV1>,
) -> Result<PreparedRealizationRecoveryV1, HierarchyRecoveryError> {
    let inventory = inventory.into_evidence();
    let authority = authority.into_evidence();
    if progress.current_stage() != Some(RealizationStageV1::Prepared)
        || inventory.state != RebootInventoryStateV1::Prepared
        || inventory.attachment != progress.attachment
        || inventory.attachment_generation != progress.attachment_generation
        || inventory.recipe_commitment != progress.recipe_commitment
        || inventory.inventory_commitment.as_bytes() == &[0; 32]
        || authority.attachment != progress.attachment
        || authority.attachment_generation != progress.attachment_generation
        || authority.recipe_commitment != progress.recipe_commitment
        || authority.authority_commitment.as_bytes() == &[0; 32]
    {
        return Err(HierarchyRecoveryError::RecoveryEvidenceMismatch);
    }

    let common = PreparedContinueV1 {
        attachment: progress.attachment,
        attachment_generation: progress.attachment_generation,
        recipe_commitment: progress.recipe_commitment,
        inventory_commitment: inventory.inventory_commitment,
        authority_commitment: authority.authority_commitment,
    };
    Ok(match authority.decision {
        PreparedRealizationRecoveryDecisionV1::Continue => {
            PreparedRealizationRecoveryV1::Continue(common)
        }
        PreparedRealizationRecoveryDecisionV1::Rollback => {
            PreparedRealizationRecoveryV1::Rollback(PreparedRollbackV1 {
                attachment: common.attachment,
                attachment_generation: common.attachment_generation,
                recipe_commitment: common.recipe_commitment,
                inventory_commitment: common.inventory_commitment,
                authority_commitment: common.authority_commitment,
            })
        }
    })
}

/// Carries a stage-typed published-generation recovery description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedRecoveryV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    replacement: Option<ReplacementTransactionV1>,
    inventory_commitment: ObjectDigest,
}

/// Records an exact observed forward stage that was not durable before restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedStageAdvanceV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    from: RealizationStageV1,
    to: RealizationStageV1,
    inventory_commitment: ObjectDigest,
}

impl ObservedStageAdvanceV1 {
    /// Returns the attachment whose exact recipe was observed.
    #[must_use]
    pub const fn attachment(self) -> AttachmentId {
        self.attachment
    }

    /// Returns the exact desired attachment generation.
    #[must_use]
    pub const fn attachment_generation(self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the exact realization recipe commitment.
    #[must_use]
    pub const fn recipe_commitment(self) -> ObjectDigest {
        self.recipe_commitment
    }

    /// Returns the durable stage before the crash.
    #[must_use]
    pub const fn from(self) -> RealizationStageV1 {
        self.from
    }

    /// Returns the verified observed next stage.
    #[must_use]
    pub const fn to(self) -> RealizationStageV1 {
        self.to
    }

    /// Returns the authenticated reboot inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }
}

impl PublishedRecoveryV1 {
    /// Returns the published attachment.
    #[must_use]
    pub const fn attachment(self) -> AttachmentId {
        self.attachment
    }

    /// Returns the exact published attachment generation.
    #[must_use]
    pub const fn attachment_generation(self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the exact published recipe.
    #[must_use]
    pub const fn recipe_commitment(self) -> ObjectDigest {
        self.recipe_commitment
    }

    /// Returns the exact immediate predecessor transaction, if any.
    #[must_use]
    pub const fn replacement(self) -> Option<ReplacementTransactionV1> {
        self.replacement
    }

    /// Returns the authenticated published-inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }
}

/// Selects the only stage-valid published-generation rollback target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishedRollbackTargetV1 {
    /// Restores the exact immediate predecessor retained by the transaction.
    RestoreImmediatePredecessor(ReplacementTransactionV1),
    /// Removes the published generation and leaves the proven prior empty slot.
    LeaveSlotEmpty,
}

/// Carries an exact stage-typed published-generation rollback description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedRollbackV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    target: PublishedRollbackTargetV1,
    inventory_commitment: ObjectDigest,
    authority_commitment: ObjectDigest,
}

impl PublishedRollbackV1 {
    /// Returns the published attachment.
    #[must_use]
    pub const fn attachment(self) -> AttachmentId {
        self.attachment
    }

    /// Returns the exact successor attachment generation.
    #[must_use]
    pub const fn attachment_generation(self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the exact successor recipe.
    #[must_use]
    pub const fn recipe_commitment(self) -> ObjectDigest {
        self.recipe_commitment
    }

    /// Returns the exact predecessor restoration or empty-slot target.
    #[must_use]
    pub const fn target(self) -> PublishedRollbackTargetV1 {
        self.target
    }

    /// Returns the fresh predecessor-inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }

    /// Returns the fresh rollback-authority commitment.
    #[must_use]
    pub const fn authority_commitment(self) -> ObjectDigest {
        self.authority_commitment
    }
}

/// Derives rollback only while a published predecessor remains recoverable.
///
/// # Errors
///
/// Returns [`HierarchyRecoveryError::InvalidTransition`] before publication or
/// after the predecessor was reaped.
pub fn published_rollback(
    progress: &DurableRealizationProgressV1,
    inventory: CurrentHierarchyProtectedEvidenceV1<'_, RebootRealizationInventoryV1>,
    authority: CurrentHierarchyProtectedEvidenceV1<'_, VerifiedPublishedRollbackAuthorityV1>,
) -> Result<PublishedRollbackV1, HierarchyRecoveryError> {
    let inventory = inventory.into_evidence();
    let authority = authority.into_evidence();
    if !matches!(
        progress.current_stage(),
        Some(
            RealizationStageV1::Published
                | RealizationStageV1::Verified
                | RealizationStageV1::Draining
        )
    ) {
        return Err(HierarchyRecoveryError::InvalidTransition);
    }
    if inventory.attachment != progress.attachment
        || inventory.attachment_generation != progress.attachment_generation
        || inventory.recipe_commitment != progress.recipe_commitment
        || inventory.recoverable_predecessor != progress.replacement
        || inventory.inventory_commitment.as_bytes() == &[0; 32]
        || !matches!(
            inventory.state,
            RebootInventoryStateV1::Published
                | RebootInventoryStateV1::Verified
                | RebootInventoryStateV1::Draining
        )
        || authority.attachment != progress.attachment
        || authority.attachment_generation != progress.attachment_generation
        || authority.recipe_commitment != progress.recipe_commitment
        || authority.authority_commitment.as_bytes() == &[0; 32]
    {
        return Err(HierarchyRecoveryError::RecoveryEvidenceMismatch);
    }
    let target = match progress.replacement {
        Some(replacement) => PublishedRollbackTargetV1::RestoreImmediatePredecessor(replacement),
        None => PublishedRollbackTargetV1::LeaveSlotEmpty,
    };
    Ok(PublishedRollbackV1 {
        attachment: progress.attachment,
        attachment_generation: progress.attachment_generation,
        recipe_commitment: progress.recipe_commitment,
        target,
        inventory_commitment: inventory.inventory_commitment,
        authority_commitment: authority.authority_commitment,
    })
}

/// Describes safe source-only reconciliation after process or node restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebootReconciliationV1 {
    /// Durable planned state has no external effect; fresh authority is needed.
    AwaitFreshAuthority,
    /// Records one exact already-observed forward stage before further effects.
    RecordObservedAdvance(ObservedStageAdvanceV1),
    /// A proven prepared generation may be removed after fresh authority.
    RollbackPrepared(PreparedRollbackV1),
    /// A published generation requires post-attach verification or rollback.
    VerifyPublished(PublishedRecoveryV1),
    /// A verified generation may continue draining its exact predecessor.
    ContinueDraining(PublishedRecoveryV1),
    /// No predecessor exists; only the durable terminal fact remains to record.
    RecordTerminalNoEffect,
    /// Durable and observed state are terminally complete.
    Complete,
    /// Durable and observed state agree on a terminal abort.
    Aborted,
    /// Durable and observed state agree on a terminal fault.
    Faulted,
    /// Durable and observed facts conflict; automatic mutation is forbidden.
    Conflict,
}

/// Reconciles durable progress with exact authenticated reboot inventory.
///
/// No variant authorizes an effect. Mutation variants require a subsequent
/// fixed-owner authority claim after this current inventory is consumed.
#[must_use]
pub fn reconcile_realization_after_reboot(
    progress: &DurableRealizationProgressV1,
    inventory: CurrentHierarchyProtectedEvidenceV1<'_, RebootRealizationInventoryV1>,
) -> RebootReconciliationV1 {
    let inventory = inventory.into_evidence();
    if inventory.attachment != progress.attachment
        || inventory.attachment_generation != progress.attachment_generation
        || inventory.recipe_commitment != progress.recipe_commitment
        || inventory.inventory_commitment.as_bytes() == &[0; 32]
    {
        return RebootReconciliationV1::Conflict;
    }
    let Some(stage) = progress.current_stage() else {
        return RebootReconciliationV1::Conflict;
    };
    let published = PublishedRecoveryV1 {
        attachment: progress.attachment,
        attachment_generation: progress.attachment_generation,
        recipe_commitment: progress.recipe_commitment,
        replacement: progress.replacement,
        inventory_commitment: inventory.inventory_commitment,
    };
    let observed_advance = |to| {
        RebootReconciliationV1::RecordObservedAdvance(ObservedStageAdvanceV1 {
            attachment: progress.attachment,
            attachment_generation: progress.attachment_generation,
            recipe_commitment: progress.recipe_commitment,
            from: stage,
            to,
            inventory_commitment: inventory.inventory_commitment,
        })
    };
    match (stage, inventory.state) {
        (RealizationStageV1::Planned, RebootInventoryStateV1::Absent) => {
            RebootReconciliationV1::AwaitFreshAuthority
        }
        (RealizationStageV1::Prepared, RebootInventoryStateV1::Prepared) => {
            RebootReconciliationV1::AwaitFreshAuthority
        }
        (RealizationStageV1::Planned, RebootInventoryStateV1::Prepared) => {
            observed_advance(RealizationStageV1::Prepared)
        }
        (RealizationStageV1::Prepared, RebootInventoryStateV1::Published) => {
            observed_advance(RealizationStageV1::Published)
        }
        (RealizationStageV1::Published, RebootInventoryStateV1::Verified) => {
            observed_advance(RealizationStageV1::Verified)
        }
        (RealizationStageV1::Verified, RebootInventoryStateV1::Draining)
            if progress.replacement.is_some() =>
        {
            observed_advance(RealizationStageV1::Draining)
        }
        (RealizationStageV1::Draining, RebootInventoryStateV1::Reaped) => {
            observed_advance(RealizationStageV1::Reaped)
        }
        (RealizationStageV1::Published, RebootInventoryStateV1::Published) => {
            RebootReconciliationV1::VerifyPublished(published)
        }
        (RealizationStageV1::Verified, RebootInventoryStateV1::Verified)
            if progress.replacement.is_none() =>
        {
            RebootReconciliationV1::RecordTerminalNoEffect
        }
        (RealizationStageV1::Verified, RebootInventoryStateV1::Verified)
        | (RealizationStageV1::Draining, RebootInventoryStateV1::Draining) => {
            RebootReconciliationV1::ContinueDraining(published)
        }
        (RealizationStageV1::Reaped, RebootInventoryStateV1::Reaped) => {
            RebootReconciliationV1::Complete
        }
        (RealizationStageV1::Aborted, RebootInventoryStateV1::Aborted) => {
            RebootReconciliationV1::Aborted
        }
        (RealizationStageV1::Faulted, RebootInventoryStateV1::Faulted) => {
            RebootReconciliationV1::Faulted
        }
        _ => RebootReconciliationV1::Conflict,
    }
}

#[allow(clippy::too_many_arguments)]
fn commit_snapshot_preparation(
    project: ProjectId,
    snapshot: SnapshotId,
    root: SandboxId,
    tree_generation: Revision,
    sandbox_generation: DesiredGeneration,
    tree_commitment: ObjectDigest,
    export_commitment: ObjectDigest,
    manifest: &ObjectDescriptor,
    retention_plan: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.hierarchy-snapshot-preparation.v1\0");
    hasher.update(project.as_bytes());
    hasher.update(snapshot.as_bytes());
    hasher.update(root.as_bytes());
    hasher.update(tree_generation.get().to_be_bytes());
    hasher.update(sandbox_generation.get().to_be_bytes());
    hasher.update(tree_commitment.as_bytes());
    hasher.update(export_commitment.as_bytes());
    hasher.update((manifest.media_type().as_str().len() as u64).to_be_bytes());
    hasher.update(manifest.media_type().as_str().as_bytes());
    hasher.update(manifest.digest().as_bytes());
    hasher.update(manifest.encoded_size().to_be_bytes());
    hasher.update(retention_plan.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Names durable monotonic detach stages.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DetachStageV1 {
    /// Exact detach recipe is durable.
    Planned = 0,
    /// Destination no longer selects the attachment.
    Detached = 1,
    /// Current inventory verified exact absence.
    Verified = 2,
    /// Terminal completion is durable.
    Completed = 3,
    /// Unstarted detach was authoritatively abandoned.
    Aborted = 4,
    /// Detach entered terminal fail-closed recovery.
    Faulted = 5,
}

/// Stores one verified durable detach-stage observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetachStageObservationV1 {
    sequence: u64,
    stage: DetachStageV1,
    inventory_commitment: ObjectDigest,
}

impl DetachStageObservationV1 {
    /// Creates an observation only after durable inventory verification.
    pub(crate) const fn from_verified_parts(
        sequence: u64,
        stage: DetachStageV1,
        inventory_commitment: ObjectDigest,
    ) -> Self {
        Self {
            sequence,
            stage,
            inventory_commitment,
        }
    }

    /// Returns the one-based durable sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the observed detach stage.
    #[must_use]
    pub const fn stage(self) -> DetachStageV1 {
        self.stage
    }

    /// Returns the authenticated inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }
}

/// Owns replayable monotonic progress for one exact detach recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableDetachProgressV1 {
    project: ProjectId,
    tree_generation: Revision,
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    detach_commitment: ObjectDigest,
    observations: Vec<DetachStageObservationV1>,
}

/// Retains a verifier-issued protected head for detach reconstruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedDetachHeadV1 {
    project: ProjectId,
    tree_generation: Revision,
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    detach_commitment: ObjectDigest,
    history_commitment: ObjectDigest,
    protected_head_commitment: ObjectDigest,
}

impl RetainedDetachHeadV1 {
    /// Creates evidence only after protected durable-state verification.
    pub(crate) const fn from_verified_parts(
        project: ProjectId,
        tree_generation: Revision,
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        detach_commitment: ObjectDigest,
        history_commitment: ObjectDigest,
        protected_head_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            tree_generation,
            attachment,
            attachment_generation,
            detach_commitment,
            history_commitment,
            protected_head_commitment,
        }
    }

    /// Returns the protected project identity.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the protected tree generation.
    #[must_use]
    pub const fn tree_generation(self) -> Revision {
        self.tree_generation
    }

    /// Returns the protected attachment identity.
    #[must_use]
    pub const fn attachment(self) -> AttachmentId {
        self.attachment
    }

    /// Returns the protected attachment generation.
    #[must_use]
    pub const fn attachment_generation(self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the protected detach commitment.
    #[must_use]
    pub const fn detach_commitment(self) -> ObjectDigest {
        self.detach_commitment
    }

    /// Returns the complete detach-history commitment.
    #[must_use]
    pub const fn history_commitment(self) -> ObjectDigest {
        self.history_commitment
    }

    /// Returns evidence that the head came from protected storage.
    #[must_use]
    pub const fn protected_head_commitment(self) -> ObjectDigest {
        self.protected_head_commitment
    }
}

impl DurableDetachProgressV1 {
    /// Reconstructs canonical detach progress and verifies every transition
    /// and the complete history commitment without creating effect authority.
    pub(crate) fn from_canonical_parts(
        project: ProjectId,
        tree_generation: Revision,
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        detach_commitment: ObjectDigest,
        observations: Vec<DetachStageObservationV1>,
        history_commitment: ObjectDigest,
    ) -> Result<Self, HierarchyRecoveryError> {
        if project.as_bytes() == &[0; 16]
            || tree_generation.get() == 0
            || attachment.as_bytes() == &[0; 16]
            || attachment_generation.get() == 0
            || detach_commitment.as_bytes() == &[0; 32]
            || history_commitment.as_bytes() == &[0; 32]
            || observations.is_empty()
            || observations.len() > MAXIMUM_REALIZATION_STAGE_HISTORY
        {
            return Err(HierarchyRecoveryError::CorruptProgress);
        }
        for (index, observation) in observations.iter().copied().enumerate() {
            let sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(HierarchyRecoveryError::Capacity)?;
            if observation.sequence != sequence
                || observation.inventory_commitment.as_bytes() == &[0; 32]
                || (index == 0 && observation.stage != DetachStageV1::Planned)
            {
                return Err(HierarchyRecoveryError::CorruptProgress);
            }
            if index != 0 {
                let prior = observations
                    .get(index - 1)
                    .ok_or(HierarchyRecoveryError::CorruptProgress)?;
                if !detach_transition_is_valid(prior.stage, observation.stage) {
                    return Err(HierarchyRecoveryError::InvalidTransition);
                }
            }
        }
        let progress = Self {
            project,
            tree_generation,
            attachment,
            attachment_generation,
            detach_commitment,
            observations,
        };
        if progress.history_commitment() != history_commitment {
            return Err(HierarchyRecoveryError::CorruptProgress);
        }
        Ok(progress)
    }

    /// Creates planned durable detach progress from one exact recipe.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError::UnspecifiedIdentity`] for a zero
    /// durable plan observation.
    pub fn planned(
        detach: &AttachmentDetachV1,
        durable_plan_observation: ObjectDigest,
    ) -> Result<Self, HierarchyRecoveryError> {
        if durable_plan_observation.as_bytes() == &[0; 32] {
            return Err(HierarchyRecoveryError::UnspecifiedIdentity);
        }
        Ok(Self {
            project: detach.project(),
            tree_generation: detach.tree_generation(),
            attachment: detach.attachment(),
            attachment_generation: detach.generation(),
            detach_commitment: detach.detach_commitment(),
            observations: vec![DetachStageObservationV1 {
                sequence: 1,
                stage: DetachStageV1::Planned,
                inventory_commitment: durable_plan_observation,
            }],
        })
    }

    /// Recovers complete detach history against a protected head commitment.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError`] for an unrelated recipe, malformed
    /// transition history, or protected-head mismatch.
    pub fn recover(
        detach: &AttachmentDetachV1,
        observations: Vec<DetachStageObservationV1>,
        retained_head: RetainedDetachHeadV1,
    ) -> Result<Self, HierarchyRecoveryError> {
        if observations.is_empty() || observations.len() > MAXIMUM_REALIZATION_STAGE_HISTORY {
            return Err(HierarchyRecoveryError::CorruptProgress);
        }
        for (index, observation) in observations.iter().copied().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(HierarchyRecoveryError::Capacity)?;
            if observation.sequence != expected
                || observation.inventory_commitment.as_bytes() == &[0; 32]
                || (index == 0 && observation.stage != DetachStageV1::Planned)
            {
                return Err(HierarchyRecoveryError::CorruptProgress);
            }
            if index != 0 {
                let prior = observations
                    .get(index - 1)
                    .ok_or(HierarchyRecoveryError::CorruptProgress)?;
                if !detach_transition_is_valid(prior.stage, observation.stage) {
                    return Err(HierarchyRecoveryError::InvalidTransition);
                }
            }
        }
        let progress = Self {
            project: detach.project(),
            tree_generation: detach.tree_generation(),
            attachment: detach.attachment(),
            attachment_generation: detach.generation(),
            detach_commitment: detach.detach_commitment(),
            observations,
        };
        if retained_head.project != progress.project
            || retained_head.tree_generation != progress.tree_generation
            || retained_head.attachment != progress.attachment
            || retained_head.attachment_generation != progress.attachment_generation
            || retained_head.detach_commitment != progress.detach_commitment
            || retained_head.history_commitment != progress.history_commitment()
            || retained_head.protected_head_commitment.as_bytes() == &[0; 32]
        {
            return Err(HierarchyRecoveryError::ProtectedHeadMismatch);
        }
        Ok(progress)
    }

    /// Advances one exact successor stage from authenticated current inventory.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError`] for stale sequence, unrelated
    /// inventory, invalid transition, or exhausted bounded history.
    pub fn advance_observed(
        &mut self,
        expected_sequence: u64,
        inventory: CurrentHierarchyProtectedEvidenceV1<'_, VerifiedDetachRebootInventoryV1>,
    ) -> Result<(), HierarchyRecoveryError> {
        let inventory = inventory.into_evidence();
        let current = self
            .observations
            .last()
            .copied()
            .ok_or(HierarchyRecoveryError::CorruptProgress)?;
        if current.sequence != expected_sequence
            || inventory.attachment != self.attachment
            || inventory.attachment_generation != self.attachment_generation
            || inventory.detach_commitment != self.detach_commitment
        {
            return Err(HierarchyRecoveryError::StaleProgress);
        }
        if !detach_transition_is_valid(current.stage, inventory.stage) {
            return Err(HierarchyRecoveryError::InvalidTransition);
        }
        if inventory.inventory_commitment.as_bytes() == &[0; 32]
            || self.observations.len() >= MAXIMUM_REALIZATION_STAGE_HISTORY
        {
            return Err(HierarchyRecoveryError::Capacity);
        }
        self.observations
            .try_reserve(1)
            .map_err(|_| HierarchyRecoveryError::Capacity)?;
        self.observations.push(DetachStageObservationV1 {
            sequence: expected_sequence
                .checked_add(1)
                .ok_or(HierarchyRecoveryError::Capacity)?,
            stage: inventory.stage,
            inventory_commitment: inventory.inventory_commitment,
        });
        Ok(())
    }

    /// Returns the detached attachment identity.
    #[must_use]
    pub const fn attachment(&self) -> AttachmentId {
        self.attachment
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the project-tree generation used to derive the detach.
    #[must_use]
    pub const fn tree_generation(&self) -> Revision {
        self.tree_generation
    }

    /// Returns the detached generation.
    #[must_use]
    pub const fn attachment_generation(&self) -> DesiredGeneration {
        self.attachment_generation
    }

    /// Returns the exact detach recipe commitment.
    #[must_use]
    pub const fn detach_commitment(&self) -> ObjectDigest {
        self.detach_commitment
    }

    /// Returns complete durable observations.
    #[must_use]
    pub fn observations(&self) -> &[DetachStageObservationV1] {
        &self.observations
    }

    /// Returns the current durable stage.
    #[must_use]
    pub fn current_stage(&self) -> Option<DetachStageV1> {
        self.observations
            .last()
            .map(|observation| observation.stage)
    }

    /// Returns the commitment to the complete detach history.
    #[must_use]
    pub fn history_commitment(&self) -> ObjectDigest {
        commit_detach_history(
            self.project,
            self.tree_generation,
            self.attachment,
            self.attachment_generation,
            self.detach_commitment,
            &self.observations,
        )
    }

    /// Returns the exact prior durable history head for a non-planned advance.
    #[must_use]
    pub fn predecessor_history_commitment(&self) -> Option<ObjectDigest> {
        let predecessor_length = self.observations.len().checked_sub(1)?;
        if predecessor_length == 0 {
            return None;
        }
        Some(commit_detach_history(
            self.project,
            self.tree_generation,
            self.attachment,
            self.attachment_generation,
            self.detach_commitment,
            &self.observations[..predecessor_length],
        ))
    }
}

fn commit_detach_history(
    project: ProjectId,
    tree_generation: Revision,
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    detach_commitment: ObjectDigest,
    observations: &[DetachStageObservationV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.detach-progress.v1\0");
    hasher.update(project.as_bytes());
    hasher.update(tree_generation.get().to_be_bytes());
    hasher.update(attachment.as_bytes());
    hasher.update(attachment_generation.get().to_be_bytes());
    hasher.update(detach_commitment.as_bytes());
    hasher.update((observations.len() as u64).to_be_bytes());
    for observation in observations {
        hasher.update(observation.sequence.to_be_bytes());
        hasher.update([observation.stage as u8]);
        hasher.update(observation.inventory_commitment.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn detach_transition_is_valid(from: DetachStageV1, to: DetachStageV1) -> bool {
    matches!(
        (from, to),
        (DetachStageV1::Planned, DetachStageV1::Detached)
            | (DetachStageV1::Detached, DetachStageV1::Verified)
            | (DetachStageV1::Verified, DetachStageV1::Completed)
            | (DetachStageV1::Planned, DetachStageV1::Aborted)
            | (
                DetachStageV1::Detached | DetachStageV1::Verified,
                DetachStageV1::Faulted
            )
    )
}

/// Describes reboot reconciliation for one exact detach recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetachReconciliationV1 {
    /// Current and durable state agree but a fresh authority is required.
    AwaitFreshAuthority,
    /// One exact observed successor stage must first become durable.
    RecordObserved(DetachStageObservationV1),
    /// Detach is terminally complete.
    Complete,
    /// Detach is terminally aborted.
    Aborted,
    /// Detach is terminally faulted.
    Faulted,
    /// Durable and current inventory conflict.
    Conflict,
}

/// Carries authenticated current detach inventory for reboot reconciliation.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedDetachRebootInventoryV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    detach_commitment: ObjectDigest,
    stage: DetachStageV1,
    inventory_commitment: ObjectDigest,
}

impl VerifiedDetachRebootInventoryV1 {
    /// Creates evidence only after a trusted current-inventory observation.
    pub(super) const fn from_verified_parts(
        _authority: &ProtectedCurrentEvidenceAuthorityV1,
        attachment: AttachmentId,
        attachment_generation: DesiredGeneration,
        detach_commitment: ObjectDigest,
        stage: DetachStageV1,
        inventory_commitment: ObjectDigest,
    ) -> Self {
        Self {
            attachment,
            attachment_generation,
            detach_commitment,
            stage,
            inventory_commitment,
        }
    }

    pub(super) const fn attachment(&self) -> AttachmentId {
        self.attachment
    }

    pub(super) const fn attachment_generation(&self) -> DesiredGeneration {
        self.attachment_generation
    }

    pub(super) const fn detach_commitment(&self) -> ObjectDigest {
        self.detach_commitment
    }

    pub(super) const fn stage(&self) -> DetachStageV1 {
        self.stage
    }

    pub(super) const fn inventory_commitment(&self) -> ObjectDigest {
        self.inventory_commitment
    }
}

/// Reconciles detach progress with one authenticated current stage observation.
#[must_use]
pub fn reconcile_detach_after_reboot(
    progress: &DurableDetachProgressV1,
    inventory: CurrentHierarchyProtectedEvidenceV1<'_, VerifiedDetachRebootInventoryV1>,
) -> DetachReconciliationV1 {
    let inventory = inventory.into_evidence();
    let Some(current) = progress.current_stage() else {
        return DetachReconciliationV1::Conflict;
    };
    if inventory.attachment != progress.attachment
        || inventory.attachment_generation != progress.attachment_generation
        || inventory.detach_commitment != progress.detach_commitment
        || inventory.inventory_commitment.as_bytes() == &[0; 32]
    {
        return DetachReconciliationV1::Conflict;
    }
    if current == inventory.stage {
        return match current {
            DetachStageV1::Completed => DetachReconciliationV1::Complete,
            DetachStageV1::Aborted => DetachReconciliationV1::Aborted,
            DetachStageV1::Faulted => DetachReconciliationV1::Faulted,
            _ => DetachReconciliationV1::AwaitFreshAuthority,
        };
    }
    if detach_transition_is_valid(current, inventory.stage) {
        let sequence = progress
            .observations()
            .last()
            .and_then(|observation| observation.sequence().checked_add(1));
        return match sequence {
            Some(sequence) => DetachReconciliationV1::RecordObserved(
                DetachStageObservationV1::from_verified_parts(
                    sequence,
                    inventory.stage,
                    inventory.inventory_commitment,
                ),
            ),
            None => DetachReconciliationV1::Conflict,
        };
    }
    DetachReconciliationV1::Conflict
}

/// Selects the terminal observation for one action in a multi-action plan.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TransactionActionOutcomeV1 {
    /// The exact action completed.
    Completed = 0,
    /// The action aborted before publication.
    Aborted = 1,
    /// The action entered terminal fail-closed state.
    Faulted = 2,
}

impl TransactionActionOutcomeV1 {
    /// Returns the stable canonical wire discriminant.
    #[must_use]
    pub const fn discriminant(self) -> u8 {
        self as u8
    }
}

/// Records one exact terminal action outcome in canonical attachment order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionActionObservationV1 {
    attachment: AttachmentId,
    action_commitment: ObjectDigest,
    outcome: TransactionActionOutcomeV1,
    inventory_commitment: ObjectDigest,
}

impl TransactionActionObservationV1 {
    /// Creates an observation only after current terminal inventory verification.
    pub(crate) const fn from_verified_parts(
        attachment: AttachmentId,
        action_commitment: ObjectDigest,
        outcome: TransactionActionOutcomeV1,
        inventory_commitment: ObjectDigest,
    ) -> Self {
        Self {
            attachment,
            action_commitment,
            outcome,
            inventory_commitment,
        }
    }

    /// Returns the action attachment.
    #[must_use]
    pub const fn attachment(self) -> AttachmentId {
        self.attachment
    }

    /// Returns the recipe or detach commitment.
    #[must_use]
    pub const fn action_commitment(self) -> ObjectDigest {
        self.action_commitment
    }

    /// Returns the terminal action outcome.
    #[must_use]
    pub const fn outcome(self) -> TransactionActionOutcomeV1 {
        self.outcome
    }

    /// Returns the terminal inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }
}

/// Owns a reboot-reconstructable terminal subset of one atomic view transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableRealizationTransactionV1 {
    project: ProjectId,
    tree_generation: Revision,
    plan_commitment: ObjectDigest,
    actions: Vec<TransactionActionObservationV1>,
    state_commitment: ObjectDigest,
}

/// Retains a verifier-issued protected head for a multi-action transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedRealizationTransactionHeadV1 {
    project: ProjectId,
    tree_generation: Revision,
    plan_commitment: ObjectDigest,
    state_commitment: ObjectDigest,
    protected_head_commitment: ObjectDigest,
}

impl RetainedRealizationTransactionHeadV1 {
    /// Creates evidence only after protected durable-state verification.
    pub(crate) const fn from_verified_parts(
        project: ProjectId,
        tree_generation: Revision,
        plan_commitment: ObjectDigest,
        state_commitment: ObjectDigest,
        protected_head_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            tree_generation,
            plan_commitment,
            state_commitment,
            protected_head_commitment,
        }
    }

    /// Returns the protected project identity.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the protected tree generation.
    #[must_use]
    pub const fn tree_generation(self) -> Revision {
        self.tree_generation
    }

    /// Returns the protected plan commitment.
    #[must_use]
    pub const fn plan_commitment(self) -> ObjectDigest {
        self.plan_commitment
    }

    /// Returns the protected transaction-state commitment.
    #[must_use]
    pub const fn state_commitment(self) -> ObjectDigest {
        self.state_commitment
    }

    /// Returns evidence that the head came from protected storage.
    #[must_use]
    pub const fn protected_head_commitment(self) -> ObjectDigest {
        self.protected_head_commitment
    }
}

impl DurableRealizationTransactionV1 {
    /// Reconstructs one canonical durable transaction subset and verifies its
    /// attachment ordering, terminal observations, and state commitment.
    pub(crate) fn from_canonical_parts(
        project: ProjectId,
        tree_generation: Revision,
        plan_commitment: ObjectDigest,
        actions: Vec<TransactionActionObservationV1>,
        state_commitment: ObjectDigest,
    ) -> Result<Self, HierarchyRecoveryError> {
        if project.as_bytes() == &[0; 16]
            || tree_generation.get() == 0
            || plan_commitment.as_bytes() == &[0; 32]
            || state_commitment.as_bytes() == &[0; 32]
            || actions.len() > super::realizer::MAXIMUM_REALIZATION_ACTIONS
            || !actions
                .windows(2)
                .all(|pair| pair[0].attachment < pair[1].attachment)
            || actions.iter().any(|action| {
                action.attachment.as_bytes() == &[0; 16]
                    || action.action_commitment.as_bytes() == &[0; 32]
                    || action.inventory_commitment.as_bytes() == &[0; 32]
            })
        {
            return Err(HierarchyRecoveryError::CorruptProgress);
        }
        let expected =
            commit_transaction_state(project, tree_generation, plan_commitment, &actions);
        if expected != state_commitment {
            return Err(HierarchyRecoveryError::CorruptProgress);
        }
        Ok(Self {
            project,
            tree_generation,
            plan_commitment,
            actions,
            state_commitment,
        })
    }

    /// Creates an empty durable transaction state for one exact plan.
    #[must_use]
    pub fn planned(plan: &ViewRealizationPlanV1) -> Self {
        Self {
            project: plan.project(),
            tree_generation: plan.tree_generation(),
            plan_commitment: plan.plan_commitment(),
            actions: Vec::new(),
            state_commitment: commit_transaction_state(
                plan.project(),
                plan.tree_generation(),
                plan.plan_commitment(),
                &[],
            ),
        }
    }

    /// Recovers canonical action outcomes and verifies exact plan membership.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError`] for duplicate, unknown, conflicting,
    /// or unauthenticated action observations.
    pub fn recover(
        plan: &ViewRealizationPlanV1,
        actions: Vec<TransactionActionObservationV1>,
        retained_head: RetainedRealizationTransactionHeadV1,
    ) -> Result<Self, HierarchyRecoveryError> {
        if actions.len() > super::realizer::MAXIMUM_REALIZATION_ACTIONS
            || !actions
                .windows(2)
                .all(|pair| pair[0].attachment < pair[1].attachment)
        {
            return Err(HierarchyRecoveryError::CorruptProgress);
        }
        let expected: BTreeMap<_, _> = plan
            .publications()
            .iter()
            .map(|action| (action.attachment(), action.recipe_commitment()))
            .chain(
                plan.detaches()
                    .iter()
                    .map(|action| (action.attachment(), action.detach_commitment())),
            )
            .collect();
        if actions.len() > plan.execution_order().len()
            || actions.iter().any(|action| {
                expected.get(&action.attachment) != Some(&action.action_commitment)
                    || action.inventory_commitment.as_bytes() == &[0; 32]
            })
        {
            return Err(HierarchyRecoveryError::PlanMismatch);
        }
        for (index, expected_action) in plan
            .execution_order()
            .iter()
            .take(actions.len())
            .enumerate()
        {
            let observation = actions
                .binary_search_by_key(&expected_action.attachment(), |action| action.attachment)
                .ok()
                .and_then(|position| actions.get(position))
                .ok_or(HierarchyRecoveryError::InvalidTransition)?;
            if index + 1 != actions.len()
                && observation.outcome != TransactionActionOutcomeV1::Completed
            {
                return Err(HierarchyRecoveryError::InvalidTransition);
            }
        }
        let state_commitment = commit_transaction_state(
            plan.project(),
            plan.tree_generation(),
            plan.plan_commitment(),
            &actions,
        );
        if retained_head.project != plan.project()
            || retained_head.tree_generation != plan.tree_generation()
            || retained_head.plan_commitment != plan.plan_commitment()
            || retained_head.state_commitment != state_commitment
            || retained_head.protected_head_commitment.as_bytes() == &[0; 32]
        {
            return Err(HierarchyRecoveryError::ProtectedHeadMismatch);
        }
        Ok(Self {
            project: plan.project(),
            tree_generation: plan.tree_generation(),
            plan_commitment: plan.plan_commitment(),
            actions,
            state_commitment,
        })
    }

    /// Appends one previously unrecorded terminal action observation.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyRecoveryError`] for stale transaction state,
    /// unrelated action, duplicate outcome, or bounded capacity exhaustion.
    pub fn advance(
        &mut self,
        plan: &ViewRealizationPlanV1,
        expected_state_commitment: ObjectDigest,
        observation: TransactionActionObservationV1,
    ) -> Result<(), HierarchyRecoveryError> {
        if self.project != plan.project()
            || self.tree_generation != plan.tree_generation()
            || self.plan_commitment != plan.plan_commitment()
            || self.state_commitment != expected_state_commitment
            || observation.inventory_commitment.as_bytes() == &[0; 32]
            || self
                .actions
                .iter()
                .any(|action| action.outcome != TransactionActionOutcomeV1::Completed)
        {
            return Err(HierarchyRecoveryError::StaleProgress);
        }
        let expected_action = plan
            .execution_order()
            .get(self.actions.len())
            .ok_or(HierarchyRecoveryError::InvalidTransition)?;
        if expected_action.attachment() != observation.attachment {
            return Err(HierarchyRecoveryError::InvalidTransition);
        }
        let action_commitment = plan
            .publications()
            .iter()
            .find(|action| action.attachment() == observation.attachment)
            .map(|action| action.recipe_commitment())
            .or_else(|| {
                plan.detaches()
                    .iter()
                    .find(|action| action.attachment() == observation.attachment)
                    .map(|action| action.detach_commitment())
            })
            .ok_or(HierarchyRecoveryError::PlanMismatch)?;
        let insertion = self
            .actions
            .binary_search_by_key(&observation.attachment, |action| action.attachment);
        if action_commitment != observation.action_commitment
            || self.actions.len() >= super::realizer::MAXIMUM_REALIZATION_ACTIONS
        {
            return Err(HierarchyRecoveryError::InvalidTransition);
        }
        let index = match insertion {
            Ok(_) => return Err(HierarchyRecoveryError::InvalidTransition),
            Err(index) => index,
        };
        self.actions
            .try_reserve(1)
            .map_err(|_| HierarchyRecoveryError::Capacity)?;
        self.actions.insert(index, observation);
        self.state_commitment = commit_transaction_state(
            self.project,
            self.tree_generation,
            self.plan_commitment,
            &self.actions,
        );
        Ok(())
    }

    /// Returns the project authority domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the exact plan tree generation.
    #[must_use]
    pub const fn tree_generation(&self) -> Revision {
        self.tree_generation
    }

    /// Returns the immutable plan commitment.
    #[must_use]
    pub const fn plan_commitment(&self) -> ObjectDigest {
        self.plan_commitment
    }

    /// Returns canonical terminal action observations.
    #[must_use]
    pub fn actions(&self) -> &[TransactionActionObservationV1] {
        &self.actions
    }

    /// Returns the protected transaction-state commitment.
    #[must_use]
    pub const fn state_commitment(&self) -> ObjectDigest {
        self.state_commitment
    }

    /// Returns the exact transaction state that must immediately precede this state.
    #[must_use]
    pub fn predecessor_state_commitment(&self) -> ObjectDigest {
        let predecessor_length = self.actions.len().saturating_sub(1);
        if self.actions.is_empty() {
            return self.plan_commitment;
        }
        commit_transaction_state(
            self.project,
            self.tree_generation,
            self.plan_commitment,
            &self.actions[..predecessor_length],
        )
    }
}

fn commit_transaction_state(
    project: ProjectId,
    tree_generation: Revision,
    plan_commitment: ObjectDigest,
    actions: &[TransactionActionObservationV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.realization-transaction-state.v1\0");
    hasher.update(project.as_bytes());
    hasher.update(tree_generation.get().to_be_bytes());
    hasher.update(plan_commitment.as_bytes());
    hasher.update((actions.len() as u64).to_be_bytes());
    for action in actions {
        hasher.update(action.attachment.as_bytes());
        hasher.update(action.action_commitment.as_bytes());
        hasher.update([action.outcome.discriminant()]);
        hasher.update(action.inventory_commitment.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Describes atomic transaction recovery without authorizing an effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealizationTransactionReconciliationV1 {
    /// No terminal failure exists and remaining actions may resume with fresh authority.
    Continue,
    /// Every action completed successfully.
    Complete,
    /// Fresh authority is required to compensate in the returned reverse order.
    AwaitCompensationAuthority(Vec<AttachmentId>),
    /// Supplied state does not belong to the plan.
    Conflict,
}

/// Reconciles a multi-action transaction and derives deterministic compensation order.
#[must_use]
pub fn reconcile_realization_transaction_after_reboot(
    plan: &ViewRealizationPlanV1,
    state: &DurableRealizationTransactionV1,
) -> RealizationTransactionReconciliationV1 {
    if state.project != plan.project()
        || state.tree_generation != plan.tree_generation()
        || state.plan_commitment != plan.plan_commitment()
    {
        return RealizationTransactionReconciliationV1::Conflict;
    }
    let expected_count = match plan.publications().len().checked_add(plan.detaches().len()) {
        Some(count) => count,
        None => return RealizationTransactionReconciliationV1::Conflict,
    };
    let failed = state.actions.iter().any(|action| {
        matches!(
            action.outcome,
            TransactionActionOutcomeV1::Aborted | TransactionActionOutcomeV1::Faulted
        )
    });
    if !failed && state.actions.len() == expected_count {
        return RealizationTransactionReconciliationV1::Complete;
    }
    if !failed {
        return RealizationTransactionReconciliationV1::Continue;
    }
    let residual: BTreeSet<_> = state
        .actions
        .iter()
        .filter_map(|action| {
            matches!(
                action.outcome,
                TransactionActionOutcomeV1::Completed | TransactionActionOutcomeV1::Faulted
            )
            .then_some(action.attachment)
        })
        .collect();
    let mut compensation = Vec::new();
    if compensation.try_reserve_exact(residual.len()).is_err() {
        return RealizationTransactionReconciliationV1::Conflict;
    }
    compensation.extend(
        plan.execution_order()
            .iter()
            .rev()
            .map(|action| action.attachment())
            .filter(|attachment| residual.contains(attachment)),
    );
    RealizationTransactionReconciliationV1::AwaitCompensationAuthority(compensation)
}

/// Reports invalid, stale, or conflicting snapshot and reboot recovery state.
#[derive(Debug, thiserror::Error)]
pub enum HierarchyRecoveryError {
    /// A required identity, descriptor, or commitment is zero.
    #[error("hierarchy recovery contains an unspecified identity")]
    UnspecifiedIdentity,
    /// The subtree root is absent from the current tree.
    #[error("hierarchy snapshot root is absent")]
    UnknownSandbox,
    /// Snapshot export closure belongs to another root.
    #[error("hierarchy snapshot export closure does not match its root")]
    ExportClosureMismatch,
    /// Stable snapshot closure contains a kernel-coupled live source.
    #[error("hierarchy snapshot export closure is not fully immutable")]
    MutableSnapshotSource,
    /// Portable snapshot bytes, ancestry, or source assignment conflict.
    #[error("portable snapshot content does not match its descriptor or hierarchy closure")]
    PortableSnapshotMismatch,
    /// Physical retention evidence conflicts with the prepared manifest.
    #[error("hierarchy snapshot retention evidence conflicts")]
    RetentionEvidenceMismatch,
    /// A realization recipe is absent from the immutable plan.
    #[error("hierarchy realization progress does not match its plan")]
    PlanMismatch,
    /// Durable realization progress has no current observation.
    #[error("hierarchy realization progress is corrupt")]
    CorruptProgress,
    /// Protected durable head does not match supplied realization history.
    #[error("protected realization head does not match recovered progress")]
    ProtectedHeadMismatch,
    /// Expected realization sequence or stage is stale.
    #[error("hierarchy realization progress compare-and-swap is stale")]
    StaleProgress,
    /// A realization stage skipped or regressed.
    #[error("hierarchy realization stage transition is invalid")]
    InvalidTransition,
    /// Fresh recovery authority or current inventory conflicts with progress.
    #[error("hierarchy recovery evidence conflicts with durable progress")]
    RecoveryEvidenceMismatch,
    /// Bounded history or checked arithmetic is exhausted.
    #[error("hierarchy recovery capacity is exhausted")]
    Capacity,
    /// Canonical tree encoding failed.
    #[error(transparent)]
    Codec(#[from] HierarchyCodecError),
}
