//! Checks recorded realization, detach and transaction history DATA.
//!
//! Canonical constructors reproduce the historical bounded state machines and
//! commitments. Recorded claims confer no native currentness or effect grant.

use std::collections::{BTreeMap, BTreeSet};
use aos_sandbox_model::{AttachmentId, DesiredGeneration, ObjectDigest, ProjectId, Revision, SnapshotId};
use sha2::{Digest as _, Sha256};
use crate::hierarchy::codec::HierarchyCodecError;
use super::realization::{AttachmentDetachV1, AttachmentRealizationV1, RealizationStageV1, ReplacementTransactionV1, ViewRealizationPlanV1};

/// Maximum monotonic observations retained for one realization operation.
pub const MAXIMUM_REALIZATION_STAGE_HISTORY: usize = 64;

/// Selects the only two recovery outcomes for a durable snapshot preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedSnapshotRecoveryDecisionV1 {
    /// Continues retention observation and commit.
    Continue,
    /// Aborts the uncommitted preparation without publishing it.
    Rollback,
}

/// Carries a fresh recorded decision for one exact snapshot preparation.
#[derive(Debug, Eq, PartialEq)]
pub struct RecordedSnapshotRecoveryAuthorityV1 {
    project: ProjectId,
    snapshot: SnapshotId,
    preparation_commitment: ObjectDigest,
    decision: PreparedSnapshotRecoveryDecisionV1,
    authority_commitment: ObjectDigest,
}

impl RecordedSnapshotRecoveryAuthorityV1 {
    /// Constructs comparison DATA only for the canonical saved-record decoder.
    pub(super) const fn from_recorded_parts(
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

/// Stores one monotonic realization-stage observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealizationStageObservationV1 {
    sequence: u64,
    stage: RealizationStageV1,
    inventory_commitment: ObjectDigest,
}

impl RealizationStageObservationV1 {
    /// Creates an observation only from the recorded durable hierarchy decoder.
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

    /// Returns the recorded inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(self) -> ObjectDigest {
        self.inventory_commitment
    }
}

/// Retains a trusted current inventory proof for one exact stage transition.
#[derive(Debug, Eq, PartialEq)]
pub struct RecordedStageTransitionV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    from: RealizationStageV1,
    to: RealizationStageV1,
    inventory_commitment: ObjectDigest,
}

impl RecordedStageTransitionV1 {
    /// Constructs comparison DATA only for the canonical saved-record decoder.
    pub(super) fn from_recorded_parts(
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
    pub(crate) const fn from_recorded_parts(
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

/// Selects an recorded reboot inventory state for one exact recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebootInventoryStateV1 {
    /// No realization with the recipe identity is present.
    Absent,
    /// A detached prepared realization is present but unpublished.
    Prepared,
    /// The recipe is published but not post-recorded.
    Published,
    /// The recipe is published and post-recorded.
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

/// Retains recorded reboot inventory without exposing effect authority.
#[derive(Debug, Eq, PartialEq)]
pub struct RecordedRebootRealizationInventoryV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    state: RebootInventoryStateV1,
    recoverable_predecessor: Option<ReplacementTransactionV1>,
    inventory_commitment: ObjectDigest,
}

impl RecordedRebootRealizationInventoryV1 {
    /// Creates inventory only after a protected observation adapter verifies it.
    pub(super) fn from_recorded_parts(
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
pub struct RecordedPublishedRollbackAuthorityV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    authority_commitment: ObjectDigest,
}

impl RecordedPublishedRollbackAuthorityV1 {
    /// Constructs comparison DATA only for the canonical saved-record decoder.
    pub(super) const fn from_recorded_parts(
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
pub struct RecordedPreparedRealizationAuthorityV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    recipe_commitment: ObjectDigest,
    decision: PreparedRealizationRecoveryDecisionV1,
    authority_commitment: ObjectDigest,
}

impl RecordedPreparedRealizationAuthorityV1 {
    /// Constructs comparison DATA only for the canonical saved-record decoder.
    pub(super) const fn from_recorded_parts(
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

/// Names durable monotonic detach stages.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DetachStageV1 {
    /// Exact detach recipe is durable.
    Planned = 0,
    /// Destination no longer selects the attachment.
    Detached = 1,
    /// Current inventory recorded exact absence.
    Verified = 2,
    /// Terminal completion is durable.
    Completed = 3,
    /// Unstarted detach was authoritatively abandoned.
    Aborted = 4,
    /// Detach entered terminal fail-closed recovery.
    Faulted = 5,
}

/// Stores one recorded durable detach-stage observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetachStageObservationV1 {
    sequence: u64,
    stage: DetachStageV1,
    inventory_commitment: ObjectDigest,
}

impl DetachStageObservationV1 {
    /// Creates an observation only after durable inventory verification.
    pub(crate) const fn from_recorded_parts(
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

    /// Returns the recorded inventory commitment.
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
    /// Constructs comparison DATA only for the canonical saved-record decoder.
    pub(crate) const fn from_recorded_parts(
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

/// Carries recorded current detach inventory for reboot reconciliation.
#[derive(Debug, Eq, PartialEq)]
pub struct RecordedDetachRebootInventoryV1 {
    attachment: AttachmentId,
    attachment_generation: DesiredGeneration,
    detach_commitment: ObjectDigest,
    stage: DetachStageV1,
    inventory_commitment: ObjectDigest,
}

impl RecordedDetachRebootInventoryV1 {
    /// Constructs comparison DATA only for the canonical saved-record decoder.
    pub(super) const fn from_recorded_parts(
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
    pub(crate) const fn from_recorded_parts(
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
    /// Constructs comparison DATA only for the canonical saved-record decoder.
    pub(crate) const fn from_recorded_parts(
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
            || actions.len() > super::realization::MAXIMUM_REALIZATION_ACTIONS
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
