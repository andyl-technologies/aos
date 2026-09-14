//! Atomic pure ownership of current tree state and idempotent transition history.
//!
//! This owner is source-only: a future journal adapter must persist the encoded
//! successor and history record atomically before publishing it as current.
//! Each history request commitment rebinds the caller's normalized request to
//! every reducer argument and compare-and-swap fence.

use aos_sandbox_core::{
    DesiredGeneration, IncarnationId, ObjectDigest, OperationId, ProjectId, Revision, SandboxId,
};
use sha2::{Digest as _, Sha256};

use super::codec::{HierarchyCodecError, tree_commitment_v1};
use super::evidence::{VerifiedDetachCompletionV1, VerifiedRealizationTransactionCompletionV1};
use super::graph::{SandboxTreeError, SandboxTreeV1};
use super::history::{
    CompactedHierarchyHistoryV1, HierarchyHistoryAppendV1, HierarchyHistoryCheckpointV1,
    HierarchyHistoryError, HierarchyHistoryRecordV1, HierarchyHistorySubjectV1, HierarchyHistoryV1,
    HierarchyTransitionKindV1, RetainedHierarchyHeadV1,
};
use super::model::SandboxTreeRecordV1;
use super::realizer::{AttachmentDetachV1, RealizationStageV1, ViewRealizationPlanV1};
use super::recovery::{
    CommittedHierarchySnapshotV1, DetachStageV1, DurableDetachProgressV1,
    DurableRealizationProgressV1, DurableRealizationTransactionV1, PreparedHierarchySnapshotV1,
};

/// Carries exact operation and idempotency metadata for one tree mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HierarchyMutationRequestV1 {
    operation: OperationId,
    idempotency_key: ObjectDigest,
    request_commitment: ObjectDigest,
}

impl HierarchyMutationRequestV1 {
    /// Constructs specified mutation metadata.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError::InvalidMutation`] for a zero field.
    pub fn new(
        operation: OperationId,
        idempotency_key: ObjectDigest,
        request_commitment: ObjectDigest,
    ) -> Result<Self, HierarchyStateError> {
        if operation.as_bytes() == &[0; 16]
            || idempotency_key.as_bytes() == &[0; 32]
            || request_commitment.as_bytes() == &[0; 32]
        {
            return Err(HierarchyStateError::InvalidMutation);
        }
        Ok(Self {
            operation,
            idempotency_key,
            request_commitment,
        })
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the project-scoped idempotency key commitment.
    #[must_use]
    pub const fn idempotency_key(self) -> ObjectDigest {
        self.idempotency_key
    }

    /// Returns the normalized request commitment that reducers bind to arguments.
    #[must_use]
    pub const fn request_commitment(self) -> ObjectDigest {
        self.request_commitment
    }
}

/// Reports a newly recorded transition or an exact replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HierarchyStateTransitionV1 {
    /// The successor and history record were accepted in this call.
    Recorded(HierarchyHistoryRecordV1),
    /// The exact request had already completed.
    Replay(HierarchyHistoryRecordV1),
}

/// Selects a complete history or a protected compacted floor with suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableHierarchyHistoryV1 {
    /// Retains every record from sequence one.
    Full(HierarchyHistoryV1),
    /// Retains a protected floor summary and subsequent records.
    Compacted(CompactedHierarchyHistoryV1),
}

impl DurableHierarchyHistoryV1 {
    fn project(&self) -> ProjectId {
        match self {
            Self::Full(history) => history.project(),
            Self::Compacted(history) => history.checkpoint().project(),
        }
    }

    fn records(&self) -> &[HierarchyHistoryRecordV1] {
        match self {
            Self::Full(history) => history.records(),
            Self::Compacted(history) => history.suffix(),
        }
    }

    fn total_record_count(&self) -> Result<u64, HierarchyStateError> {
        match self {
            Self::Full(history) => u64::try_from(history.records().len())
                .map_err(|_| HierarchyStateError::HistoryStateMismatch),
            Self::Compacted(history) => u64::try_from(history.suffix().len())
                .ok()
                .and_then(|count| history.checkpoint().through_sequence().checked_add(count))
                .ok_or(HierarchyStateError::HistoryStateMismatch),
        }
    }

    fn record_commitment(&self) -> Option<ObjectDigest> {
        match self {
            Self::Full(history) => history
                .records()
                .last()
                .map(|record| record.record_commitment()),
            Self::Compacted(history) => Some(
                history
                    .suffix()
                    .last()
                    .map(|record| record.record_commitment())
                    .unwrap_or(history.checkpoint().through_record_commitment()),
            ),
        }
    }

    fn resource_head(&self, subject: HierarchyHistorySubjectV1) -> Option<ObjectDigest> {
        match self {
            Self::Full(history) => history.resource_head(subject),
            Self::Compacted(history) => history.resource_head(subject),
        }
    }

    fn idempotency_record(&self, key: ObjectDigest) -> Option<HierarchyHistoryRecordV1> {
        match self {
            Self::Full(history) => history.idempotency_record(key),
            Self::Compacted(history) => history.idempotency_record(key),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn append(
        &mut self,
        subject: HierarchyHistorySubjectV1,
        transition: HierarchyTransitionKindV1,
        operation: OperationId,
        idempotency_key: ObjectDigest,
        request_commitment: ObjectDigest,
        expected_resource_head: Option<ObjectDigest>,
        result_commitment: ObjectDigest,
    ) -> Result<HierarchyHistoryAppendV1, HierarchyHistoryError> {
        match self {
            Self::Full(history) => history.append(
                subject,
                transition,
                operation,
                idempotency_key,
                request_commitment,
                expected_resource_head,
                result_commitment,
            ),
            Self::Compacted(history) => history.append(
                subject,
                transition,
                operation,
                idempotency_key,
                request_commitment,
                expected_resource_head,
                result_commitment,
            ),
        }
    }
}

/// Owns one current validated tree and its project-scoped operation history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableHierarchyStateV1 {
    tree: SandboxTreeV1,
    history: DurableHierarchyHistoryV1,
}

impl DurableHierarchyStateV1 {
    /// Recovers a current tree against history and a protected durable head.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for a project, head, or tree-result
    /// mismatch. Truncated history cannot match the exact retained head.
    pub fn recover(
        tree: SandboxTreeV1,
        history: DurableHierarchyHistoryV1,
        retained_head: RetainedHierarchyHeadV1,
    ) -> Result<Self, HierarchyStateError> {
        if tree.project() != history.project() || retained_head.project() != tree.project() {
            return Err(HierarchyStateError::ProjectMismatch);
        }
        let record_count = history.total_record_count()?;
        let record_commitment = history.record_commitment();
        let tree_commitment = tree_commitment_v1(&tree)?;
        if retained_head.record_count() != record_count
            || retained_head.record_commitment() != record_commitment
            || retained_head.tree_commitment() != tree_commitment
            || retained_head.protected_head_commitment().as_bytes() == &[0; 32]
        {
            return Err(HierarchyStateError::ProtectedHeadMismatch);
        }
        let latest_tree_record = history
            .records()
            .iter()
            .rev()
            .find(|record| transition_changes_tree(record.transition()));
        match latest_tree_record {
            Some(record) if record.result_commitment() != tree_commitment => {
                return Err(HierarchyStateError::HistoryStateMismatch);
            }
            None if matches!(&history, DurableHierarchyHistoryV1::Full(full) if tree.records().len() != 0 || !full.records().is_empty()) =>
            {
                return Err(HierarchyStateError::HistoryStateMismatch);
            }
            None if matches!(&history, DurableHierarchyHistoryV1::Compacted(compacted) if compacted.checkpoint().state_commitment() != tree_commitment) =>
            {
                return Err(HierarchyStateError::HistoryStateMismatch);
            }
            _ => {}
        }
        Ok(Self { tree, history })
    }

    /// Returns the current validated project tree.
    #[must_use]
    pub const fn tree(&self) -> &SandboxTreeV1 {
        &self.tree
    }

    /// Returns the validated project-scoped history.
    #[must_use]
    pub const fn history(&self) -> &DurableHierarchyHistoryV1 {
        &self.history
    }

    /// Advances the durable history floor through the current protected head.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] unless the checkpoint covers the exact
    /// current record count and current tree state commitment.
    pub fn compact_history(
        &mut self,
        checkpoint: HierarchyHistoryCheckpointV1,
    ) -> Result<(), HierarchyStateError> {
        if checkpoint.through_sequence() != self.history.total_record_count()?
            || checkpoint.state_commitment() != tree_commitment_v1(&self.tree)?
        {
            return Err(HierarchyStateError::ProtectedHeadMismatch);
        }
        let compacted = match &self.history {
            DurableHierarchyHistoryV1::Full(history) => history.compact_through(checkpoint)?,
            DurableHierarchyHistoryV1::Compacted(history) => history.compact_through(checkpoint)?,
        };
        self.history = DurableHierarchyHistoryV1::Compacted(compacted);
        Ok(())
    }

    /// Inserts one project root or generation-fenced child atomically in memory.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for stale graph input, conflicting
    /// idempotency, or canonical encoding failure.
    pub fn insert(
        &mut self,
        record: SandboxTreeRecordV1,
        expected_tree_generation: Revision,
        expected_parent_generation: Option<DesiredGeneration>,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let kind = if record.parent().is_some() {
            HierarchyTransitionKindV1::CreateChild
        } else {
            HierarchyTransitionKindV1::CreateRoot
        };
        let subject = HierarchyHistorySubjectV1::Sandbox(record.sandbox());
        let request_commitment = commit_insert_request(
            self.tree.project(),
            kind,
            record,
            expected_tree_generation,
            expected_parent_generation,
            request.request_commitment(),
        );
        self.commit(subject, kind, request, request_commitment, |tree| {
            tree.insert(record, expected_tree_generation, expected_parent_generation)
        })
    }

    /// Advances one sandbox desired generation without changing topology.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for stale graph input, conflicting
    /// idempotency, or canonical encoding failure.
    pub fn advance_sandbox_generation(
        &mut self,
        sandbox: SandboxId,
        expected_tree_generation: Revision,
        expected_sandbox_generation: DesiredGeneration,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let transition = HierarchyTransitionKindV1::UpdateSandbox;
        let request_commitment = commit_subject_request(
            self.tree.project(),
            transition,
            sandbox,
            expected_tree_generation,
            expected_sandbox_generation,
            request.request_commitment(),
        );
        self.commit(
            HierarchyHistorySubjectV1::Sandbox(sandbox),
            transition,
            request,
            request_commitment,
            |tree| {
                tree.advance_sandbox_generation(
                    sandbox,
                    expected_tree_generation,
                    expected_sandbox_generation,
                )
            },
        )
    }

    /// Reparents one stopped sandbox under exact subject, tree, and parent fences.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for stale graph input, conflicting
    /// idempotency, or canonical encoding failure.
    #[allow(clippy::too_many_arguments)]
    pub fn reparent(
        &mut self,
        sandbox: SandboxId,
        new_parent: Option<SandboxId>,
        expected_tree_generation: Revision,
        expected_sandbox_generation: DesiredGeneration,
        expected_new_parent_generation: Option<DesiredGeneration>,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let transition = HierarchyTransitionKindV1::ReparentSandbox;
        let request_commitment = commit_reparent_request(
            self.tree.project(),
            sandbox,
            expected_tree_generation,
            expected_sandbox_generation,
            new_parent,
            expected_new_parent_generation,
            request.request_commitment(),
        );
        self.commit(
            HierarchyHistorySubjectV1::Sandbox(sandbox),
            transition,
            request,
            request_commitment,
            |tree| {
                tree.reparent(
                    sandbox,
                    new_parent,
                    expected_tree_generation,
                    expected_sandbox_generation,
                    expected_new_parent_generation,
                )
            },
        )
    }

    /// Changes one sandbox's explicit live incarnation state.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for stale graph input, conflicting
    /// idempotency, or canonical encoding failure.
    pub fn set_incarnation(
        &mut self,
        sandbox: SandboxId,
        expected_tree_generation: Revision,
        expected_sandbox_generation: DesiredGeneration,
        incarnation: Option<IncarnationId>,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let transition = HierarchyTransitionKindV1::SetIncarnation;
        let request_commitment = commit_incarnation_request(
            self.tree.project(),
            sandbox,
            expected_tree_generation,
            expected_sandbox_generation,
            incarnation,
            request.request_commitment(),
        );
        self.commit(
            HierarchyHistorySubjectV1::Sandbox(sandbox),
            transition,
            request,
            request_commitment,
            |tree| {
                tree.set_incarnation(
                    sandbox,
                    expected_tree_generation,
                    expected_sandbox_generation,
                    incarnation,
                )
            },
        )
    }

    /// Deletes one stopped generation-fenced leaf.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for stale graph input, conflicting
    /// idempotency, or canonical encoding failure.
    pub fn delete_leaf(
        &mut self,
        sandbox: SandboxId,
        expected_tree_generation: Revision,
        expected_sandbox_generation: DesiredGeneration,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let transition = HierarchyTransitionKindV1::DeleteLeaf;
        let request_commitment = commit_subject_request(
            self.tree.project(),
            transition,
            sandbox,
            expected_tree_generation,
            expected_sandbox_generation,
            request.request_commitment(),
        );
        self.commit(
            HierarchyHistorySubjectV1::Sandbox(sandbox),
            transition,
            request,
            request_commitment,
            |tree| {
                tree.delete_leaf(
                    sandbox,
                    expected_tree_generation,
                    expected_sandbox_generation,
                )
            },
        )
    }

    /// Records one exact durable snapshot preparation without changing the tree.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for another project or tree generation,
    /// conflicting idempotency, or invalid history state.
    pub fn record_snapshot_preparation(
        &mut self,
        prepared: &PreparedHierarchySnapshotV1,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let subject = HierarchyHistorySubjectV1::Snapshot(prepared.snapshot());
        let transition = HierarchyTransitionKindV1::PrepareSnapshot;
        let result_commitment = prepared.preparation_commitment();
        if prepared.project() != self.tree.project() {
            return Err(self.artifact_binding_error(request));
        }
        if let Some(replay) =
            self.artifact_replay(subject, &[transition], request, result_commitment)?
        {
            return Ok(replay);
        }
        if prepared.captured_tree_generation() != self.tree.tree_generation()
            || self.history.resource_head(subject).is_some()
        {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        self.record_artifact(subject, transition, request, result_commitment)
    }

    /// Records one exact snapshot commit without changing the tree.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for another project or tree generation,
    /// conflicting idempotency, or invalid history state.
    pub fn record_snapshot_commit(
        &mut self,
        committed: &CommittedHierarchySnapshotV1,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let prepared = committed.prepared();
        let subject = HierarchyHistorySubjectV1::Snapshot(prepared.snapshot());
        let transition = HierarchyTransitionKindV1::CommitSnapshot;
        let result_commitment = committed.commit_commitment();
        if prepared.project() != self.tree.project() {
            return Err(self.artifact_binding_error(request));
        }
        if let Some(replay) =
            self.artifact_replay(subject, &[transition], request, result_commitment)?
        {
            return Ok(replay);
        }
        if prepared.captured_tree_generation() != self.tree.tree_generation()
            || self.history.resource_head(subject) != Some(prepared.preparation_commitment())
        {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        self.record_artifact(subject, transition, request, result_commitment)
    }

    /// Records a complete multi-action realization transaction.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for another project or tree generation,
    /// conflicting idempotency, or invalid history state.
    pub fn record_realization_plan(
        &mut self,
        plan: &ViewRealizationPlanV1,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let subject = HierarchyHistorySubjectV1::Project(plan.project());
        let transition = HierarchyTransitionKindV1::PlanRealizationTransaction;
        let result_commitment = plan.plan_commitment();
        if plan.project() != self.tree.project() {
            return Err(self.artifact_binding_error(request));
        }
        if let Some(replay) =
            self.artifact_replay(subject, &[transition], request, result_commitment)?
        {
            return Ok(replay);
        }
        if plan.tree_generation() != self.tree.tree_generation() {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        self.record_artifact(subject, transition, request, result_commitment)
    }

    /// Records current durable progress for one action in its complete plan.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for a plan/progress mismatch,
    /// conflicting idempotency, or invalid history state.
    pub fn record_realization_progress(
        &mut self,
        plan: &ViewRealizationPlanV1,
        progress: &DurableRealizationProgressV1,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let transition = match progress.current_stage() {
            Some(RealizationStageV1::Planned) => HierarchyTransitionKindV1::PlanRealization,
            Some(RealizationStageV1::Reaped) => HierarchyTransitionKindV1::CompleteRealization,
            Some(RealizationStageV1::Aborted) => HierarchyTransitionKindV1::AbortRealization,
            Some(RealizationStageV1::Faulted) => HierarchyTransitionKindV1::FaultRealization,
            Some(_) => HierarchyTransitionKindV1::AdvanceRealization,
            None => return Err(HierarchyStateError::ArtifactStateMismatch),
        };
        let subject = HierarchyHistorySubjectV1::Attachment(progress.attachment());
        let result_commitment = progress.history_commitment();
        let matching_recipe = plan
            .publications()
            .binary_search_by_key(&progress.attachment(), |recipe| recipe.attachment())
            .ok()
            .and_then(|index| plan.publications().get(index));
        if plan.project() != self.tree.project()
            || progress.project() != plan.project()
            || progress.tree_generation() != plan.tree_generation()
            || progress.plan_commitment() != plan.plan_commitment()
            || matching_recipe.is_none_or(|recipe| {
                recipe.intent().desired_generation() != progress.attachment_generation()
                    || recipe.recipe_commitment() != progress.recipe_commitment()
            })
        {
            return Err(self.artifact_binding_error(request));
        }
        if let Some(replay) =
            self.artifact_replay(subject, &[transition], request, result_commitment)?
        {
            return Ok(replay);
        }
        if plan.tree_generation() != self.tree.tree_generation() {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        if transition != HierarchyTransitionKindV1::PlanRealization
            && self.history.resource_head(subject) != progress.predecessor_history_commitment()
        {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        self.record_artifact(subject, transition, request, result_commitment)
    }

    /// Records one exact current detach action.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for another project or tree generation,
    /// conflicting idempotency, or invalid history state.
    pub fn record_detach_plan(
        &mut self,
        detach: &AttachmentDetachV1,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let subject = HierarchyHistorySubjectV1::Attachment(detach.attachment());
        let transition = HierarchyTransitionKindV1::PlanDetach;
        let result_commitment = detach.detach_commitment();
        if detach.project() != self.tree.project() {
            return Err(self.artifact_binding_error(request));
        }
        if let Some(replay) =
            self.artifact_replay(subject, &[transition], request, result_commitment)?
        {
            return Ok(replay);
        }
        if detach.tree_generation() != self.tree.tree_generation() {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        self.record_artifact(subject, transition, request, result_commitment)
    }

    /// Records terminal completion of one exact detach plan.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] unless verified terminal evidence binds
    /// the exact plan, project, generation, and nonzero inventory commitments.
    pub fn record_detach_completion(
        &mut self,
        detach: &AttachmentDetachV1,
        completion: VerifiedDetachCompletionV1,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let subject = HierarchyHistorySubjectV1::Attachment(detach.attachment());
        let transition = HierarchyTransitionKindV1::CompleteDetach;
        let result_commitment = completion.completion_commitment();
        if detach.project() != self.tree.project()
            || completion.project() != detach.project()
            || completion.tree_generation() != detach.tree_generation()
            || completion.attachment() != detach.attachment()
            || completion.attachment_generation() != detach.generation()
            || completion.detach_commitment() != detach.detach_commitment()
            || completion.inventory_commitment().as_bytes() == &[0; 32]
        {
            return Err(self.artifact_binding_error(request));
        }
        if let Some(replay) =
            self.artifact_replay(subject, &[transition], request, result_commitment)?
        {
            return Ok(replay);
        }
        if detach.tree_generation() != self.tree.tree_generation()
            || self.history.resource_head(subject) != Some(completion.detach_history_commitment())
        {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        self.record_artifact(subject, transition, request, result_commitment)
    }

    /// Records exact durable progress for one detach recipe.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] for a plan/progress mismatch,
    /// conflicting idempotency, or invalid history state.
    pub fn record_detach_progress(
        &mut self,
        detach: &AttachmentDetachV1,
        progress: &DurableDetachProgressV1,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let subject = HierarchyHistorySubjectV1::Attachment(detach.attachment());
        let result_commitment = progress.history_commitment();
        let replay_transitions: &[HierarchyTransitionKindV1] = match progress.current_stage() {
            Some(DetachStageV1::Planned) => &[
                HierarchyTransitionKindV1::PlanDetach,
                HierarchyTransitionKindV1::AdvanceDetach,
            ],
            Some(DetachStageV1::Completed) => &[HierarchyTransitionKindV1::CompleteDetach],
            Some(_) => &[HierarchyTransitionKindV1::AdvanceDetach],
            None => return Err(HierarchyStateError::ArtifactStateMismatch),
        };
        if detach.project() != self.tree.project()
            || progress.attachment() != detach.attachment()
            || progress.project() != detach.project()
            || progress.tree_generation() != detach.tree_generation()
            || progress.attachment_generation() != detach.generation()
            || progress.detach_commitment() != detach.detach_commitment()
        {
            return Err(self.artifact_binding_error(request));
        }
        if let Some(replay) =
            self.artifact_replay(subject, replay_transitions, request, result_commitment)?
        {
            return Ok(replay);
        }
        if detach.tree_generation() != self.tree.tree_generation() {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        let current_head = self.history.resource_head(subject);
        let transition = match progress.current_stage() {
            Some(DetachStageV1::Planned) if current_head == Some(detach.detach_commitment()) => {
                HierarchyTransitionKindV1::AdvanceDetach
            }
            Some(DetachStageV1::Planned) => HierarchyTransitionKindV1::PlanDetach,
            Some(DetachStageV1::Completed) => HierarchyTransitionKindV1::CompleteDetach,
            Some(_) => HierarchyTransitionKindV1::AdvanceDetach,
            None => return Err(HierarchyStateError::ArtifactStateMismatch),
        };
        if progress.current_stage() != Some(DetachStageV1::Planned)
            && current_head != progress.predecessor_history_commitment()
        {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        self.record_artifact(subject, transition, request, result_commitment)
    }

    /// Records a protected multi-action recovery state for its exact plan.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] unless the state binds the current plan.
    pub fn record_realization_transaction_state(
        &mut self,
        plan: &ViewRealizationPlanV1,
        state: &DurableRealizationTransactionV1,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let subject = HierarchyHistorySubjectV1::Project(plan.project());
        let transition = HierarchyTransitionKindV1::AdvanceRealizationTransaction;
        let result_commitment = state.state_commitment();
        if plan.project() != self.tree.project()
            || state.project() != plan.project()
            || state.tree_generation() != plan.tree_generation()
            || state.plan_commitment() != plan.plan_commitment()
        {
            return Err(self.artifact_binding_error(request));
        }
        if let Some(replay) =
            self.artifact_replay(subject, &[transition], request, result_commitment)?
        {
            return Ok(replay);
        }
        if plan.tree_generation() != self.tree.tree_generation()
            || self.history.resource_head(subject) != Some(state.predecessor_state_commitment())
        {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        self.record_artifact(subject, transition, request, result_commitment)
    }

    /// Records terminal completion of a complete multi-action transaction.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyStateError`] unless verified terminal heads bind the
    /// exact plan and project with nonzero commitments.
    pub fn record_realization_transaction_completion(
        &mut self,
        plan: &ViewRealizationPlanV1,
        completion: VerifiedRealizationTransactionCompletionV1,
        request: HierarchyMutationRequestV1,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        let subject = HierarchyHistorySubjectV1::Project(plan.project());
        let transition = HierarchyTransitionKindV1::CompleteRealizationTransaction;
        let result_commitment = completion.completion_commitment();
        if plan.project() != self.tree.project()
            || completion.project() != plan.project()
            || completion.tree_generation() != plan.tree_generation()
            || completion.plan_commitment() != plan.plan_commitment()
            || completion.terminal_heads_commitment().as_bytes() == &[0; 32]
        {
            return Err(self.artifact_binding_error(request));
        }
        if let Some(replay) =
            self.artifact_replay(subject, &[transition], request, result_commitment)?
        {
            return Ok(replay);
        }
        if plan.tree_generation() != self.tree.tree_generation()
            || self.history.resource_head(subject)
                != Some(completion.transaction_state_commitment())
        {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        self.record_artifact(subject, transition, request, result_commitment)
    }

    /// Classifies a companion mismatch as a conflict when its key is retained.
    fn artifact_binding_error(&self, request: HierarchyMutationRequestV1) -> HierarchyStateError {
        if self
            .history
            .idempotency_record(request.idempotency_key())
            .is_some()
        {
            HierarchyStateError::IdempotencyConflict
        } else {
            HierarchyStateError::ArtifactStateMismatch
        }
    }

    /// Resolves an exact retained retry without consulting freshness fences.
    fn artifact_replay(
        &self,
        subject: HierarchyHistorySubjectV1,
        allowed_transitions: &[HierarchyTransitionKindV1],
        request: HierarchyMutationRequestV1,
        result_commitment: ObjectDigest,
    ) -> Result<Option<HierarchyStateTransitionV1>, HierarchyStateError> {
        let Some(record) = self.history.idempotency_record(request.idempotency_key()) else {
            return Ok(None);
        };
        let exact_request_commitment = commit_artifact_request(
            self.tree.project(),
            subject,
            record.transition(),
            request.request_commitment(),
            result_commitment,
        );
        if record.subject() != subject
            || !allowed_transitions.contains(&record.transition())
            || record.operation() != request.operation()
            || record.request_commitment() != exact_request_commitment
            || record.result_commitment() != result_commitment
        {
            return Err(HierarchyStateError::IdempotencyConflict);
        }
        Ok(Some(HierarchyStateTransitionV1::Replay(record)))
    }

    fn record_artifact(
        &mut self,
        subject: HierarchyHistorySubjectV1,
        transition: HierarchyTransitionKindV1,
        request: HierarchyMutationRequestV1,
        result_commitment: ObjectDigest,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError> {
        if result_commitment.as_bytes() == &[0; 32] {
            return Err(HierarchyStateError::ArtifactStateMismatch);
        }
        let request_commitment = commit_artifact_request(
            self.tree.project(),
            subject,
            transition,
            request.request_commitment(),
            result_commitment,
        );
        let expected_resource_head = self.history.resource_head(subject);
        let appended = self.history.append(
            subject,
            transition,
            request.operation(),
            request.idempotency_key(),
            request_commitment,
            expected_resource_head,
            result_commitment,
        )?;
        Ok(match appended {
            HierarchyHistoryAppendV1::Recorded(record) => {
                HierarchyStateTransitionV1::Recorded(record)
            }
            HierarchyHistoryAppendV1::Replay(record) => HierarchyStateTransitionV1::Replay(record),
        })
    }

    fn commit<F>(
        &mut self,
        subject: HierarchyHistorySubjectV1,
        transition: HierarchyTransitionKindV1,
        request: HierarchyMutationRequestV1,
        request_commitment: ObjectDigest,
        reduce: F,
    ) -> Result<HierarchyStateTransitionV1, HierarchyStateError>
    where
        F: FnOnce(&SandboxTreeV1) -> Result<SandboxTreeV1, SandboxTreeError>,
    {
        if let Some(record) = self.history.idempotency_record(request.idempotency_key()) {
            if record.subject() == subject
                && record.transition() == transition
                && record.operation() == request.operation()
                && record.request_commitment() == request_commitment
            {
                return Ok(HierarchyStateTransitionV1::Replay(record));
            }
            return Err(HierarchyStateError::IdempotencyConflict);
        }

        let expected_resource_head = self.history.resource_head(subject);
        let successor = reduce(&self.tree)?;
        let result_commitment = tree_commitment_v1(&successor)?;
        let append = self.history.append(
            subject,
            transition,
            request.operation(),
            request.idempotency_key(),
            request_commitment,
            expected_resource_head,
            result_commitment,
        )?;
        let HierarchyHistoryAppendV1::Recorded(record) = append else {
            return Err(HierarchyStateError::HistoryStateMismatch);
        };
        self.tree = successor;
        Ok(HierarchyStateTransitionV1::Recorded(record))
    }
}

fn commit_artifact_request(
    project: ProjectId,
    subject: HierarchyHistorySubjectV1,
    transition: HierarchyTransitionKindV1,
    normalized_request: ObjectDigest,
    result_commitment: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.hierarchy-artifact-request.v1\0");
    hasher.update(project.as_bytes());
    hasher.update([subject.tag(), transition as u8]);
    hasher.update(subject.bytes());
    hasher.update(normalized_request.as_bytes());
    hasher.update(result_commitment.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn commit_insert_request(
    project: ProjectId,
    transition: HierarchyTransitionKindV1,
    record: SandboxTreeRecordV1,
    expected_tree_generation: Revision,
    expected_parent_generation: Option<DesiredGeneration>,
    normalized_request: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = begin_request_commitment(
        project,
        transition,
        record.sandbox(),
        expected_tree_generation,
        normalized_request,
    );
    hash_optional_generation(&mut hasher, None);
    hash_optional_sandbox(&mut hasher, record.parent());
    hash_optional_generation(&mut hasher, expected_parent_generation);
    hash_optional_generation(&mut hasher, Some(record.desired_generation()));
    hash_optional_incarnation(&mut hasher, record.incarnation());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn commit_subject_request(
    project: ProjectId,
    transition: HierarchyTransitionKindV1,
    sandbox: SandboxId,
    expected_tree_generation: Revision,
    expected_sandbox_generation: DesiredGeneration,
    normalized_request: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = begin_request_commitment(
        project,
        transition,
        sandbox,
        expected_tree_generation,
        normalized_request,
    );
    hash_optional_generation(&mut hasher, Some(expected_sandbox_generation));
    ObjectDigest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn commit_reparent_request(
    project: ProjectId,
    sandbox: SandboxId,
    expected_tree_generation: Revision,
    expected_sandbox_generation: DesiredGeneration,
    new_parent: Option<SandboxId>,
    expected_new_parent_generation: Option<DesiredGeneration>,
    normalized_request: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = begin_request_commitment(
        project,
        HierarchyTransitionKindV1::ReparentSandbox,
        sandbox,
        expected_tree_generation,
        normalized_request,
    );
    hash_optional_generation(&mut hasher, Some(expected_sandbox_generation));
    hash_optional_sandbox(&mut hasher, new_parent);
    hash_optional_generation(&mut hasher, expected_new_parent_generation);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn commit_incarnation_request(
    project: ProjectId,
    sandbox: SandboxId,
    expected_tree_generation: Revision,
    expected_sandbox_generation: DesiredGeneration,
    incarnation: Option<IncarnationId>,
    normalized_request: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = begin_request_commitment(
        project,
        HierarchyTransitionKindV1::SetIncarnation,
        sandbox,
        expected_tree_generation,
        normalized_request,
    );
    hash_optional_generation(&mut hasher, Some(expected_sandbox_generation));
    hash_optional_incarnation(&mut hasher, incarnation);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn begin_request_commitment(
    project: ProjectId,
    transition: HierarchyTransitionKindV1,
    sandbox: SandboxId,
    expected_tree_generation: Revision,
    normalized_request: ObjectDigest,
) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.hierarchy-tree-mutation.v1\0");
    hasher.update(project.as_bytes());
    hasher.update([transition as u8]);
    hasher.update(sandbox.as_bytes());
    hasher.update(expected_tree_generation.get().to_be_bytes());
    hasher.update(normalized_request.as_bytes());
    hasher
}

fn hash_optional_sandbox(hasher: &mut Sha256, value: Option<SandboxId>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.as_bytes());
        }
        None => {
            hasher.update([0]);
            hasher.update([0; 16]);
        }
    }
}

fn hash_optional_incarnation(hasher: &mut Sha256, value: Option<IncarnationId>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.as_bytes());
        }
        None => {
            hasher.update([0]);
            hasher.update([0; 16]);
        }
    }
}

fn hash_optional_generation(hasher: &mut Sha256, value: Option<DesiredGeneration>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.get().to_be_bytes());
        }
        None => {
            hasher.update([0]);
            hasher.update([0; 8]);
        }
    }
}

fn transition_changes_tree(transition: HierarchyTransitionKindV1) -> bool {
    matches!(
        transition,
        HierarchyTransitionKindV1::CreateRoot
            | HierarchyTransitionKindV1::CreateChild
            | HierarchyTransitionKindV1::UpdateSandbox
            | HierarchyTransitionKindV1::ReparentSandbox
            | HierarchyTransitionKindV1::SetIncarnation
            | HierarchyTransitionKindV1::DeleteLeaf
    )
}

/// Reports invalid, stale, conflicting, or corrupt durable hierarchy state.
#[derive(Debug, thiserror::Error)]
pub enum HierarchyStateError {
    /// Mutation metadata contains a zero field.
    #[error("hierarchy mutation metadata is invalid")]
    InvalidMutation,
    /// Tree and history belong to different projects.
    #[error("hierarchy tree and history projects differ")]
    ProjectMismatch,
    /// Current tree does not match the last tree-transition result.
    #[error("hierarchy history does not commit the current tree")]
    HistoryStateMismatch,
    /// Protected durable head does not match the supplied history and tree.
    #[error("protected hierarchy head does not match recovered state")]
    ProtectedHeadMismatch,
    /// One idempotency key was reused for different semantics.
    #[error("hierarchy idempotency key conflicts with prior use")]
    IdempotencyConflict,
    /// A snapshot, realization, or detach conflicts with current source state.
    #[error("hierarchy artifact does not match current durable source state")]
    ArtifactStateMismatch,
    /// The pure graph reducer rejected the mutation.
    #[error(transparent)]
    Tree(#[from] SandboxTreeError),
    /// Canonical tree commitment failed.
    #[error(transparent)]
    Codec(#[from] HierarchyCodecError),
    /// History append or recovery failed.
    #[error(transparent)]
    History(#[from] HierarchyHistoryError),
}
