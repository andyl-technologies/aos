//! Bounded digest-linked hierarchy operation history and idempotency replay.

use std::collections::BTreeMap;

use aos_sandbox_core::{AttachmentId, ObjectDigest, OperationId, ProjectId, SandboxId, SnapshotId};
use sha2::{Digest as _, Sha256};

/// Maximum retained source-model history records.
pub const MAXIMUM_HIERARCHY_HISTORY_RECORDS: usize = 250_000;

/// Selects the exact logical resource changed by one history record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HierarchyHistorySubjectV1 {
    /// Project-wide tree or accounting state.
    Project(ProjectId),
    /// One logical sandbox.
    Sandbox(SandboxId),
    /// One logical attachment.
    Attachment(AttachmentId),
    /// One immutable sandbox snapshot.
    Snapshot(SnapshotId),
}

impl HierarchyHistorySubjectV1 {
    /// Returns the fixed canonical subject discriminant.
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Project(_) => 0,
            Self::Sandbox(_) => 1,
            Self::Attachment(_) => 2,
            Self::Snapshot(_) => 3,
        }
    }

    /// Returns the subject identity as exact canonical bytes.
    pub(crate) const fn bytes(self) -> [u8; 16] {
        match self {
            Self::Project(value) => value.into_bytes(),
            Self::Sandbox(value) => value.into_bytes(),
            Self::Attachment(value) => value.into_bytes(),
            Self::Snapshot(value) => value.into_bytes(),
        }
    }
}

/// Names one closed hierarchy or view transition class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HierarchyTransitionKindV1 {
    /// Creates a project-root sandbox.
    CreateRoot = 0,
    /// Creates a generation-fenced child sandbox.
    CreateChild = 1,
    /// Replaces sandbox desired state without changing parent.
    UpdateSandbox = 2,
    /// Changes one sandbox's logical parent.
    ReparentSandbox = 3,
    /// Changes one sandbox's runtime incarnation observation.
    SetIncarnation = 4,
    /// Deletes one proven leaf.
    DeleteLeaf = 5,
    /// Prepares an immutable hierarchy snapshot.
    PrepareSnapshot = 6,
    /// Commits retained snapshot evidence.
    CommitSnapshot = 7,
    /// Records a complete attachment realization plan.
    PlanRealization = 8,
    /// Advances one realization stage.
    AdvanceRealization = 9,
    /// Records terminal realization completion.
    CompleteRealization = 10,
    /// Records terminal realization abort.
    AbortRealization = 11,
    /// Records one exact detach plan.
    PlanDetach = 12,
    /// Records terminal detach completion.
    CompleteDetach = 13,
    /// Records one complete multi-action realization transaction.
    PlanRealizationTransaction = 14,
    /// Commits terminal completion of a multi-action transaction.
    CompleteRealizationTransaction = 15,
    /// Records a terminal fail-closed realization fault.
    FaultRealization = 16,
    /// Advances one durable detach stage.
    AdvanceDetach = 17,
    /// Advances one multi-action transaction recovery state.
    AdvanceRealizationTransaction = 18,
}

impl HierarchyTransitionKindV1 {
    fn supports_subject(self, subject: HierarchyHistorySubjectV1) -> bool {
        matches!(
            (self, subject),
            (
                Self::CreateRoot
                    | Self::CreateChild
                    | Self::UpdateSandbox
                    | Self::ReparentSandbox
                    | Self::SetIncarnation
                    | Self::DeleteLeaf,
                HierarchyHistorySubjectV1::Sandbox(_)
            ) | (
                Self::PrepareSnapshot | Self::CommitSnapshot,
                HierarchyHistorySubjectV1::Snapshot(_)
            ) | (
                Self::PlanRealization
                    | Self::AdvanceRealization
                    | Self::CompleteRealization
                    | Self::AbortRealization
                    | Self::FaultRealization
                    | Self::PlanDetach
                    | Self::AdvanceDetach
                    | Self::CompleteDetach,
                HierarchyHistorySubjectV1::Attachment(_)
            ) | (
                Self::PlanRealizationTransaction
                    | Self::AdvanceRealizationTransaction
                    | Self::CompleteRealizationTransaction,
                HierarchyHistorySubjectV1::Project(_)
            )
        )
    }

    /// Decodes one closed transition discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError::CorruptRecord`] for an unknown value.
    pub(crate) fn from_byte(value: u8) -> Result<Self, HierarchyHistoryError> {
        match value {
            0 => Ok(Self::CreateRoot),
            1 => Ok(Self::CreateChild),
            2 => Ok(Self::UpdateSandbox),
            3 => Ok(Self::ReparentSandbox),
            4 => Ok(Self::SetIncarnation),
            5 => Ok(Self::DeleteLeaf),
            6 => Ok(Self::PrepareSnapshot),
            7 => Ok(Self::CommitSnapshot),
            8 => Ok(Self::PlanRealization),
            9 => Ok(Self::AdvanceRealization),
            10 => Ok(Self::CompleteRealization),
            11 => Ok(Self::AbortRealization),
            12 => Ok(Self::PlanDetach),
            13 => Ok(Self::CompleteDetach),
            14 => Ok(Self::PlanRealizationTransaction),
            15 => Ok(Self::CompleteRealizationTransaction),
            16 => Ok(Self::FaultRealization),
            17 => Ok(Self::AdvanceDetach),
            18 => Ok(Self::AdvanceRealizationTransaction),
            _ => Err(HierarchyHistoryError::CorruptRecord),
        }
    }
}

/// Stores one canonical digest-linked source-model history record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HierarchyHistoryRecordV1 {
    project: ProjectId,
    sequence: u64,
    subject: HierarchyHistorySubjectV1,
    transition: HierarchyTransitionKindV1,
    operation: OperationId,
    idempotency_key: ObjectDigest,
    request_commitment: ObjectDigest,
    prior_resource_commitment: Option<ObjectDigest>,
    predecessor: Option<ObjectDigest>,
    result_commitment: ObjectDigest,
    record_commitment: ObjectDigest,
}

impl HierarchyHistoryRecordV1 {
    /// Constructs and commits one validated canonical record.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError::InvalidRecord`] for zero fields or an
    /// illegal transition/subject pairing.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        project: ProjectId,
        sequence: u64,
        subject: HierarchyHistorySubjectV1,
        transition: HierarchyTransitionKindV1,
        operation: OperationId,
        idempotency_key: ObjectDigest,
        request_commitment: ObjectDigest,
        prior_resource_commitment: Option<ObjectDigest>,
        predecessor: Option<ObjectDigest>,
        result_commitment: ObjectDigest,
    ) -> Result<Self, HierarchyHistoryError> {
        if project.as_bytes() == &[0; 16]
            || sequence == 0
            || subject.bytes() == [0; 16]
            || operation.as_bytes() == &[0; 16]
            || idempotency_key.as_bytes() == &[0; 32]
            || request_commitment.as_bytes() == &[0; 32]
            || prior_resource_commitment.is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || predecessor.is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || result_commitment.as_bytes() == &[0; 32]
            || matches!(subject, HierarchyHistorySubjectV1::Project(value) if value != project)
            || !transition.supports_subject(subject)
        {
            return Err(HierarchyHistoryError::InvalidRecord);
        }
        let mut record = Self {
            project,
            sequence,
            subject,
            transition,
            operation,
            idempotency_key,
            request_commitment,
            prior_resource_commitment,
            predecessor,
            result_commitment,
            record_commitment: ObjectDigest::from_bytes([0; 32]),
        };
        record.record_commitment = record.compute_commitment();
        Ok(record)
    }

    /// Reconstructs one record only when its stored commitment is exact.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError`] for invalid fields or commitment drift.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_decoded_parts(
        project: ProjectId,
        sequence: u64,
        subject: HierarchyHistorySubjectV1,
        transition: HierarchyTransitionKindV1,
        operation: OperationId,
        idempotency_key: ObjectDigest,
        request_commitment: ObjectDigest,
        prior_resource_commitment: Option<ObjectDigest>,
        predecessor: Option<ObjectDigest>,
        result_commitment: ObjectDigest,
        record_commitment: ObjectDigest,
    ) -> Result<Self, HierarchyHistoryError> {
        let expected = Self::from_parts(
            project,
            sequence,
            subject,
            transition,
            operation,
            idempotency_key,
            request_commitment,
            prior_resource_commitment,
            predecessor,
            result_commitment,
        )?;
        if expected.record_commitment != record_commitment {
            return Err(HierarchyHistoryError::CorruptRecord);
        }
        Ok(expected)
    }

    /// Returns the project-scoped history domain.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the one-based history sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the exact changed resource.
    #[must_use]
    pub const fn subject(self) -> HierarchyHistorySubjectV1 {
        self.subject
    }

    /// Returns the closed transition class.
    #[must_use]
    pub const fn transition(self) -> HierarchyTransitionKindV1 {
        self.transition
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

    /// Returns the normalized request commitment.
    #[must_use]
    pub const fn request_commitment(self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the compare-and-swap head for this logical resource.
    #[must_use]
    pub const fn prior_resource_commitment(self) -> Option<ObjectDigest> {
        self.prior_resource_commitment
    }

    /// Returns the preceding record commitment, if any.
    #[must_use]
    pub const fn predecessor(self) -> Option<ObjectDigest> {
        self.predecessor
    }

    /// Returns the committed deterministic result.
    #[must_use]
    pub const fn result_commitment(self) -> ObjectDigest {
        self.result_commitment
    }

    /// Returns this record's domain-separated commitment.
    #[must_use]
    pub const fn record_commitment(self) -> ObjectDigest {
        self.record_commitment
    }

    fn compute_commitment(self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.hierarchy-history-record.v1\0");
        hasher.update(self.project.as_bytes());
        hasher.update(self.sequence.to_be_bytes());
        hasher.update([self.subject.tag(), self.transition as u8]);
        hasher.update(self.subject.bytes());
        hasher.update(self.operation.as_bytes());
        hasher.update(self.idempotency_key.as_bytes());
        hasher.update(self.request_commitment.as_bytes());
        match self.prior_resource_commitment {
            Some(commitment) => {
                hasher.update([1]);
                hasher.update(commitment.as_bytes());
            }
            None => {
                hasher.update([0]);
                hasher.update([0; 32]);
            }
        }
        match self.predecessor {
            Some(predecessor) => {
                hasher.update([1]);
                hasher.update(predecessor.as_bytes());
            }
            None => {
                hasher.update([0]);
                hasher.update([0; 32]);
            }
        }
        hasher.update(self.result_commitment.as_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

/// Reports whether an append committed or replayed an exact prior result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HierarchyHistoryAppendV1 {
    /// The new record was appended.
    Recorded(HierarchyHistoryRecordV1),
    /// The exact idempotent request already completed.
    Replay(HierarchyHistoryRecordV1),
}

/// Retains a protected durable head for rollback-resistant state recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedHierarchyHeadV1 {
    project: ProjectId,
    record_count: u64,
    record_commitment: Option<ObjectDigest>,
    tree_commitment: ObjectDigest,
    protected_head_commitment: ObjectDigest,
}

impl RetainedHierarchyHeadV1 {
    /// Creates a head only after a future durable adapter verifies protected state.
    pub(crate) fn from_verified_parts(
        project: ProjectId,
        record_count: u64,
        record_commitment: Option<ObjectDigest>,
        tree_commitment: ObjectDigest,
        protected_head_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            record_count,
            record_commitment,
            tree_commitment,
            protected_head_commitment,
        }
    }

    /// Returns the project-scoped history domain.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the exact durable record count.
    #[must_use]
    pub const fn record_count(self) -> u64 {
        self.record_count
    }

    /// Returns the exact final record commitment, or `None` for empty history.
    #[must_use]
    pub const fn record_commitment(self) -> Option<ObjectDigest> {
        self.record_commitment
    }

    /// Returns the canonical current-tree commitment retained with the head.
    #[must_use]
    pub const fn tree_commitment(self) -> ObjectDigest {
        self.tree_commitment
    }

    /// Returns evidence that the head came from protected durable state.
    #[must_use]
    pub const fn protected_head_commitment(self) -> ObjectDigest {
        self.protected_head_commitment
    }
}

/// Owns bounded validated history and its exact idempotency index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HierarchyHistoryV1 {
    project: ProjectId,
    records: Vec<HierarchyHistoryRecordV1>,
    idempotency: BTreeMap<ObjectDigest, usize>,
    resource_states: BTreeMap<HierarchyHistorySubjectV1, HierarchyTransitionKindV1>,
    resource_heads: BTreeMap<HierarchyHistorySubjectV1, ObjectDigest>,
}

impl HierarchyHistoryV1 {
    /// Reconstructs history only after validating sequence, predecessor, and
    /// idempotency uniqueness for every record.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError`] for oversized, corrupt, or conflicting
    /// history.
    pub fn from_records(
        project: ProjectId,
        records: Vec<HierarchyHistoryRecordV1>,
    ) -> Result<Self, HierarchyHistoryError> {
        if project.as_bytes() == &[0; 16] || records.len() > MAXIMUM_HIERARCHY_HISTORY_RECORDS {
            return Err(HierarchyHistoryError::Capacity);
        }
        let mut idempotency = BTreeMap::new();
        let mut resource_states = BTreeMap::new();
        let mut resource_heads = BTreeMap::new();
        let mut predecessor = None;
        for (index, record) in records.iter().copied().enumerate() {
            let sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(HierarchyHistoryError::Capacity)?;
            if record.project() != project
                || record.sequence() != sequence
                || record.predecessor() != predecessor
            {
                return Err(HierarchyHistoryError::CorruptHistory);
            }
            if idempotency
                .insert(record.idempotency_key(), index)
                .is_some()
            {
                return Err(HierarchyHistoryError::IdempotencyConflict);
            }
            validate_resource_transition(&resource_states, record.subject(), record.transition())?;
            if record.prior_resource_commitment() != resource_heads.get(&record.subject()).copied()
            {
                return Err(HierarchyHistoryError::StaleResourceHead);
            }
            resource_states.insert(record.subject(), record.transition());
            resource_heads.insert(record.subject(), record.result_commitment());
            predecessor = Some(record.record_commitment());
        }
        Ok(Self {
            project,
            records,
            idempotency,
            resource_states,
            resource_heads,
        })
    }

    /// Returns an empty project-scoped validated history.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError::InvalidRecord`] for a zero project.
    pub fn empty(project: ProjectId) -> Result<Self, HierarchyHistoryError> {
        if project.as_bytes() == &[0; 16] {
            return Err(HierarchyHistoryError::InvalidRecord);
        }
        Ok(Self {
            project,
            records: Vec::new(),
            idempotency: BTreeMap::new(),
            resource_states: BTreeMap::new(),
            resource_heads: BTreeMap::new(),
        })
    }

    /// Returns the project-scoped idempotency domain.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns records in durable sequence order.
    #[must_use]
    pub fn records(&self) -> &[HierarchyHistoryRecordV1] {
        &self.records
    }

    /// Finds a prior record by exact project-scoped idempotency key.
    #[must_use]
    pub fn idempotency_record(
        &self,
        idempotency_key: ObjectDigest,
    ) -> Option<HierarchyHistoryRecordV1> {
        self.idempotency
            .get(&idempotency_key)
            .and_then(|index| self.records.get(*index))
            .copied()
    }

    /// Returns the latest committed model head for one logical resource.
    #[must_use]
    pub fn resource_head(&self, subject: HierarchyHistorySubjectV1) -> Option<ObjectDigest> {
        self.resource_heads.get(&subject).copied()
    }

    /// Appends a new transition or returns an exact idempotent replay.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError::IdempotencyConflict`] when a key was
    /// used for different request semantics, or another variant for invalid
    /// or exhausted input.
    pub fn append(
        &mut self,
        subject: HierarchyHistorySubjectV1,
        transition: HierarchyTransitionKindV1,
        operation: OperationId,
        idempotency_key: ObjectDigest,
        request_commitment: ObjectDigest,
        expected_resource_head: Option<ObjectDigest>,
        result_commitment: ObjectDigest,
    ) -> Result<HierarchyHistoryAppendV1, HierarchyHistoryError> {
        if matches!(subject, HierarchyHistorySubjectV1::Project(project) if project != self.project)
            || !transition.supports_subject(subject)
        {
            return Err(HierarchyHistoryError::InvalidRecord);
        }
        if let Some(index) = self.idempotency.get(&idempotency_key).copied() {
            let record = self
                .records
                .get(index)
                .copied()
                .ok_or(HierarchyHistoryError::CorruptHistory)?;
            if record.subject() == subject
                && record.transition() == transition
                && record.operation() == operation
                && record.request_commitment() == request_commitment
                && record.prior_resource_commitment() == expected_resource_head
                && record.result_commitment() == result_commitment
            {
                return Ok(HierarchyHistoryAppendV1::Replay(record));
            }
            return Err(HierarchyHistoryError::IdempotencyConflict);
        }
        if self.records.len() >= MAXIMUM_HIERARCHY_HISTORY_RECORDS {
            return Err(HierarchyHistoryError::Capacity);
        }
        validate_resource_transition(&self.resource_states, subject, transition)?;
        if self.resource_head(subject) != expected_resource_head {
            return Err(HierarchyHistoryError::StaleResourceHead);
        }
        let sequence = u64::try_from(self.records.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(HierarchyHistoryError::Capacity)?;
        let predecessor = self.records.last().map(|record| record.record_commitment());
        let record = HierarchyHistoryRecordV1::from_parts(
            self.project,
            sequence,
            subject,
            transition,
            operation,
            idempotency_key,
            request_commitment,
            expected_resource_head,
            predecessor,
            result_commitment,
        )?;
        self.records
            .try_reserve(1)
            .map_err(|_| HierarchyHistoryError::Capacity)?;
        self.idempotency.insert(idempotency_key, self.records.len());
        self.resource_states.insert(subject, transition);
        self.resource_heads.insert(subject, result_commitment);
        self.records.push(record);
        Ok(HierarchyHistoryAppendV1::Recorded(record))
    }

    /// Compacts an exact protected prefix into a fail-closed history floor.
    ///
    /// Idempotency keys at or below the protected floor are deliberately
    /// reclaimed. Callers must retain no retry beyond that advertised floor.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError`] unless the checkpoint identifies an
    /// exact record in this history and carries nonzero protected commitments.
    pub fn compact_through(
        &self,
        checkpoint: HierarchyHistoryCheckpointV1,
    ) -> Result<CompactedHierarchyHistoryV1, HierarchyHistoryError> {
        if checkpoint.project != self.project
            || checkpoint.through_sequence == 0
            || checkpoint.state_commitment.as_bytes() == &[0; 32]
            || checkpoint.checkpoint_commitment.as_bytes() == &[0; 32]
            || checkpoint.protected_checkpoint_commitment.as_bytes() == &[0; 32]
        {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }
        let floor_index = usize::try_from(checkpoint.through_sequence)
            .ok()
            .and_then(|sequence| sequence.checked_sub(1))
            .ok_or(HierarchyHistoryError::CheckpointMismatch)?;
        let floor_record = self
            .records
            .get(floor_index)
            .ok_or(HierarchyHistoryError::CheckpointMismatch)?;
        if floor_record.record_commitment() != checkpoint.through_record_commitment {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }

        let mut floor_states = BTreeMap::new();
        let mut floor_heads = BTreeMap::new();
        let retired_idempotency = BTreeMap::new();
        for record in &self.records[..=floor_index] {
            floor_states.insert(record.subject(), record.transition());
            floor_heads.insert(record.subject(), record.result_commitment());
        }
        if checkpoint.checkpoint_commitment
            != compute_checkpoint_commitment(
                checkpoint.project,
                checkpoint.through_sequence,
                checkpoint.through_record_commitment,
                checkpoint.state_commitment,
                &floor_states,
                &floor_heads,
                &retired_idempotency,
            )?
        {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }

        let suffix_length = self
            .records
            .len()
            .checked_sub(floor_index + 1)
            .ok_or(HierarchyHistoryError::CorruptHistory)?;
        let mut suffix = Vec::new();
        suffix
            .try_reserve_exact(suffix_length)
            .map_err(|_| HierarchyHistoryError::Capacity)?;
        suffix.extend_from_slice(&self.records[floor_index + 1..]);

        let mut live_idempotency = BTreeMap::new();
        for (index, record) in suffix.iter().enumerate() {
            live_idempotency.insert(record.idempotency_key(), index);
        }
        Ok(CompactedHierarchyHistoryV1 {
            project: self.project,
            checkpoint,
            suffix,
            retired_idempotency,
            live_idempotency,
            resource_states: self.resource_states.clone(),
            resource_heads: self.resource_heads.clone(),
            floor_states,
            floor_heads,
        })
    }
}

fn validate_resource_transition(
    states: &BTreeMap<HierarchyHistorySubjectV1, HierarchyTransitionKindV1>,
    subject: HierarchyHistorySubjectV1,
    next: HierarchyTransitionKindV1,
) -> Result<(), HierarchyHistoryError> {
    let prior = states.get(&subject).copied();
    let valid = match subject {
        HierarchyHistorySubjectV1::Sandbox(_) => match (prior, next) {
            (
                None,
                HierarchyTransitionKindV1::CreateRoot | HierarchyTransitionKindV1::CreateChild,
            ) => true,
            (
                Some(
                    HierarchyTransitionKindV1::CreateRoot
                    | HierarchyTransitionKindV1::CreateChild
                    | HierarchyTransitionKindV1::UpdateSandbox
                    | HierarchyTransitionKindV1::ReparentSandbox
                    | HierarchyTransitionKindV1::SetIncarnation,
                ),
                HierarchyTransitionKindV1::UpdateSandbox
                | HierarchyTransitionKindV1::ReparentSandbox
                | HierarchyTransitionKindV1::SetIncarnation
                | HierarchyTransitionKindV1::DeleteLeaf,
            ) => true,
            _ => false,
        },
        HierarchyHistorySubjectV1::Snapshot(_) => matches!(
            (prior, next),
            (None, HierarchyTransitionKindV1::PrepareSnapshot)
                | (
                    Some(HierarchyTransitionKindV1::PrepareSnapshot),
                    HierarchyTransitionKindV1::CommitSnapshot
                )
        ),
        HierarchyHistorySubjectV1::Attachment(_) => match (prior, next) {
            (None, HierarchyTransitionKindV1::PlanRealization) => true,
            (
                Some(HierarchyTransitionKindV1::PlanRealization),
                HierarchyTransitionKindV1::AdvanceRealization
                | HierarchyTransitionKindV1::AbortRealization,
            ) => true,
            (
                Some(HierarchyTransitionKindV1::AdvanceRealization),
                HierarchyTransitionKindV1::AdvanceRealization
                | HierarchyTransitionKindV1::CompleteRealization
                | HierarchyTransitionKindV1::AbortRealization
                | HierarchyTransitionKindV1::FaultRealization,
            ) => true,
            (
                Some(HierarchyTransitionKindV1::CompleteRealization),
                HierarchyTransitionKindV1::PlanRealization | HierarchyTransitionKindV1::PlanDetach,
            ) => true,
            (
                Some(HierarchyTransitionKindV1::PlanDetach),
                HierarchyTransitionKindV1::AdvanceDetach,
            ) => true,
            (
                Some(HierarchyTransitionKindV1::AdvanceDetach),
                HierarchyTransitionKindV1::AdvanceDetach
                | HierarchyTransitionKindV1::CompleteDetach,
            ) => true,
            (
                Some(
                    HierarchyTransitionKindV1::CompleteDetach
                    | HierarchyTransitionKindV1::AbortRealization
                    | HierarchyTransitionKindV1::FaultRealization,
                ),
                HierarchyTransitionKindV1::PlanRealization,
            ) => true,
            _ => false,
        },
        HierarchyHistorySubjectV1::Project(_) => matches!(
            (prior, next),
            (None, HierarchyTransitionKindV1::PlanRealizationTransaction)
                | (
                    Some(HierarchyTransitionKindV1::PlanRealizationTransaction),
                    HierarchyTransitionKindV1::AdvanceRealizationTransaction
                )
                | (
                    Some(HierarchyTransitionKindV1::AdvanceRealizationTransaction),
                    HierarchyTransitionKindV1::AdvanceRealizationTransaction
                        | HierarchyTransitionKindV1::CompleteRealizationTransaction
                )
                | (
                    Some(HierarchyTransitionKindV1::CompleteRealizationTransaction),
                    HierarchyTransitionKindV1::PlanRealizationTransaction
                )
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(HierarchyHistoryError::IllegalResourceTransition)
    }
}

fn compute_checkpoint_commitment(
    project: ProjectId,
    through_sequence: u64,
    through_record_commitment: ObjectDigest,
    state_commitment: ObjectDigest,
    floor_states: &BTreeMap<HierarchyHistorySubjectV1, HierarchyTransitionKindV1>,
    floor_heads: &BTreeMap<HierarchyHistorySubjectV1, ObjectDigest>,
    retired_keys: &BTreeMap<ObjectDigest, ()>,
) -> Result<ObjectDigest, HierarchyHistoryError> {
    let state_count =
        u32::try_from(floor_states.len()).map_err(|_| HierarchyHistoryError::Capacity)?;
    let retired_count =
        u32::try_from(retired_keys.len()).map_err(|_| HierarchyHistoryError::Capacity)?;
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.hierarchy-history-checkpoint.v1\0");
    hasher.update(project.as_bytes());
    hasher.update(through_sequence.to_be_bytes());
    hasher.update(through_record_commitment.as_bytes());
    hasher.update(state_commitment.as_bytes());
    hasher.update(state_count.to_be_bytes());
    for (subject, transition) in floor_states {
        hasher.update([subject.tag(), *transition as u8]);
        hasher.update(subject.bytes());
        let head = floor_heads
            .get(subject)
            .ok_or(HierarchyHistoryError::CheckpointMismatch)?;
        hasher.update(head.as_bytes());
    }
    hasher.update(retired_count.to_be_bytes());
    for key in retired_keys.keys() {
        hasher.update(key.as_bytes());
    }
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

/// Carries a protected state checkpoint for one exact history prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HierarchyHistoryCheckpointV1 {
    project: ProjectId,
    through_sequence: u64,
    through_record_commitment: ObjectDigest,
    state_commitment: ObjectDigest,
    checkpoint_commitment: ObjectDigest,
    protected_checkpoint_commitment: ObjectDigest,
}

impl HierarchyHistoryCheckpointV1 {
    /// Creates evidence only after a durable adapter verifies protected state.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_verified_parts(
        project: ProjectId,
        through_sequence: u64,
        through_record_commitment: ObjectDigest,
        state_commitment: ObjectDigest,
        checkpoint_commitment: ObjectDigest,
        protected_checkpoint_commitment: ObjectDigest,
    ) -> Self {
        Self {
            project,
            through_sequence,
            through_record_commitment,
            state_commitment,
            checkpoint_commitment,
            protected_checkpoint_commitment,
        }
    }

    /// Verifies canonical floor summaries before admitting a protected checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError::CheckpointMismatch`] for noncanonical
    /// summaries, zero protected evidence, or a mismatched checkpoint digest.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_protected_parts(
        project: ProjectId,
        through_sequence: u64,
        through_record_commitment: ObjectDigest,
        state_commitment: ObjectDigest,
        floor_states: &[(HierarchyHistorySubjectV1, HierarchyTransitionKindV1)],
        floor_heads: &[(HierarchyHistorySubjectV1, ObjectDigest)],
        retired_idempotency_keys: &[ObjectDigest],
        checkpoint_commitment: ObjectDigest,
        protected_checkpoint_commitment: ObjectDigest,
    ) -> Result<Self, HierarchyHistoryError> {
        if project.as_bytes() == &[0; 16]
            || through_sequence == 0
            || through_record_commitment.as_bytes() == &[0; 32]
            || state_commitment.as_bytes() == &[0; 32]
            || protected_checkpoint_commitment.as_bytes() == &[0; 32]
            || floor_states.len() > MAXIMUM_HIERARCHY_HISTORY_RECORDS
            || floor_heads.len() != floor_states.len()
            || !retired_idempotency_keys.is_empty()
            || !floor_states.windows(2).all(|pair| pair[0].0 < pair[1].0)
            || !floor_heads.windows(2).all(|pair| pair[0].0 < pair[1].0)
        {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }
        let floor_states: BTreeMap<_, _> = floor_states.iter().copied().collect();
        let floor_heads: BTreeMap<_, _> = floor_heads.iter().copied().collect();
        if floor_states.keys().ne(floor_heads.keys())
            || floor_heads.values().any(|head| head.as_bytes() == &[0; 32])
        {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }
        let retired: BTreeMap<_, _> = retired_idempotency_keys
            .iter()
            .copied()
            .map(|key| (key, ()))
            .collect();
        if checkpoint_commitment
            != compute_checkpoint_commitment(
                project,
                through_sequence,
                through_record_commitment,
                state_commitment,
                &floor_states,
                &floor_heads,
                &retired,
            )?
        {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }
        Ok(Self::from_verified_parts(
            project,
            through_sequence,
            through_record_commitment,
            state_commitment,
            checkpoint_commitment,
            protected_checkpoint_commitment,
        ))
    }

    /// Returns the project whose prefix is checkpointed.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the inclusive history floor sequence.
    #[must_use]
    pub const fn through_sequence(self) -> u64 {
        self.through_sequence
    }

    /// Returns the inclusive sequence below which idempotency keys were reclaimed.
    #[must_use]
    pub const fn idempotency_floor_sequence(self) -> u64 {
        self.through_sequence
    }

    /// Returns the record commitment at the inclusive floor.
    #[must_use]
    pub const fn through_record_commitment(self) -> ObjectDigest {
        self.through_record_commitment
    }

    /// Returns the complete source-state commitment at the floor.
    #[must_use]
    pub const fn state_commitment(self) -> ObjectDigest {
        self.state_commitment
    }

    /// Returns the canonical checkpoint commitment.
    #[must_use]
    pub const fn checkpoint_commitment(self) -> ObjectDigest {
        self.checkpoint_commitment
    }

    /// Returns proof that the checkpoint came from protected storage.
    #[must_use]
    pub const fn protected_checkpoint_commitment(self) -> ObjectDigest {
        self.protected_checkpoint_commitment
    }
}

/// Owns a protected history floor plus its validated digest-linked suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactedHierarchyHistoryV1 {
    project: ProjectId,
    checkpoint: HierarchyHistoryCheckpointV1,
    suffix: Vec<HierarchyHistoryRecordV1>,
    retired_idempotency: BTreeMap<ObjectDigest, ()>,
    live_idempotency: BTreeMap<ObjectDigest, usize>,
    resource_states: BTreeMap<HierarchyHistorySubjectV1, HierarchyTransitionKindV1>,
    resource_heads: BTreeMap<HierarchyHistorySubjectV1, ObjectDigest>,
    floor_states: BTreeMap<HierarchyHistorySubjectV1, HierarchyTransitionKindV1>,
    floor_heads: BTreeMap<HierarchyHistorySubjectV1, ObjectDigest>,
}

impl CompactedHierarchyHistoryV1 {
    /// Recovers a compacted history from its protected anchor and canonical suffix.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError`] for an unauthenticated floor summary,
    /// malformed suffix chain, illegal resource transition, or idempotency reuse.
    pub fn recover(
        checkpoint: HierarchyHistoryCheckpointV1,
        floor_states: Vec<(HierarchyHistorySubjectV1, HierarchyTransitionKindV1)>,
        floor_heads: Vec<(HierarchyHistorySubjectV1, ObjectDigest)>,
        retired_idempotency_keys: Vec<ObjectDigest>,
        suffix: Vec<HierarchyHistoryRecordV1>,
    ) -> Result<Self, HierarchyHistoryError> {
        let retained_units = floor_states
            .len()
            .checked_add(suffix.len())
            .ok_or(HierarchyHistoryError::Capacity)?;
        if retained_units > MAXIMUM_HIERARCHY_HISTORY_RECORDS
            || floor_heads.len() != floor_states.len()
            || !retired_idempotency_keys.is_empty()
            || !floor_states.windows(2).all(|pair| pair[0].0 < pair[1].0)
            || !floor_heads.windows(2).all(|pair| pair[0].0 < pair[1].0)
        {
            return Err(HierarchyHistoryError::CorruptHistory);
        }
        let floor_states: BTreeMap<_, _> = floor_states.into_iter().collect();
        let floor_heads: BTreeMap<_, _> = floor_heads.into_iter().collect();
        if floor_states.keys().ne(floor_heads.keys())
            || floor_heads.values().any(|head| head.as_bytes() == &[0; 32])
        {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }
        let retired_idempotency: BTreeMap<_, _> = retired_idempotency_keys
            .into_iter()
            .map(|key| (key, ()))
            .collect();
        if checkpoint.project.as_bytes() == &[0; 16]
            || checkpoint.through_sequence == 0
            || checkpoint.through_record_commitment.as_bytes() == &[0; 32]
            || checkpoint.state_commitment.as_bytes() == &[0; 32]
            || checkpoint.checkpoint_commitment
                != compute_checkpoint_commitment(
                    checkpoint.project,
                    checkpoint.through_sequence,
                    checkpoint.through_record_commitment,
                    checkpoint.state_commitment,
                    &floor_states,
                    &floor_heads,
                    &retired_idempotency,
                )?
            || checkpoint.protected_checkpoint_commitment.as_bytes() == &[0; 32]
        {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }

        let mut resource_states = floor_states.clone();
        let mut resource_heads = floor_heads.clone();
        let mut live_idempotency = BTreeMap::new();
        let mut sequence = checkpoint.through_sequence;
        let mut predecessor = checkpoint.through_record_commitment;
        for (index, record) in suffix.iter().copied().enumerate() {
            sequence = sequence
                .checked_add(1)
                .ok_or(HierarchyHistoryError::Capacity)?;
            if record.project() != checkpoint.project
                || record.sequence() != sequence
                || record.predecessor() != Some(predecessor)
                || record.prior_resource_commitment()
                    != resource_heads.get(&record.subject()).copied()
                || retired_idempotency.contains_key(&record.idempotency_key())
                || live_idempotency
                    .insert(record.idempotency_key(), index)
                    .is_some()
            {
                return Err(HierarchyHistoryError::CorruptHistory);
            }
            validate_resource_transition(&resource_states, record.subject(), record.transition())?;
            resource_states.insert(record.subject(), record.transition());
            resource_heads.insert(record.subject(), record.result_commitment());
            predecessor = record.record_commitment();
        }
        Ok(Self {
            project: checkpoint.project,
            checkpoint,
            suffix,
            retired_idempotency,
            live_idempotency,
            resource_states,
            resource_heads,
            floor_states,
            floor_heads,
        })
    }

    /// Returns the protected inclusive history floor.
    #[must_use]
    pub const fn checkpoint(&self) -> HierarchyHistoryCheckpointV1 {
        self.checkpoint
    }

    /// Returns retained records after the history floor.
    #[must_use]
    pub fn suffix(&self) -> &[HierarchyHistoryRecordV1] {
        &self.suffix
    }

    /// Returns canonical resource states retained at the protected floor.
    #[must_use]
    pub fn floor_states(&self) -> &BTreeMap<HierarchyHistorySubjectV1, HierarchyTransitionKindV1> {
        &self.floor_states
    }

    /// Returns canonical resource model heads retained at the protected floor.
    #[must_use]
    pub fn floor_heads(&self) -> &BTreeMap<HierarchyHistorySubjectV1, ObjectDigest> {
        &self.floor_heads
    }

    /// Returns retired idempotency keys in canonical digest order.
    ///
    /// Version one reclaims every key through the advertised floor, so this
    /// iterator is empty for every accepted compacted history.
    #[must_use]
    pub fn retired_idempotency_keys(&self) -> impl ExactSizeIterator<Item = ObjectDigest> + '_ {
        self.retired_idempotency.keys().copied()
    }

    /// Finds a retained-suffix record by its exact idempotency key.
    #[must_use]
    pub fn idempotency_record(
        &self,
        idempotency_key: ObjectDigest,
    ) -> Option<HierarchyHistoryRecordV1> {
        self.live_idempotency
            .get(&idempotency_key)
            .and_then(|index| self.suffix.get(*index))
            .copied()
    }

    /// Returns the latest committed model head for one logical resource.
    #[must_use]
    pub fn resource_head(&self, subject: HierarchyHistorySubjectV1) -> Option<ObjectDigest> {
        self.resource_heads.get(&subject).copied()
    }

    /// Advances the protected floor through one exact retained suffix record.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError`] unless the new checkpoint commits the
    /// resulting floor summaries and an exact record in the current suffix.
    pub fn compact_through(
        &self,
        checkpoint: HierarchyHistoryCheckpointV1,
    ) -> Result<Self, HierarchyHistoryError> {
        if checkpoint.project != self.project
            || checkpoint.through_sequence <= self.checkpoint.through_sequence
        {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }
        let floor_index = self
            .suffix
            .binary_search_by_key(&checkpoint.through_sequence, |record| record.sequence())
            .map_err(|_| HierarchyHistoryError::CheckpointMismatch)?;
        let floor_record = self
            .suffix
            .get(floor_index)
            .ok_or(HierarchyHistoryError::CheckpointMismatch)?;
        if floor_record.record_commitment() != checkpoint.through_record_commitment {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }
        let mut floor_states = self.floor_states.clone();
        let mut floor_heads = self.floor_heads.clone();
        let retired_idempotency = BTreeMap::new();
        for record in &self.suffix[..=floor_index] {
            floor_states.insert(record.subject(), record.transition());
            floor_heads.insert(record.subject(), record.result_commitment());
        }
        if checkpoint.checkpoint_commitment
            != compute_checkpoint_commitment(
                checkpoint.project,
                checkpoint.through_sequence,
                checkpoint.through_record_commitment,
                checkpoint.state_commitment,
                &floor_states,
                &floor_heads,
                &retired_idempotency,
            )?
            || checkpoint.protected_checkpoint_commitment.as_bytes() == &[0; 32]
        {
            return Err(HierarchyHistoryError::CheckpointMismatch);
        }
        let suffix = self.suffix[floor_index + 1..].to_vec();
        let floor_states_vec: Vec<_> = floor_states.into_iter().collect();
        let floor_heads_vec: Vec<_> = floor_heads.into_iter().collect();
        let retired_keys: Vec<_> = retired_idempotency.into_keys().collect();
        Self::recover(
            checkpoint,
            floor_states_vec,
            floor_heads_vec,
            retired_keys,
            suffix,
        )
    }

    /// Appends after the retained suffix while preserving exact idempotency.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyHistoryError::IdempotencyConflict`] when a retired
    /// key is reused, or the same errors as [`HierarchyHistoryV1::append`].
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        subject: HierarchyHistorySubjectV1,
        transition: HierarchyTransitionKindV1,
        operation: OperationId,
        idempotency_key: ObjectDigest,
        request_commitment: ObjectDigest,
        expected_resource_head: Option<ObjectDigest>,
        result_commitment: ObjectDigest,
    ) -> Result<HierarchyHistoryAppendV1, HierarchyHistoryError> {
        if self.retired_idempotency.contains_key(&idempotency_key) {
            return Err(HierarchyHistoryError::IdempotencyConflict);
        }
        if let Some(index) = self.live_idempotency.get(&idempotency_key).copied() {
            let record = self
                .suffix
                .get(index)
                .copied()
                .ok_or(HierarchyHistoryError::CorruptHistory)?;
            if record.subject() == subject
                && record.transition() == transition
                && record.operation() == operation
                && record.request_commitment() == request_commitment
                && record.prior_resource_commitment() == expected_resource_head
                && record.result_commitment() == result_commitment
            {
                return Ok(HierarchyHistoryAppendV1::Replay(record));
            }
            return Err(HierarchyHistoryError::IdempotencyConflict);
        }
        let retained_units = self
            .floor_states
            .len()
            .checked_add(self.suffix.len())
            .ok_or(HierarchyHistoryError::Capacity)?;
        if retained_units >= MAXIMUM_HIERARCHY_HISTORY_RECORDS {
            return Err(HierarchyHistoryError::Capacity);
        }
        validate_resource_transition(&self.resource_states, subject, transition)?;
        if self.resource_heads.get(&subject).copied() != expected_resource_head {
            return Err(HierarchyHistoryError::StaleResourceHead);
        }
        if !transition.supports_subject(subject)
            || matches!(subject, HierarchyHistorySubjectV1::Project(value) if value != self.project)
        {
            return Err(HierarchyHistoryError::InvalidRecord);
        }
        let sequence = self
            .suffix
            .last()
            .map(HierarchyHistoryRecordV1::sequence)
            .unwrap_or(self.checkpoint.through_sequence)
            .checked_add(1)
            .ok_or(HierarchyHistoryError::Capacity)?;
        let predecessor = self
            .suffix
            .last()
            .map(|record| record.record_commitment())
            .or(Some(self.checkpoint.through_record_commitment));
        let record = HierarchyHistoryRecordV1::from_parts(
            self.project,
            sequence,
            subject,
            transition,
            operation,
            idempotency_key,
            request_commitment,
            expected_resource_head,
            predecessor,
            result_commitment,
        )?;
        self.suffix
            .try_reserve(1)
            .map_err(|_| HierarchyHistoryError::Capacity)?;
        self.live_idempotency
            .insert(idempotency_key, self.suffix.len());
        self.resource_states.insert(subject, transition);
        self.resource_heads.insert(subject, result_commitment);
        self.suffix.push(record);
        Ok(HierarchyHistoryAppendV1::Recorded(record))
    }
}

/// Reports invalid, conflicting, or corrupt hierarchy history.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HierarchyHistoryError {
    /// One record contains a zero or structurally invalid field.
    #[error("hierarchy history record is invalid")]
    InvalidRecord,
    /// One encoded record has invalid magic, length, tag, or commitment.
    #[error("hierarchy history record is corrupt")]
    CorruptRecord,
    /// The sequence or predecessor chain is inconsistent.
    #[error("hierarchy history chain is corrupt")]
    CorruptHistory,
    /// A resource transition does not follow its prior durable state.
    #[error("hierarchy resource transition is illegal for its durable state")]
    IllegalResourceTransition,
    /// A record does not compare-and-swap the prior resource model head.
    #[error("hierarchy resource model head is stale")]
    StaleResourceHead,
    /// One idempotency key names conflicting request semantics.
    #[error("hierarchy idempotency key conflicts with prior use")]
    IdempotencyConflict,
    /// A protected checkpoint does not identify an exact history prefix.
    #[error("hierarchy history checkpoint does not match the retained chain")]
    CheckpointMismatch,
    /// Retained history or allocation capacity is exhausted.
    #[error("hierarchy history capacity is exhausted")]
    Capacity,
}
