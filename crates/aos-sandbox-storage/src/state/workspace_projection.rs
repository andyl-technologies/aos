//! Authenticated logical workspace projection planning.
//!
//! The planner accounts for every managed workspace represented by the
//! authenticated physical catalog. Ready entries retain the existing catalog
//! projection, while valid ambiguous work and the narrow committed-create
//! crash gap remain explicit pending entries. Corrupt authority links are
//! errors rather than silently omitted rows.

use std::collections::BTreeSet;

use aos_sandbox::RecordNamespace;
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    CatalogPlanV1, CommittedStorageResultV1, DurableStoragePhase, PhysicalWorkspaceProjection,
    StorageStateError, StorageTransactionStore, StorageWorkspaceProjection, WorkspacePinActionV1,
    WorkspacePinAttemptPhaseV1, WorkspacePinAttemptV1, requires_workspace_publication,
};

const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-snapshot.v1\0";
const PLAN_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-plan.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceProjectionPendingReasonV1 {
    MissingPinAdmission,
    ObserveInitialEnsure,
    ObserveRepairEnsure,
    ObserveRemoval,
    AwaitRetirementCommit,
    IncompleteRetirementHistory,
}

impl WorkspaceProjectionPendingReasonV1 {
    const fn wire(self) -> u8 {
        match self {
            Self::MissingPinAdmission => 1,
            Self::ObserveInitialEnsure => 2,
            Self::ObserveRepairEnsure => 3,
            Self::ObserveRemoval => 4,
            Self::AwaitRetirementCommit => 5,
            Self::IncompleteRetirementHistory => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceCatalogRowExpectationV1 {
    MustBeAbsent,
    MayRetainExactActive(WorkspaceAttemptBindingV1),
    MustConvergeActive(WorkspaceAttemptBindingV1),
    MustConvergeRetired {
        historical_ensure: WorkspaceAttemptBindingV1,
        removal: WorkspaceAttemptBindingV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkspaceAttemptBindingV1 {
    attempt_id: [u8; 16],
    attempt_ordinal: u8,
    record_digest: ObjectDigest,
}

impl WorkspaceAttemptBindingV1 {
    /// Returns the stable identity of the bound attempt record.
    pub(crate) const fn attempt_id(self) -> [u8; 16] {
        self.attempt_id
    }

    /// Returns the contiguous ordinal of the bound attempt.
    pub(crate) const fn attempt_ordinal(self) -> u8 {
        self.attempt_ordinal
    }

    /// Returns the digest of the exact authenticated materialized record.
    pub(crate) const fn record_digest(self) -> ObjectDigest {
        self.record_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WorkspaceProjectionDispositionV1 {
    Ready(Box<StorageWorkspaceProjection>),
    Pending {
        reason: WorkspaceProjectionPendingReasonV1,
        latest_attempt: Option<WorkspaceAttemptBindingV1>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageWorkspaceProjectionEntryV1 {
    workspace_handle: [u8; 32],
    dataset_guid: u64,
    creation_operation_id: [u8; 16],
    disposition: WorkspaceProjectionDispositionV1,
    row_expectation: WorkspaceCatalogRowExpectationV1,
}

/// Binds complete managed-workspace accounting to one transaction snapshot.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct StorageWorkspaceProjectionPlanV1 {
    transaction_sequence: u64,
    transaction_snapshot_digest: ObjectDigest,
    plan_digest: ObjectDigest,
    physical_head_generation: u64,
    physical_head_digest: ObjectDigest,
    expected_workspace_handles: BTreeSet<[u8; 32]>,
    entries: Vec<StorageWorkspaceProjectionEntryV1>,
}

#[allow(
    dead_code,
    reason = "closed catalog-plan accessors await the physical-evidence runtime boundary"
)]
impl StorageWorkspaceProjectionPlanV1 {
    /// Returns the authenticated Storage transaction-journal sequence.
    pub(crate) const fn transaction_sequence(&self) -> u64 {
        self.transaction_sequence
    }

    /// Returns the digest of the complete authenticated transaction snapshot.
    pub(crate) const fn transaction_snapshot_digest(&self) -> ObjectDigest {
        self.transaction_snapshot_digest
    }

    /// Returns the digest of this closed projection plan.
    pub(crate) const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    /// Returns the authenticated physical-catalog head generation.
    pub(crate) const fn physical_head_generation(&self) -> u64 {
        self.physical_head_generation
    }

    /// Returns the authenticated physical-catalog head digest.
    pub(crate) const fn physical_head_digest(&self) -> ObjectDigest {
        self.physical_head_digest
    }

    /// Returns every managed workspace in bytewise handle order.
    pub(crate) fn entries(&self) -> &[StorageWorkspaceProjectionEntryV1] {
        &self.entries
    }

    /// Returns the ready-only projection used by the catalog adapter.
    ///
    /// Pending rows stay explicitly accounted for by this plan but remain
    /// withheld from publication until the later physical-evidence boundary.
    pub(super) fn ready_projection(
        &self,
    ) -> Result<Vec<StorageWorkspaceProjection>, StorageStateError> {
        if self.transaction_sequence == 0
            || self.transaction_snapshot_digest.as_bytes() == &[0; 32]
            || self.plan_digest.as_bytes() == &[0; 32]
            || self.physical_head_generation == 0
            || self.physical_head_digest.as_bytes() == &[0; 32]
            || self.entries.len() != self.expected_workspace_handles.len()
        {
            return Err(StorageStateError::InvalidTransition);
        }

        let mut observed_handles = BTreeSet::new();
        let mut projection = Vec::new();
        for entry in &self.entries {
            if !observed_handles.insert(entry.workspace_handle)
                || entry.workspace_handle == [0; 32]
                || entry.dataset_guid == 0
                || entry.creation_operation_id == [0; 16]
            {
                return Err(StorageStateError::AuthorityLinkMismatch);
            }

            validate_entry(entry)?;
            if let WorkspaceProjectionDispositionV1::Ready(ready) = &entry.disposition {
                projection.push(**ready);
            }
        }
        if observed_handles != self.expected_workspace_handles {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(projection)
    }
}

#[allow(
    dead_code,
    reason = "closed catalog-plan accessors await the physical-evidence runtime boundary"
)]
impl StorageWorkspaceProjectionEntryV1 {
    /// Returns the opaque managed-workspace handle.
    pub(crate) const fn workspace_handle(&self) -> [u8; 32] {
        self.workspace_handle
    }

    /// Returns the immutable physical dataset GUID.
    pub(crate) const fn dataset_guid(&self) -> u64 {
        self.dataset_guid
    }

    /// Returns the operation that created this managed workspace.
    pub(crate) const fn creation_operation_id(&self) -> [u8; 16] {
        self.creation_operation_id
    }

    /// Returns a ready catalog projection, if physical observation is complete.
    pub(crate) fn ready_projection(&self) -> Option<&StorageWorkspaceProjection> {
        match &self.disposition {
            WorkspaceProjectionDispositionV1::Ready(projection) => Some(projection),
            WorkspaceProjectionDispositionV1::Pending { .. } => None,
        }
    }

    /// Reports whether the durable workspace row must be absent.
    pub(crate) const fn requires_absent_row(&self) -> bool {
        matches!(
            self.row_expectation,
            WorkspaceCatalogRowExpectationV1::MustBeAbsent
        )
    }

    /// Returns the exact historical Ensure allowed to remain active.
    pub(crate) const fn retained_active_binding(&self) -> Option<WorkspaceAttemptBindingV1> {
        match self.row_expectation {
            WorkspaceCatalogRowExpectationV1::MayRetainExactActive(binding) => Some(binding),
            _ => None,
        }
    }

    /// Returns the exact Ensure that makes an active row convergable.
    pub(crate) const fn converging_active_binding(&self) -> Option<WorkspaceAttemptBindingV1> {
        match self.row_expectation {
            WorkspaceCatalogRowExpectationV1::MustConvergeActive(binding) => Some(binding),
            _ => None,
        }
    }

    /// Returns the exact historical Ensure and removal for a retired row.
    pub(crate) const fn converging_retired_bindings(
        &self,
    ) -> Option<(WorkspaceAttemptBindingV1, WorkspaceAttemptBindingV1)> {
        match self.row_expectation {
            WorkspaceCatalogRowExpectationV1::MustConvergeRetired {
                historical_ensure,
                removal,
            } => Some((historical_ensure, removal)),
            _ => None,
        }
    }
}

#[allow(
    dead_code,
    reason = "closed catalog-plan accessors await the physical-evidence runtime boundary"
)]
impl StorageTransactionStore {
    pub(crate) fn workspace_projection_plan(
        &self,
    ) -> Result<StorageWorkspaceProjectionPlanV1, StorageStateError> {
        self.ensure_authority_readable()?;
        self.validate_projection_snapshot()?;
        let physical_head = self
            .catalog_transitions
            .head_binding()
            .ok_or(StorageStateError::InvalidTransition)?;
        let transaction_sequence = self.journal.snapshot_sequence();
        if transaction_sequence == 0 {
            return Err(StorageStateError::InvalidTransition);
        }

        let mut physical_projection = self.catalog_transitions.workspace_projection()?;
        physical_projection.sort_unstable();
        let transaction_snapshot_digest =
            self.workspace_transaction_snapshot_digest(transaction_sequence, &physical_projection)?;

        let mut expected_workspace_handles = BTreeSet::new();
        let mut expected_dataset_guids = BTreeSet::new();
        let mut entries = Vec::new();
        for physical in physical_projection {
            let entry = match physical {
                PhysicalWorkspaceProjection::Active {
                    operation_id,
                    object_guid,
                } => Some(self.plan_active_workspace(operation_id, object_guid)?),
                PhysicalWorkspaceProjection::Retired {
                    operation_id,
                    object_guid,
                } => self.plan_retired_workspace(operation_id, object_guid)?,
            };
            let Some(entry) = entry else {
                // A physical tombstone can represent a non-workspace dataset.
                // It is already bound into the snapshot digest above.
                continue;
            };
            if !expected_workspace_handles.insert(entry.workspace_handle)
                || !expected_dataset_guids.insert(entry.dataset_guid)
            {
                return Err(StorageStateError::AuthorityLinkMismatch);
            }
            entries.push(entry);
        }
        entries.sort_unstable_by_key(|entry| entry.workspace_handle);

        let plan_digest = projection_plan_digest(
            transaction_sequence,
            transaction_snapshot_digest,
            physical_head.generation(),
            physical_head.digest(),
            &entries,
        )?;
        Ok(StorageWorkspaceProjectionPlanV1 {
            transaction_sequence,
            transaction_snapshot_digest,
            plan_digest,
            physical_head_generation: physical_head.generation(),
            physical_head_digest: physical_head.digest(),
            expected_workspace_handles,
            entries,
        })
    }

    /// Reconstructs the committed creation represented by one plan entry.
    pub(crate) fn workspace_projection_creation(
        &self,
        entry: &StorageWorkspaceProjectionEntryV1,
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        let creation = self.projected_committed_result(entry.creation_operation_id)?;
        self.require_workspace_creation(entry.creation_operation_id, creation)?;
        if creation.storage_handle() != Some(entry.workspace_handle)
            || creation.object_guid() != Some(entry.dataset_guid)
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(creation)
    }

    /// Recovers the exact satisfied Ensure proof selected by a plan binding.
    pub(crate) fn workspace_projection_ensure_pin(
        &self,
        entry: &StorageWorkspaceProjectionEntryV1,
        binding: WorkspaceAttemptBindingV1,
    ) -> Result<super::WorkspaceRootPinProofV1, StorageStateError> {
        let attempt = self.workspace_projection_attempt(entry, binding)?;
        self.satisfied_workspace_ensure_pin(
            attempt,
            entry.creation_operation_id,
            entry.workspace_handle,
        )
    }

    /// Returns every exact satisfied Ensure binding in authenticated order.
    pub(crate) fn workspace_projection_satisfied_ensure_bindings(
        &self,
        entry: &StorageWorkspaceProjectionEntryV1,
    ) -> Result<Vec<WorkspaceAttemptBindingV1>, StorageStateError> {
        self.workspace_attempt_history(entry.creation_operation_id, entry.workspace_handle)?
            .into_iter()
            .filter(|attempt| {
                attempt.action() == WorkspacePinActionV1::Ensure
                    && attempt.phase() == WorkspacePinAttemptPhaseV1::Satisfied
            })
            .map(|attempt| self.attempt_binding(attempt))
            .collect()
    }

    /// Requires one exact satisfied effect attempt selected by a plan binding.
    pub(crate) fn require_workspace_projection_effect(
        &self,
        entry: &StorageWorkspaceProjectionEntryV1,
        effect_operation_id: [u8; 16],
        action: WorkspacePinActionV1,
        binding: WorkspaceAttemptBindingV1,
    ) -> Result<(), StorageStateError> {
        let attempt = self.workspace_projection_attempt(entry, binding)?;
        if attempt.effect_operation_id() != effect_operation_id
            || attempt.action() != action
            || attempt.phase() != WorkspacePinAttemptPhaseV1::Satisfied
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(())
    }

    fn workspace_projection_attempt(
        &self,
        entry: &StorageWorkspaceProjectionEntryV1,
        binding: WorkspaceAttemptBindingV1,
    ) -> Result<&WorkspacePinAttemptV1, StorageStateError> {
        let attempt = self
            .pin_attempts
            .get(&binding.attempt_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let record = self.workspace_pin_attempt_record(attempt)?;
        if attempt.attempt_ordinal() != binding.attempt_ordinal
            || digest_bytes(&record)? != binding.record_digest
            || attempt.creation_operation_id() != entry.creation_operation_id
            || attempt.workspace_handle() != entry.workspace_handle
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(attempt)
    }

    fn plan_active_workspace(
        &self,
        operation_id: [u8; 16],
        object_guid: u64,
    ) -> Result<StorageWorkspaceProjectionEntryV1, StorageStateError> {
        let creation = self.projected_committed_result(operation_id)?;
        if creation.object_guid() != Some(object_guid) {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        self.require_workspace_creation(operation_id, creation)?;
        let workspace_handle = creation
            .storage_handle()
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let history = self.workspace_attempt_history(operation_id, workspace_handle)?;
        let historical_ensure = self.latest_satisfied_ensure_binding(&history)?;

        let (disposition, row_expectation) = match history.last().copied() {
            None => (
                WorkspaceProjectionDispositionV1::Pending {
                    reason: WorkspaceProjectionPendingReasonV1::MissingPinAdmission,
                    latest_attempt: None,
                },
                WorkspaceCatalogRowExpectationV1::MustBeAbsent,
            ),
            Some(latest) => match (latest.action(), latest.phase()) {
                (WorkspacePinActionV1::Ensure, WorkspacePinAttemptPhaseV1::Satisfied) => {
                    let binding = self.attempt_binding(latest)?;
                    (
                        WorkspaceProjectionDispositionV1::Ready(Box::new(
                            StorageWorkspaceProjection::Active(creation),
                        )),
                        WorkspaceCatalogRowExpectationV1::MustConvergeActive(binding),
                    )
                }
                (WorkspacePinActionV1::Ensure, WorkspacePinAttemptPhaseV1::Ambiguous) => {
                    let pending = if latest.effect_operation_id() == operation_id {
                        WorkspaceProjectionPendingReasonV1::ObserveInitialEnsure
                    } else {
                        WorkspaceProjectionPendingReasonV1::ObserveRepairEnsure
                    };
                    (
                        WorkspaceProjectionDispositionV1::Pending {
                            reason: pending,
                            latest_attempt: Some(self.attempt_binding(latest)?),
                        },
                        retained_active_row(historical_ensure),
                    )
                }
                (WorkspacePinActionV1::RemoveAndDestroy, WorkspacePinAttemptPhaseV1::Ambiguous) => {
                    (
                        WorkspaceProjectionDispositionV1::Pending {
                            reason: WorkspaceProjectionPendingReasonV1::ObserveRemoval,
                            latest_attempt: Some(self.attempt_binding(latest)?),
                        },
                        retained_active_row(historical_ensure),
                    )
                }
                (WorkspacePinActionV1::RemoveAndDestroy, WorkspacePinAttemptPhaseV1::Satisfied) => {
                    (
                        WorkspaceProjectionDispositionV1::Pending {
                            reason: WorkspaceProjectionPendingReasonV1::AwaitRetirementCommit,
                            latest_attempt: Some(self.attempt_binding(latest)?),
                        },
                        retained_active_row(historical_ensure),
                    )
                }
            },
        };
        Ok(StorageWorkspaceProjectionEntryV1 {
            workspace_handle,
            dataset_guid: object_guid,
            creation_operation_id: operation_id,
            disposition,
            row_expectation,
        })
    }

    fn plan_retired_workspace(
        &self,
        retirement_operation_id: [u8; 16],
        object_guid: u64,
    ) -> Result<Option<StorageWorkspaceProjectionEntryV1>, StorageStateError> {
        let Some(creation) = self.managed_workspace_creation(object_guid)? else {
            return Ok(None);
        };
        self.require_workspace_creation(creation.operation_id(), creation)?;
        let workspace_handle = creation
            .storage_handle()
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let retirement = self.projected_committed_result(retirement_operation_id)?;
        let retirement_record = self
            .records
            .get(&retirement_operation_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let retirement_catalog = super::ResolvedCatalogCommitmentV1::from_canonical_bytes(
            &retirement_record.catalog_bytes,
        )
        .map_err(|_| StorageStateError::CorruptRecord)?;
        let CatalogPlanV1::DestroyDataset { dataset } = retirement_catalog.plan() else {
            return Err(StorageStateError::AuthorityLinkMismatch);
        };
        if dataset.guid() != object_guid
            || dataset.storage_handle() != workspace_handle
            || retirement.object_guid().is_some()
            || retirement.storage_handle() != Some(workspace_handle)
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        let history = self.workspace_attempt_history(creation.operation_id(), workspace_handle)?;
        let latest = history
            .last()
            .copied()
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if latest.action() != WorkspacePinActionV1::RemoveAndDestroy
            || latest.effect_operation_id() != retirement_operation_id
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        let historical_ensure = self.latest_satisfied_ensure_binding(&history)?;
        let (disposition, row_expectation) = match latest.phase() {
            WorkspacePinAttemptPhaseV1::Ambiguous => (
                WorkspaceProjectionDispositionV1::Pending {
                    reason: WorkspaceProjectionPendingReasonV1::ObserveRemoval,
                    latest_attempt: Some(self.attempt_binding(latest)?),
                },
                retained_active_row(historical_ensure),
            ),
            WorkspacePinAttemptPhaseV1::Satisfied => match historical_ensure {
                Some(historical_ensure) => (
                    WorkspaceProjectionDispositionV1::Ready(Box::new(
                        StorageWorkspaceProjection::Retired {
                            creation,
                            retirement,
                        },
                    )),
                    WorkspaceCatalogRowExpectationV1::MustConvergeRetired {
                        historical_ensure,
                        removal: self.attempt_binding(latest)?,
                    },
                ),
                None => (
                    WorkspaceProjectionDispositionV1::Pending {
                        reason: WorkspaceProjectionPendingReasonV1::IncompleteRetirementHistory,
                        latest_attempt: Some(self.attempt_binding(latest)?),
                    },
                    WorkspaceCatalogRowExpectationV1::MustBeAbsent,
                ),
            },
        };
        Ok(Some(StorageWorkspaceProjectionEntryV1 {
            workspace_handle,
            dataset_guid: object_guid,
            creation_operation_id: creation.operation_id(),
            disposition,
            row_expectation,
        }))
    }

    fn require_workspace_creation(
        &self,
        operation_id: [u8; 16],
        creation: CommittedStorageResultV1,
    ) -> Result<(), StorageStateError> {
        let record = self
            .records
            .get(&operation_id)
            .filter(|record| record.phase == DurableStoragePhase::Committed)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let catalog =
            super::ResolvedCatalogCommitmentV1::from_canonical_bytes(&record.catalog_bytes)
                .map_err(|_| StorageStateError::CorruptRecord)?;
        let intent = self
            .publication_intents
            .get(&operation_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if record.format_version != super::VERSION
            || !requires_workspace_publication(catalog.plan())
            || intent.operation_id() != operation_id
            || intent.request_catalog() != catalog.binding()
            || creation.operation_id() != operation_id
            || creation.catalog().generation() <= catalog.generation()
            || creation.storage_handle().is_none()
            || creation.immutable_version_handle().is_some()
            || creation.object_guid().is_none()
            || record.result != Some(creation)
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(())
    }

    fn validate_projection_snapshot(&self) -> Result<(), StorageStateError> {
        let records = super::load_durable_records(&self.journal, &self.key)?;
        let publication_intents = super::load_publication_intents(&self.journal, &self.key)?;
        let pin_attempts = super::load_attempts(&self.journal, self.key.key_id, &self.key.secret)?;
        let repair_intents =
            super::load_repair_intents(&self.journal, self.key.key_id, &self.key.secret)?;
        if records != self.records
            || publication_intents != self.publication_intents
            || pin_attempts != self.pin_attempts
            || repair_intents != self.repair_intents
        {
            return Err(StorageStateError::CorruptRecord);
        }

        let catalog_transitions = super::StorageCatalogTransitionProvider::load(
            &self.journal,
            self.key.key_id,
            &self.key.secret,
        )?;
        super::validate_durable_records(&records, &catalog_transitions, &self.key)?;
        catalog_transitions.validate_operation_set(records.keys().copied())?;
        super::validate_publication_intent_set(&records, &publication_intents)?;
        super::validate_repair_intent_set(
            &self.journal,
            &records,
            &publication_intents,
            &pin_attempts,
            &repair_intents,
        )?;
        let fresh_projection = catalog_transitions.workspace_projection()?;
        let cached_projection = self.catalog_transitions.workspace_projection()?;
        if catalog_transitions.head_binding() != self.catalog_transitions.head_binding()
            || fresh_projection != cached_projection
        {
            return Err(StorageStateError::CorruptRecord);
        }
        for attempt in self.pin_attempts.values() {
            self.validate_pin_attempt_context(attempt)?;
        }
        Ok(())
    }

    fn workspace_attempt_history(
        &self,
        creation_operation_id: [u8; 16],
        workspace_handle: [u8; 32],
    ) -> Result<Vec<&WorkspacePinAttemptV1>, StorageStateError> {
        let mut history = self
            .pin_attempts
            .values()
            .filter(|attempt| {
                attempt.creation_operation_id() == creation_operation_id
                    || attempt.workspace_handle() == workspace_handle
            })
            .collect::<Vec<_>>();
        for attempt in &history {
            if attempt.creation_operation_id() != creation_operation_id
                || attempt.workspace_handle() != workspace_handle
            {
                return Err(StorageStateError::AuthorityLinkMismatch);
            }
            self.validate_pin_attempt_context(attempt)?;
        }
        history.sort_unstable_by_key(|attempt| attempt.attempt_ordinal());
        for (index, attempt) in history.iter().enumerate() {
            let expected_ordinal =
                u8::try_from(index + 1).map_err(|_| StorageStateError::InvalidTransition)?;
            if attempt.attempt_ordinal() != expected_ordinal {
                return Err(StorageStateError::AuthorityLinkMismatch);
            }
            match (index, attempt.action()) {
                (0, WorkspacePinActionV1::Ensure)
                    if attempt.effect_operation_id() == creation_operation_id => {}
                (0, _) => return Err(StorageStateError::AuthorityLinkMismatch),
                (_, WorkspacePinActionV1::Ensure)
                    if attempt.effect_operation_id() != creation_operation_id
                        && history[index - 1].action()
                            != WorkspacePinActionV1::RemoveAndDestroy => {}
                (_, WorkspacePinActionV1::RemoveAndDestroy)
                    if history[index - 1].action() != WorkspacePinActionV1::RemoveAndDestroy => {}
                _ => return Err(StorageStateError::AuthorityLinkMismatch),
            }
        }
        Ok(history)
    }

    fn latest_satisfied_ensure_binding(
        &self,
        history: &[&WorkspacePinAttemptV1],
    ) -> Result<Option<WorkspaceAttemptBindingV1>, StorageStateError> {
        history
            .iter()
            .rev()
            .copied()
            .find(|attempt| {
                attempt.action() == WorkspacePinActionV1::Ensure
                    && attempt.phase() == WorkspacePinAttemptPhaseV1::Satisfied
            })
            .map(|attempt| self.attempt_binding(attempt))
            .transpose()
    }

    fn attempt_binding(
        &self,
        attempt: &WorkspacePinAttemptV1,
    ) -> Result<WorkspaceAttemptBindingV1, StorageStateError> {
        let record = self.workspace_pin_attempt_record(attempt)?;
        Ok(WorkspaceAttemptBindingV1 {
            attempt_id: attempt.attempt_id(),
            attempt_ordinal: attempt.attempt_ordinal(),
            record_digest: digest_bytes(&record)?,
        })
    }

    fn workspace_transaction_snapshot_digest(
        &self,
        transaction_sequence: u64,
        physical_projection: &[PhysicalWorkspaceProjection],
    ) -> Result<ObjectDigest, StorageStateError> {
        let mut hash = FramedDigest::new(SNAPSHOT_DIGEST_DOMAIN);
        hash.field(&transaction_sequence.to_be_bytes())?;
        let physical_head = self
            .catalog_transitions
            .head_binding()
            .ok_or(StorageStateError::InvalidTransition)?;
        hash.catalog_binding(physical_head)?;
        for projection in physical_projection {
            match projection {
                PhysicalWorkspaceProjection::Active {
                    operation_id,
                    object_guid,
                } => {
                    hash.field(&[1])?;
                    hash.field(operation_id)?;
                    hash.field(&object_guid.to_be_bytes())?;
                }
                PhysicalWorkspaceProjection::Retired {
                    operation_id,
                    object_guid,
                } => {
                    hash.field(&[2])?;
                    hash.field(operation_id)?;
                    hash.field(&object_guid.to_be_bytes())?;
                }
            }
        }
        for operation_id in self.records.keys() {
            hash.journal_record(
                RecordNamespace::Operation,
                operation_id,
                self.journal
                    .get(RecordNamespace::Operation, operation_id)
                    .ok_or(StorageStateError::MissingAuthorityLink)?,
            )?;
        }
        for operation_id in self.publication_intents.keys() {
            hash.journal_record(
                RecordNamespace::StorageWorkspacePublicationIntent,
                operation_id,
                self.journal
                    .get(
                        RecordNamespace::StorageWorkspacePublicationIntent,
                        operation_id,
                    )
                    .ok_or(StorageStateError::MissingAuthorityLink)?,
            )?;
        }
        for attempt_id in self.pin_attempts.keys() {
            hash.journal_record(
                RecordNamespace::StorageWorkspacePinAttempt,
                attempt_id,
                self.journal
                    .get(RecordNamespace::StorageWorkspacePinAttempt, attempt_id)
                    .ok_or(StorageStateError::MissingAuthorityLink)?,
            )?;
        }
        for operation_id in self.repair_intents.keys() {
            hash.journal_record(
                RecordNamespace::StorageWorkspacePinRepairIntent,
                operation_id,
                self.journal
                    .get(
                        RecordNamespace::StorageWorkspacePinRepairIntent,
                        operation_id,
                    )
                    .ok_or(StorageStateError::MissingAuthorityLink)?,
            )?;
        }
        for namespace in [
            RecordNamespace::DesiredState,
            RecordNamespace::Effect,
            RecordNamespace::AuthorityPublication,
        ] {
            let mut records = self.journal.records(namespace).collect::<Vec<_>>();
            records.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (key, value) in records {
                hash.journal_record(namespace, key, value)?;
            }
        }
        hash.finish()
    }
}

fn retained_active_row(
    historical_ensure: Option<WorkspaceAttemptBindingV1>,
) -> WorkspaceCatalogRowExpectationV1 {
    historical_ensure.map_or(
        WorkspaceCatalogRowExpectationV1::MustBeAbsent,
        WorkspaceCatalogRowExpectationV1::MayRetainExactActive,
    )
}

fn validate_entry(entry: &StorageWorkspaceProjectionEntryV1) -> Result<(), StorageStateError> {
    let valid_binding = |binding: WorkspaceAttemptBindingV1| {
        binding.attempt_id != [0; 16]
            && binding.attempt_ordinal != 0
            && binding.record_digest.as_bytes() != &[0; 32]
    };
    let matches_entry = |result: CommittedStorageResultV1| {
        result.operation_id() == entry.creation_operation_id
            && result.storage_handle() == Some(entry.workspace_handle)
            && result.immutable_version_handle().is_none()
            && result.object_guid() == Some(entry.dataset_guid)
    };
    let valid = match (&entry.disposition, entry.row_expectation) {
        (
            WorkspaceProjectionDispositionV1::Ready(ready),
            WorkspaceCatalogRowExpectationV1::MustConvergeActive(binding),
        ) => {
            matches!(
                ready.as_ref(),
                StorageWorkspaceProjection::Active(result) if matches_entry(*result)
            ) && valid_binding(binding)
        }
        (
            WorkspaceProjectionDispositionV1::Ready(ready),
            WorkspaceCatalogRowExpectationV1::MustConvergeRetired {
                historical_ensure,
                removal,
            },
        ) => {
            matches!(
                ready.as_ref(),
                StorageWorkspaceProjection::Retired {
                    creation,
                    retirement,
                } if matches_entry(*creation)
                    && retirement.operation_id() != entry.creation_operation_id
                    && retirement.storage_handle() == Some(entry.workspace_handle)
                    && retirement.immutable_version_handle().is_none()
                    && retirement.object_guid().is_none()
            ) && valid_binding(historical_ensure)
                && valid_binding(removal)
                && historical_ensure.attempt_ordinal < removal.attempt_ordinal
        }
        (
            WorkspaceProjectionDispositionV1::Pending {
                reason: WorkspaceProjectionPendingReasonV1::MissingPinAdmission,
                latest_attempt: None,
            },
            WorkspaceCatalogRowExpectationV1::MustBeAbsent,
        ) => true,
        (
            WorkspaceProjectionDispositionV1::Pending {
                reason: WorkspaceProjectionPendingReasonV1::ObserveInitialEnsure,
                latest_attempt: Some(latest),
            },
            WorkspaceCatalogRowExpectationV1::MustBeAbsent,
        ) => valid_binding(*latest) && latest.attempt_ordinal == 1,
        (
            WorkspaceProjectionDispositionV1::Pending {
                reason:
                    WorkspaceProjectionPendingReasonV1::ObserveRepairEnsure
                    | WorkspaceProjectionPendingReasonV1::ObserveRemoval
                    | WorkspaceProjectionPendingReasonV1::AwaitRetirementCommit
                    | WorkspaceProjectionPendingReasonV1::IncompleteRetirementHistory,
                latest_attempt: Some(latest),
            },
            WorkspaceCatalogRowExpectationV1::MustBeAbsent,
        ) => valid_binding(*latest),
        (
            WorkspaceProjectionDispositionV1::Pending {
                reason:
                    WorkspaceProjectionPendingReasonV1::ObserveRepairEnsure
                    | WorkspaceProjectionPendingReasonV1::ObserveRemoval
                    | WorkspaceProjectionPendingReasonV1::AwaitRetirementCommit,
                latest_attempt: Some(latest),
            },
            WorkspaceCatalogRowExpectationV1::MayRetainExactActive(historical_ensure),
        ) => {
            valid_binding(*latest)
                && valid_binding(historical_ensure)
                && historical_ensure.attempt_ordinal < latest.attempt_ordinal
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(StorageStateError::AuthorityLinkMismatch)
    }
}

fn projection_plan_digest(
    transaction_sequence: u64,
    transaction_snapshot_digest: ObjectDigest,
    physical_head_generation: u64,
    physical_head_digest: ObjectDigest,
    entries: &[StorageWorkspaceProjectionEntryV1],
) -> Result<ObjectDigest, StorageStateError> {
    let mut hash = FramedDigest::new(PLAN_DIGEST_DOMAIN);
    hash.field(&transaction_sequence.to_be_bytes())?;
    hash.field(transaction_snapshot_digest.as_bytes())?;
    hash.field(&physical_head_generation.to_be_bytes())?;
    hash.field(physical_head_digest.as_bytes())?;
    for entry in entries {
        hash.field(&entry.workspace_handle)?;
        hash.field(&entry.dataset_guid.to_be_bytes())?;
        hash.field(&entry.creation_operation_id)?;
        match &entry.disposition {
            WorkspaceProjectionDispositionV1::Ready(ready) => match ready.as_ref() {
                StorageWorkspaceProjection::Active(result) => {
                    hash.field(&[1])?;
                    hash.result(*result)?;
                }
                StorageWorkspaceProjection::Retired {
                    creation,
                    retirement,
                } => {
                    hash.field(&[2])?;
                    hash.result(*creation)?;
                    hash.result(*retirement)?;
                }
            },
            WorkspaceProjectionDispositionV1::Pending {
                reason,
                latest_attempt,
            } => {
                hash.field(&[3, reason.wire()])?;
                match latest_attempt {
                    Some(binding) => {
                        hash.field(&[1])?;
                        hash.attempt_binding(*binding)?;
                    }
                    None => hash.field(&[0])?,
                }
            }
        }
        match entry.row_expectation {
            WorkspaceCatalogRowExpectationV1::MustBeAbsent => hash.field(&[1])?,
            WorkspaceCatalogRowExpectationV1::MayRetainExactActive(binding) => {
                hash.field(&[2])?;
                hash.attempt_binding(binding)?;
            }
            WorkspaceCatalogRowExpectationV1::MustConvergeActive(binding) => {
                hash.field(&[3])?;
                hash.attempt_binding(binding)?;
            }
            WorkspaceCatalogRowExpectationV1::MustConvergeRetired {
                historical_ensure,
                removal,
            } => {
                hash.field(&[4])?;
                hash.attempt_binding(historical_ensure)?;
                hash.attempt_binding(removal)?;
            }
        }
    }
    hash.finish()
}

fn digest_bytes(bytes: &[u8]) -> Result<ObjectDigest, StorageStateError> {
    let digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
    if digest.as_bytes() == &[0; 32] {
        Err(StorageStateError::InvalidValue)
    } else {
        Ok(digest)
    }
}

struct FramedDigest(Sha256);

impl FramedDigest {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(domain);
        Self(hash)
    }

    fn field(&mut self, bytes: &[u8]) -> Result<(), StorageStateError> {
        // A fixed u64 frame makes the digest portable across pointer widths.
        // Journal and typed state limits keep every admitted field below this
        // bound; an unrepresentable in-memory slice therefore fails closed.
        let length = u64::try_from(bytes.len()).map_err(|_| StorageStateError::InvalidValue)?;
        self.0.update(length.to_be_bytes());
        self.0.update(bytes);
        Ok(())
    }

    fn catalog_binding(
        &mut self,
        binding: super::CatalogBindingV1,
    ) -> Result<(), StorageStateError> {
        self.field(&binding.generation().to_be_bytes())?;
        self.field(binding.digest().as_bytes())
    }

    fn result(&mut self, result: CommittedStorageResultV1) -> Result<(), StorageStateError> {
        self.field(&result.operation_id())?;
        self.catalog_binding(result.catalog())?;
        self.field(result.result_digest().as_bytes())?;
        self.field(
            result
                .storage_handle()
                .as_ref()
                .map_or(&[][..], <[u8; 32]>::as_slice),
        )?;
        self.field(
            result
                .immutable_version_handle()
                .as_ref()
                .map_or(&[][..], <[u8; 32]>::as_slice),
        )?;
        self.field(
            &result
                .object_guid()
                .map(u64::to_be_bytes)
                .unwrap_or_default(),
        )
    }

    fn attempt_binding(
        &mut self,
        binding: WorkspaceAttemptBindingV1,
    ) -> Result<(), StorageStateError> {
        self.field(&binding.attempt_id)?;
        self.field(&[binding.attempt_ordinal])?;
        self.field(binding.record_digest.as_bytes())
    }

    fn journal_record(
        &mut self,
        namespace: RecordNamespace,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StorageStateError> {
        self.field(&(namespace as u16).to_be_bytes())?;
        self.field(key)?;
        self.field(value)
    }

    fn finish(self) -> Result<ObjectDigest, StorageStateError> {
        let digest = ObjectDigest::from_bytes(self.0.finalize().into());
        if digest.as_bytes() == &[0; 32] {
            Err(StorageStateError::InvalidValue)
        } else {
            Ok(digest)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;

    use aos_sandbox::{JournalTransaction, RecordNamespace};
    use tempfile::TempDir;

    use super::*;
    use crate::broker::FreshWorkspacePinAuthority;
    use crate::catalog::ResolvedCatalogCommitmentV1;
    use crate::root_policy::WorkspaceRootPolicyV1;
    use crate::state::tests::{
        catalog, destroy_dataset_catalog, digest, initialize, key,
        prepare_workspace_remove_attempt, publication_intent,
    };
    use crate::state::{BeginStorageTransaction, StorageTransactionStore, attempt_record};
    use crate::workspace_pin::{
        WorkspaceDatasetObservationV1, WorkspacePinHostScopeV1, WorkspacePinObservationV1,
        WorkspacePinRecoveryDispositionV1, WorkspaceRootPinProofV1,
    };
    use crate::workspace_repair::StorageWorkspacePinRepairIntentV1;

    fn workspace_pin_proof(
        workspace_handle: [u8; 32],
        dataset_name: &str,
        dataset_guid: u64,
    ) -> WorkspaceRootPinProofV1 {
        use std::fmt::Write as _;

        let mut mount_point = "/run/aos/sandbox-pins/workspaces/".to_owned();
        for byte in workspace_handle {
            write!(mount_point, "{byte:02x}").unwrap();
        }

        WorkspaceRootPinProofV1::new(
            [4; 16],
            5,
            6,
            7,
            "/".to_owned(),
            mount_point,
            "zfs".to_owned(),
            dataset_name.to_owned(),
            dataset_guid,
            8,
            9,
            WorkspaceRootPolicyV1::create_initialize().root_attributes(),
        )
        .unwrap()
    }

    fn clone_test_store(source: &TempDir) -> (TempDir, StorageTransactionStore) {
        let destination = TempDir::new().unwrap();
        fs::copy(
            source.path().join("storage-state.journal"),
            destination.path().join("storage-state.journal"),
        )
        .unwrap();
        let store = StorageTransactionStore::open_for_test(destination.path(), key(1), 0).unwrap();
        (destination, store)
    }

    fn ambiguous_ensure_with_dataset_guid(
        attempt: &WorkspacePinAttemptV1,
        dataset_guid: u64,
    ) -> WorkspacePinAttemptV1 {
        WorkspacePinAttemptV1::new_ambiguous(
            attempt.attempt_id(),
            attempt.attempt_ordinal(),
            WorkspacePinActionV1::Ensure,
            attempt.effect_operation_id(),
            attempt.creation_operation_id(),
            attempt.operation_fence_digest(),
            attempt.effect_assignment_digest(),
            attempt.workspace_assignment_digest(),
            attempt.creation_result_catalog(),
            attempt.creation_result_digest(),
            attempt.workspace_handle(),
            attempt.host_boot_id(),
            attempt.host_mount_namespace_device(),
            attempt.host_mount_namespace_inode(),
            attempt.clock_provenance(),
            attempt.effect_deadline_boottime_nanoseconds(),
            attempt.dataset_name().to_owned(),
            dataset_guid,
            attempt.identity_range_start(),
            attempt.identity_range_size(),
            attempt.root_policy(),
            None,
        )
        .unwrap()
        .with_authority_receipt(attempt.authority_receipt().to_vec())
        .unwrap()
    }

    fn replace_authenticated_attempt(
        store: &mut StorageTransactionStore,
        transaction_id: [u8; 16],
        attempt: WorkspacePinAttemptV1,
    ) {
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![attempt_record(&attempt, store.key.key_id, &store.key.secret).unwrap()],
        )
        .unwrap();
        store.commit_journal(&transaction).unwrap();
        store.pin_attempts.insert(attempt.attempt_id(), attempt);
    }

    #[test]
    fn strictly_unused_store_stays_uninitialized_while_initialized_empty_is_stable() {
        let unused_directory = TempDir::new().unwrap();
        let unused =
            StorageTransactionStore::open_for_test(unused_directory.path(), key(1), 0).unwrap();
        let unused_sequence = unused.journal.snapshot_sequence();
        assert!(matches!(
            unused.workspace_projection_plan(),
            Err(StorageStateError::InvalidTransition)
        ));
        assert_eq!(unused.journal.snapshot_sequence(), unused_sequence);

        let initialized_directory = TempDir::new().unwrap();
        let initial_catalog = catalog(7, "tank/aos/project/work");
        let mut initialized =
            StorageTransactionStore::open_for_test(initialized_directory.path(), key(1), 0)
                .unwrap();
        initialize(&mut initialized, &initial_catalog);

        let plan = initialized.workspace_projection_plan().unwrap();
        assert!(plan.entries.is_empty());
        assert!(plan.expected_workspace_handles.is_empty());
        assert!(plan.ready_projection().unwrap().is_empty());
        drop(initialized);

        let reopened =
            StorageTransactionStore::open_for_test(initialized_directory.path(), key(1), 0)
                .unwrap();
        assert_eq!(reopened.workspace_projection_plan().unwrap(), plan);
    }

    #[test]
    fn nonworkspace_tombstones_are_omitted_but_snapshot_bound() {
        let plan_for = |directory: &TempDir,
                        catalog: ResolvedCatalogCommitmentV1,
                        operation_id: [u8; 16],
                        request_digest: ObjectDigest,
                        result_digest: ObjectDigest| {
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            initialize(&mut store, &catalog);
            let BeginStorageTransaction::Prepared { mutation_digest } =
                store.begin(operation_id, request_digest, &catalog).unwrap()
            else {
                panic!("nonworkspace destruction was not prepared")
            };
            store
                .mark_mutation_ambiguous(operation_id, mutation_digest)
                .unwrap();
            store
                .commit_observed(
                    operation_id,
                    mutation_digest,
                    &catalog,
                    &catalog.plan().postcondition(),
                    None,
                    result_digest,
                )
                .unwrap();

            assert!(matches!(
                store
                    .catalog_transitions
                    .workspace_projection()
                    .unwrap()
                    .as_slice(),
                [PhysicalWorkspaceProjection::Retired { .. }]
            ));
            store.workspace_projection_plan().unwrap()
        };

        let left_directory = TempDir::new().unwrap();
        let left = plan_for(
            &left_directory,
            destroy_dataset_catalog(7, "tank/aos/project/source-a", 15, [9; 32]),
            [51; 16],
            digest(52),
            digest(53),
        );
        let right_directory = TempDir::new().unwrap();
        let right = plan_for(
            &right_directory,
            destroy_dataset_catalog(7, "tank/aos/project/source-b", 16, [10; 32]),
            [51; 16],
            digest(52),
            digest(53),
        );

        assert_eq!(left.transaction_sequence, right.transaction_sequence);
        assert!(left.entries.is_empty());
        assert!(left.expected_workspace_handles.is_empty());
        assert!(right.entries.is_empty());
        assert!(right.expected_workspace_handles.is_empty());
        assert_ne!(
            left.transaction_snapshot_digest,
            right.transaction_snapshot_digest
        );
        assert_ne!(left.plan_digest, right.plan_digest);
    }

    #[test]
    fn multiple_managed_workspaces_are_complete_and_handle_sorted() {
        let directory = TempDir::new().unwrap();
        let first_catalog = catalog(7, "tank/aos/project/zeta");
        let second_catalog = catalog(9, "tank/aos/project/alpha");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &first_catalog);

        let mut expected_handles = BTreeSet::new();
        for (marker, catalog, dataset_guid) in [
            (61_u8, &first_catalog, 101_u64),
            (71_u8, &second_catalog, 102_u64),
        ] {
            let operation_id = [marker; 16];
            let intent = publication_intent(operation_id, catalog, marker.wrapping_add(5));
            let assignment_digest = intent.assignment_digest();
            let BeginStorageTransaction::Prepared { mutation_digest } = store
                .begin_authorized_with_publication(
                    operation_id,
                    digest(marker.wrapping_add(2)),
                    catalog,
                    [marker.wrapping_add(3); 16],
                    [marker.wrapping_add(4); 16],
                    vec![marker.wrapping_add(5); 8],
                    vec![marker.wrapping_add(6); 8],
                    vec![marker.wrapping_add(7); 8],
                    Some(intent),
                )
                .unwrap()
            else {
                panic!("workspace creation was not prepared")
            };
            store
                .mark_mutation_ambiguous(operation_id, mutation_digest)
                .unwrap();
            let creation = store
                .commit_observed(
                    operation_id,
                    mutation_digest,
                    catalog,
                    &catalog.plan().postcondition(),
                    Some(dataset_guid),
                    digest(marker.wrapping_add(8)),
                )
                .unwrap();
            let workspace_handle = creation.storage_handle().unwrap();
            assert!(expected_handles.insert(workspace_handle));

            let attempt = store
                .plan_workspace_pin_ensure(
                    creation,
                    assignment_digest,
                    WorkspacePinHostScopeV1::new([4; 16], 5, 6).unwrap(),
                    [10; 16],
                    1_000,
                )
                .unwrap();
            store
                .begin_workspace_pin_attempt(
                    attempt.clone(),
                    FreshWorkspacePinAuthority::new_for_test(
                        attempt.attempt_id(),
                        attempt.authority_digest().unwrap(),
                    ),
                )
                .unwrap();
            let dataset_name = match catalog.plan() {
                CatalogPlanV1::CreateWorkspace { destination, .. } => destination.name(),
                _ => panic!("fixture catalog was not a workspace creation"),
            };
            assert_eq!(
                store
                    .complete_workspace_pin_attempt(
                        attempt.attempt_id(),
                        &WorkspaceDatasetObservationV1::Exact {
                            name: dataset_name.to_owned(),
                            guid: dataset_guid,
                        },
                        &WorkspacePinObservationV1::Present(workspace_pin_proof(
                            workspace_handle,
                            dataset_name,
                            dataset_guid,
                        )),
                    )
                    .unwrap(),
                WorkspacePinRecoveryDispositionV1::CompletePublication
            );
        }

        let plan = store.workspace_projection_plan().unwrap();
        let planned_handles = plan
            .entries
            .iter()
            .map(|entry| entry.workspace_handle)
            .collect::<Vec<_>>();
        assert_eq!(plan.expected_workspace_handles, expected_handles);
        assert_eq!(planned_handles.len(), expected_handles.len());
        assert!(planned_handles.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(plan.entries.iter().all(|entry| matches!(
            entry.disposition,
            WorkspaceProjectionDispositionV1::Ready(_)
        )));
        assert_eq!(plan.ready_projection().unwrap().len(), 2);
    }

    #[test]
    fn initial_pin_lifecycle_is_complete_and_snapshot_bound() {
        let directory = TempDir::new().unwrap();
        let create = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &create);
        let operation_id = [31; 16];
        let BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin_authorized_with_publication(
                operation_id,
                digest(32),
                &create,
                [33; 16],
                [34; 16],
                vec![1; 8],
                vec![2; 8],
                vec![3; 8],
                Some(publication_intent(operation_id, &create, 35)),
            )
            .unwrap()
        else {
            panic!("workspace creation was not prepared")
        };
        store
            .mark_mutation_ambiguous(operation_id, mutation_digest)
            .unwrap();
        let creation = store
            .commit_observed(
                operation_id,
                mutation_digest,
                &create,
                &create.plan().postcondition(),
                Some(101),
                digest(36),
            )
            .unwrap();

        let missing = store.workspace_projection_plan().unwrap();
        assert_eq!(missing.entries.len(), 1);
        assert_eq!(
            missing.expected_workspace_handles,
            BTreeSet::from([creation.storage_handle().unwrap()])
        );
        assert!(matches!(
            missing.entries[0],
            StorageWorkspaceProjectionEntryV1 {
                disposition: WorkspaceProjectionDispositionV1::Pending {
                    reason: WorkspaceProjectionPendingReasonV1::MissingPinAdmission,
                    latest_attempt: None,
                },
                row_expectation: WorkspaceCatalogRowExpectationV1::MustBeAbsent,
                ..
            }
        ));
        assert!(missing.ready_projection().unwrap().is_empty());

        let host_scope = WorkspacePinHostScopeV1::new([4; 16], 5, 6).unwrap();
        let attempt = store
            .plan_workspace_pin_ensure(
                creation,
                publication_intent(operation_id, &create, 35).assignment_digest(),
                host_scope,
                [10; 16],
                1_000,
            )
            .unwrap();
        store
            .begin_workspace_pin_attempt(
                attempt.clone(),
                FreshWorkspacePinAuthority::new_for_test(
                    attempt.attempt_id(),
                    attempt.authority_digest().unwrap(),
                ),
            )
            .unwrap();

        let ambiguous = store.workspace_projection_plan().unwrap();
        assert_ne!(ambiguous.transaction_sequence, missing.transaction_sequence);
        assert_ne!(
            ambiguous.transaction_snapshot_digest,
            missing.transaction_snapshot_digest
        );
        assert_ne!(ambiguous.plan_digest, missing.plan_digest);
        assert!(matches!(
            ambiguous.entries.as_slice(),
            [StorageWorkspaceProjectionEntryV1 {
                disposition: WorkspaceProjectionDispositionV1::Pending {
                    reason: WorkspaceProjectionPendingReasonV1::ObserveInitialEnsure,
                    latest_attempt: Some(binding),
                },
                row_expectation: WorkspaceCatalogRowExpectationV1::MustBeAbsent,
                ..
            }] if binding.attempt_id == attempt.attempt_id()
        ));
        assert!(ambiguous.ready_projection().unwrap().is_empty());

        let proof = workspace_pin_proof(
            creation.storage_handle().unwrap(),
            "tank/aos/project/work",
            101,
        );
        store
            .complete_workspace_pin_attempt(
                attempt.attempt_id(),
                &WorkspaceDatasetObservationV1::Exact {
                    name: "tank/aos/project/work".to_owned(),
                    guid: 101,
                },
                &WorkspacePinObservationV1::Present(proof),
            )
            .unwrap();

        let ready = store.workspace_projection_plan().unwrap();
        assert_ne!(ready.transaction_sequence, ambiguous.transaction_sequence);
        assert_ne!(
            ready.transaction_snapshot_digest,
            ambiguous.transaction_snapshot_digest
        );
        assert_ne!(ready.plan_digest, ambiguous.plan_digest);
        assert!(matches!(
            ready.entries.as_slice(),
            [StorageWorkspaceProjectionEntryV1 {
                disposition: WorkspaceProjectionDispositionV1::Ready(ready_projection),
                row_expectation: WorkspaceCatalogRowExpectationV1::MustConvergeActive(binding),
                ..
            }] if matches!(
                ready_projection.as_ref(),
                StorageWorkspaceProjection::Active(result) if *result == creation
            ) && binding.attempt_id == attempt.attempt_id()
        ));
        assert_eq!(
            ready.ready_projection().unwrap(),
            vec![StorageWorkspaceProjection::Active(creation)]
        );

        drop(store);
        let reopened = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(reopened.workspace_projection_plan().unwrap(), ready);
    }

    #[test]
    fn latest_ambiguous_removal_is_accounted_without_falling_back() {
        let directory = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let (remove, mutation_digest) = prepare_workspace_remove_attempt(&mut store);

        let ready = store.workspace_projection_plan().unwrap();
        assert!(matches!(
            ready.entries.as_slice(),
            [StorageWorkspaceProjectionEntryV1 {
                disposition: WorkspaceProjectionDispositionV1::Ready(ready_projection),
                row_expectation: WorkspaceCatalogRowExpectationV1::MustConvergeActive(_),
                ..
            }] if matches!(
                ready_projection.as_ref(),
                StorageWorkspaceProjection::Active(_)
            )
        ));
        store
            .begin_workspace_pin_remove_and_destroy(
                remove.clone(),
                mutation_digest,
                FreshWorkspacePinAuthority::new_for_test(
                    remove.attempt_id(),
                    remove.authority_digest().unwrap(),
                ),
            )
            .unwrap();

        let pending = store.workspace_projection_plan().unwrap();
        assert_ne!(pending.transaction_sequence, ready.transaction_sequence);
        assert_ne!(
            pending.transaction_snapshot_digest,
            ready.transaction_snapshot_digest
        );
        assert_ne!(pending.plan_digest, ready.plan_digest);
        assert!(matches!(
            pending.entries.as_slice(),
            [StorageWorkspaceProjectionEntryV1 {
                disposition: WorkspaceProjectionDispositionV1::Pending {
                    reason: WorkspaceProjectionPendingReasonV1::ObserveRemoval,
                    latest_attempt: Some(latest),
                },
                row_expectation: WorkspaceCatalogRowExpectationV1::MayRetainExactActive(_),
                ..
            }] if latest.attempt_id == remove.attempt_id()
        ));
        assert!(pending.ready_projection().unwrap().is_empty());

        drop(store);
        let mut reopened =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(reopened.workspace_projection_plan().unwrap(), pending);
        reopened
            .complete_workspace_pin_attempt(
                remove.attempt_id(),
                &WorkspaceDatasetObservationV1::Absent,
                &WorkspacePinObservationV1::Absent,
            )
            .unwrap();

        let awaiting_commit = reopened.workspace_projection_plan().unwrap();
        assert_ne!(awaiting_commit.plan_digest, pending.plan_digest);
        assert!(matches!(
            awaiting_commit.entries.as_slice(),
            [StorageWorkspaceProjectionEntryV1 {
                disposition: WorkspaceProjectionDispositionV1::Pending {
                    reason: WorkspaceProjectionPendingReasonV1::AwaitRetirementCommit,
                    latest_attempt: Some(latest),
                },
                row_expectation: WorkspaceCatalogRowExpectationV1::MayRetainExactActive(_),
                ..
            }] if latest.attempt_id == remove.attempt_id()
        ));
        assert!(awaiting_commit.ready_projection().unwrap().is_empty());

        let destroy = ResolvedCatalogCommitmentV1::from_canonical_bytes(
            &reopened
                .records
                .get(&remove.effect_operation_id())
                .unwrap()
                .catalog_bytes,
        )
        .unwrap();
        reopened
            .commit_observed(
                remove.effect_operation_id(),
                mutation_digest,
                &destroy,
                &destroy.plan().postcondition(),
                None,
                digest(201),
            )
            .unwrap();

        let retired = reopened.workspace_projection_plan().unwrap();
        assert_ne!(retired.plan_digest, awaiting_commit.plan_digest);
        assert!(matches!(
            retired.entries.as_slice(),
            [StorageWorkspaceProjectionEntryV1 {
                disposition: WorkspaceProjectionDispositionV1::Ready(ready_projection),
                row_expectation: WorkspaceCatalogRowExpectationV1::MustConvergeRetired {
                    historical_ensure,
                    removal: removal_binding,
                },
                ..
            }] if matches!(
                ready_projection.as_ref(),
                StorageWorkspaceProjection::Retired { creation, retirement }
                    if creation.operation_id() == remove.creation_operation_id()
                        && retirement.operation_id() == remove.effect_operation_id()
            )
                && historical_ensure.attempt_ordinal < removal_binding.attempt_ordinal
        ));
        assert!(matches!(
            retired.ready_projection().unwrap().as_slice(),
            [StorageWorkspaceProjection::Retired { .. }]
        ));
    }

    #[test]
    fn retired_workspace_without_satisfied_ensure_remains_accounted() {
        let directory = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let (remove, mutation_digest) = prepare_workspace_remove_attempt(&mut store);
        let satisfied_ensure = store
            .pin_attempts
            .values()
            .find(|attempt| attempt.action() == WorkspacePinActionV1::Ensure)
            .unwrap()
            .clone();
        let ambiguous_ensure =
            ambiguous_ensure_with_dataset_guid(&satisfied_ensure, satisfied_ensure.dataset_guid());
        replace_authenticated_attempt(&mut store, [225; 16], ambiguous_ensure);

        store
            .begin_workspace_pin_remove_and_destroy(
                remove.clone(),
                mutation_digest,
                FreshWorkspacePinAuthority::new_for_test(
                    remove.attempt_id(),
                    remove.authority_digest().unwrap(),
                ),
            )
            .unwrap();
        store
            .complete_workspace_pin_attempt(
                remove.attempt_id(),
                &WorkspaceDatasetObservationV1::Absent,
                &WorkspacePinObservationV1::Absent,
            )
            .unwrap();
        let destroy = ResolvedCatalogCommitmentV1::from_canonical_bytes(
            &store
                .records
                .get(&remove.effect_operation_id())
                .unwrap()
                .catalog_bytes,
        )
        .unwrap();
        store
            .commit_observed(
                remove.effect_operation_id(),
                mutation_digest,
                &destroy,
                &destroy.plan().postcondition(),
                None,
                digest(201),
            )
            .unwrap();

        let plan = store.workspace_projection_plan().unwrap();
        assert_eq!(
            plan.expected_workspace_handles,
            BTreeSet::from([remove.workspace_handle()])
        );
        assert!(matches!(
            plan.entries.as_slice(),
            [StorageWorkspaceProjectionEntryV1 {
                workspace_handle,
                disposition: WorkspaceProjectionDispositionV1::Pending {
                    reason: WorkspaceProjectionPendingReasonV1::IncompleteRetirementHistory,
                    latest_attempt: Some(latest),
                },
                row_expectation: WorkspaceCatalogRowExpectationV1::MustBeAbsent,
                ..
            }] if *workspace_handle == remove.workspace_handle()
                && latest.attempt_id == remove.attempt_id()
        ));
        assert!(plan.ready_projection().unwrap().is_empty());

        drop(store);
        let reopened = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(reopened.workspace_projection_plan().unwrap(), plan);
    }

    #[test]
    fn authenticated_attempt_with_mismatched_dataset_guid_fails_closed() {
        let directory = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let (_remove, _) = prepare_workspace_remove_attempt(&mut store);
        let satisfied_ensure = store
            .pin_attempts
            .values()
            .find(|attempt| attempt.action() == WorkspacePinActionV1::Ensure)
            .unwrap()
            .clone();
        let mismatched = ambiguous_ensure_with_dataset_guid(
            &satisfied_ensure,
            satisfied_ensure.dataset_guid() + 1,
        );
        replace_authenticated_attempt(&mut store, [226; 16], mismatched);

        assert!(matches!(
            store.workspace_projection_plan(),
            Err(StorageStateError::AuthorityLinkMismatch)
        ));
        drop(store);
        assert!(matches!(
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0),
            Err(StorageStateError::AuthorityLinkMismatch)
        ));
    }

    #[test]
    fn ambiguous_and_satisfied_repair_bind_the_exact_history() {
        let directory = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let (_remove, _) = prepare_workspace_remove_attempt(&mut store);
        let initial = store
            .pin_attempts
            .values()
            .find(|attempt| attempt.action() == WorkspacePinActionV1::Ensure)
            .unwrap()
            .clone();
        let creation = store
            .records
            .get(&initial.creation_operation_id())
            .and_then(|record| record.result)
            .unwrap();
        let initial_plan = store.workspace_projection_plan().unwrap();
        assert!(matches!(
            initial_plan.entries.as_slice(),
            [StorageWorkspaceProjectionEntryV1 {
                disposition: WorkspaceProjectionDispositionV1::Ready(ready_projection),
                row_expectation: WorkspaceCatalogRowExpectationV1::MustConvergeActive(binding),
                ..
            }] if matches!(
                ready_projection.as_ref(),
                StorageWorkspaceProjection::Active(_)
            ) && binding.attempt_id == initial.attempt_id()
        ));

        let repair_operation_id = [211; 16];
        let repair_request_id = [212; 16];
        let repair_assignment_digest = digest(213);
        let sealed_pending_effect = vec![214; 8];
        let sealed_completed_effect = vec![215; 8];
        let sealed_operation_fence = vec![216; 8];
        let operation_fence_digest = digest_bytes(&sealed_operation_fence).unwrap();
        let repair = store
            .plan_workspace_pin_repair(
                &initial,
                repair_operation_id,
                operation_fence_digest,
                repair_assignment_digest,
                WorkspacePinHostScopeV1::new([4; 16], 5, 6).unwrap(),
                [217; 16],
                2_000,
            )
            .unwrap()
            .with_authority_receipt(vec![218])
            .unwrap();
        let publication_record_digest = digest_bytes(
            store
                .journal
                .get(
                    RecordNamespace::StorageWorkspacePublicationIntent,
                    &creation.operation_id(),
                )
                .unwrap(),
        )
        .unwrap();
        let initial_record_digest = digest_bytes(
            store
                .journal
                .get(
                    RecordNamespace::StorageWorkspacePinAttempt,
                    &initial.attempt_id(),
                )
                .unwrap(),
        )
        .unwrap();
        let intent = StorageWorkspacePinRepairIntentV1::new_for_test(
            repair_operation_id,
            repair_request_id,
            digest(219),
            digest(220),
            repair_assignment_digest,
            sealed_pending_effect.clone(),
            operation_fence_digest,
            creation.operation_id(),
            creation.catalog(),
            creation.result_digest(),
            publication_record_digest,
            creation.storage_handle().unwrap(),
            initial.attempt_id(),
            initial.phase(),
            initial_record_digest,
            repair.attempt_id(),
            repair.attempt_ordinal(),
        )
        .unwrap();
        store
            .retain_workspace_pin_repair_for_test(
                [221; 16],
                intent,
                repair.clone(),
                vec![222; 8],
                sealed_pending_effect,
                sealed_operation_fence,
            )
            .unwrap();

        let ambiguous = store.workspace_projection_plan().unwrap();
        assert_ne!(ambiguous.plan_digest, initial_plan.plan_digest);
        assert!(matches!(
            ambiguous.entries.as_slice(),
            [StorageWorkspaceProjectionEntryV1 {
                disposition: WorkspaceProjectionDispositionV1::Pending {
                    reason: WorkspaceProjectionPendingReasonV1::ObserveRepairEnsure,
                    latest_attempt: Some(latest),
                },
                row_expectation: WorkspaceCatalogRowExpectationV1::MayRetainExactActive(binding),
                ..
            }] if latest.attempt_id == repair.attempt_id()
                && binding.attempt_id == initial.attempt_id()
        ));
        assert!(ambiguous.ready_projection().unwrap().is_empty());

        drop(store);
        let (_left_directory, mut left_effect) = clone_test_store(&directory);
        let (_right_directory, mut right_effect) = clone_test_store(&directory);
        left_effect.put_authority_record_for_test(
            RecordNamespace::Effect,
            &repair_request_id,
            vec![1; 8],
        );
        right_effect.put_authority_record_for_test(
            RecordNamespace::Effect,
            &repair_request_id,
            vec![2; 8],
        );
        assert_eq!(
            left_effect.journal.snapshot_sequence(),
            right_effect.journal.snapshot_sequence()
        );
        let left_effect_plan = left_effect.workspace_projection_plan().unwrap();
        let right_effect_plan = right_effect.workspace_projection_plan().unwrap();
        assert_ne!(
            left_effect_plan.transaction_snapshot_digest,
            right_effect_plan.transaction_snapshot_digest
        );
        drop(left_effect);
        drop(right_effect);

        let (_left_directory, mut left_desired) = clone_test_store(&directory);
        let (_right_directory, mut right_desired) = clone_test_store(&directory);
        left_desired.put_authority_record_for_test(
            RecordNamespace::DesiredState,
            &[221; 16],
            vec![3; 8],
        );
        right_desired.put_authority_record_for_test(
            RecordNamespace::DesiredState,
            &[221; 16],
            vec![4; 8],
        );
        assert_eq!(
            left_desired.journal.snapshot_sequence(),
            right_desired.journal.snapshot_sequence()
        );
        let left_desired_plan = left_desired.workspace_projection_plan().unwrap();
        let right_desired_plan = right_desired.workspace_projection_plan().unwrap();
        assert_ne!(
            left_desired_plan.transaction_snapshot_digest,
            right_desired_plan.transaction_snapshot_digest
        );
        drop(left_desired);
        drop(right_desired);

        let (_invalid_directory, mut invalid_fence) = clone_test_store(&directory);
        invalid_fence.put_authority_record_for_test(
            RecordNamespace::AuthorityPublication,
            &repair_operation_id,
            vec![5; 8],
        );
        assert!(matches!(
            invalid_fence.workspace_projection_plan(),
            Err(StorageStateError::AuthorityLinkMismatch)
        ));
        drop(invalid_fence);

        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();

        let proof = workspace_pin_proof(
            creation.storage_handle().unwrap(),
            initial.dataset_name(),
            initial.dataset_guid(),
        );
        store
            .complete_workspace_pin_repair_attempt(
                repair.attempt_id(),
                &WorkspaceDatasetObservationV1::Exact {
                    name: initial.dataset_name().to_owned(),
                    guid: initial.dataset_guid(),
                },
                &WorkspacePinObservationV1::Present(proof),
                sealed_completed_effect,
            )
            .unwrap();

        let ready = store.workspace_projection_plan().unwrap();
        assert_ne!(ready.plan_digest, ambiguous.plan_digest);
        assert!(matches!(
            ready.entries.as_slice(),
            [StorageWorkspaceProjectionEntryV1 {
                disposition: WorkspaceProjectionDispositionV1::Ready(ready_projection),
                row_expectation: WorkspaceCatalogRowExpectationV1::MustConvergeActive(binding),
                ..
            }] if matches!(
                ready_projection.as_ref(),
                StorageWorkspaceProjection::Active(result) if *result == creation
            ) && binding.attempt_id == repair.attempt_id()
        ));
    }

    #[test]
    fn cached_attempt_without_its_authenticated_record_fails_closed() {
        let directory = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let (remove, mutation_digest) = prepare_workspace_remove_attempt(&mut store);
        store
            .begin_workspace_pin_remove_and_destroy(
                remove.clone(),
                mutation_digest,
                FreshWorkspacePinAuthority::new_for_test(
                    remove.attempt_id(),
                    remove.authority_digest().unwrap(),
                ),
            )
            .unwrap();
        store.remove_authority_record_for_test(
            RecordNamespace::StorageWorkspacePinAttempt,
            &remove.attempt_id(),
        );

        assert!(matches!(
            store.workspace_projection_plan(),
            Err(StorageStateError::CorruptRecord)
        ));
    }

    #[test]
    fn cached_publication_intent_without_its_authenticated_record_fails_closed() {
        let directory = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let (remove, _) = prepare_workspace_remove_attempt(&mut store);
        store.remove_authority_record_for_test(
            RecordNamespace::StorageWorkspacePublicationIntent,
            &remove.creation_operation_id(),
        );

        assert!(matches!(
            store.workspace_projection_plan(),
            Err(StorageStateError::CorruptRecord)
        ));
    }
}
