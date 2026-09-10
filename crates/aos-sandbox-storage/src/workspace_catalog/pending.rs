//! Structurally validated workspace-catalog state before physical observation.
//!
//! This module owns the pre-activation catalog typestate. Opening may acquire
//! protected journal custody and recover a bounded uncommitted tail, but it
//! never initializes a semantic head, reserves identity space, observes pins,
//! converges rows, or emits inventory. A closed authority plan can be checked
//! against the durable rows without granting any of those capabilities.

use std::collections::BTreeSet;
use std::path::Path;

use aos_sandbox::{Journal, JournalRecord, JournalTransaction, RecordNamespace, RecoveryReport};
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    AssignmentWire, CatalogBindingWire, CatalogHeadV1, HEAD_KEY, IdentityPoolWire,
    ObjectDescriptorWire, RECORD_KEY_PREFIX, StorageIdentityPoolV1, StorageWorkspaceCatalogError,
    StorageWorkspacePublicationV1, StorageWorkspaceRetirementV1, WORKSPACE_JOURNAL_FILE,
    WorkspaceLifecycleV1, WorkspaceRecordV1, decode_head, decode_record, decode_record_key,
    encode_head, encode_record, genesis_transaction_id, next_generation, record_key,
    transaction_id, validate_identity_range, validate_record_set, workspace_journal_limits,
};

const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-catalog-snapshot.v1\0";

/// Reports whether opening recovered an incomplete journal tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageWorkspaceCatalogRecoveryV1 {
    /// Replay found an already-clean durable prefix.
    Clean {
        /// Number of committed transactions replayed from the current file.
        committed_transactions: usize,
        /// Number of committed record frames replayed from the current file.
        committed_records: usize,
    },
    /// Replay truncated a partial frame or complete uncommitted transaction.
    RecoveredTail {
        /// Number of committed transactions replayed from the retained prefix.
        committed_transactions: usize,
        /// Number of committed records replayed from the retained prefix.
        committed_records: usize,
        /// Number of non-authoritative tail bytes removed and synchronized.
        truncated_bytes: u64,
    },
}

impl From<RecoveryReport> for StorageWorkspaceCatalogRecoveryV1 {
    fn from(report: RecoveryReport) -> Self {
        if report.truncated_bytes == 0 {
            Self::Clean {
                committed_transactions: report.committed_transactions,
                committed_records: report.committed_records,
            }
        } else {
            Self::RecoveredTail {
                committed_transactions: report.committed_transactions,
                committed_records: report.committed_records,
                truncated_bytes: report.truncated_bytes,
            }
        }
    }
}

/// Binds one complete materialized workspace-catalog snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageWorkspaceCatalogSnapshotV1 {
    journal_sequence: u64,
    digest: ObjectDigest,
    catalog_generation: Option<u64>,
    identity_pool: StorageIdentityPoolV1,
}

impl StorageWorkspaceCatalogSnapshotV1 {
    /// Returns the journal sequence delimiting the materialized snapshot.
    pub(crate) const fn journal_sequence(self) -> u64 {
        self.journal_sequence
    }

    /// Returns the digest of the sequence, pool, head, and every logical row.
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }

    /// Returns the durable workspace-catalog generation, if initialized.
    pub(crate) const fn catalog_generation(self) -> Option<u64> {
        self.catalog_generation
    }

    /// Returns the configured subordinate-identity allocation envelope.
    pub(crate) const fn identity_pool(self) -> StorageIdentityPoolV1 {
        self.identity_pool
    }
}

/// Selects the only structurally valid durable-row states for one workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StorageWorkspaceCatalogRowPolicyV1 {
    /// No durable catalog row may exist.
    MustBeAbsent,
    /// The row may be absent or retain this exact active creation.
    MayRetainExactActive(StorageWorkspacePublicationV1),
    /// The row may be absent or already equal this exact active creation.
    MustConvergeActive(StorageWorkspacePublicationV1),
    /// The row may be absent, retain the exact creation, or equal the retirement.
    MustConvergeRetired {
        /// Exact historical creation identity and portable publication facts.
        creation: StorageWorkspacePublicationV1,
        /// Exact committed destruction identity.
        retirement: StorageWorkspaceRetirementV1,
    },
}

/// Binds one permitted active-row prefix to its authenticated Ensure attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageWorkspaceCatalogActivePrefixV1 {
    attempt_id: [u8; 16],
    attempt_ordinal: u8,
    attempt_record_digest: ObjectDigest,
    publication: StorageWorkspacePublicationV1,
}

impl StorageWorkspaceCatalogActivePrefixV1 {
    /// Constructs an exact active prefix from one authenticated satisfied Ensure.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError::InvalidCandidate`] when an
    /// attempt binding is zero.
    pub(crate) fn new(
        attempt_id: [u8; 16],
        attempt_ordinal: u8,
        attempt_record_digest: ObjectDigest,
        publication: StorageWorkspacePublicationV1,
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        if attempt_id == [0; 16]
            || attempt_ordinal == 0
            || attempt_record_digest.as_bytes() == &[0; 32]
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        Ok(Self {
            attempt_id,
            attempt_ordinal,
            attempt_record_digest,
            publication,
        })
    }

    /// Returns the exact publication facts proven by this Ensure attempt.
    pub(crate) const fn publication(&self) -> &StorageWorkspacePublicationV1 {
        &self.publication
    }
}

/// Carries one managed workspace's complete structural row requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageWorkspaceCatalogRowPlanV1 {
    workspace_handle: [u8; 32],
    dataset_guid: u64,
    creation_operation_id: [u8; 16],
    identity_range_start: u32,
    identity_range_size: u32,
    policy: StorageWorkspaceCatalogRowPolicyV1,
    active_prefixes: Vec<StorageWorkspaceCatalogActivePrefixV1>,
}

impl StorageWorkspaceCatalogRowPlanV1 {
    /// Constructs a closed row requirement from authenticated transaction state.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError::InvalidCandidate`] when a stable
    /// identity or allocation range is invalid, or when a publication or
    /// retirement does not describe the exact row named by the requirement.
    pub(crate) fn new(
        workspace_handle: [u8; 32],
        dataset_guid: u64,
        creation_operation_id: [u8; 16],
        identity_range_start: u32,
        identity_range_size: u32,
        policy: StorageWorkspaceCatalogRowPolicyV1,
        active_prefixes: Vec<StorageWorkspaceCatalogActivePrefixV1>,
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        let row = Self {
            workspace_handle,
            dataset_guid,
            creation_operation_id,
            identity_range_start,
            identity_range_size,
            policy,
            active_prefixes,
        };
        row.validate()?;
        Ok(row)
    }

    /// Returns the opaque managed-workspace handle.
    pub(crate) const fn workspace_handle(&self) -> [u8; 32] {
        self.workspace_handle
    }

    /// Returns the immutable physical dataset GUID.
    pub(crate) const fn dataset_guid(&self) -> u64 {
        self.dataset_guid
    }

    /// Returns the operation that created the managed workspace.
    pub(crate) const fn creation_operation_id(&self) -> [u8; 16] {
        self.creation_operation_id
    }

    /// Returns the permanently reserved subordinate-identity range.
    pub(crate) const fn identity_range(&self) -> (u32, u32) {
        (self.identity_range_start, self.identity_range_size)
    }

    /// Returns the closed durable-row policy.
    pub(crate) const fn policy(&self) -> &StorageWorkspaceCatalogRowPolicyV1 {
        &self.policy
    }

    /// Returns every exact authenticated active row allowed before convergence.
    pub(crate) fn active_prefixes(&self) -> &[StorageWorkspaceCatalogActivePrefixV1] {
        &self.active_prefixes
    }

    fn validate(&self) -> Result<(), StorageWorkspaceCatalogError> {
        if self.workspace_handle == [0; 32]
            || self.dataset_guid == 0
            || self.creation_operation_id == [0; 16]
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        validate_identity_range(self.identity_range_start, self.identity_range_size)?;

        let creation = match &self.policy {
            StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent => {
                return if self.active_prefixes.is_empty() {
                    Ok(())
                } else {
                    Err(StorageWorkspaceCatalogError::InvalidCandidate)
                };
            }
            StorageWorkspaceCatalogRowPolicyV1::MayRetainExactActive(creation)
            | StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(creation)
            | StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired { creation, .. } => creation,
        };
        if creation.workspace_handle != self.workspace_handle
            || creation.dataset_guid != self.dataset_guid
            || creation.operation_id != self.creation_operation_id
            || creation.identity_range_start != self.identity_range_start
            || creation.identity_range_size != self.identity_range_size
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }

        let mut prior_ordinal = None;
        let mut attempt_ids = BTreeSet::new();
        let mut attempt_digests = BTreeSet::new();
        for prefix in &self.active_prefixes {
            if prior_ordinal.is_some_and(|prior| prior >= prefix.attempt_ordinal)
                || !attempt_ids.insert(prefix.attempt_id)
                || !attempt_digests.insert(*prefix.attempt_record_digest.as_bytes())
                || !publications_share_creation(&prefix.publication, creation)
            {
                return Err(StorageWorkspaceCatalogError::InvalidCandidate);
            }
            prior_ordinal = Some(prefix.attempt_ordinal);
        }
        if self.active_prefixes.is_empty()
            || self
                .active_prefixes
                .last()
                .is_none_or(|prefix| prefix.publication != *creation)
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        if let StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired { retirement, .. } =
            &self.policy
        {
            if retirement.workspace_handle != self.workspace_handle
                || retirement.dataset_guid != self.dataset_guid
                || retirement.operation_id == self.creation_operation_id
                || retirement.request_catalog.generation() < creation.result_catalog.generation()
            {
                return Err(StorageWorkspaceCatalogError::InvalidCandidate);
            }
        }
        Ok(())
    }
}

fn publications_share_creation(
    left: &StorageWorkspacePublicationV1,
    right: &StorageWorkspacePublicationV1,
) -> bool {
    left.operation_id == right.operation_id
        && left.request_catalog == right.request_catalog
        && left.result_catalog == right.result_catalog
        && left.result_digest == right.result_digest
        && left.workspace_handle == right.workspace_handle
        && left.dataset_guid == right.dataset_guid
        && left.assignment == right.assignment
        && left.root_image == right.root_image
        && left.identity_range_start == right.identity_range_start
        && left.identity_range_size == right.identity_range_size
}

/// Binds authenticated Storage state to a complete closed workspace row set.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct StorageWorkspaceCatalogPlanV1 {
    transaction_sequence: u64,
    transaction_snapshot_digest: ObjectDigest,
    plan_digest: ObjectDigest,
    physical_head_generation: u64,
    physical_head_digest: ObjectDigest,
    rows: Vec<StorageWorkspaceCatalogRowPlanV1>,
}

impl StorageWorkspaceCatalogPlanV1 {
    /// Constructs a complete row plan in strict bytewise handle order.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError::InvalidCandidate`] when a
    /// binding is zero, rows are not strictly ordered, identities collide, or
    /// subordinate-identity ranges overlap.
    pub(crate) fn new(
        transaction_sequence: u64,
        transaction_snapshot_digest: ObjectDigest,
        plan_digest: ObjectDigest,
        physical_head_generation: u64,
        physical_head_digest: ObjectDigest,
        rows: Vec<StorageWorkspaceCatalogRowPlanV1>,
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        if transaction_sequence == 0
            || transaction_snapshot_digest.as_bytes() == &[0; 32]
            || plan_digest.as_bytes() == &[0; 32]
            || physical_head_generation == 0
            || physical_head_digest.as_bytes() == &[0; 32]
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }

        let mut prior_handle = None;
        let mut operation_ids = BTreeSet::new();
        let mut dataset_guids = BTreeSet::new();
        let mut ranges = Vec::with_capacity(rows.len());
        for row in &rows {
            row.validate()?;
            if prior_handle.is_some_and(|prior| prior >= row.workspace_handle)
                || !operation_ids.insert(row.creation_operation_id)
                || !dataset_guids.insert(row.dataset_guid)
            {
                return Err(StorageWorkspaceCatalogError::InvalidCandidate);
            }
            if let StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired { retirement, .. } =
                &row.policy
                && !operation_ids.insert(retirement.operation_id)
            {
                return Err(StorageWorkspaceCatalogError::InvalidCandidate);
            }
            prior_handle = Some(row.workspace_handle);
            ranges.push((
                row.identity_range_start,
                validate_identity_range(row.identity_range_start, row.identity_range_size)?,
            ));
        }
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }

        Ok(Self {
            transaction_sequence,
            transaction_snapshot_digest,
            plan_digest,
            physical_head_generation,
            physical_head_digest,
            rows,
        })
    }

    /// Returns the authenticated Storage transaction-journal sequence.
    pub(crate) const fn transaction_sequence(&self) -> u64 {
        self.transaction_sequence
    }

    /// Returns the digest of the complete authenticated transaction snapshot.
    pub(crate) const fn transaction_snapshot_digest(&self) -> ObjectDigest {
        self.transaction_snapshot_digest
    }

    /// Returns the digest of the logical projection plan.
    pub(crate) const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    /// Returns the authenticated physical-catalog head binding.
    pub(crate) const fn physical_head(&self) -> (u64, ObjectDigest) {
        (self.physical_head_generation, self.physical_head_digest)
    }

    /// Returns every managed row in strict bytewise handle order.
    pub(crate) fn rows(&self) -> &[StorageWorkspaceCatalogRowPlanV1] {
        &self.rows
    }
}

/// Owns structurally valid workspace-catalog custody without physical authority.
pub(crate) struct PendingStorageWorkspaceCatalogV1 {
    journal: Journal,
    identity_pool: StorageIdentityPoolV1,
    head: Option<CatalogHeadV1>,
    records: std::collections::BTreeMap<[u8; 32], WorkspaceRecordV1>,
    snapshot: StorageWorkspaceCatalogSnapshotV1,
    recovery: StorageWorkspaceCatalogRecoveryV1,
    #[cfg(test)]
    fail_after_next_materialization_commit: bool,
}

impl PendingStorageWorkspaceCatalogV1 {
    /// Opens protected journal state without initializing semantic catalog data.
    ///
    /// The caller must establish runtime custody before invoking this opener.
    /// The protected journal may create its journal and lock files and may
    /// truncate a bounded incomplete tail. It never creates a catalog head,
    /// accesses the workspace pin root, or changes a logical workspace row.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError`] for an unsafe directory,
    /// journal failure, foreign namespace, corrupt head or row, changed pool,
    /// or a headless state that has any committed history.
    pub(crate) fn open_root_owned(
        state_directory: &Path,
        identity_pool: StorageIdentityPoolV1,
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        let (journal, recovery) = Journal::open_protected_at(
            state_directory,
            WORKSPACE_JOURNAL_FILE,
            workspace_journal_limits(),
        )?;
        Self::recover(journal, recovery, identity_pool)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        state_directory: &Path,
        identity_pool: StorageIdentityPoolV1,
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        let (journal, recovery) = Journal::open(
            state_directory.join(WORKSPACE_JOURNAL_FILE),
            workspace_journal_limits(),
        )?;
        Self::recover(journal, recovery, identity_pool)
    }

    #[cfg(test)]
    pub(crate) fn write_active_record_for_test(
        state_directory: &Path,
        identity_pool: StorageIdentityPoolV1,
        publication: &StorageWorkspacePublicationV1,
        pin_proof: super::WorkspaceRootPinProofV1,
    ) -> Result<(), StorageWorkspaceCatalogError> {
        let mut record = WorkspaceRecordV1 {
            catalog_generation: 2,
            workspace_handle: publication.workspace_handle,
            creation_operation_id: publication.operation_id,
            request_catalog: super::CatalogBindingWire::from(publication.request_catalog),
            result_catalog: super::CatalogBindingWire::from(publication.result_catalog),
            result_digest: *publication.result_digest.as_bytes(),
            assignment: super::AssignmentWire::from(publication.assignment),
            root_image: super::ObjectDescriptorWire::from_runtime(&publication.root_image)?,
            kernel_boot_id: pin_proof.kernel_boot_id(),
            root_device: pin_proof.root_device(),
            root_inode: pin_proof.root_inode(),
            dataset_guid: publication.dataset_guid,
            pin_proof,
            uid_range_start: publication.identity_range_start,
            uid_range_size: publication.identity_range_size,
            lifecycle: super::WorkspaceLifecycleV1::Active,
            resource_digest: [0; 32],
        };
        record.refresh_digest()?;
        record.validate()?;

        let head = CatalogHeadV1 {
            generation: record.catalog_generation,
            identity_pool: IdentityPoolWire::from(identity_pool),
        };
        let (mut journal, _) = Journal::open(
            state_directory.join(WORKSPACE_JOURNAL_FILE),
            workspace_journal_limits(),
        )?;
        journal.commit(&aos_sandbox::JournalTransaction::new(
            [0xa7; 16],
            vec![
                aos_sandbox::JournalRecord::put(
                    RecordNamespace::StorageResourceInventory,
                    HEAD_KEY.to_vec(),
                    super::encode_head(&head)?,
                ),
                aos_sandbox::JournalRecord::put(
                    RecordNamespace::StorageResourceInventory,
                    super::record_key(&record.workspace_handle),
                    super::encode_record(&record)?,
                ),
            ],
        )?)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn initialize_empty_for_test(
        state_directory: &Path,
        identity_pool: StorageIdentityPoolV1,
    ) -> Result<(), StorageWorkspaceCatalogError> {
        let head = CatalogHeadV1 {
            generation: 1,
            identity_pool: IdentityPoolWire::from(identity_pool),
        };
        let (mut journal, _) = Journal::open(
            state_directory.join(WORKSPACE_JOURNAL_FILE),
            workspace_journal_limits(),
        )?;
        journal.commit(&aos_sandbox::JournalTransaction::new(
            [0xa8; 16],
            vec![aos_sandbox::JournalRecord::put(
                RecordNamespace::StorageResourceInventory,
                HEAD_KEY.to_vec(),
                super::encode_head(&head)?,
            )],
        )?)?;
        Ok(())
    }

    fn recover(
        journal: Journal,
        recovery: RecoveryReport,
        identity_pool: StorageIdentityPoolV1,
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        let mut head = None;
        let mut records = std::collections::BTreeMap::new();
        for (namespace, key, value) in journal.all_records() {
            if namespace != RecordNamespace::StorageResourceInventory {
                return Err(StorageWorkspaceCatalogError::CorruptRecord);
            }
            if key == HEAD_KEY {
                if head.replace(decode_head(value)?).is_some() {
                    return Err(StorageWorkspaceCatalogError::CorruptRecord);
                }
                continue;
            }
            if !key.starts_with(RECORD_KEY_PREFIX) {
                return Err(StorageWorkspaceCatalogError::CorruptRecord);
            }
            let handle = decode_record_key(key)?;
            let record = decode_record(value)?;
            if record.workspace_handle != handle || records.insert(handle, record).is_some() {
                return Err(StorageWorkspaceCatalogError::CorruptRecord);
            }
        }

        match &head {
            Some(head) => {
                let expected_generation = records
                    .values()
                    .map(|record| record.catalog_generation)
                    .max()
                    .unwrap_or(1);
                if head.identity_pool != IdentityPoolWire::from(identity_pool)
                    || head.generation != expected_generation
                    || head.generation == 0
                {
                    return Err(StorageWorkspaceCatalogError::CorruptRecord);
                }
            }
            None => {
                if !records.is_empty()
                    || recovery.committed_transactions != 0
                    || recovery.committed_records != 0
                    || journal.snapshot_sequence() != 1
                {
                    return Err(StorageWorkspaceCatalogError::CorruptRecord);
                }
            }
        }
        validate_record_set(&records, identity_pool)?;

        let snapshot = snapshot_binding(&journal, identity_pool, head.as_ref())?;
        Ok(Self {
            journal,
            identity_pool,
            head,
            records,
            snapshot,
            recovery: recovery.into(),
            #[cfg(test)]
            fail_after_next_materialization_commit: false,
        })
    }

    /// Returns the complete recovered catalog snapshot binding.
    pub(crate) const fn snapshot(&self) -> StorageWorkspaceCatalogSnapshotV1 {
        self.snapshot
    }

    /// Returns whether an incomplete journal tail was removed during opening.
    pub(crate) const fn recovery(&self) -> StorageWorkspaceCatalogRecoveryV1 {
        self.recovery
    }

    /// Checks a complete authenticated plan without granting active operations.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError`] when a planned allocation lies
    /// outside the configured pool, a durable row is orphaned or substituted,
    /// or its lifecycle is not an allowed prefix of the exact row policy.
    pub(crate) fn validate_plan(
        self,
        plan: StorageWorkspaceCatalogPlanV1,
    ) -> Result<ValidatedPendingStorageWorkspaceCatalogV1, StorageWorkspaceCatalogError> {
        validate_plan_against_pending(&self, &plan)?;

        Ok(ValidatedPendingStorageWorkspaceCatalogV1 {
            pending: self,
            plan,
        })
    }
}

fn validate_plan_against_pending(
    pending: &PendingStorageWorkspaceCatalogV1,
    plan: &StorageWorkspaceCatalogPlanV1,
) -> Result<(), StorageWorkspaceCatalogError> {
    let pool_end = pending.identity_pool.end()?;
    let mut planned_handles = BTreeSet::new();
    for row in &plan.rows {
        let range_end = validate_identity_range(row.identity_range_start, row.identity_range_size)?;
        if row.identity_range_start < pending.identity_pool.range_start
            || range_end > pool_end
            || !planned_handles.insert(row.workspace_handle)
        {
            return Err(StorageWorkspaceCatalogError::IdentityConflict);
        }

        match (pending.records.get(&row.workspace_handle), &row.policy) {
            (None, _) => {}
            (Some(_), StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent) => {
                return Err(StorageWorkspaceCatalogError::IdentityConflict);
            }
            (Some(record), _) if record.matches_pending_plan(row) => {}
            (Some(_), _) => return Err(StorageWorkspaceCatalogError::IdentityConflict),
        }
    }
    if pending
        .records
        .keys()
        .any(|handle| !planned_handles.contains(handle))
    {
        return Err(StorageWorkspaceCatalogError::IdentityConflict);
    }
    Ok(())
}

/// Retains structurally validated catalog state and its exact authority plan.
///
/// This typestate exposes no physical observation, allocation, or inventory
/// authority. Its only semantic mutation is the private terminal materializer,
/// which the activation typestate may call after consuming fresh evidence.
pub(crate) struct ValidatedPendingStorageWorkspaceCatalogV1 {
    pending: PendingStorageWorkspaceCatalogV1,
    plan: StorageWorkspaceCatalogPlanV1,
}

impl ValidatedPendingStorageWorkspaceCatalogV1 {
    /// Returns the structurally validated workspace-catalog snapshot binding.
    pub(crate) const fn snapshot(&self) -> StorageWorkspaceCatalogSnapshotV1 {
        self.pending.snapshot
    }

    /// Returns whether journal opening recovered an incomplete tail.
    pub(crate) const fn recovery(&self) -> StorageWorkspaceCatalogRecoveryV1 {
        self.pending.recovery
    }

    /// Returns the exact authenticated plan checked against durable rows.
    pub(crate) const fn plan(&self) -> &StorageWorkspaceCatalogPlanV1 {
        &self.plan
    }

    /// Replaces only the in-memory authority plan after exact revalidation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError`] when the current durable rows
    /// are not an allowed prefix of the newly composed transaction plan.
    pub(crate) fn revalidate_plan(
        &mut self,
        plan: StorageWorkspaceCatalogPlanV1,
    ) -> Result<(), StorageWorkspaceCatalogError> {
        validate_plan_against_pending(&self.pending, &plan)?;
        self.plan = plan;
        Ok(())
    }

    /// Consumes fresh-observation custody and durably reaches every terminal row.
    ///
    /// The caller must hold the private fresh-observation capability for this
    /// exact plan before invoking this method. All deterministic journal and
    /// record bounds are preflighted before the first write. Each row and its
    /// new head are one atomic transaction, so a crash leaves an authenticated
    /// prefix that can be resumed after a new observation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError`] when the plan is not terminal,
    /// a terminal record is invalid, a journal bound is exhausted, or a commit
    /// fails. A commit error consumes custody because journal durability may be
    /// ambiguous; callers must reopen and recover rather than retrying it.
    pub(super) fn materialize_terminal(mut self) -> Result<Self, StorageWorkspaceCatalogError> {
        let mut generation = self.pending.head.as_ref().map_or(1, |head| head.generation);
        let mut projected_records = self.pending.records.clone();
        let mut transactions = Vec::new();

        if self.pending.head.is_none() {
            let head = CatalogHeadV1 {
                generation,
                identity_pool: IdentityPoolWire::from(self.pending.identity_pool),
            };
            transactions.push(JournalTransaction::new(
                genesis_transaction_id(self.pending.identity_pool),
                vec![JournalRecord::put(
                    RecordNamespace::StorageResourceInventory,
                    HEAD_KEY.to_vec(),
                    encode_head(&head)?,
                )],
            )?);
        }

        for row in &self.plan.rows {
            if projected_records
                .get(&row.workspace_handle)
                .is_some_and(|record| record_matches_terminal_policy(record, row))
            {
                continue;
            }

            generation = next_generation(generation)?;
            let (record, operation_id) = terminal_record(row, generation)?;
            let head = CatalogHeadV1 {
                generation,
                identity_pool: IdentityPoolWire::from(self.pending.identity_pool),
            };
            transactions.push(JournalTransaction::new(
                transaction_id(operation_id, generation),
                vec![
                    JournalRecord::put(
                        RecordNamespace::StorageResourceInventory,
                        HEAD_KEY.to_vec(),
                        encode_head(&head)?,
                    ),
                    JournalRecord::put(
                        RecordNamespace::StorageResourceInventory,
                        record_key(&record.workspace_handle),
                        encode_record(&record)?,
                    ),
                ],
            )?);
            projected_records.insert(row.workspace_handle, record);
        }

        validate_record_set(&projected_records, self.pending.identity_pool)?;
        self.pending.journal.preflight_transactions(&transactions)?;
        for transaction in &transactions {
            self.pending.journal.commit(transaction)?;
            #[cfg(test)]
            if std::mem::take(&mut self.pending.fail_after_next_materialization_commit) {
                // Model an error returned after a complete transaction became
                // durable but before the in-memory projection was refreshed.
                return Err(aos_sandbox::JournalError::Io(std::io::Error::other(
                    "injected failure after durable workspace catalog commit",
                ))
                .into());
            }
        }

        self.pending.head = Some(CatalogHeadV1 {
            generation,
            identity_pool: IdentityPoolWire::from(self.pending.identity_pool),
        });
        self.pending.records = projected_records;
        self.pending.snapshot = snapshot_binding(
            &self.pending.journal,
            self.pending.identity_pool,
            self.pending.head.as_ref(),
        )?;
        validate_plan_against_pending(&self.pending, &self.plan)?;
        if !self.is_terminally_materialized() {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }

        Ok(self)
    }

    #[cfg(test)]
    pub(crate) fn fail_after_next_materialization_commit_for_test(&mut self) {
        self.pending.fail_after_next_materialization_commit = true;
    }

    /// Returns whether the semantic workspace catalog already has a head.
    pub(crate) const fn is_initialized(&self) -> bool {
        self.pending.head.is_some()
    }

    /// Reports whether every durable row already equals its terminal policy.
    pub(crate) fn is_terminally_materialized(&self) -> bool {
        self.is_initialized()
            && self.pending.records.len() == self.plan.rows.len()
            && self.plan.rows.iter().all(|row| {
                let Some(record) = self.pending.records.get(&row.workspace_handle) else {
                    return false;
                };
                match &row.policy {
                    StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(publication) => {
                        record.is_active()
                            && record.matches_creation(publication)
                            && record.pin_proof == publication.pin_proof
                    }
                    StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired {
                        creation,
                        retirement,
                    } => {
                        record.matches_creation(creation)
                            && record.pin_proof == creation.pin_proof
                            && record.matches_retirement(retirement)
                    }
                    StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent
                    | StorageWorkspaceCatalogRowPolicyV1::MayRetainExactActive(_) => false,
                }
            })
    }

    /// Returns the retained journal sequence for a future freshness check.
    pub(crate) const fn journal_sequence(&self) -> u64 {
        self.pending.journal.snapshot_sequence()
    }

    /// Recomputes the retained journal binding without changing typestate.
    pub(super) fn validate_current_snapshot(
        &self,
    ) -> Result<StorageWorkspaceCatalogSnapshotV1, StorageWorkspaceCatalogError> {
        let current = snapshot_binding(
            &self.pending.journal,
            self.pending.identity_pool,
            self.pending.head.as_ref(),
        )?;
        if current != self.pending.snapshot {
            return Err(StorageWorkspaceCatalogError::CorruptRecord);
        }
        Ok(current)
    }

    /// Borrows the exact decoded rows retained under the journal lock.
    pub(super) const fn records(&self) -> &std::collections::BTreeMap<[u8; 32], WorkspaceRecordV1> {
        &self.pending.records
    }
}

fn terminal_record(
    row: &StorageWorkspaceCatalogRowPlanV1,
    catalog_generation: u64,
) -> Result<(WorkspaceRecordV1, [u8; 16]), StorageWorkspaceCatalogError> {
    let (publication, lifecycle, root_device, root_inode, operation_id) = match &row.policy {
        StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(publication) => (
            publication,
            WorkspaceLifecycleV1::Active,
            publication.pin_proof.root_device(),
            publication.pin_proof.root_inode(),
            publication.operation_id,
        ),
        StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired {
            creation,
            retirement,
        } => (
            creation,
            WorkspaceLifecycleV1::Retired {
                operation_id: retirement.operation_id,
                request_catalog: CatalogBindingWire::from(retirement.request_catalog),
                result_catalog: CatalogBindingWire::from(retirement.result_catalog),
                result_digest: *retirement.result_digest.as_bytes(),
            },
            0,
            0,
            retirement.operation_id,
        ),
        StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent
        | StorageWorkspaceCatalogRowPolicyV1::MayRetainExactActive(_) => {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
    };
    let mut record = WorkspaceRecordV1 {
        catalog_generation,
        workspace_handle: publication.workspace_handle,
        creation_operation_id: publication.operation_id,
        request_catalog: CatalogBindingWire::from(publication.request_catalog),
        result_catalog: CatalogBindingWire::from(publication.result_catalog),
        result_digest: *publication.result_digest.as_bytes(),
        assignment: AssignmentWire::from(publication.assignment),
        root_image: ObjectDescriptorWire::from_runtime(&publication.root_image)?,
        kernel_boot_id: publication.pin_proof.kernel_boot_id(),
        root_device,
        root_inode,
        dataset_guid: publication.dataset_guid,
        pin_proof: publication.pin_proof.clone(),
        uid_range_start: publication.identity_range_start,
        uid_range_size: publication.identity_range_size,
        lifecycle,
        resource_digest: [0; 32],
    };
    record.refresh_digest()?;
    record.validate()?;

    Ok((record, operation_id))
}

fn record_matches_terminal_policy(
    record: &WorkspaceRecordV1,
    row: &StorageWorkspaceCatalogRowPlanV1,
) -> bool {
    match row.policy() {
        StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(publication) => {
            record.is_active()
                && record.matches_creation(publication)
                && record.pin_proof == publication.pin_proof
        }
        StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired {
            creation,
            retirement,
        } => {
            record.matches_creation(creation)
                && record.pin_proof == creation.pin_proof
                && record.matches_retirement(retirement)
        }
        StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent
        | StorageWorkspaceCatalogRowPolicyV1::MayRetainExactActive(_) => false,
    }
}

fn snapshot_binding(
    journal: &Journal,
    identity_pool: StorageIdentityPoolV1,
    head: Option<&CatalogHeadV1>,
) -> Result<StorageWorkspaceCatalogSnapshotV1, StorageWorkspaceCatalogError> {
    let journal_sequence = journal.snapshot_sequence();
    if journal_sequence == 0 {
        return Err(StorageWorkspaceCatalogError::CorruptRecord);
    }

    let mut digest = FramedDigest::new(SNAPSHOT_DIGEST_DOMAIN);
    digest.field(&journal_sequence.to_be_bytes())?;
    digest.field(&identity_pool.range_start.to_be_bytes())?;
    digest.field(&identity_pool.range_size.to_be_bytes())?;
    let catalog_generation = match head {
        Some(head) => {
            digest.field(&[1])?;
            digest.field(&head.generation.to_be_bytes())?;
            digest.field(&head.identity_pool.range_start.to_be_bytes())?;
            digest.field(&head.identity_pool.range_size.to_be_bytes())?;
            Some(head.generation)
        }
        None => {
            digest.field(&[0])?;
            None
        }
    };
    for (namespace, key, value) in journal.all_records() {
        digest.field(&(namespace as u16).to_be_bytes())?;
        digest.field(key)?;
        digest.field(value)?;
    }

    Ok(StorageWorkspaceCatalogSnapshotV1 {
        journal_sequence,
        digest: digest.finish()?,
        catalog_generation,
        identity_pool,
    })
}

struct FramedDigest(Sha256);

impl FramedDigest {
    fn new(domain: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(domain);
        Self(digest)
    }

    fn field(&mut self, bytes: &[u8]) -> Result<(), StorageWorkspaceCatalogError> {
        // Fixed-width framing keeps this binding independent of pointer width.
        let length =
            u64::try_from(bytes.len()).map_err(|_| StorageWorkspaceCatalogError::CorruptRecord)?;
        self.0.update(length.to_be_bytes());
        self.0.update(bytes);
        Ok(())
    }

    fn finish(self) -> Result<ObjectDigest, StorageWorkspaceCatalogError> {
        let digest = ObjectDigest::from_bytes(self.0.finalize().into());
        if digest.as_bytes() == &[0; 32] {
            Err(StorageWorkspaceCatalogError::CorruptRecord)
        } else {
            Ok(digest)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::OpenOptions;
    use std::io::Write as _;

    use aos_sandbox::{JournalRecord, JournalTransaction};
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, MediaType,
        ObjectDescriptor, PortableMediaType, SandboxId,
    };
    use aos_sandbox_protocol::MINIMUM_HOST_IDENTITY_RANGE;
    use tempfile::TempDir;

    use super::*;
    use crate::CatalogBindingV1;
    use crate::workspace_pin::WorkspaceRootPinProofV1;

    const RANGE_SIZE: u32 = MINIMUM_HOST_IDENTITY_RANGE;

    fn pool(range_count: u32) -> StorageIdentityPoolV1 {
        StorageIdentityPoolV1::new(RANGE_SIZE, RANGE_SIZE * range_count).unwrap()
    }

    fn binding(generation: u64, marker: u8) -> CatalogBindingV1 {
        CatalogBindingV1::from_publisher(generation, ObjectDigest::from_bytes([marker; 32]))
            .unwrap()
    }

    fn publication(marker: u8) -> StorageWorkspacePublicationV1 {
        let dataset_guid = u64::from(marker) + 100;
        let pin_proof = WorkspaceRootPinProofV1::new(
            [marker.wrapping_add(40); 16],
            u64::from(marker) + 50,
            u64::from(marker) + 60,
            u64::from(marker) + 70,
            "/".to_owned(),
            format!("/run/aos/sandbox-pins/workspaces/{marker:02x}"),
            "zfs".to_owned(),
            format!("tank/aos/project/work-{marker}"),
            dataset_guid,
            u64::from(marker) + 80,
            u64::from(marker) + 90,
            crate::root_policy::WorkspaceRootPolicyV1::create_initialize().root_attributes(),
        )
        .unwrap();
        StorageWorkspacePublicationV1 {
            operation_id: [marker.wrapping_add(10); 16],
            request_catalog: binding(u64::from(marker) + 10, marker.wrapping_add(20)),
            result_catalog: binding(u64::from(marker) + 11, marker.wrapping_add(21)),
            result_digest: ObjectDigest::from_bytes([marker.wrapping_add(22); 32]),
            workspace_handle: [marker; 32],
            dataset_guid,
            assignment: BrokerAssignment::new(
                SandboxId::from_bytes([marker; 16]),
                IncarnationId::from_bytes([marker.wrapping_add(1); 16]),
                AssignmentEpoch::new(u64::from(marker) + 1),
                DesiredGeneration::new(u64::from(marker) + 2),
                ObjectDigest::from_bytes([marker.wrapping_add(2); 32]),
            )
            .unwrap(),
            root_image: ObjectDescriptor::new(
                MediaType::new(PortableMediaType::View.as_str().to_owned()).unwrap(),
                ObjectDigest::from_bytes([marker.wrapping_add(30); 32]),
                u64::from(marker) + 1,
            ),
            identity_range_start: u32::from(marker) * RANGE_SIZE,
            identity_range_size: RANGE_SIZE,
            pin_proof,
        }
    }

    fn retirement(marker: u8) -> StorageWorkspaceRetirementV1 {
        StorageWorkspaceRetirementV1 {
            operation_id: [marker.wrapping_add(100); 16],
            request_catalog: binding(u64::from(marker) + 30, marker.wrapping_add(40)),
            result_catalog: binding(u64::from(marker) + 31, marker.wrapping_add(41)),
            result_digest: ObjectDigest::from_bytes([marker.wrapping_add(42); 32]),
            workspace_handle: [marker; 32],
            dataset_guid: u64::from(marker) + 100,
        }
    }

    fn active_record(publication: &StorageWorkspacePublicationV1) -> WorkspaceRecordV1 {
        let mut record = WorkspaceRecordV1 {
            catalog_generation: 2,
            workspace_handle: publication.workspace_handle,
            creation_operation_id: publication.operation_id,
            request_catalog: super::super::CatalogBindingWire::from(publication.request_catalog),
            result_catalog: super::super::CatalogBindingWire::from(publication.result_catalog),
            result_digest: *publication.result_digest.as_bytes(),
            assignment: super::super::AssignmentWire::from(publication.assignment),
            root_image: super::super::ObjectDescriptorWire::from_runtime(&publication.root_image)
                .unwrap(),
            kernel_boot_id: publication.pin_proof.kernel_boot_id(),
            root_device: publication.pin_proof.root_device(),
            root_inode: publication.pin_proof.root_inode(),
            dataset_guid: publication.dataset_guid,
            pin_proof: publication.pin_proof.clone(),
            uid_range_start: publication.identity_range_start,
            uid_range_size: publication.identity_range_size,
            lifecycle: super::super::WorkspaceLifecycleV1::Active,
            resource_digest: [0; 32],
        };
        record.refresh_digest().unwrap();
        record.validate().unwrap();
        record
    }

    fn retired_record(
        publication: &StorageWorkspacePublicationV1,
        retirement: StorageWorkspaceRetirementV1,
    ) -> WorkspaceRecordV1 {
        let mut record = active_record(publication);
        record.lifecycle = super::super::WorkspaceLifecycleV1::Retired {
            operation_id: retirement.operation_id,
            request_catalog: super::super::CatalogBindingWire::from(retirement.request_catalog),
            result_catalog: super::super::CatalogBindingWire::from(retirement.result_catalog),
            result_digest: *retirement.result_digest.as_bytes(),
        };
        record.refresh_digest().unwrap();
        record.validate().unwrap();
        record
    }

    fn row(
        publication: &StorageWorkspacePublicationV1,
        policy: StorageWorkspaceCatalogRowPolicyV1,
    ) -> StorageWorkspaceCatalogRowPlanV1 {
        let active_prefixes = if matches!(policy, StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent)
        {
            Vec::new()
        } else {
            vec![active_prefix(publication, 1)]
        };
        StorageWorkspaceCatalogRowPlanV1::new(
            publication.workspace_handle,
            publication.dataset_guid,
            publication.operation_id,
            publication.identity_range_start,
            publication.identity_range_size,
            policy,
            active_prefixes,
        )
        .unwrap()
    }

    fn active_prefix(
        publication: &StorageWorkspacePublicationV1,
        attempt_ordinal: u8,
    ) -> StorageWorkspaceCatalogActivePrefixV1 {
        StorageWorkspaceCatalogActivePrefixV1::new(
            [publication.workspace_handle[0].wrapping_add(attempt_ordinal); 16],
            attempt_ordinal,
            ObjectDigest::from_bytes([attempt_ordinal.wrapping_add(100); 32]),
            publication.clone(),
        )
        .unwrap()
    }

    fn plan(rows: Vec<StorageWorkspaceCatalogRowPlanV1>) -> StorageWorkspaceCatalogPlanV1 {
        StorageWorkspaceCatalogPlanV1::new(
            7,
            ObjectDigest::from_bytes([71; 32]),
            ObjectDigest::from_bytes([72; 32]),
            8,
            ObjectDigest::from_bytes([73; 32]),
            rows,
        )
        .unwrap()
    }

    fn commit_catalog_record(
        directory: &TempDir,
        identity_pool: StorageIdentityPoolV1,
        record: &WorkspaceRecordV1,
    ) {
        let (mut journal, _) = Journal::open(
            directory.path().join(WORKSPACE_JOURNAL_FILE),
            workspace_journal_limits(),
        )
        .unwrap();
        let head = CatalogHeadV1 {
            generation: record.catalog_generation,
            identity_pool: IdentityPoolWire::from(identity_pool),
        };
        journal
            .commit(
                &JournalTransaction::new(
                    [record.workspace_handle[0].wrapping_add(150); 16],
                    vec![
                        JournalRecord::put(
                            RecordNamespace::StorageResourceInventory,
                            HEAD_KEY.to_vec(),
                            super::super::encode_head(&head).unwrap(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::StorageResourceInventory,
                            super::super::record_key(&record.workspace_handle),
                            super::super::encode_record(record).unwrap(),
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
    }

    fn validate_with_record(
        identity_pool: StorageIdentityPoolV1,
        record: Option<&WorkspaceRecordV1>,
        authority_plan: StorageWorkspaceCatalogPlanV1,
    ) -> Result<ValidatedPendingStorageWorkspaceCatalogV1, StorageWorkspaceCatalogError> {
        let directory = TempDir::new().unwrap();
        if let Some(record) = record {
            commit_catalog_record(&directory, identity_pool, record);
        }
        PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)?
            .validate_plan(authority_plan)
    }

    #[test]
    fn headless_catalog_is_only_valid_for_never_initialized_history() {
        let directory = TempDir::new().unwrap();
        let identity_pool = pool(2);
        assert!(!directory.path().join(WORKSPACE_JOURNAL_FILE).exists());

        let pending =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap();
        let snapshot = pending.snapshot();
        assert_eq!(snapshot.journal_sequence(), 1);
        assert_eq!(snapshot.catalog_generation(), None);
        assert_eq!(snapshot.identity_pool(), identity_pool);
        assert!(pending.journal.is_materialized_empty());
        assert_eq!(
            pending.recovery(),
            StorageWorkspaceCatalogRecoveryV1::Clean {
                committed_transactions: 0,
                committed_records: 0,
            }
        );
        let validated = pending.validate_plan(plan(Vec::new())).unwrap();
        assert!(!validated.is_initialized());
        assert_eq!(validated.journal_sequence(), 1);
        drop(validated);

        let reopened =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap();
        assert_eq!(reopened.snapshot(), snapshot);
        drop(reopened);

        let deleted = TempDir::new().unwrap();
        let (mut journal, _) = Journal::open(
            deleted.path().join(WORKSPACE_JOURNAL_FILE),
            workspace_journal_limits(),
        )
        .unwrap();
        let head = CatalogHeadV1 {
            generation: 1,
            identity_pool: IdentityPoolWire::from(identity_pool),
        };
        journal
            .commit(
                &JournalTransaction::new(
                    [1; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::StorageResourceInventory,
                        HEAD_KEY.to_vec(),
                        super::super::encode_head(&head).unwrap(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [2; 16],
                    vec![JournalRecord::delete(
                        RecordNamespace::StorageResourceInventory,
                        HEAD_KEY.to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(journal.is_materialized_empty());
        drop(journal);

        assert!(matches!(
            PendingStorageWorkspaceCatalogV1::open_for_test(deleted.path(), identity_pool),
            Err(StorageWorkspaceCatalogError::CorruptRecord)
        ));
    }

    #[test]
    fn terminal_materialization_resumes_an_atomic_crash_prefix_and_replays() {
        let directory = TempDir::new().unwrap();
        let identity_pool = pool(3);
        let active_publication = publication(1);
        let retired_publication = publication(2);
        let retired = retirement(2);
        commit_catalog_record(
            &directory,
            identity_pool,
            &active_record(&active_publication),
        );

        // The first row represents the durable prefix left by a crash between
        // row transactions. A new activation resumes only the missing row.
        let authority_plan = || {
            plan(vec![
                row(
                    &active_publication,
                    StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(
                        active_publication.clone(),
                    ),
                ),
                row(
                    &retired_publication,
                    StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired {
                        creation: retired_publication.clone(),
                        retirement: retired,
                    },
                ),
            ])
        };
        let validated =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap()
                .validate_plan(authority_plan())
                .unwrap();
        let materialized = validated.materialize_terminal().unwrap();
        let terminal_snapshot = materialized.snapshot();

        assert!(materialized.is_terminally_materialized());
        assert_eq!(terminal_snapshot.catalog_generation(), Some(3));
        assert_eq!(materialized.records().len(), 2);

        // Exact replay emits no transaction and therefore keeps the complete
        // snapshot binding unchanged.
        let replayed = materialized.materialize_terminal().unwrap();
        assert_eq!(replayed.snapshot(), terminal_snapshot);
        drop(replayed);

        let reopened =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap()
                .validate_plan(authority_plan())
                .unwrap();
        assert!(reopened.is_terminally_materialized());
        assert_eq!(reopened.snapshot(), terminal_snapshot);
    }

    #[test]
    fn recovered_empty_tail_is_distinct_and_snapshot_stabilizes_on_clean_reopen() {
        let directory = TempDir::new().unwrap();
        let identity_pool = pool(2);
        let journal_path = directory.path().join(WORKSPACE_JOURNAL_FILE);
        let (journal, _) = Journal::open(&journal_path, workspace_journal_limits()).unwrap();
        drop(journal);
        let mut file = OpenOptions::new().append(true).open(&journal_path).unwrap();
        file.write_all(b"incomplete-frame").unwrap();
        file.sync_data().unwrap();
        drop(file);

        let recovered =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap();
        assert_eq!(
            recovered.recovery(),
            StorageWorkspaceCatalogRecoveryV1::RecoveredTail {
                committed_transactions: 0,
                committed_records: 0,
                truncated_bytes: 16,
            }
        );
        let recovered_snapshot = recovered.snapshot();
        assert_eq!(recovered_snapshot.journal_sequence(), 1);
        drop(recovered);

        let clean =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap();
        assert!(matches!(
            clean.recovery(),
            StorageWorkspaceCatalogRecoveryV1::Clean { .. }
        ));
        assert_eq!(clean.snapshot(), recovered_snapshot);
    }

    #[test]
    fn foreign_and_mixed_namespaces_fail_closed() {
        let identity_pool = pool(2);
        let foreign = TempDir::new().unwrap();
        let (mut journal, _) = Journal::open(
            foreign.path().join(WORKSPACE_JOURNAL_FILE),
            workspace_journal_limits(),
        )
        .unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [1; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        b"foreign".to_vec(),
                        b"value".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(matches!(
            PendingStorageWorkspaceCatalogV1::open_for_test(foreign.path(), identity_pool),
            Err(StorageWorkspaceCatalogError::CorruptRecord)
        ));

        let mixed = TempDir::new().unwrap();
        let (mut journal, _) = Journal::open(
            mixed.path().join(WORKSPACE_JOURNAL_FILE),
            workspace_journal_limits(),
        )
        .unwrap();
        let head = CatalogHeadV1 {
            generation: 1,
            identity_pool: IdentityPoolWire::from(identity_pool),
        };
        journal
            .commit(
                &JournalTransaction::new(
                    [2; 16],
                    vec![
                        JournalRecord::put(
                            RecordNamespace::StorageResourceInventory,
                            HEAD_KEY.to_vec(),
                            super::super::encode_head(&head).unwrap(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::Effect,
                            b"foreign".to_vec(),
                            b"value".to_vec(),
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(matches!(
            PendingStorageWorkspaceCatalogV1::open_for_test(mixed.path(), identity_pool),
            Err(StorageWorkspaceCatalogError::CorruptRecord)
        ));
    }

    fn raw_snapshot_digest(
        namespace: RecordNamespace,
        key: &[u8],
        value: &[u8],
        identity_pool: StorageIdentityPoolV1,
        head: CatalogHeadV1,
        overwrite: bool,
    ) -> ObjectDigest {
        let directory = TempDir::new().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join(WORKSPACE_JOURNAL_FILE),
            workspace_journal_limits(),
        )
        .unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [1; 16],
                    vec![JournalRecord::put(namespace, key.to_vec(), value.to_vec())],
                )
                .unwrap(),
            )
            .unwrap();
        if overwrite {
            journal
                .commit(
                    &JournalTransaction::new(
                        [2; 16],
                        vec![JournalRecord::put(namespace, key.to_vec(), value.to_vec())],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        snapshot_binding(&journal, identity_pool, Some(&head))
            .unwrap()
            .digest()
    }

    #[test]
    fn snapshot_digest_frames_sequence_pool_head_namespace_key_and_value() {
        let identity_pool = pool(2);
        let head = CatalogHeadV1 {
            generation: 1,
            identity_pool: IdentityPoolWire::from(identity_pool),
        };
        let baseline = raw_snapshot_digest(
            RecordNamespace::StorageResourceInventory,
            b"key",
            b"value",
            identity_pool,
            head.clone(),
            false,
        );
        let mut expected = Sha256::new();
        expected.update(SNAPSHOT_DIGEST_DOMAIN);
        for field in [
            4_u64.to_be_bytes().as_slice(),
            identity_pool.range_start.to_be_bytes().as_slice(),
            identity_pool.range_size.to_be_bytes().as_slice(),
            [1_u8].as_slice(),
            head.generation.to_be_bytes().as_slice(),
            head.identity_pool.range_start.to_be_bytes().as_slice(),
            head.identity_pool.range_size.to_be_bytes().as_slice(),
            (RecordNamespace::StorageResourceInventory as u16)
                .to_be_bytes()
                .as_slice(),
            b"key".as_slice(),
            b"value".as_slice(),
        ] {
            expected.update((field.len() as u64).to_be_bytes());
            expected.update(field);
        }
        assert_eq!(
            baseline,
            ObjectDigest::from_bytes(expected.finalize().into())
        );

        let variants = [
            raw_snapshot_digest(
                RecordNamespace::DesiredState,
                b"key",
                b"value",
                identity_pool,
                head.clone(),
                false,
            ),
            raw_snapshot_digest(
                RecordNamespace::StorageResourceInventory,
                b"key-2",
                b"value",
                identity_pool,
                head.clone(),
                false,
            ),
            raw_snapshot_digest(
                RecordNamespace::StorageResourceInventory,
                b"key",
                b"value-2",
                identity_pool,
                head.clone(),
                false,
            ),
            raw_snapshot_digest(
                RecordNamespace::StorageResourceInventory,
                b"key",
                b"value",
                identity_pool,
                head.clone(),
                true,
            ),
            raw_snapshot_digest(
                RecordNamespace::StorageResourceInventory,
                b"key",
                b"value",
                pool(3),
                head.clone(),
                false,
            ),
            raw_snapshot_digest(
                RecordNamespace::StorageResourceInventory,
                b"key",
                b"value",
                identity_pool,
                CatalogHeadV1 {
                    generation: 2,
                    identity_pool: IdentityPoolWire::from(identity_pool),
                },
                false,
            ),
        ];
        assert!(variants.into_iter().all(|variant| variant != baseline));
    }

    #[test]
    fn every_row_policy_accepts_only_its_exact_durable_prefixes() {
        let identity_pool = pool(3);
        let creation = publication(1);
        let active = active_record(&creation);
        let removal = retirement(1);
        let retired = retired_record(&creation, removal);

        let absent = row(&creation, StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent);
        assert!(validate_with_record(identity_pool, None, plan(vec![absent.clone()])).is_ok());
        assert!(matches!(
            validate_with_record(identity_pool, Some(&active), plan(vec![absent])),
            Err(StorageWorkspaceCatalogError::IdentityConflict)
        ));

        let retained = row(
            &creation,
            StorageWorkspaceCatalogRowPolicyV1::MayRetainExactActive(creation.clone()),
        );
        assert!(validate_with_record(identity_pool, None, plan(vec![retained.clone()])).is_ok());
        assert!(
            validate_with_record(identity_pool, Some(&active), plan(vec![retained.clone()]))
                .is_ok()
        );
        assert!(matches!(
            validate_with_record(identity_pool, Some(&retired), plan(vec![retained])),
            Err(StorageWorkspaceCatalogError::IdentityConflict)
        ));

        let converge_active = row(
            &creation,
            StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(creation.clone()),
        );
        assert!(
            validate_with_record(identity_pool, None, plan(vec![converge_active.clone()])).is_ok()
        );
        assert!(
            validate_with_record(
                identity_pool,
                Some(&active),
                plan(vec![converge_active.clone()]),
            )
            .is_ok()
        );
        assert!(matches!(
            validate_with_record(identity_pool, Some(&retired), plan(vec![converge_active]),),
            Err(StorageWorkspaceCatalogError::IdentityConflict)
        ));

        let converge_retired = row(
            &creation,
            StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired {
                creation: creation.clone(),
                retirement: removal,
            },
        );
        assert!(
            validate_with_record(identity_pool, None, plan(vec![converge_retired.clone()])).is_ok()
        );
        assert!(
            validate_with_record(
                identity_pool,
                Some(&active),
                plan(vec![converge_retired.clone()]),
            )
            .is_ok()
        );
        assert!(
            validate_with_record(identity_pool, Some(&retired), plan(vec![converge_retired]),)
                .is_ok()
        );
    }

    #[test]
    fn an_allowed_older_active_prefix_never_becomes_terminal_authority() {
        let identity_pool = pool(3);
        let latest = publication(1);
        let mut older = latest.clone();
        let proof = &latest.pin_proof;
        older.pin_proof = WorkspaceRootPinProofV1::new(
            proof.kernel_boot_id(),
            proof.mount_namespace_device(),
            proof.mount_namespace_inode(),
            proof.mount_id() + 100,
            proof.mount_root().to_owned(),
            proof.mount_point().to_owned(),
            proof.filesystem_type().to_owned(),
            proof.superblock_source().to_owned(),
            proof.dataset_guid(),
            proof.root_device() + 100,
            proof.root_inode() + 100,
            proof.root_attributes(),
        )
        .unwrap();
        let row = StorageWorkspaceCatalogRowPlanV1::new(
            latest.workspace_handle,
            latest.dataset_guid,
            latest.operation_id,
            latest.identity_range_start,
            latest.identity_range_size,
            StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(latest.clone()),
            vec![active_prefix(&older, 1), active_prefix(&latest, 2)],
        )
        .unwrap();

        let retained_older = validate_with_record(
            identity_pool,
            Some(&active_record(&older)),
            plan(vec![row.clone()]),
        )
        .unwrap();
        assert!(!retained_older.is_terminally_materialized());

        let retained_latest = validate_with_record(
            identity_pool,
            Some(&active_record(&latest)),
            plan(vec![row]),
        )
        .unwrap();
        assert!(retained_latest.is_terminally_materialized());
    }

    #[test]
    fn row_substitution_and_orphan_records_fail_closed() {
        let identity_pool = pool(3);
        let creation = publication(1);
        let expected = row(
            &creation,
            StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(creation.clone()),
        );
        let active = active_record(&creation);

        let mut substituted = active.clone();
        substituted.assignment.desired_generation += 1;
        substituted.refresh_digest().unwrap();
        substituted.validate().unwrap();
        assert!(matches!(
            validate_with_record(identity_pool, Some(&substituted), plan(vec![expected])),
            Err(StorageWorkspaceCatalogError::IdentityConflict)
        ));

        assert!(matches!(
            validate_with_record(identity_pool, Some(&active), plan(Vec::new())),
            Err(StorageWorkspaceCatalogError::IdentityConflict)
        ));

        let second = publication(2);
        assert!(
            StorageWorkspaceCatalogPlanV1::new(
                7,
                ObjectDigest::from_bytes([71; 32]),
                ObjectDigest::from_bytes([72; 32]),
                8,
                ObjectDigest::from_bytes([73; 32]),
                vec![
                    row(&second, StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent),
                    row(&creation, StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent),
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn structural_open_does_not_depend_on_the_ambient_pin_root() {
        let directory = TempDir::new().unwrap();
        let identity_pool = pool(2);
        let nonexistent_pin_root = directory.path().join("pins-never-created");
        assert!(!nonexistent_pin_root.exists());

        let pending =
            PendingStorageWorkspaceCatalogV1::open_for_test(directory.path(), identity_pool)
                .unwrap();
        assert_eq!(pending.snapshot().catalog_generation(), None);
        assert!(!nonexistent_pin_root.exists());
    }

    #[test]
    fn row_plan_rejects_cross_bound_publication_and_retirement() {
        let creation = publication(1);
        let mut substituted_creation = creation.clone();
        substituted_creation.dataset_guid += 1;
        assert!(
            StorageWorkspaceCatalogRowPlanV1::new(
                creation.workspace_handle,
                creation.dataset_guid,
                creation.operation_id,
                creation.identity_range_start,
                creation.identity_range_size,
                StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(substituted_creation),
                vec![active_prefix(&creation, 1)],
            )
            .is_err()
        );

        let mut substituted_portable_facts = creation.clone();
        substituted_portable_facts.assignment = publication(2).assignment;
        assert!(
            StorageWorkspaceCatalogRowPlanV1::new(
                creation.workspace_handle,
                creation.dataset_guid,
                creation.operation_id,
                creation.identity_range_start,
                creation.identity_range_size,
                StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(substituted_portable_facts,),
                vec![active_prefix(&creation, 1)],
            )
            .is_err()
        );

        let mut substituted_retirement = retirement(1);
        substituted_retirement.workspace_handle = [2; 32];
        assert!(
            StorageWorkspaceCatalogRowPlanV1::new(
                creation.workspace_handle,
                creation.dataset_guid,
                creation.operation_id,
                creation.identity_range_start,
                creation.identity_range_size,
                StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired {
                    creation,
                    retirement: substituted_retirement,
                },
                vec![active_prefix(&publication(1), 1)],
            )
            .is_err()
        );
    }
}
