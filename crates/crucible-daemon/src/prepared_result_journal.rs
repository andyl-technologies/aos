//! Crash-safe local ownership of one prepared semantic attempt result.
//!
//! Each execution key selects one directory in an operator-owned namespace:
//!
//! ```text
//! <namespace>/.lock-<execution-key-digest>
//! <namespace>/<execution-key-digest>/result-v2
//! <namespace>/<execution-key-digest>/state-v2
//! <namespace>/.staged-<execution-key-digest>/...
//! <namespace>/.retired-<execution-key-digest>/...
//! ```
//!
//! The result contains the complete typed observation/finding closure. State
//! binds its hash and exact publication IDs to the lineage, attempt, and
//! versioned execution scope. State is published last. A visible directory
//! without both authenticated files is incomplete and fails closed; recovery
//! must inspect the operational ledger before deciding whether such a pre-stage
//! orphan may be removed.
//!
//! ```text
//! state-v2 := magic, key-digest, lineage, attempt, scope, execution,
//!             payload-limit, observation, measurement-evidence-count,
//!             measurement-evidence-set-hash, finding-present, [finding],
//!             payload-length, payload-hash, state-checksum
//! result-v2 := prepared-semantic-attempt-result-v6
//! ```
//!
//! State is bounded at 16 KiB. The result has both the format ceiling and the
//! smaller operational ceiling authenticated in state. Runtime opens accept
//! only the current v2 file pair; legacy conversion is an explicit offline
//! operation.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crucible_campaign::{
    AttemptExecutionScope, AttemptId, CampaignHash, CampaignLineageId, ExecutionId,
};

use crate::crucible_artifact::is_current_prepared_result_payload;
use crate::owned_advisory_lock::OwnedAdvisoryLock;
use crate::{
    AssignmentLedger, AssignmentLedgerError, AttemptExecutionKey, DirectoryAssignmentLedger,
    MAX_PREPARED_SEMANTIC_RESULT_BYTES, PreparedSemanticAttemptResult,
    PreparedSemanticResultCodecError,
};

const JOURNAL_LOCK_PREFIX: &str = ".lock-";
const JOURNAL_STAGED_PREFIX: &str = ".staged-";
const JOURNAL_RETIRED_PREFIX: &str = ".retired-";
const JOURNAL_RESULT_FILE: &str = "result-v2";
const JOURNAL_STATE_FILE: &str = "state-v2";
const JOURNAL_STATE_MAGIC_V2: &[u8] = b"crucible.executor.prepared-result-journal-state.v2\0";
const JOURNAL_STATE_HASH_DOMAIN_V2: &str = "crucible.executor.prepared-result-journal-state.v2";
const JOURNAL_MEASUREMENT_EVIDENCE_HASH_DOMAIN: &str =
    "crucible.executor.prepared-result-journal-measurement-evidence.v1";
const PREPARED_RESULT_LEDGER_BINDING_DOMAIN: &str =
    "crucible.executor.prepared-result-ledger-binding.v1";
const MAX_JOURNAL_STATE_BYTES: usize = 16 * 1024;
const MAX_ORPHAN_DIRECTORY_ENTRIES: usize = 4;

/// Outcome of idempotently creating one prepared-result journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedResultJournalCreateDisposition {
    /// This call durably created the exact journal.
    Created,
    /// The exact journal already existed and was reopened.
    Existing,
}

/// Bounded outcome of a ledger-authorized orphan cleanup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreparedResultJournalCleanupDisposition {
    /// Whether a pre-publication staging directory was removed.
    pub staged_removed: bool,
    /// Whether a post-retirement directory was removed.
    pub retired_removed: bool,
}

/// Bounded result of an explicit prepared-result journal migration.
#[derive(Debug)]
pub(crate) struct PreparedResultJournalMigrationSummary {
    /// Number of authenticated visible journals examined.
    pub journals: usize,
    /// Number of legacy journals converted or durably finalized.
    pub migrated: usize,
    /// Pinned durable prepared-result rewrite receipt.
    pub(crate) receipt: crate::operational_state_migration::receipt::PhaseReceipt,
}

/// Exclusive authenticated owner of one prepared semantic result journal.
#[derive(Debug)]
pub struct DirectoryPreparedResultJournal {
    root: PathBuf,
    namespace_guard: crate::anchored_fs::AnchoredDirectory,
    staged: bool,
    key: AttemptExecutionKey,
    execution: ExecutionId,
    maximum_payload_bytes: usize,
    prepared_result_digest: CampaignHash,
    result: PreparedSemanticAttemptResult,
    namespace_lock: OwnedAdvisoryLock,
}

impl DirectoryPreparedResultJournal {
    /// Creates or reopens the journal for `key` below `namespace`.
    ///
    /// `namespace` must already exist as an ordinary operator-owned directory.
    /// An existing journal is accepted only when its complete result equals
    /// `result` exactly.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when encoding, filesystem
    /// durability, locking, authentication, or exact replay validation fails.
    pub fn create(
        namespace: impl AsRef<Path>,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        maximum_payload_bytes: usize,
        result: PreparedSemanticAttemptResult,
    ) -> Result<(Self, PreparedResultJournalCreateDisposition), PreparedResultJournalError> {
        let (mut journal, disposition) =
            Self::prepare_staged(namespace, key, execution, maximum_payload_bytes, result)?;
        journal.commit_staged()?;
        Ok((journal, disposition))
    }

    /// Durably prepares a hidden journal without making it a recovery root.
    ///
    /// The caller must retain repository GC exclusion until [`Self::commit_staged`]
    /// succeeds after the matching operational publication-root transition.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when encoding, filesystem
    /// durability, locking, authentication, or exact replay validation fails.
    pub(crate) fn prepare_staged(
        namespace: impl AsRef<Path>,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        maximum_payload_bytes: usize,
        result: PreparedSemanticAttemptResult,
    ) -> Result<(Self, PreparedResultJournalCreateDisposition), PreparedResultJournalError> {
        let namespace_guard = open_runtime_namespace(namespace.as_ref())?;
        let namespace = namespace_guard.path().to_owned();
        let anchored_namespace = namespace_guard.anchored_path();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        validate_result_key(key, &result)?;
        reject_active_migration(&namespace_guard)?;
        let namespace_lock = acquire_namespace_lock(&anchored_namespace, key)?;
        reject_active_migration(&namespace_guard)?;
        let root = journal_path(&namespace, key);
        let anchored_root = journal_path(&anchored_namespace, key);
        if path_presence(&anchored_root, "inspect-journal-before-create")? {
            let journal = Self::open_locked(
                root,
                key,
                Some(execution),
                maximum_payload_bytes,
                namespace_lock,
                namespace_guard,
                false,
            )?;
            if journal.result != result {
                return Err(PreparedResultJournalError::ResultMismatch);
            }
            return Ok((journal, PreparedResultJournalCreateDisposition::Existing));
        }
        let staging = staged_path(&namespace, key);
        let anchored_staging = staged_path(&anchored_namespace, key);
        if path_presence(&anchored_staging, "inspect-staged-journal-before-create")? {
            let journal = Self::open_locked(
                staging,
                key,
                Some(execution),
                maximum_payload_bytes,
                namespace_lock,
                namespace_guard,
                true,
            )?;
            if journal.result != result {
                return Err(PreparedResultJournalError::ResultMismatch);
            }
            return Ok((journal, PreparedResultJournalCreateDisposition::Existing));
        }
        if path_presence(
            &retired_path(&anchored_namespace, key),
            "inspect-retired-journal-before-create",
        )? {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }

        let payload = result.canonical_bytes_with_limit(maximum_payload_bytes)?;
        let prepared_result_digest =
            CampaignHash::derive(PREPARED_RESULT_LEDGER_BINDING_DOMAIN, &payload);
        let state = encode_state(key, execution, maximum_payload_bytes, &result, &payload)?;
        let staging = staged_path(&namespace, key);
        namespace_guard
            .create_directory(&staging, "create-staged-journal")
            .map_err(migration_guard_error)?;
        namespace_guard
            .write_once(&staging.join(JOURNAL_RESULT_FILE), &payload)
            .map_err(migration_guard_error)?;
        namespace_guard
            .write_once(&staging.join(JOURNAL_STATE_FILE), &state)
            .map_err(migration_guard_error)?;
        Ok((
            Self {
                root: staging,
                namespace_guard,
                staged: true,
                key,
                execution,
                maximum_payload_bytes,
                prepared_result_digest,
                result,
                namespace_lock,
            },
            PreparedResultJournalCreateDisposition::Created,
        ))
    }

    /// Atomically promotes a durable staged journal into the recovery namespace.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when rename or parent-directory
    /// durability fails.
    pub(crate) fn commit_staged(&mut self) -> Result<(), PreparedResultJournalError> {
        reject_active_migration(&self.namespace_guard)?;
        if !self.staged {
            return Ok(());
        }
        let namespace = self
            .root
            .parent()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        let visible = journal_path(namespace, self.key);
        self.namespace_guard
            .rename_noreplace(&self.root, &visible, "publish-journal-directory")
            .map_err(migration_guard_error)?;
        self.root = visible;
        self.staged = false;
        Ok(())
    }

    /// Opens an authenticated hidden journal after the ledger proves Publishing.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] for invalid namespace, locking,
    /// authentication, or staged journal bytes.
    pub(crate) fn open_staged_for_recovery(
        namespace: impl AsRef<Path>,
        key: AttemptExecutionKey,
        maximum_payload_bytes: usize,
    ) -> Result<Option<Self>, PreparedResultJournalError> {
        let namespace_guard = open_runtime_namespace(namespace.as_ref())?;
        let namespace = namespace_guard.path().to_owned();
        let anchored_namespace = namespace_guard.anchored_path();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        reject_active_migration(&namespace_guard)?;
        let namespace_lock = acquire_namespace_lock(&anchored_namespace, key)?;
        let root = staged_path(&namespace, key);
        if !path_presence(
            &staged_path(&anchored_namespace, key),
            "inspect-staged-journal-for-recovery",
        )? {
            return Ok(None);
        }
        Self::open_locked(
            root,
            key,
            None,
            maximum_payload_bytes,
            namespace_lock,
            namespace_guard,
            true,
        )
        .map(Some)
    }

    /// Opens and authenticates the complete journal for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when the expected directory is
    /// incomplete, malformed, corrupt, locked, or bound to different result
    /// IDs or execution-key material.
    pub fn open(
        namespace: impl AsRef<Path>,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        maximum_payload_bytes: usize,
    ) -> Result<Self, PreparedResultJournalError> {
        let namespace_guard = open_runtime_namespace(namespace.as_ref())?;
        let namespace = namespace_guard.path().to_owned();
        let anchored_namespace = namespace_guard.anchored_path();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        reject_active_migration(&namespace_guard)?;
        let namespace_lock = acquire_namespace_lock(&anchored_namespace, key)?;
        let root = journal_path(&namespace, key);
        Self::open_locked(
            root,
            key,
            Some(execution),
            maximum_payload_bytes,
            namespace_lock,
            namespace_guard,
            false,
        )
    }

    /// Opens a complete journal without replacing its producer execution.
    ///
    /// This is the restart path used after the supervisor allocates a fresh
    /// process-local recovery execution. The execution authenticated in journal
    /// state remains available through [`Self::execution`] and is never
    /// rewritten. Absence is returned separately from malformed or incomplete
    /// journal state.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when the namespace, key, locking,
    /// journal authentication, or exact result validation fails.
    pub fn open_for_recovery(
        namespace: impl AsRef<Path>,
        key: AttemptExecutionKey,
        maximum_payload_bytes: usize,
    ) -> Result<Option<Self>, PreparedResultJournalError> {
        let namespace_guard = open_runtime_namespace(namespace.as_ref())?;
        let namespace = namespace_guard.path().to_owned();
        let anchored_namespace = namespace_guard.anchored_path();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        reject_active_migration(&namespace_guard)?;
        let namespace_lock = acquire_namespace_lock(&anchored_namespace, key)?;
        let root = journal_path(&namespace, key);
        if !path_presence(
            &journal_path(&anchored_namespace, key),
            "inspect-journal-for-recovery",
        )? {
            if path_presence(
                &staged_path(&anchored_namespace, key),
                "inspect-staged-journal-for-recovery",
            )? || path_presence(
                &retired_path(&anchored_namespace, key),
                "inspect-retired-journal-for-recovery",
            )? {
                return Err(PreparedResultJournalError::RecoveryRequired);
            }
            return Ok(None);
        }
        Self::open_locked(
            root,
            key,
            None,
            maximum_payload_bytes,
            namespace_lock,
            namespace_guard,
            false,
        )
        .map(Some)
    }

    /// Reports whether this key has a visible journal or interrupted transition.
    ///
    /// This inventory probe does not acquire the per-key journal lock. Callers
    /// must already exclude ledger writers and repository GC, and must use a
    /// locked open or cleanup operation before trusting or removing any bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when the namespace or key is
    /// invalid or any owned path cannot be inspected safely.
    pub(crate) fn artifacts_present(
        namespace: impl AsRef<Path>,
        key: AttemptExecutionKey,
    ) -> Result<bool, PreparedResultJournalError> {
        let namespace_guard = open_runtime_namespace(namespace.as_ref())?;
        let anchored_namespace = namespace_guard.anchored_path();
        validate_semantic_key(key)?;

        Ok(path_presence(
            &journal_path(&anchored_namespace, key),
            "inventory-prepared-result-journal",
        )? || path_presence(
            &staged_path(&anchored_namespace, key),
            "inventory-staged-prepared-result-journal",
        )? || path_presence(
            &retired_path(&anchored_namespace, key),
            "inventory-retired-prepared-result-journal",
        )?)
    }

    fn open_locked(
        root: PathBuf,
        key: AttemptExecutionKey,
        expected_execution: Option<ExecutionId>,
        maximum_payload_bytes: usize,
        namespace_lock: OwnedAdvisoryLock,
        namespace_guard: crate::anchored_fs::AnchoredDirectory,
        staged: bool,
    ) -> Result<Self, PreparedResultJournalError> {
        reject_active_migration(&namespace_guard)?;
        let root_guard = namespace_guard
            .open_child(&root, "open-current-journal")
            .map_err(migration_guard_error)?;
        root_guard.sync().map_err(migration_guard_error)?;
        namespace_guard.sync().map_err(migration_guard_error)?;

        let (state_file, result_file) = journal_files(&root_guard.anchored_path())?;
        let state = read_bounded_anchored_file(
            &root_guard,
            state_file,
            MAX_JOURNAL_STATE_BYTES,
            "read-journal-state",
        )?;
        let envelope = decode_state(&state, key, expected_execution, maximum_payload_bytes)?;
        let payload = read_bounded_anchored_file(
            &root_guard,
            result_file,
            maximum_payload_bytes,
            "read-journal-result",
        )?;
        envelope.validate_payload(&payload)?;
        if !is_current_prepared_result_payload(&payload) {
            return Err(PreparedResultJournalError::InvalidState);
        }
        let result = PreparedSemanticAttemptResult::from_canonical_bytes_with_limit(
            &payload,
            maximum_payload_bytes,
        )?;
        envelope.validate_result(&result)?;
        validate_result_key(key, &result)?;

        Ok(Self {
            root,
            namespace_guard,
            staged,
            key,
            execution: envelope.execution,
            maximum_payload_bytes,
            prepared_result_digest: CampaignHash::derive(
                PREPARED_RESULT_LEDGER_BINDING_DOMAIN,
                &payload,
            ),
            result,
            namespace_lock,
        })
    }

    /// Returns the exact journal directory selected by the scoped key.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the exact lineage, attempt, and execution-scope key.
    #[must_use]
    pub const fn key(&self) -> AttemptExecutionKey {
        self.key
    }

    /// Returns the exact local execution incarnation that produced the result.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the operational encoded-payload ceiling bound into state.
    #[must_use]
    pub const fn maximum_payload_bytes(&self) -> usize {
        self.maximum_payload_bytes
    }

    /// Returns the authenticated full-payload digest bound into the ledger.
    #[must_use]
    pub const fn prepared_result_digest(&self) -> CampaignHash {
        self.prepared_result_digest
    }

    /// Returns the complete prepared publication value.
    #[must_use]
    pub const fn result(&self) -> &PreparedSemanticAttemptResult {
        &self.result
    }

    /// Consumes the journal owner and returns the prepared result while leaving
    /// its durable files in place.
    #[must_use]
    pub fn into_result(self) -> PreparedSemanticAttemptResult {
        self.result
    }

    /// Deletes this journal after the operational ledger proves it is no longer
    /// needed for publication recovery.
    ///
    /// Removal occurs while the journal lock is held. The parent directory is
    /// synced after the name disappears.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] if a file or directory cannot be
    /// removed or the parent cannot be synced. The caller must treat an error as
    /// indeterminate cleanup and retry without rerunning guest execution.
    pub fn remove(&self) -> Result<(), PreparedResultJournalError> {
        let _held_lock = &self.namespace_lock;
        reject_active_migration(&self.namespace_guard)?;
        let namespace = self
            .root
            .parent()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        if self.staged {
            remove_orphan_directory(&self.namespace_guard, &self.root)?;
            return Ok(());
        }
        let tombstone = retired_path(namespace, self.key);
        let anchored_root = self
            .namespace_guard
            .anchored_path_for(&self.root)
            .map_err(migration_guard_error)?;
        let anchored_tombstone = self
            .namespace_guard
            .anchored_path_for(&tombstone)
            .map_err(migration_guard_error)?;
        let root_present = path_presence(&anchored_root, "inspect-journal-before-retire")?;
        let tombstone_present = path_presence(&anchored_tombstone, "inspect-retired-journal")?;
        match (root_present, tombstone_present) {
            (true, false) => {
                self.namespace_guard
                    .rename_noreplace(&self.root, &tombstone, "retire-journal-directory")
                    .map_err(migration_guard_error)?;
            }
            (false, true) | (false, false) => {}
            (true, true) => return Err(PreparedResultJournalError::RecoveryRequired),
        }
        reject_active_migration(&self.namespace_guard)?;
        remove_orphan_directory(&self.namespace_guard, &tombstone)?;
        Ok(())
    }

    /// Removes at most the fixed staged and retired orphans for `key`.
    ///
    /// The caller must first acquire the production repository-GC and ledger
    /// exclusions, prove that `key` has no result requiring recovery, and retain
    /// those exclusions through this call. An active publication may already
    /// hold this key's journal lock while it enters repository or ledger code,
    /// so namespace acquisition is nonblocking. Contention returns an I/O error;
    /// callers must release outer fences before retrying.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] for an invalid key or namespace,
    /// lock contention, unexpected orphan contents, or failed durable removal.
    pub fn cleanup_orphans_after_ledger_check(
        namespace: impl AsRef<Path>,
        key: AttemptExecutionKey,
    ) -> Result<PreparedResultJournalCleanupDisposition, PreparedResultJournalError> {
        let namespace_guard = open_runtime_namespace(namespace.as_ref())?;
        let namespace = namespace_guard.anchored_path();
        let namespace = namespace.as_path();
        validate_semantic_key(key)?;
        reject_active_migration(&namespace_guard)?;
        let namespace_lock = acquire_namespace_lock(namespace, key)?;
        reject_active_migration(&namespace_guard)?;
        if journal_path(namespace, key).exists() {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }

        let staged_removed =
            remove_orphan_directory(&namespace_guard, &staged_path(namespace, key))?;
        reject_active_migration(&namespace_guard)?;
        let retired_removed =
            remove_orphan_directory(&namespace_guard, &retired_path(namespace, key))?;
        drop(namespace_lock);
        Ok(PreparedResultJournalCleanupDisposition {
            staged_removed,
            retired_removed,
        })
    }
}

/// Converts every legacy prepared-result journal in an offline namespace.
///
/// The caller must retain the assignment ledger's exclusive writer lock. This
/// function acquires per-key namespace locks in sorted key order, authenticates
/// the complete bounded inventory before staging anything, and rewrites each
/// journal through pinned files. A rerun completes an interrupted rewrite.
///
/// # Errors
///
/// Returns [`PreparedResultJournalError`] when the namespace is invalid, its
/// inventory exceeds `maximum_entries`, a journal or ledger binding is
/// invalid, a per-key lock is held, or durable conversion fails.
pub(crate) fn migrate_prepared_result_journals(
    namespace: &crate::anchored_fs::AnchoredDirectory,
    receipt_directory: &crate::anchored_fs::AnchoredDirectory,
    ledger: &mut DirectoryAssignmentLedger,
    maximum_entries: usize,
    maximum_payload_bytes: usize,
) -> Result<PreparedResultJournalMigrationSummary, crate::OperationalStateMigrationError> {
    migration::migrate_prepared_result_journals(
        namespace,
        receipt_directory,
        ledger,
        maximum_entries,
        maximum_payload_bytes,
    )
}

/// Failure to persist, reopen, authenticate, or remove a prepared result.
#[derive(Debug, Error)]
pub enum PreparedResultJournalError {
    /// A filesystem operation failed.
    #[error("prepared-result journal {operation} failed for {path}")]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Affected journal path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: io::Error,
    },
    /// The result codec rejected nested immutable records.
    #[error(transparent)]
    Result(#[from] PreparedSemanticResultCodecError),
    /// The namespace is absent or is not an ordinary directory.
    #[error("prepared-result journal namespace is not an ordinary directory")]
    InvalidNamespace,
    /// The journal path is absent or is not an ordinary directory.
    #[error("prepared-result journal path is not an ordinary directory")]
    InvalidDirectory,
    /// Initial publication did not complete.
    #[error("prepared-result journal is incomplete")]
    Incomplete,
    /// State does not authenticate the scoped key, result IDs, length, or hash.
    #[error("prepared-result journal state is invalid")]
    InvalidState,
    /// An existing journal retains a different prepared result.
    #[error("prepared-result journal retains a different result")]
    ResultMismatch,
    /// A fixed staging or retirement name requires ledger-authorized recovery.
    #[error("prepared-result journal requires ledger-authorized orphan recovery")]
    RecoveryRequired,
    /// The observation belongs to a different admitted attempt than the key.
    #[error("prepared-result journal observation attempt does not match its execution key")]
    AttemptMismatch,
    /// This journal accepts semantic attempt execution only.
    #[error("prepared-result journal key is not semantic execution")]
    NonSemanticKey,
    /// The operational payload ceiling is zero or exceeds the format ceiling.
    #[error("prepared-result journal payload limit is invalid")]
    InvalidPayloadLimit,
    /// The bounded migration inventory contains too many journals.
    #[error("prepared-result journal migration limit exceeded")]
    MigrationLimitExceeded,
    /// The assignment ledger could not authenticate a journal binding.
    #[error(transparent)]
    Ledger(#[from] AssignmentLedgerError),
}

fn journal_path(namespace: &Path, key: AttemptExecutionKey) -> PathBuf {
    namespace.join(hex(key.storage_digest().as_bytes()))
}

fn namespace_lock_path(namespace: &Path, key: AttemptExecutionKey) -> PathBuf {
    namespace.join(format!(
        "{JOURNAL_LOCK_PREFIX}{}",
        hex(key.storage_digest().as_bytes())
    ))
}

fn staged_path(namespace: &Path, key: AttemptExecutionKey) -> PathBuf {
    namespace.join(format!(
        "{JOURNAL_STAGED_PREFIX}{}",
        hex(key.storage_digest().as_bytes())
    ))
}

fn retired_path(namespace: &Path, key: AttemptExecutionKey) -> PathBuf {
    namespace.join(format!(
        "{JOURNAL_RETIRED_PREFIX}{}",
        hex(key.storage_digest().as_bytes())
    ))
}

fn encode_state(
    key: AttemptExecutionKey,
    execution: ExecutionId,
    maximum_payload_bytes: usize,
    result: &PreparedSemanticAttemptResult,
    payload: &[u8],
) -> Result<Vec<u8>, PreparedResultJournalError> {
    let observation = result
        .observation()
        .observation()
        .id()
        .map_err(PreparedSemanticResultCodecError::from)?;
    let finding = result
        .finding()
        .map(|finding| finding.id().map_err(PreparedSemanticResultCodecError::from))
        .transpose()?;
    let (measurement_evidence_count, measurement_evidence_hash) =
        measurement_evidence_identity(result)?;
    let mut state = Vec::new();
    state.extend_from_slice(JOURNAL_STATE_MAGIC_V2);
    state.extend_from_slice(&key.storage_digest().as_bytes());
    push_text(&mut state, &key.lineage().content_id().encode())?;
    push_text(&mut state, &key.attempt().content_id().encode())?;
    push_bytes(&mut state, &key.scope().canonical_bytes())?;
    state.extend_from_slice(&execution.as_bytes());
    state.extend_from_slice(
        &u64::try_from(maximum_payload_bytes)
            .map_err(|_| PreparedResultJournalError::InvalidPayloadLimit)?
            .to_be_bytes(),
    );
    push_text(&mut state, &observation.content_id().encode())?;
    state.extend_from_slice(
        &u64::try_from(measurement_evidence_count)
            .map_err(|_| PreparedResultJournalError::InvalidState)?
            .to_be_bytes(),
    );
    state.extend_from_slice(&measurement_evidence_hash);
    match finding {
        Some(finding) => {
            state.push(1);
            push_text(&mut state, &finding.content_id().encode())?;
        }
        None => state.push(0),
    }
    state.extend_from_slice(
        &u64::try_from(payload.len())
            .map_err(|_| PreparedResultJournalError::InvalidState)?
            .to_be_bytes(),
    );
    state.extend_from_slice(blake3::hash(payload).as_bytes());
    let checksum_key = blake3::derive_key(JOURNAL_STATE_HASH_DOMAIN_V2, JOURNAL_STATE_MAGIC_V2);
    let checksum = blake3::keyed_hash(&checksum_key, &state);
    state.extend_from_slice(checksum.as_bytes());
    if state.len() > MAX_JOURNAL_STATE_BYTES {
        return Err(PreparedResultJournalError::InvalidState);
    }
    Ok(state)
}

struct JournalStateEnvelope<'a> {
    execution: ExecutionId,
    observation: &'a [u8],
    measurement_evidence: Option<(usize, [u8; 32])>,
    finding: Option<&'a [u8]>,
    payload_length: usize,
    payload_hash: [u8; 32],
}

impl JournalStateEnvelope<'_> {
    fn validate_payload(&self, payload: &[u8]) -> Result<(), PreparedResultJournalError> {
        if payload.len() != self.payload_length
            || blake3::hash(payload).as_bytes() != &self.payload_hash
        {
            return Err(PreparedResultJournalError::InvalidState);
        }
        Ok(())
    }

    fn validate_result(
        &self,
        result: &PreparedSemanticAttemptResult,
    ) -> Result<(), PreparedResultJournalError> {
        let observation = result
            .observation()
            .observation()
            .id()
            .map_err(PreparedSemanticResultCodecError::from)?;
        if self.observation != observation.content_id().encode().as_bytes() {
            return Err(PreparedResultJournalError::InvalidState);
        }

        let actual_measurement_evidence = measurement_evidence_identity(result)?;
        match self.measurement_evidence {
            Some(expected) if expected != actual_measurement_evidence => {
                return Err(PreparedResultJournalError::InvalidState);
            }
            None if actual_measurement_evidence.0 != 0 => {
                return Err(PreparedResultJournalError::InvalidState);
            }
            _ => {}
        }

        let finding = result
            .finding()
            .map(|finding| {
                finding
                    .id()
                    .map(|id| id.content_id().encode())
                    .map_err(PreparedSemanticResultCodecError::from)
            })
            .transpose()?;
        if self.finding != finding.as_deref().map(str::as_bytes) {
            return Err(PreparedResultJournalError::InvalidState);
        }
        Ok(())
    }
}

fn decode_state<'a>(
    state: &'a [u8],
    key: AttemptExecutionKey,
    expected_execution: Option<ExecutionId>,
    maximum_payload_bytes: usize,
) -> Result<JournalStateEnvelope<'a>, PreparedResultJournalError> {
    let checksum_offset = state
        .len()
        .checked_sub(32)
        .ok_or(PreparedResultJournalError::InvalidState)?;
    let (body, checksum) = state.split_at(checksum_offset);
    let checksum_key = blake3::derive_key(JOURNAL_STATE_HASH_DOMAIN_V2, JOURNAL_STATE_MAGIC_V2);
    if blake3::keyed_hash(&checksum_key, body).as_bytes() != checksum {
        return Err(PreparedResultJournalError::InvalidState);
    }

    let mut decoder = JournalStateDecoder::new(body);
    decoder.expect_exact(JOURNAL_STATE_MAGIC_V2)?;
    decoder.expect_exact(key.storage_digest().as_bytes().as_slice())?;
    decoder.expect_bytes(key.lineage().content_id().encode().as_bytes())?;
    decoder.expect_bytes(key.attempt().content_id().encode().as_bytes())?;
    decoder.expect_bytes(&key.scope().canonical_bytes())?;
    let execution_bytes: [u8; 16] = decoder
        .take(16)?
        .try_into()
        .map_err(|_| PreparedResultJournalError::InvalidState)?;
    let execution = ExecutionId::from_bytes(execution_bytes)
        .map_err(|_| PreparedResultJournalError::InvalidState)?;
    if expected_execution.is_some_and(|expected| expected != execution) {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let expected_payload_limit = u64::try_from(maximum_payload_bytes)
        .map_err(|_| PreparedResultJournalError::InvalidPayloadLimit)?;
    if decoder.u64()? != expected_payload_limit {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let observation = decoder.bytes()?;
    let count =
        usize::try_from(decoder.u64()?).map_err(|_| PreparedResultJournalError::InvalidState)?;
    let hash = decoder
        .take(32)?
        .try_into()
        .map_err(|_| PreparedResultJournalError::InvalidState)?;
    let measurement_evidence = Some((count, hash));
    let finding = match decoder.byte()? {
        0 => None,
        1 => Some(decoder.bytes()?),
        _ => return Err(PreparedResultJournalError::InvalidState),
    };
    let payload_length =
        usize::try_from(decoder.u64()?).map_err(|_| PreparedResultJournalError::InvalidState)?;
    if payload_length > maximum_payload_bytes {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let payload_hash = decoder
        .take(32)?
        .try_into()
        .map_err(|_| PreparedResultJournalError::InvalidState)?;
    decoder.finish()?;

    Ok(JournalStateEnvelope {
        execution,
        observation,
        measurement_evidence,
        finding,
        payload_length,
        payload_hash,
    })
}

fn journal_files(root: &Path) -> Result<(&'static str, &'static str), PreparedResultJournalError> {
    let mut state = false;
    let mut result = false;
    for entry in fs::read_dir(root)
        .map_err(|source| io_error("read-current-journal-directory", root, source))?
    {
        let entry = entry
            .map_err(|source| io_error("read-current-journal-directory-entry", root, source))?;
        if !entry
            .file_type()
            .map_err(|source| io_error("stat-current-journal-entry", &entry.path(), source))?
            .is_file()
        {
            return Err(PreparedResultJournalError::Incomplete);
        }
        let name = entry.file_name();
        match name.to_str() {
            Some(JOURNAL_STATE_FILE) if !state => state = true,
            Some(JOURNAL_RESULT_FILE) if !result => result = true,
            _ => return Err(PreparedResultJournalError::Incomplete),
        }
    }
    if state && result {
        Ok((JOURNAL_STATE_FILE, JOURNAL_RESULT_FILE))
    } else {
        Err(PreparedResultJournalError::Incomplete)
    }
}

fn measurement_evidence_identity(
    result: &PreparedSemanticAttemptResult,
) -> Result<(usize, [u8; 32]), PreparedResultJournalError> {
    let mut hasher = blake3::Hasher::new_derive_key(JOURNAL_MEASUREMENT_EVIDENCE_HASH_DOMAIN);
    for evidence in result.measurement_replay_evidence() {
        let id = evidence
            .id()
            .map_err(PreparedSemanticResultCodecError::from)?;
        let encoded = id.encode();
        hasher.update(&(encoded.len() as u64).to_be_bytes());
        hasher.update(encoded.as_bytes());
    }
    Ok((
        result.measurement_replay_evidence().len(),
        *hasher.finalize().as_bytes(),
    ))
}

struct JournalStateDecoder<'a> {
    remaining: &'a [u8],
}

impl<'a> JournalStateDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn finish(self) -> Result<(), PreparedResultJournalError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(PreparedResultJournalError::InvalidState)
        }
    }

    fn expect_exact(&mut self, expected: &[u8]) -> Result<(), PreparedResultJournalError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(PreparedResultJournalError::InvalidState)
        }
    }

    fn expect_bytes(&mut self, expected: &[u8]) -> Result<(), PreparedResultJournalError> {
        if self.bytes()? == expected {
            Ok(())
        } else {
            Err(PreparedResultJournalError::InvalidState)
        }
    }

    fn byte(&mut self) -> Result<u8, PreparedResultJournalError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, PreparedResultJournalError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| PreparedResultJournalError::InvalidState)?,
        ))
    }

    fn bytes(&mut self) -> Result<&'a [u8], PreparedResultJournalError> {
        let length = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PreparedResultJournalError::InvalidState)?,
        ) as usize;
        self.take(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PreparedResultJournalError> {
        if self.remaining.len() < length {
            return Err(PreparedResultJournalError::InvalidState);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }
}

fn push_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), PreparedResultJournalError> {
    push_bytes(bytes, value.as_bytes())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), PreparedResultJournalError> {
    let length =
        u32::try_from(value.len()).map_err(|_| PreparedResultJournalError::InvalidState)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn validate_semantic_key(key: AttemptExecutionKey) -> Result<(), PreparedResultJournalError> {
    if key.scope() == AttemptExecutionScope::Semantic {
        Ok(())
    } else {
        Err(PreparedResultJournalError::NonSemanticKey)
    }
}

fn validate_result_key(
    key: AttemptExecutionKey,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), PreparedResultJournalError> {
    if result.observation().observation().attempt() == key.attempt() {
        Ok(())
    } else {
        Err(PreparedResultJournalError::AttemptMismatch)
    }
}

fn validate_payload_limit(maximum: usize) -> Result<usize, PreparedResultJournalError> {
    if maximum == 0 || maximum > MAX_PREPARED_SEMANTIC_RESULT_BYTES {
        Err(PreparedResultJournalError::InvalidPayloadLimit)
    } else {
        Ok(maximum)
    }
}

fn path_presence(path: &Path, operation: &'static str) -> Result<bool, PreparedResultJournalError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(operation, path, source)),
    }
}

fn remove_orphan_directory(
    namespace: &crate::anchored_fs::AnchoredDirectory,
    root: &Path,
) -> Result<bool, PreparedResultJournalError> {
    let anchored_root = namespace
        .anchored_path_for(root)
        .map_err(migration_guard_error)?;
    match fs::symlink_metadata(&anchored_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(PreparedResultJournalError::InvalidDirectory),
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(io_error("inspect-journal-orphan", &anchored_root, source)),
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(&anchored_root)
        .map_err(|source| io_error("read-journal-orphan", &anchored_root, source))?
        .take(MAX_ORPHAN_DIRECTORY_ENTRIES + 1)
    {
        let entry = entry.map_err(|source| io_error("read-journal-orphan", root, source))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        if entries.len() == MAX_ORPHAN_DIRECTORY_ENTRIES || !is_owned_orphan_file(name) {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        entries.push(entry.path());
    }
    for entry in entries {
        let relative_name = entry
            .file_name()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?
            .to_owned();
        namespace
            .remove_file_if_present(&root.join(relative_name), "remove-journal-orphan-file")
            .map_err(migration_guard_error)?;
    }
    namespace
        .remove_directory_if_present(root, "remove-journal-directory")
        .map_err(migration_guard_error)
}

fn is_owned_orphan_file(name: &str) -> bool {
    name == JOURNAL_STATE_FILE
        || name == JOURNAL_RESULT_FILE
        || name == "lock"
        || name.starts_with(&format!(".{JOURNAL_STATE_FILE}."))
        || name.starts_with(&format!(".{JOURNAL_RESULT_FILE}."))
}

fn read_bounded_anchored_file(
    root: &crate::anchored_fs::AnchoredDirectory,
    name: &str,
    maximum: usize,
    operation: &'static str,
) -> Result<Vec<u8>, PreparedResultJournalError> {
    let path = root.path().join(name);
    root.open_regular_optional(&path, operation)
        .map_err(migration_guard_error)?
        .ok_or(PreparedResultJournalError::Incomplete)?
        .read_bounded(maximum as u64)
        .map_err(migration_guard_error)
}

fn acquire_namespace_lock(
    namespace: &Path,
    key: AttemptExecutionKey,
) -> Result<OwnedAdvisoryLock, PreparedResultJournalError> {
    let path = namespace_lock_path(namespace, key);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| io_error("open-journal-namespace-lock", &path, source))?;
    lock_exclusive(lock, &path)
}

fn lock_exclusive(
    lock: File,
    path: &Path,
) -> Result<OwnedAdvisoryLock, PreparedResultJournalError> {
    OwnedAdvisoryLock::try_exclusive(lock)
        .map_err(|source| io_error("lock-journal-namespace", path, io::Error::from(source)))
}

fn validate_namespace(path: &Path) -> Result<(), PreparedResultJournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(PreparedResultJournalError::InvalidNamespace),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            Err(PreparedResultJournalError::InvalidNamespace)
        }
        Err(source) => Err(io_error("inspect-journal-namespace", path, source)),
    }
}

fn open_runtime_namespace(
    path: &Path,
) -> Result<crate::anchored_fs::AnchoredDirectory, PreparedResultJournalError> {
    validate_namespace(path)?;
    let namespace = crate::anchored_fs::AnchoredDirectory::new(path.to_owned())
        .map_err(migration_guard_error)?;
    reject_runtime_migration_state(&namespace)?;
    Ok(namespace)
}

fn reject_active_migration(
    namespace: &crate::anchored_fs::AnchoredDirectory,
) -> Result<(), PreparedResultJournalError> {
    if crate::operational_state_migration::receipt::marker_present_guarded(namespace).map_err(
        |source| {
            io_error(
                "inspect-operational-state-migration",
                namespace.path(),
                source,
            )
        },
    )? {
        Err(PreparedResultJournalError::RecoveryRequired)
    } else {
        Ok(())
    }
}

fn reject_runtime_migration_state(
    namespace: &crate::anchored_fs::AnchoredDirectory,
) -> Result<(), PreparedResultJournalError> {
    reject_active_migration(namespace)?;
    reject_unfenced_migration_entries(namespace)
}

fn migration_guard_error(error: crate::anchored_fs::AnchoredFsError) -> PreparedResultJournalError {
    let (operation, path, source) = error.into_io_parts("guard-prepared-result-namespace");
    io_error(operation, &path, source)
}

fn reject_unfenced_migration_entries(
    namespace: &crate::anchored_fs::AnchoredDirectory,
) -> Result<(), PreparedResultJournalError> {
    let anchored_namespace = namespace.anchored_path();
    let mut entries = 0usize;
    let mut bytes = 0u64;
    for entry in fs::read_dir(&anchored_namespace).map_err(|source| {
        io_error(
            "read-runtime-journal-namespace",
            &anchored_namespace,
            source,
        )
    })? {
        let entry = entry.map_err(|source| {
            io_error(
                "read-runtime-journal-namespace-entry",
                &anchored_namespace,
                source,
            )
        })?;
        admit_runtime_entry(&mut entries, &mut bytes, &entry.path())?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| io_error("stat-runtime-journal-entry", &entry.path(), source))?;
        let file_type = metadata.file_type();
        if name == crate::operational_state_migration::receipt::ACTIVE_MARKER {
            if !file_type.is_file() {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            continue;
        }
        if name.starts_with(JOURNAL_LOCK_PREFIX) {
            if !name
                .strip_prefix(JOURNAL_LOCK_PREFIX)
                .is_some_and(|name| is_lower_hex(name, 64))
                || !file_type.is_file()
            {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            continue;
        }
        if name.starts_with(JOURNAL_STAGED_PREFIX) || name.starts_with(JOURNAL_RETIRED_PREFIX) {
            let key = name
                .strip_prefix(JOURNAL_STAGED_PREFIX)
                .or_else(|| name.strip_prefix(JOURNAL_RETIRED_PREFIX));
            if !key.is_some_and(|name| is_lower_hex(name, 64)) || !file_type.is_dir() {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            let root = namespace
                .open_child(&entry.path(), "open-runtime-journal-orphan")
                .map_err(migration_guard_error)?;
            inspect_runtime_journal_directory(&root, true, &mut entries, &mut bytes)?;
            continue;
        }
        if !is_lower_hex(name, 64) || !file_type.is_dir() {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        let root = namespace
            .open_child(&entry.path(), "open-runtime-journal")
            .map_err(migration_guard_error)?;
        inspect_runtime_journal_directory(&root, false, &mut entries, &mut bytes)
            .map_err(|_| PreparedResultJournalError::RecoveryRequired)?;
    }
    Ok(())
}

fn inspect_runtime_journal_directory(
    root: &crate::anchored_fs::AnchoredDirectory,
    orphan: bool,
    entries: &mut usize,
    bytes: &mut u64,
) -> Result<(), PreparedResultJournalError> {
    let anchored = root.anchored_path();
    let mut state = false;
    let mut result = false;
    for entry in fs::read_dir(&anchored)
        .map_err(|source| io_error("read-runtime-journal", &anchored, source))?
    {
        let entry =
            entry.map_err(|source| io_error("read-runtime-journal-entry", &anchored, source))?;
        admit_runtime_entry(entries, bytes, &entry.path())?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| io_error("stat-runtime-journal-file", &entry.path(), source))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?
            .to_owned();
        if !metadata.file_type().is_file()
            || metadata.len() > runtime_journal_file_limit(&name) as u64
        {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        match name.as_str() {
            JOURNAL_STATE_FILE if !state => state = true,
            JOURNAL_RESULT_FILE if !result => result = true,
            name if orphan && is_owned_orphan_file(name) => {}
            _ => return Err(PreparedResultJournalError::InvalidDirectory),
        }
    }
    if !orphan && !(state && result) {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    Ok(())
}

fn admit_runtime_entry(
    entries: &mut usize,
    bytes: &mut u64,
    path: &Path,
) -> Result<(), PreparedResultJournalError> {
    *entries = entries
        .checked_add(1)
        .ok_or(PreparedResultJournalError::RecoveryRequired)?;
    if *entries > crate::operational_state_migration::MAX_OPERATIONAL_STATE_MIGRATION_ENTRIES {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("bound-runtime-journal-entry", path, source))?;
    *bytes = bytes
        .checked_add(metadata.len())
        .ok_or(PreparedResultJournalError::RecoveryRequired)?;
    let maximum = crate::operational_state_migration::MAX_OPERATIONAL_STATE_MIGRATION_ENTRIES
        as u64
        * (MAX_PREPARED_SEMANTIC_RESULT_BYTES as u64 + MAX_JOURNAL_STATE_BYTES as u64);
    if *bytes > maximum {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    Ok(())
}

fn runtime_journal_file_limit(name: &str) -> usize {
    if name == JOURNAL_RESULT_FILE || name.starts_with(&format!(".{JOURNAL_RESULT_FILE}.")) {
        MAX_PREPARED_SEMANTIC_RESULT_BYTES
    } else {
        MAX_JOURNAL_STATE_BYTES
    }
}

#[cfg(test)]
fn sync_directory(path: &Path, operation: &'static str) -> Result<(), PreparedResultJournalError> {
    let directory = File::open(path).map_err(|source| io_error(operation, path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error(operation, path, source))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> PreparedResultJournalError {
    PreparedResultJournalError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn hex(bytes: [u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(DIGITS[(byte >> 4) as usize]));
        encoded.push(char::from(DIGITS[(byte & 0x0f) as usize]));
    }
    encoded
}

mod migration;

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- journal tests use panic shortcuts for precise fixture failures.
    #![allow(clippy::expect_used)]

    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, symlink};

    use crucible_campaign::{
        AttemptExecutionScope, AttemptId, BranchPathId, CampaignFactId, CampaignHash,
        CampaignLineageId, ConfigurationArtifact, ConfigurationId, CoverageProjection, DaemonEpoch,
        ExecutionId, MeasurementSet, Observation, ObservationCandidate, PropertyVerdictSet,
        ScenarioArtifactId, ScenarioDefId, StopOutcome,
    };
    use crucible_cas::content_store::{ContentId, ObjectKind};
    use tempfile::TempDir;

    use crate::{
        AttemptExecutionOrigin, AttemptRuntimeState, AttemptStateCas, DirectoryAssignmentLedger,
    };

    use super::*;

    const TEST_PAYLOAD_LIMIT: usize = 1024 * 1024;

    struct LegacyJournalFixture {
        _ledger_root: TempDir,
        namespace: TempDir,
        ledger: DirectoryAssignmentLedger,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        result: PreparedSemanticAttemptResult,
    }

    impl LegacyJournalFixture {
        fn migrate(
            &mut self,
        ) -> Result<PreparedResultJournalMigrationSummary, crate::OperationalStateMigrationError>
        {
            let receipt_parent = TempDir::new().expect("receipt parent");
            let receipt = receipt_parent.path().join("receipt");
            let receipt_guard =
                crate::operational_state_migration::receipt::prepare_receipt_directory(&receipt)?;
            let namespace_guard =
                crate::anchored_fs::AnchoredDirectory::new(self.namespace.path().to_owned())?;
            migrate_prepared_result_journals(
                &namespace_guard,
                &receipt_guard,
                &mut self.ledger,
                16,
                TEST_PAYLOAD_LIMIT,
            )
        }

        fn open(&self) -> Result<DirectoryPreparedResultJournal, PreparedResultJournalError> {
            DirectoryPreparedResultJournal::open(
                self.namespace.path(),
                self.key,
                self.execution,
                TEST_PAYLOAD_LIMIT,
            )
        }
    }

    fn legacy_journal_fixture(marker: u8) -> LegacyJournalFixture {
        let ledger_root = TempDir::new().expect("ledger root");
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(&[marker]);
        let execution = ExecutionId::from_bytes([marker; 16]).expect("execution");
        let result = observation_result(marker.wrapping_add(1), key.attempt());
        let observation = result
            .observation()
            .observation()
            .id()
            .expect("observation ID");
        let state = AttemptRuntimeState::Publishing {
            execution_basis: CampaignHash::derive("test.execution-basis.v1", &[marker]),
            origin: AttemptExecutionOrigin::Initial,
            daemon_epoch: DaemonEpoch::from_bytes([marker.wrapping_add(2); 16])
                .expect("daemon epoch"),
            execution,
            observation,
            finding_candidate: None,
            finding_replay_captures: None,
            finding_exact_retention_roots: [None; 3],
            prepared_result_digest: None,
        };
        let mut ledger = DirectoryAssignmentLedger::open(ledger_root.path()).expect("ledger");
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, None, Some(state))
                .expect("publish ledger state"),
            AttemptStateCas::Advanced
        );
        migration::write_legacy_journal_for_test(
            namespace.path(),
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            &result,
        )
        .expect("legacy journal");
        LegacyJournalFixture {
            _ledger_root: ledger_root,
            namespace,
            ledger,
            key,
            execution,
            result,
        }
    }

    #[test]
    fn legacy_journal_requires_explicit_migration_before_runtime_open() {
        let mut fixture = legacy_journal_fixture(0x61);

        assert!(matches!(
            fixture.open(),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));
        let other_key = semantic_key(b"other-runtime-key");
        assert!(matches!(
            DirectoryPreparedResultJournal::prepare_staged(
                fixture.namespace.path(),
                other_key,
                ExecutionId::from_bytes([0x62; 16]).expect("other execution"),
                TEST_PAYLOAD_LIMIT,
                observation_result(0x63, other_key.attempt()),
            ),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));

        let summary = fixture.migrate().expect("migrate journal");
        assert_eq!(summary.journals, 1);
        assert_eq!(summary.migrated, 1);
        assert_eq!(summary.receipt.id.len(), 64);
        let journal = fixture.open().expect("open migrated journal");
        assert_eq!(journal.result(), &fixture.result);
    }

    #[test]
    fn legacy_semantic_payload_rewrite_resumes_after_every_file_cut() {
        for (marker, cut) in (0x69..=0x70).zip(0..=7) {
            let mut fixture = legacy_journal_fixture(marker);
            fixture.migrate().expect("migrate journal file pair");
            let root = journal_path(fixture.namespace.path(), fixture.key);
            let legacy_payload = crate::crucible_artifact::encode_version_for_test(
                &fixture.result,
                2,
                TEST_PAYLOAD_LIMIT,
            )
            .expect("encode legacy semantic payload");
            let legacy_state = encode_state(
                fixture.key,
                fixture.execution,
                TEST_PAYLOAD_LIMIT,
                &fixture.result,
                &legacy_payload,
            )
            .expect("encode legacy semantic state");
            fs::write(root.join(JOURNAL_RESULT_FILE), &legacy_payload)
                .expect("write legacy payload");
            fs::write(root.join(JOURNAL_STATE_FILE), &legacy_state).expect("write legacy state");

            let receipt_parent = TempDir::new().expect("receipt parent");
            let receipt = crate::operational_state_migration::receipt::prepare_receipt_directory(
                &receipt_parent.path().join("receipt"),
            )
            .expect("receipt directory");
            let namespace =
                crate::anchored_fs::AnchoredDirectory::new(fixture.namespace.path().to_owned())
                    .expect("namespace authority");
            migrate_prepared_result_journals(
                &namespace,
                &receipt,
                &mut fixture.ledger,
                8,
                TEST_PAYLOAD_LIMIT,
            )
            .expect("establish semantic rewrite receipt");
            let current_payload =
                fs::read(root.join(JOURNAL_RESULT_FILE)).expect("current payload");
            let current_state = fs::read(root.join(JOURNAL_STATE_FILE)).expect("current state");
            fs::write(root.join(JOURNAL_RESULT_FILE), legacy_payload).expect("restore old payload");
            fs::write(root.join(JOURNAL_STATE_FILE), legacy_state).expect("restore old state");
            if cut >= 5 {
                fs::write(
                    root.join(migration::CURRENT_RESULT_PENDING),
                    &current_payload,
                )
                .expect("retain pending result during replacement");
                fs::write(root.join(migration::CURRENT_STATE_PENDING), &current_state)
                    .expect("retain pending state during replacement");
            }
            match cut {
                0 => {}
                1 => fs::write(
                    root.join(migration::CURRENT_RESULT_PENDING),
                    &current_payload[..current_payload.len() / 2],
                )
                .expect("interrupt pending result write"),
                2 => fs::write(
                    root.join(migration::CURRENT_RESULT_PENDING),
                    &current_payload,
                )
                .expect("complete pending result write"),
                3 => {
                    fs::write(
                        root.join(migration::CURRENT_RESULT_PENDING),
                        &current_payload,
                    )
                    .expect("complete pending result write");
                    fs::write(
                        root.join(migration::CURRENT_STATE_PENDING),
                        &current_state[..current_state.len() / 2],
                    )
                    .expect("interrupt pending state write");
                }
                4 => {
                    fs::write(
                        root.join(migration::CURRENT_RESULT_PENDING),
                        &current_payload,
                    )
                    .expect("complete pending result write");
                    fs::write(root.join(migration::CURRENT_STATE_PENDING), &current_state)
                        .expect("complete pending state write");
                }
                5 => fs::write(
                    root.join(JOURNAL_RESULT_FILE),
                    &current_payload[..current_payload.len() / 2],
                )
                .expect("interrupt result replacement"),
                6 => {
                    fs::write(root.join(JOURNAL_RESULT_FILE), &current_payload)
                        .expect("complete result replacement");
                    fs::write(
                        root.join(JOURNAL_STATE_FILE),
                        &current_state[..current_state.len() / 2],
                    )
                    .expect("interrupt state replacement");
                }
                7 => {
                    fs::write(root.join(JOURNAL_RESULT_FILE), &current_payload)
                        .expect("complete result replacement");
                    fs::write(root.join(JOURNAL_STATE_FILE), &current_state)
                        .expect("complete state replacement");
                }
                _ => unreachable!(),
            }

            migrate_prepared_result_journals(
                &namespace,
                &receipt,
                &mut fixture.ledger,
                8,
                TEST_PAYLOAD_LIMIT,
            )
            .unwrap_or_else(|error| panic!("resume semantic rewrite at cut {cut}: {error}"));
            DirectoryPreparedResultJournal::open(
                fixture.namespace.path(),
                fixture.key,
                fixture.execution,
                TEST_PAYLOAD_LIMIT,
            )
            .expect("open rewritten semantic payload");
        }
    }

    #[test]
    fn migration_resumes_after_every_journal_file_publish_cut() {
        for (marker, cut) in (0x71..=0x75).zip(0..=4) {
            let mut fixture = legacy_journal_fixture(marker);
            let root = journal_path(fixture.namespace.path(), fixture.key);
            let payload = fixture
                .result
                .canonical_bytes_with_limit(TEST_PAYLOAD_LIMIT)
                .expect("current payload");
            let state = encode_state(
                fixture.key,
                fixture.execution,
                TEST_PAYLOAD_LIMIT,
                &fixture.result,
                &payload,
            )
            .expect("current journal state");
            if cut >= 1 {
                fs::write(root.join(".result-v2.pending"), &payload)
                    .expect("write interrupted result temporary");
            }
            if cut >= 2 {
                fs::rename(
                    root.join(".result-v2.pending"),
                    root.join(JOURNAL_RESULT_FILE),
                )
                .expect("publish interrupted result");
            }
            if cut >= 3 {
                fs::write(root.join(".state-v2.pending"), &state)
                    .expect("write interrupted state temporary");
            }
            if cut >= 4 {
                fs::rename(
                    root.join(".state-v2.pending"),
                    root.join(JOURNAL_STATE_FILE),
                )
                .expect("publish interrupted state");
            }

            assert!(matches!(
                fixture.open(),
                Err(PreparedResultJournalError::RecoveryRequired)
            ));
            let summary = fixture
                .migrate()
                .unwrap_or_else(|error| panic!("resume migration at cut {cut}: {error}"));
            assert_eq!(summary.migrated, 1);
            assert!(!root.join(migration::JOURNAL_RESULT_FILE_V1).exists());
            assert!(!root.join(migration::JOURNAL_STATE_FILE_V1).exists());
            fixture.open().expect("open resumed journal");
        }
    }

    #[test]
    fn migration_resumes_after_first_legacy_file_removal() {
        let mut fixture = legacy_journal_fixture(0x77);
        let root = journal_path(fixture.namespace.path(), fixture.key);
        let legacy_state = fs::read(root.join(migration::JOURNAL_STATE_FILE_V1))
            .expect("legacy state before migration");
        let receipt_parent = TempDir::new().expect("receipt parent");
        let receipt_path = receipt_parent.path().join("receipt");
        let receipt =
            crate::operational_state_migration::receipt::prepare_receipt_directory(&receipt_path)
                .expect("receipt directory");
        let namespace =
            crate::anchored_fs::AnchoredDirectory::new(fixture.namespace.path().to_owned())
                .expect("namespace authority");

        migrate_prepared_result_journals(
            &namespace,
            &receipt,
            &mut fixture.ledger,
            8,
            TEST_PAYLOAD_LIMIT,
        )
        .expect("initial migration");
        fs::write(root.join(migration::JOURNAL_STATE_FILE_V1), legacy_state)
            .expect("simulate interrupted legacy cleanup");

        let resumed = migrate_prepared_result_journals(
            &namespace,
            &receipt,
            &mut fixture.ledger,
            8,
            TEST_PAYLOAD_LIMIT,
        )
        .expect("resume legacy cleanup");
        assert_eq!(resumed.migrated, 1);
        assert!(!root.join(migration::JOURNAL_STATE_FILE_V1).exists());
    }

    #[test]
    fn migration_rejects_corruption_before_staging_or_replacement() {
        let mut fixture = legacy_journal_fixture(0x79);
        let root = journal_path(fixture.namespace.path(), fixture.key);
        let result_path = root.join(migration::JOURNAL_RESULT_FILE_V1);
        let state_path = root.join(migration::JOURNAL_STATE_FILE_V1);
        let original_state = fs::read(&state_path).expect("read legacy state");
        fs::write(&result_path, b"corrupt legacy payload").expect("corrupt payload");

        assert!(fixture.migrate().is_err());
        assert_eq!(
            fs::read(state_path).expect("read unchanged state"),
            original_state
        );
        assert!(!root.join(JOURNAL_RESULT_FILE).exists());
    }

    #[test]
    fn migration_rejects_a_held_journal_lock_before_staging() {
        let mut fixture = legacy_journal_fixture(0x7d);
        let lock = acquire_namespace_lock(fixture.namespace.path(), fixture.key)
            .expect("hold journal lock");
        assert!(fixture.migrate().is_err());
        assert!(
            !journal_path(fixture.namespace.path(), fixture.key)
                .join(JOURNAL_RESULT_FILE)
                .exists()
        );
        drop(lock);
    }

    #[test]
    fn active_migration_fences_every_runtime_mutation_entry() {
        let namespace = TempDir::new().expect("journal namespace");
        let assignment = TempDir::new().expect("assignment root");
        let receipt_parent = TempDir::new().expect("receipt parent");
        let receipt_path = receipt_parent.path().join("receipt");
        let receipt_guard =
            crate::operational_state_migration::receipt::prepare_receipt_directory(&receipt_path)
                .expect("receipt directory");
        let namespace_guard = crate::anchored_fs::AnchoredDirectory::new(
            namespace
                .path()
                .canonicalize()
                .expect("canonical namespace"),
        )
        .expect("namespace guard");
        let assignment_path = assignment
            .path()
            .canonicalize()
            .expect("canonical assignment root");
        let prepared_path = namespace
            .path()
            .canonicalize()
            .expect("canonical prepared root");

        let staged_key = semantic_key(b"fenced-stage");
        let staged_execution = ExecutionId::from_bytes([0x91; 16]).expect("staged execution");
        let staged_result = observation_result(0x92, staged_key.attempt());
        let (mut staged, _) = DirectoryPreparedResultJournal::prepare_staged(
            namespace.path(),
            staged_key,
            staged_execution,
            TEST_PAYLOAD_LIMIT,
            staged_result,
        )
        .expect("prepare journal before migration");

        let visible_key = semantic_key(b"fenced-visible");
        let visible_execution = ExecutionId::from_bytes([0x93; 16]).expect("visible execution");
        let visible_result = observation_result(0x94, visible_key.attempt());
        let (visible, _) = DirectoryPreparedResultJournal::create(
            namespace.path(),
            visible_key,
            visible_execution,
            TEST_PAYLOAD_LIMIT,
            visible_result,
        )
        .expect("create journal before migration");

        crate::operational_state_migration::receipt::activate_marker(
            &namespace_guard,
            &receipt_guard,
            &assignment_path,
            &prepared_path,
        )
        .expect("activate migration fence");

        let absent_key = semantic_key(b"fenced-absent");
        let absent_result = observation_result(0x95, absent_key.attempt());
        assert!(matches!(
            DirectoryPreparedResultJournal::prepare_staged(
                namespace.path(),
                absent_key,
                ExecutionId::from_bytes([0x96; 16]).expect("absent execution"),
                TEST_PAYLOAD_LIMIT,
                absent_result,
            ),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));
        assert!(matches!(
            DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(
                namespace.path(),
                absent_key,
            ),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));
        assert!(matches!(
            staged.commit_staged(),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));
        assert!(matches!(
            visible.remove(),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));
    }

    #[test]
    fn runtime_rejects_nonregular_and_tampered_migration_markers() {
        for marker_kind in ["directory", "symlink", "tampered"] {
            let namespace = TempDir::new().expect("journal namespace");
            let marker = namespace
                .path()
                .join(crate::operational_state_migration::receipt::ACTIVE_MARKER);
            match marker_kind {
                "directory" => fs::create_dir(&marker).expect("marker directory"),
                "symlink" => symlink("missing-marker-target", &marker).expect("marker symlink"),
                "tampered" => {
                    fs::write(&marker, b"not an authenticated marker").expect("tampered marker")
                }
                _ => unreachable!(),
            }
            let key = semantic_key(marker_kind.as_bytes());
            let result = observation_result(0x97, key.attempt());

            assert!(
                DirectoryPreparedResultJournal::prepare_staged(
                    namespace.path(),
                    key,
                    ExecutionId::from_bytes([0x98; 16]).expect("execution"),
                    TEST_PAYLOAD_LIMIT,
                    result,
                )
                .is_err()
            );
            assert!(!staged_path(namespace.path(), key).exists());
        }
    }

    #[test]
    fn runtime_inventory_rejects_nonregular_or_oversized_journal_children() {
        for kind in ["visible-symlink", "staged-symlink", "retired-oversized"] {
            let namespace = TempDir::new().expect("journal namespace");
            let key = semantic_key(kind.as_bytes());
            let root = match kind {
                "visible-symlink" => journal_path(namespace.path(), key),
                "staged-symlink" => staged_path(namespace.path(), key),
                "retired-oversized" => retired_path(namespace.path(), key),
                _ => unreachable!(),
            };
            fs::create_dir(&root).expect("journal directory");
            if kind.ends_with("symlink") {
                std::os::unix::fs::symlink("missing", root.join(JOURNAL_RESULT_FILE))
                    .expect("journal symlink");
            } else {
                let file = File::create(root.join(JOURNAL_RESULT_FILE)).expect("oversized result");
                file.set_len(MAX_PREPARED_SEMANTIC_RESULT_BYTES as u64 + 1)
                    .expect("extend result");
            }

            assert!(
                DirectoryPreparedResultJournal::artifacts_present(namespace.path(), key).is_err()
            );
        }
    }

    #[test]
    fn staged_journal_is_durable_hidden_and_promotes_exactly() {
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(b"staged");
        let execution = ExecutionId::from_bytes([0x4f; 16]).expect("execution");
        let result = observation_result(0x5f, key.attempt());

        let (staged, disposition) = DirectoryPreparedResultJournal::prepare_staged(
            namespace.path(),
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result.clone(),
        )
        .expect("prepare hidden journal");
        assert_eq!(disposition, PreparedResultJournalCreateDisposition::Created);
        assert_eq!(staged.root(), staged_path(namespace.path(), key));
        assert!(!journal_path(namespace.path(), key).exists());
        drop(staged);
        assert!(matches!(
            DirectoryPreparedResultJournal::open_for_recovery(
                namespace.path(),
                key,
                TEST_PAYLOAD_LIMIT,
            ),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));

        let mut recovered = DirectoryPreparedResultJournal::open_staged_for_recovery(
            namespace.path(),
            key,
            TEST_PAYLOAD_LIMIT,
        )
        .expect("authenticate staged journal")
        .expect("staged journal exists");
        assert_eq!(recovered.result(), &result);
        recovered.commit_staged().expect("promote staged journal");
        assert_eq!(recovered.root(), journal_path(namespace.path(), key));
        assert!(!staged_path(namespace.path(), key).exists());
        assert!(journal_path(namespace.path(), key).is_dir());
    }

    #[test]
    fn staged_journal_rejects_result_substitution() {
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(b"staged-substitution");
        let execution = ExecutionId::from_bytes([0x4e; 16]).expect("execution");
        let result = observation_result(0x5e, key.attempt());
        let (staged, _) = DirectoryPreparedResultJournal::prepare_staged(
            namespace.path(),
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result,
        )
        .expect("prepare hidden journal");
        drop(staged);

        assert!(matches!(
            DirectoryPreparedResultJournal::prepare_staged(
                namespace.path(),
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                observation_result(0x5d, key.attempt()),
            ),
            Err(PreparedResultJournalError::ResultMismatch)
        ));
    }

    #[test]
    fn journal_create_reopen_authenticate_and_remove_are_exact() {
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(b"main");
        let execution = ExecutionId::from_bytes([0x51; 16]).expect("execution");
        let result = observation_result(0x61, key.attempt());

        let (journal, disposition) = DirectoryPreparedResultJournal::create(
            namespace.path(),
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result.clone(),
        )
        .expect("create journal");
        assert_eq!(disposition, PreparedResultJournalCreateDisposition::Created);
        assert_eq!(journal.result(), &result);
        assert!(journal.root().is_dir());
        let namespace_lock = namespace_lock_path(namespace.path(), key);
        let lock_inode = fs::metadata(&namespace_lock)
            .expect("namespace lock metadata")
            .ino();
        assert!(matches!(
            DirectoryPreparedResultJournal::open(
                namespace.path(),
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
            ),
            Err(PreparedResultJournalError::Io {
                operation: "lock-journal-namespace",
                ..
            })
        ));
        let root = journal.root().to_path_buf();
        let retained_owner_description = journal
            .namespace_lock
            .file()
            .try_clone()
            .expect("duplicate successful owner lock descriptor");
        drop(journal);

        let failed_open_lock = acquire_namespace_lock(namespace.path(), key)
            .expect("acquire lock for failed authenticated open");
        let failed_open_guard =
            open_runtime_namespace(namespace.path()).expect("guard namespace for failed open");
        let retained_failed_open_description = failed_open_lock
            .file()
            .try_clone()
            .expect("duplicate failed-open lock descriptor");
        assert!(matches!(
            DirectoryPreparedResultJournal::open_locked(
                root.clone(),
                key,
                Some(ExecutionId::from_bytes([0x52; 16]).expect("other execution")),
                TEST_PAYLOAD_LIMIT,
                failed_open_lock,
                failed_open_guard,
                false,
            ),
            Err(PreparedResultJournalError::InvalidState)
        ));
        let reopened_after_failure = DirectoryPreparedResultJournal::open(
            namespace.path(),
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
        )
        .expect("failed authenticated open releases retained lock description");
        drop(reopened_after_failure);
        drop(retained_failed_open_description);
        assert!(matches!(
            DirectoryPreparedResultJournal::open(
                namespace.path(),
                key,
                execution,
                TEST_PAYLOAD_LIMIT / 2,
            ),
            Err(PreparedResultJournalError::InvalidState)
        ));

        let (journal, disposition) = DirectoryPreparedResultJournal::create(
            namespace.path(),
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result.clone(),
        )
        .expect("reopen exact journal");
        assert_eq!(
            disposition,
            PreparedResultJournalCreateDisposition::Existing
        );
        drop(journal);
        assert!(matches!(
            DirectoryPreparedResultJournal::create(
                namespace.path(),
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                observation_result(0x62, key.attempt()),
            ),
            Err(PreparedResultJournalError::ResultMismatch)
        ));

        let journal = DirectoryPreparedResultJournal::open(
            namespace.path(),
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
        )
        .expect("open complete journal");
        journal.remove().expect("remove journal");
        journal.remove().expect("repeat durable removal");
        assert!(!root.exists());
        assert_eq!(
            fs::metadata(&namespace_lock)
                .expect("persistent namespace lock metadata")
                .ino(),
            lock_inode
        );
        drop(journal);
        let (recreated, disposition) = DirectoryPreparedResultJournal::create(
            namespace.path(),
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result,
        )
        .expect("recreate journal after retirement");
        assert_eq!(disposition, PreparedResultJournalCreateDisposition::Created);
        assert_eq!(
            fs::metadata(&namespace_lock)
                .expect("reused namespace lock metadata")
                .ino(),
            lock_inode
        );
        recreated.remove().expect("remove recreated journal");
        drop(retained_owner_description);
    }

    #[test]
    fn journal_rejects_corrupt_incomplete_and_nonsemantic_state() {
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(b"corrupt");
        let execution = ExecutionId::from_bytes([0x71; 16]).expect("execution");
        let (journal, _) = DirectoryPreparedResultJournal::create(
            namespace.path(),
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            observation_result(0x72, key.attempt()),
        )
        .expect("create journal");
        let root = journal.root().to_path_buf();
        drop(journal);

        let state_path = root.join(JOURNAL_STATE_FILE);
        let mut state = fs::read(&state_path).expect("read state");
        state[0] ^= 0xff;
        fs::write(&state_path, state).expect("corrupt state");
        assert!(matches!(
            DirectoryPreparedResultJournal::open(
                namespace.path(),
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
            ),
            Err(PreparedResultJournalError::InvalidState)
        ));

        let incomplete_namespace = TempDir::new().expect("incomplete namespace");
        fs::create_dir(journal_path(incomplete_namespace.path(), key))
            .expect("incomplete journal directory");
        assert!(matches!(
            DirectoryPreparedResultJournal::open(
                incomplete_namespace.path(),
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
            ),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));

        let request = CampaignFactId::parse(&typed_content_text(
            "crucible.campaign.fact",
            ObjectKind::CampaignFact,
            10,
            b"savepoint-capture-request",
        ))
        .expect("capture request ID");
        let nonsemantic = AttemptExecutionKey::new_scoped(
            key.lineage(),
            key.attempt(),
            AttemptExecutionScope::SavepointCapture { request },
        );
        assert!(matches!(
            DirectoryPreparedResultJournal::create(
                namespace.path(),
                nonsemantic,
                execution,
                TEST_PAYLOAD_LIMIT,
                observation_result(0x73, key.attempt()),
            ),
            Err(PreparedResultJournalError::NonSemanticKey)
        ));
    }

    #[test]
    fn journal_rejects_attempt_mismatch_before_creating_lock_or_staging() {
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(b"attempt-binding");
        let other = semantic_key(b"other-attempt").attempt();
        let execution = ExecutionId::from_bytes([0x81; 16]).expect("execution");

        assert!(matches!(
            DirectoryPreparedResultJournal::create(
                namespace.path(),
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                observation_result(0x82, other),
            ),
            Err(PreparedResultJournalError::AttemptMismatch)
        ));
        assert_eq!(
            fs::read_dir(namespace.path())
                .expect("read namespace")
                .count(),
            0
        );
    }

    #[test]
    fn ledger_gated_cleanup_recovers_fixed_partial_staging_and_retirement() {
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(b"orphan-recovery");
        let execution = ExecutionId::from_bytes([0x91; 16]).expect("execution");
        let result = observation_result(0x92, key.attempt());

        let staged = staged_path(namespace.path(), key);
        fs::create_dir(&staged).expect("partial staging directory");
        fs::write(staged.join(JOURNAL_RESULT_FILE), b"partial").expect("partial result");
        fs::write(staged.join(".state-v2.123.0"), b"partial")
            .expect("partial atomic state temporary");
        assert!(matches!(
            DirectoryPreparedResultJournal::create(
                namespace.path(),
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                result.clone(),
            ),
            Err(PreparedResultJournalError::Incomplete)
        ));
        let cleaned = DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(
            namespace.path(),
            key,
        )
        .expect("clean partial staging");
        assert_eq!(
            cleaned,
            PreparedResultJournalCleanupDisposition {
                staged_removed: true,
                retired_removed: false,
            }
        );

        let (journal, _) = DirectoryPreparedResultJournal::create(
            namespace.path(),
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result,
        )
        .expect("create after staged cleanup");
        let root = journal.root().to_path_buf();
        drop(journal);
        let retired = retired_path(namespace.path(), key);
        fs::rename(&root, &retired).expect("simulate completed retirement rename");
        fs::remove_file(retired.join(JOURNAL_RESULT_FILE))
            .expect("simulate partial retired cleanup");

        let cleaned = DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(
            namespace.path(),
            key,
        )
        .expect("finish partial retirement");
        assert_eq!(
            cleaned,
            PreparedResultJournalCleanupDisposition {
                staged_removed: false,
                retired_removed: true,
            }
        );
        assert_eq!(
            DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(
                namespace.path(),
                key,
            )
            .expect("idempotent orphan cleanup"),
            PreparedResultJournalCleanupDisposition::default()
        );
    }

    fn semantic_key(marker: &[u8]) -> AttemptExecutionKey {
        let lineage = CampaignLineageId::parse(&typed_content_text(
            "crucible.campaign.lineage",
            ObjectKind::CampaignFact,
            1,
            marker,
        ))
        .expect("lineage ID");
        let attempt = AttemptId::parse(&typed_content_text(
            "crucible.campaign.attempt",
            ObjectKind::CampaignFact,
            1,
            marker,
        ))
        .expect("attempt ID");
        AttemptExecutionKey::new(lineage, attempt)
    }

    fn observation_result(marker: u8, attempt: AttemptId) -> PreparedSemanticAttemptResult {
        let candidate = observation_candidate(
            marker,
            attempt,
            MeasurementSet::new(BTreeMap::new()).expect("measurements"),
        );
        PreparedSemanticAttemptResult::new(candidate, None).expect("prepared result")
    }

    fn observation_candidate(
        marker: u8,
        attempt: AttemptId,
        measurements: MeasurementSet,
    ) -> ObservationCandidate {
        let scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", &[marker, 0]));
        let scenario_artifact = ScenarioArtifactId::parse(&typed_content_text(
            "crucible.campaign.scenario-artifact",
            ObjectKind::Scenario,
            1,
            &[marker, 1],
        ))
        .expect("scenario artifact ID");
        let configuration = ConfigurationId::from_hash(CampaignHash::derive("test", &[marker, 2]));
        let child =
            ConfigurationArtifact::new(scenario, scenario_artifact, configuration, 1, vec![marker])
                .expect("configuration artifact");
        let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
        let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
        let path = BranchPathId::parse(&typed_content_text(
            "crucible.campaign.branch-path",
            ObjectKind::CampaignFact,
            2,
            &[marker, 4],
        ))
        .expect("branch path ID");
        let observation = Observation::new(
            attempt,
            configuration,
            child.id().expect("configuration artifact ID"),
            path,
            StopOutcome::TerminalSuccess,
            measurements.id().expect("measurement ID"),
            properties.id().expect("property ID"),
            coverage.id().expect("coverage ID"),
            BTreeSet::new(),
        )
        .expect("observation");
        ObservationCandidate::new(
            child,
            measurements,
            properties,
            coverage,
            Vec::new(),
            observation,
        )
        .expect("observation candidate")
    }

    fn typed_content_text(
        tag: &str,
        kind: ObjectKind,
        schema_version: u32,
        marker: &[u8],
    ) -> String {
        let content = ContentId::for_bytes(kind, schema_version, marker);
        format!("{tag}@{}", content.encode())
    }
}
