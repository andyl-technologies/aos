//! Crash-safe local ownership of one prepared semantic attempt result.
//!
//! Each execution key selects one directory in an operator-owned namespace:
//!
//! ```text
//! <namespace>/.lock-runtime-owner
//! <namespace>/.lock-<execution-key-digest>
//! <namespace>/<execution-key-digest>/result-v2
//! <namespace>/<execution-key-digest>/state-v2
//! <namespace>/.staged-<execution-key-digest>/...
//! <namespace>/.retired-<execution-key-digest>/...
//! <namespace>/<execution-key-digest>/.<legacy-name>.removing-v1-<device>-<inode>
//! <namespace>/.<staged-or-retired-name>.removing-v1-<device>-<inode>/
//!   .orphan-cleanup-v1.json
//!   .<owned-file>.removing-v1-<device>-<inode>
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
//! operation. Zero-length migration tombstones remain terminal metadata and
//! are admitted only when their exact name and inode are sealed by the
//! completed prepared-result rewrite receipt. Normal orphan cleanup similarly
//! retains one terminal directory containing a write-once authenticated cleanup
//! receipt and the zero-length children sealed by that receipt.
//! The retained runtime-owner lock gives one startup-inventoried authority
//! exclusive ownership of the namespace for the daemon lifetime.

use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
const JOURNAL_OWNER_LOCK: &str = ".lock-runtime-owner";
const JOURNAL_STAGED_PREFIX: &str = ".staged-";
const JOURNAL_RETIRED_PREFIX: &str = ".retired-";
const JOURNAL_RESULT_FILE: &str = "result-v2";
const JOURNAL_STATE_FILE: &str = "state-v2";
const ORPHAN_CLEANUP_RECEIPT: &str = ".orphan-cleanup-v1.json";
const ORPHAN_CLEANUP_RECEIPT_PENDING: &str = "..orphan-cleanup-v1.json.pending";
const ORPHAN_CLEANUP_OUTPUT_SCHEMA: &str = "crucible.executor.prepared-result-orphan-cleanup.v1";
const JOURNAL_STATE_MAGIC_V2: &[u8] = b"crucible.executor.prepared-result-journal-state.v2\0";
const JOURNAL_STATE_HASH_DOMAIN_V2: &str = "crucible.executor.prepared-result-journal-state.v2";
const JOURNAL_MEASUREMENT_EVIDENCE_HASH_DOMAIN: &str =
    "crucible.executor.prepared-result-journal-measurement-evidence.v1";
const PREPARED_RESULT_LEDGER_BINDING_DOMAIN: &str =
    "crucible.executor.prepared-result-ledger-binding.v1";
const MAX_JOURNAL_STATE_BYTES: usize = 16 * 1024;
const MAX_ORPHAN_DIRECTORY_ENTRIES: usize = 6;

/// Startup-validated authority for one prepared-result journal namespace.
///
/// Opening this authority performs the single bounded inventory required before
/// normal runtime work. Clones retain the same anchored directory and terminal
/// inventory; journal operations do not reopen or rescan the namespace.
#[derive(Clone, Debug)]
pub(crate) struct PreparedResultJournalNamespace {
    runtime: Arc<RuntimeNamespace>,
}

impl PreparedResultJournalNamespace {
    /// Opens, authenticates, and completely inventories an existing namespace.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when the path is not an ordinary
    /// directory, a migration is active, or the bounded inventory contains an
    /// incomplete, legacy, malformed, or unauthenticated entry.
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, PreparedResultJournalError> {
        let path = path.as_ref();
        validate_namespace(path)?;
        let path = fs::canonicalize(path)
            .map_err(|source| io_error("canonicalize-journal-namespace", path, source))?;
        let guard =
            crate::anchored_fs::AnchoredDirectory::new(path).map_err(migration_guard_error)?;
        reject_active_migration_guard(&guard)?;
        let owner_lock = acquire_runtime_owner_lock(&guard)?;
        let terminal_orphans = reject_unfenced_migration_entries(&guard)?;
        #[cfg(test)]
        run_journal_race_hook();
        guard.verify_path_binding().map_err(migration_guard_error)?;

        Ok(Self {
            runtime: Arc::new(RuntimeNamespace {
                guard,
                _owner_lock: owner_lock,
                terminal_orphans: Mutex::new(terminal_orphans),
            }),
        })
    }
}

/// Outcome of idempotently creating one prepared-result journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedResultJournalCreateDisposition {
    /// This call durably created the exact journal.
    Created,
    /// The exact journal already existed and was reopened.
    Existing,
}

/// Bounded outcome of a ledger-authorized orphan cleanup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PreparedResultJournalCleanupDisposition {
    /// Whether a live staging name was retired into authenticated terminal state.
    pub staged_removed: bool,
    /// Whether a live retired name was retired into authenticated terminal state.
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
pub(crate) struct DirectoryPreparedResultJournal {
    root: PathBuf,
    root_guard: crate::anchored_fs::AnchoredDirectory,
    namespace_guard: Arc<RuntimeNamespace>,
    staged: bool,
    key: AttemptExecutionKey,
    execution: ExecutionId,
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
    #[cfg(test)]
    pub(crate) fn create(
        namespace: &PreparedResultJournalNamespace,
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
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        maximum_payload_bytes: usize,
        result: PreparedSemanticAttemptResult,
    ) -> Result<(Self, PreparedResultJournalCreateDisposition), PreparedResultJournalError> {
        let namespace_guard = Arc::clone(&namespace.runtime);
        let namespace = namespace_guard.path().to_owned();
        let anchored_namespace = namespace_guard.anchored_path();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        validate_result_key(key, &result)?;
        reject_active_migration(&namespace_guard)?;
        let namespace_lock = acquire_namespace_lock(&namespace_guard, key)?;
        reject_active_migration(&namespace_guard)?;
        if namespace_guard.has_terminal(&staged_path(&namespace, key))
            || namespace_guard.has_terminal(&retired_path(&namespace, key))
        {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
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
        let root_guard = namespace_guard
            .open_child(&staging, "pin-staged-journal")
            .map_err(migration_guard_error)?;
        namespace_lock
            .verify_path_binding()
            .map_err(migration_guard_error)?;
        reject_active_migration(&namespace_guard)?;
        Ok((
            Self {
                root: staging,
                root_guard,
                namespace_guard,
                staged: true,
                key,
                execution,
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
        self.namespace_lock
            .verify_path_binding()
            .map_err(migration_guard_error)?;
        reject_active_migration(&self.namespace_guard)?;
        if !self.staged {
            return Ok(());
        }
        let namespace = self
            .root
            .parent()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        let visible = journal_path(namespace, self.key);
        let visible_guard = rename_bound_journal_directory(
            &self.namespace_guard,
            &self.root_guard,
            &visible,
            "publish-journal-directory",
        )?;
        self.root = visible;
        self.root_guard = visible_guard;
        self.staged = false;
        self.namespace_lock
            .verify_path_binding()
            .map_err(migration_guard_error)?;
        reject_active_migration(&self.namespace_guard)?;
        Ok(())
    }

    /// Opens an authenticated hidden journal after the ledger proves Publishing.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] for invalid namespace, locking,
    /// authentication, or staged journal bytes.
    pub(crate) fn open_staged_for_recovery(
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
        maximum_payload_bytes: usize,
    ) -> Result<Option<Self>, PreparedResultJournalError> {
        let namespace_guard = Arc::clone(&namespace.runtime);
        let namespace = namespace_guard.path().to_owned();
        let anchored_namespace = namespace_guard.anchored_path();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        reject_active_migration(&namespace_guard)?;
        let namespace_lock = acquire_namespace_lock(&namespace_guard, key)?;
        if namespace_guard.has_terminal_key(key) {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
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
    #[cfg(test)]
    pub(crate) fn open(
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        maximum_payload_bytes: usize,
    ) -> Result<Self, PreparedResultJournalError> {
        let namespace_guard = Arc::clone(&namespace.runtime);
        let namespace = namespace_guard.path().to_owned();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        reject_active_migration(&namespace_guard)?;
        let namespace_lock = acquire_namespace_lock(&namespace_guard, key)?;
        if namespace_guard.has_terminal_key(key) {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
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
    pub(crate) fn open_for_recovery(
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
        maximum_payload_bytes: usize,
    ) -> Result<Option<Self>, PreparedResultJournalError> {
        let namespace_guard = Arc::clone(&namespace.runtime);
        let namespace = namespace_guard.path().to_owned();
        let anchored_namespace = namespace_guard.anchored_path();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        reject_active_migration(&namespace_guard)?;
        let namespace_lock = acquire_namespace_lock(&namespace_guard, key)?;
        if namespace_guard.has_terminal_key(key) {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
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
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
    ) -> Result<bool, PreparedResultJournalError> {
        let namespace_guard = Arc::clone(&namespace.runtime);
        let anchored_namespace = namespace_guard.anchored_path();
        validate_semantic_key(key)?;
        reject_active_migration(&namespace_guard)?;

        let present = namespace_guard.has_terminal_key(key)
            || path_presence(
                &journal_path(&anchored_namespace, key),
                "inventory-prepared-result-journal",
            )?
            || path_presence(
                &staged_path(&anchored_namespace, key),
                "inventory-staged-prepared-result-journal",
            )?
            || path_presence(
                &retired_path(&anchored_namespace, key),
                "inventory-retired-prepared-result-journal",
            )?;
        reject_active_migration(&namespace_guard)?;
        Ok(present)
    }

    fn open_locked(
        root: PathBuf,
        key: AttemptExecutionKey,
        expected_execution: Option<ExecutionId>,
        maximum_payload_bytes: usize,
        namespace_lock: OwnedAdvisoryLock,
        namespace_guard: Arc<RuntimeNamespace>,
        staged: bool,
    ) -> Result<Self, PreparedResultJournalError> {
        reject_active_migration(&namespace_guard)?;
        let root_guard = namespace_guard
            .open_child(&root, "open-current-journal")
            .map_err(migration_guard_error)?;
        root_guard.sync().map_err(migration_guard_error)?;
        namespace_guard.sync().map_err(migration_guard_error)?;

        let cleanup_keys = sealed_prepared_cleanup_keys(&namespace_guard)?;
        let (state_file, result_file) = journal_files(&root_guard, cleanup_keys.as_ref())?;
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
        root_guard
            .verify_path_binding()
            .map_err(migration_guard_error)?;
        namespace_lock
            .verify_path_binding()
            .map_err(migration_guard_error)?;
        reject_active_migration(&namespace_guard)?;

        Ok(Self {
            root,
            root_guard,
            namespace_guard,
            staged,
            key,
            execution: envelope.execution,
            prepared_result_digest: CampaignHash::derive(
                PREPARED_RESULT_LEDGER_BINDING_DOMAIN,
                &payload,
            ),
            result,
            namespace_lock,
        })
    }

    /// Returns the exact journal directory selected by the scoped key.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the exact local execution incarnation that produced the result.
    #[must_use]
    pub(crate) const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the authenticated full-payload digest bound into the ledger.
    #[must_use]
    pub(crate) const fn prepared_result_digest(&self) -> CampaignHash {
        self.prepared_result_digest
    }

    /// Returns the complete prepared publication value.
    #[must_use]
    pub(crate) const fn result(&self) -> &PreparedSemanticAttemptResult {
        &self.result
    }

    /// Retires this journal after the operational ledger proves it is no longer
    /// needed for publication recovery.
    ///
    /// Cleanup occurs while the journal lock is held and leaves one bounded,
    /// authenticated terminal tombstone for this key.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] if a file or directory cannot be
    /// retired or the parent cannot be synced. The caller must treat an error
    /// as indeterminate cleanup and retry without rerunning guest execution.
    pub(crate) fn remove(&self) -> Result<(), PreparedResultJournalError> {
        self.namespace_lock
            .verify_path_binding()
            .map_err(migration_guard_error)?;
        reject_active_migration(&self.namespace_guard)?;
        let namespace = self
            .root
            .parent()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        if self.staged {
            let anchored_root = self
                .namespace_guard
                .anchored_path_for(&self.root)
                .map_err(migration_guard_error)?;
            if path_presence(&anchored_root, "inspect-staged-journal-before-remove")? {
                self.root_guard
                    .verify_path_binding()
                    .map_err(migration_guard_error)?;
                remove_bound_orphan_directory(&self.namespace_guard, &self.root, &self.root_guard)?;
                self.namespace_guard.record_terminal(&self.root)?;
            }
            self.namespace_lock
                .verify_path_binding()
                .map_err(migration_guard_error)?;
            return reject_active_migration(&self.namespace_guard);
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
        if root_present && self.namespace_guard.has_terminal(&tombstone) {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
        let retired_guard = match (root_present, tombstone_present) {
            (true, false) => Some(rename_bound_journal_directory(
                &self.namespace_guard,
                &self.root_guard,
                &tombstone,
                "retire-journal-directory",
            )?),
            (false, true) => {
                let guard = self
                    .namespace_guard
                    .open_inventory_child(&tombstone, "pin-retired-journal")
                    .map_err(migration_guard_error)?;
                if guard.identity() != self.root_guard.identity() {
                    return Err(PreparedResultJournalError::RecoveryRequired);
                }
                Some(guard)
            }
            (false, false) => None,
            (true, true) => return Err(PreparedResultJournalError::RecoveryRequired),
        };
        reject_active_migration(&self.namespace_guard)?;
        if let Some(retired_guard) = retired_guard {
            remove_bound_orphan_directory(&self.namespace_guard, &tombstone, &retired_guard)?;
            self.namespace_guard.record_terminal(&tombstone)?;
        }
        self.namespace_lock
            .verify_path_binding()
            .map_err(migration_guard_error)?;
        reject_active_migration(&self.namespace_guard)
    }

    /// Retires at most the fixed staged and retired live names for `key`.
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
    /// lock contention, unexpected orphan contents, or failed durable
    /// transition to terminal state.
    pub(crate) fn cleanup_orphans_after_ledger_check(
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
    ) -> Result<PreparedResultJournalCleanupDisposition, PreparedResultJournalError> {
        let namespace_guard = Arc::clone(&namespace.runtime);
        let namespace = namespace_guard.anchored_path();
        let namespace = namespace.as_path();
        validate_semantic_key(key)?;
        reject_active_migration(&namespace_guard)?;
        let namespace_lock = acquire_namespace_lock(&namespace_guard, key)?;
        reject_active_migration(&namespace_guard)?;
        #[cfg(test)]
        run_journal_race_hook();
        if path_presence(
            &journal_path(namespace, key),
            "inspect-visible-journal-before-orphan-cleanup",
        )? {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }

        let staged_removed =
            remove_orphan_directory(&namespace_guard, &staged_path(namespace, key))?;
        reject_active_migration(&namespace_guard)?;
        let retired_removed =
            remove_orphan_directory(&namespace_guard, &retired_path(namespace, key))?;
        namespace_lock
            .verify_path_binding()
            .map_err(migration_guard_error)?;
        reject_active_migration(&namespace_guard)?;
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

fn journal_files(
    root: &crate::anchored_fs::AnchoredDirectory,
    cleanup_keys: Option<&std::collections::BTreeSet<String>>,
) -> Result<(&'static str, &'static str), PreparedResultJournalError> {
    let mut state = false;
    let mut result = false;
    let anchored = root.anchored_path();
    for entry in fs::read_dir(&anchored)
        .map_err(|source| io_error("read-current-journal-directory", &anchored, source))?
    {
        let entry = entry.map_err(|source| {
            io_error("read-current-journal-directory-entry", &anchored, source)
        })?;
        if !entry
            .file_type()
            .map_err(|source| io_error("stat-current-journal-entry", &entry.path(), source))?
            .is_file()
        {
            return Err(PreparedResultJournalError::Incomplete);
        }
        let name = entry.file_name();
        if let Some(logical_name) = crate::anchored_fs::removal_original_name(&name) {
            let authority = root
                .open_inventory_file(&entry.path(), "pin-current-journal-tombstone")
                .map_err(migration_guard_error)?
                .ok_or(PreparedResultJournalError::Incomplete)?;
            let metadata = entry.metadata().map_err(|source| {
                io_error("inspect-current-journal-tombstone", &entry.path(), source)
            })?;
            let journal = root
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(PreparedResultJournalError::Incomplete)?;
            let logical_name = logical_name
                .to_str()
                .ok_or(PreparedResultJournalError::Incomplete)?;
            if metadata.len() != 0
                || !cleanup_keys.is_some_and(|keys| {
                    keys.contains(&migration::prepared_cleanup_key(
                        journal,
                        logical_name,
                        authority.identity(),
                    ))
                })
            {
                return Err(PreparedResultJournalError::Incomplete);
            }
            continue;
        }
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

fn rename_bound_journal_directory(
    namespace: &crate::anchored_fs::AnchoredDirectory,
    source_guard: &crate::anchored_fs::AnchoredDirectory,
    destination: &Path,
    operation: &'static str,
) -> Result<crate::anchored_fs::AnchoredDirectory, PreparedResultJournalError> {
    namespace
        .rename_bound_directory_with(source_guard, destination, operation, || {
            #[cfg(test)]
            run_journal_race_hook();
            Ok(())
        })
        .map_err(migration_guard_error)
}

fn remove_orphan_directory(
    namespace: &RuntimeNamespace,
    root: &Path,
) -> Result<bool, PreparedResultJournalError> {
    let anchored_root = namespace
        .anchored_path_for(root)
        .map_err(migration_guard_error)?;
    if namespace.has_terminal(root) {
        return if path_presence(&anchored_root, "inspect-terminal-orphan-logical-name")? {
            Err(PreparedResultJournalError::RecoveryRequired)
        } else {
            Ok(false)
        };
    }
    let Some((root_guard, entries)) = inventory_orphan_directory(namespace, root)? else {
        return Ok(false);
    };
    remove_orphan_inventory(namespace, root_guard, entries)?;
    namespace.record_terminal(root)?;
    Ok(true)
}

fn remove_bound_orphan_directory(
    namespace: &RuntimeNamespace,
    root: &Path,
    expected: &crate::anchored_fs::AnchoredDirectory,
) -> Result<(), PreparedResultJournalError> {
    if namespace.has_terminal(root) {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    let (root_guard, entries) = inventory_orphan_directory(namespace, root)?
        .ok_or(PreparedResultJournalError::RecoveryRequired)?;
    if root_guard.identity() != expected.identity() {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    remove_orphan_inventory(namespace, root_guard, entries)
}

fn remove_orphan_inventory(
    namespace: &crate::anchored_fs::AnchoredDirectory,
    root_guard: crate::anchored_fs::AnchoredDirectory,
    entries: Vec<crate::anchored_fs::AnchoredFile>,
) -> Result<(), PreparedResultJournalError> {
    let receipt = seal_orphan_cleanup(&root_guard, &entries)?;
    for entry in entries {
        root_guard
            .remove_bound_file(&entry, "remove-journal-orphan-file")
            .map_err(migration_guard_error)?;
    }
    receipt
        .verify_path_binding()
        .map_err(|_| PreparedResultJournalError::RecoveryRequired)?;
    namespace
        .remove_bound_directory(&root_guard, "remove-journal-directory")
        .map_err(migration_guard_error)
}

fn seal_orphan_cleanup(
    root: &crate::anchored_fs::AnchoredDirectory,
    entries: &[crate::anchored_fs::AnchoredFile],
) -> Result<crate::operational_state_migration::receipt::PhaseReceipt, PreparedResultJournalError> {
    let prior = crate::operational_state_migration::receipt::load_phase_receipt(
        root,
        ORPHAN_CLEANUP_RECEIPT,
        ORPHAN_CLEANUP_OUTPUT_SCHEMA,
    )
    .map_err(|_| PreparedResultJournalError::RecoveryRequired)?;
    if let Some(receipt) = prior {
        validate_orphan_cleanup_receipt(root, entries, &receipt)?;
        return Ok(receipt);
    }
    if entries
        .iter()
        .any(|entry| entry.removal_original_name().is_some())
    {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    let objects = orphan_cleanup_objects(root, entries, true)?;
    let receipt = crate::operational_state_migration::receipt::persist_phase_receipt(
        root,
        ORPHAN_CLEANUP_RECEIPT,
        ORPHAN_CLEANUP_OUTPUT_SCHEMA,
        objects,
    )
    .map_err(|_| PreparedResultJournalError::RecoveryRequired)?;
    validate_orphan_cleanup_receipt(root, entries, &receipt)?;
    Ok(receipt)
}

fn validate_orphan_cleanup_receipt(
    root: &crate::anchored_fs::AnchoredDirectory,
    entries: &[crate::anchored_fs::AnchoredFile],
    receipt: &crate::operational_state_migration::receipt::PhaseReceipt,
) -> Result<(), PreparedResultJournalError> {
    let objects = orphan_cleanup_objects(root, entries, false)?;
    if receipt.objects.len() != objects.len()
        || objects.iter().any(|object| {
            !receipt.objects.iter().any(|sealed| {
                sealed.key == object.key
                    && sealed.output_object_id == object.output_object_id
                    && (sealed.source_object_id == object.source_object_id
                        || object.source_object_id == object.output_object_id)
            })
        })
    {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    receipt
        .verify_path_binding()
        .map_err(|_| PreparedResultJournalError::RecoveryRequired)
}

fn orphan_cleanup_objects(
    root: &crate::anchored_fs::AnchoredDirectory,
    entries: &[crate::anchored_fs::AnchoredFile],
    require_sources: bool,
) -> Result<
    Vec<crate::operational_state_migration::receipt::MigrationObjectReceipt>,
    PreparedResultJournalError,
> {
    let root_name = crate::anchored_fs::removal_original_name(
        root.path()
            .file_name()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?,
    )
    .unwrap_or_else(|| root.path().file_name().unwrap_or_default().to_owned());
    let (root_device, root_inode) = root.identity();
    let root_id = crate::operational_state_migration::receipt::authenticated_id(
        "crucible.prepared-result-orphan-cleanup-root.v1",
        &[
            root_name.as_bytes(),
            &root_device.to_be_bytes(),
            &root_inode.to_be_bytes(),
        ],
    );
    let mut objects = vec![
        crate::operational_state_migration::receipt::MigrationObjectReceipt {
            key: "root".to_owned(),
            source_object_id: root_id.clone(),
            output_object_id: root_id,
        },
    ];
    for entry in entries {
        let name = entry.logical_name();
        let (device, inode) = entry.identity();
        let output = crate::operational_state_migration::receipt::authenticated_id(
            "crucible.prepared-result-orphan-cleanup-output.v1",
            &[name.as_bytes(), &device.to_be_bytes(), &inode.to_be_bytes()],
        );
        let bytes = entry
            .read_bounded(runtime_journal_file_limit(&name.to_string_lossy()) as u64)
            .map_err(migration_guard_error)?;
        let source = if entry.removal_original_name().is_some() && bytes.is_empty() {
            output.clone()
        } else {
            if require_sources && entry.removal_original_name().is_some() {
                return Err(PreparedResultJournalError::RecoveryRequired);
            }
            crate::operational_state_migration::receipt::authenticated_id(
                "crucible.prepared-result-orphan-cleanup-source.v1",
                &[
                    name.as_bytes(),
                    &device.to_be_bytes(),
                    &inode.to_be_bytes(),
                    &bytes,
                ],
            )
        };
        objects.push(
            crate::operational_state_migration::receipt::MigrationObjectReceipt {
                key: format!("file/{}", name.to_string_lossy()),
                source_object_id: source,
                output_object_id: output,
            },
        );
    }
    Ok(objects)
}

fn inventory_orphan_directory(
    namespace: &crate::anchored_fs::AnchoredDirectory,
    root: &Path,
) -> Result<
    Option<(
        crate::anchored_fs::AnchoredDirectory,
        Vec<crate::anchored_fs::AnchoredFile>,
    )>,
    PreparedResultJournalError,
> {
    let actual_root = namespace
        .anchored_path_for(root)
        .map_err(migration_guard_error)?;
    if !path_presence(&actual_root, "inspect-journal-orphan")? {
        return Ok(None);
    }
    let root_guard = namespace
        .open_inventory_child(&actual_root, "open-journal-orphan")
        .map_err(migration_guard_error)?;
    let anchored_root = root_guard.anchored_path();
    let mut entries = Vec::new();
    let mut raw_entries = 0usize;
    let mut cleanup_receipt_seen = false;
    for entry in fs::read_dir(&anchored_root)
        .map_err(|source| io_error("read-journal-orphan", &anchored_root, source))?
        .take(MAX_ORPHAN_DIRECTORY_ENTRIES + 2)
    {
        let entry = entry.map_err(|source| io_error("read-journal-orphan", root, source))?;
        raw_entries += 1;
        if raw_entries > MAX_ORPHAN_DIRECTORY_ENTRIES + 1 {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        let actual_name = entry.file_name();
        if actual_name == ORPHAN_CLEANUP_RECEIPT || actual_name == ORPHAN_CLEANUP_RECEIPT_PENDING {
            if cleanup_receipt_seen {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            cleanup_receipt_seen = true;
            root_guard
                .open_inventory_file(&entry.path(), "pin-orphan-cleanup-receipt")
                .map_err(migration_guard_error)?
                .ok_or(PreparedResultJournalError::InvalidDirectory)?;
            continue;
        }
        let name = crate::anchored_fs::removal_original_name(&actual_name)
            .unwrap_or_else(|| actual_name.clone());
        let name = name
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        if entries.len() == MAX_ORPHAN_DIRECTORY_ENTRIES || !is_owned_orphan_file(name) {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        let authority = root_guard
            .open_inventory_file(&entry.path(), "pin-journal-orphan-file")
            .map_err(migration_guard_error)?
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        entries.push(authority);
    }
    Ok(Some((root_guard, entries)))
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
    namespace: &crate::anchored_fs::AnchoredDirectory,
    key: AttemptExecutionKey,
) -> Result<OwnedAdvisoryLock, PreparedResultJournalError> {
    let path = namespace_lock_path(namespace.path(), key);
    let lock = namespace
        .open_or_create_regular(&path, "open-journal-namespace-lock")
        .map_err(migration_guard_error)?;
    lock_exclusive(lock, &path)
}

fn lock_exclusive(
    lock: crate::anchored_fs::AnchoredFile,
    path: &Path,
) -> Result<OwnedAdvisoryLock, PreparedResultJournalError> {
    OwnedAdvisoryLock::try_exclusive_bound(lock).map_err(|source| {
        let (_, _, source) = source.into_io_parts("lock-journal-namespace");
        io_error("lock-journal-namespace", path, source)
    })
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

#[derive(Debug)]
struct RuntimeNamespace {
    guard: crate::anchored_fs::AnchoredDirectory,
    _owner_lock: OwnedAdvisoryLock,
    terminal_orphans: Mutex<std::collections::BTreeSet<std::ffi::OsString>>,
}

impl RuntimeNamespace {
    fn has_terminal(&self, logical_path: &Path) -> bool {
        logical_path.file_name().is_some_and(|name| {
            self.terminal_orphans
                .lock()
                .map_or(true, |terminals| terminals.contains(name))
        })
    }

    fn record_terminal(&self, logical_path: &Path) -> Result<(), PreparedResultJournalError> {
        let name = logical_path
            .file_name()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?
            .to_owned();
        self.terminal_orphans
            .lock()
            .map_err(|_| PreparedResultJournalError::RecoveryRequired)?
            .insert(name);
        Ok(())
    }

    fn has_terminal_key(&self, key: AttemptExecutionKey) -> bool {
        self.has_terminal(&staged_path(self.path(), key))
            || self.has_terminal(&retired_path(self.path(), key))
    }
}

impl std::ops::Deref for RuntimeNamespace {
    type Target = crate::anchored_fs::AnchoredDirectory;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

fn reject_active_migration(namespace: &RuntimeNamespace) -> Result<(), PreparedResultJournalError> {
    namespace
        ._owner_lock
        .verify_path_binding()
        .map_err(migration_guard_error)?;
    reject_active_migration_guard(&namespace.guard)
}

fn reject_active_migration_guard(
    namespace: &crate::anchored_fs::AnchoredDirectory,
) -> Result<(), PreparedResultJournalError> {
    namespace
        .verify_path_binding()
        .map_err(migration_guard_error)?;
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

pub(crate) fn acquire_runtime_owner_lock(
    namespace: &crate::anchored_fs::AnchoredDirectory,
) -> Result<OwnedAdvisoryLock, PreparedResultJournalError> {
    let path = namespace.path().join(JOURNAL_OWNER_LOCK);
    let lock = namespace
        .open_or_create_regular(&path, "open-runtime-namespace-owner-lock")
        .map_err(migration_guard_error)?;
    lock_exclusive(lock, &path)
}

fn migration_guard_error(error: crate::anchored_fs::AnchoredFsError) -> PreparedResultJournalError {
    let (operation, path, source) = error.into_io_parts("guard-prepared-result-namespace");
    io_error(operation, &path, source)
}

fn reject_unfenced_migration_entries(
    namespace: &crate::anchored_fs::AnchoredDirectory,
) -> Result<std::collections::BTreeSet<std::ffi::OsString>, PreparedResultJournalError> {
    let cleanup_keys = sealed_prepared_cleanup_keys(namespace)?;
    let anchored_namespace = namespace.anchored_path();
    let mut entries = 0usize;
    let mut bytes = 0u64;
    let mut terminal_orphans = std::collections::BTreeSet::new();
    let mut orphan_keys = std::collections::BTreeSet::new();
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
        let metadata = admit_runtime_entry(&mut entries, &mut bytes, &entry.path())?;
        let actual_name = entry.file_name();
        if let Some(original_name) = crate::anchored_fs::removal_original_name(&actual_name) {
            if !terminal_orphans.insert(original_name.clone()) {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            let name = original_name
                .to_str()
                .ok_or(PreparedResultJournalError::InvalidDirectory)?;
            let key = name
                .strip_prefix(JOURNAL_STAGED_PREFIX)
                .or_else(|| name.strip_prefix(JOURNAL_RETIRED_PREFIX));
            if !key
                .is_some_and(|name| is_lower_hex(name, 64) && orphan_keys.insert(name.to_owned()))
                || !metadata.file_type().is_dir()
            {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            let root = namespace
                .open_inventory_child(&entry.path(), "open-runtime-journal-tombstone")
                .map_err(migration_guard_error)?;
            inspect_runtime_journal_directory(
                &root,
                true,
                cleanup_keys.as_ref(),
                &mut entries,
                &mut bytes,
            )?;
            continue;
        }
        let name = actual_name
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        let file_type = metadata.file_type();
        if name == crate::operational_state_migration::receipt::ACTIVE_MARKER {
            if !file_type.is_file() {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            continue;
        }
        if name == JOURNAL_OWNER_LOCK {
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
            if !key
                .is_some_and(|name| is_lower_hex(name, 64) && orphan_keys.insert(name.to_owned()))
                || !file_type.is_dir()
            {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            let root = namespace
                .open_inventory_child(&entry.path(), "open-runtime-journal-orphan")
                .map_err(migration_guard_error)?;
            inspect_runtime_journal_directory(
                &root,
                true,
                cleanup_keys.as_ref(),
                &mut entries,
                &mut bytes,
            )?;
            continue;
        }
        if !is_lower_hex(name, 64) || !file_type.is_dir() {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        let root = namespace
            .open_child(&entry.path(), "open-runtime-journal")
            .map_err(migration_guard_error)?;
        inspect_runtime_journal_directory(
            &root,
            false,
            cleanup_keys.as_ref(),
            &mut entries,
            &mut bytes,
        )
        .map_err(|_| PreparedResultJournalError::RecoveryRequired)?;
    }
    Ok(terminal_orphans)
}

fn inspect_runtime_journal_directory(
    root: &crate::anchored_fs::AnchoredDirectory,
    orphan: bool,
    cleanup_keys: Option<&std::collections::BTreeSet<String>>,
    entries: &mut usize,
    bytes: &mut u64,
) -> Result<(), PreparedResultJournalError> {
    let anchored = root.anchored_path();
    let terminal_orphan = orphan
        && root
            .path()
            .file_name()
            .and_then(crate::anchored_fs::removal_original_name)
            .is_some();
    let orphan_receipt = if orphan {
        crate::operational_state_migration::receipt::load_phase_receipt(
            root,
            ORPHAN_CLEANUP_RECEIPT,
            ORPHAN_CLEANUP_OUTPUT_SCHEMA,
        )
        .map_err(|_| PreparedResultJournalError::RecoveryRequired)?
    } else {
        None
    };
    let mut orphan_entries = Vec::new();
    let mut orphan_receipt_present = false;
    let mut orphan_receipt_pending = false;
    let mut state = false;
    let mut result = false;
    for entry in fs::read_dir(&anchored)
        .map_err(|source| io_error("read-runtime-journal", &anchored, source))?
    {
        let entry =
            entry.map_err(|source| io_error("read-runtime-journal-entry", &anchored, source))?;
        let metadata = admit_runtime_entry(entries, bytes, &entry.path())?;
        let actual_name = entry.file_name();
        if orphan
            && (actual_name == ORPHAN_CLEANUP_RECEIPT
                || actual_name == ORPHAN_CLEANUP_RECEIPT_PENDING)
        {
            if !metadata.file_type().is_file() {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            if actual_name == ORPHAN_CLEANUP_RECEIPT {
                orphan_receipt_present = true;
            } else {
                orphan_receipt_pending = true;
            }
            continue;
        }
        let name = crate::anchored_fs::removal_original_name(&actual_name)
            .unwrap_or_else(|| actual_name.clone())
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?
            .to_owned();
        if let Some(logical_name) = crate::anchored_fs::removal_original_name(&actual_name) {
            let authority = root
                .open_inventory_file(&entry.path(), "pin-runtime-removal-file")
                .map_err(migration_guard_error)?
                .ok_or(PreparedResultJournalError::InvalidDirectory)?;
            if metadata.len() != 0 {
                if !orphan {
                    return Err(PreparedResultJournalError::InvalidDirectory);
                }
            }
            if orphan && is_owned_orphan_file(&name) {
                orphan_entries.push(authority);
                continue;
            }
            let journal = root
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(PreparedResultJournalError::InvalidDirectory)?;
            let logical_name = logical_name
                .to_str()
                .ok_or(PreparedResultJournalError::InvalidDirectory)?;
            if !cleanup_keys.is_some_and(|keys| {
                keys.contains(&migration::prepared_cleanup_key(
                    journal,
                    logical_name,
                    authority.identity(),
                ))
            }) {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            continue;
        }
        if !metadata.file_type().is_file()
            || metadata.len() > runtime_journal_file_limit(&name) as u64
        {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        match name.as_str() {
            JOURNAL_STATE_FILE if !state => state = true,
            JOURNAL_RESULT_FILE if !result => result = true,
            name if orphan && is_owned_orphan_file(name) => {
                if orphan_receipt.is_some() {
                    orphan_entries.push(
                        root.open_inventory_file(&entry.path(), "pin-sealed-orphan-file")
                            .map_err(migration_guard_error)?
                            .ok_or(PreparedResultJournalError::InvalidDirectory)?,
                    );
                }
            }
            _ => return Err(PreparedResultJournalError::InvalidDirectory),
        }
    }
    if (orphan_receipt_present && orphan_receipt_pending)
        || (terminal_orphan && orphan_receipt_pending)
    {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    if terminal_orphan || !orphan_entries.is_empty() {
        validate_orphan_cleanup_receipt(
            root,
            &orphan_entries,
            orphan_receipt
                .as_ref()
                .ok_or(PreparedResultJournalError::RecoveryRequired)?,
        )?;
    }
    if !orphan && !(state && result) {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    Ok(())
}

fn sealed_prepared_cleanup_keys(
    namespace: &crate::anchored_fs::AnchoredDirectory,
) -> Result<Option<std::collections::BTreeSet<String>>, PreparedResultJournalError> {
    let Some(receipts) =
        crate::operational_state_migration::receipt::completed_receipt_directory_guarded(namespace)
            .map_err(|source| {
                io_error(
                    "open-completed-migration-receipts",
                    namespace.path(),
                    source,
                )
            })?
    else {
        return Ok(None);
    };
    let receipt = crate::operational_state_migration::receipt::load_phase_receipt(
        &receipts,
        crate::operational_state_migration::receipt::PREPARED_RECEIPT,
        migration::OUTPUT_SCHEMA,
    )
    .map_err(|_| PreparedResultJournalError::RecoveryRequired)?
    .ok_or(PreparedResultJournalError::RecoveryRequired)?;
    Ok(Some(
        receipt
            .objects
            .into_iter()
            .filter(|object| object.key.starts_with("cleanup/"))
            .map(|object| object.key)
            .collect(),
    ))
}

fn admit_runtime_entry(
    entries: &mut usize,
    bytes: &mut u64,
    path: &Path,
) -> Result<fs::Metadata, PreparedResultJournalError> {
    *entries = entries
        .checked_add(1)
        .ok_or(PreparedResultJournalError::RecoveryRequired)?;
    if *entries > crate::operational_state_migration::MAX_OPERATIONAL_STATE_RUNTIME_ENTRIES {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("bound-runtime-journal-entry", path, source))?;
    *bytes = bytes
        .checked_add(metadata.len())
        .ok_or(PreparedResultJournalError::RecoveryRequired)?;
    let maximum = crate::operational_state_migration::MAX_OPERATIONAL_STATE_RUNTIME_ENTRIES as u64
        * (MAX_PREPARED_SEMANTIC_RESULT_BYTES as u64 + MAX_JOURNAL_STATE_BYTES as u64);
    if *bytes > maximum {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    Ok(metadata)
}

fn runtime_journal_file_limit(name: &str) -> usize {
    if name == JOURNAL_RESULT_FILE || name.starts_with(&format!(".{JOURNAL_RESULT_FILE}.")) {
        MAX_PREPARED_SEMANTIC_RESULT_BYTES
    } else {
        MAX_JOURNAL_STATE_BYTES
    }
}

#[cfg(test)]
thread_local! {
    static JOURNAL_RACE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn install_journal_race_hook(hook: impl FnOnce() + 'static) {
    JOURNAL_RACE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_journal_race_hook() {
    JOURNAL_RACE_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
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
mod tests;
