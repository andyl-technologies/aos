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
//! ```
//!
//! The result contains the complete typed observation/finding closure. State
//! binds its hash and exact publication IDs to the lineage, attempt, and
//! versioned execution scope. The complete pair remains hidden until the
//! operational ledger grants `Publishing`, then one rename makes it visible.
//! A visible directory
//! without both authenticated files is incomplete and fails closed; recovery
//! must inspect the operational ledger before deciding whether such a pre-stage
//! orphan may be removed.
//!
//! ```text
//! state-v2 := magic, key-digest, lineage, attempt, scope, execution,
//!             payload-limit, observation, measurement-evidence-count,
//!             measurement-evidence-set-hash, finding-present, [finding],
//!             payload-length, payload-hash, state-checksum
//! result-v2 := prepared-semantic-attempt-result-v7
//! ```
//!
//! State is bounded at 16 KiB. The result has both the format ceiling and the
//! smaller operational ceiling authenticated in state. Noncurrent file pairs fail
//! closed at ordinary journal open.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crucible_campaign::{AttemptExecutionScope, ExecutionId};

use crate::owned_advisory_lock::OwnedAdvisoryLock;
use crate::{
    AttemptExecutionKey, MAX_PREPARED_SEMANTIC_RESULT_BYTES, PreparedSemanticAttemptResult,
    PreparedSemanticResultCodecError,
};

const JOURNAL_LOCK_PREFIX: &str = ".lock-";
const JOURNAL_OWNER_LOCK: &str = ".lock-runtime-owner";
const JOURNAL_STAGED_PREFIX: &str = ".staged-";
const JOURNAL_RESULT_FILE: &str = "result-v2";
const JOURNAL_STATE_FILE: &str = "state-v2";
const JOURNAL_STATE_MAGIC_V2: &[u8] = b"crucible.executor.prepared-result-journal-state.v2\0";
const JOURNAL_STATE_HASH_DOMAIN_V2: &str = "crucible.executor.prepared-result-journal-state.v2";
const JOURNAL_MEASUREMENT_EVIDENCE_HASH_DOMAIN: &str =
    "crucible.executor.prepared-result-journal-measurement-evidence.v1";
const MAX_JOURNAL_STATE_BYTES: usize = 16 * 1024;
const MAX_ORPHAN_DIRECTORY_ENTRIES: usize = 4;
const MAX_RUNTIME_JOURNAL_ENTRIES: usize = 1_000_000;

static JOURNAL_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Descriptor-bound process authority for one prepared-result namespace.
///
/// Construction acquires the namespace's single-owner lease and validates its
/// complete current-format inventory before any worker can use it.
#[derive(Clone, Debug)]
pub struct PreparedResultJournalNamespace {
    runtime: Arc<PreparedResultJournalRuntime>,
}

#[derive(Debug)]
struct PreparedResultJournalRuntime {
    directory: crate::anchored_fs::AnchoredDirectory,
    owner_lock: OwnedAdvisoryLock,
}

impl PreparedResultJournalNamespace {
    /// Opens and validates one exact v2/v6 runtime namespace.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] if the directory or owner lock is
    /// replaced, another process owns it, or any entry is malformed, unsupported,
    /// unbounded, or outside the current journal layout.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PreparedResultJournalError> {
        let path = path.as_ref();
        validate_namespace(path)?;
        let canonical = fs::canonicalize(path)
            .map_err(|source| io_error("canonicalize-journal-namespace", path, source))?;
        let directory = crate::anchored_fs::AnchoredDirectory::open(canonical)
            .map_err(|source| anchored_journal_error(source, "open-journal-namespace"))?;
        let lock_path = directory.path().join(JOURNAL_OWNER_LOCK);
        let lock = directory
            .open_or_create_regular(&lock_path, "open-journal-owner-lock")
            .map_err(|source| anchored_journal_error(source, "open-journal-owner-lock"))?;
        let owner_lock = OwnedAdvisoryLock::try_exclusive_bound(lock)
            .map_err(|source| anchored_journal_error(source, "lock-journal-namespace"))?;
        validate_runtime_namespace(&directory)?;
        directory
            .verify_path_binding()
            .map_err(|source| anchored_journal_error(source, "verify-journal-namespace"))?;

        Ok(Self {
            runtime: Arc::new(PreparedResultJournalRuntime {
                directory,
                owner_lock,
            }),
        })
    }

    fn root(&self) -> PathBuf {
        self.runtime.directory.path().to_owned()
    }

    fn verify(&self) -> Result<(), PreparedResultJournalError> {
        self.runtime
            .owner_lock
            .verify_path_binding()
            .map_err(|source| anchored_journal_error(source, "verify-journal-owner-lock"))?;
        self.runtime
            .directory
            .verify_path_binding()
            .map_err(|source| anchored_journal_error(source, "verify-journal-namespace"))
    }
}

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
    /// Whether an incomplete visible directory was removed.
    pub visible_removed: bool,
    /// Whether a pre-publication staging directory was removed.
    pub staged_removed: bool,
}

/// Exclusive authenticated owner of one prepared semantic result journal.
#[derive(Debug)]
pub struct DirectoryPreparedResultJournal {
    namespace: PreparedResultJournalNamespace,
    root: PathBuf,
    root_authority: crate::anchored_fs::AnchoredDirectory,
    key: AttemptExecutionKey,
    execution: ExecutionId,
    maximum_payload_bytes: usize,
    result: PreparedSemanticAttemptResult,
    namespace_lock: OwnedAdvisoryLock,
    staged: bool,
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

    /// Durably prepares a hidden journal without granting publication authority.
    ///
    /// The caller must commit the operational ledger's `Publishing` state before
    /// calling [`Self::commit_staged`]. An exact existing hidden or visible
    /// journal is reopened idempotently.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when the namespace, result,
    /// journal identity, lock, or durable write is invalid.
    pub(crate) fn prepare_staged(
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        maximum_payload_bytes: usize,
        result: PreparedSemanticAttemptResult,
    ) -> Result<(Self, PreparedResultJournalCreateDisposition), PreparedResultJournalError> {
        namespace.verify()?;
        let namespace_root = namespace.root();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        validate_result_key(key, &result)?;
        let namespace_lock = acquire_namespace_lock(namespace, key)?;
        let root = journal_path(&namespace_root, key);
        let staging = staged_path(&namespace_root, key);
        let root_present = directory_presence(
            &namespace.runtime.directory,
            &root,
            "inspect-journal-before-create",
        )?;
        let staging_present = directory_presence(
            &namespace.runtime.directory,
            &staging,
            "inspect-staged-journal-before-create",
        )?;
        if root_present && staging_present {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
        if root_present {
            let journal = Self::open_locked(
                namespace.clone(),
                root,
                key,
                Some(execution),
                maximum_payload_bytes,
                namespace_lock,
                false,
            )?;
            if journal.result != result {
                return Err(PreparedResultJournalError::ResultMismatch);
            }
            return Ok((journal, PreparedResultJournalCreateDisposition::Existing));
        }
        if staging_present {
            let journal = match Self::open_locked(
                namespace.clone(),
                staging,
                key,
                Some(execution),
                maximum_payload_bytes,
                namespace_lock,
                true,
            ) {
                Ok(journal) => journal,
                Err(source @ PreparedResultJournalError::Io { .. }) => return Err(source),
                Err(_) => return Err(PreparedResultJournalError::RecoveryRequired),
            };
            if journal.result != result {
                return Err(PreparedResultJournalError::ResultMismatch);
            }
            return Ok((journal, PreparedResultJournalCreateDisposition::Existing));
        }
        let payload = result.canonical_bytes_with_limit(maximum_payload_bytes)?;
        let state = encode_state(key, execution, maximum_payload_bytes, &result, &payload)?;
        let root_authority = create_staging_directory(namespace, key)?;
        initialize_new(&root_authority, &payload, &state)?;
        namespace.verify()?;
        Ok((
            Self {
                namespace: namespace.clone(),
                root: staging,
                root_authority,
                key,
                execution,
                maximum_payload_bytes,
                result,
                namespace_lock,
                staged: true,
            },
            PreparedResultJournalCreateDisposition::Created,
        ))
    }

    /// Makes a prepared journal visible after the ledger grants publication.
    ///
    /// Repeating the operation on an already visible journal is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when authority was replaced, a
    /// conflicting visible name exists, or the rename cannot be made durable.
    pub(crate) fn commit_staged(&mut self) -> Result<(), PreparedResultJournalError> {
        if !self.staged {
            self.namespace.verify()?;
            self.root_authority
                .verify_path_binding()
                .map_err(|source| anchored_journal_error(source, "verify-visible-journal"))?;
            return Ok(());
        }

        self.namespace.verify()?;
        self.namespace_lock
            .verify_path_binding()
            .map_err(|source| anchored_journal_error(source, "verify-journal-key-lock"))?;
        let namespace_authority = &self.namespace.runtime.directory;
        let visible = journal_path(&self.namespace.root(), self.key);
        let staged_present = directory_presence(
            namespace_authority,
            &self.root,
            "inspect-staged-journal-before-commit",
        )?;
        let visible_present = directory_presence(
            namespace_authority,
            &visible,
            "inspect-visible-journal-before-commit",
        )?;
        let committed = match (staged_present, visible_present) {
            (true, false) => namespace_authority
                .rename_directory(
                    &self.root_authority,
                    &visible,
                    true,
                    "commit-staged-journal",
                )
                .map_err(|source| anchored_journal_error(source, "commit-staged-journal"))?,
            (false, true) => namespace_authority
                .open_directory(&visible, "open-committed-journal")
                .map_err(|source| anchored_journal_error(source, "open-committed-journal"))?,
            (true, true) | (false, false) => {
                return Err(PreparedResultJournalError::RecoveryRequired);
            }
        };
        namespace_authority
            .sync()
            .map_err(|source| anchored_journal_error(source, "sync-journal-after-commit"))?;
        if committed.identity() != self.root_authority.identity() {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }

        self.root = visible;
        self.root_authority = committed;
        self.staged = false;
        self.namespace.verify()
    }

    /// Opens and authenticates the complete journal for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when the expected directory is
    /// incomplete, malformed, corrupt, locked, or bound to different result
    /// IDs or execution-key material.
    pub fn open(
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        maximum_payload_bytes: usize,
    ) -> Result<Self, PreparedResultJournalError> {
        namespace.verify()?;
        let namespace_root = namespace.root();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        let namespace_lock = acquire_namespace_lock(namespace, key)?;
        let root = journal_path(&namespace_root, key);
        Self::open_locked(
            namespace.clone(),
            root,
            key,
            Some(execution),
            maximum_payload_bytes,
            namespace_lock,
            false,
        )
    }

    /// Opens a hidden journal for restart reconciliation against the ledger.
    ///
    /// Absence is distinct from malformed or conflicting visible state.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedResultJournalError`] when authority, locking, state,
    /// or exact v2/v6 result authentication fails.
    pub(crate) fn open_staged_for_recovery(
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
        maximum_payload_bytes: usize,
    ) -> Result<Option<Self>, PreparedResultJournalError> {
        namespace.verify()?;
        let namespace_root = namespace.root();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        let namespace_lock = acquire_namespace_lock(namespace, key)?;
        let staged = staged_path(&namespace_root, key);
        if !directory_presence(
            &namespace.runtime.directory,
            &staged,
            "inspect-staged-journal-for-recovery",
        )? {
            return Ok(None);
        }
        if directory_presence(
            &namespace.runtime.directory,
            &journal_path(&namespace_root, key),
            "inspect-visible-journal-beside-staged",
        )? {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
        Self::open_locked(
            namespace.clone(),
            staged,
            key,
            None,
            maximum_payload_bytes,
            namespace_lock,
            true,
        )
        .map(Some)
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
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
        maximum_payload_bytes: usize,
    ) -> Result<Option<Self>, PreparedResultJournalError> {
        namespace.verify()?;
        let namespace_root = namespace.root();
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        let namespace_lock = acquire_namespace_lock(namespace, key)?;
        let root = journal_path(&namespace_root, key);
        if !directory_presence(
            &namespace.runtime.directory,
            &root,
            "inspect-journal-for-recovery",
        )? {
            if directory_presence(
                &namespace.runtime.directory,
                &staged_path(&namespace_root, key),
                "inspect-staged-journal-for-recovery",
            )? {
                return Err(PreparedResultJournalError::RecoveryRequired);
            }
            return Ok(None);
        }
        Self::open_locked(
            namespace.clone(),
            root,
            key,
            None,
            maximum_payload_bytes,
            namespace_lock,
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
        namespace.verify()?;
        let namespace_root = namespace.root();
        validate_semantic_key(key)?;

        Ok(directory_presence(
            &namespace.runtime.directory,
            &journal_path(&namespace_root, key),
            "inventory-prepared-result-journal",
        )? || directory_presence(
            &namespace.runtime.directory,
            &staged_path(&namespace_root, key),
            "inventory-staged-prepared-result-journal",
        )?)
    }

    fn open_locked(
        namespace: PreparedResultJournalNamespace,
        root: PathBuf,
        key: AttemptExecutionKey,
        expected_execution: Option<ExecutionId>,
        maximum_payload_bytes: usize,
        namespace_lock: OwnedAdvisoryLock,
        staged: bool,
    ) -> Result<Self, PreparedResultJournalError> {
        namespace.verify()?;
        let root_authority = namespace
            .runtime
            .directory
            .open_directory(&root, "open-journal-directory")
            .map_err(|source| anchored_journal_error(source, "open-journal-directory"))?;
        root_authority
            .sync()
            .map_err(|source| anchored_journal_error(source, "sync-journal-directory-on-open"))?;
        namespace
            .runtime
            .directory
            .sync()
            .map_err(|source| anchored_journal_error(source, "sync-journal-parent-on-open"))?;

        let mut journal_entries = 0;
        validate_runtime_journal_directory(&root_authority, false, &mut journal_entries)?;
        let state = read_bounded_file(
            &root_authority,
            &root.join(JOURNAL_STATE_FILE),
            MAX_JOURNAL_STATE_BYTES,
            "read-journal-state",
        )?;
        let envelope = decode_state(&state, key, expected_execution, maximum_payload_bytes)?;
        let payload = read_bounded_file(
            &root_authority,
            &root.join(JOURNAL_RESULT_FILE),
            maximum_payload_bytes,
            "read-journal-result",
        )?;
        envelope.validate_payload(&payload)?;
        let result = PreparedSemanticAttemptResult::from_canonical_bytes_with_limit(
            &payload,
            maximum_payload_bytes,
        )?;
        envelope.validate_result(&result)?;
        validate_result_key(key, &result)?;
        namespace_lock
            .verify_path_binding()
            .map_err(|source| anchored_journal_error(source, "verify-journal-key-lock"))?;
        root_authority
            .verify_path_binding()
            .map_err(|source| anchored_journal_error(source, "verify-journal-directory"))?;
        namespace.verify()?;

        Ok(Self {
            namespace,
            root,
            root_authority,
            key,
            execution: envelope.execution,
            maximum_payload_bytes,
            result,
            namespace_lock,
            staged,
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

    /// Returns the complete prepared publication value.
    #[must_use]
    pub const fn result(&self) -> &PreparedSemanticAttemptResult {
        &self.result
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
        self.namespace.verify()?;
        self.namespace_lock
            .verify_path_binding()
            .map_err(|source| anchored_journal_error(source, "verify-journal-key-lock"))?;
        remove_orphan_directory(
            &self.namespace,
            &self.root,
            Some(self.root_authority.identity()),
        )?;
        self.namespace
            .runtime
            .directory
            .sync()
            .map_err(|source| anchored_journal_error(source, "sync-journal-parent-after-remove"))?;
        self.namespace.verify()
    }

    /// Removes at most the fixed visible and staged orphans for `key`.
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
        namespace: &PreparedResultJournalNamespace,
        key: AttemptExecutionKey,
    ) -> Result<PreparedResultJournalCleanupDisposition, PreparedResultJournalError> {
        namespace.verify()?;
        let namespace_root = namespace.root();
        validate_semantic_key(key)?;
        let namespace_lock = acquire_namespace_lock(namespace, key)?;
        let visible_removed =
            remove_orphan_directory(namespace, &journal_path(&namespace_root, key), None)?;
        let staged_removed =
            remove_orphan_directory(namespace, &staged_path(&namespace_root, key), None)?;
        // Retry the durability barrier even when a prior call removed the
        // names and failed its parent sync.
        namespace.runtime.directory.sync().map_err(|source| {
            anchored_journal_error(source, "sync-journal-parent-after-cleanup")
        })?;
        namespace.verify()?;
        drop(namespace_lock);
        Ok(PreparedResultJournalCleanupDisposition {
            visible_removed,
            staged_removed,
        })
    }
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
    /// A fixed visible or staging name requires ledger-authorized recovery.
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

fn create_staging_directory(
    namespace: &PreparedResultJournalNamespace,
    key: AttemptExecutionKey,
) -> Result<crate::anchored_fs::AnchoredDirectory, PreparedResultJournalError> {
    let staging = staged_path(&namespace.root(), key);
    namespace
        .runtime
        .directory
        .create_new_directory(&staging, "create-journal-staging-directory")
        .map_err(|source| match source {
            crate::anchored_fs::AnchoredFsError::Io { ref source, .. }
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                PreparedResultJournalError::RecoveryRequired
            }
            source => anchored_journal_error(source, "create-journal-staging-directory"),
        })
}

fn initialize_new(
    root: &crate::anchored_fs::AnchoredDirectory,
    payload: &[u8],
    state: &[u8],
) -> Result<(), PreparedResultJournalError> {
    write_atomic(root, JOURNAL_RESULT_FILE, payload)?;
    write_atomic(root, JOURNAL_STATE_FILE, state)?;
    root.sync()
        .map_err(|source| anchored_journal_error(source, "sync-journal-directory-after-initialize"))
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

fn directory_presence(
    namespace: &crate::anchored_fs::AnchoredDirectory,
    path: &Path,
    operation: &'static str,
) -> Result<bool, PreparedResultJournalError> {
    namespace
        .open_directory_optional(path, operation)
        .map(|directory| directory.is_some())
        .map_err(|source| anchored_journal_error(source, operation))
}

fn remove_orphan_directory(
    namespace: &PreparedResultJournalNamespace,
    root: &Path,
    expected_identity: Option<(u64, u64)>,
) -> Result<bool, PreparedResultJournalError> {
    namespace.verify()?;
    let Some(root_authority) = namespace
        .runtime
        .directory
        .open_directory_optional(root, "open-journal-orphan")
        .map_err(|source| anchored_journal_error(source, "open-journal-orphan"))?
    else {
        return Ok(false);
    };
    if expected_identity.is_some_and(|expected| expected != root_authority.identity()) {
        return Err(PreparedResultJournalError::RecoveryRequired);
    }
    let mut entries = Vec::new();
    for name in root_authority
        .entry_names(MAX_ORPHAN_DIRECTORY_ENTRIES + 1, "read-journal-orphan")
        .map_err(|source| anchored_journal_error(source, "read-journal-orphan"))?
    {
        let name = name
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        if entries.len() == MAX_ORPHAN_DIRECTORY_ENTRIES || !is_owned_orphan_file(name) {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        let file = root_authority
            .open_regular_optional(&root.join(name), "open-journal-orphan-file")
            .map_err(|source| anchored_journal_error(source, "open-journal-orphan-file"))?
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        entries.push(file);
    }
    for entry in entries {
        root_authority
            .remove_file(&entry, "remove-journal-orphan-file")
            .map_err(|source| anchored_journal_error(source, "remove-journal-orphan-file"))?;
    }
    namespace
        .runtime
        .directory
        .remove_directory(&root_authority, "remove-journal-directory")
        .map_err(|source| anchored_journal_error(source, "remove-journal-directory"))?;
    namespace.verify()?;
    Ok(true)
}

fn is_owned_orphan_file(name: &str) -> bool {
    name == JOURNAL_STATE_FILE
        || name == JOURNAL_RESULT_FILE
        || is_current_temporary_name(name, JOURNAL_STATE_FILE)
        || is_current_temporary_name(name, JOURNAL_RESULT_FILE)
}

fn write_atomic(
    root: &crate::anchored_fs::AnchoredDirectory,
    name: &str,
    bytes: &[u8],
) -> Result<(), PreparedResultJournalError> {
    let temporary = loop {
        let suffix = JOURNAL_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = root
            .path()
            .join(format!(".{name}.{}.{}", std::process::id(), suffix));
        match root.create_new_regular(&path, "create-journal-temporary") {
            Ok(file) => break file,
            Err(crate::anchored_fs::AnchoredFsError::Io { ref source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(source) => {
                return Err(anchored_journal_error(source, "create-journal-temporary"));
            }
        }
    };
    temporary
        .write_all_sync(bytes)
        .map_err(|source| anchored_journal_error(source, "write-journal-temporary"))?;
    let destination = root.path().join(name);
    root.rename_file(&temporary, &destination, true, "publish-journal-file")
        .map_err(|source| anchored_journal_error(source, "publish-journal-file"))?;
    root.sync()
        .map_err(|source| anchored_journal_error(source, "sync-journal-directory-after-file"))
}

fn read_bounded_file(
    root: &crate::anchored_fs::AnchoredDirectory,
    path: &Path,
    maximum: usize,
    operation: &'static str,
) -> Result<Vec<u8>, PreparedResultJournalError> {
    let file = root
        .open_regular_optional(path, operation)
        .map_err(|source| anchored_journal_error(source, operation))?
        .ok_or(PreparedResultJournalError::Incomplete)?;
    let length = file
        .length()
        .map_err(|source| anchored_journal_error(source, operation))?;
    if length > maximum as u64 {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let bytes = file
        .read_bounded(maximum as u64)
        .map_err(|source| anchored_journal_error(source, operation))?;
    if bytes.len() > maximum {
        return Err(PreparedResultJournalError::InvalidState);
    }
    file.verify_path_binding()
        .map_err(|source| anchored_journal_error(source, operation))?;
    root.verify_path_binding()
        .map_err(|source| anchored_journal_error(source, operation))?;
    Ok(bytes)
}

fn acquire_namespace_lock(
    namespace: &PreparedResultJournalNamespace,
    key: AttemptExecutionKey,
) -> Result<OwnedAdvisoryLock, PreparedResultJournalError> {
    namespace.verify()?;
    let path = namespace_lock_path(namespace.runtime.directory.path(), key);
    let lock = namespace
        .runtime
        .directory
        .open_or_create_regular(&path, "open-journal-key-lock")
        .map_err(|source| anchored_journal_error(source, "open-journal-key-lock"))?;
    OwnedAdvisoryLock::try_exclusive_bound(lock)
        .map_err(|source| anchored_journal_error(source, "lock-journal-key"))
}

fn anchored_journal_error(
    source: crate::anchored_fs::AnchoredFsError,
    operation: &'static str,
) -> PreparedResultJournalError {
    let (operation, path, source) = source.into_io_parts(operation);
    io_error(operation, &path, source)
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

fn validate_runtime_namespace(
    namespace: &crate::anchored_fs::AnchoredDirectory,
) -> Result<(), PreparedResultJournalError> {
    let root = namespace.path().to_owned();
    let mut entry_count = 0usize;
    let mut journal_keys = std::collections::BTreeSet::new();
    for entry_name in namespace
        .entry_names(
            MAX_RUNTIME_JOURNAL_ENTRIES,
            "read-runtime-journal-namespace",
        )
        .map_err(|source| anchored_journal_error(source, "read-runtime-journal-namespace"))?
    {
        entry_count = entry_count
            .checked_add(1)
            .ok_or(PreparedResultJournalError::RecoveryRequired)?;
        if entry_count > MAX_RUNTIME_JOURNAL_ENTRIES {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
        let name = entry_name
            .into_string()
            .map_err(|_| PreparedResultJournalError::InvalidDirectory)?;
        let path = root.join(&name);

        if name == JOURNAL_OWNER_LOCK {
            validate_runtime_lock(namespace, &path)?;
            continue;
        }
        if let Some(digest) = name.strip_prefix(JOURNAL_LOCK_PREFIX) {
            if !is_lower_hex(digest, 64) {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            validate_runtime_lock(namespace, &path)?;
            continue;
        }

        let (digest, incomplete) = if is_lower_hex(&name, 64) {
            (name.as_str(), false)
        } else if let Some(digest) = name.strip_prefix(JOURNAL_STAGED_PREFIX) {
            (digest, true)
        } else {
            return Err(PreparedResultJournalError::InvalidDirectory);
        };
        if !is_lower_hex(digest, 64) || !journal_keys.insert(digest.to_owned()) {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
        let journal = namespace
            .open_directory(&path, "open-runtime-journal-entry")
            .map_err(|source| anchored_journal_error(source, "open-runtime-journal-entry"))?;
        validate_runtime_journal_directory(&journal, incomplete, &mut entry_count)?;
    }
    Ok(())
}

fn validate_runtime_lock(
    namespace: &crate::anchored_fs::AnchoredDirectory,
    path: &Path,
) -> Result<(), PreparedResultJournalError> {
    let lock = namespace
        .open_regular_optional(path, "open-runtime-journal-lock")
        .map_err(|source| anchored_journal_error(source, "open-runtime-journal-lock"))?
        .ok_or(PreparedResultJournalError::InvalidDirectory)?;
    let length = lock
        .length()
        .map_err(|source| anchored_journal_error(source, "inspect-runtime-journal-lock"))?;
    if length == 0 {
        Ok(())
    } else {
        Err(PreparedResultJournalError::InvalidDirectory)
    }
}

fn validate_runtime_journal_directory(
    journal: &crate::anchored_fs::AnchoredDirectory,
    incomplete: bool,
    total_entries: &mut usize,
) -> Result<(), PreparedResultJournalError> {
    let root = journal.path().to_owned();
    let mut result_present = false;
    let mut state_present = false;
    let mut local_entries = 0usize;
    for entry_name in journal
        .entry_names(
            MAX_ORPHAN_DIRECTORY_ENTRIES + 1,
            "read-runtime-journal-directory",
        )
        .map_err(|source| anchored_journal_error(source, "read-runtime-journal-directory"))?
    {
        local_entries += 1;
        *total_entries = total_entries
            .checked_add(1)
            .ok_or(PreparedResultJournalError::RecoveryRequired)?;
        if local_entries > MAX_ORPHAN_DIRECTORY_ENTRIES
            || *total_entries > MAX_RUNTIME_JOURNAL_ENTRIES
        {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
        let name = entry_name
            .into_string()
            .map_err(|_| PreparedResultJournalError::InvalidDirectory)?;
        let maximum = if name == JOURNAL_RESULT_FILE {
            result_present = true;
            MAX_PREPARED_SEMANTIC_RESULT_BYTES
        } else if name == JOURNAL_STATE_FILE {
            state_present = true;
            MAX_JOURNAL_STATE_BYTES
        } else if incomplete && is_current_temporary_name(&name, JOURNAL_RESULT_FILE) {
            MAX_PREPARED_SEMANTIC_RESULT_BYTES
        } else if incomplete && is_current_temporary_name(&name, JOURNAL_STATE_FILE) {
            MAX_JOURNAL_STATE_BYTES
        } else {
            return Err(PreparedResultJournalError::InvalidDirectory);
        };
        let file = journal
            .open_regular_optional(&root.join(&name), "open-runtime-journal-file")
            .map_err(|source| anchored_journal_error(source, "open-runtime-journal-file"))?
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        if file
            .length()
            .map_err(|source| anchored_journal_error(source, "inspect-runtime-journal-file"))?
            > maximum as u64
        {
            return Err(PreparedResultJournalError::InvalidState);
        }
    }
    if !incomplete && (!result_present || !state_present || local_entries != 2) {
        return Err(PreparedResultJournalError::Incomplete);
    }
    Ok(())
}

fn is_current_temporary_name(name: &str, stable: &str) -> bool {
    let Some(suffix) = name.strip_prefix(&format!(".{stable}.")) else {
        return false;
    };
    let Some((process, ordinal)) = suffix.split_once('.') else {
        return false;
    };
    !process.is_empty()
        && process.bytes().all(|byte| byte.is_ascii_digit())
        && !ordinal.is_empty()
        && ordinal.bytes().all(|byte| byte.is_ascii_digit())
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

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- journal tests use panic shortcuts for precise fixture failures.
    #![allow(clippy::expect_used)]

    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, symlink};

    use crucible::VirtualTime;
    use crucible::model::{MeasurementDefinitions, MeasurementTerminalState};
    use crucible_campaign::{
        AttemptExecutionScope, AttemptId, BranchPathId, CampaignFactId, CampaignHash,
        CampaignLineageId, ConfigurationArtifact, ConfigurationId, CoverageProjection, ExecutionId,
        MeasurementSet, Observation, ObservationCandidate, PropertyVerdictSet, ScenarioArtifactId,
        ScenarioDefId, StopOutcome,
    };
    use crucible_cas::content_store::{ContentId, ObjectKind};
    use tempfile::TempDir;

    use crate::{
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES, evaluate_crucible_measurement_publication,
    };

    use super::*;

    const TEST_PAYLOAD_LIMIT: usize = 1024 * 1024;

    #[test]
    fn journal_create_reopen_authenticate_and_remove_are_exact() {
        let namespace = TempDir::new().expect("journal namespace");
        let runtime = PreparedResultJournalNamespace::open(namespace.path()).expect("runtime");
        let key = semantic_key(b"main");
        let execution = ExecutionId::from_bytes([0x51; 16]).expect("execution");
        let result = observation_result(0x61, key.attempt());

        let (journal, disposition) = DirectoryPreparedResultJournal::create(
            &runtime,
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
            DirectoryPreparedResultJournal::open(&runtime, key, execution, TEST_PAYLOAD_LIMIT,),
            Err(PreparedResultJournalError::Io {
                operation: "lock-file",
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

        let failed_open_lock = acquire_namespace_lock(&runtime, key)
            .expect("acquire lock for failed authenticated open");
        let retained_failed_open_description = failed_open_lock
            .file()
            .try_clone()
            .expect("duplicate failed-open lock descriptor");
        assert!(matches!(
            DirectoryPreparedResultJournal::open_locked(
                runtime.clone(),
                root.clone(),
                key,
                Some(ExecutionId::from_bytes([0x52; 16]).expect("other execution")),
                TEST_PAYLOAD_LIMIT,
                failed_open_lock,
                false,
            ),
            Err(PreparedResultJournalError::InvalidState)
        ));
        let reopened_after_failure =
            DirectoryPreparedResultJournal::open(&runtime, key, execution, TEST_PAYLOAD_LIMIT)
                .expect("failed authenticated open releases retained lock description");
        drop(reopened_after_failure);
        drop(retained_failed_open_description);
        assert!(matches!(
            DirectoryPreparedResultJournal::open(&runtime, key, execution, TEST_PAYLOAD_LIMIT / 2,),
            Err(PreparedResultJournalError::InvalidState)
        ));

        let (journal, disposition) = DirectoryPreparedResultJournal::create(
            &runtime,
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
                &runtime,
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                observation_result(0x62, key.attempt()),
            ),
            Err(PreparedResultJournalError::ResultMismatch)
        ));

        let journal =
            DirectoryPreparedResultJournal::open(&runtime, key, execution, TEST_PAYLOAD_LIMIT)
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
            &runtime,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result,
        )
        .expect("recreate journal after removal");
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
    fn journal_v2_owns_raw_measurement_leaf() {
        let namespace = TempDir::new().expect("journal namespace");
        let runtime = PreparedResultJournalNamespace::open(namespace.path()).expect("runtime");
        let key = semantic_key(b"measurement-evidence");
        let execution = ExecutionId::from_bytes([0x63; 16]).expect("execution");
        let result = measurement_result(0x64, key.attempt());
        let payload = result
            .canonical_bytes_with_limit(TEST_PAYLOAD_LIMIT)
            .expect("v2 prepared result");

        let (journal, disposition) = DirectoryPreparedResultJournal::create(
            &runtime,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result.clone(),
        )
        .expect("create v2 journal");
        assert_eq!(disposition, PreparedResultJournalCreateDisposition::Created);
        assert_eq!(journal.result(), &result);
        assert_eq!(journal.result().measurement_replay_evidence().len(), 1);
        assert_eq!(
            fs::read(journal.root().join(JOURNAL_RESULT_FILE)).expect("v2 payload"),
            payload
        );
        assert_eq!(
            blake3::hash(&payload).to_hex().as_str(),
            "cd69f331dd3299f67b9b4c293edd9c8dd1c3b9d3f4dc173afabcc741d3c19daa"
        );
        let state = fs::read(journal.root().join(JOURNAL_STATE_FILE)).expect("v2 state");
        assert_eq!(
            blake3::hash(&state).to_hex().as_str(),
            "ad3c60c271c1441a76a22096a1cb1ad21754571b9a45b58c630023906394f2ba"
        );
        journal.remove().expect("remove v2 journal");
    }

    #[test]
    fn journal_rejects_corrupt_incomplete_and_nonsemantic_state() {
        let namespace = TempDir::new().expect("journal namespace");
        let runtime = PreparedResultJournalNamespace::open(namespace.path()).expect("runtime");
        let key = semantic_key(b"corrupt");
        let execution = ExecutionId::from_bytes([0x71; 16]).expect("execution");
        let (journal, _) = DirectoryPreparedResultJournal::create(
            &runtime,
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
            DirectoryPreparedResultJournal::open(&runtime, key, execution, TEST_PAYLOAD_LIMIT,),
            Err(PreparedResultJournalError::InvalidState)
        ));

        let incomplete_namespace = TempDir::new().expect("incomplete namespace");
        fs::create_dir(journal_path(incomplete_namespace.path(), key))
            .expect("incomplete journal directory");
        assert!(matches!(
            PreparedResultJournalNamespace::open(incomplete_namespace.path()),
            Err(PreparedResultJournalError::Incomplete)
        ));

        let request = CampaignFactId::parse(&typed_content_text(
            "crucible.campaign.fact",
            ObjectKind::CampaignFact,
            15,
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
                &runtime,
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
        let runtime = PreparedResultJournalNamespace::open(namespace.path()).expect("runtime");
        let key = semantic_key(b"attempt-binding");
        let other = semantic_key(b"other-attempt").attempt();
        let execution = ExecutionId::from_bytes([0x81; 16]).expect("execution");

        assert!(matches!(
            DirectoryPreparedResultJournal::create(
                &runtime,
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
            1
        );
    }

    #[test]
    fn ledger_gated_cleanup_recovers_fixed_partial_staging_and_visible_removal() {
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(b"orphan-recovery");
        let execution = ExecutionId::from_bytes([0x91; 16]).expect("execution");
        let result = observation_result(0x92, key.attempt());

        let staged = staged_path(namespace.path(), key);
        fs::create_dir(&staged).expect("partial staging directory");
        fs::write(staged.join(JOURNAL_RESULT_FILE), b"partial").expect("partial result");
        fs::write(staged.join(".state-v2.123.0"), b"partial")
            .expect("partial atomic state temporary");
        let runtime = PreparedResultJournalNamespace::open(namespace.path()).expect("runtime");
        assert!(matches!(
            DirectoryPreparedResultJournal::create(
                &runtime,
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                result.clone(),
            ),
            Err(PreparedResultJournalError::RecoveryRequired)
        ));
        let cleaned =
            DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(&runtime, key)
                .expect("clean partial staging");
        assert_eq!(
            cleaned,
            PreparedResultJournalCleanupDisposition {
                visible_removed: false,
                staged_removed: true,
            }
        );

        let (journal, _) = DirectoryPreparedResultJournal::create(
            &runtime,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            result,
        )
        .expect("create after staged cleanup");
        let root = journal.root().to_path_buf();
        drop(journal);
        fs::remove_file(root.join(JOURNAL_RESULT_FILE)).expect("simulate partial visible cleanup");

        let cleaned =
            DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(&runtime, key)
                .expect("finish partial visible removal");
        assert_eq!(
            cleaned,
            PreparedResultJournalCleanupDisposition {
                visible_removed: true,
                staged_removed: false,
            }
        );
        assert_eq!(
            DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(&runtime, key,)
                .expect("idempotent orphan cleanup"),
            PreparedResultJournalCleanupDisposition::default()
        );
    }

    #[test]
    fn hidden_journal_becomes_visible_only_after_commit() {
        let namespace = TempDir::new().expect("journal namespace");
        let runtime = PreparedResultJournalNamespace::open(namespace.path()).expect("runtime");
        let key = semantic_key(b"hidden-publication-root");
        let execution = ExecutionId::from_bytes([0x94; 16]).expect("execution");
        let visible = journal_path(&runtime.root(), key);
        let staged = staged_path(&runtime.root(), key);

        let (mut journal, disposition) = DirectoryPreparedResultJournal::prepare_staged(
            &runtime,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            observation_result(0x95, key.attempt()),
        )
        .expect("prepare hidden journal");
        assert_eq!(disposition, PreparedResultJournalCreateDisposition::Created);
        assert!(staged.is_dir());
        assert!(!visible.exists());

        journal.commit_staged().expect("commit visible journal");
        assert!(!staged.exists());
        assert!(visible.is_dir());
        journal.commit_staged().expect("repeat journal commit");
    }

    #[test]
    fn namespace_owner_and_replacement_fence_runtime_mutation() {
        let parent = TempDir::new().expect("journal parent");
        let path = parent.path().join("journals");
        fs::create_dir(&path).expect("journal namespace");
        let runtime = PreparedResultJournalNamespace::open(&path).expect("runtime");
        assert!(PreparedResultJournalNamespace::open(&path).is_err());

        let detached = parent.path().join("detached");
        fs::rename(&path, &detached).expect("detach namespace");
        fs::create_dir(&path).expect("replacement namespace");
        let key = semantic_key(b"replaced-namespace");
        assert!(
            DirectoryPreparedResultJournal::prepare_staged(
                &runtime,
                key,
                ExecutionId::from_bytes([0x96; 16]).expect("execution"),
                TEST_PAYLOAD_LIMIT,
                observation_result(0x97, key.attempt()),
            )
            .is_err()
        );
    }

    #[test]
    fn key_lock_replacement_fences_hidden_commit() {
        let namespace = TempDir::new().expect("journal namespace");
        let runtime = PreparedResultJournalNamespace::open(namespace.path()).expect("runtime");
        let key = semantic_key(b"replaced-key-lock");
        let execution = ExecutionId::from_bytes([0x98; 16]).expect("execution");
        let (mut journal, _) = DirectoryPreparedResultJournal::prepare_staged(
            &runtime,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            observation_result(0x99, key.attempt()),
        )
        .expect("prepare hidden journal");
        let lock = namespace_lock_path(namespace.path(), key);
        fs::rename(&lock, namespace.path().join("detached-key-lock")).expect("detach key lock");
        fs::write(&lock, []).expect("replacement key lock");

        assert!(journal.commit_staged().is_err());
        assert!(staged_path(&runtime.root(), key).is_dir());
        assert!(!journal_path(&runtime.root(), key).exists());
    }

    #[test]
    fn journal_rejects_a_replaced_result_child_without_external_access() {
        let namespace = TempDir::new().expect("journal namespace");
        let outside = TempDir::new().expect("outside directory");
        let runtime = PreparedResultJournalNamespace::open(namespace.path()).expect("runtime");
        let key = semantic_key(b"replaced-result-child");
        let execution = ExecutionId::from_bytes([0x9a; 16]).expect("execution");
        let (journal, _) = DirectoryPreparedResultJournal::create(
            &runtime,
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            observation_result(0x9b, key.attempt()),
        )
        .expect("create journal");
        let result_path = journal.root().join(JOURNAL_RESULT_FILE);
        let exact_bytes = fs::read(&result_path).expect("exact result bytes");
        let outside_result = outside.path().join("outside-result");
        fs::write(&outside_result, &exact_bytes).expect("outside result");
        fs::remove_file(&result_path).expect("remove journal result");
        symlink(&outside_result, &result_path).expect("replace result with symlink");
        drop(journal);

        let open_error =
            DirectoryPreparedResultJournal::open(&runtime, key, execution, TEST_PAYLOAD_LIMIT)
                .expect_err("reject result symlink");
        let cleanup_error =
            DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(&runtime, key)
                .expect_err("reject result symlink before cleanup");
        for error in [open_error, cleanup_error] {
            let PreparedResultJournalError::Io { source, .. } = error else {
                panic!("result symlink must fail during descriptor-relative resolution");
            };
            assert_eq!(
                source.raw_os_error(),
                Some(rustix::io::Errno::LOOP.raw_os_error())
            );
        }
        assert_eq!(
            fs::read(&outside_result).expect("outside result remains"),
            exact_bytes
        );
    }

    #[test]
    fn runtime_namespace_rejects_unknown_entries() {
        for name in [
            "unexpected-visible-entry",
            ".unexpected-hidden-entry",
            ".collision-0000000000000000000000000000000000000000000000000000000000000000",
            "UnexpectedEntry",
        ] {
            let namespace = TempDir::new().expect("journal namespace");
            fs::write(namespace.path().join(name), []).expect("unknown entry");

            assert!(PreparedResultJournalNamespace::open(namespace.path()).is_err());
        }
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
            9,
            marker,
        ))
        .expect("attempt ID");
        AttemptExecutionKey::new(lineage, attempt)
    }

    fn observation_result(marker: u8, attempt: AttemptId) -> PreparedSemanticAttemptResult {
        measurement_result(marker, attempt)
    }

    fn measurement_result(marker: u8, attempt: AttemptId) -> PreparedSemanticAttemptResult {
        let scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", &[marker, 0]));
        let configuration = ConfigurationId::from_hash(CampaignHash::derive("test", &[marker, 2]));
        let publication = evaluate_crucible_measurement_publication(
            scenario,
            configuration,
            &MeasurementDefinitions::empty(),
            Vec::new(),
            MeasurementTerminalState {
                scenario_ready_at: None,
                at: VirtualTime { ticks: 0 },
                node_icounts: BTreeMap::new(),
                scheduler_quiescent: true,
            },
            MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
        )
        .expect("measurement publication");
        let (evidence, _, measurements) = publication.into_parts();
        let candidate = observation_candidate(marker, attempt, measurements);

        assert!(matches!(
            PreparedSemanticAttemptResult::new(candidate.clone(), Vec::new(), None),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "missing measurement replay evidence"
            })
        ));
        assert!(matches!(
            PreparedSemanticAttemptResult::new(
                candidate.clone(),
                vec![evidence.clone(), evidence.clone()],
                None,
            ),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "duplicate measurement replay evidence"
            })
        ));

        let result = PreparedSemanticAttemptResult::new(candidate, vec![evidence], None)
            .expect("prepared measurement result");
        let encoded = result
            .canonical_bytes()
            .expect("encoded measurement result");
        assert_eq!(
            PreparedSemanticAttemptResult::from_canonical_bytes(&encoded)
                .expect("decoded measurement result"),
            result
        );
        result
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
            Observation::outcome(
                configuration,
                child.id().expect("configuration artifact ID"),
                path,
                StopOutcome::TerminalSuccess,
                measurements.id().expect("measurement ID"),
                properties.id().expect("property ID"),
                coverage.id().expect("coverage ID"),
            ),
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
