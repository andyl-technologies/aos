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
//! result-v2 := prepared-semantic-attempt-result-v2
//! ```
//!
//! State is bounded at 16 KiB. The result has both the format ceiling and the
//! smaller operational ceiling authenticated in state. Complete v1 file pairs
//! remain readable for publication recovery and are never rewritten in place.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crucible_campaign::{AttemptExecutionScope, ExecutionId};

use crate::crucible_artifact::PreparedSemanticResultVersion;
use crate::owned_advisory_lock::OwnedAdvisoryLock;
use crate::{
    AttemptExecutionKey, MAX_PREPARED_SEMANTIC_RESULT_BYTES, PreparedSemanticAttemptResult,
    PreparedSemanticResultCodecError,
};

const JOURNAL_LOCK_PREFIX: &str = ".lock-";
const JOURNAL_STAGED_PREFIX: &str = ".staged-";
const JOURNAL_RETIRED_PREFIX: &str = ".retired-";
const JOURNAL_RESULT_FILE: &str = "result-v2";
const JOURNAL_STATE_FILE: &str = "state-v2";
const JOURNAL_RESULT_FILE_V1: &str = "result-v1";
const JOURNAL_STATE_FILE_V1: &str = "state-v1";
const JOURNAL_STATE_MAGIC_V1: &[u8] = b"crucible.executor.prepared-result-journal-state.v1\0";
const JOURNAL_STATE_MAGIC_V2: &[u8] = b"crucible.executor.prepared-result-journal-state.v2\0";
const JOURNAL_STATE_HASH_DOMAIN_V1: &str = "crucible.executor.prepared-result-journal-state.v1";
const JOURNAL_STATE_HASH_DOMAIN_V2: &str = "crucible.executor.prepared-result-journal-state.v2";
const JOURNAL_MEASUREMENT_EVIDENCE_HASH_DOMAIN: &str =
    "crucible.executor.prepared-result-journal-measurement-evidence.v1";
const MAX_JOURNAL_STATE_BYTES: usize = 16 * 1024;
const MAX_ORPHAN_DIRECTORY_ENTRIES: usize = 4;

static JOURNAL_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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

/// Exclusive authenticated owner of one prepared semantic result journal.
#[derive(Debug)]
pub struct DirectoryPreparedResultJournal {
    root: PathBuf,
    key: AttemptExecutionKey,
    execution: ExecutionId,
    maximum_payload_bytes: usize,
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
        let namespace = namespace.as_ref();
        validate_namespace(namespace)?;
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        validate_result_key(key, &result)?;
        let namespace_lock = acquire_namespace_lock(namespace, key)?;
        let root = journal_path(namespace, key);
        if path_presence(&root, "inspect-journal-before-create")? {
            let journal = Self::open_locked(
                root,
                key,
                Some(execution),
                maximum_payload_bytes,
                namespace_lock,
            )?;
            if journal.result != result {
                return Err(PreparedResultJournalError::ResultMismatch);
            }
            return Ok((journal, PreparedResultJournalCreateDisposition::Existing));
        }
        if path_presence(
            &staged_path(namespace, key),
            "inspect-staged-journal-before-create",
        )? || path_presence(
            &retired_path(namespace, key),
            "inspect-retired-journal-before-create",
        )? {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }

        let payload = result.canonical_bytes_with_limit(maximum_payload_bytes)?;
        let state = encode_state(
            key,
            execution,
            maximum_payload_bytes,
            &result,
            &payload,
            JournalVersion::V2,
        )?;
        let staging = create_staging_directory(namespace, key)?;
        initialize_new(&staging, &payload, &state)?;
        match rename_noreplace(&staging, &root) {
            Ok(()) => {
                sync_parent(&root, "sync-journal-parent-after-create")?;
                Ok((
                    Self {
                        root,
                        key,
                        execution,
                        maximum_payload_bytes,
                        result,
                        namespace_lock,
                    },
                    PreparedResultJournalCreateDisposition::Created,
                ))
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                Err(PreparedResultJournalError::RecoveryRequired)
            }
            Err(source) => Err(io_error("publish-journal-directory", &root, source)),
        }
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
        let namespace = namespace.as_ref();
        validate_namespace(namespace)?;
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        let namespace_lock = acquire_namespace_lock(namespace, key)?;
        let root = journal_path(namespace, key);
        Self::open_locked(
            root,
            key,
            Some(execution),
            maximum_payload_bytes,
            namespace_lock,
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
        let namespace = namespace.as_ref();
        validate_namespace(namespace)?;
        validate_semantic_key(key)?;
        let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
        let namespace_lock = acquire_namespace_lock(namespace, key)?;
        let root = journal_path(namespace, key);
        if !path_presence(&root, "inspect-journal-for-recovery")? {
            if path_presence(
                &staged_path(namespace, key),
                "inspect-staged-journal-for-recovery",
            )? || path_presence(
                &retired_path(namespace, key),
                "inspect-retired-journal-for-recovery",
            )? {
                return Err(PreparedResultJournalError::RecoveryRequired);
            }
            return Ok(None);
        }
        Self::open_locked(root, key, None, maximum_payload_bytes, namespace_lock).map(Some)
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
        let namespace = namespace.as_ref();
        validate_namespace(namespace)?;
        validate_semantic_key(key)?;

        Ok(path_presence(
            &journal_path(namespace, key),
            "inventory-prepared-result-journal",
        )? || path_presence(
            &staged_path(namespace, key),
            "inventory-staged-prepared-result-journal",
        )? || path_presence(
            &retired_path(namespace, key),
            "inventory-retired-prepared-result-journal",
        )?)
    }

    fn open_locked(
        root: PathBuf,
        key: AttemptExecutionKey,
        expected_execution: Option<ExecutionId>,
        maximum_payload_bytes: usize,
        namespace_lock: OwnedAdvisoryLock,
    ) -> Result<Self, PreparedResultJournalError> {
        validate_journal_directory(&root)?;
        sync_directory(&root, "sync-journal-directory-on-open")?;
        sync_parent(&root, "sync-journal-parent-on-open")?;

        let (state_file, result_file, version) = journal_files(&root)?;
        let state = read_bounded_file(
            &root.join(state_file),
            MAX_JOURNAL_STATE_BYTES,
            "read-journal-state",
        )?;
        let envelope = decode_state(
            &state,
            key,
            expected_execution,
            maximum_payload_bytes,
            version,
        )?;
        let payload = read_bounded_file(
            &root.join(result_file),
            maximum_payload_bytes,
            "read-journal-result",
        )?;
        envelope.validate_payload(&payload)?;
        let payload_version = PreparedSemanticResultVersion::from_payload(&payload)
            .ok_or(PreparedResultJournalError::InvalidState)?;
        if !version.matches_payload(payload_version) {
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
            key,
            execution: envelope.execution,
            maximum_payload_bytes,
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
        let namespace = self
            .root
            .parent()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        let tombstone = retired_path(namespace, self.key);
        let root_present = path_presence(&self.root, "inspect-journal-before-retire")?;
        let tombstone_present = path_presence(&tombstone, "inspect-retired-journal")?;
        match (root_present, tombstone_present) {
            (true, false) => {
                rename_noreplace(&self.root, &tombstone)
                    .map_err(|source| io_error("retire-journal-directory", &self.root, source))?;
            }
            (false, true) | (false, false) => {}
            (true, true) => return Err(PreparedResultJournalError::RecoveryRequired),
        }
        sync_parent(&tombstone, "sync-journal-parent-after-retire")?;
        remove_orphan_directory(&tombstone)?;
        sync_parent(&tombstone, "sync-journal-parent-after-remove")
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
        let namespace = namespace.as_ref();
        validate_namespace(namespace)?;
        validate_semantic_key(key)?;
        let namespace_lock = acquire_namespace_lock(namespace, key)?;
        if journal_path(namespace, key).exists() {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }

        let staged_removed = remove_orphan_directory(&staged_path(namespace, key))?;
        let retired_removed = remove_orphan_directory(&retired_path(namespace, key))?;
        // Retry the durability barrier even when a prior call removed the
        // names and failed its parent sync.
        sync_directory(namespace, "sync-journal-parent-after-orphan-cleanup")?;
        drop(namespace_lock);
        Ok(PreparedResultJournalCleanupDisposition {
            staged_removed,
            retired_removed,
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

fn create_staging_directory(
    namespace: &Path,
    key: AttemptExecutionKey,
) -> Result<PathBuf, PreparedResultJournalError> {
    let staging = staged_path(namespace, key);
    fs::create_dir(&staging).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            PreparedResultJournalError::RecoveryRequired
        } else {
            io_error("create-journal-staging-directory", &staging, source)
        }
    })?;
    Ok(staging)
}

fn initialize_new(
    root: &Path,
    payload: &[u8],
    state: &[u8],
) -> Result<(), PreparedResultJournalError> {
    write_atomic(root, JOURNAL_RESULT_FILE, payload)?;
    write_atomic(root, JOURNAL_STATE_FILE, state)?;
    sync_directory(root, "sync-journal-directory-after-initialize")
}

fn encode_state(
    key: AttemptExecutionKey,
    execution: ExecutionId,
    maximum_payload_bytes: usize,
    result: &PreparedSemanticAttemptResult,
    payload: &[u8],
    version: JournalVersion,
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
    if matches!(version, JournalVersion::V1) && measurement_evidence_count != 0 {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let mut state = Vec::new();
    state.extend_from_slice(version.magic());
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
    if matches!(version, JournalVersion::V2) {
        state.extend_from_slice(
            &u64::try_from(measurement_evidence_count)
                .map_err(|_| PreparedResultJournalError::InvalidState)?
                .to_be_bytes(),
        );
        state.extend_from_slice(&measurement_evidence_hash);
    }
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
    let checksum_key = blake3::derive_key(version.hash_domain(), version.magic());
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
    version: JournalVersion,
) -> Result<JournalStateEnvelope<'a>, PreparedResultJournalError> {
    let checksum_offset = state
        .len()
        .checked_sub(32)
        .ok_or(PreparedResultJournalError::InvalidState)?;
    let (body, checksum) = state.split_at(checksum_offset);
    let checksum_key = blake3::derive_key(version.hash_domain(), version.magic());
    if blake3::keyed_hash(&checksum_key, body).as_bytes() != checksum {
        return Err(PreparedResultJournalError::InvalidState);
    }

    let mut decoder = JournalStateDecoder::new(body);
    decoder.expect(version.magic())?;
    decoder.expect(key.storage_digest().as_bytes().as_slice())?;
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
    let measurement_evidence = match version {
        JournalVersion::V1 => None,
        JournalVersion::V2 => {
            let count = usize::try_from(decoder.u64()?)
                .map_err(|_| PreparedResultJournalError::InvalidState)?;
            let hash = decoder
                .take(32)?
                .try_into()
                .map_err(|_| PreparedResultJournalError::InvalidState)?;
            Some((count, hash))
        }
    };
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

#[derive(Clone, Copy)]
enum JournalVersion {
    V1,
    V2,
}

impl JournalVersion {
    const fn magic(self) -> &'static [u8] {
        match self {
            Self::V1 => JOURNAL_STATE_MAGIC_V1,
            Self::V2 => JOURNAL_STATE_MAGIC_V2,
        }
    }

    const fn hash_domain(self) -> &'static str {
        match self {
            Self::V1 => JOURNAL_STATE_HASH_DOMAIN_V1,
            Self::V2 => JOURNAL_STATE_HASH_DOMAIN_V2,
        }
    }

    const fn matches_payload(self, payload: PreparedSemanticResultVersion) -> bool {
        matches!(
            (self, payload),
            (Self::V1, PreparedSemanticResultVersion::V1)
                | (Self::V2, PreparedSemanticResultVersion::V2)
        )
    }
}

fn journal_files(
    root: &Path,
) -> Result<(&'static str, &'static str, JournalVersion), PreparedResultJournalError> {
    let has_v2_state = root.join(JOURNAL_STATE_FILE).exists();
    let has_v2_result = root.join(JOURNAL_RESULT_FILE).exists();
    let has_v1_state = root.join(JOURNAL_STATE_FILE_V1).exists();
    let has_v1_result = root.join(JOURNAL_RESULT_FILE_V1).exists();
    if has_v2_state || has_v2_result {
        if !has_v2_state || !has_v2_result || has_v1_state || has_v1_result {
            return Err(PreparedResultJournalError::Incomplete);
        }
        return Ok((JOURNAL_STATE_FILE, JOURNAL_RESULT_FILE, JournalVersion::V2));
    }
    if has_v1_state && has_v1_result {
        Ok((
            JOURNAL_STATE_FILE_V1,
            JOURNAL_RESULT_FILE_V1,
            JournalVersion::V1,
        ))
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

    fn expect(&mut self, expected: &[u8]) -> Result<(), PreparedResultJournalError> {
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

fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
}

fn remove_orphan_directory(root: &Path) -> Result<bool, PreparedResultJournalError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(PreparedResultJournalError::InvalidDirectory),
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(io_error("inspect-journal-orphan", root, source)),
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|source| io_error("read-journal-orphan", root, source))?
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
        remove_file_if_present(&entry, "remove-journal-orphan-file")?;
    }
    match fs::remove_dir(root) {
        Ok(()) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("remove-journal-directory", root, source)),
    }
}

fn is_owned_orphan_file(name: &str) -> bool {
    name == JOURNAL_STATE_FILE
        || name == JOURNAL_RESULT_FILE
        || name == JOURNAL_STATE_FILE_V1
        || name == JOURNAL_RESULT_FILE_V1
        || name == "lock"
        || name.starts_with(&format!(".{JOURNAL_STATE_FILE}."))
        || name.starts_with(&format!(".{JOURNAL_RESULT_FILE}."))
        || name.starts_with(&format!(".{JOURNAL_STATE_FILE_V1}."))
        || name.starts_with(&format!(".{JOURNAL_RESULT_FILE_V1}."))
}

fn write_atomic(root: &Path, name: &str, bytes: &[u8]) -> Result<(), PreparedResultJournalError> {
    let suffix = JOURNAL_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(".{name}.{}.{}", std::process::id(), suffix));
    let destination = root.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|source| io_error("create-journal-temporary", &temporary, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write-journal-temporary", &temporary, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync-journal-temporary", &temporary, source))?;
    fs::rename(&temporary, &destination)
        .map_err(|source| io_error("publish-journal-file", &destination, source))?;
    sync_directory(root, "sync-journal-directory-after-file")
}

fn read_bounded_file(
    path: &Path,
    maximum: usize,
    operation: &'static str,
) -> Result<Vec<u8>, PreparedResultJournalError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(PreparedResultJournalError::Incomplete);
        }
        Err(source) => return Err(io_error(operation, path, source)),
    };
    let length = file
        .metadata()
        .map_err(|source| io_error(operation, path, source))?
        .len();
    if length > maximum as u64 {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(operation, path, source))?;
    if bytes.len() > maximum {
        return Err(PreparedResultJournalError::InvalidState);
    }
    Ok(bytes)
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

fn validate_journal_directory(path: &Path) -> Result<(), PreparedResultJournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(PreparedResultJournalError::InvalidDirectory),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            Err(PreparedResultJournalError::InvalidDirectory)
        }
        Err(source) => Err(io_error("inspect-journal-directory", path, source)),
    }
}

fn sync_directory(path: &Path, operation: &'static str) -> Result<(), PreparedResultJournalError> {
    let directory = File::open(path).map_err(|source| io_error(operation, path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error(operation, path, source))
}

fn sync_parent(path: &Path, operation: &'static str) -> Result<(), PreparedResultJournalError> {
    let parent = path
        .parent()
        .ok_or(PreparedResultJournalError::InvalidDirectory)?;
    sync_directory(parent, operation)
}

fn remove_file_if_present(
    path: &Path,
    operation: &'static str,
) -> Result<(), PreparedResultJournalError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(operation, path, source)),
    }
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
    #![allow(clippy::expect_used)]

    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::os::unix::fs::MetadataExt;

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
    fn journal_v2_owns_raw_measurement_leaf_and_v1_remains_recoverable() {
        let namespace = TempDir::new().expect("journal namespace");
        let key = semantic_key(b"measurement-evidence");
        let execution = ExecutionId::from_bytes([0x63; 16]).expect("execution");
        let result = measurement_result(0x64, key.attempt());
        let payload = result
            .canonical_bytes_with_limit(TEST_PAYLOAD_LIMIT)
            .expect("v2 prepared result");

        let (journal, disposition) = DirectoryPreparedResultJournal::create(
            namespace.path(),
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
            "31c8b31392bbc85ca11c2ffee98136fa7a9b4229d31849c55e291cf24636f551"
        );
        let state = fs::read(journal.root().join(JOURNAL_STATE_FILE)).expect("v2 state");
        assert_eq!(
            blake3::hash(&state).to_hex().as_str(),
            "572578832ea7b855dd41d48fb3301d92e9ac4455520f428ea681d4ee3f316eb3"
        );
        journal.remove().expect("remove v2 journal");

        let legacy_key = semantic_key(b"legacy-result");
        let legacy_execution = ExecutionId::from_bytes([0x65; 16]).expect("legacy execution");
        let legacy_result = observation_result(0x66, legacy_key.attempt());
        let legacy_payload = legacy_result
            .canonical_v1_bytes_with_limit(TEST_PAYLOAD_LIMIT)
            .expect("legacy payload");
        let legacy_payload_limit = legacy_payload.len();
        assert!(matches!(
            legacy_result.canonical_bytes_with_limit(legacy_payload_limit),
            Err(PreparedSemanticResultCodecError::LimitExceeded)
        ));
        let decoded = PreparedSemanticAttemptResult::from_canonical_bytes_with_limit(
            &legacy_payload,
            legacy_payload_limit,
        )
        .expect("decode legacy payload");
        assert_eq!(decoded, legacy_result);
        assert_ne!(
            decoded.canonical_bytes().expect("upgraded v2 bytes"),
            legacy_payload
        );

        let legacy_state = encode_state(
            legacy_key,
            legacy_execution,
            legacy_payload_limit,
            &legacy_result,
            &legacy_payload,
            JournalVersion::V1,
        )
        .expect("legacy state");
        let legacy_root = journal_path(namespace.path(), legacy_key);
        fs::create_dir(&legacy_root).expect("legacy journal directory");
        write_atomic(&legacy_root, JOURNAL_RESULT_FILE_V1, &legacy_payload)
            .expect("legacy result file");
        write_atomic(&legacy_root, JOURNAL_STATE_FILE_V1, &legacy_state)
            .expect("legacy state file");
        sync_directory(namespace.path(), "sync-test-legacy-parent").expect("sync legacy parent");

        let recovered = DirectoryPreparedResultJournal::open(
            namespace.path(),
            legacy_key,
            legacy_execution,
            legacy_payload_limit,
        )
        .expect("recover legacy journal");
        assert_eq!(recovered.result(), &legacy_result);
        drop(recovered);
        let (recovered, disposition) = DirectoryPreparedResultJournal::create(
            namespace.path(),
            legacy_key,
            legacy_execution,
            legacy_payload_limit,
            legacy_result.clone(),
        )
        .expect("reopen exact-bound legacy journal through create");
        assert_eq!(
            disposition,
            PreparedResultJournalCreateDisposition::Existing
        );
        recovered.remove().expect("remove legacy journal");

        let v2_payload = legacy_result
            .canonical_bytes_with_limit(TEST_PAYLOAD_LIMIT)
            .expect("v2 legacy-content payload");
        assert_cross_version_pair_fails(
            b"v2-state-v1-result",
            legacy_result.clone(),
            &legacy_payload,
            JournalVersion::V2,
            JOURNAL_RESULT_FILE,
            JOURNAL_STATE_FILE,
        );
        assert_cross_version_pair_fails(
            b"v1-state-v2-result",
            legacy_result,
            &v2_payload,
            JournalVersion::V1,
            JOURNAL_RESULT_FILE_V1,
            JOURNAL_STATE_FILE_V1,
        );
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
            Err(PreparedResultJournalError::Incomplete)
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
        fs::write(staged.join(".state-v1.123.0"), b"partial")
            .expect("partial atomic state temporary");
        assert!(matches!(
            DirectoryPreparedResultJournal::create(
                namespace.path(),
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
                result.clone(),
            ),
            Err(PreparedResultJournalError::RecoveryRequired)
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

    fn assert_cross_version_pair_fails(
        marker: &[u8],
        result: PreparedSemanticAttemptResult,
        payload: &[u8],
        state_version: JournalVersion,
        result_file: &str,
        state_file: &str,
    ) {
        let namespace = TempDir::new().expect("cross-version namespace");
        let key = semantic_key(marker);
        let execution = ExecutionId::from_bytes([0x67; 16]).expect("cross-version execution");
        let state = encode_state(
            key,
            execution,
            TEST_PAYLOAD_LIMIT,
            &result,
            payload,
            state_version,
        )
        .expect("cross-version state");
        let root = journal_path(namespace.path(), key);
        fs::create_dir(&root).expect("cross-version journal directory");
        write_atomic(&root, result_file, payload).expect("cross-version result file");
        write_atomic(&root, state_file, &state).expect("cross-version state file");

        assert!(matches!(
            DirectoryPreparedResultJournal::open(
                namespace.path(),
                key,
                execution,
                TEST_PAYLOAD_LIMIT,
            ),
            Err(PreparedResultJournalError::InvalidState)
        ));
    }

    fn observation_result(marker: u8, attempt: AttemptId) -> PreparedSemanticAttemptResult {
        let candidate = observation_candidate(
            marker,
            attempt,
            MeasurementSet::new(BTreeMap::new()).expect("measurements"),
        );
        PreparedSemanticAttemptResult::new(candidate, None).expect("prepared result")
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
            PreparedSemanticAttemptResult::new(candidate.clone(), None),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "missing measurement replay evidence"
            })
        ));
        assert!(matches!(
            PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
                candidate.clone(),
                vec![evidence.clone(), evidence.clone()],
                None,
            ),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "duplicate measurement replay evidence"
            })
        ));

        let result = PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
            candidate,
            vec![evidence],
            None,
        )
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
