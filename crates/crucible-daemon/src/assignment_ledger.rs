//! Crash-safe operational assignment records for the local executor.
//!
//! The ledger separates immutable assignment replies from mutable per-attempt
//! runtime state. Directory records are addressed directly by assignment or
//! attempt identity, so restart recovery does not materialize daemon history in
//! memory. Every file is bounded, checksummed, strictly decoded, and published
//! through an fsynced staging file followed by an atomic link or rename.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_campaign::{
    AssignmentId, AttemptId, CampaignCodecError, CampaignHash, CampaignLineageId, DaemonEpoch,
    ExecutionId, ObservationId, SubmitAttemptRequest, SubmitAttemptResponse,
};
use rustix::fs::{FlockOperation, flock};

const ASSIGNMENT_MAGIC: &[u8] = b"crucible.executor.assignment-record.v1\0";
const ATTEMPT_STATE_MAGIC: &[u8] = b"crucible.executor.attempt-state-record.v1\0";
const ASSIGNMENT_CHECKSUM_DOMAIN: &str = "crucible.executor.assignment-record.v1";
const ATTEMPT_STATE_CHECKSUM_DOMAIN: &str = "crucible.executor.attempt-state-record.v1";
const MAX_LEDGER_RECORD_BYTES: u64 = 16 * 1024;
const MAX_TYPED_ID_BYTES: usize = 256;

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One immutable exact request and its first durable protocol response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentRecord {
    request: SubmitAttemptRequest,
    response: SubmitAttemptResponse,
}

impl AssignmentRecord {
    /// Builds an assignment record whose response authenticates the request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to any other
    /// canonical request basis.
    pub fn new(
        request: SubmitAttemptRequest,
        response: SubmitAttemptResponse,
    ) -> Result<Self, CampaignCodecError> {
        response.validate_for(&request)?;
        Ok(Self { request, response })
    }

    /// Returns the exact request retained for idempotency.
    #[must_use]
    pub const fn request(&self) -> &SubmitAttemptRequest {
        &self.request
    }

    /// Returns the first durable response retained for exact replay.
    #[must_use]
    pub const fn response(&self) -> &SubmitAttemptResponse {
        &self.response
    }
}

/// Exact lineage-qualified semantic key for operational attempt runtime state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttemptExecutionKey {
    lineage: CampaignLineageId,
    attempt: AttemptId,
}

impl AttemptExecutionKey {
    /// Builds the runtime key for one exact lineage and semantic attempt.
    #[must_use]
    pub const fn new(lineage: CampaignLineageId, attempt: AttemptId) -> Self {
        Self { lineage, attempt }
    }

    /// Returns the exact compatibility lineage.
    #[must_use]
    pub const fn lineage(self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the immutable semantic attempt.
    #[must_use]
    pub const fn attempt(self) -> AttemptId {
        self.attempt
    }
}

/// Durable operational state for one semantic attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptRuntimeState {
    /// One execution is currently owned by a daemon incarnation.
    Running {
        /// Digest of lineage, attempt, resources, and retention.
        execution_basis: CampaignHash,
        /// Daemon incarnation that admitted the execution.
        daemon_epoch: DaemonEpoch,
        /// Process-local execution identity.
        execution: ExecutionId,
    },
    /// One execution published an immutable observation.
    Completed {
        /// Digest of lineage, attempt, resources, and retention.
        execution_basis: CampaignHash,
        /// Daemon incarnation that admitted the completed execution.
        daemon_epoch: DaemonEpoch,
        /// Process-local execution identity.
        execution: ExecutionId,
        /// Immutable completed observation.
        observation: ObservationId,
    },
    /// The daemon accepted cancellation before canonical completion.
    Canceled {
        /// Digest of lineage, attempt, resources, and retention.
        execution_basis: CampaignHash,
        /// Daemon incarnation that admitted the canceled execution.
        daemon_epoch: DaemonEpoch,
        /// Process-local execution identity.
        execution: ExecutionId,
    },
}

impl AttemptRuntimeState {
    /// Returns the exact operational execution-contract digest.
    #[must_use]
    pub const fn execution_basis(self) -> CampaignHash {
        match self {
            Self::Running {
                execution_basis, ..
            }
            | Self::Completed {
                execution_basis, ..
            }
            | Self::Canceled {
                execution_basis, ..
            } => execution_basis,
        }
    }

    /// Returns the daemon incarnation that admitted this runtime state.
    #[must_use]
    pub const fn daemon_epoch(self) -> DaemonEpoch {
        match self {
            Self::Running { daemon_epoch, .. }
            | Self::Completed { daemon_epoch, .. }
            | Self::Canceled { daemon_epoch, .. } => daemon_epoch,
        }
    }

    /// Returns the local execution named by this runtime state.
    #[must_use]
    pub const fn execution(self) -> ExecutionId {
        match self {
            Self::Running { execution, .. }
            | Self::Completed { execution, .. }
            | Self::Canceled { execution, .. } => execution,
        }
    }

    /// Returns the completed observation, when one was durably published.
    #[must_use]
    pub const fn observation(self) -> Option<ObservationId> {
        match self {
            Self::Completed { observation, .. } => Some(observation),
            Self::Running { .. } | Self::Canceled { .. } => None,
        }
    }
}

/// Result of conditionally publishing one immutable assignment record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignmentPublish {
    /// The record became durable in this call.
    Stored,
    /// The exact record was already durable.
    Existing,
    /// The assignment identity already named different canonical bytes.
    Conflict,
}

/// Result of conditionally replacing one attempt runtime state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptStateCas {
    /// The requested state became durable.
    Advanced,
    /// The expected state did not match the current durable state.
    Conflict {
        /// Current state observed during the failed comparison.
        current: Option<AttemptRuntimeState>,
    },
}

/// Pluggable operational ledger used by the single-host executor supervisor.
pub trait AssignmentLedger {
    /// Backend-specific persistence failure.
    type Error;

    /// Loads an immutable assignment response by exact assignment identity.
    ///
    /// A successful existing-record result also reestablishes durable parent
    /// directory metadata after a prior commit-indeterminate publication.
    ///
    /// # Errors
    ///
    /// Returns the backend error when absence cannot be distinguished safely or
    /// when an existing record is malformed, corrupt, or inconsistent.
    fn load_assignment(
        &self,
        assignment: AssignmentId,
    ) -> Result<Option<AssignmentRecord>, Self::Error>;

    /// Conditionally publishes one immutable assignment response.
    ///
    /// # Errors
    ///
    /// Returns the backend error when durable publication or validation fails.
    fn publish_assignment(
        &mut self,
        record: &AssignmentRecord,
    ) -> Result<AssignmentPublish, Self::Error>;

    /// Loads durable runtime state for one lineage-qualified semantic attempt.
    ///
    /// A successful result, including absence, also reestablishes durable
    /// parent-directory metadata when the directory exists. A caller may
    /// therefore use the result to reconcile a prior compare-exchange error.
    ///
    /// # Errors
    ///
    /// Returns the backend error when absence cannot be distinguished safely or
    /// when an existing record is malformed, corrupt, or inconsistent.
    fn load_attempt(
        &self,
        key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::Error>;

    /// Conditionally replaces one attempt runtime state.
    ///
    /// # Errors
    ///
    /// Returns the backend error when durable publication or validation fails.
    fn compare_exchange_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::Error>;
}

/// In-memory assignment ledger for component tests and fake executors.
#[derive(Default)]
pub struct MemoryAssignmentLedger {
    assignments: BTreeMap<AssignmentId, AssignmentRecord>,
    attempts: BTreeMap<AttemptExecutionKey, AttemptRuntimeState>,
}

impl AssignmentLedger for MemoryAssignmentLedger {
    type Error = std::convert::Infallible;

    fn load_assignment(
        &self,
        assignment: AssignmentId,
    ) -> Result<Option<AssignmentRecord>, Self::Error> {
        Ok(self.assignments.get(&assignment).cloned())
    }

    fn publish_assignment(
        &mut self,
        record: &AssignmentRecord,
    ) -> Result<AssignmentPublish, Self::Error> {
        let assignment = record.request.assignment();
        let outcome = match self.assignments.get(&assignment) {
            Some(existing) if existing == record => AssignmentPublish::Existing,
            Some(_) => AssignmentPublish::Conflict,
            None => {
                self.assignments.insert(assignment, record.clone());
                AssignmentPublish::Stored
            }
        };
        Ok(outcome)
    }

    fn load_attempt(
        &self,
        key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::Error> {
        Ok(self.attempts.get(&key).copied())
    }

    fn compare_exchange_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::Error> {
        let current = self.attempts.get(&key).copied();
        if current != expected {
            return Ok(AttemptStateCas::Conflict { current });
        }
        match next {
            Some(next) => {
                self.attempts.insert(key, next);
            }
            None => {
                self.attempts.remove(&key);
            }
        }
        Ok(AttemptStateCas::Advanced)
    }
}

/// Failure from a durable directory assignment ledger.
#[derive(Debug, thiserror::Error)]
pub enum AssignmentLedgerError {
    /// A filesystem operation failed.
    #[error("assignment ledger {operation} failed for {}: {source}", path.display())]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Exact path being operated on.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A canonical component message failed strict decoding.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// A ledger record was truncated, corrupt, or internally inconsistent.
    #[error("assignment ledger record is corrupt: {reason}")]
    Corrupt {
        /// Stable corruption category.
        reason: &'static str,
    },
}

/// Crash-safe directory ledger with one nonblocking process writer lock.
pub struct DirectoryAssignmentLedger {
    root: PathBuf,
    _writer_lock: File,
}

impl DirectoryAssignmentLedger {
    /// Opens a durable ledger and acquires exclusive single-writer ownership.
    ///
    /// Direct record lookup keeps restart memory proportional to active work,
    /// not historical assignments.
    ///
    /// # Errors
    ///
    /// Returns [`AssignmentLedgerError`] when the directory cannot be created,
    /// another writer owns it, or the lock cannot be acquired safely.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, AssignmentLedgerError> {
        let root = root.into();
        create_directory_durable(&root)?;
        let lock_path = root.join("writer.lock");
        let writer_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| io_error("open-writer-lock", &lock_path, source))?;
        flock(&writer_lock, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
            io_error(
                "lock-writer",
                &lock_path,
                std::io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?;
        sync_directory(&root)?;
        Ok(Self {
            root,
            _writer_lock: writer_lock,
        })
    }

    /// Returns the physical ledger root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn assignment_path(&self, assignment: AssignmentId) -> PathBuf {
        let encoded = encode_hex(&assignment.as_bytes());
        self.root
            .join("assignments")
            .join(&encoded[..2])
            .join(encoded)
    }

    fn attempt_path(&self, key: AttemptExecutionKey) -> PathBuf {
        let mut material = Vec::with_capacity(256);
        push_bytes(&mut material, key.lineage.to_text().as_bytes());
        push_bytes(&mut material, key.attempt.to_text().as_bytes());
        let encoded =
            CampaignHash::derive("crucible.executor.attempt-execution-key.v1", &material).to_hex();
        self.root.join("attempts").join(&encoded[..2]).join(encoded)
    }
}

impl AssignmentLedger for DirectoryAssignmentLedger {
    type Error = AssignmentLedgerError;

    fn load_assignment(
        &self,
        assignment: AssignmentId,
    ) -> Result<Option<AssignmentRecord>, Self::Error> {
        let path = self.assignment_path(assignment);
        let Some(bytes) = read_optional_bounded(&path)? else {
            return Ok(None);
        };
        sync_record_parent(&path)?;
        let record = decode_assignment_record(&bytes)?;
        if record.request.assignment() != assignment {
            return Err(corrupt("assignment-path-identity-mismatch"));
        }
        Ok(Some(record))
    }

    fn publish_assignment(
        &mut self,
        record: &AssignmentRecord,
    ) -> Result<AssignmentPublish, Self::Error> {
        let assignment = record.request.assignment();
        if let Some(existing) = self.load_assignment(assignment)? {
            return Ok(if existing == *record {
                AssignmentPublish::Existing
            } else {
                AssignmentPublish::Conflict
            });
        }

        let path = self.assignment_path(assignment);
        let published = publish_immutable(&path, &encode_assignment_record(record))?;
        if published {
            return Ok(AssignmentPublish::Stored);
        }
        let existing = self
            .load_assignment(assignment)?
            .ok_or_else(|| corrupt("assignment-publish-lost-race"))?;
        Ok(if existing == *record {
            AssignmentPublish::Existing
        } else {
            AssignmentPublish::Conflict
        })
    }

    fn load_attempt(
        &self,
        key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::Error> {
        let path = self.attempt_path(key);
        let Some(bytes) = read_optional_bounded(&path)? else {
            sync_record_parent_if_present(&path)?;
            return Ok(None);
        };
        sync_record_parent(&path)?;
        let (recorded_key, state) = decode_attempt_state(&bytes)?;
        if recorded_key != key {
            return Err(corrupt("attempt-path-identity-mismatch"));
        }
        Ok(Some(state))
    }

    fn compare_exchange_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::Error> {
        let current = self.load_attempt(key)?;
        if current != expected {
            return Ok(AttemptStateCas::Conflict { current });
        }
        let path = self.attempt_path(key);
        match next {
            Some(next) => replace_mutable(&path, &encode_attempt_state(key, next))?,
            None => remove_mutable(&path)?,
        }
        Ok(AttemptStateCas::Advanced)
    }
}

fn encode_assignment_record(record: &AssignmentRecord) -> Vec<u8> {
    let request = record.request.canonical_bytes();
    let response = record.response.canonical_bytes();
    let mut payload = Vec::with_capacity(
        ASSIGNMENT_MAGIC.len() + request.len() + response.len() + 2 * size_of::<u32>(),
    );
    payload.extend_from_slice(ASSIGNMENT_MAGIC);
    push_bytes(&mut payload, &request);
    push_bytes(&mut payload, &response);
    seal(payload, ASSIGNMENT_CHECKSUM_DOMAIN)
}

fn decode_assignment_record(bytes: &[u8]) -> Result<AssignmentRecord, AssignmentLedgerError> {
    let payload = open_sealed(bytes, ASSIGNMENT_CHECKSUM_DOMAIN)?;
    let mut cursor = RecordCursor::new(payload);
    cursor.require(ASSIGNMENT_MAGIC)?;
    let request = SubmitAttemptRequest::from_canonical_bytes(cursor.bytes()?)?;
    let response = SubmitAttemptResponse::from_canonical_bytes(cursor.bytes()?)?;
    cursor.finish()?;
    AssignmentRecord::new(request, response).map_err(Into::into)
}

fn encode_attempt_state(key: AttemptExecutionKey, state: AttemptRuntimeState) -> Vec<u8> {
    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC);
    push_bytes(&mut payload, key.lineage.to_text().as_bytes());
    push_bytes(&mut payload, key.attempt.to_text().as_bytes());
    payload.extend_from_slice(&state.execution_basis().as_bytes());
    match state {
        AttemptRuntimeState::Running {
            daemon_epoch,
            execution,
            ..
        } => {
            payload.push(0);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
        }
        AttemptRuntimeState::Completed {
            daemon_epoch,
            execution,
            observation,
            ..
        } => {
            payload.push(1);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, observation.to_text().as_bytes());
        }
        AttemptRuntimeState::Canceled {
            daemon_epoch,
            execution,
            ..
        } => {
            payload.push(2);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
        }
    }
    seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN)
}

fn decode_attempt_state(
    bytes: &[u8],
) -> Result<(AttemptExecutionKey, AttemptRuntimeState), AssignmentLedgerError> {
    let payload = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN)?;
    let mut cursor = RecordCursor::new(payload);
    cursor.require(ATTEMPT_STATE_MAGIC)?;
    let lineage = parse_typed(cursor.bytes()?, CampaignLineageId::parse)?;
    let attempt = parse_typed(cursor.bytes()?, AttemptId::parse)?;
    let execution_basis = CampaignHash::from_bytes(cursor.fixed()?);
    let tag = cursor.byte()?;
    let daemon_epoch = DaemonEpoch::from_bytes(cursor.fixed()?)?;
    let execution = ExecutionId::from_bytes(cursor.fixed()?)?;
    let state = match tag {
        0 => AttemptRuntimeState::Running {
            execution_basis,
            daemon_epoch,
            execution,
        },
        1 => AttemptRuntimeState::Completed {
            execution_basis,
            daemon_epoch,
            execution,
            observation: parse_typed(cursor.bytes()?, ObservationId::parse)?,
        },
        2 => AttemptRuntimeState::Canceled {
            execution_basis,
            daemon_epoch,
            execution,
        },
        _ => return Err(corrupt("attempt-state-unknown-tag")),
    };
    cursor.finish()?;
    Ok((AttemptExecutionKey::new(lineage, attempt), state))
}

fn parse_typed<T>(
    bytes: &[u8],
    parse: impl FnOnce(&str) -> Result<T, CampaignCodecError>,
) -> Result<T, AssignmentLedgerError> {
    if bytes.len() > MAX_TYPED_ID_BYTES {
        return Err(corrupt("typed-id-too-large"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| corrupt("typed-id-not-utf8"))?;
    parse(text).map_err(Into::into)
}

fn seal(mut payload: Vec<u8>, domain: &str) -> Vec<u8> {
    let checksum = CampaignHash::derive(domain, &payload);
    payload.extend_from_slice(&checksum.as_bytes());
    payload
}

fn open_sealed<'a>(bytes: &'a [u8], domain: &str) -> Result<&'a [u8], AssignmentLedgerError> {
    if bytes.len() < 32 || bytes.len() as u64 > MAX_LEDGER_RECORD_BYTES {
        return Err(corrupt("record-size"));
    }
    let payload_length = bytes.len() - 32;
    let (payload, checksum) = bytes.split_at(payload_length);
    if checksum != CampaignHash::derive(domain, payload).as_bytes() {
        return Err(corrupt("record-checksum"));
    }
    Ok(payload)
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
}

struct RecordCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> RecordCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AssignmentLedgerError> {
        if self.remaining.len() < length {
            return Err(corrupt("record-truncated"));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], AssignmentLedgerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| corrupt("record-fixed-width"))
    }

    fn byte(&mut self) -> Result<u8, AssignmentLedgerError> {
        Ok(self.fixed::<1>()?[0])
    }

    fn bytes(&mut self) -> Result<&'a [u8], AssignmentLedgerError> {
        let length = u32::from_be_bytes(self.fixed()?) as usize;
        self.take(length)
    }

    fn require(&mut self, expected: &[u8]) -> Result<(), AssignmentLedgerError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(corrupt("record-magic"))
        }
    }

    fn finish(self) -> Result<(), AssignmentLedgerError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(corrupt("record-trailing-bytes"))
        }
    }
}

fn read_optional_bounded(path: &Path) -> Result<Option<Vec<u8>>, AssignmentLedgerError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("open-record", path, source)),
    };
    let mut bytes = Vec::new();
    file.take(MAX_LEDGER_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read-record", path, source))?;
    if bytes.len() as u64 > MAX_LEDGER_RECORD_BYTES {
        return Err(corrupt("record-size"));
    }
    Ok(Some(bytes))
}

fn publish_immutable(path: &Path, bytes: &[u8]) -> Result<bool, AssignmentLedgerError> {
    let directory = record_directory(path)?;
    let (staging_path, mut staging) = create_staging(directory)?;
    staging
        .write_all(bytes)
        .and_then(|()| staging.sync_all())
        .map_err(|source| io_error("write-assignment-staging", &staging_path, source))?;
    let published = match fs::hard_link(&staging_path, path) {
        Ok(()) => true,
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(source) => return Err(io_error("publish-assignment", path, source)),
    };
    fs::remove_file(&staging_path)
        .map_err(|source| io_error("remove-assignment-staging", &staging_path, source))?;
    sync_directory(directory)?;
    Ok(published)
}

fn replace_mutable(path: &Path, bytes: &[u8]) -> Result<(), AssignmentLedgerError> {
    let directory = record_directory(path)?;
    let (staging_path, mut staging) = create_staging(directory)?;
    staging
        .write_all(bytes)
        .and_then(|()| staging.sync_all())
        .map_err(|source| io_error("write-attempt-staging", &staging_path, source))?;
    fs::rename(&staging_path, path)
        .map_err(|source| io_error("publish-attempt-state", path, source))?;
    sync_directory(directory)
}

fn remove_mutable(path: &Path) -> Result<(), AssignmentLedgerError> {
    match fs::remove_file(path) {
        Ok(()) => {
            let directory = path
                .parent()
                .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
            sync_directory(directory)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove-attempt-state", path, source)),
    }
}

fn record_directory(path: &Path) -> Result<&Path, AssignmentLedgerError> {
    let directory = path
        .parent()
        .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
    create_directory_durable(directory)?;
    Ok(directory)
}

fn sync_record_parent(path: &Path) -> Result<(), AssignmentLedgerError> {
    let directory = path
        .parent()
        .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
    sync_directory(directory)
}

fn sync_record_parent_if_present(path: &Path) -> Result<(), AssignmentLedgerError> {
    let directory = path
        .parent()
        .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
    if directory.is_dir() {
        sync_directory(directory)
    } else {
        Ok(())
    }
}

fn create_staging(directory: &Path) -> Result<(PathBuf, File), AssignmentLedgerError> {
    loop {
        let ordinal = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".staging-{}-{ordinal}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("create-staging", &path, source)),
        }
    }
}

fn create_directory_durable(path: &Path) -> Result<(), AssignmentLedgerError> {
    if path.as_os_str().is_empty() || path == Path::new(".") {
        return Ok(());
    }
    if path.is_dir() {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| corrupt("directory-has-no-parent"))?;
    if parent != path {
        create_directory_durable(parent)?;
    }
    match fs::create_dir(path) {
        Ok(()) => sync_directory(parent),
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {
            Ok(())
        }
        Err(source) => Err(io_error("create-directory", path, source)),
    }
}

fn sync_directory(path: &Path) -> Result<(), AssignmentLedgerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync-directory", path, source))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn corrupt(reason: &'static str) -> AssignmentLedgerError {
    AssignmentLedgerError::Corrupt { reason }
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> AssignmentLedgerError {
    AssignmentLedgerError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests;
