//! Durable desired-state and operation journal.
//!
//! The journal is a sequence of checksummed frames grouped into transactions:
//!
//! ```text
//! begin(sequence, transaction, record_count)
//! record(sequence + 1, transaction, namespace, key, value)
//! ...
//! commit(sequence + n, transaction, record_count, transaction_digest)
//! ```
//!
//! A transaction becomes visible only after its commit frame and `sync_data`
//! complete. Replay discards a structurally valid but uncommitted tail and a
//! partial final frame. A checksum mismatch, sequence discontinuity, malformed
//! committed transaction, or unsupported version fails closed. Compaction
//! writes and syncs a replacement file, atomically renames it, then syncs the
//! parent directory. A separate advisory lock remains held across replacement.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_core::OperationId;
use rustix::fs::{
    AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, ResolveFlags, flock, fstat, fsync,
    openat2, renameat, unlinkat,
};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"AOSJRN01";
const FORMAT_VERSION: u16 = 1;
const HEADER_BYTES: usize = 72;
const CHECKSUM_OFFSET: usize = 40;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.journal.transaction.v1\0";
const FRAME_DOMAIN: &[u8] = b"aos.sandbox.journal.frame.v1\0";
const IDEMPOTENCY_VALUE_BYTES: usize = 48;
const MAXIMUM_PROTECTED_COMPONENT_BYTES: usize = 255;
const MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES: usize = 200;

/// Bounds all disk input and in-memory work performed while opening a journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLimits {
    /// Maximum journal length accepted during replay.
    pub maximum_journal_bytes: u64,
    /// Maximum payload bytes in one record frame.
    pub maximum_record_bytes: usize,
    /// Maximum key bytes in one record.
    pub maximum_key_bytes: usize,
    /// Maximum records admitted in one transaction.
    pub maximum_records_per_transaction: usize,
    /// Maximum aggregate encoded record bytes admitted in one transaction.
    pub maximum_transaction_bytes: usize,
    /// Maximum committed transactions accepted during replay.
    pub maximum_transactions: usize,
    /// Maximum logical key and value bytes retained by the materialized view.
    pub maximum_materialized_bytes: usize,
    /// Maximum entries retained by the materialized view.
    pub maximum_materialized_records: usize,
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_key_bytes: 1024,
            maximum_records_per_transaction: 4096,
            maximum_transaction_bytes: 64 * 1024 * 1024,
            maximum_transactions: 1_000_000,
            maximum_materialized_bytes: 512 * 1024 * 1024,
            maximum_materialized_records: 1_000_000,
        }
    }
}

/// Selects the independently materialized keyspace changed by a record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RecordNamespace {
    /// Desired resource state indexed by stable resource identity.
    DesiredState = 1,
    /// Durable operation state indexed by operation identity.
    Operation = 2,
    /// Effect intent and completion evidence indexed by effect identity.
    Effect = 3,
    /// Idempotency decisions indexed by caller-provided request key.
    Idempotency = 4,
    /// Ownership-pending controller gates indexed by operation identity.
    OwnershipGate = 5,
    /// Durable authority publications isolated from generic desired-state keys.
    AuthorityPublication = 6,
    /// Controller-resolved publisher capabilities and current authority records.
    PublisherAuthority = 7,
    /// Current publisher policy, resource bindings, and controller generation heads.
    PublisherPolicy = 8,
    /// Publisher execution and immutable challenge-registration audit records.
    PublisherIngress = 9,
    /// Runtime holder decisions, pending intents, and monotone sandbox heads.
    RuntimeAuthority = 10,
    /// Immutable observed runtime generations and exact latest-generation heads.
    RuntimeGeneration = 11,
    /// Signed namespace targets allocated to observed runtime generations.
    NamespaceTarget = 12,
    /// Exact controller Mount attempts admitted from live namespace authority.
    MountAttempt = 13,
}

impl RecordNamespace {
    fn from_byte(value: u8) -> Result<Self, JournalError> {
        match value {
            1 => Ok(Self::DesiredState),
            2 => Ok(Self::Operation),
            3 => Ok(Self::Effect),
            4 => Ok(Self::Idempotency),
            5 => Ok(Self::OwnershipGate),
            6 => Ok(Self::AuthorityPublication),
            7 => Ok(Self::PublisherAuthority),
            8 => Ok(Self::PublisherPolicy),
            9 => Ok(Self::PublisherIngress),
            10 => Ok(Self::RuntimeAuthority),
            11 => Ok(Self::RuntimeGeneration),
            12 => Ok(Self::NamespaceTarget),
            13 => Ok(Self::MountAttempt),
            _ => Err(JournalError::MalformedRecord("unknown record namespace")),
        }
    }
}

/// Describes one value replacement or deletion inside a journal transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    namespace: RecordNamespace,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

impl JournalRecord {
    /// Constructs a value replacement.
    #[must_use]
    pub fn put(namespace: RecordNamespace, key: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            namespace,
            key,
            value: Some(value),
        }
    }

    /// Constructs an idempotent deletion.
    #[must_use]
    pub fn delete(namespace: RecordNamespace, key: Vec<u8>) -> Self {
        Self {
            namespace,
            key,
            value: None,
        }
    }

    /// Constructs an idempotency decision record.
    #[must_use]
    pub fn idempotency(
        key: &IdempotencyKey,
        request_digest: [u8; 32],
        operation_id: OperationId,
    ) -> Self {
        let mut value = Vec::with_capacity(IDEMPOTENCY_VALUE_BYTES);
        value.extend_from_slice(&request_digest);
        value.extend_from_slice(operation_id.as_bytes());
        Self::put(RecordNamespace::Idempotency, key.as_bytes().to_vec(), value)
    }

    /// Returns the record keyspace.
    #[must_use]
    pub const fn namespace(&self) -> RecordNamespace {
        self.namespace
    }

    /// Returns the opaque record key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the replacement value, or `None` for a deletion.
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

/// Carries one atomic group of desired-state and operation mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalTransaction {
    id: [u8; 16],
    records: Vec<JournalRecord>,
}

impl JournalTransaction {
    /// Constructs a transaction with a nonzero stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidTransaction`] when `id` is all zeroes or
    /// the transaction has no records.
    pub fn new(id: [u8; 16], records: Vec<JournalRecord>) -> Result<Self, JournalError> {
        if id == [0; 16] || records.is_empty() {
            return Err(JournalError::InvalidTransaction);
        }
        Ok(Self { id, records })
    }

    /// Returns the stable transaction identity.
    #[must_use]
    pub const fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Returns the ordered records committed by this transaction.
    #[must_use]
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }
}

/// Stores a bounded, nonempty opaque client idempotency key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IdempotencyKey(Vec<u8>);

impl IdempotencyKey {
    /// Validates a client idempotency key.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidIdempotencyKey`] for an empty key or a
    /// key longer than 128 bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, JournalError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > 128 {
            return Err(JournalError::InvalidIdempotencyKey);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact opaque key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Reports whether a request key is new, an exact replay, or a conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdempotencyOutcome {
    /// No durable decision exists for this key.
    Vacant,
    /// The exact semantic request was previously accepted as this operation.
    Replay(OperationId),
    /// The key is already bound to different semantic request bytes.
    Conflict,
}

/// Summarizes recovery performed while opening a journal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Number of committed transactions replayed.
    pub committed_transactions: usize,
    /// Number of committed records replayed.
    pub committed_records: usize,
    /// Structurally valid uncommitted or partial-tail bytes removed.
    pub truncated_bytes: u64,
}

/// Identifies the durable position reached by a successful commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitResult {
    /// Sequence number of the synced commit frame.
    pub commit_sequence: u64,
    /// Durable file length after the commit.
    pub durable_bytes: u64,
}

/// Reports journal validation, durability, and ownership failures.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// A filesystem operation failed.
    #[error("journal I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Another process owns the journal lock.
    #[error("journal is already owned by another process")]
    AlreadyLocked,
    /// The journal exceeds its configured replay byte bound.
    #[error("journal exceeds the configured replay byte bound")]
    JournalTooLarge,
    /// A frame uses an unsupported format version.
    #[error("unsupported journal format version {0}")]
    UnsupportedVersion(u16),
    /// A complete frame failed checksum validation.
    #[error("journal frame checksum mismatch at byte offset {0}")]
    ChecksumMismatch(u64),
    /// Frame sequence numbers are not exact and monotonic.
    #[error("journal sequence discontinuity at byte offset {0}")]
    SequenceDiscontinuity(u64),
    /// A frame violates transaction ordering or commit invariants.
    #[error("malformed journal transaction: {0}")]
    MalformedTransaction(&'static str),
    /// A record payload violates the closed binary schema.
    #[error("malformed journal record: {0}")]
    MalformedRecord(&'static str),
    /// A caller supplied an invalid transaction.
    #[error("transaction identity must be nonzero and records must be nonempty")]
    InvalidTransaction,
    /// A caller supplied an empty or oversized idempotency key.
    #[error("idempotency key must contain between 1 and 128 bytes")]
    InvalidIdempotencyKey,
    /// A configured size or count limit was exceeded.
    #[error("journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// A transaction changes the same logical key more than once.
    #[error("transaction contains duplicate logical record keys")]
    DuplicateRecordKey,
    /// A committed transaction identity was reused.
    #[error("transaction identity was already committed")]
    DuplicateTransaction,
    /// A committed idempotency key was rebound to another decision.
    #[error("idempotency key is already bound to another decision")]
    IdempotencyConflict,
    /// An earlier durability failure requires the journal to be reopened.
    #[error("journal handle is poisoned and must be reopened")]
    Poisoned,
    /// A protected path, owner, file type, or mode violates its boundary.
    #[error("protected journal storage boundary is invalid")]
    ProtectedBoundary,
    /// The kernel cannot enforce the protected opener's resolution policy.
    #[error("protected journal opening requires supported, permitted openat2 resolution")]
    UnsupportedProtectedOpen,
    /// Sequence space is exhausted and cannot safely wrap.
    #[error("journal sequence space is exhausted")]
    SequenceExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IdempotencyDecision {
    request_digest: [u8; 32],
    operation_id: OperationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum FrameKind {
    Begin = 1,
    Record = 2,
    Commit = 3,
}

impl FrameKind {
    fn from_byte(value: u8) -> Result<Self, JournalError> {
        match value {
            1 => Ok(Self::Begin),
            2 => Ok(Self::Record),
            3 => Ok(Self::Commit),
            _ => Err(JournalError::MalformedTransaction("unknown frame kind")),
        }
    }
}

struct Frame {
    kind: FrameKind,
    sequence: u64,
    transaction_id: [u8; 16],
    payload: Vec<u8>,
}

struct PendingTransaction {
    id: [u8; 16],
    expected_records: usize,
    records: Vec<JournalRecord>,
    digest: Sha256,
}

/// Owns one exclusively locked, append-only journal and its replayed indexes.
pub struct Journal {
    path: PathBuf,
    file: File,
    _lock: File,
    limits: JournalLimits,
    next_sequence: u64,
    committed_transactions: usize,
    transaction_ids: BTreeSet<[u8; 16]>,
    state: BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    materialized_bytes: usize,
    idempotency: BTreeMap<Vec<u8>, IdempotencyDecision>,
    poisoned: bool,
    protected: Option<ProtectedJournalLocation>,
}

struct ProtectedJournalLocation {
    directory: File,
    name: String,
    expected_uid: u32,
}

#[derive(Clone, Copy)]
enum ProtectedOwnerPolicy {
    Root,
    Exact(u32),
}

impl ProtectedOwnerPolicy {
    fn expected_uid(self) -> u32 {
        match self {
            Self::Root => 0,
            Self::Exact(uid) => uid,
        }
    }
}

impl Journal {
    /// Opens, exclusively locks, validates, and replays a journal.
    ///
    /// The parent directory must already exist. A partial final frame or a
    /// complete but uncommitted tail is truncated and synced before return.
    /// Complete corrupt frames and committed semantic corruption fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when ownership cannot be acquired, filesystem
    /// operations fail, a configured bound is exceeded, or durable bytes fail
    /// structural, sequence, checksum, or transaction validation.
    pub fn open(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        validate_limits(limits)?;
        let path = path.as_ref().to_path_buf();
        let lock_path = sibling_with_suffix(&path, ".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                JournalError::AlreadyLocked
            } else {
                JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error()))
            }
        })?;

        let existed = path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        if !existed {
            sync_parent(&path)?;
        }
        let length = file.metadata()?.len();
        if length > limits.maximum_journal_bytes {
            return Err(JournalError::JournalTooLarge);
        }

        let replay = replay(&mut file, limits)?;
        let truncated_bytes = length.saturating_sub(replay.durable_end);
        if truncated_bytes > 0 {
            file.set_len(replay.durable_end)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;

        let report = RecoveryReport {
            committed_transactions: replay.committed_transactions,
            committed_records: replay.committed_records,
            truncated_bytes,
        };
        Ok((
            Self {
                path,
                file,
                _lock: lock,
                limits,
                next_sequence: replay.next_sequence,
                committed_transactions: replay.committed_transactions,
                transaction_ids: replay.transaction_ids,
                state: replay.state,
                materialized_bytes: replay.materialized_bytes,
                idempotency: replay.idempotency,
                poisoned: false,
                protected: None,
            },
            report,
        ))
    }

    /// Opens a root-owned journal beneath one protected directory.
    ///
    /// `directory` must be an unambiguous absolute path. Resolution starts at
    /// an opened `/`, never follows symlinks, and requires every traversed
    /// directory to be root-owned and not group- or other-writable. The final
    /// directory must additionally be mode 0700 and remains open. `name` must
    /// be one ordinary basename. Journal and lock files are no-follow
    /// root-owned regular files mode 0600.
    /// Compaction uses an exclusive, unique temporary name and remains entirely
    /// relative to the retained directory FD, including cleanup and directory
    /// synchronization.
    ///
    /// This boundary provides local integrity and confidentiality against
    /// unprivileged users while the kernel and supplied root-owned directory
    /// remain trusted. It does not encrypt journal contents or authenticate
    /// records copied from another equally protected directory.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::ProtectedBoundary`] for a path, type, owner, or
    /// mode violation, [`JournalError::UnsupportedProtectedOpen`] when the
    /// kernel cannot enforce the required resolution policy, or another
    /// [`JournalError`] for lock, replay, or I/O failure. Callers must not fall
    /// back to [`Journal::open`] after either protected-opening error.
    pub fn open_protected_at(
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let directory = resolve_protected_directory_from_root(directory.as_ref(), 0)?;
        Self::open_protected_directory(directory, name, limits, ProtectedOwnerPolicy::Root)
    }

    /// Opens a protected journal owned by one configured service UID.
    ///
    /// Resolution starts at `/` and rejects symlinks and ambiguous components.
    /// Ancestors must be root-owned until ownership first transitions to
    /// `expected_uid`; all remaining ancestors must belong to that UID. No
    /// traversed directory may be group- or other-writable, including sticky
    /// directories. The final directory must have exactly mode 0700 and the
    /// expected owner. UID zero selects an entirely root-owned chain.
    ///
    /// Journal, lock, and compaction files retain the exact-owner, regular-file,
    /// mode-0600 checks of [`Self::open_protected_at`]. All effects stay relative
    /// to the retained final directory. This method neither changes credentials
    /// nor authenticates the configured UID: the service and root remain trusted,
    /// as do the kernel and filesystem enforcing these checks. Checksums do not
    /// authenticate records against that service or provide rollback protection.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::ProtectedBoundary`] for unsafe paths, ownership,
    /// types or modes, [`JournalError::UnsupportedProtectedOpen`] when the kernel
    /// cannot enforce resolution, or another journal error for I/O, locking or
    /// replay failures. Callers must not fall back to an unprotected opener.
    pub fn open_protected_at_for_uid(
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let directory = resolve_protected_directory_from_root(directory.as_ref(), expected_uid)?;
        Self::open_protected_directory(
            directory,
            name,
            limits,
            ProtectedOwnerPolicy::Exact(expected_uid),
        )
    }

    #[cfg(test)]
    pub(crate) fn open_protected_at_uid(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let directory: File = openat2(
            CWD,
            directory_path,
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(protected_open_error)?
        .into();
        Self::open_protected_directory(
            directory,
            name,
            limits,
            ProtectedOwnerPolicy::Exact(expected_uid),
        )
    }

    fn open_protected_directory(
        directory: File,
        name: &str,
        limits: JournalLimits,
        owner: ProtectedOwnerPolicy,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let expected_uid = owner.expected_uid();
        validate_limits(limits)?;
        if name.len() > MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES {
            return Err(JournalError::ProtectedBoundary);
        }
        validate_basename(name)?;
        validate_protected_fd(&directory, expected_uid, FileType::Directory, Mode::RWXU)?;
        let lock_name = format!("{name}.lock");
        let lock = open_protected_file(&directory, &lock_name, expected_uid, true, false, false)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                JournalError::AlreadyLocked
            } else {
                rustix_io(error)
            }
        })?;
        remove_stale_protected_compaction(&directory, name)?;
        let mut file = open_protected_file(&directory, name, expected_uid, true, false, false)?;
        fsync(&directory).map_err(rustix_io)?;
        let length = file.metadata()?.len();
        if length > limits.maximum_journal_bytes {
            return Err(JournalError::JournalTooLarge);
        }
        let replay = replay(&mut file, limits)?;
        let truncated_bytes = length.saturating_sub(replay.durable_end);
        if truncated_bytes > 0 {
            file.set_len(replay.durable_end)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        let report = RecoveryReport {
            committed_transactions: replay.committed_transactions,
            committed_records: replay.committed_records,
            truncated_bytes,
        };
        Ok((
            Self {
                path: PathBuf::from(name),
                file,
                _lock: lock,
                limits,
                next_sequence: replay.next_sequence,
                committed_transactions: replay.committed_transactions,
                transaction_ids: replay.transaction_ids,
                state: replay.state,
                materialized_bytes: replay.materialized_bytes,
                idempotency: replay.idempotency,
                poisoned: false,
                protected: Some(ProtectedJournalLocation {
                    directory,
                    name: name.to_owned(),
                    expected_uid,
                }),
            },
            report,
        ))
    }

    /// Rejects authority reads after an ambiguous durable mutation.
    ///
    /// Materialized values deliberately remain available for diagnostics after
    /// an I/O failure, but they may precede a transaction that reached disk.
    /// Authority consumers must use this guard before reading, including when
    /// rebuilding a facade around the same exclusively borrowed journal.
    pub(crate) fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.poisoned {
            Err(JournalError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Requires retained protected storage provenance before resolving authority.
    pub(crate) fn ensure_protected_authority(&self) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if self.protected.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Returns the currently materialized value for a logical key.
    ///
    /// This diagnostic view remains readable after an ambiguous I/O failure.
    /// It does not establish that the value is current durable authority.
    #[must_use]
    pub fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.state
            .get(&(namespace, key.to_vec()))
            .map(Vec::as_slice)
    }

    /// Iterates the materialized records in one namespace by bytewise key.
    ///
    /// The iterator is a stable snapshot only while this journal remains
    /// immutably borrowed. Callers must copy values needed across a commit.
    /// Like [`Self::get`], this diagnostic view does not establish current
    /// authority after an ambiguous I/O failure. The ordered namespace range
    /// avoids scanning unrelated desired-state and operation records.
    pub fn records(&self, namespace: RecordNamespace) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.state
            .range((namespace, Vec::new())..)
            .take_while(move |((record_namespace, _), _)| *record_namespace == namespace)
            .map(|((_, key), value)| (key.as_slice(), value.as_slice()))
    }

    /// Returns the next monotonic frame sequence defining the current snapshot boundary.
    ///
    /// The value starts at one for an empty journal and advances only after a
    /// transaction is durably committed. Inventory producers may therefore use
    /// it as a nonzero watermark without implying that an empty journal has a
    /// committed frame.
    #[must_use]
    pub const fn snapshot_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Resolves a caller key against durable semantic request identity.
    #[must_use]
    pub fn check_idempotency(
        &self,
        key: &IdempotencyKey,
        request_digest: [u8; 32],
    ) -> IdempotencyOutcome {
        match self.idempotency.get(key.as_bytes()) {
            None => IdempotencyOutcome::Vacant,
            Some(decision) if decision.request_digest == request_digest => {
                IdempotencyOutcome::Replay(decision.operation_id)
            }
            Some(_) => IdempotencyOutcome::Conflict,
        }
    }

    /// Appends and synchronously commits one transaction.
    ///
    /// The in-memory view changes only after all frames have been written and
    /// `sync_data` succeeds. An I/O error leaves the handle unusable for safe
    /// retry; callers must drop and reopen it to replay the durable prefix.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for invalid records, duplicate keys, exceeded
    /// bounds, exhausted sequence space, or an append/sync failure.
    pub fn commit(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        self.ensure_healthy()?;
        validate_transaction(transaction, self.limits)?;
        if self.transaction_ids.contains(transaction.id()) {
            return Err(JournalError::DuplicateTransaction);
        }
        if self.committed_transactions >= self.limits.maximum_transactions {
            return Err(JournalError::LimitExceeded("committed transaction count"));
        }
        validate_idempotency_changes(&self.idempotency, transaction.records())?;
        let materialized_bytes = validate_materialized_change(
            &self.state,
            self.materialized_bytes,
            transaction.records(),
            self.limits,
        )?;
        let frames = encode_transaction(transaction, self.next_sequence)?;
        let frame_count = u64::try_from(frames.len())
            .map_err(|_| JournalError::LimitExceeded("transaction frame count"))?;
        let commit_sequence = self
            .next_sequence
            .checked_add(frame_count - 1)
            .ok_or(JournalError::SequenceExhausted)?;
        let additional_bytes = frames
            .iter()
            .try_fold(0_u64, |total, frame| total.checked_add(frame.len() as u64));
        let expected_length = self
            .file
            .metadata()?
            .len()
            .checked_add(additional_bytes.ok_or(JournalError::JournalTooLarge)?)
            .ok_or(JournalError::JournalTooLarge)?;
        if expected_length > self.limits.maximum_journal_bytes {
            return Err(JournalError::JournalTooLarge);
        }

        let durable_bytes = match append_and_sync(&mut self.file, &frames) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if durable_bytes != expected_length {
            self.poisoned = true;
            return Err(JournalError::Io(io::Error::other(
                "journal length changed outside the exclusive writer",
            )));
        }

        for record in &transaction.records {
            apply_record(&mut self.state, &mut self.idempotency, record)?;
        }
        self.materialized_bytes = materialized_bytes;
        self.next_sequence = commit_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        self.committed_transactions += 1;
        self.transaction_ids.insert(transaction.id);

        Ok(CommitResult {
            commit_sequence,
            durable_bytes,
        })
    }

    /// Rewrites the materialized state into an atomically installed journal.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when the compacted state exceeds transaction
    /// bounds or any temporary-file, sync, rename, directory-sync, reopen, or
    /// validation operation fails.
    pub fn compact(&mut self) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if let Err(error) = self.compact_inner() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn compact_inner(&mut self) -> Result<(), JournalError> {
        if let Some(location) = &self.protected {
            let (file, replay) = compact_protected(location, &self.state, self.limits)?;
            self.file = file;
            self.next_sequence = replay.next_sequence;
            self.committed_transactions = replay.committed_transactions;
            self.transaction_ids = replay.transaction_ids;
            self.state = replay.state;
            self.materialized_bytes = replay.materialized_bytes;
            self.idempotency = replay.idempotency;
            return Ok(());
        }
        let temporary = sibling_with_suffix(&self.path, ".compact.tmp");
        let mut replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;

        write_compacted(&mut replacement, &self.state, self.limits)?;
        replacement.sync_all()?;
        if replacement.metadata()?.len() > self.limits.maximum_journal_bytes {
            return Err(JournalError::JournalTooLarge);
        }
        drop(replacement);

        fs::rename(&temporary, &self.path)?;
        sync_parent(&self.path)?;

        let (file, replay) = reopen_replacement(&self.path, self.limits)?;
        self.file = file;
        self.next_sequence = replay.next_sequence;
        self.committed_transactions = replay.committed_transactions;
        self.transaction_ids = replay.transaction_ids;
        self.state = replay.state;
        self.materialized_bytes = replay.materialized_bytes;
        self.idempotency = replay.idempotency;
        Ok(())
    }
}

struct ReplayState {
    durable_end: u64,
    next_sequence: u64,
    committed_transactions: usize,
    committed_records: usize,
    transaction_ids: BTreeSet<[u8; 16]>,
    state: BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    materialized_bytes: usize,
    idempotency: BTreeMap<Vec<u8>, IdempotencyDecision>,
}

fn replay(file: &mut File, limits: JournalLimits) -> Result<ReplayState, JournalError> {
    file.seek(SeekFrom::Start(0))?;
    let mut offset = 0_u64;
    let mut durable_end = 0_u64;
    let mut expected_sequence = 1_u64;
    let mut durable_next_sequence = 1_u64;
    let mut committed_transactions = 0_usize;
    let mut committed_records = 0_usize;
    let mut transaction_ids = BTreeSet::new();
    let mut state = BTreeMap::new();
    let mut materialized_bytes = 0_usize;
    let mut idempotency = BTreeMap::new();
    let mut pending: Option<PendingTransaction> = None;

    loop {
        let Some((frame, bytes_read)) = read_frame(file, offset, limits)? else {
            break;
        };
        if frame.sequence != expected_sequence {
            return Err(JournalError::SequenceDiscontinuity(offset));
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        offset = offset
            .checked_add(bytes_read)
            .ok_or(JournalError::JournalTooLarge)?;

        match frame.kind {
            FrameKind::Begin => {
                if pending.is_some() {
                    return Err(JournalError::MalformedTransaction("nested begin frame"));
                }
                let count = decode_count(&frame.payload)?;
                if count == 0 || count > limits.maximum_records_per_transaction {
                    return Err(JournalError::LimitExceeded("records per transaction"));
                }
                pending = Some(PendingTransaction {
                    id: frame.transaction_id,
                    expected_records: count,
                    records: Vec::with_capacity(count),
                    digest: transaction_hasher(),
                });
            }
            FrameKind::Record => {
                let transaction = pending.as_mut().ok_or(JournalError::MalformedTransaction(
                    "record outside transaction",
                ))?;
                if transaction.id != frame.transaction_id {
                    return Err(JournalError::MalformedTransaction(
                        "record transaction identity mismatch",
                    ));
                }
                if transaction.records.len() >= transaction.expected_records {
                    return Err(JournalError::MalformedTransaction("too many record frames"));
                }
                transaction.digest.update(&frame.payload);
                transaction
                    .records
                    .push(decode_record(&frame.payload, limits)?);
            }
            FrameKind::Commit => {
                let transaction = pending.take().ok_or(JournalError::MalformedTransaction(
                    "commit outside transaction",
                ))?;
                if transaction.id != frame.transaction_id
                    || transaction.records.len() != transaction.expected_records
                {
                    return Err(JournalError::MalformedTransaction(
                        "commit transaction identity or record count mismatch",
                    ));
                }
                validate_commit(&frame.payload, &transaction)?;
                let replay_transaction = JournalTransaction {
                    id: transaction.id,
                    records: transaction.records,
                };
                validate_transaction(&replay_transaction, limits)?;
                if !transaction_ids.insert(replay_transaction.id) {
                    return Err(JournalError::DuplicateTransaction);
                }
                validate_idempotency_changes(&idempotency, &replay_transaction.records)?;
                materialized_bytes = validate_materialized_change(
                    &state,
                    materialized_bytes,
                    &replay_transaction.records,
                    limits,
                )?;
                for record in &replay_transaction.records {
                    apply_record(&mut state, &mut idempotency, record)?;
                }
                committed_transactions = committed_transactions
                    .checked_add(1)
                    .ok_or(JournalError::LimitExceeded("committed transaction count"))?;
                if committed_transactions > limits.maximum_transactions {
                    return Err(JournalError::LimitExceeded("committed transaction count"));
                }
                committed_records = committed_records
                    .checked_add(replay_transaction.records.len())
                    .ok_or(JournalError::LimitExceeded("committed record count"))?;
                durable_end = offset;
                durable_next_sequence = expected_sequence;
            }
        }
    }

    Ok(ReplayState {
        durable_end,
        next_sequence: durable_next_sequence,
        committed_transactions,
        committed_records,
        transaction_ids,
        state,
        materialized_bytes,
        idempotency,
    })
}

fn read_frame(
    file: &mut File,
    offset: u64,
    limits: JournalLimits,
) -> Result<Option<(Frame, u64)>, JournalError> {
    let mut header = [0_u8; HEADER_BYTES];
    let mut filled = 0_usize;
    while filled < HEADER_BYTES {
        let read = file.read(&mut header[filled..])?;
        if read == 0 {
            return Ok(None);
        }
        filled += read;
    }
    if &header[..8] != MAGIC {
        return Err(JournalError::MalformedTransaction("invalid frame magic"));
    }
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version != FORMAT_VERSION {
        return Err(JournalError::UnsupportedVersion(version));
    }
    if header[11] != 0 {
        return Err(JournalError::MalformedTransaction(
            "nonzero reserved frame flags",
        ));
    }
    let kind = FrameKind::from_byte(header[10])?;
    let sequence = u64::from_le_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| JournalError::MalformedTransaction("invalid sequence field"))?,
    );
    let transaction_id = header[20..36]
        .try_into()
        .map_err(|_| JournalError::MalformedTransaction("invalid transaction identity"))?;
    if transaction_id == [0; 16] {
        return Err(JournalError::MalformedTransaction(
            "zero transaction identity",
        ));
    }
    let payload_length = u32::from_le_bytes(
        header[36..40]
            .try_into()
            .map_err(|_| JournalError::MalformedTransaction("invalid payload length"))?,
    ) as usize;
    let maximum_frame_payload = limits.maximum_record_bytes.saturating_add(7);
    if payload_length > maximum_frame_payload {
        return Err(JournalError::LimitExceeded("frame payload bytes"));
    }

    let mut payload = vec![0_u8; payload_length];
    let mut payload_filled = 0_usize;
    while payload_filled < payload_length {
        let read = file.read(&mut payload[payload_filled..])?;
        if read == 0 {
            return Ok(None);
        }
        payload_filled += read;
    }

    let expected_checksum: [u8; 32] = header[CHECKSUM_OFFSET..]
        .try_into()
        .map_err(|_| JournalError::MalformedTransaction("invalid checksum field"))?;
    let actual_checksum = frame_checksum(&header[..CHECKSUM_OFFSET], &payload);
    if expected_checksum != actual_checksum {
        return Err(JournalError::ChecksumMismatch(offset));
    }

    let bytes =
        u64::try_from(HEADER_BYTES + payload_length).map_err(|_| JournalError::JournalTooLarge)?;
    Ok(Some((
        Frame {
            kind,
            sequence,
            transaction_id,
            payload,
        },
        bytes,
    )))
}

fn validate_transaction(
    transaction: &JournalTransaction,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    if transaction.id == [0; 16] || transaction.records.is_empty() {
        return Err(JournalError::InvalidTransaction);
    }
    if transaction.records.len() > limits.maximum_records_per_transaction {
        return Err(JournalError::LimitExceeded("records per transaction"));
    }
    let mut keys = BTreeSet::new();
    let mut transaction_bytes = 0_usize;
    for record in &transaction.records {
        if record.key.is_empty() || record.key.len() > limits.maximum_key_bytes {
            return Err(JournalError::LimitExceeded("record key bytes"));
        }
        let encoded = encode_record(record)?;
        if encoded.len() > limits.maximum_record_bytes {
            return Err(JournalError::LimitExceeded("record payload bytes"));
        }
        transaction_bytes = transaction_bytes
            .checked_add(encoded.len())
            .ok_or(JournalError::LimitExceeded("transaction bytes"))?;
        if transaction_bytes > limits.maximum_transaction_bytes {
            return Err(JournalError::LimitExceeded("transaction bytes"));
        }
        if record.namespace == RecordNamespace::Idempotency {
            let value = record.value.as_ref().ok_or(JournalError::MalformedRecord(
                "idempotency records cannot be deleted",
            ))?;
            if IdempotencyKey::new(record.key.clone()).is_err()
                || value.len() != IDEMPOTENCY_VALUE_BYTES
                || value[32..] == [0; 16]
            {
                return Err(JournalError::MalformedRecord(
                    "invalid idempotency decision",
                ));
            }
        }
        if !keys.insert((record.namespace, record.key.clone())) {
            return Err(JournalError::DuplicateRecordKey);
        }
    }
    Ok(())
}

fn validate_limits(limits: JournalLimits) -> Result<(), JournalError> {
    if limits.maximum_journal_bytes < HEADER_BYTES as u64
        || limits.maximum_record_bytes < 7
        || limits.maximum_key_bytes == 0
        || limits.maximum_key_bytes > u16::MAX as usize
        || limits.maximum_records_per_transaction == 0
        || limits.maximum_transaction_bytes < 7
        || limits.maximum_transactions == 0
        || limits.maximum_materialized_bytes == 0
        || limits.maximum_materialized_records == 0
    {
        return Err(JournalError::LimitExceeded("invalid journal configuration"));
    }
    Ok(())
}

fn validate_materialized_change(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    current_bytes: usize,
    records: &[JournalRecord],
    limits: JournalLimits,
) -> Result<usize, JournalError> {
    let mut bytes = current_bytes;
    let mut entries = state.len();
    for record in records {
        let key = (record.namespace, record.key.clone());
        let existing = state.get(&key);
        if let Some(value) = existing {
            bytes = bytes.saturating_sub(record.key.len().saturating_add(value.len()));
        }
        match &record.value {
            Some(value) => {
                if existing.is_none() {
                    entries = entries
                        .checked_add(1)
                        .ok_or(JournalError::LimitExceeded("materialized record count"))?;
                }
                bytes = bytes
                    .checked_add(record.key.len())
                    .and_then(|size| size.checked_add(value.len()))
                    .ok_or(JournalError::LimitExceeded("materialized state bytes"))?;
            }
            None if existing.is_some() => entries -= 1,
            None => {}
        }
    }
    if bytes > limits.maximum_materialized_bytes {
        return Err(JournalError::LimitExceeded("materialized state bytes"));
    }
    if entries > limits.maximum_materialized_records {
        return Err(JournalError::LimitExceeded("materialized record count"));
    }
    Ok(bytes)
}

fn validate_idempotency_changes(
    idempotency: &BTreeMap<Vec<u8>, IdempotencyDecision>,
    records: &[JournalRecord],
) -> Result<(), JournalError> {
    for record in records {
        if record.namespace != RecordNamespace::Idempotency {
            continue;
        }
        let value = record.value.as_ref().ok_or(JournalError::MalformedRecord(
            "idempotency records cannot be deleted",
        ))?;
        let request_digest = value[..32]
            .try_into()
            .map_err(|_| JournalError::MalformedRecord("invalid idempotency digest"))?;
        let operation_bytes = value[32..]
            .try_into()
            .map_err(|_| JournalError::MalformedRecord("invalid operation identity"))?;
        let proposed = IdempotencyDecision {
            request_digest,
            operation_id: OperationId::from_bytes(operation_bytes),
        };
        if idempotency
            .get(&record.key)
            .is_some_and(|existing| existing != &proposed)
        {
            return Err(JournalError::IdempotencyConflict);
        }
    }
    Ok(())
}

fn append_and_sync(file: &mut File, frames: &[Vec<u8>]) -> Result<u64, JournalError> {
    for frame in frames {
        file.write_all(frame)?;
    }
    file.flush()?;
    file.sync_data()?;
    Ok(file.metadata()?.len())
}

fn encode_transaction(
    transaction: &JournalTransaction,
    first_sequence: u64,
) -> Result<Vec<Vec<u8>>, JournalError> {
    let record_count = u32::try_from(transaction.records.len())
        .map_err(|_| JournalError::LimitExceeded("records per transaction"))?;
    let mut sequence = first_sequence;
    let mut frames = Vec::with_capacity(transaction.records.len() + 2);
    frames.push(encode_frame(
        FrameKind::Begin,
        sequence,
        transaction.id,
        &record_count.to_le_bytes(),
    )?);
    sequence = sequence
        .checked_add(1)
        .ok_or(JournalError::SequenceExhausted)?;

    let mut transaction_digest = transaction_hasher();
    for record in &transaction.records {
        let payload = encode_record(record)?;
        transaction_digest.update(&payload);
        frames.push(encode_frame(
            FrameKind::Record,
            sequence,
            transaction.id,
            &payload,
        )?);
        sequence = sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
    }

    let mut commit = Vec::with_capacity(36);
    commit.extend_from_slice(&record_count.to_le_bytes());
    commit.extend_from_slice(&transaction_digest.finalize());
    frames.push(encode_frame(
        FrameKind::Commit,
        sequence,
        transaction.id,
        &commit,
    )?);
    Ok(frames)
}

fn encode_frame(
    kind: FrameKind,
    sequence: u64,
    transaction_id: [u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, JournalError> {
    let payload_length = u32::try_from(payload.len())
        .map_err(|_| JournalError::LimitExceeded("frame payload bytes"))?;
    let mut header = [0_u8; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[10] = kind as u8;
    header[12..20].copy_from_slice(&sequence.to_le_bytes());
    header[20..36].copy_from_slice(&transaction_id);
    header[36..40].copy_from_slice(&payload_length.to_le_bytes());
    let checksum = frame_checksum(&header[..CHECKSUM_OFFSET], payload);
    header[CHECKSUM_OFFSET..].copy_from_slice(&checksum);

    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn frame_checksum(header_prefix: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(FRAME_DOMAIN);
    digest.update(header_prefix);
    digest.update(payload);
    digest.finalize().into()
}

fn transaction_hasher() -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest
}

fn encode_record(record: &JournalRecord) -> Result<Vec<u8>, JournalError> {
    let key_length = u16::try_from(record.key.len())
        .map_err(|_| JournalError::LimitExceeded("record key bytes"))?;
    let value_length = match &record.value {
        Some(value) => u32::try_from(value.len())
            .map_err(|_| JournalError::LimitExceeded("record value bytes"))?,
        None => u32::MAX,
    };
    let value_bytes = record.value.as_deref().unwrap_or_default();
    let mut payload = Vec::with_capacity(7 + record.key.len() + value_bytes.len());
    payload.push(record.namespace as u8);
    payload.extend_from_slice(&key_length.to_le_bytes());
    payload.extend_from_slice(&value_length.to_le_bytes());
    payload.extend_from_slice(&record.key);
    payload.extend_from_slice(value_bytes);
    Ok(payload)
}

fn decode_record(payload: &[u8], limits: JournalLimits) -> Result<JournalRecord, JournalError> {
    if payload.len() < 7 {
        return Err(JournalError::MalformedRecord("record header is truncated"));
    }
    let namespace = RecordNamespace::from_byte(payload[0])?;
    let key_length = u16::from_le_bytes([payload[1], payload[2]]) as usize;
    let value_length = u32::from_le_bytes(
        payload[3..7]
            .try_into()
            .map_err(|_| JournalError::MalformedRecord("invalid value length"))?,
    );
    if key_length == 0 || key_length > limits.maximum_key_bytes {
        return Err(JournalError::LimitExceeded("record key bytes"));
    }
    let expected = if value_length == u32::MAX {
        7_usize.checked_add(key_length)
    } else {
        7_usize
            .checked_add(key_length)
            .and_then(|length| length.checked_add(value_length as usize))
    }
    .ok_or(JournalError::LimitExceeded("record payload bytes"))?;
    if expected != payload.len() || payload.len() > limits.maximum_record_bytes {
        return Err(JournalError::MalformedRecord("record length mismatch"));
    }
    let key = payload[7..7 + key_length].to_vec();
    let value = if value_length == u32::MAX {
        None
    } else {
        Some(payload[7 + key_length..].to_vec())
    };
    Ok(JournalRecord {
        namespace,
        key,
        value,
    })
}

fn decode_count(payload: &[u8]) -> Result<usize, JournalError> {
    if payload.len() != 4 {
        return Err(JournalError::MalformedTransaction(
            "invalid begin record count",
        ));
    }
    Ok(u32::from_le_bytes(
        payload
            .try_into()
            .map_err(|_| JournalError::MalformedTransaction("invalid begin payload"))?,
    ) as usize)
}

fn validate_commit(payload: &[u8], transaction: &PendingTransaction) -> Result<(), JournalError> {
    if payload.len() != 36 {
        return Err(JournalError::MalformedTransaction("invalid commit payload"));
    }
    let count = u32::from_le_bytes(
        payload[..4]
            .try_into()
            .map_err(|_| JournalError::MalformedTransaction("invalid commit count"))?,
    ) as usize;
    if count != transaction.expected_records {
        return Err(JournalError::MalformedTransaction(
            "commit record count mismatch",
        ));
    }
    let expected: [u8; 32] = payload[4..]
        .try_into()
        .map_err(|_| JournalError::MalformedTransaction("invalid commit digest"))?;
    let actual: [u8; 32] = transaction.digest.clone().finalize().into();
    if expected != actual {
        return Err(JournalError::MalformedTransaction(
            "transaction digest mismatch",
        ));
    }
    Ok(())
}

fn apply_record(
    state: &mut BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    idempotency: &mut BTreeMap<Vec<u8>, IdempotencyDecision>,
    record: &JournalRecord,
) -> Result<(), JournalError> {
    let composite_key = (record.namespace, record.key.clone());
    match &record.value {
        Some(value) => {
            state.insert(composite_key, value.clone());
        }
        None => {
            state.remove(&composite_key);
        }
    }

    if record.namespace == RecordNamespace::Idempotency {
        let value = record.value.as_ref().ok_or(JournalError::MalformedRecord(
            "idempotency records cannot be deleted",
        ))?;
        let request_digest = value[..32]
            .try_into()
            .map_err(|_| JournalError::MalformedRecord("invalid idempotency digest"))?;
        let operation_bytes = value[32..]
            .try_into()
            .map_err(|_| JournalError::MalformedRecord("invalid operation identity"))?;
        idempotency.insert(
            record.key.clone(),
            IdempotencyDecision {
                request_digest,
                operation_id: OperationId::from_bytes(operation_bytes),
            },
        );
    }
    Ok(())
}

fn write_compacted(
    file: &mut File,
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    let mut first_sequence = 1_u64;
    let mut transaction_index = 0_u64;
    let mut chunk = Vec::new();
    let mut chunk_bytes = 0_usize;
    for ((namespace, key), value) in state {
        let record = JournalRecord::put(*namespace, key.clone(), value.clone());
        let record_bytes = encode_record(&record)?.len();
        if !chunk.is_empty()
            && (chunk.len() == limits.maximum_records_per_transaction
                || chunk_bytes.saturating_add(record_bytes) > limits.maximum_transaction_bytes)
        {
            if transaction_index >= limits.maximum_transactions as u64 {
                return Err(JournalError::LimitExceeded("committed transaction count"));
            }
            first_sequence = write_compaction_transaction(
                file,
                &chunk,
                transaction_index,
                first_sequence,
                limits,
            )?;
            transaction_index = transaction_index
                .checked_add(1)
                .ok_or(JournalError::SequenceExhausted)?;
            chunk.clear();
            chunk_bytes = 0;
        }
        chunk_bytes = chunk_bytes
            .checked_add(record_bytes)
            .ok_or(JournalError::LimitExceeded("transaction bytes"))?;
        chunk.push(record);
    }
    if !chunk.is_empty() {
        if transaction_index >= limits.maximum_transactions as u64 {
            return Err(JournalError::LimitExceeded("committed transaction count"));
        }
        write_compaction_transaction(file, &chunk, transaction_index, first_sequence, limits)?;
    }
    file.flush()?;
    Ok(())
}

fn write_compaction_transaction(
    file: &mut File,
    records: &[JournalRecord],
    transaction_index: u64,
    first_sequence: u64,
    limits: JournalLimits,
) -> Result<u64, JournalError> {
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&(transaction_index + 1).to_le_bytes());
    id[8..].copy_from_slice(b"compact1");
    let transaction = JournalTransaction::new(id, records.to_vec())?;
    validate_transaction(&transaction, limits)?;
    let frames = encode_transaction(&transaction, first_sequence)?;
    for frame in &frames {
        file.write_all(frame)?;
    }
    first_sequence
        .checked_add(frames.len() as u64)
        .ok_or(JournalError::SequenceExhausted)
}

fn reopen_replacement(
    path: &Path,
    limits: JournalLimits,
) -> Result<(File, ReplayState), JournalError> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let replay = replay(&mut file, limits)?;
    if replay.durable_end != file.metadata()?.len() {
        return Err(JournalError::MalformedTransaction(
            "compacted journal has an uncommitted tail",
        ));
    }
    file.seek(SeekFrom::End(0))?;
    Ok((file, replay))
}

fn protected_directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn resolve_protected_directory_from_root(
    path: &Path,
    expected_uid: u32,
) -> Result<File, JournalError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.first() != Some(&b'/') {
        return Err(JournalError::ProtectedBoundary);
    }
    let components = &bytes[1..];
    if components.is_empty() {
        return Err(JournalError::ProtectedBoundary);
    }
    let components = components.split(|byte| *byte == b'/');
    if components.clone().any(|component| {
        component.is_empty()
            || component == b"."
            || component == b".."
            || component.contains(&0)
            || component.len() > MAXIMUM_PROTECTED_COMPONENT_BYTES
    }) {
        return Err(JournalError::ProtectedBoundary);
    }

    let root: File = openat2(
        CWD,
        "/",
        protected_directory_flags(),
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(protected_open_error)?
    .into();
    traverse_protected_directory(root, components, expected_uid)
}

fn traverse_protected_directory<'a>(
    mut directory: File,
    components: impl IntoIterator<Item = &'a [u8]>,
    expected_uid: u32,
) -> Result<File, JournalError> {
    let mut ancestry = ProtectedAncestry::new(expected_uid);
    ancestry.admit(&directory)?;
    for component in components {
        let child: File = openat2(
            &directory,
            OsStr::from_bytes(component),
            protected_directory_flags(),
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(protected_open_error)?
        .into();
        ancestry.admit(&child)?;
        directory = child;
    }
    validate_protected_fd(&directory, expected_uid, FileType::Directory, Mode::RWXU)?;
    Ok(directory)
}

/// Tracks the one-way transition from administrative to service-owned ancestry.
struct ProtectedAncestry {
    expected_uid: u32,
    service_owned: bool,
}

impl ProtectedAncestry {
    const fn new(expected_uid: u32) -> Self {
        Self {
            expected_uid,
            service_owned: false,
        }
    }

    fn admit(&mut self, file: &File) -> Result<(), JournalError> {
        let stat = fstat(file).map_err(rustix_io)?;
        self.admit_metadata(stat.st_uid, stat.st_mode)
    }

    fn admit_metadata(&mut self, uid: u32, mode: u32) -> Result<(), JournalError> {
        if FileType::from_raw_mode(mode) != FileType::Directory || mode & 0o022 != 0 {
            return Err(JournalError::ProtectedBoundary);
        }
        if uid == self.expected_uid {
            self.service_owned = true;
        } else if uid != 0 || self.service_owned {
            // A root-owned descendant cannot restore trust after a service has
            // acquired authority over the path above it.
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

fn validate_basename(name: &str) -> Result<(), JournalError> {
    if name.is_empty()
        || name.len() > MAXIMUM_PROTECTED_COMPONENT_BYTES
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&0)
        || name.as_bytes().contains(&b'/')
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn rustix_io(error: rustix::io::Errno) -> JournalError {
    JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error()))
}

fn protected_open_error(error: rustix::io::Errno) -> JournalError {
    if error == rustix::io::Errno::NOSYS
        || error == rustix::io::Errno::PERM
        || error == rustix::io::Errno::INVAL
    {
        JournalError::UnsupportedProtectedOpen
    } else if error == rustix::io::Errno::LOOP
        || error == rustix::io::Errno::XDEV
        || error == rustix::io::Errno::NOTDIR
        || error == rustix::io::Errno::ISDIR
        || error == rustix::io::Errno::ACCESS
    {
        JournalError::ProtectedBoundary
    } else {
        rustix_io(error)
    }
}

fn protected_compaction_name(name: &str) -> String {
    format!("{name}.compact.tmp")
}

fn remove_stale_protected_compaction(directory: &File, name: &str) -> Result<(), JournalError> {
    let temporary = protected_compaction_name(name);
    validate_basename(&temporary)?;
    match unlinkat(directory, temporary.as_str(), AtFlags::empty()) {
        Ok(()) => fsync(directory).map_err(rustix_io),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(rustix_io(error)),
    }
}

fn validate_protected_fd(
    file: &File,
    expected_uid: u32,
    expected_type: FileType,
    expected_mode: Mode,
) -> Result<(), JournalError> {
    let stat = fstat(file).map_err(rustix_io)?;
    if stat.st_uid != expected_uid
        || FileType::from_raw_mode(stat.st_mode) != expected_type
        || Mode::from_raw_mode(stat.st_mode) != expected_mode
        || (expected_type == FileType::RegularFile && stat.st_nlink != 1)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn open_protected_file(
    directory: &File,
    name: &str,
    expected_uid: u32,
    create: bool,
    exclusive: bool,
    truncate: bool,
) -> Result<File, JournalError> {
    validate_basename(name)?;
    let mut flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if create {
        flags |= OFlags::CREATE;
    }
    if exclusive {
        flags |= OFlags::EXCL;
    }
    if truncate {
        flags |= OFlags::TRUNC;
    }
    let create_mode = if create {
        Mode::RUSR | Mode::WUSR
    } else {
        Mode::empty()
    };
    let file: File = openat2(
        directory,
        name,
        flags,
        create_mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(protected_open_error)?
    .into();
    if let Err(error) = validate_protected_fd(
        &file,
        expected_uid,
        FileType::RegularFile,
        Mode::RUSR | Mode::WUSR,
    ) {
        if create && exclusive {
            drop(file);
            let _ = unlinkat(directory, name, AtFlags::empty());
            let _ = fsync(directory);
        }
        return Err(error);
    }
    Ok(file)
}

/// Removes an uncommitted compaction file relative to the retained directory.
struct ProtectedTemporary<'a> {
    directory: &'a File,
    name: String,
    armed: bool,
}

impl ProtectedTemporary<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProtectedTemporary<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlinkat(self.directory, self.name.as_str(), AtFlags::empty());
            let _ = fsync(self.directory);
        }
    }
}

fn compact_protected(
    location: &ProtectedJournalLocation,
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    limits: JournalLimits,
) -> Result<(File, ReplayState), JournalError> {
    let temporary = protected_compaction_name(&location.name);
    let mut replacement = open_protected_file(
        &location.directory,
        &temporary,
        location.expected_uid,
        true,
        true,
        true,
    )?;
    let mut cleanup = ProtectedTemporary {
        directory: &location.directory,
        name: temporary.clone(),
        armed: true,
    };
    write_compacted(&mut replacement, state, limits)?;
    replacement.sync_all()?;
    if replacement.metadata()?.len() > limits.maximum_journal_bytes {
        return Err(JournalError::JournalTooLarge);
    }
    drop(replacement);
    renameat(
        &location.directory,
        temporary.as_str(),
        &location.directory,
        location.name.as_str(),
    )
    .map_err(rustix_io)?;
    cleanup.disarm();
    fsync(&location.directory).map_err(rustix_io)?;
    let mut file = open_protected_file(
        &location.directory,
        &location.name,
        location.expected_uid,
        false,
        false,
        false,
    )?;
    let replay = replay(&mut file, limits)?;
    if replay.durable_end != file.metadata()?.len() {
        return Err(JournalError::MalformedTransaction(
            "compacted journal has an uncommitted tail",
        ));
    }
    file.seek(SeekFrom::End(0))?;
    Ok((file, replay))
}

fn sync_parent(path: &Path) -> Result<(), JournalError> {
    let parent = path.parent().ok_or_else(|| {
        JournalError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal path has no parent directory",
        ))
    })?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::{self, File, OpenOptions};
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use aos_sandbox_core::OperationId;

    use super::{
        HEADER_BYTES, IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalLimits,
        JournalRecord, JournalTransaction, MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES,
        ProtectedAncestry, ProtectedOwnerPolicy, RecordNamespace, RecoveryReport,
        encode_transaction, open_protected_file, protected_open_error,
        traverse_protected_directory,
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-sandbox-journal-{label}-{}-{}",
                std::process::id(),
                OperationId::new()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("state.journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn transaction(id: u8, records: Vec<JournalRecord>) -> JournalTransaction {
        JournalTransaction::new([id; 16], records).unwrap()
    }

    #[test]
    fn namespace_codes_are_append_only_and_unknown_codes_fail_closed() {
        let namespaces = [
            RecordNamespace::DesiredState,
            RecordNamespace::Operation,
            RecordNamespace::Effect,
            RecordNamespace::Idempotency,
            RecordNamespace::OwnershipGate,
            RecordNamespace::AuthorityPublication,
            RecordNamespace::PublisherAuthority,
            RecordNamespace::PublisherPolicy,
            RecordNamespace::PublisherIngress,
            RecordNamespace::RuntimeAuthority,
            RecordNamespace::RuntimeGeneration,
            RecordNamespace::NamespaceTarget,
            RecordNamespace::MountAttempt,
        ];
        for (index, namespace) in namespaces.into_iter().enumerate() {
            let code = u8::try_from(index + 1).unwrap();
            assert_eq!(namespace as u8, code);
            assert_eq!(RecordNamespace::from_byte(code).unwrap(), namespace);
        }
        for code in [0, 14, 255] {
            assert!(RecordNamespace::from_byte(code).is_err());
        }
    }

    #[test]
    fn publisher_authority_namespace_survives_replay_and_compaction() {
        let directory = TestDirectory::new("publisher-namespace");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let key = b"same-key".to_vec();
        journal
            .commit(&transaction(
                1,
                vec![
                    JournalRecord::put(
                        RecordNamespace::PublisherAuthority,
                        key.clone(),
                        b"publisher-record".to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::AuthorityPublication,
                        key.clone(),
                        b"assignment-record".to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::PublisherPolicy,
                        key.clone(),
                        b"policy-record".to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::PublisherIngress,
                        key.clone(),
                        b"ingress-record".to_vec(),
                    ),
                ],
            ))
            .unwrap();
        journal.compact().unwrap();
        drop(journal);

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert_eq!(
            journal.get(RecordNamespace::PublisherAuthority, &key),
            Some(b"publisher-record".as_slice()),
        );
        assert_eq!(
            journal.get(RecordNamespace::AuthorityPublication, &key),
            Some(b"assignment-record".as_slice()),
        );
        assert_eq!(
            journal
                .records(RecordNamespace::AuthorityPublication)
                .collect::<Vec<_>>(),
            vec![(key.as_slice(), b"assignment-record".as_slice())],
        );
        assert_eq!(
            journal
                .records(RecordNamespace::PublisherAuthority)
                .collect::<Vec<_>>(),
            vec![(key.as_slice(), b"publisher-record".as_slice())],
        );
        assert_eq!(journal.records(RecordNamespace::DesiredState).count(), 0);
        assert_eq!(
            journal
                .records(RecordNamespace::PublisherPolicy)
                .collect::<Vec<_>>(),
            vec![(key.as_slice(), b"policy-record".as_slice())],
        );
        assert_eq!(
            journal
                .records(RecordNamespace::PublisherIngress)
                .collect::<Vec<_>>(),
            vec![(key.as_slice(), b"ingress-record".as_slice())],
        );
    }

    fn protected_open(directory: &Path) -> Result<(Journal, RecoveryReport), JournalError> {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory).unwrap().uid();
        Journal::open_protected_at_uid(
            directory,
            "protected.journal",
            JournalLimits::default(),
            uid,
        )
    }

    #[test]
    fn service_ancestry_only_transitions_from_root_to_exact_owner() {
        let directory_mode = rustix::fs::FileType::Directory.as_raw_mode() | 0o755;
        for owners in [vec![0, 0, 1000, 1000], vec![1000, 1000]] {
            let mut policy = ProtectedAncestry::new(1000);
            for uid in owners {
                policy.admit_metadata(uid, directory_mode).unwrap();
            }
        }
        for owners in [vec![0, 1001], vec![0, 1000, 1001], vec![0, 1000, 0]] {
            let mut policy = ProtectedAncestry::new(1000);
            let mut rejected = false;
            for uid in owners {
                if policy.admit_metadata(uid, directory_mode).is_err() {
                    rejected = true;
                    break;
                }
            }
            assert!(rejected);
        }
        let mut root_only = ProtectedAncestry::new(0);
        root_only.admit_metadata(0, directory_mode).unwrap();
        root_only.admit_metadata(0, directory_mode).unwrap();
        assert!(root_only.admit_metadata(1000, directory_mode).is_err());
    }

    #[test]
    fn service_ancestry_rejects_writable_directories_and_non_directories() {
        for owner in [0, 1000] {
            for mode in [0o722, 0o770, 0o777, 0o1777] {
                let mut policy = ProtectedAncestry::new(1000);
                assert!(
                    policy
                        .admit_metadata(owner, rustix::fs::FileType::Directory.as_raw_mode() | mode)
                        .is_err()
                );
            }
            let mut policy = ProtectedAncestry::new(1000);
            assert!(
                policy
                    .admit_metadata(
                        owner,
                        rustix::fs::FileType::RegularFile.as_raw_mode() | 0o700
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn service_opener_never_skips_unsafe_absolute_ancestry() {
        let directory = TestDirectory::new("service-ancestry");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o777)).unwrap();
        let leaf = directory.0.join("private");
        fs::create_dir(&leaf).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        // The private test opener accepts this leaf, but production must reject
        // its writable ancestor regardless of the leaf's owner and mode. The
        // fixture owns that ancestor; no property of the host TMPDIR is assumed.
        assert!(matches!(
            Journal::open_protected_at_for_uid(
                &leaf,
                "state.journal",
                JournalLimits::default(),
                uid,
            ),
            Err(JournalError::ProtectedBoundary)
        ));
        for path in [
            "relative",
            "",
            "/",
            "/tmp//leaf",
            "/tmp/./leaf",
            "/tmp/../leaf",
        ] {
            assert!(matches!(
                Journal::open_protected_at_for_uid(
                    path,
                    "state.journal",
                    JournalLimits::default(),
                    uid,
                ),
                Err(JournalError::ProtectedBoundary)
            ));
        }
    }

    #[test]
    fn protected_open_rejects_public_modes_and_symlinks() {
        let directory = TestDirectory::new("protected-rejections");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        assert!(matches!(
            Journal::open_protected_at_uid(
                &directory.0,
                "protected.journal",
                JournalLimits::default(),
                uid,
            ),
            Err(JournalError::ProtectedBoundary)
        ));

        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let target = directory.0.join("target");
        fs::write(&target, b"").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, directory.0.join("protected.journal")).unwrap();
        assert!(protected_open(&directory.0).is_err());
        fs::remove_file(directory.0.join("protected.journal")).unwrap();
        fs::write(directory.0.join("protected.journal"), b"").unwrap();
        fs::set_permissions(
            directory.0.join("protected.journal"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            protected_open(&directory.0),
            Err(JournalError::ProtectedBoundary)
        ));
        fs::remove_file(directory.0.join("protected.journal")).unwrap();
        fs::remove_file(directory.0.join("protected.journal.lock")).unwrap();
        symlink(&target, directory.0.join("protected.journal.lock")).unwrap();
        assert!(protected_open(&directory.0).is_err());
        fs::remove_file(directory.0.join("protected.journal.lock")).unwrap();
        fs::create_dir(directory.0.join("protected.journal")).unwrap();
        assert!(protected_open(&directory.0).is_err());
        fs::remove_dir(directory.0.join("protected.journal")).unwrap();

        fs::hard_link(&target, directory.0.join("protected.journal")).unwrap();
        assert!(matches!(
            protected_open(&directory.0),
            Err(JournalError::ProtectedBoundary)
        ));
        fs::remove_file(directory.0.join("protected.journal")).unwrap();
        fs::remove_file(directory.0.join("protected.journal.lock")).unwrap();
        fs::hard_link(&target, directory.0.join("protected.journal.lock")).unwrap();
        assert!(matches!(
            protected_open(&directory.0),
            Err(JournalError::ProtectedBoundary)
        ));
        fs::remove_file(directory.0.join("protected.journal.lock")).unwrap();

        assert!(matches!(
            Journal::open_protected_at_uid(
                &directory.0,
                "protected.journal",
                JournalLimits::default(),
                uid.wrapping_add(1),
            ),
            Err(JournalError::ProtectedBoundary)
        ));

        let alias = directory.0.with_extension("symlink");
        symlink(&directory.0, &alias).unwrap();
        assert!(
            Journal::open_protected_at_uid(
                &alias,
                "another.journal",
                JournalLimits::default(),
                uid,
            )
            .is_err()
        );
        fs::remove_file(alias).unwrap();

        let maximum_name = "j".repeat(MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES);
        let (mut journal, _) = Journal::open_protected_at_uid(
            &directory.0,
            &maximum_name,
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        journal.compact().unwrap();
        drop(journal);
        assert!(matches!(
            Journal::open_protected_at_uid(
                &directory.0,
                &"j".repeat(MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES + 1),
                JournalLimits::default(),
                uid,
            ),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn protected_traversal_rejects_untrusted_ancestors_and_relative_paths() {
        assert!(matches!(
            Journal::open_protected_at(
                "relative/protected",
                "state.journal",
                JournalLimits::default(),
            ),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            Journal::open_protected_at(
                "/tmp//ambiguous",
                "state.journal",
                JournalLimits::default(),
            ),
            Err(JournalError::ProtectedBoundary)
        ));

        let root = TestDirectory::new("protected-ancestry");
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&root.0).unwrap().uid();
        fs::create_dir(root.0.join("trusted")).unwrap();
        fs::set_permissions(root.0.join("trusted"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.0.join("trusted/final")).unwrap();
        fs::set_permissions(
            root.0.join("trusted/final"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let directory = traverse_protected_directory(
            File::open(&root.0).unwrap(),
            [b"trusted".as_slice(), b"final".as_slice()],
            uid,
        )
        .unwrap();
        let (journal, _) = Journal::open_protected_directory(
            directory,
            "state.journal",
            JournalLimits::default(),
            ProtectedOwnerPolicy::Exact(uid),
        )
        .unwrap();
        drop(journal);

        fs::create_dir(root.0.join("writable")).unwrap();
        fs::set_permissions(root.0.join("writable"), fs::Permissions::from_mode(0o777)).unwrap();
        fs::create_dir(root.0.join("writable/final")).unwrap();
        fs::set_permissions(
            root.0.join("writable/final"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(matches!(
            traverse_protected_directory(
                File::open(&root.0).unwrap(),
                [b"writable".as_slice(), b"final".as_slice()],
                uid,
            ),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn protected_open_errors_distinguish_policy_and_kernel_support() {
        assert!(matches!(
            protected_open_error(rustix::io::Errno::LOOP),
            JournalError::ProtectedBoundary
        ));
        assert!(matches!(
            protected_open_error(rustix::io::Errno::XDEV),
            JournalError::ProtectedBoundary
        ));
        assert!(matches!(
            protected_open_error(rustix::io::Errno::NOSYS),
            JournalError::UnsupportedProtectedOpen
        ));
        assert!(matches!(
            protected_open_error(rustix::io::Errno::PERM),
            JournalError::UnsupportedProtectedOpen
        ));
        assert!(matches!(
            protected_open_error(rustix::io::Errno::INVAL),
            JournalError::UnsupportedProtectedOpen
        ));
        assert!(matches!(
            protected_open_error(rustix::io::Errno::NOENT),
            JournalError::Io(_)
        ));
    }

    #[test]
    fn protected_files_are_private_locked_and_compact_fd_relatively() {
        let directory = TestDirectory::new("protected-compact");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        assert_eq!(
            fs::metadata(directory.0.join("protected.journal"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(directory.0.join("protected.journal.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(matches!(
            protected_open(&directory.0),
            Err(JournalError::AlreadyLocked)
        ));
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"key".to_vec(),
                    b"value".to_vec(),
                )],
            ))
            .unwrap();

        let moved = directory.0.with_extension("retained");
        fs::rename(&directory.0, &moved).unwrap();
        fs::create_dir(&directory.0).unwrap();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        journal.compact().unwrap();
        assert!(moved.join("protected.journal").exists());
        assert!(!directory.0.join("protected.journal").exists());
        drop(journal);
        fs::remove_dir(&directory.0).unwrap();
        fs::rename(&moved, &directory.0).unwrap();
        let (journal, _) = protected_open(&directory.0).unwrap();
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"key"),
            Some(b"value".as_slice())
        );
    }

    #[test]
    fn protected_open_removes_bounded_stale_temp_without_reusing_it() {
        let directory = TestDirectory::new("protected-stale-temp");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let temporary = directory.0.join("protected.journal.compact.tmp");
        fs::write(&temporary, b"partial prior compaction").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        assert!(!temporary.exists());
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"key".to_vec(),
                    b"value".to_vec(),
                )],
            ))
            .unwrap();
        journal.compact().unwrap();
        assert!(!temporary.exists());
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"key"),
            Some(b"value".as_slice())
        );
        drop(journal);

        let victim = directory.0.join("victim");
        fs::write(&victim, b"must remain unchanged").unwrap();
        symlink(&victim, &temporary).unwrap();
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        assert!(!temporary.exists());
        journal.compact().unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"must remain unchanged");
        assert!(!temporary.exists());
    }

    #[test]
    fn protected_exclusive_temp_rejects_regular_and_symlink_collisions() {
        let directory = TestDirectory::new("protected-temp-collisions");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let directory_fd = File::open(&directory.0).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let collision = directory.0.join("collision.tmp");
        fs::write(&collision, b"stale").unwrap();
        fs::set_permissions(&collision, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            open_protected_file(&directory_fd, "collision.tmp", uid, true, true, true).is_err()
        );
        assert_eq!(fs::read(&collision).unwrap(), b"stale");

        fs::remove_file(&collision).unwrap();
        let victim = directory.0.join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, &collision).unwrap();
        assert!(
            open_protected_file(&directory_fd, "collision.tmp", uid, true, true, true).is_err()
        );
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    }

    #[test]
    fn protected_compaction_cleans_bounded_temp_after_failure() {
        let directory = TestDirectory::new("protected-temp-cleanup");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"key".to_vec(),
                    b"value".to_vec(),
                )],
            ))
            .unwrap();
        journal.limits.maximum_journal_bytes = 1;
        assert!(journal.compact().is_err());
        let names: Vec<_> = fs::read_dir(&directory.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| !name.to_string_lossy().contains(".compact."))
        );
    }

    #[test]
    fn protected_reopen_truncates_a_partial_crash_tail() {
        let directory = TestDirectory::new("protected-crash-tail");
        let path = directory.0.join("protected.journal");
        let (journal, _) = protected_open(&directory.0).unwrap();
        drop(journal);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"partial-frame").unwrap();
        file.sync_data().unwrap();
        drop(file);
        let (_, report) = protected_open(&directory.0).unwrap();
        assert_eq!(report.truncated_bytes, 13);
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    fn commit_fixture(path: &Path) -> u64 {
        let (mut journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"sandbox-1".to_vec(),
                    b"running".to_vec(),
                )],
            ))
            .unwrap()
            .durable_bytes
    }

    #[test]
    fn committed_transactions_replay_atomically() {
        let directory = TestDirectory::new("replay");
        let path = directory.journal();
        let length = commit_fixture(&path);

        let (journal, report) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert_eq!(report.committed_transactions, 1);
        assert_eq!(report.committed_records, 1);
        assert_eq!(report.truncated_bytes, 0);
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"sandbox-1"),
            Some(b"running".as_slice())
        );
        assert_eq!(fs::metadata(path).unwrap().len(), length);
    }

    #[test]
    fn partial_final_frame_is_removed_to_last_commit() {
        let directory = TestDirectory::new("partial");
        let path = directory.journal();
        let committed_length = commit_fixture(&path);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0xa5; HEADER_BYTES / 2]).unwrap();
        file.sync_data().unwrap();
        drop(file);

        let (_, report) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert_eq!(report.truncated_bytes, (HEADER_BYTES / 2) as u64);
        assert_eq!(fs::metadata(path).unwrap().len(), committed_length);
    }

    #[test]
    fn complete_corrupt_frame_fails_closed() {
        let directory = TestDirectory::new("checksum");
        let path = directory.journal();
        commit_fixture(&path);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(HEADER_BYTES as u64)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_data().unwrap();
        drop(file);

        assert!(matches!(
            Journal::open(path, JournalLimits::default()),
            Err(JournalError::ChecksumMismatch(_))
        ));
    }

    #[test]
    fn exact_idempotency_replay_and_conflict_survive_reopen() {
        let directory = TestDirectory::new("idempotency");
        let path = directory.journal();
        let key = IdempotencyKey::new(b"request-42".to_vec()).unwrap();
        let operation = OperationId::from_bytes([0x44; 16]);
        let digest = [0x11; 32];
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::idempotency(&key, digest, operation)],
            ))
            .unwrap();
        drop(journal);

        let (journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        assert_eq!(
            journal.check_idempotency(&key, digest),
            IdempotencyOutcome::Replay(operation)
        );
        assert_eq!(
            journal.check_idempotency(&key, [0x22; 32]),
            IdempotencyOutcome::Conflict
        );
    }

    #[test]
    fn compaction_preserves_only_materialized_values_and_indexes() {
        let directory = TestDirectory::new("compact");
        let path = directory.journal();
        let key = IdempotencyKey::new(b"request".to_vec()).unwrap();
        let operation = OperationId::from_bytes([0x33; 16]);
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        b"resource".to_vec(),
                        b"old".to_vec(),
                    ),
                    JournalRecord::idempotency(&key, [0x55; 32], operation),
                ],
            ))
            .unwrap();
        journal
            .commit(&transaction(
                2,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"resource".to_vec(),
                    b"new".to_vec(),
                )],
            ))
            .unwrap();
        journal.compact().unwrap();
        drop(journal);

        let (journal, report) = Journal::open(path, JournalLimits::default()).unwrap();
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"resource"),
            Some(b"new".as_slice())
        );
        assert_eq!(
            journal.check_idempotency(&key, [0x55; 32]),
            IdempotencyOutcome::Replay(operation)
        );
        assert_eq!(report.committed_records, 2);
    }

    #[test]
    fn a_second_owner_is_rejected() {
        let directory = TestDirectory::new("lock");
        let path = directory.journal();
        let (_journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert!(matches!(
            Journal::open(path, JournalLimits::default()),
            Err(JournalError::AlreadyLocked)
        ));
    }

    #[test]
    fn transaction_duplicate_keys_are_rejected_before_append() {
        let directory = TestDirectory::new("duplicate");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let record = JournalRecord::put(
            RecordNamespace::Operation,
            b"operation".to_vec(),
            b"accepted".to_vec(),
        );
        let error = journal
            .commit(&transaction(1, vec![record.clone(), record]))
            .unwrap_err();
        assert!(matches!(error, JournalError::DuplicateRecordKey));
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn valid_uncommitted_tail_is_removed_and_sequence_is_reused() {
        let directory = TestDirectory::new("uncommitted");
        let path = directory.journal();
        let committed_length = commit_fixture(&path);
        let trailing = transaction(
            2,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"not-committed".to_vec(),
                b"invisible".to_vec(),
            )],
        );
        let frames = encode_transaction(&trailing, 4).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&frames[0]).unwrap();
        file.write_all(&frames[1]).unwrap();
        file.sync_data().unwrap();
        drop(file);

        let (mut journal, report) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert!(report.truncated_bytes > 0);
        assert_eq!(fs::metadata(&path).unwrap().len(), committed_length);
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"not-committed"),
            None
        );
        let result = journal.commit(&trailing).unwrap();
        assert_eq!(result.commit_sequence, 6);
    }

    #[test]
    fn duplicate_transaction_identity_is_rejected() {
        let directory = TestDirectory::new("duplicate-transaction");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let first = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                b"one".to_vec(),
                b"accepted".to_vec(),
            )],
        );
        journal.commit(&first).unwrap();
        let duplicate = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                b"two".to_vec(),
                b"accepted".to_vec(),
            )],
        );
        assert!(matches!(
            journal.commit(&duplicate),
            Err(JournalError::DuplicateTransaction)
        ));
    }

    #[test]
    fn idempotency_decisions_cannot_be_rebound() {
        let directory = TestDirectory::new("idempotency-rebind");
        let path = directory.journal();
        let key = IdempotencyKey::new(b"request".to_vec()).unwrap();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::idempotency(
                    &key,
                    [0x11; 32],
                    OperationId::from_bytes([0x22; 16]),
                )],
            ))
            .unwrap();
        let rebind = transaction(
            2,
            vec![JournalRecord::idempotency(
                &key,
                [0x33; 32],
                OperationId::from_bytes([0x44; 16]),
            )],
        );
        assert!(matches!(
            journal.commit(&rebind),
            Err(JournalError::IdempotencyConflict)
        ));
    }

    #[test]
    fn append_failure_poisons_handle_until_reopen() {
        let directory = TestDirectory::new("poison");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal.ensure_healthy().unwrap();
        journal.file = OpenOptions::new().read(true).open(&path).unwrap();
        let entry = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"resource".to_vec(),
                b"desired".to_vec(),
            )],
        );
        assert!(matches!(journal.commit(&entry), Err(JournalError::Io(_))));
        assert!(matches!(
            journal.ensure_healthy(),
            Err(JournalError::Poisoned)
        ));
        assert!(matches!(
            journal.commit(&entry),
            Err(JournalError::Poisoned)
        ));
    }

    #[test]
    fn publisher_registry_rejects_unprotected_or_poisoned_journal() {
        use crate::publisher_authority::{PublisherAuthorityLimits, PublisherCapabilityRegistry};
        use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};

        let directory = TestDirectory::new("publisher-poison");
        let (mut unprotected, _) =
            Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        assert!(matches!(
            unprotected.ensure_protected_authority(),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(
            PublisherPolicyStore::load(&mut unprotected, PublisherPolicyLimits::default()).is_err()
        );
        assert!(
            PublisherCapabilityRegistry::load(
                &mut unprotected,
                PublisherAuthorityLimits::default(),
            )
            .is_err()
        );

        let (mut journal, _) = protected_open(&directory.0).unwrap();
        assert!(
            PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default(),)
                .is_ok()
        );
        journal.file = OpenOptions::new()
            .read(true)
            .open(directory.0.join("protected.journal"))
            .unwrap();
        let entry = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"resource".to_vec(),
                b"desired".to_vec(),
            )],
        );
        assert!(matches!(journal.commit(&entry), Err(JournalError::Io(_))));
        assert!(matches!(
            journal.ensure_protected_authority(),
            Err(JournalError::Poisoned)
        ));
        assert!(
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).is_err()
        );
        assert!(
            PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default(),)
                .is_err()
        );

        drop(journal);
        let (mut reopened, _) = protected_open(&directory.0).unwrap();
        assert!(
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).is_ok()
        );
        assert!(
            PublisherCapabilityRegistry::load(&mut reopened, PublisherAuthorityLimits::default(),)
                .is_ok()
        );
    }

    #[cfg(all(target_os = "linux", feature = "kernel-tests"))]
    #[test]
    fn poisoned_journal_blocks_holder_join_despite_cached_live_state() {
        use crate::publisher_authority::PublisherCapabilityRegistry;
        use crate::publisher_control::tests::join::{join_fixture, join_now, send_holder};
        use crate::publisher_control::{PublisherControlError, PublisherJoinError};
        use crate::publisher_ingress::PublisherIngressStore;

        let mut fixture = join_fixture();
        let capability = fixture.request.capability();
        let instance = fixture.registered.registration.fields().instance;
        {
            let capabilities = PublisherCapabilityRegistry::load(
                &mut fixture.registered.local.journal,
                fixture.join_policy.authority_limits,
            )
            .unwrap();
            assert_eq!(
                capabilities.resolve_current(capability).unwrap().id(),
                capability
            );
        }
        {
            let ingress = PublisherIngressStore::load(
                &mut fixture.registered.local.journal,
                fixture.join_policy.control.ingress_limits,
            )
            .unwrap();
            let pending = ingress
                .challenge(instance, fixture.request.challenge())
                .unwrap()
                .unwrap();
            assert_eq!(&pending.fields().request, &fixture.request);
        }
        let authority_before: Vec<_> = fixture
            .registered
            .local
            .journal
            .records(RecordNamespace::PublisherAuthority)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        let ingress_before: Vec<_> = fixture
            .registered
            .local
            .journal
            .records(RecordNamespace::PublisherIngress)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        send_holder(&mut fixture.holder, &fixture.request);

        // An append/sync error is always durability-ambiguous to the service.
        // Keep the materialized capability and challenge maps in memory while
        // forcing the protected handle into its permanently poisoned state.
        fixture.registered.local.journal.file = OpenOptions::new()
            .read(true)
            .open(
                fixture
                    .registered
                    .local
                    .directory
                    .path()
                    .join("issuance.journal"),
            )
            .unwrap();
        let failed = transaction(
            0xee,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"holder-join-poison".to_vec(),
                b"must-not-authorize".to_vec(),
            )],
        );
        assert!(matches!(
            fixture.registered.local.journal.commit(&failed),
            Err(JournalError::Io(_))
        ));
        assert!(matches!(
            fixture
                .registered
                .local
                .journal
                .ensure_protected_authority(),
            Err(JournalError::Poisoned)
        ));

        assert!(matches!(
            join_now(&mut fixture),
            Err(PublisherJoinError::Control(PublisherControlError::Journal(
                JournalError::Poisoned
            )))
        ));
        assert_eq!(
            fixture.holders.capability_id(fixture.holder_id).unwrap(),
            capability,
            "the poisoned precheck must not consume and reinterpret the queued holder record"
        );
        let authority_after: Vec<_> = fixture
            .registered
            .local
            .journal
            .records(RecordNamespace::PublisherAuthority)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        let ingress_after: Vec<_> = fixture
            .registered
            .local
            .journal
            .records(RecordNamespace::PublisherIngress)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(authority_after, authority_before);
        assert_eq!(ingress_after, ingress_before);
    }

    #[cfg(all(target_os = "linux", feature = "kernel-tests"))]
    #[test]
    fn failed_local_issuance_commit_never_activates_a_session() {
        use crate::local_provisioning::LocalProvisioningError;
        use crate::local_provisioning::tests::{
            anchor, fixture, open_journal, provision_samples, sample, sessions,
        };
        use crate::publisher_authority::{
            PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
        };

        let mut fixture = fixture(true, true);
        let mut sessions = sessions();
        assert_eq!(
            fixture
                .journal
                .records(RecordNamespace::PublisherAuthority)
                .count(),
            0,
        );
        // Preserve the healthy protected journal and policy state while making
        // the first issuance append fail before any bytes can be written.
        fixture.journal.file = OpenOptions::new()
            .read(true)
            .open(fixture.directory.path().join("issuance.journal"))
            .unwrap();
        assert!(matches!(
            provision_samples(&mut fixture, &mut sessions, vec![Ok(sample(150, 1000))]),
            Err(LocalProvisioningError::Authority(
                PublisherAuthorityError::Journal(JournalError::Io(_))
            ))
        ));
        assert!(matches!(
            fixture.journal.ensure_healthy(),
            Err(JournalError::Poisoned)
        ));
        assert!(matches!(
            PublisherCapabilityRegistry::load(
                &mut fixture.journal,
                PublisherAuthorityLimits::default(),
            ),
            Err(PublisherAuthorityError::Journal(JournalError::Poisoned)),
        ));
        // Capacity is exactly one. A new preparation can succeed only if the
        // failed operation neither activated a session nor retained its slot.
        let pending = sessions.prepare(fixture.scope, anchor()).unwrap();
        drop(pending);

        let directory = fixture.directory.path().to_path_buf();
        drop(fixture.journal);
        let reopened = open_journal(&directory);
        assert_eq!(
            reopened
                .records(RecordNamespace::PublisherAuthority)
                .count(),
            0
        );
        // Replay, not the poisoned in-memory view, establishes that this
        // injected pre-write failure committed neither capability nor audit.
        reopened.ensure_protected_authority().unwrap();
    }

    #[cfg(all(target_os = "linux", feature = "kernel-tests"))]
    #[test]
    fn failed_publisher_registration_commit_retires_execution_pin() {
        use crate::local_provisioning::tests::{anchor, fixture, open_journal, sample};
        use crate::publisher_control::{PublisherControlError, PublisherControlPolicy};
        use crate::publisher_ingress::{PublisherIngressError, PublisherIngressLimits};
        use crate::publisher_sessions::{
            PublisherSessionError, PublisherSessionLimits, PublisherSessionRegistry,
            PublisherSessionScope,
        };
        use aos_sandbox_linux::seqpacket::RecordSubjectListener;
        use rustix::net::{
            AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
        };

        let mut fixture = fixture(true, true);
        let socket_directory = tempfile::tempdir().unwrap();
        let path = socket_directory.path().join("publisher.sock");
        let mut listener = RecordSubjectListener::bind(&path, 2).unwrap();
        let sender = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        connect(&sender, &SocketAddrUnix::new(&path).unwrap()).unwrap();
        let scope = PublisherSessionScope {
            principal: fixture.scope.holder,
            node: aos_sandbox_core::NodeId::from_bytes([0x73; 16]),
            project: fixture.scope.project,
            cache_resource: fixture.scope.cache_resource,
        };
        let config = PublisherControlPolicy {
            clock_provenance: fixture.config.clock_provenance,
            maximum_challenge_seconds: 60,
            policy_limits: fixture.config.policy_limits,
            ingress_limits: PublisherIngressLimits::default(),
        };
        let mut sessions = PublisherSessionRegistry::new(PublisherSessionLimits {
            maximum_sessions: 1,
        })
        .unwrap();
        // Keep protected policy real, but fail the append before any write.
        // The caller cannot assume that every possible I/O failure is pre-write.
        fixture.journal.file = OpenOptions::new()
            .read(true)
            .open(fixture.directory.path().join("issuance.journal"))
            .unwrap();
        assert!(matches!(
            crate::publisher_control::register(
                &mut fixture.journal,
                &mut sessions,
                &mut listener,
                scope,
                anchor(),
                config,
                &mut || Ok(sample(150, 1000)),
            ),
            Err(PublisherControlError::Ingress(
                PublisherIngressError::Journal(JournalError::Io(_))
            ))
        ));
        assert!(matches!(
            fixture.journal.ensure_healthy(),
            Err(JournalError::Poisoned)
        ));
        // No instance greeting escaped, but the exact process pin still reserves
        // this service: an ambiguous commit cannot make it available for reuse.
        assert!(matches!(
            sessions.prepare(&mut listener, scope, anchor()),
            Err(PublisherSessionError::ServiceReserved)
        ));

        let directory = fixture.directory.path().to_path_buf();
        drop(fixture.journal);
        let reopened = open_journal(&directory);
        assert_eq!(
            reopened.records(RecordNamespace::PublisherIngress).count(),
            0
        );
        reopened.ensure_protected_authority().unwrap();
    }

    #[test]
    fn failed_capability_revocation_denies_reads_until_protected_replay() {
        use crate::publisher_authority::{
            PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
        };

        let directory = TestDirectory::new("publisher-revocation-poison");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let id = aos_sandbox_core::CapabilityId::new();
        let capability = crate::publisher_authority::tests::capability(id, 200);
        PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default())
            .unwrap()
            .install_from_trusted_controller([1; 16], capability.clone())
            .unwrap();

        journal.file = OpenOptions::new()
            .read(true)
            .open(directory.0.join("protected.journal"))
            .unwrap();
        {
            let mut registry = PublisherCapabilityRegistry::load(
                &mut journal,
                PublisherAuthorityLimits::default(),
            )
            .unwrap();
            assert_eq!(registry.resolve_current(id).unwrap(), capability);
            assert!(matches!(
                registry.revoke_from_trusted_controller([2; 16], id),
                Err(PublisherAuthorityError::Journal(JournalError::Io(_))),
            ));
            assert!(matches!(
                registry.resolve_current(id),
                Err(PublisherAuthorityError::Journal(JournalError::Poisoned)),
            ));
        }
        assert!(matches!(
            PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default()),
            Err(PublisherAuthorityError::Journal(JournalError::Poisoned)),
        ));

        drop(journal);
        let (mut reopened, _) = protected_open(&directory.0).unwrap();
        let registry =
            PublisherCapabilityRegistry::load(&mut reopened, PublisherAuthorityLimits::default())
                .unwrap();
        // The injected descriptor rejected the write before any bytes reached
        // disk. Only protected replay, not the stale in-memory snapshot, may
        // therefore restore this still-active record.
        assert_eq!(registry.resolve_current(id).unwrap(), capability);
    }

    #[test]
    fn failed_controller_generation_update_denies_policy_reads_until_replay() {
        use crate::publisher_policy::{
            PublisherControllerHeadV1, PublisherPolicyError, PublisherPolicyLimits,
            PublisherPolicyStore,
        };

        let directory = TestDirectory::new("publisher-policy-poison");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let first = PublisherControllerHeadV1 {
            principal: aos_sandbox_core::PrincipalId::new(),
            generation: 1,
        };
        PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default())
            .unwrap()
            .advance_controller_from_trusted_controller([1; 16], None, first)
            .unwrap();

        journal.file = OpenOptions::new()
            .read(true)
            .open(directory.0.join("protected.journal"))
            .unwrap();
        {
            let mut policies =
                PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
            assert_eq!(policies.controller_head().unwrap(), Some(first));
            assert!(matches!(
                policies.advance_controller_from_trusted_controller(
                    [2; 16],
                    Some(1),
                    PublisherControllerHeadV1 {
                        generation: 2,
                        ..first
                    },
                ),
                Err(PublisherPolicyError::Journal(JournalError::Io(_))),
            ));
            assert!(matches!(
                policies.controller_head(),
                Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
            ));
            assert!(matches!(
                policies.current_policy(aos_sandbox_core::ProjectId::new()),
                Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
            ));
            assert!(matches!(
                policies.revocation_head(aos_sandbox_core::RevocationScopeId::new()),
                Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
            ));
            assert!(matches!(
                policies.resource_binding(aos_sandbox_core::ResourceId::new()),
                Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
            ));
        }
        assert!(matches!(
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()),
            Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
        ));

        drop(journal);
        let (mut reopened, _) = protected_open(&directory.0).unwrap();
        let policies =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        assert_eq!(policies.controller_head().unwrap(), Some(first));
    }

    #[test]
    fn materialized_limit_rejects_before_writing() {
        let directory = TestDirectory::new("materialized-limit");
        let path = directory.journal();
        let limits = JournalLimits {
            maximum_materialized_bytes: 4,
            ..JournalLimits::default()
        };
        let (mut journal, _) = Journal::open(&path, limits).unwrap();
        let entry = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"key".to_vec(),
                b"value".to_vec(),
            )],
        );
        assert!(matches!(
            journal.commit(&entry),
            Err(JournalError::LimitExceeded("materialized state bytes"))
        ));
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn every_transaction_frame_boundary_recovers_atomically() {
        let records = vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                b"sandbox".to_vec(),
                b"running".to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::Operation,
                b"operation".to_vec(),
                b"applying".to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::Effect,
                b"effect".to_vec(),
                b"planned".to_vec(),
            ),
        ];
        let transaction = transaction(1, records);
        let frames = encode_transaction(&transaction, 1).unwrap();

        for persisted_frames in 0..=frames.len() {
            let directory = TestDirectory::new(&format!("frame-boundary-{persisted_frames}"));
            let path = directory.journal();
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            drop(journal);

            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            for frame in frames.iter().take(persisted_frames) {
                file.write_all(frame).unwrap();
            }
            file.sync_data().unwrap();
            drop(file);

            let (journal, report) = Journal::open(&path, JournalLimits::default()).unwrap();
            if persisted_frames == frames.len() {
                assert_eq!(report.committed_transactions, 1);
                assert_eq!(
                    journal.get(RecordNamespace::DesiredState, b"sandbox"),
                    Some(b"running".as_slice())
                );
                assert_eq!(
                    journal.get(RecordNamespace::Operation, b"operation"),
                    Some(b"applying".as_slice())
                );
                assert_eq!(
                    journal.get(RecordNamespace::Effect, b"effect"),
                    Some(b"planned".as_slice())
                );
            } else {
                assert_eq!(report.committed_transactions, 0);
                assert!(report.truncated_bytes > 0 || persisted_frames == 0);
                assert_eq!(journal.get(RecordNamespace::DesiredState, b"sandbox"), None);
                assert_eq!(fs::metadata(path).unwrap().len(), 0);
            }
        }
    }
}
