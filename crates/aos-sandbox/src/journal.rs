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
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aos_sandbox_core::OperationId;
use rustix::fs::{FlockOperation, flock};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"AOSJRN01";
const FORMAT_VERSION: u16 = 1;
const HEADER_BYTES: usize = 72;
const CHECKSUM_OFFSET: usize = 40;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.journal.transaction.v1\0";
const FRAME_DOMAIN: &[u8] = b"aos.sandbox.journal.frame.v1\0";
const IDEMPOTENCY_VALUE_BYTES: usize = 48;

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
}

impl RecordNamespace {
    fn from_byte(value: u8) -> Result<Self, JournalError> {
        match value {
            1 => Ok(Self::DesiredState),
            2 => Ok(Self::Operation),
            3 => Ok(Self::Effect),
            4 => Ok(Self::Idempotency),
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
            },
            report,
        ))
    }

    /// Returns the currently materialized value for a logical key.
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
    pub fn records(&self, namespace: RecordNamespace) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.state
            .iter()
            .filter_map(move |((record_namespace, key), value)| {
                (*record_namespace == namespace).then_some((key.as_slice(), value.as_slice()))
            })
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
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
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
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        if let Err(error) = self.compact_inner() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn compact_inner(&mut self) -> Result<(), JournalError> {
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

    use std::fs::{self, OpenOptions};
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::path::{Path, PathBuf};

    use aos_sandbox_core::OperationId;

    use super::{
        HEADER_BYTES, IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalLimits,
        JournalRecord, JournalTransaction, RecordNamespace, encode_transaction,
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
            journal.commit(&entry),
            Err(JournalError::Poisoned)
        ));
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
