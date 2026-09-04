//! Durable, authenticated storage transaction state machine.
//!
//! One exclusively locked [`aos_sandbox::Journal`] remains owned for the
//! lifetime of [`StorageTransactionStore`]. Each state transition is an atomic,
//! checksummed journal transaction whose value is independently HMAC-authenticated.
//! A mutation must be marked [`DurableStoragePhase::Ambiguous`] before a future
//! helper may invoke ZFS. Recovery exposes that phase only for re-observation;
//! this module contains no API that returns or reissues mutation argv.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};

use crate::{CatalogBindingV1, PostconditionPolicyV1, ResolvedCatalogCommitmentV1};

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 8] = b"AOSSTX01";
const VERSION: u16 = 1;
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.storage.state.record.v1\0";
const MUTATION_DOMAIN: &[u8] = b"aos.sandbox.storage.mutation.v1\0";
const POSTCONDITION_DOMAIN: &[u8] = b"aos.sandbox.storage.postcondition.v1\0";
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024;
const FIXED_PREFIX_BYTES: usize = 8 + 2 + 1 + 16 + 32 + 32 + 8 + 32 + 32 + 4;
const RESULT_BYTES: usize = 8 + 32 + 32;
const MAC_BYTES: usize = 32;
const MAXIMUM_OPERATIONS: usize = 1024;

/// Reports durable storage state validation or transition failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageStateError {
    /// The state directory is not a root-owned, non-group/other-writable directory.
    #[error("storage state directory is not protected")]
    UnprotectedDirectory,
    /// The journal failed validation, locking, or durable publication.
    #[error("storage journal failure: {0}")]
    Journal(#[from] aos_sandbox::JournalError),
    /// The authenticated storage record is malformed, corrupt, or from another key.
    #[error("storage transaction record authentication or structure failed")]
    CorruptRecord,
    /// Durable generation is below the external rollback anchor.
    #[error("storage catalog generation rolled back")]
    Rollback,
    /// One operation identity was reused for different semantics.
    #[error("storage operation identity equivocated")]
    Equivocation,
    /// The requested transition is not valid from the durable phase.
    #[error("storage transaction phase transition is invalid")]
    InvalidTransition,
    /// A key, operation identifier, digest, or result uses a reserved zero value.
    #[error("storage transaction contains a reserved value")]
    InvalidValue,
}

/// Holds the node-local secret used to authenticate storage records.
pub struct StorageStateKey {
    key_id: [u8; 16],
    secret: [u8; 32],
}

impl StorageStateKey {
    /// Constructs a nonzero key identity and secret.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::InvalidValue`] for either zero sentinel.
    pub fn new(key_id: [u8; 16], secret: [u8; 32]) -> Result<Self, StorageStateError> {
        if key_id == [0; 16] || secret == [0; 32] {
            Err(StorageStateError::InvalidValue)
        } else {
            Ok(Self { key_id, secret })
        }
    }
}

impl Drop for StorageStateKey {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

/// Identifies the durable crash boundary of one storage mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableStoragePhase {
    /// Intent is durable but no mutation may yet have been attempted.
    Prepared,
    /// The mutation may have happened and must only be re-observed.
    Ambiguous,
    /// The typed postcondition and committed result were durably published.
    Committed,
}

/// Carries an authenticated committed storage result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedStorageResultV1 {
    catalog: CatalogBindingV1,
    result_digest: ObjectDigest,
}

impl CommittedStorageResultV1 {
    /// Returns the resulting catalog generation and digest.
    #[must_use]
    pub const fn catalog(self) -> CatalogBindingV1 {
        self.catalog
    }

    /// Returns the bounded typed observation digest.
    #[must_use]
    pub const fn result_digest(self) -> ObjectDigest {
        self.result_digest
    }
}

/// Carries a mechanically checked, transaction-bound observation assertion.
///
/// This value is not proof that ZFS was inspected. A future privileged helper
/// must construct it from a fresh observation while the catalog lock is held.
/// The type prevents an assertion for one request, catalog, or postcondition
/// from being committed as the result of another transaction.
pub struct VerifiedStorageResultV1 {
    operation_id: [u8; 16],
    request_digest: ObjectDigest,
    mutation_digest: ObjectDigest,
    catalog: CatalogBindingV1,
    postcondition_digest: ObjectDigest,
    result: CommittedStorageResultV1,
}

impl VerifiedStorageResultV1 {
    /// Validates a typed observation assertion from an observation-only helper.
    ///
    /// The future helper supplies the complete typed state it observed. This
    /// constructor mechanically compares it with the postcondition derived
    /// from the exact resolved catalog and binds the assertion to the request
    /// and mutation identity. It does not itself inspect ZFS.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::InvalidValue`] for a zero result digest and
    /// [`StorageStateError::InvalidTransition`] when `observed` differs from
    /// the complete typed postcondition derived from `catalog`.
    pub fn verify_observation(
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        observed: &PostconditionPolicyV1,
        result_catalog: CatalogBindingV1,
        result_digest: ObjectDigest,
    ) -> Result<Self, StorageStateError> {
        if operation_id == [0; 16]
            || request_digest.as_bytes() == &[0; 32]
            || result_digest.as_bytes() == &[0; 32]
        {
            return Err(StorageStateError::InvalidValue);
        }
        if &catalog.plan().postcondition() != observed {
            return Err(StorageStateError::InvalidTransition);
        }
        Ok(Self {
            operation_id,
            request_digest,
            mutation_digest: mutation_digest(operation_id, request_digest, catalog.binding()),
            catalog: catalog.binding(),
            postcondition_digest: postcondition_digest(catalog.canonical_bytes()),
            result: CommittedStorageResultV1 {
                catalog: result_catalog,
                result_digest,
            },
        })
    }
}

/// Reports whether preparation created intent or found durable prior state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginStorageTransaction {
    /// A new prepared intent was synchronously committed.
    Prepared {
        /// Deterministic identity of the pending mutation.
        mutation_digest: ObjectDigest,
    },
    /// The same operation is pending or ambiguous and must not be reapplied.
    ObserveOnly {
        /// Current durable crash phase.
        phase: DurableStoragePhase,
        /// Deterministic mutation identity.
        mutation_digest: ObjectDigest,
    },
    /// The exact request already committed and returns its prior result.
    Replay(CommittedStorageResultV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableRecord {
    phase: DurableStoragePhase,
    operation_id: [u8; 16],
    request_digest: ObjectDigest,
    mutation_digest: ObjectDigest,
    catalog: CatalogBindingV1,
    postcondition_digest: ObjectDigest,
    catalog_bytes: Vec<u8>,
    result: Option<CommittedStorageResultV1>,
}

/// Owns the exclusive catalog transaction lock and authenticated journal state.
pub struct StorageTransactionStore {
    journal: Journal,
    key: StorageStateKey,
    records: BTreeMap<[u8; 16], DurableRecord>,
}

impl StorageTransactionStore {
    /// Opens a root-owned protected directory and exclusively locks its journal.
    ///
    /// `minimum_generation` is an external monotonic rollback anchor. Opening a
    /// valid older record below it fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError`] for directory ownership/mode failure,
    /// lock contention, journal corruption, record authentication failure, or
    /// rollback below `minimum_generation`.
    pub fn open_root_owned(
        directory: &Path,
        key: StorageStateKey,
        minimum_generation: u64,
    ) -> Result<Self, StorageStateError> {
        let metadata = fs::symlink_metadata(directory).map_err(aos_sandbox::JournalError::Io)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(StorageStateError::UnprotectedDirectory);
        }
        validate_existing_state_file(&directory.join("storage-state.journal"))?;
        validate_existing_state_file(&directory.join("storage-state.journal.lock"))?;
        let store = Self::open_checked(directory, key, minimum_generation)?;
        protect_state_file(&directory.join("storage-state.journal"))?;
        protect_state_file(&directory.join("storage-state.journal.lock"))?;
        Ok(store)
    }

    #[cfg(test)]
    fn open_for_test(
        directory: &Path,
        key: StorageStateKey,
        minimum_generation: u64,
    ) -> Result<Self, StorageStateError> {
        Self::open_checked(directory, key, minimum_generation)
    }

    fn open_checked(
        directory: &Path,
        key: StorageStateKey,
        minimum_generation: u64,
    ) -> Result<Self, StorageStateError> {
        let limits = JournalLimits {
            maximum_journal_bytes: 64 * 1024 * 1024,
            maximum_record_bytes: MAXIMUM_RECORD_BYTES,
            maximum_key_bytes: 128,
            maximum_records_per_transaction: 2,
            maximum_transaction_bytes: MAXIMUM_RECORD_BYTES * 2,
            maximum_transactions: 65_536,
            maximum_materialized_bytes: MAXIMUM_RECORD_BYTES * MAXIMUM_OPERATIONS,
            maximum_materialized_records: MAXIMUM_OPERATIONS,
        };
        let (journal, _) = Journal::open(directory.join("storage-state.journal"), limits)?;
        let mut records = BTreeMap::new();
        for (record_key, bytes) in journal.records(RecordNamespace::Effect) {
            let record = decode_record(bytes, &key)?;
            if record_key != record.operation_id {
                return Err(StorageStateError::CorruptRecord);
            }
            records.insert(record.operation_id, record);
        }
        let latest_generation = latest_generation(&records);
        if latest_generation < minimum_generation {
            return Err(StorageStateError::Rollback);
        }
        Ok(Self {
            journal,
            key,
            records,
        })
    }

    /// Returns the durable crash phase for `operation_id`.
    #[must_use]
    pub fn phase(&self, operation_id: [u8; 16]) -> Option<DurableStoragePhase> {
        self.records.get(&operation_id).map(|record| record.phase)
    }

    /// Durably prepares one idempotent mutation or resolves its replay state.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::Equivocation`] when `operation_id` is bound
    /// to different request/catalog semantics, or a durability error.
    pub fn begin(
        &mut self,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<BeginStorageTransaction, StorageStateError> {
        if operation_id == [0; 16] || request_digest.as_bytes() == &[0; 32] {
            return Err(StorageStateError::InvalidValue);
        }
        let mutation_digest = mutation_digest(operation_id, request_digest, catalog.binding());
        if let Some(current) = self.records.get(&operation_id) {
            if current.request_digest != request_digest
                || current.catalog != catalog.binding()
                || current.mutation_digest != mutation_digest
            {
                return Err(StorageStateError::Equivocation);
            }
            return Ok(match (current.phase, current.result) {
                (DurableStoragePhase::Committed, Some(result)) => {
                    BeginStorageTransaction::Replay(result)
                }
                (phase, _) => BeginStorageTransaction::ObserveOnly {
                    phase,
                    mutation_digest,
                },
            });
        }
        let latest_generation = latest_generation(&self.records);
        if catalog.generation() < latest_generation {
            return Err(StorageStateError::Rollback);
        }
        if self.records.values().any(|record| {
            catalog_forks(record.catalog, catalog.binding())
                || record
                    .result
                    .is_some_and(|result| catalog_forks(result.catalog, catalog.binding()))
        }) {
            return Err(StorageStateError::Equivocation);
        }
        let record = DurableRecord {
            phase: DurableStoragePhase::Prepared,
            operation_id,
            request_digest,
            mutation_digest,
            catalog: catalog.binding(),
            postcondition_digest: postcondition_digest(catalog.canonical_bytes()),
            catalog_bytes: catalog.canonical_bytes().to_vec(),
            result: None,
        };
        self.publish(record)?;
        Ok(BeginStorageTransaction::Prepared { mutation_digest })
    }

    /// Durably crosses the point after which mutation outcome may be ambiguous.
    ///
    /// A future helper must call this and sync it before invoking ZFS.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::InvalidTransition`] unless the exact
    /// prepared operation and mutation digest are current.
    pub fn mark_mutation_ambiguous(
        &mut self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
    ) -> Result<(), StorageStateError> {
        let mut record = self.exact_current(operation_id, mutation_digest)?.clone();
        if record.phase != DurableStoragePhase::Prepared {
            return Err(StorageStateError::InvalidTransition);
        }
        record.phase = DurableStoragePhase::Ambiguous;
        self.publish(record)
    }

    /// Publishes a committed result after observation verifies the postcondition.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::InvalidTransition`] unless the exact
    /// ambiguous operation is current and the result advances catalog generation.
    pub fn commit_verified(
        &mut self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        verified: VerifiedStorageResultV1,
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        let mut record = self.exact_current(operation_id, mutation_digest)?.clone();
        let latest_generation = latest_generation(&self.records);
        if record.phase != DurableStoragePhase::Ambiguous
            || verified.operation_id != record.operation_id
            || verified.request_digest != record.request_digest
            || verified.mutation_digest != record.mutation_digest
            || verified.catalog != record.catalog
            || verified.postcondition_digest != record.postcondition_digest
            || verified.result.catalog.generation() <= record.catalog.generation()
            || verified.result.catalog.generation() < latest_generation
            || self.records.values().any(|existing| {
                catalog_forks(existing.catalog, verified.result.catalog)
                    || existing.result.is_some_and(|result| {
                        catalog_forks(result.catalog, verified.result.catalog)
                    })
            })
        {
            return Err(StorageStateError::InvalidTransition);
        }
        record.phase = DurableStoragePhase::Committed;
        record.result = Some(verified.result);
        self.publish(record)?;
        Ok(verified.result)
    }

    fn exact_current(
        &self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
    ) -> Result<&DurableRecord, StorageStateError> {
        self.records
            .get(&operation_id)
            .filter(|record| record.mutation_digest == mutation_digest)
            .ok_or(StorageStateError::InvalidTransition)
    }

    fn publish(&mut self, record: DurableRecord) -> Result<(), StorageStateError> {
        let bytes = encode_record(&record, &self.key)?;
        let transaction = JournalTransaction::new(
            transaction_id(record.operation_id, record.phase),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                record.operation_id.to_vec(),
                bytes,
            )],
        )?;
        self.journal.commit(&transaction)?;
        self.records.insert(record.operation_id, record);
        Ok(())
    }
}

fn protect_state_file(path: &Path) -> Result<(), StorageStateError> {
    let metadata = fs::symlink_metadata(path).map_err(aos_sandbox::JournalError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.uid() != 0 {
        return Err(StorageStateError::UnprotectedDirectory);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(aos_sandbox::JournalError::Io)?;
    Ok(())
}

fn validate_existing_state_file(path: &Path) -> Result<(), StorageStateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && metadata.is_file()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(StorageStateError::UnprotectedDirectory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StorageStateError::Journal(aos_sandbox::JournalError::Io(
            error,
        ))),
    }
}

fn latest_generation(records: &BTreeMap<[u8; 16], DurableRecord>) -> u64 {
    records
        .values()
        .flat_map(|record| {
            [
                Some(record.catalog.generation()),
                record.result.map(|result| result.catalog.generation()),
            ]
        })
        .flatten()
        .max()
        .unwrap_or(0)
}

fn catalog_forks(left: CatalogBindingV1, right: CatalogBindingV1) -> bool {
    left.generation() == right.generation() && left.digest() != right.digest()
}

fn mutation_digest(
    operation_id: [u8; 16],
    request_digest: ObjectDigest,
    catalog: CatalogBindingV1,
) -> ObjectDigest {
    let mut hash = Sha256::new();
    hash.update(MUTATION_DOMAIN);
    hash.update(operation_id);
    hash.update(request_digest.as_bytes());
    hash.update(catalog.generation().to_be_bytes());
    hash.update(catalog.digest().as_bytes());
    ObjectDigest::from_bytes(hash.finalize().into())
}

fn postcondition_digest(catalog_bytes: &[u8]) -> ObjectDigest {
    let mut hash = Sha256::new();
    hash.update(POSTCONDITION_DOMAIN);
    hash.update(catalog_bytes);
    ObjectDigest::from_bytes(hash.finalize().into())
}

fn transaction_id(operation_id: [u8; 16], phase: DurableStoragePhase) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(RECORD_DOMAIN);
    hash.update(operation_id);
    hash.update([phase_code(phase)]);
    let digest: [u8; 32] = hash.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] {
        id[15] = 1;
    }
    id
}

fn phase_code(phase: DurableStoragePhase) -> u8 {
    match phase {
        DurableStoragePhase::Prepared => 1,
        DurableStoragePhase::Ambiguous => 2,
        DurableStoragePhase::Committed => 3,
    }
}

fn encode_record(
    record: &DurableRecord,
    key: &StorageStateKey,
) -> Result<Vec<u8>, StorageStateError> {
    let result_len = if record.result.is_some() {
        RESULT_BYTES
    } else {
        0
    };
    let capacity = FIXED_PREFIX_BYTES
        .checked_add(record.catalog_bytes.len())
        .and_then(|value| value.checked_add(result_len + 16 + MAC_BYTES))
        .ok_or(StorageStateError::CorruptRecord)?;
    if capacity > MAXIMUM_RECORD_BYTES {
        return Err(StorageStateError::CorruptRecord);
    }
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(phase_code(record.phase));
    bytes.extend_from_slice(&record.operation_id);
    bytes.extend_from_slice(record.request_digest.as_bytes());
    bytes.extend_from_slice(record.mutation_digest.as_bytes());
    bytes.extend_from_slice(&record.catalog.generation().to_be_bytes());
    bytes.extend_from_slice(record.catalog.digest().as_bytes());
    bytes.extend_from_slice(record.postcondition_digest.as_bytes());
    bytes.extend_from_slice(&(record.catalog_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&record.catalog_bytes);
    bytes.extend_from_slice(&key.key_id);
    if let Some(result) = record.result {
        bytes.extend_from_slice(&result.catalog.generation().to_be_bytes());
        bytes.extend_from_slice(result.catalog.digest().as_bytes());
        bytes.extend_from_slice(result.result_digest.as_bytes());
    }
    let mut mac =
        HmacSha256::new_from_slice(&key.secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(RECORD_DOMAIN);
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    Ok(bytes)
}

fn decode_record(bytes: &[u8], key: &StorageStateKey) -> Result<DurableRecord, StorageStateError> {
    if bytes.len() > MAXIMUM_RECORD_BYTES || bytes.len() < FIXED_PREFIX_BYTES + 16 + MAC_BYTES {
        return Err(StorageStateError::CorruptRecord);
    }
    let (body, tag) = bytes.split_at(bytes.len() - MAC_BYTES);
    let mut mac =
        HmacSha256::new_from_slice(&key.secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(RECORD_DOMAIN);
    mac.update(body);
    mac.verify_slice(tag)
        .map_err(|_| StorageStateError::CorruptRecord)?;
    let mut cursor = Cursor::new(body);
    if cursor.take(8)? != MAGIC || cursor.u16()? != VERSION {
        return Err(StorageStateError::CorruptRecord);
    }
    let phase = match cursor.u8()? {
        1 => DurableStoragePhase::Prepared,
        2 => DurableStoragePhase::Ambiguous,
        3 => DurableStoragePhase::Committed,
        _ => return Err(StorageStateError::CorruptRecord),
    };
    let operation_id = cursor.array()?;
    let request_digest = ObjectDigest::from_bytes(cursor.array()?);
    let stored_mutation_digest = ObjectDigest::from_bytes(cursor.array()?);
    let generation = cursor.u64()?;
    let digest = ObjectDigest::from_bytes(cursor.array()?);
    let catalog = CatalogBindingV1::from_publisher(generation, digest)
        .map_err(|_| StorageStateError::CorruptRecord)?;
    let stored_postcondition_digest = ObjectDigest::from_bytes(cursor.array()?);
    let catalog_len = cursor.u32()? as usize;
    let catalog_bytes = cursor.take(catalog_len)?.to_vec();
    if cursor.take(16)? != key.key_id {
        return Err(StorageStateError::CorruptRecord);
    }
    let result = if phase == DurableStoragePhase::Committed {
        Some(CommittedStorageResultV1 {
            catalog: CatalogBindingV1::from_publisher(
                cursor.u64()?,
                ObjectDigest::from_bytes(cursor.array()?),
            )
            .map_err(|_| StorageStateError::CorruptRecord)?,
            result_digest: ObjectDigest::from_bytes(cursor.array()?),
        })
    } else {
        None
    };
    if cursor.remaining() != 0
        || operation_id == [0; 16]
        || request_digest.as_bytes() == &[0; 32]
        || stored_mutation_digest.as_bytes() == &[0; 32]
        || stored_postcondition_digest.as_bytes() == &[0; 32]
        || result.is_some_and(|value| value.result_digest.as_bytes() == &[0; 32])
        || !ResolvedCatalogCommitmentV1::authenticates_persisted_bytes(catalog, &catalog_bytes)
        || postcondition_digest(&catalog_bytes) != stored_postcondition_digest
        || mutation_digest(operation_id, request_digest, catalog) != stored_mutation_digest
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(DurableRecord {
        phase,
        operation_id,
        request_digest,
        mutation_digest: stored_mutation_digest,
        catalog,
        postcondition_digest: stored_postcondition_digest,
        catalog_bytes,
        result,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], StorageStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StorageStateError::CorruptRecord)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StorageStateError::CorruptRecord)?;
        self.offset = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], StorageStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)
    }
    fn u8(&mut self) -> Result<u8, StorageStateError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, StorageStateError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, StorageStateError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, StorageStateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::OpenOptions;
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

    use aos_sandbox::JournalError;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedDataset, StorageDomainsV1, StorageOperation,
        WorkspaceSpacePolicyV1, ZfsTransaction,
    };

    fn key(byte: u8) -> StorageStateKey {
        StorageStateKey::new([byte; 16], [byte.wrapping_add(1); 32]).unwrap()
    }

    fn domains() -> StorageDomainsV1 {
        StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap()
    }

    fn catalog(generation: u64, destination_name: &str) -> ResolvedCatalogCommitmentV1 {
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [1; 32], domains())
                .unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap();
        let destination = PlannedDataset::from_catalog(root, destination_name, domains()).unwrap();
        let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap();
        ResolvedCatalogCommitmentV1::new(
            generation,
            domains(),
            CatalogPlanV1::CreateWorkspace {
                destination,
                space,
                ancestor,
            },
        )
        .unwrap()
    }

    fn program(catalog: &ResolvedCatalogCommitmentV1) -> ZfsTransaction {
        ZfsTransaction::from_catalog(
            StorageOperation::CreateWorkspace { quota_bytes: 4096 },
            catalog,
        )
        .unwrap()
    }

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    #[test]
    fn lock_excludes_a_second_store() {
        let directory = TempDir::new().unwrap();
        let _first = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert!(matches!(
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0),
            Err(StorageStateError::Journal(JournalError::AlreadyLocked))
        ));
    }

    #[test]
    fn prepared_and_ambiguous_recovery_are_observation_only() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let operation_id = [31; 16];
        let request_digest = digest(32);
        let mutation_digest = {
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            match store.begin(operation_id, request_digest, &catalog).unwrap() {
                BeginStorageTransaction::Prepared { mutation_digest } => mutation_digest,
                other => panic!("unexpected preparation: {other:?}"),
            }
        };

        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(
            store.begin(operation_id, request_digest, &catalog).unwrap(),
            BeginStorageTransaction::ObserveOnly {
                phase: DurableStoragePhase::Prepared,
                mutation_digest,
            }
        );
        store
            .mark_mutation_ambiguous(operation_id, mutation_digest)
            .unwrap();
        drop(store);

        let mut recovered =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(
            recovered
                .begin(operation_id, request_digest, &catalog)
                .unwrap(),
            BeginStorageTransaction::ObserveOnly {
                phase: DurableStoragePhase::Ambiguous,
                mutation_digest,
            }
        );
    }

    #[test]
    fn exact_committed_result_replays_after_reopen() {
        let directory = TempDir::new().unwrap();
        let initial_catalog = catalog(7, "tank/aos/project/work");
        let next_catalog = catalog(8, "tank/aos/project/next");
        let program = program(&initial_catalog);
        let operation_id = [41; 16];
        let request_digest = digest(42);
        let expected = {
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            let BeginStorageTransaction::Prepared { mutation_digest } = store
                .begin(operation_id, request_digest, &initial_catalog)
                .unwrap()
            else {
                panic!("new operation was not prepared")
            };
            store
                .mark_mutation_ambiguous(operation_id, mutation_digest)
                .unwrap();
            let verified = VerifiedStorageResultV1::verify_observation(
                operation_id,
                request_digest,
                &initial_catalog,
                program.postcondition(),
                next_catalog.binding(),
                digest(44),
            )
            .unwrap();
            store
                .commit_verified(operation_id, mutation_digest, verified)
                .unwrap()
        };
        let mut recovered =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 7).unwrap();
        assert!(matches!(
            recovered
                .begin([45; 16], digest(46), &next_catalog)
                .unwrap(),
            BeginStorageTransaction::Prepared { .. }
        ));
        assert_eq!(
            recovered
                .begin(operation_id, request_digest, &initial_catalog)
                .unwrap(),
            BeginStorageTransaction::Replay(expected)
        );
    }

    #[test]
    fn request_handle_guid_and_generation_substitution_fail_closed() {
        let directory = TempDir::new().unwrap();
        let original = catalog(7, "tank/aos/project/work");
        let substituted = catalog(8, "tank/aos/project/other");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        store.begin([51; 16], digest(52), &original).unwrap();
        assert!(matches!(
            store.begin([51; 16], digest(53), &original),
            Err(StorageStateError::Equivocation)
        ));
        assert!(matches!(
            store.begin([51; 16], digest(52), &substituted),
            Err(StorageStateError::Equivocation)
        ));
        assert!(matches!(
            store.begin([54; 16], digest(55), &catalog(6, "tank/aos/project/old")),
            Err(StorageStateError::Rollback)
        ));
    }

    #[test]
    fn catalog_generation_forks_and_wrong_postconditions_are_rejected() {
        let directory = TempDir::new().unwrap();
        let original = catalog(7, "tank/aos/project/work");
        let fork = catalog(7, "tank/aos/project/other");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        store.begin([61; 16], digest(62), &original).unwrap();
        assert!(matches!(
            store.begin([63; 16], digest(64), &fork),
            Err(StorageStateError::Equivocation)
        ));
        assert!(matches!(
            VerifiedStorageResultV1::verify_observation(
                [61; 16],
                digest(62),
                &original,
                &fork.plan().postcondition(),
                CatalogBindingV1::from_publisher(8, digest(65)).unwrap(),
                digest(66),
            ),
            Err(StorageStateError::InvalidTransition)
        ));

        let BeginStorageTransaction::ObserveOnly {
            mutation_digest: first_mutation,
            ..
        } = store.begin([61; 16], digest(62), &original).unwrap()
        else {
            panic!("first operation lost its durable intent")
        };
        store
            .mark_mutation_ambiguous([61; 16], first_mutation)
            .unwrap();
        let verified_for_first = VerifiedStorageResultV1::verify_observation(
            [61; 16],
            digest(62),
            &original,
            &original.plan().postcondition(),
            catalog(8, "tank/aos/project/next").binding(),
            digest(67),
        )
        .unwrap();
        let BeginStorageTransaction::Prepared {
            mutation_digest: second_mutation,
        } = store.begin([63; 16], digest(64), &original).unwrap()
        else {
            panic!("second operation was not prepared")
        };
        store
            .mark_mutation_ambiguous([63; 16], second_mutation)
            .unwrap();
        assert!(matches!(
            store.commit_verified([63; 16], second_mutation, verified_for_first),
            Err(StorageStateError::InvalidTransition)
        ));
    }

    #[test]
    fn corruption_wrong_authentication_key_and_rollback_anchor_fail_closed() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        {
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            store.begin([71; 16], digest(72), &catalog).unwrap();
        }
        assert!(matches!(
            StorageTransactionStore::open_for_test(directory.path(), key(2), 0),
            Err(StorageStateError::CorruptRecord)
        ));
        assert!(matches!(
            StorageTransactionStore::open_for_test(directory.path(), key(1), 8),
            Err(StorageStateError::Rollback)
        ));

        let path = directory.path().join("storage-state.journal");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let length = file.seek(SeekFrom::End(0)).unwrap();
        file.seek(SeekFrom::Start(length - 1)).unwrap();
        let mut byte = [0];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xff;
        file.seek(SeekFrom::Start(length - 1)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0),
            Err(StorageStateError::Journal(JournalError::ChecksumMismatch(
                _
            )))
        ));
    }

    #[test]
    fn protected_open_rejects_writable_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            StorageTransactionStore::open_root_owned(directory.path(), key(1), 0),
            Err(StorageStateError::UnprotectedDirectory)
        ));
    }
}
