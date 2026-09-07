//! Durable, authenticated storage transaction state machine.
//!
//! One exclusively locked [`aos_sandbox::Journal`] remains owned for the
//! lifetime of [`StorageTransactionStore`]. Each state transition is an atomic,
//! checksummed journal transaction whose value is independently HMAC-authenticated.
//! A mutation must be marked [`DurableStoragePhase::Ambiguous`] before a future
//! helper may invoke ZFS. Recovery exposes that phase only for re-observation;
//! this module contains no API that returns or reissues mutation argv.

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};

use crate::{CatalogBindingV1, CatalogPlanV1, PostconditionPolicyV1, ResolvedCatalogCommitmentV1};

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 8] = b"AOSSTX01";
const VERSION: u16 = 3;
const LEGACY_VERSION: u16 = 2;
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.storage.state.record.v1\0";
const MUTATION_DOMAIN: &[u8] = b"aos.sandbox.storage.mutation.v1\0";
const POSTCONDITION_DOMAIN: &[u8] = b"aos.sandbox.storage.postcondition.v1\0";
const RESOURCE_HANDLE_DOMAIN: &[u8] = b"aos.sandbox.storage.resource-handle.v1\0";
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024;
const FIXED_PREFIX_BYTES: usize = 8 + 2 + 1 + 16 + 16 + 16 + 32 + 32 + 8 + 32 + 32 + 4;
const LEGACY_RESULT_BYTES: usize = 8 + 32 + 32;
const RESULT_BYTES: usize = LEGACY_RESULT_BYTES + 1 + 32 + 32 + 8;
const MAC_BYTES: usize = 32;
const RESULT_HAS_STORAGE_HANDLE: u8 = 1;
const RESULT_HAS_VERSION_HANDLE: u8 = 1 << 1;
const RESULT_HAS_OBJECT_GUID: u8 = 1 << 2;
const MAXIMUM_OPERATIONS: usize = 256;

/// Reports durable storage state validation or transition failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageStateError {
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
    /// A durable operation is missing its atomically committed authority link.
    #[error("storage transaction authority cross-link is missing")]
    MissingAuthorityLink,
    /// Authenticated authority state names different durable semantics.
    #[error("storage transaction authority cross-link does not match")]
    AuthorityLinkMismatch,
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
    storage_handle: Option<[u8; 32]>,
    immutable_version_handle: Option<[u8; 32]>,
    object_guid: Option<u64>,
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

    /// Returns the broker-minted workspace handle addressed by the result.
    #[must_use]
    pub const fn storage_handle(self) -> Option<[u8; 32]> {
        self.storage_handle
    }

    /// Returns the broker-minted immutable-version handle, when applicable.
    #[must_use]
    pub const fn immutable_version_handle(self) -> Option<[u8; 32]> {
        self.immutable_version_handle
    }

    /// Returns the freshly observed exact ZFS object GUID, when one must exist.
    #[must_use]
    pub const fn object_guid(self) -> Option<u64> {
        self.object_guid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifiedResourceIdentity {
    MintWorkspace {
        object_guid: u64,
    },
    MintVersion {
        storage_handle: [u8; 32],
        object_guid: u64,
    },
    Existing {
        storage_handle: [u8; 32],
        immutable_version_handle: Option<[u8; 32]>,
        object_guid: Option<u64>,
    },
}

struct DecodedResultIdentity {
    storage_handle: Option<[u8; 32]>,
    immutable_version_handle: Option<[u8; 32]>,
    object_guid: Option<u64>,
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
    result_catalog: CatalogBindingV1,
    result_digest: ObjectDigest,
    resource_identity: VerifiedResourceIdentity,
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
    /// the complete typed postcondition derived from `catalog`, or when the
    /// observed object GUID is absent, unexpected, or differs from the exact
    /// pre-existing object selected by that postcondition.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_observation(
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        observed: &PostconditionPolicyV1,
        observed_object_guid: Option<u64>,
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
        let resource_identity = verified_resource_identity(catalog.plan(), observed_object_guid)?;
        Ok(Self {
            operation_id,
            request_digest,
            mutation_digest: mutation_digest(operation_id, request_digest, catalog.binding()),
            catalog: catalog.binding(),
            postcondition_digest: postcondition_digest(catalog.canonical_bytes()),
            result_catalog,
            result_digest,
            resource_identity,
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

/// Summarizes one bounded durable operation for startup reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageRecoveryEntry {
    operation_id: [u8; 16],
    sandbox_id: [u8; 16],
    request_id: [u8; 16],
    phase: DurableStoragePhase,
    mutation_digest: ObjectDigest,
    catalog: CatalogBindingV1,
}

impl StorageRecoveryEntry {
    /// Returns the durable client operation identity.
    #[must_use]
    pub const fn operation_id(self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the assignment location of the authority fence.
    #[must_use]
    pub const fn sandbox_id(self) -> [u8; 16] {
        self.sandbox_id
    }

    /// Returns the exact location of the sealed admission intent.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the crash-recovery phase.
    #[must_use]
    pub const fn phase(self) -> DurableStoragePhase {
        self.phase
    }

    /// Returns the exact pending mutation commitment.
    #[must_use]
    pub const fn mutation_digest(self) -> ObjectDigest {
        self.mutation_digest
    }

    /// Returns the opaque catalog generation/digest association.
    #[must_use]
    pub const fn catalog(self) -> CatalogBindingV1 {
        self.catalog
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableRecord {
    phase: DurableStoragePhase,
    operation_id: [u8; 16],
    sandbox_id: [u8; 16],
    request_id: [u8; 16],
    request_digest: ObjectDigest,
    mutation_digest: ObjectDigest,
    catalog: CatalogBindingV1,
    postcondition_digest: ObjectDigest,
    catalog_bytes: Vec<u8>,
    result: Option<CommittedStorageResultV1>,
}

enum PreparedRecord {
    Existing(BeginStorageTransaction),
    New(Box<DurableRecord>),
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
    /// `directory` must be an absolute path whose complete ancestry satisfies
    /// [`Journal::open_protected_at`]. The final directory must be exactly mode
    /// 0700; the journal and independent lock must be root-owned, single-link
    /// regular files exactly mode 0600. Protected-open rejection never falls
    /// back to the ordinary pathname opener.
    ///
    /// `minimum_generation` is an external monotonic rollback anchor. Opening a
    /// valid older record below it fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::Journal`] for protected-path rejection,
    /// unsupported protected resolution, lock contention, or journal failure;
    /// returns another [`StorageStateError`] for record authentication failure
    /// or rollback below `minimum_generation`.
    pub fn open_root_owned(
        directory: &Path,
        key: StorageStateKey,
        minimum_generation: u64,
    ) -> Result<Self, StorageStateError> {
        let (journal, _) =
            Journal::open_protected_at(directory, "storage-state.journal", journal_limits())?;
        Self::from_journal(journal, key, minimum_generation)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        directory: &Path,
        key: StorageStateKey,
        minimum_generation: u64,
    ) -> Result<Self, StorageStateError> {
        let (journal, _) =
            Journal::open(directory.join("storage-state.journal"), journal_limits())?;
        Self::from_journal(journal, key, minimum_generation)
    }

    fn from_journal(
        journal: Journal,
        key: StorageStateKey,
        minimum_generation: u64,
    ) -> Result<Self, StorageStateError> {
        let mut records = BTreeMap::new();
        for (record_key, bytes) in journal.records(RecordNamespace::Operation) {
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

    /// Iterates every bounded durable operation for startup reconciliation.
    ///
    /// This path does not rerun live admission, so a newer assignment fence or
    /// lease cannot silently orphan an older pending/ambiguous operation. A
    /// privileged observer must still authenticate that operation's persisted
    /// authority links before reconciling it.
    pub fn recovery_entries(&self) -> impl Iterator<Item = StorageRecoveryEntry> + '_ {
        self.records.values().map(|record| StorageRecoveryEntry {
            operation_id: record.operation_id,
            sandbox_id: record.sandbox_id,
            request_id: record.request_id,
            phase: record.phase,
            mutation_digest: record.mutation_digest,
            catalog: record.catalog,
        })
    }

    /// Reconstructs the exact typed catalog for one enumerated recovery entry.
    ///
    /// The returned plan contains node-local dataset names and is intended only
    /// for the privileged observation helper. The entry must still name the
    /// exact current operation record; copying an entry from another store or
    /// from an older phase cannot select different persisted bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::InvalidTransition`] when `entry` is not the
    /// current exact record, and [`StorageStateError::CorruptRecord`] when its
    /// authenticated catalog bytes cannot reproduce the committed binding.
    pub fn recover_catalog(
        &self,
        entry: StorageRecoveryEntry,
    ) -> Result<ResolvedCatalogCommitmentV1, StorageStateError> {
        let record = self
            .records
            .get(&entry.operation_id)
            .filter(|record| {
                record.sandbox_id == entry.sandbox_id
                    && record.request_id == entry.request_id
                    && record.phase == entry.phase
                    && record.mutation_digest == entry.mutation_digest
                    && record.catalog == entry.catalog
            })
            .ok_or(StorageStateError::InvalidTransition)?;
        let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(&record.catalog_bytes)
            .map_err(|_| StorageStateError::CorruptRecord)?;
        if catalog.binding() != record.catalog {
            return Err(StorageStateError::CorruptRecord);
        }
        Ok(catalog)
    }

    #[cfg(test)]
    pub(crate) fn begin(
        &mut self,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<BeginStorageTransaction, StorageStateError> {
        match self.prepare_record(operation_id, request_digest, catalog)? {
            PreparedRecord::Existing(outcome) => Ok(outcome),
            PreparedRecord::New(record) => {
                let mutation_digest = record.mutation_digest;
                self.publish(*record)?;
                Ok(BeginStorageTransaction::Prepared { mutation_digest })
            }
        }
    }

    fn prepare_record(
        &self,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<PreparedRecord, StorageStateError> {
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
            return Ok(PreparedRecord::Existing(
                match (current.phase, current.result) {
                    (DurableStoragePhase::Committed, Some(result)) => {
                        BeginStorageTransaction::Replay(result)
                    }
                    (phase, _) => BeginStorageTransaction::ObserveOnly {
                        phase,
                        mutation_digest,
                    },
                },
            ));
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
            sandbox_id: [0; 16],
            request_id: [0; 16],
            request_digest,
            mutation_digest,
            catalog: catalog.binding(),
            postcondition_digest: postcondition_digest(catalog.canonical_bytes()),
            catalog_bytes: catalog.canonical_bytes().to_vec(),
            result: None,
        };
        Ok(PreparedRecord::New(Box::new(record)))
    }

    pub(crate) fn authority_record(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.journal.get(namespace, key)
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn remove_authority_record_for_test(
        &mut self,
        namespace: RecordNamespace,
        key: &[u8],
    ) {
        let transaction = JournalTransaction::new(
            [241; 16],
            vec![JournalRecord::delete(namespace, key.to_vec())],
        )
        .unwrap();
        self.journal.commit(&transaction).unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_authorized(
        &mut self,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        sandbox_id: [u8; 16],
        request_id: [u8; 16],
        sealed_fence: Vec<u8>,
        sealed_effect: Vec<u8>,
    ) -> Result<BeginStorageTransaction, StorageStateError> {
        if sealed_fence.is_empty()
            || sealed_effect.is_empty()
            || sealed_fence.len() > MAXIMUM_RECORD_BYTES
            || sealed_effect.len() > MAXIMUM_RECORD_BYTES
        {
            return Err(StorageStateError::InvalidValue);
        }
        let record = match self.prepare_record(operation_id, request_digest, catalog)? {
            PreparedRecord::Existing(outcome) => {
                let current = self
                    .records
                    .get(&operation_id)
                    .ok_or(StorageStateError::InvalidTransition)?;
                if current.sandbox_id != sandbox_id || current.request_id != request_id {
                    return Err(StorageStateError::AuthorityLinkMismatch);
                }
                return Ok(outcome);
            }
            PreparedRecord::New(mut record) => {
                record.sandbox_id = sandbox_id;
                record.request_id = request_id;
                *record
            }
        };
        let mutation_digest = record.mutation_digest;
        self.publish_with(
            record,
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    sandbox_id.to_vec(),
                    sealed_fence,
                ),
                JournalRecord::put(RecordNamespace::Effect, request_id.to_vec(), sealed_effect),
            ],
        )?;
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

    pub(crate) fn mark_mutation_ambiguous_exact(
        &mut self,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<(), StorageStateError> {
        self.validate_mutation_exact(operation_id, request_digest, mutation_digest, catalog)?;
        self.mark_mutation_ambiguous(operation_id, mutation_digest)
    }

    pub(crate) fn validate_mutation_exact(
        &self,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<(), StorageStateError> {
        // This read-only guard runs before a privileged observer is allowed to
        // derive names from the supplied catalog. The state transition repeats
        // the same comparison immediately before publishing Ambiguous so a
        // future store implementation cannot accidentally widen the TOCTOU gap.
        let record = self.exact_current(operation_id, mutation_digest)?;
        if record.request_digest != request_digest
            || record.catalog != catalog.binding()
            || record.catalog_bytes != catalog.canonical_bytes()
            || record.postcondition_digest != postcondition_digest(catalog.canonical_bytes())
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(())
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
            || verified.result_catalog.generation() <= record.catalog.generation()
            || verified.result_catalog.generation() < latest_generation
            || self.records.values().any(|existing| {
                catalog_forks(existing.catalog, verified.result_catalog)
                    || existing.result.is_some_and(|result| {
                        catalog_forks(result.catalog, verified.result_catalog)
                    })
            })
        {
            return Err(StorageStateError::InvalidTransition);
        }
        let result = self.committed_result(&verified)?;
        record.phase = DurableStoragePhase::Committed;
        record.result = Some(result);
        self.publish(record)?;
        Ok(result)
    }

    fn committed_result(
        &self,
        verified: &VerifiedStorageResultV1,
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        let (storage_handle, immutable_version_handle, object_guid) =
            match verified.resource_identity {
                VerifiedResourceIdentity::MintWorkspace { object_guid } => (
                    Some(self.mint_resource_handle(1, verified, object_guid)?),
                    None,
                    Some(object_guid),
                ),
                VerifiedResourceIdentity::MintVersion {
                    storage_handle,
                    object_guid,
                } => (
                    Some(storage_handle),
                    Some(self.mint_resource_handle(2, verified, object_guid)?),
                    Some(object_guid),
                ),
                VerifiedResourceIdentity::Existing {
                    storage_handle,
                    immutable_version_handle,
                    object_guid,
                } => (Some(storage_handle), immutable_version_handle, object_guid),
            };

        Ok(CommittedStorageResultV1 {
            catalog: verified.result_catalog,
            result_digest: verified.result_digest,
            storage_handle,
            immutable_version_handle,
            object_guid,
        })
    }

    fn mint_resource_handle(
        &self,
        kind: u8,
        verified: &VerifiedStorageResultV1,
        object_guid: u64,
    ) -> Result<[u8; 32], StorageStateError> {
        let mut mac = HmacSha256::new_from_slice(&self.key.secret)
            .map_err(|_| StorageStateError::InvalidValue)?;
        mac.update(RESOURCE_HANDLE_DOMAIN);
        mac.update(&self.key.key_id);
        mac.update(&[kind]);
        mac.update(&verified.operation_id);
        mac.update(verified.request_digest.as_bytes());
        mac.update(&object_guid.to_be_bytes());
        mac.update(&verified.result_catalog.generation().to_be_bytes());
        mac.update(verified.result_catalog.digest().as_bytes());
        let mut handle: [u8; 32] = mac.finalize().into_bytes().into();
        if handle == [0; 32] {
            handle[31] = 1;
        }
        Ok(handle)
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
        self.publish_with(record, Vec::new())
    }

    fn publish_with(
        &mut self,
        record: DurableRecord,
        mut additional: Vec<JournalRecord>,
    ) -> Result<(), StorageStateError> {
        let bytes = encode_record(&record, &self.key)?;
        additional.push(JournalRecord::put(
            RecordNamespace::Operation,
            record.operation_id.to_vec(),
            bytes,
        ));
        let transaction = JournalTransaction::new(
            transaction_id(record.operation_id, record.phase),
            additional,
        )?;
        self.journal.commit(&transaction)?;
        self.records.insert(record.operation_id, record);
        Ok(())
    }
}

const fn journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_RECORD_BYTES,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 4,
        maximum_transaction_bytes: MAXIMUM_RECORD_BYTES * 4,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: MAXIMUM_RECORD_BYTES * MAXIMUM_OPERATIONS * 3,
        maximum_materialized_records: MAXIMUM_OPERATIONS * 3,
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

fn verified_resource_identity(
    plan: &CatalogPlanV1,
    observed_object_guid: Option<u64>,
) -> Result<VerifiedResourceIdentity, StorageStateError> {
    match plan {
        CatalogPlanV1::CreateWorkspace { .. } | CatalogPlanV1::Clone { .. } => {
            let object_guid = nonzero_observed_guid(observed_object_guid)?;
            Ok(VerifiedResourceIdentity::MintWorkspace { object_guid })
        }
        CatalogPlanV1::Snapshot { source, .. } => {
            let object_guid = nonzero_observed_guid(observed_object_guid)?;
            Ok(VerifiedResourceIdentity::MintVersion {
                storage_handle: source.storage_handle(),
                object_guid,
            })
        }
        CatalogPlanV1::HoldSnapshot { snapshot, .. }
        | CatalogPlanV1::ReleaseHold { snapshot, .. } => {
            require_observed_guid(observed_object_guid, snapshot.guid())?;
            Ok(VerifiedResourceIdentity::Existing {
                storage_handle: snapshot.dataset().storage_handle(),
                immutable_version_handle: Some(snapshot.version_handle()),
                object_guid: Some(snapshot.guid()),
            })
        }
        CatalogPlanV1::SetQuota { dataset, .. } => {
            require_observed_guid(observed_object_guid, dataset.guid())?;
            Ok(VerifiedResourceIdentity::Existing {
                storage_handle: dataset.storage_handle(),
                immutable_version_handle: None,
                object_guid: Some(dataset.guid()),
            })
        }
        CatalogPlanV1::DestroyDataset { dataset } => {
            require_absent_guid(observed_object_guid)?;
            Ok(VerifiedResourceIdentity::Existing {
                storage_handle: dataset.storage_handle(),
                immutable_version_handle: None,
                object_guid: None,
            })
        }
        CatalogPlanV1::DestroySnapshot { snapshot } => {
            require_absent_guid(observed_object_guid)?;
            Ok(VerifiedResourceIdentity::Existing {
                storage_handle: snapshot.dataset().storage_handle(),
                immutable_version_handle: Some(snapshot.version_handle()),
                object_guid: None,
            })
        }
    }
}

fn nonzero_observed_guid(value: Option<u64>) -> Result<u64, StorageStateError> {
    value
        .filter(|guid| *guid != 0)
        .ok_or(StorageStateError::InvalidTransition)
}

fn require_observed_guid(value: Option<u64>, expected: u64) -> Result<(), StorageStateError> {
    if value == Some(expected) {
        Ok(())
    } else {
        Err(StorageStateError::InvalidTransition)
    }
}

fn require_absent_guid(value: Option<u64>) -> Result<(), StorageStateError> {
    if value.is_none() {
        Ok(())
    } else {
        Err(StorageStateError::InvalidTransition)
    }
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
    encode_record_version(record, key, VERSION)
}

fn encode_record_version(
    record: &DurableRecord,
    key: &StorageStateKey,
    version: u16,
) -> Result<Vec<u8>, StorageStateError> {
    if !matches!(version, LEGACY_VERSION | VERSION) {
        return Err(StorageStateError::CorruptRecord);
    }
    let result_len = if record.result.is_some() {
        if version == VERSION {
            RESULT_BYTES
        } else {
            LEGACY_RESULT_BYTES
        }
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
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.push(phase_code(record.phase));
    bytes.extend_from_slice(&record.operation_id);
    bytes.extend_from_slice(&record.sandbox_id);
    bytes.extend_from_slice(&record.request_id);
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
        if version == VERSION {
            let flags = (u8::from(result.storage_handle.is_some()) * RESULT_HAS_STORAGE_HANDLE)
                | (u8::from(result.immutable_version_handle.is_some()) * RESULT_HAS_VERSION_HANDLE)
                | (u8::from(result.object_guid.is_some()) * RESULT_HAS_OBJECT_GUID);
            bytes.push(flags);
            bytes.extend_from_slice(&result.storage_handle.unwrap_or([0; 32]));
            bytes.extend_from_slice(&result.immutable_version_handle.unwrap_or([0; 32]));
            bytes.extend_from_slice(&result.object_guid.unwrap_or(0).to_be_bytes());
        }
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
    if cursor.take(8)? != MAGIC {
        return Err(StorageStateError::CorruptRecord);
    }
    let version = cursor.u16()?;
    if !matches!(version, LEGACY_VERSION | VERSION) {
        return Err(StorageStateError::CorruptRecord);
    }
    let phase = match cursor.u8()? {
        1 => DurableStoragePhase::Prepared,
        2 => DurableStoragePhase::Ambiguous,
        3 => DurableStoragePhase::Committed,
        _ => return Err(StorageStateError::CorruptRecord),
    };
    let operation_id = cursor.array()?;
    let sandbox_id = cursor.array()?;
    let request_id = cursor.array()?;
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
        let catalog = CatalogBindingV1::from_publisher(
            cursor.u64()?,
            ObjectDigest::from_bytes(cursor.array()?),
        )
        .map_err(|_| StorageStateError::CorruptRecord)?;
        let result_digest = ObjectDigest::from_bytes(cursor.array()?);
        let identity = if version == VERSION {
            decode_result_identity(&mut cursor)?
        } else {
            DecodedResultIdentity {
                storage_handle: None,
                immutable_version_handle: None,
                object_guid: None,
            }
        };
        Some(CommittedStorageResultV1 {
            catalog,
            result_digest,
            storage_handle: identity.storage_handle,
            immutable_version_handle: identity.immutable_version_handle,
            object_guid: identity.object_guid,
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
        sandbox_id,
        request_id,
        request_digest,
        mutation_digest: stored_mutation_digest,
        catalog,
        postcondition_digest: stored_postcondition_digest,
        catalog_bytes,
        result,
    })
}

fn decode_result_identity(
    cursor: &mut Cursor<'_>,
) -> Result<DecodedResultIdentity, StorageStateError> {
    let flags = cursor.u8()?;
    if flags & !(RESULT_HAS_STORAGE_HANDLE | RESULT_HAS_VERSION_HANDLE | RESULT_HAS_OBJECT_GUID)
        != 0
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let storage_bytes = cursor.array()?;
    let version_bytes = cursor.array()?;
    let guid = cursor.u64()?;
    let storage_handle =
        optional_nonzero_array(storage_bytes, flags & RESULT_HAS_STORAGE_HANDLE != 0)?;
    let immutable_version_handle =
        optional_nonzero_array(version_bytes, flags & RESULT_HAS_VERSION_HANDLE != 0)?;
    let object_guid = match (flags & RESULT_HAS_OBJECT_GUID != 0, guid) {
        (true, 1..) => Some(guid),
        (false, 0) => None,
        _ => return Err(StorageStateError::CorruptRecord),
    };
    if immutable_version_handle.is_some() && storage_handle.is_none() {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(DecodedResultIdentity {
        storage_handle,
        immutable_version_handle,
        object_guid,
    })
}

fn optional_nonzero_array<const N: usize>(
    bytes: [u8; N],
    present: bool,
) -> Result<Option<[u8; N]>, StorageStateError> {
    match (present, bytes == [0; N]) {
        (true, false) => Ok(Some(bytes)),
        (false, true) => Ok(None),
        _ => Err(StorageStateError::CorruptRecord),
    }
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

    use std::fs::{self, OpenOptions};
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

    use aos_sandbox::JournalError;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, PlannedDataset, PlannedSnapshot,
        ProjectAncestorPolicyV1, ReservationPolicy, ResolvedDataset, StorageDomainsV1,
        StorageOperation, WorkspaceSpacePolicyV1, ZfsTransaction,
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

    fn snapshot_catalog(generation: u64) -> ResolvedCatalogCommitmentV1 {
        let source = ResolvedDataset::from_catalog(
            ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap(),
            "tank/aos/project/work",
            11,
            [81; 32],
            domains(),
        )
        .unwrap();
        let destination = PlannedSnapshot::from_catalog(source.clone(), "revision-1").unwrap();
        ResolvedCatalogCommitmentV1::new(
            generation,
            domains(),
            CatalogPlanV1::Snapshot {
                source,
                destination,
            },
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
    fn authorized_prepare_atomically_recovers_all_cross_links() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let sandbox_id = [33; 16];
        let request_id = [34; 16];
        let fence = b"sealed-storage-fence".to_vec();
        let intent = b"sealed-storage-admission-intent".to_vec();
        {
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            assert!(matches!(
                store
                    .begin_authorized(
                        [31; 16],
                        digest(32),
                        &catalog,
                        sandbox_id,
                        request_id,
                        fence.clone(),
                        intent.clone(),
                    )
                    .unwrap(),
                BeginStorageTransaction::Prepared { .. }
            ));
        }

        let store = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(
            store.authority_record(RecordNamespace::DesiredState, &sandbox_id),
            Some(fence.as_slice())
        );
        assert_eq!(
            store.authority_record(RecordNamespace::Effect, &request_id),
            Some(intent.as_slice())
        );
        assert_eq!(store.phase([31; 16]), Some(DurableStoragePhase::Prepared));
    }

    #[test]
    fn unauthenticated_partial_intent_has_no_authority_cross_links() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        store.begin([35; 16], digest(36), &catalog).unwrap();
        assert!(
            store
                .authority_record(RecordNamespace::DesiredState, &[37; 16])
                .is_none()
        );
        assert!(
            store
                .authority_record(RecordNamespace::Effect, &[38; 16])
                .is_none()
        );
    }

    #[test]
    fn recovery_scan_surfaces_pending_work_without_live_readmission() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        store.begin([39; 16], digest(40), &catalog).unwrap();
        let entries = store.recovery_entries().collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].operation_id(), [39; 16]);
        assert_eq!(entries[0].phase(), DurableStoragePhase::Prepared);
        assert_eq!(entries[0].catalog(), catalog.binding());
        assert_eq!(store.recover_catalog(entries[0]).unwrap(), catalog);
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
                Some(91),
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
        assert_eq!(expected.object_guid(), Some(91));
        assert!(
            expected
                .storage_handle()
                .is_some_and(|handle| handle != [0; 32])
        );
        assert_eq!(expected.immutable_version_handle(), None);
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
    fn snapshot_result_retains_workspace_and_mints_a_version_handle() {
        let directory = TempDir::new().unwrap();
        let catalog = snapshot_catalog(7);
        let operation_id = [47; 16];
        let request_digest = digest(48);
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let BeginStorageTransaction::Prepared { mutation_digest } =
            store.begin(operation_id, request_digest, &catalog).unwrap()
        else {
            panic!("new snapshot operation was not prepared")
        };
        store
            .mark_mutation_ambiguous(operation_id, mutation_digest)
            .unwrap();
        let verified = VerifiedStorageResultV1::verify_observation(
            operation_id,
            request_digest,
            &catalog,
            &catalog.plan().postcondition(),
            Some(91),
            CatalogBindingV1::from_publisher(8, digest(49)).unwrap(),
            digest(50),
        )
        .unwrap();
        let result = store
            .commit_verified(operation_id, mutation_digest, verified)
            .unwrap();

        assert_eq!(result.storage_handle(), Some([81; 32]));
        assert_eq!(result.object_guid(), Some(91));
        assert!(
            result
                .immutable_version_handle()
                .is_some_and(|handle| handle != [0; 32] && handle != [81; 32])
        );

        let legacy_bytes = encode_record_version(
            store.records.get(&operation_id).unwrap(),
            &store.key,
            LEGACY_VERSION,
        )
        .unwrap();
        let legacy = decode_record(&legacy_bytes, &store.key)
            .unwrap()
            .result
            .unwrap();
        assert_eq!(legacy.storage_handle(), None);
        assert_eq!(legacy.immutable_version_handle(), None);
        assert_eq!(legacy.object_guid(), None);
    }

    #[test]
    fn malformed_result_identity_shapes_fail_closed() {
        let cases = [
            (8, [0; 32], [0; 32], 0_u64),
            (RESULT_HAS_STORAGE_HANDLE, [0; 32], [0; 32], 0_u64),
            (RESULT_HAS_VERSION_HANDLE, [0; 32], [1; 32], 0_u64),
            (RESULT_HAS_OBJECT_GUID, [0; 32], [0; 32], 0_u64),
        ];

        for (flags, storage_handle, version_handle, object_guid) in cases {
            let mut bytes = Vec::with_capacity(RESULT_BYTES - LEGACY_RESULT_BYTES);
            bytes.push(flags);
            bytes.extend_from_slice(&storage_handle);
            bytes.extend_from_slice(&version_handle);
            bytes.extend_from_slice(&object_guid.to_be_bytes());

            assert!(matches!(
                decode_result_identity(&mut Cursor::new(&bytes)),
                Err(StorageStateError::CorruptRecord)
            ));
        }
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
                Some(91),
                CatalogBindingV1::from_publisher(8, digest(65)).unwrap(),
                digest(66),
            ),
            Err(StorageStateError::InvalidTransition)
        ));
        for invalid_guid in [None, Some(0)] {
            assert!(matches!(
                VerifiedStorageResultV1::verify_observation(
                    [61; 16],
                    digest(62),
                    &original,
                    &original.plan().postcondition(),
                    invalid_guid,
                    CatalogBindingV1::from_publisher(8, digest(65)).unwrap(),
                    digest(66),
                ),
                Err(StorageStateError::InvalidTransition)
            ));
        }

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
            Some(91),
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
    fn protected_open_rejects_relative_and_unsafe_ancestry() {
        use std::os::unix::fs::PermissionsExt as _;

        assert!(matches!(
            StorageTransactionStore::open_root_owned(Path::new("relative/state"), key(1), 0),
            Err(StorageStateError::Journal(JournalError::ProtectedBoundary))
        ));

        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            StorageTransactionStore::open_root_owned(directory.path(), key(1), 0),
            Err(StorageStateError::Journal(JournalError::ProtectedBoundary))
        ));
    }
}
