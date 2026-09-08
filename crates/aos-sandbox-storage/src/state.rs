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
use aos_sandbox_core::{MediaType, ObjectDescriptor, ObjectDigest};
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};

use crate::catalog_transition::{
    CatalogReservation, PhysicalWorkspaceProjection, StorageCatalogTransitionProvider,
};
use crate::workspace_catalog::StorageWorkspacePublicationIntentV1;
use crate::{CatalogBindingV1, CatalogPlanV1, PostconditionPolicyV1, ResolvedCatalogCommitmentV1};

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 8] = b"AOSSTX01";
const VERSION: u16 = 4;
const IDENTITY_VERSION: u16 = 3;
const LEGACY_VERSION: u16 = 2;
#[cfg(test)]
pub(crate) const TEST_LEGACY_FORMAT_VERSIONS: [u16; 2] = [LEGACY_VERSION, IDENTITY_VERSION];
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.storage.state.record.v1\0";
const MUTATION_DOMAIN: &[u8] = b"aos.sandbox.storage.mutation.v1\0";
const POSTCONDITION_DOMAIN: &[u8] = b"aos.sandbox.storage.postcondition.v1\0";
const RESOURCE_HANDLE_DOMAIN: &[u8] = b"aos.sandbox.storage.resource-handle.v1\0";
const RUNTIME_CONFIGURATION_DOMAIN: &[u8] = b"aos.sandbox.storage.runtime-configuration.v1\0";
const RUNTIME_CONFIGURATION_MAGIC: &[u8; 8] = b"AOSSCFG1";
const RUNTIME_CONFIGURATION_VERSION: u16 = 1;
const RUNTIME_CONFIGURATION_KEY: &[u8] = b"current";
const PUBLICATION_INTENT_DOMAIN: &[u8] = b"aos.sandbox.storage.publication-intent.v1\0";
const PUBLICATION_INTENT_MAGIC: &[u8; 8] = b"AOSSPI01";
const PUBLICATION_INTENT_VERSION: u16 = 1;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024;
const FIXED_PREFIX_BYTES: usize = 8 + 2 + 1 + 16 + 16 + 16 + 32 + 32 + 8 + 32 + 32 + 4;
const LEGACY_RESULT_BYTES: usize = 8 + 32 + 32;
const RESULT_BYTES: usize = LEGACY_RESULT_BYTES + 1 + 32 + 32 + 8;
const MAC_BYTES: usize = 32;
const RESULT_HAS_STORAGE_HANDLE: u8 = 1;
const RESULT_HAS_VERSION_HANDLE: u8 = 1 << 1;
const RESULT_HAS_OBJECT_GUID: u8 = 1 << 2;
const MAXIMUM_OPERATIONS: usize = 256;
const MATERIALIZED_RECORDS_PER_OPERATION: usize = 7;
const GLOBAL_MATERIALIZED_RECORDS: usize = 2;
const MAXIMUM_JOURNAL_RECORD_BYTES: usize = MAXIMUM_RECORD_BYTES + 128;

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
    operation_id: [u8; 16],
    catalog: CatalogBindingV1,
    result_digest: ObjectDigest,
    storage_handle: Option<[u8; 32]>,
    immutable_version_handle: Option<[u8; 32]>,
    object_guid: Option<u64>,
}

impl CommittedStorageResultV1 {
    /// Returns the exact idempotent operation that committed this result.
    #[must_use]
    pub const fn operation_id(self) -> [u8; 16] {
        self.operation_id
    }

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
    request_digest: ObjectDigest,
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

    /// Returns SHA-256 over the exact admitted request body.
    #[must_use]
    pub const fn request_digest(self) -> ObjectDigest {
        self.request_digest
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageWorkspaceProjection {
    Active(CommittedStorageResultV1),
    Retired {
        creation: CommittedStorageResultV1,
        retirement: CommittedStorageResultV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableRecord {
    format_version: u16,
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
    catalog_transitions: StorageCatalogTransitionProvider,
    runtime_configuration: Option<ObjectDigest>,
    publication_intents: BTreeMap<[u8; 16], StorageWorkspacePublicationIntentV1>,
    commit_failed: bool,
    #[cfg(test)]
    fail_after_next_journal_commit: bool,
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

    /// Opens initialized runtime state or atomically initializes an unused journal.
    ///
    /// Existing state always authenticates and enforces `minimum_generation`
    /// before it is returned. A physically unused journal is the sole exception
    /// to opening at generation zero: it is initialized, while the exclusive
    /// journal lock is held, with the protected runtime binding and complete
    /// genesis snapshot. Its `genesis_generation` must already satisfy the
    /// protected minimum.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::Rollback`] when an existing authenticated
    /// generation or the proposed genesis is below `minimum_generation`.
    /// Returns [`StorageStateError::InvalidTransition`] when unused-state
    /// validation or atomic initialization fails, and another
    /// [`StorageStateError`] for protected-path, authentication, catalog, or
    /// durable commit failure.
    pub fn open_root_owned_runtime(
        directory: &Path,
        key: StorageStateKey,
        minimum_generation: u64,
        configuration_binding: ObjectDigest,
        genesis_generation: u64,
        genesis_catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<Self, StorageStateError> {
        let (journal, _) =
            Journal::open_protected_at(directory, "storage-state.journal", journal_limits())?;
        Self::open_or_initialize_runtime(
            journal,
            key,
            minimum_generation,
            configuration_binding,
            genesis_generation,
            genesis_catalogs,
        )
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

    #[cfg(test)]
    fn open_runtime_for_test(
        directory: &Path,
        key: StorageStateKey,
        minimum_generation: u64,
        configuration_binding: ObjectDigest,
        genesis_generation: u64,
        genesis_catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<Self, StorageStateError> {
        let (journal, _) =
            Journal::open(directory.join("storage-state.journal"), journal_limits())?;
        Self::open_or_initialize_runtime(
            journal,
            key,
            minimum_generation,
            configuration_binding,
            genesis_generation,
            genesis_catalogs,
        )
    }

    #[cfg(test)]
    fn open_for_test_with_limits(
        directory: &Path,
        key: StorageStateKey,
        minimum_generation: u64,
        limits: JournalLimits,
    ) -> Result<Self, StorageStateError> {
        let (journal, _) = Journal::open(directory.join("storage-state.journal"), limits)?;
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
        let runtime_configuration = load_runtime_configuration(&journal, &key)?;
        let publication_intents = load_publication_intents(&journal, &key)?;
        let catalog_transitions =
            StorageCatalogTransitionProvider::load(&journal, key.key_id, &key.secret)?;
        let latest_generation = latest_generation(&records).max(
            catalog_transitions
                .head_binding()
                .map_or(0, CatalogBindingV1::generation),
        );
        if latest_generation < minimum_generation {
            return Err(StorageStateError::Rollback);
        }
        for record in records.values() {
            let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(&record.catalog_bytes)
                .map_err(|_| StorageStateError::CorruptRecord)?;
            let evidence = catalog_transitions.validates_operation_transition(
                record.format_version,
                record.operation_id,
                record.request_digest,
                record.mutation_digest,
                &catalog,
                record.phase,
                record.result.map(|result| result.catalog),
                key.key_id,
                &key.secret,
            )?;
            match (record.result, evidence) {
                (Some(result), Some(evidence)) => {
                    let verified = VerifiedStorageResultV1::verify_observation(
                        record.operation_id,
                        record.request_digest,
                        &catalog,
                        &catalog.plan().postcondition(),
                        evidence.object_guid,
                        evidence.result_catalog,
                        evidence.observation_digest,
                    )?;
                    if committed_result_with_key(&key, &verified)? != result {
                        return Err(StorageStateError::CorruptRecord);
                    }
                }
                (Some(_), None)
                    if matches!(record.format_version, LEGACY_VERSION | IDENTITY_VERSION) => {}
                (None, None) => {}
                _ => return Err(StorageStateError::CorruptRecord),
            }
        }
        catalog_transitions.validate_operation_set(records.keys().copied())?;
        validate_publication_intent_set(&records, &publication_intents)?;
        Ok(Self {
            journal,
            key,
            records,
            catalog_transitions,
            runtime_configuration,
            publication_intents,
            commit_failed: false,
            #[cfg(test)]
            fail_after_next_journal_commit: false,
        })
    }

    fn open_or_initialize_runtime(
        journal: Journal,
        key: StorageStateKey,
        minimum_generation: u64,
        configuration_binding: ObjectDigest,
        genesis_generation: u64,
        genesis_catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<Self, StorageStateError> {
        // The ordinary opener must retain strict rollback behavior. This
        // runtime-only path first authenticates generation-zero emptiness, then
        // consumes that state immediately with one durable bootstrap commit.
        let mut store = Self::from_journal(journal, key, 0)?;
        if store.is_strictly_unused() {
            if genesis_generation < minimum_generation {
                return Err(StorageStateError::Rollback);
            }
            store.initialize_runtime_from_protected_snapshot(
                configuration_binding,
                genesis_generation,
                genesis_catalogs,
            )?;
        } else {
            store.enforce_minimum_generation(minimum_generation)?;
        }
        Ok(store)
    }

    fn enforce_minimum_generation(&self, minimum_generation: u64) -> Result<(), StorageStateError> {
        let latest_generation = latest_generation(&self.records).max(
            self.catalog_transitions
                .head_binding()
                .map_or(0, CatalogBindingV1::generation),
        );
        if latest_generation < minimum_generation {
            Err(StorageStateError::Rollback)
        } else {
            Ok(())
        }
    }

    fn is_strictly_unused(&self) -> bool {
        self.records.is_empty()
            && self.catalog_transitions.head_binding().is_none()
            && self.runtime_configuration.is_none()
            && self.publication_intents.is_empty()
            && self.journal.is_materialized_empty()
            && self.journal.snapshot_sequence() == 1
    }

    /// Returns the durable crash phase for `operation_id`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::Journal`] after any commit failure makes
    /// the cached materialized view unsafe for authority decisions.
    pub fn phase(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<DurableStoragePhase>, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self.records.get(&operation_id).map(|record| record.phase))
    }

    /// Iterates every bounded durable operation for startup reconciliation.
    ///
    /// This path does not rerun live admission, so a newer assignment fence or
    /// lease cannot silently orphan an older pending/ambiguous operation. A
    /// privileged observer must still authenticate that operation's persisted
    /// authority links before reconciling it.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::Journal`] after any commit failure makes
    /// the cached materialized view unsafe for startup reconciliation.
    pub fn recovery_entries(
        &self,
    ) -> Result<impl Iterator<Item = StorageRecoveryEntry> + '_, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self.records.values().map(recovery_entry))
    }

    pub(crate) fn current_recovery_entry(
        &self,
        operation_id: [u8; 16],
    ) -> Result<StorageRecoveryEntry, StorageStateError> {
        self.ensure_authority_readable()?;
        self.records
            .get(&operation_id)
            .map(recovery_entry)
            .ok_or(StorageStateError::InvalidTransition)
    }

    pub(crate) fn committed_recovery_entry(
        &self,
        result: CommittedStorageResultV1,
    ) -> Result<StorageRecoveryEntry, StorageStateError> {
        self.ensure_authority_readable()?;
        self.records
            .get(&result.operation_id)
            .filter(|record| {
                record.phase == DurableStoragePhase::Committed && record.result == Some(result)
            })
            .map(recovery_entry)
            .ok_or(StorageStateError::InvalidTransition)
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
    /// Returns [`StorageStateError::Journal`] after a commit failure poisons
    /// the cached authority view until reopen.
    pub fn recover_catalog(
        &self,
        entry: StorageRecoveryEntry,
    ) -> Result<ResolvedCatalogCommitmentV1, StorageStateError> {
        self.ensure_authority_readable()?;
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
                let reservation = self.reserve_catalog_transition(&record, catalog)?;
                self.publish_with(
                    *record,
                    vec![StorageCatalogTransitionProvider::reservation_record(
                        &reservation,
                    )],
                )?;
                self.catalog_transitions.install_reservation(reservation);
                Ok(BeginStorageTransaction::Prepared { mutation_digest })
            }
        }
    }

    /// Initializes the physical catalog head from one complete protected snapshot.
    ///
    /// Every catalog in `catalogs` contributes its already-existing roots,
    /// datasets, snapshots, and holds. Planned destinations are not imported.
    /// Initialization is permitted exactly once, before any operation or
    /// physical-catalog transition has been recorded.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::InvalidTransition`] if the catalog was
    /// already initialized or operation state exists. Returns another
    /// [`StorageStateError`] if the snapshot is empty, inconsistent, exceeds
    /// a bounded record limit, or cannot be committed durably.
    pub fn initialize_catalog_from_protected_snapshot(
        &mut self,
        generation: u64,
        catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<CatalogBindingV1, StorageStateError> {
        self.initialize_catalog(generation, catalogs, None)
    }

    /// Binds protected runtime authority while initializing an empty catalog.
    ///
    /// `catalogs` must come from the separately protected complete-bootstrap
    /// publisher contract. This function cannot prove completeness from a
    /// caller flag. It accepts the snapshot only when the journal has no
    /// operation, catalog, reservation, transition, or runtime binding.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::InvalidTransition`] unless the store is
    /// truly empty, and another [`StorageStateError`] for invalid bootstrap
    /// state, a zero configuration binding, or durable commit failure.
    pub fn initialize_runtime_from_protected_snapshot(
        &mut self,
        configuration_binding: ObjectDigest,
        generation: u64,
        catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<CatalogBindingV1, StorageStateError> {
        if configuration_binding.as_bytes() == &[0; 32] || self.runtime_configuration.is_some() {
            return Err(StorageStateError::InvalidTransition);
        }
        self.initialize_catalog(generation, catalogs, Some(configuration_binding))
    }

    /// Validates current protected authority and the immutable genesis identity.
    ///
    /// The authenticated current head may legitimately be newer than the
    /// static genesis after completed operations. Rollback is checked
    /// separately by [`Self::open_root_owned`] against its monotonic minimum.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::AuthorityLinkMismatch`] when protected
    /// authority or genesis identity changed, and
    /// [`StorageStateError::InvalidTransition`] when runtime configuration was
    /// never bound.
    pub fn validate_runtime_restart(
        &self,
        configuration_binding: ObjectDigest,
        genesis_generation: u64,
        genesis_catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<CatalogBindingV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let configured = self
            .runtime_configuration
            .ok_or(StorageStateError::InvalidTransition)?;
        let expected_genesis = StorageCatalogTransitionProvider::bootstrap_binding(
            genesis_generation,
            genesis_catalogs,
        )?;
        if configured != configuration_binding
            || self.catalog_transitions.genesis_binding() != Some(expected_genesis)
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        self.catalog_transitions
            .head_binding()
            .ok_or(StorageStateError::InvalidTransition)
    }

    /// Reports whether legacy pending state lacks the runtime binding.
    ///
    /// Such state may be observed for recovery but cannot authorize dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::Journal`] after a commit failure poisons
    /// the cached authority view.
    pub fn requires_legacy_recovery(&self) -> Result<bool, StorageStateError> {
        self.ensure_authority_readable()?;
        let missing_publication_intent = self.records.values().try_fold(
            false,
            |missing, record| -> Result<bool, StorageStateError> {
                let catalog =
                    ResolvedCatalogCommitmentV1::from_canonical_bytes(&record.catalog_bytes)
                        .map_err(|_| StorageStateError::CorruptRecord)?;
                Ok(missing
                    || (requires_workspace_publication(catalog.plan())
                        && !self.publication_intents.contains_key(&record.operation_id)))
            },
        )?;
        Ok((self.runtime_configuration.is_none()
            && (!self.records.is_empty() || self.catalog_transitions.head_binding().is_some()))
            || missing_publication_intent)
    }

    pub(crate) fn workspace_publication_intent(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<&StorageWorkspacePublicationIntentV1>, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self.publication_intents.get(&operation_id))
    }

    pub(crate) fn workspace_identity_ranges(&self) -> Result<Vec<(u32, u32)>, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self
            .publication_intents
            .values()
            .map(|intent| (intent.identity_range_start(), intent.identity_range_size()))
            .collect())
    }

    pub(crate) fn workspace_identity_range(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<(u32, u32)>, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self
            .publication_intents
            .get(&operation_id)
            .map(|intent| (intent.identity_range_start(), intent.identity_range_size())))
    }

    pub(crate) fn workspace_projection(
        &self,
    ) -> Result<Vec<StorageWorkspaceProjection>, StorageStateError> {
        self.ensure_authority_readable()?;
        let mut workspace_projection = Vec::new();
        for projection in self.catalog_transitions.workspace_projection()? {
            match projection {
                PhysicalWorkspaceProjection::Active {
                    operation_id,
                    object_guid,
                } => {
                    let result = self.projected_committed_result(operation_id)?;
                    if result.object_guid() != Some(object_guid) {
                        return Err(StorageStateError::AuthorityLinkMismatch);
                    }
                    if !self.publication_intents.contains_key(&operation_id) {
                        return Err(StorageStateError::MissingAuthorityLink);
                    }
                    workspace_projection.push(StorageWorkspaceProjection::Active(result));
                }
                PhysicalWorkspaceProjection::Retired {
                    operation_id,
                    object_guid,
                } => {
                    let Some(creation) = self.managed_workspace_creation(object_guid)? else {
                        continue;
                    };
                    let retirement = self.projected_committed_result(operation_id)?;
                    let record = self
                        .records
                        .get(&operation_id)
                        .ok_or(StorageStateError::MissingAuthorityLink)?;
                    let catalog =
                        ResolvedCatalogCommitmentV1::from_canonical_bytes(&record.catalog_bytes)
                            .map_err(|_| StorageStateError::CorruptRecord)?;
                    let CatalogPlanV1::DestroyDataset { dataset } = catalog.plan() else {
                        return Err(StorageStateError::AuthorityLinkMismatch);
                    };
                    if dataset.guid() != object_guid
                        || retirement.object_guid().is_some()
                        || retirement.storage_handle() != Some(dataset.storage_handle())
                        || creation.storage_handle() != retirement.storage_handle()
                    {
                        return Err(StorageStateError::AuthorityLinkMismatch);
                    }
                    workspace_projection.push(StorageWorkspaceProjection::Retired {
                        creation,
                        retirement,
                    });
                }
            }
        }
        Ok(workspace_projection)
    }

    fn managed_workspace_creation(
        &self,
        object_guid: u64,
    ) -> Result<Option<CommittedStorageResultV1>, StorageStateError> {
        let mut found = None;
        for record in self.records.values().filter(|record| {
            record.phase == DurableStoragePhase::Committed
                && record
                    .result
                    .is_some_and(|result| result.object_guid() == Some(object_guid))
        }) {
            let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(&record.catalog_bytes)
                .map_err(|_| StorageStateError::CorruptRecord)?;
            if !requires_workspace_publication(catalog.plan()) {
                continue;
            }
            if !self.publication_intents.contains_key(&record.operation_id) {
                return Err(StorageStateError::MissingAuthorityLink);
            }
            let result = record
                .result
                .ok_or(StorageStateError::MissingAuthorityLink)?;
            if found.replace(result).is_some() {
                return Err(StorageStateError::AuthorityLinkMismatch);
            }
        }
        Ok(found)
    }

    fn projected_committed_result(
        &self,
        operation_id: [u8; 16],
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        let record = self
            .records
            .get(&operation_id)
            .filter(|record| record.phase == DurableStoragePhase::Committed)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        record.result.ok_or(StorageStateError::MissingAuthorityLink)
    }

    fn initialize_catalog(
        &mut self,
        generation: u64,
        catalogs: &[ResolvedCatalogCommitmentV1],
        configuration_binding: Option<ObjectDigest>,
    ) -> Result<CatalogBindingV1, StorageStateError> {
        self.ensure_authority_readable()?;
        if !self.is_strictly_unused() {
            return Err(StorageStateError::InvalidTransition);
        }
        let bootstrap = self.catalog_transitions.prepare_bootstrap(
            generation,
            catalogs,
            self.key.key_id,
            &self.key.secret,
        )?;
        let binding = bootstrap.binding();
        let mut hash = Sha256::new();
        hash.update(b"aos.sandbox.storage.catalog-bootstrap.v1\0");
        hash.update(binding.generation().to_be_bytes());
        hash.update(binding.digest().as_bytes());
        let digest: [u8; 32] = hash.finalize().into();
        let mut transaction_id = [0; 16];
        transaction_id.copy_from_slice(&digest[..16]);
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }
        let mut journal_records = Vec::with_capacity(2);
        if let Some(configuration_binding) = configuration_binding {
            journal_records.push(runtime_configuration_record(
                &self.key,
                configuration_binding,
            )?);
        }
        journal_records.push(bootstrap.record());
        let transaction = JournalTransaction::new(transaction_id, journal_records)?;
        self.commit_journal(&transaction)?;
        self.catalog_transitions.install_bootstrap(bootstrap);
        self.runtime_configuration = configuration_binding.or(self.runtime_configuration);
        Ok(binding)
    }

    fn prepare_record(
        &self,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<PreparedRecord, StorageStateError> {
        self.ensure_authority_readable()?;
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
            format_version: VERSION,
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

    pub(crate) fn authority_record(
        &self,
        namespace: RecordNamespace,
        key: &[u8],
    ) -> Result<Option<&[u8]>, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self.journal.get(namespace, key))
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn remove_authority_record_for_test(
        &mut self,
        namespace: RecordNamespace,
        key: &[u8],
    ) {
        let transaction = JournalTransaction::new(
            [240_u8.wrapping_add(namespace as u8); 16],
            vec![JournalRecord::delete(namespace, key.to_vec())],
        )
        .unwrap();
        self.journal.commit(&transaction).unwrap();
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn put_authority_record_for_test(
        &mut self,
        namespace: RecordNamespace,
        key: &[u8],
        value: Vec<u8>,
    ) {
        let transaction = JournalTransaction::new(
            [230_u8.wrapping_add(namespace as u8); 16],
            vec![JournalRecord::put(namespace, key.to_vec(), value)],
        )
        .unwrap();
        self.journal.commit(&transaction).unwrap();
    }

    #[cfg(test)]
    fn fail_after_next_journal_commit_for_test(&mut self) {
        self.fail_after_next_journal_commit = true;
    }

    #[cfg(test)]
    fn journal_sequence_for_test(&self) -> u64 {
        self.journal.snapshot_sequence()
    }

    #[cfg(test)]
    pub(crate) fn rewrite_legacy_ambiguous_for_test(
        &mut self,
        operation_id: [u8; 16],
        format_version: u16,
    ) -> Result<(), StorageStateError> {
        let mut record = self
            .records
            .get(&operation_id)
            .cloned()
            .ok_or(StorageStateError::InvalidTransition)?;
        if record.phase != DurableStoragePhase::Prepared || record.format_version != VERSION {
            return Err(StorageStateError::InvalidTransition);
        }
        if !TEST_LEGACY_FORMAT_VERSIONS.contains(&format_version) {
            return Err(StorageStateError::InvalidValue);
        }
        record.format_version = format_version;
        record.phase = DurableStoragePhase::Ambiguous;
        let transaction = JournalTransaction::new(
            transaction_id(operation_id, DurableStoragePhase::Ambiguous),
            vec![
                JournalRecord::put(
                    RecordNamespace::Operation,
                    operation_id.to_vec(),
                    encode_record(&record, &self.key)?,
                ),
                JournalRecord::delete(
                    RecordNamespace::StorageCatalogReservation,
                    operation_id.to_vec(),
                ),
            ],
        )?;
        self.commit_journal(&transaction)?;
        self.records.insert(operation_id, record);
        self.catalog_transitions
            .remove_reservation_for_test(operation_id);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_authorized_with_publication(
        &mut self,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        sandbox_id: [u8; 16],
        request_id: [u8; 16],
        sealed_fence: Vec<u8>,
        sealed_effect: Vec<u8>,
        sealed_operation_fence: Vec<u8>,
        publication_intent: Option<StorageWorkspacePublicationIntentV1>,
    ) -> Result<BeginStorageTransaction, StorageStateError> {
        if sealed_fence.is_empty()
            || sealed_effect.is_empty()
            || sealed_operation_fence.is_empty()
            || sealed_fence.len() > MAXIMUM_RECORD_BYTES
            || sealed_effect.len() > MAXIMUM_RECORD_BYTES
            || sealed_operation_fence.len() > MAXIMUM_RECORD_BYTES
        {
            return Err(StorageStateError::InvalidValue);
        }
        if requires_workspace_publication(catalog.plan()) != publication_intent.is_some()
            || publication_intent.as_ref().is_some_and(|intent| {
                intent.operation_id() != operation_id
                    || intent.request_catalog() != catalog.binding()
            })
        {
            return Err(StorageStateError::MissingAuthorityLink);
        }
        if let Some(intent) = publication_intent.as_ref() {
            self.validate_publication_intent_range(intent)?;
        }
        let record = match self.prepare_record(operation_id, request_digest, catalog)? {
            PreparedRecord::Existing(outcome) => {
                let current = self
                    .records
                    .get(&operation_id)
                    .ok_or(StorageStateError::InvalidTransition)?;
                if current.sandbox_id != sandbox_id
                    || current.request_id != request_id
                    || self.publication_intents.get(&operation_id) != publication_intent.as_ref()
                {
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
        let reservation = self.reserve_catalog_transition(&record, catalog)?;
        let mut linked_records = vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                sandbox_id.to_vec(),
                sealed_fence,
            ),
            JournalRecord::put(RecordNamespace::Effect, request_id.to_vec(), sealed_effect),
            JournalRecord::put(
                RecordNamespace::AuthorityPublication,
                operation_id.to_vec(),
                sealed_operation_fence,
            ),
            StorageCatalogTransitionProvider::reservation_record(&reservation),
        ];
        if let Some(intent) = publication_intent.as_ref() {
            linked_records.push(publication_intent_record(&self.key, intent)?);
        }
        self.publish_with(record, linked_records)?;
        self.catalog_transitions.install_reservation(reservation);
        if let Some(intent) = publication_intent {
            self.publication_intents.insert(operation_id, intent);
        }
        Ok(BeginStorageTransaction::Prepared { mutation_digest })
    }

    fn validate_publication_intent_range(
        &self,
        candidate: &StorageWorkspacePublicationIntentV1,
    ) -> Result<(), StorageStateError> {
        let candidate_end = candidate
            .identity_range_start()
            .checked_add(candidate.identity_range_size())
            .ok_or(StorageStateError::InvalidValue)?;
        if self.publication_intents.values().any(|existing| {
            existing.operation_id() != candidate.operation_id()
                && existing
                    .identity_range_start()
                    .checked_add(existing.identity_range_size())
                    .is_none_or(|existing_end| {
                        candidate.identity_range_start() < existing_end
                            && existing.identity_range_start() < candidate_end
                    })
        }) {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(())
    }

    fn reserve_catalog_transition(
        &self,
        record: &DurableRecord,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<CatalogReservation, StorageStateError> {
        self.catalog_transitions.reserve(
            record.operation_id,
            record.request_digest,
            record.mutation_digest,
            catalog,
            self.key.key_id,
            &self.key.secret,
        )
    }

    /// Durably crosses the point after which mutation outcome may be ambiguous.
    ///
    /// The privileged helper calls this and syncs it before invoking ZFS.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::InvalidTransition`] unless the exact
    /// prepared operation and mutation digest are current. Returns
    /// [`StorageStateError::Journal`] if the cached view is poisoned, the
    /// complete effect sequence cannot fit its preflight budget, or the
    /// Ambiguous publication fails.
    pub fn mark_mutation_ambiguous(
        &mut self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
    ) -> Result<(), StorageStateError> {
        let mut record = self.exact_current(operation_id, mutation_digest)?.clone();
        if record.phase != DurableStoragePhase::Prepared {
            return Err(StorageStateError::InvalidTransition);
        }
        if record.format_version >= VERSION {
            self.preflight_effect_capacity(&record)?;
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
        self.ensure_authority_readable()?;
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

    /// Publishes a committed result for a recovered legacy transaction.
    ///
    /// Current records must use the observation-bound catalog transition path.
    /// This low-level compatibility entry point can finish an already-ambiguous
    /// version 2 or 3 record only when a trusted migration caller supplies the
    /// externally published result-catalog binding. The production helper has
    /// no such migration source and deliberately leaves legacy recovery open
    /// and observation-only; it never redispatches the mutation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::InvalidTransition`] unless the exact
    /// ambiguous legacy operation is current and the result advances catalog
    /// generation. Returns [`StorageStateError::Journal`] after a commit
    /// failure poisons the cached authority view until reopen.
    pub fn commit_verified(
        &mut self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        verified: VerifiedStorageResultV1,
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let mut record = self.exact_current(operation_id, mutation_digest)?.clone();
        let latest_generation = latest_generation(&self.records);
        if record.format_version >= VERSION
            || record.phase != DurableStoragePhase::Ambiguous
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_observed(
        &mut self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        observed: &PostconditionPolicyV1,
        observed_object_guid: Option<u64>,
        observation_digest: ObjectDigest,
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let mut record = self.exact_current(operation_id, mutation_digest)?.clone();
        if record.phase != DurableStoragePhase::Ambiguous
            || record.catalog != catalog.binding()
            || record.catalog_bytes != catalog.canonical_bytes()
        {
            return Err(StorageStateError::InvalidTransition);
        }

        let transition = self.catalog_transitions.prepare_transition(
            operation_id,
            mutation_digest,
            catalog,
            observed_object_guid,
            observation_digest,
            self.key.key_id,
            &self.key.secret,
        )?;
        let verified = VerifiedStorageResultV1::verify_observation(
            operation_id,
            record.request_digest,
            catalog,
            observed,
            observed_object_guid,
            transition.result_binding(),
            observation_digest,
        )?;
        self.validate_verified_result(&record, &verified)?;

        let result = self.committed_result(&verified)?;
        record.phase = DurableStoragePhase::Committed;
        record.result = Some(result);
        self.publish_with(record, transition.records())?;
        self.catalog_transitions.install_transition(transition);
        Ok(result)
    }

    fn validate_verified_result(
        &self,
        record: &DurableRecord,
        verified: &VerifiedStorageResultV1,
    ) -> Result<(), StorageStateError> {
        let latest_generation = latest_generation(&self.records);
        if verified.operation_id != record.operation_id
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
            Err(StorageStateError::InvalidTransition)
        } else {
            Ok(())
        }
    }

    fn committed_result(
        &self,
        verified: &VerifiedStorageResultV1,
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        committed_result_with_key(&self.key, verified)
    }

    fn preflight_effect_capacity(&self, prepared: &DurableRecord) -> Result<(), StorageStateError> {
        let mut ambiguous = prepared.clone();
        ambiguous.phase = DurableStoragePhase::Ambiguous;
        let ambiguous_transaction = JournalTransaction::new(
            transaction_id(prepared.operation_id, DurableStoragePhase::Ambiguous),
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                prepared.operation_id.to_vec(),
                encode_record(&ambiguous, &self.key)?,
            )],
        )?;

        let result_catalog = CatalogBindingV1::from_publisher(
            prepared
                .catalog
                .generation()
                .checked_add(1)
                .ok_or(StorageStateError::InvalidValue)?,
            ObjectDigest::from_bytes([u8::MAX; 32]),
        )
        .map_err(|_| StorageStateError::InvalidValue)?;
        let mut committed = prepared.clone();
        committed.phase = DurableStoragePhase::Committed;
        committed.result = Some(CommittedStorageResultV1 {
            operation_id: prepared.operation_id,
            catalog: result_catalog,
            result_digest: ObjectDigest::from_bytes([u8::MAX; 32]),
            storage_handle: Some([u8::MAX; 32]),
            immutable_version_handle: Some([u8::MAX; 32]),
            object_guid: Some(u64::MAX),
        });
        let mut completion_records = self
            .catalog_transitions
            .effect_capacity_records(prepared.operation_id)?;
        completion_records.push(JournalRecord::put(
            RecordNamespace::Operation,
            prepared.operation_id.to_vec(),
            encode_record(&committed, &self.key)?,
        ));
        let completion_transaction = JournalTransaction::new(
            transaction_id(prepared.operation_id, DurableStoragePhase::Committed),
            completion_records,
        )?;

        self.journal
            .preflight_transactions(&[ambiguous_transaction, completion_transaction])?;
        Ok(())
    }

    fn exact_current(
        &self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
    ) -> Result<&DurableRecord, StorageStateError> {
        self.ensure_authority_readable()?;
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
        self.commit_journal(&transaction)?;
        self.records.insert(record.operation_id, record);
        Ok(())
    }

    fn commit_journal(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<(), StorageStateError> {
        let result = self.journal.commit(transaction);
        #[cfg(test)]
        let result = result.and_then(|commit| {
            if std::mem::take(&mut self.fail_after_next_journal_commit) {
                // Model an error returned after the commit reached durable
                // storage, before callers update their materialized cache.
                Err(aos_sandbox::JournalError::Io(std::io::Error::other(
                    "injected failure after durable journal commit",
                )))
            } else {
                Ok(commit)
            }
        });
        if let Err(error) = result {
            // An append or sync error may have reached durable storage even
            // when the caller received failure. Cached records cannot remain
            // an authority source until protected reopen replays the prefix.
            self.commit_failed = true;
            return Err(error.into());
        }
        Ok(())
    }

    pub(crate) fn ensure_authority_readable(&self) -> Result<(), StorageStateError> {
        if self.commit_failed {
            Err(aos_sandbox::JournalError::Poisoned.into())
        } else {
            Ok(())
        }
    }
}

fn committed_result_with_key(
    key: &StorageStateKey,
    verified: &VerifiedStorageResultV1,
) -> Result<CommittedStorageResultV1, StorageStateError> {
    let (storage_handle, immutable_version_handle, object_guid) = match verified.resource_identity {
        VerifiedResourceIdentity::MintWorkspace { object_guid } => (
            Some(mint_resource_handle(key, 1, verified, object_guid)?),
            None,
            Some(object_guid),
        ),
        VerifiedResourceIdentity::MintVersion {
            storage_handle,
            object_guid,
        } => (
            Some(storage_handle),
            Some(mint_resource_handle(key, 2, verified, object_guid)?),
            Some(object_guid),
        ),
        VerifiedResourceIdentity::Existing {
            storage_handle,
            immutable_version_handle,
            object_guid,
        } => (Some(storage_handle), immutable_version_handle, object_guid),
    };

    Ok(CommittedStorageResultV1 {
        operation_id: verified.operation_id,
        catalog: verified.result_catalog,
        result_digest: verified.result_digest,
        storage_handle,
        immutable_version_handle,
        object_guid,
    })
}

fn load_publication_intents(
    journal: &Journal,
    key: &StorageStateKey,
) -> Result<BTreeMap<[u8; 16], StorageWorkspacePublicationIntentV1>, StorageStateError> {
    let mut intents = BTreeMap::new();
    for (record_key, bytes) in journal.records(RecordNamespace::StorageWorkspacePublicationIntent) {
        let operation_id: [u8; 16] = record_key
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let intent = decode_publication_intent(key, record_key, bytes)?;
        if intent.operation_id() != operation_id || intents.insert(operation_id, intent).is_some() {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    Ok(intents)
}

fn validate_publication_intent_set(
    records: &BTreeMap<[u8; 16], DurableRecord>,
    intents: &BTreeMap<[u8; 16], StorageWorkspacePublicationIntentV1>,
) -> Result<(), StorageStateError> {
    let mut ranges = Vec::with_capacity(intents.len());
    for (operation_id, intent) in intents {
        let record = records
            .get(operation_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(&record.catalog_bytes)
            .map_err(|_| StorageStateError::CorruptRecord)?;
        if !requires_workspace_publication(catalog.plan())
            || intent.request_catalog() != record.catalog
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        let end = intent
            .identity_range_start()
            .checked_add(intent.identity_range_size())
            .ok_or(StorageStateError::CorruptRecord)?;
        ranges.push((intent.identity_range_start(), end));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(StorageStateError::AuthorityLinkMismatch);
    }
    Ok(())
}

fn requires_workspace_publication(plan: &CatalogPlanV1) -> bool {
    matches!(
        plan,
        CatalogPlanV1::CreateWorkspace { .. } | CatalogPlanV1::Clone { .. }
    )
}

fn publication_intent_record(
    key: &StorageStateKey,
    intent: &StorageWorkspacePublicationIntentV1,
) -> Result<JournalRecord, StorageStateError> {
    let record_key = intent.operation_id().to_vec();
    let media_type = intent.root_image().media_type().as_str().as_bytes();
    let media_length =
        u16::try_from(media_type.len()).map_err(|_| StorageStateError::InvalidValue)?;
    let mut bytes = Vec::with_capacity(196 + media_type.len());
    bytes.extend_from_slice(PUBLICATION_INTENT_MAGIC);
    bytes.extend_from_slice(&PUBLICATION_INTENT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&key.key_id);
    bytes.extend_from_slice(&intent.operation_id());
    bytes.extend_from_slice(&intent.request_catalog().generation().to_be_bytes());
    bytes.extend_from_slice(intent.request_catalog().digest().as_bytes());
    bytes.extend_from_slice(intent.assignment_digest().as_bytes());
    bytes.extend_from_slice(&media_length.to_be_bytes());
    bytes.extend_from_slice(media_type);
    bytes.extend_from_slice(intent.root_image().digest().as_bytes());
    bytes.extend_from_slice(&intent.root_image().encoded_size().to_be_bytes());
    bytes.extend_from_slice(&intent.identity_range_start().to_be_bytes());
    bytes.extend_from_slice(&intent.identity_range_size().to_be_bytes());
    let tag = publication_intent_tag(key, &record_key, &bytes)?;
    bytes.extend_from_slice(&tag);
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(StorageStateError::InvalidValue);
    }
    Ok(JournalRecord::put(
        RecordNamespace::StorageWorkspacePublicationIntent,
        record_key,
        bytes,
    ))
}

fn decode_publication_intent(
    key: &StorageStateKey,
    record_key: &[u8],
    bytes: &[u8],
) -> Result<StorageWorkspacePublicationIntentV1, StorageStateError> {
    if bytes.len() > MAXIMUM_RECORD_BYTES || bytes.len() < 197 {
        return Err(StorageStateError::CorruptRecord);
    }
    let payload_length = bytes
        .len()
        .checked_sub(MAC_BYTES)
        .ok_or(StorageStateError::CorruptRecord)?;
    publication_intent_mac(key, record_key, &bytes[..payload_length])?
        .verify_slice(&bytes[payload_length..])
        .map_err(|_| StorageStateError::CorruptRecord)?;

    let mut decoder = Cursor::new(&bytes[..payload_length]);
    if decoder.take(8)? != PUBLICATION_INTENT_MAGIC
        || decoder.u16()? != PUBLICATION_INTENT_VERSION
        || decoder.array::<16>()? != key.key_id
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let operation_id = decoder.array::<16>()?;
    let request_catalog = CatalogBindingV1::from_publisher(
        decoder.u64()?,
        ObjectDigest::from_bytes(decoder.array::<32>()?),
    )
    .map_err(|_| StorageStateError::CorruptRecord)?;
    let assignment_digest = ObjectDigest::from_bytes(decoder.array::<32>()?);
    let media_length = usize::from(decoder.u16()?);
    let media_type = std::str::from_utf8(decoder.take(media_length)?)
        .map_err(|_| StorageStateError::CorruptRecord)?;
    let root_image = ObjectDescriptor::new(
        MediaType::new(media_type.to_owned()).map_err(|_| StorageStateError::CorruptRecord)?,
        ObjectDigest::from_bytes(decoder.array::<32>()?),
        decoder.u64()?,
    );
    let identity_range_start = decoder.u32()?;
    let identity_range_size = decoder.u32()?;
    if decoder.remaining() != 0 {
        return Err(StorageStateError::CorruptRecord);
    }
    StorageWorkspacePublicationIntentV1::from_authenticated_parts(
        operation_id,
        request_catalog,
        assignment_digest,
        root_image,
        identity_range_start,
        identity_range_size,
    )
    .map_err(|_| StorageStateError::CorruptRecord)
}

fn publication_intent_tag(
    key: &StorageStateKey,
    record_key: &[u8],
    payload: &[u8],
) -> Result<[u8; 32], StorageStateError> {
    Ok(publication_intent_mac(key, record_key, payload)?
        .finalize()
        .into_bytes()
        .into())
}

fn publication_intent_mac(
    key: &StorageStateKey,
    record_key: &[u8],
    payload: &[u8],
) -> Result<HmacSha256, StorageStateError> {
    let mut mac =
        HmacSha256::new_from_slice(&key.secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(PUBLICATION_INTENT_DOMAIN);
    mac.update(&[RecordNamespace::StorageWorkspacePublicationIntent as u8]);
    mac.update(
        &u32::try_from(record_key.len())
            .map_err(|_| StorageStateError::InvalidValue)?
            .to_be_bytes(),
    );
    mac.update(record_key);
    mac.update(payload);
    Ok(mac)
}

fn load_runtime_configuration(
    journal: &Journal,
    key: &StorageStateKey,
) -> Result<Option<ObjectDigest>, StorageStateError> {
    let mut records = journal.records(RecordNamespace::StorageRuntimeConfiguration);
    let Some((record_key, bytes)) = records.next() else {
        return Ok(None);
    };
    if record_key != RUNTIME_CONFIGURATION_KEY || records.next().is_some() {
        return Err(StorageStateError::CorruptRecord);
    }
    decode_runtime_configuration(key, bytes).map(Some)
}

fn runtime_configuration_record(
    key: &StorageStateKey,
    binding: ObjectDigest,
) -> Result<JournalRecord, StorageStateError> {
    if binding.as_bytes() == &[0; 32] {
        return Err(StorageStateError::InvalidValue);
    }
    let mut bytes = Vec::with_capacity(90);
    bytes.extend_from_slice(RUNTIME_CONFIGURATION_MAGIC);
    bytes.extend_from_slice(&RUNTIME_CONFIGURATION_VERSION.to_be_bytes());
    bytes.extend_from_slice(&key.key_id);
    bytes.extend_from_slice(binding.as_bytes());
    let tag = runtime_configuration_tag(key, &bytes)?;
    bytes.extend_from_slice(&tag);
    Ok(JournalRecord::put(
        RecordNamespace::StorageRuntimeConfiguration,
        RUNTIME_CONFIGURATION_KEY.to_vec(),
        bytes,
    ))
}

fn decode_runtime_configuration(
    key: &StorageStateKey,
    bytes: &[u8],
) -> Result<ObjectDigest, StorageStateError> {
    if bytes.len() != 90
        || &bytes[..8] != RUNTIME_CONFIGURATION_MAGIC
        || u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| StorageStateError::CorruptRecord)?,
        ) != RUNTIME_CONFIGURATION_VERSION
        || bytes[10..26] != key.key_id
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let payload = &bytes[..58];
    runtime_configuration_mac(key, payload)?
        .verify_slice(&bytes[58..])
        .map_err(|_| StorageStateError::CorruptRecord)?;
    let binding = ObjectDigest::from_bytes(
        bytes[26..58]
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?,
    );
    if binding.as_bytes() == &[0; 32] {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(binding)
}

fn runtime_configuration_tag(
    key: &StorageStateKey,
    payload: &[u8],
) -> Result<[u8; 32], StorageStateError> {
    let mac = runtime_configuration_mac(key, payload)?;
    Ok(mac.finalize().into_bytes().into())
}

fn runtime_configuration_mac(
    key: &StorageStateKey,
    payload: &[u8],
) -> Result<HmacSha256, StorageStateError> {
    let mut mac =
        HmacSha256::new_from_slice(&key.secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(RUNTIME_CONFIGURATION_DOMAIN);
    mac.update(&[RecordNamespace::StorageRuntimeConfiguration as u8]);
    mac.update(&(RUNTIME_CONFIGURATION_KEY.len() as u32).to_be_bytes());
    mac.update(RUNTIME_CONFIGURATION_KEY);
    mac.update(payload);
    Ok(mac)
}

fn mint_resource_handle(
    key: &StorageStateKey,
    kind: u8,
    verified: &VerifiedStorageResultV1,
    object_guid: u64,
) -> Result<[u8; 32], StorageStateError> {
    let mut mac =
        HmacSha256::new_from_slice(&key.secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(RESOURCE_HANDLE_DOMAIN);
    mac.update(&key.key_id);
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

fn recovery_entry(record: &DurableRecord) -> StorageRecoveryEntry {
    StorageRecoveryEntry {
        operation_id: record.operation_id,
        sandbox_id: record.sandbox_id,
        request_id: record.request_id,
        request_digest: record.request_digest,
        phase: record.phase,
        mutation_digest: record.mutation_digest,
        catalog: record.catalog,
    }
}

const fn journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 512 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_JOURNAL_RECORD_BYTES,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 6,
        maximum_transaction_bytes: MAXIMUM_JOURNAL_RECORD_BYTES * 6,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: MAXIMUM_JOURNAL_RECORD_BYTES
            * (MAXIMUM_OPERATIONS * MATERIALIZED_RECORDS_PER_OPERATION
                + GLOBAL_MATERIALIZED_RECORDS),
        maximum_materialized_records: MAXIMUM_OPERATIONS * MATERIALIZED_RECORDS_PER_OPERATION
            + GLOBAL_MATERIALIZED_RECORDS,
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
    encode_record_version(record, key, record.format_version)
}

fn encode_record_version(
    record: &DurableRecord,
    key: &StorageStateKey,
    version: u16,
) -> Result<Vec<u8>, StorageStateError> {
    if !matches!(version, LEGACY_VERSION | IDENTITY_VERSION | VERSION) {
        return Err(StorageStateError::CorruptRecord);
    }
    let result_len = if record.result.is_some() {
        if version >= IDENTITY_VERSION {
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
        if version >= IDENTITY_VERSION {
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
    if !matches!(version, LEGACY_VERSION | IDENTITY_VERSION | VERSION) {
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
        let identity = if version >= IDENTITY_VERSION {
            decode_result_identity(&mut cursor)?
        } else {
            DecodedResultIdentity {
                storage_handle: None,
                immutable_version_handle: None,
                object_guid: None,
            }
        };
        Some(CommittedStorageResultV1 {
            operation_id,
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
        format_version: version,
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
    use aos_sandbox_core::PortableMediaType;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        ActiveHoldEvidence, CatalogPlanV1, HoldId, ManagedDatasetRoot, PlannedDataset,
        PlannedSnapshot, ProjectAncestorPolicyV1, ReservationPolicy, ResolvedDataset,
        ResolvedSnapshot, StorageDomainsV1, StorageOperation, WorkspaceSpacePolicyV1,
        ZfsTransaction,
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
        catalog_with_physical_identity(generation, destination_name, 10, 15)
    }

    fn publication_intent(
        operation_id: [u8; 16],
        catalog: &ResolvedCatalogCommitmentV1,
        marker: u8,
    ) -> StorageWorkspacePublicationIntentV1 {
        publication_intent_at(
            operation_id,
            catalog,
            marker,
            u32::from(marker) * 65_536,
            65_536,
        )
    }

    fn publication_intent_at(
        operation_id: [u8; 16],
        catalog: &ResolvedCatalogCommitmentV1,
        marker: u8,
        range_start: u32,
        range_size: u32,
    ) -> StorageWorkspacePublicationIntentV1 {
        StorageWorkspacePublicationIntentV1::from_authenticated_parts(
            operation_id,
            catalog.binding(),
            digest(marker),
            ObjectDescriptor::new(
                MediaType::new(PortableMediaType::View.as_str().to_owned()).unwrap(),
                digest(marker.wrapping_add(1)),
                u64::from(marker) + 1,
            ),
            range_start,
            range_size,
        )
        .unwrap()
    }

    fn catalog_with_physical_identity(
        generation: u64,
        destination_name: &str,
        root_guid: u64,
        ancestor_guid: u64,
    ) -> ResolvedCatalogCommitmentV1 {
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", root_guid).unwrap();
        let ancestor_dataset = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project",
            ancestor_guid,
            [1; 32],
            domains(),
        )
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

    fn destroy_dataset_catalog(
        generation: u64,
        name: &str,
        guid: u64,
        storage_handle: [u8; 32],
    ) -> ResolvedCatalogCommitmentV1 {
        let dataset = ResolvedDataset::from_catalog(
            ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap(),
            name,
            guid,
            storage_handle,
            domains(),
        )
        .unwrap();
        ResolvedCatalogCommitmentV1::new(
            generation,
            domains(),
            CatalogPlanV1::DestroyDataset { dataset },
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

    fn initialize(store: &mut StorageTransactionStore, catalog: &ResolvedCatalogCommitmentV1) {
        store
            .initialize_catalog_from_protected_snapshot(
                catalog.generation() - 1,
                std::slice::from_ref(catalog),
            )
            .unwrap();
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
    fn bootstrap_only_head_participates_in_the_rollback_anchor() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        {
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            assert_eq!(
                store
                    .initialize_catalog_from_protected_snapshot(6, &[catalog])
                    .unwrap()
                    .generation(),
                6
            );
        }

        let equal = StorageTransactionStore::open_for_test(directory.path(), key(1), 6).unwrap();
        assert_eq!(equal.recovery_entries().unwrap().count(), 0);
        drop(equal);
        assert!(matches!(
            StorageTransactionStore::open_for_test(directory.path(), key(1), 7),
            Err(StorageStateError::Rollback)
        ));
    }

    #[test]
    fn runtime_open_initializes_only_unused_state_at_a_valid_floor() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let configuration_binding = digest(93);

        assert!(matches!(
            StorageTransactionStore::open_for_test(directory.path(), key(1), 6),
            Err(StorageStateError::Rollback)
        ));

        let initialized = StorageTransactionStore::open_runtime_for_test(
            directory.path(),
            key(1),
            5,
            configuration_binding,
            6,
            std::slice::from_ref(&catalog),
        )
        .unwrap();
        assert_eq!(
            initialized
                .validate_runtime_restart(configuration_binding, 6, std::slice::from_ref(&catalog),)
                .unwrap()
                .generation(),
            6
        );
        drop(initialized);

        assert!(matches!(
            StorageTransactionStore::open_runtime_for_test(
                directory.path(),
                key(1),
                7,
                configuration_binding,
                6,
                std::slice::from_ref(&catalog),
            ),
            Err(StorageStateError::Rollback)
        ));
    }

    #[test]
    fn runtime_open_rejects_a_new_genesis_below_the_protected_floor() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let configuration_binding = digest(94);

        assert!(matches!(
            StorageTransactionStore::open_runtime_for_test(
                directory.path(),
                key(1),
                7,
                configuration_binding,
                6,
                std::slice::from_ref(&catalog),
            ),
            Err(StorageStateError::Rollback)
        ));

        let initialized = StorageTransactionStore::open_runtime_for_test(
            directory.path(),
            key(1),
            6,
            configuration_binding,
            6,
            std::slice::from_ref(&catalog),
        )
        .unwrap();
        assert!(
            initialized
                .validate_runtime_restart(configuration_binding, 6, std::slice::from_ref(&catalog),)
                .is_ok()
        );
    }

    #[test]
    fn runtime_open_never_bootstraps_authority_only_or_deleted_history() {
        for delete_authority in [false, true] {
            let directory = TempDir::new().unwrap();
            let catalog = catalog(7, "tank/aos/project/work");
            let configuration_binding = digest(101);
            {
                let mut store =
                    StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
                store
                    .commit_journal(
                        &JournalTransaction::new(
                            [102; 16],
                            vec![JournalRecord::put(
                                RecordNamespace::DesiredState,
                                vec![103; 16],
                                b"retained-authority".to_vec(),
                            )],
                        )
                        .unwrap(),
                    )
                    .unwrap();
                if delete_authority {
                    store
                        .commit_journal(
                            &JournalTransaction::new(
                                [104; 16],
                                vec![JournalRecord::delete(
                                    RecordNamespace::DesiredState,
                                    vec![103; 16],
                                )],
                            )
                            .unwrap(),
                        )
                        .unwrap();
                }
            }

            assert!(matches!(
                StorageTransactionStore::open_runtime_for_test(
                    directory.path(),
                    key(1),
                    6,
                    configuration_binding,
                    6,
                    std::slice::from_ref(&catalog),
                ),
                Err(StorageStateError::Rollback)
            ));
        }
    }

    #[test]
    fn runtime_restart_binds_configuration_and_genesis_while_the_floor_advances() {
        let directory = TempDir::new().unwrap();
        let genesis_catalog = catalog(7, "tank/aos/project/work");
        let equivalent_planned_destination = catalog(7, "tank/aos/project/substituted");
        let substituted_genesis =
            catalog_with_physical_identity(7, "tank/aos/project/work", 12, 15);
        let configuration_binding = digest(95);
        let operation_id = [96; 16];
        let request_digest = digest(97);

        let result = {
            let mut store = StorageTransactionStore::open_runtime_for_test(
                directory.path(),
                key(1),
                6,
                configuration_binding,
                6,
                std::slice::from_ref(&genesis_catalog),
            )
            .unwrap();
            assert!(matches!(
                store.validate_runtime_restart(
                    digest(98),
                    6,
                    std::slice::from_ref(&genesis_catalog),
                ),
                Err(StorageStateError::AuthorityLinkMismatch)
            ));
            assert!(matches!(
                store.validate_runtime_restart(
                    configuration_binding,
                    6,
                    std::slice::from_ref(&substituted_genesis),
                ),
                Err(StorageStateError::AuthorityLinkMismatch)
            ));
            assert!(
                store
                    .validate_runtime_restart(
                        configuration_binding,
                        6,
                        std::slice::from_ref(&equivalent_planned_destination),
                    )
                    .is_ok()
            );

            let BeginStorageTransaction::Prepared { mutation_digest } = store
                .begin(operation_id, request_digest, &genesis_catalog)
                .unwrap()
            else {
                panic!("runtime fixture did not prepare the physical transition")
            };
            store
                .mark_mutation_ambiguous(operation_id, mutation_digest)
                .unwrap();
            store
                .commit_observed(
                    operation_id,
                    mutation_digest,
                    &genesis_catalog,
                    &genesis_catalog.plan().postcondition(),
                    Some(99),
                    digest(100),
                )
                .unwrap()
        };
        assert_eq!(result.catalog().generation(), 8);

        let restarted = StorageTransactionStore::open_runtime_for_test(
            directory.path(),
            key(1),
            8,
            configuration_binding,
            6,
            std::slice::from_ref(&genesis_catalog),
        )
        .unwrap();
        assert!(
            restarted
                .validate_runtime_restart(
                    configuration_binding,
                    6,
                    std::slice::from_ref(&genesis_catalog),
                )
                .is_ok()
        );
        drop(restarted);

        assert!(matches!(
            StorageTransactionStore::open_runtime_for_test(
                directory.path(),
                key(1),
                9,
                configuration_binding,
                6,
                std::slice::from_ref(&genesis_catalog),
            ),
            Err(StorageStateError::Rollback)
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
            initialize(&mut store, &catalog);
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
        let operation_fence = b"sealed-storage-operation-fence".to_vec();
        {
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            initialize(&mut store, &catalog);
            assert!(matches!(
                store
                    .begin_authorized_with_publication(
                        [31; 16],
                        digest(32),
                        &catalog,
                        sandbox_id,
                        request_id,
                        fence.clone(),
                        intent.clone(),
                        operation_fence.clone(),
                        Some(publication_intent([31; 16], &catalog, 35)),
                    )
                    .unwrap(),
                BeginStorageTransaction::Prepared { .. }
            ));
        }

        let store = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(
            store
                .authority_record(RecordNamespace::DesiredState, &sandbox_id)
                .unwrap(),
            Some(fence.as_slice())
        );
        assert_eq!(
            store
                .authority_record(RecordNamespace::Effect, &request_id)
                .unwrap(),
            Some(intent.as_slice())
        );
        assert_eq!(
            store
                .authority_record(RecordNamespace::AuthorityPublication, &[31; 16])
                .unwrap(),
            Some(operation_fence.as_slice())
        );
        assert_eq!(
            store.phase([31; 16]).unwrap(),
            Some(DurableStoragePhase::Prepared)
        );
        assert_eq!(
            store.workspace_publication_intent([31; 16]).unwrap(),
            Some(&publication_intent([31; 16], &catalog, 35))
        );
    }

    #[test]
    fn publication_intent_codec_rejects_location_mac_and_schema_substitutions() {
        let state_key = key(1);
        let catalog = catalog(7, "tank/aos/project/work");
        let intent = publication_intent([31; 16], &catalog, 35);
        let encoded = publication_intent_record(&state_key, &intent).unwrap();
        let record_key = encoded.key();
        let bytes = encoded.value().unwrap();
        assert_eq!(
            decode_publication_intent(&state_key, record_key, bytes).unwrap(),
            intent
        );
        assert!(matches!(
            decode_publication_intent(&state_key, &[32; 16], bytes),
            Err(StorageStateError::CorruptRecord)
        ));

        let mut wrong_mac = bytes.to_vec();
        *wrong_mac.last_mut().unwrap() ^= 0xff;
        assert!(matches!(
            decode_publication_intent(&state_key, record_key, &wrong_mac),
            Err(StorageStateError::CorruptRecord)
        ));

        let retag = |payload: &mut Vec<u8>| {
            let tag = publication_intent_tag(&state_key, record_key, payload).unwrap();
            payload.extend_from_slice(&tag);
        };
        let payload_length = bytes.len() - MAC_BYTES;

        let mut unknown_version = bytes[..payload_length].to_vec();
        unknown_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
        retag(&mut unknown_version);
        assert!(matches!(
            decode_publication_intent(&state_key, record_key, &unknown_version),
            Err(StorageStateError::CorruptRecord)
        ));

        let mut trailing = bytes[..payload_length].to_vec();
        trailing.push(0);
        retag(&mut trailing);
        assert!(matches!(
            decode_publication_intent(&state_key, record_key, &trailing),
            Err(StorageStateError::CorruptRecord)
        ));

        let media_start = 8 + 2 + 16 + 16 + 8 + 32 + 32 + 2;
        let mut invalid_descriptor = bytes[..payload_length].to_vec();
        invalid_descriptor[media_start] = b'A';
        retag(&mut invalid_descriptor);
        assert!(matches!(
            decode_publication_intent(&state_key, record_key, &invalid_descriptor),
            Err(StorageStateError::CorruptRecord)
        ));

        let mut invalid_range = bytes[..payload_length].to_vec();
        invalid_range[payload_length - 4..].copy_from_slice(&1_u32.to_be_bytes());
        retag(&mut invalid_range);
        assert!(matches!(
            decode_publication_intent(&state_key, record_key, &invalid_range),
            Err(StorageStateError::CorruptRecord)
        ));

        let mut invalid_range_start = bytes[..payload_length].to_vec();
        invalid_range_start[payload_length - 8..payload_length - 4]
            .copy_from_slice(&0_u32.to_be_bytes());
        retag(&mut invalid_range_start);
        assert!(matches!(
            decode_publication_intent(&state_key, record_key, &invalid_range_start),
            Err(StorageStateError::CorruptRecord)
        ));
    }

    #[test]
    fn publication_intent_replay_rejects_same_operation_substitution() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);
        let operation_id = [41; 16];
        let first = publication_intent(operation_id, &catalog, 42);
        let substituted = publication_intent(operation_id, &catalog, 43);
        let arguments = (
            operation_id,
            digest(44),
            &catalog,
            [45; 16],
            [46; 16],
            vec![1; 8],
            vec![2; 8],
            vec![3; 8],
        );

        assert!(matches!(
            store.begin_authorized_with_publication(
                arguments.0,
                arguments.1,
                arguments.2,
                arguments.3,
                arguments.4,
                arguments.5.clone(),
                arguments.6.clone(),
                arguments.7.clone(),
                Some(first),
            ),
            Ok(BeginStorageTransaction::Prepared { .. })
        ));
        assert!(matches!(
            store.begin_authorized_with_publication(
                arguments.0,
                arguments.1,
                arguments.2,
                arguments.3,
                arguments.4,
                arguments.5,
                arguments.6,
                arguments.7,
                Some(substituted),
            ),
            Err(StorageStateError::AuthorityLinkMismatch)
        ));
    }

    #[test]
    fn publication_intent_admission_rejects_overlaps_without_advancing_the_journal() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);
        let first_operation = [47; 16];
        let range_start = 47 * 65_536;
        let first = publication_intent_at(first_operation, &catalog, 48, range_start, 65_536);
        let prepare = |store: &mut StorageTransactionStore,
                       operation_id,
                       intent: StorageWorkspacePublicationIntentV1| {
            store.begin_authorized_with_publication(
                operation_id,
                digest(operation_id[0].wrapping_add(2)),
                &catalog,
                [operation_id[0].wrapping_add(3); 16],
                [operation_id[0].wrapping_add(4); 16],
                vec![1; 8],
                vec![2; 8],
                vec![3; 8],
                Some(intent),
            )
        };
        assert!(matches!(
            prepare(&mut store, first_operation, first.clone()),
            Ok(BeginStorageTransaction::Prepared { .. })
        ));
        let sequence = store.journal_sequence_for_test();
        assert!(matches!(
            prepare(&mut store, first_operation, first),
            Ok(BeginStorageTransaction::ObserveOnly { .. })
        ));
        assert_eq!(store.journal_sequence_for_test(), sequence);

        for (operation_id, candidate_start) in [
            ([48; 16], range_start),
            ([49; 16], range_start + 65_536 / 2),
        ] {
            let candidate = publication_intent_at(
                operation_id,
                &catalog,
                operation_id[0],
                candidate_start,
                65_536,
            );
            assert!(matches!(
                prepare(&mut store, operation_id, candidate),
                Err(StorageStateError::AuthorityLinkMismatch)
            ));
            assert_eq!(store.journal_sequence_for_test(), sequence);
        }
    }

    #[test]
    fn physical_workspace_projection_excludes_bootstrap_datasets() {
        let directory = TempDir::new().unwrap();
        let catalog = destroy_dataset_catalog(7, "tank/aos/project/source", 15, [9; 32]);
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);
        assert!(store.workspace_projection().unwrap().is_empty());

        let BeginStorageTransaction::Prepared { mutation_digest } =
            store.begin([51; 16], digest(52), &catalog).unwrap()
        else {
            panic!("bootstrap dataset destruction was not prepared")
        };
        store
            .mark_mutation_ambiguous([51; 16], mutation_digest)
            .unwrap();
        store
            .commit_observed(
                [51; 16],
                mutation_digest,
                &catalog,
                &catalog.plan().postcondition(),
                None,
                digest(53),
            )
            .unwrap();
        assert!(store.workspace_projection().unwrap().is_empty());
    }

    #[test]
    fn physical_workspace_projection_replaces_creation_with_exact_retirement() {
        let directory = TempDir::new().unwrap();
        let create = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &create);
        let create_operation = [61; 16];
        let BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin_authorized_with_publication(
                create_operation,
                digest(62),
                &create,
                [63; 16],
                [64; 16],
                vec![1; 8],
                vec![2; 8],
                vec![3; 8],
                Some(publication_intent(create_operation, &create, 65)),
            )
            .unwrap()
        else {
            panic!("managed workspace creation was not prepared")
        };
        store
            .mark_mutation_ambiguous(create_operation, mutation_digest)
            .unwrap();
        let creation = store
            .commit_observed(
                create_operation,
                mutation_digest,
                &create,
                &create.plan().postcondition(),
                Some(101),
                digest(66),
            )
            .unwrap();
        assert_eq!(
            store.workspace_projection().unwrap(),
            vec![StorageWorkspaceProjection::Active(creation)]
        );

        let destroy = destroy_dataset_catalog(
            9,
            "tank/aos/project/work",
            101,
            creation.storage_handle().unwrap(),
        );
        let destroy_operation = [67; 16];
        let BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin(destroy_operation, digest(68), &destroy)
            .unwrap()
        else {
            panic!("managed workspace destruction was not prepared")
        };
        store
            .mark_mutation_ambiguous(destroy_operation, mutation_digest)
            .unwrap();
        let retirement = store
            .commit_observed(
                destroy_operation,
                mutation_digest,
                &destroy,
                &destroy.plan().postcondition(),
                None,
                digest(69),
            )
            .unwrap();
        assert_eq!(
            store.workspace_projection().unwrap(),
            vec![StorageWorkspaceProjection::Retired {
                creation,
                retirement,
            }]
        );
    }

    #[test]
    fn effect_preflight_rejects_append_exhaustion_before_ambiguous() {
        let catalog = catalog(7, "tank/aos/project/work");
        let reference = TempDir::new().unwrap();
        let admitted_bytes = {
            let mut store =
                StorageTransactionStore::open_for_test(reference.path(), key(1), 0).unwrap();
            initialize(&mut store, &catalog);
            store
                .begin_authorized_with_publication(
                    [81; 16],
                    digest(82),
                    &catalog,
                    [83; 16],
                    [84; 16],
                    vec![1; 32],
                    vec![2; 32],
                    vec![3; 32],
                    Some(publication_intent([81; 16], &catalog, 85)),
                )
                .unwrap();
            fs::metadata(reference.path().join("storage-state.journal"))
                .unwrap()
                .len()
        };

        let directory = TempDir::new().unwrap();
        let limits = JournalLimits {
            maximum_journal_bytes: admitted_bytes,
            ..journal_limits()
        };
        let mut store =
            StorageTransactionStore::open_for_test_with_limits(directory.path(), key(1), 0, limits)
                .unwrap();
        initialize(&mut store, &catalog);
        let BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin_authorized_with_publication(
                [81; 16],
                digest(82),
                &catalog,
                [83; 16],
                [84; 16],
                vec![1; 32],
                vec![2; 32],
                vec![3; 32],
                Some(publication_intent([81; 16], &catalog, 85)),
            )
            .unwrap()
        else {
            panic!("bounded fixture did not admit the prepared intent")
        };

        assert!(matches!(
            store.mark_mutation_ambiguous([81; 16], mutation_digest),
            Err(StorageStateError::Journal(JournalError::JournalTooLarge))
        ));
        assert_eq!(
            store.phase([81; 16]).unwrap(),
            Some(DurableStoragePhase::Prepared)
        );
    }

    #[test]
    fn post_commit_failure_poisons_cache_and_reopen_recovers_durable_record() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);
        store.fail_after_next_journal_commit_for_test();

        assert!(matches!(
            store.begin([71; 16], digest(72), &catalog),
            Err(StorageStateError::Journal(JournalError::Io(_)))
        ));
        assert!(matches!(
            store.phase([71; 16]),
            Err(StorageStateError::Journal(JournalError::Poisoned))
        ));
        assert!(matches!(
            store.recovery_entries(),
            Err(StorageStateError::Journal(JournalError::Poisoned))
        ));
        assert!(matches!(
            store.authority_record(RecordNamespace::DesiredState, &[71; 16]),
            Err(StorageStateError::Journal(JournalError::Poisoned))
        ));
        drop(store);

        let reopened = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(
            reopened.phase([71; 16]).unwrap(),
            Some(DurableStoragePhase::Prepared)
        );
        assert_eq!(reopened.recovery_entries().unwrap().count(), 1);
    }

    #[test]
    fn materialized_budget_accounts_for_seven_rows_per_distinct_sandbox() {
        let directory = TempDir::new().unwrap();
        let first = catalog(7, "tank/aos/project/first");
        let second = catalog(9, "tank/aos/project/second");
        let third = catalog(11, "tank/aos/project/third");
        let limits = JournalLimits {
            maximum_materialized_records: 2 * MATERIALIZED_RECORDS_PER_OPERATION
                + GLOBAL_MATERIALIZED_RECORDS,
            ..journal_limits()
        };
        let mut store =
            StorageTransactionStore::open_for_test_with_limits(directory.path(), key(1), 0, limits)
                .unwrap();
        initialize(&mut store, &first);

        for (index, catalog) in [(1_u8, &first), (2, &second)] {
            let operation_id = [index; 16];
            let BeginStorageTransaction::Prepared { mutation_digest } = store
                .begin_authorized_with_publication(
                    operation_id,
                    digest(90 + index),
                    catalog,
                    [10 + index; 16],
                    [20 + index; 16],
                    vec![30 + index; 8],
                    vec![40 + index; 8],
                    vec![50 + index; 8],
                    Some(publication_intent(operation_id, catalog, 60 + index)),
                )
                .unwrap()
            else {
                panic!("distinct sandbox did not prepare")
            };
            store
                .mark_mutation_ambiguous(operation_id, mutation_digest)
                .unwrap();
            store
                .commit_observed(
                    operation_id,
                    mutation_digest,
                    catalog,
                    &catalog.plan().postcondition(),
                    Some(100 + u64::from(index)),
                    digest(60 + index),
                )
                .unwrap();
        }

        assert!(matches!(
            store.begin_authorized_with_publication(
                [3; 16],
                digest(93),
                &third,
                [13; 16],
                [23; 16],
                vec![33; 8],
                vec![43; 8],
                vec![53; 8],
                Some(publication_intent([3; 16], &third, 63)),
            ),
            Err(StorageStateError::Journal(JournalError::LimitExceeded(
                "materialized record count"
            )))
        ));
        assert!(matches!(
            store.phase([1; 16]),
            Err(StorageStateError::Journal(JournalError::Poisoned))
        ));
        assert!(matches!(
            store.recovery_entries(),
            Err(StorageStateError::Journal(JournalError::Poisoned))
        ));
        assert!(matches!(
            store.authority_record(RecordNamespace::DesiredState, &[11; 16]),
            Err(StorageStateError::Journal(JournalError::Poisoned))
        ));
        drop(store);

        let reopened =
            StorageTransactionStore::open_for_test_with_limits(directory.path(), key(1), 0, limits)
                .unwrap();
        assert_eq!(
            reopened.phase([1; 16]).unwrap(),
            Some(DurableStoragePhase::Committed)
        );
        assert_eq!(reopened.phase([3; 16]).unwrap(), None);
    }

    #[test]
    fn physical_catalog_chain_recovers_every_zfs_transition_kind() {
        let directory = TempDir::new().unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [1; 32], domains())
                .unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap();
        let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap();
        let workspace = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project/work",
            101,
            [31; 32],
            domains(),
        )
        .unwrap();
        let snapshot =
            ResolvedSnapshot::from_catalog(workspace.clone(), "revision-1", 201, [32; 32]).unwrap();
        let clone = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project/clone",
            301,
            [33; 32],
            domains(),
        )
        .unwrap();
        let hold_id = HoldId::from_bytes([34; 16]).unwrap();
        let catalogs = vec![
            ResolvedCatalogCommitmentV1::new(
                7,
                domains(),
                CatalogPlanV1::CreateWorkspace {
                    destination: PlannedDataset::from_catalog(
                        root.clone(),
                        workspace.name(),
                        domains(),
                    )
                    .unwrap(),
                    space,
                    ancestor: ancestor.clone(),
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new(
                9,
                domains(),
                CatalogPlanV1::Snapshot {
                    source: workspace.clone(),
                    destination: PlannedSnapshot::from_catalog(
                        workspace.clone(),
                        snapshot.component(),
                    )
                    .unwrap(),
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new(
                11,
                domains(),
                CatalogPlanV1::HoldSnapshot {
                    snapshot: snapshot.clone(),
                    hold_id,
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new(
                13,
                domains(),
                CatalogPlanV1::Clone {
                    source: Box::new(snapshot.clone()),
                    origin_hold: ActiveHoldEvidence::from_catalog(snapshot.guid(), hold_id)
                        .unwrap(),
                    destination: PlannedDataset::from_catalog(root, clone.name(), domains())
                        .unwrap(),
                    space,
                    ancestor: ancestor.clone(),
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new(
                15,
                domains(),
                CatalogPlanV1::SetQuota {
                    dataset: clone.clone(),
                    space: WorkspaceSpacePolicyV1::new(8192, ReservationPolicy::None).unwrap(),
                    ancestor: ancestor.clone(),
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new(
                17,
                domains(),
                CatalogPlanV1::DestroyDataset {
                    dataset: clone.clone(),
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new(
                19,
                domains(),
                CatalogPlanV1::ReleaseHold {
                    snapshot: snapshot.clone(),
                    hold_id,
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new(
                21,
                domains(),
                CatalogPlanV1::DestroySnapshot {
                    snapshot: snapshot.clone(),
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new(
                23,
                domains(),
                CatalogPlanV1::DestroyDataset { dataset: workspace },
            )
            .unwrap(),
        ];
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalogs[0]);

        for (index, catalog) in catalogs.iter().enumerate() {
            let operation_byte = u8::try_from(index + 1).unwrap();
            let operation_id = [operation_byte; 16];
            let BeginStorageTransaction::Prepared { mutation_digest } = store
                .begin(operation_id, digest(100 + operation_byte), catalog)
                .unwrap()
            else {
                panic!("lifecycle operation did not prepare")
            };
            store
                .mark_mutation_ambiguous(operation_id, mutation_digest)
                .unwrap();
            let object_guid = match catalog.plan() {
                CatalogPlanV1::CreateWorkspace { .. } => Some(101),
                CatalogPlanV1::Snapshot { .. }
                | CatalogPlanV1::HoldSnapshot { .. }
                | CatalogPlanV1::ReleaseHold { .. } => Some(201),
                CatalogPlanV1::Clone { .. } => Some(301),
                CatalogPlanV1::SetQuota { .. } => Some(301),
                _ => None,
            };
            if matches!(
                catalog.plan(),
                CatalogPlanV1::HoldSnapshot { .. }
                    | CatalogPlanV1::ReleaseHold { .. }
                    | CatalogPlanV1::SetQuota { .. }
            ) {
                assert!(matches!(
                    store.commit_observed(
                        operation_id,
                        mutation_digest,
                        catalog,
                        &catalog.plan().postcondition(),
                        object_guid.map(|guid| guid + 1),
                        digest(120 + operation_byte),
                    ),
                    Err(StorageStateError::InvalidTransition)
                ));
                assert_eq!(
                    store.phase(operation_id).unwrap(),
                    Some(DurableStoragePhase::Ambiguous)
                );
            }
            store
                .commit_observed(
                    operation_id,
                    mutation_digest,
                    catalog,
                    &catalog.plan().postcondition(),
                    object_guid,
                    digest(120 + operation_byte),
                )
                .unwrap_or_else(|error| panic!("lifecycle operation {index} failed: {error}"));
        }
        drop(store);

        let recovered =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 24).unwrap();
        assert_eq!(
            recovered.recovery_entries().unwrap().count(),
            catalogs.len()
        );
        for index in 1..=catalogs.len() {
            assert_eq!(
                recovered.phase([u8::try_from(index).unwrap(); 16]).unwrap(),
                Some(DurableStoragePhase::Committed)
            );
        }
    }

    #[test]
    fn unauthenticated_partial_intent_has_no_authority_cross_links() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);
        store.begin([35; 16], digest(36), &catalog).unwrap();
        assert!(
            store
                .authority_record(RecordNamespace::DesiredState, &[37; 16])
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .authority_record(RecordNamespace::Effect, &[38; 16])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn recovery_scan_surfaces_pending_work_without_live_readmission() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);
        store.begin([39; 16], digest(40), &catalog).unwrap();
        let entries = store.recovery_entries().unwrap().collect::<Vec<_>>();
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
        let next_catalog = catalog(9, "tank/aos/project/next");
        let program = program(&initial_catalog);
        let operation_id = [41; 16];
        let request_digest = digest(42);
        let expected = {
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            initialize(&mut store, &initial_catalog);
            let BeginStorageTransaction::Prepared { mutation_digest } = store
                .begin(operation_id, request_digest, &initial_catalog)
                .unwrap()
            else {
                panic!("new operation was not prepared")
            };
            store
                .mark_mutation_ambiguous(operation_id, mutation_digest)
                .unwrap();
            store
                .commit_observed(
                    operation_id,
                    mutation_digest,
                    &initial_catalog,
                    program.postcondition(),
                    Some(91),
                    digest(44),
                )
                .unwrap()
        };
        let mut recovered =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 7).unwrap();
        assert_eq!(expected.operation_id(), operation_id);
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
        initialize(&mut store, &catalog);
        let BeginStorageTransaction::Prepared { mutation_digest } =
            store.begin(operation_id, request_digest, &catalog).unwrap()
        else {
            panic!("new snapshot operation was not prepared")
        };
        store
            .mark_mutation_ambiguous(operation_id, mutation_digest)
            .unwrap();
        let result = store
            .commit_observed(
                operation_id,
                mutation_digest,
                &catalog,
                &catalog.plan().postcondition(),
                Some(91),
                digest(50),
            )
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
        initialize(&mut store, &original);
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
        initialize(&mut store, &original);
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
        let result = store
            .commit_observed(
                [61; 16],
                first_mutation,
                &original,
                &original.plan().postcondition(),
                Some(91),
                digest(67),
            )
            .unwrap();
        assert_eq!(result.catalog().generation(), 8);
        assert!(matches!(
            store.begin([63; 16], digest(64), &original),
            Err(StorageStateError::Rollback)
        ));
    }

    #[test]
    fn corruption_wrong_authentication_key_and_rollback_anchor_fail_closed() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        {
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            initialize(&mut store, &catalog);
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
