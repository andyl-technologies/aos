//! Durable, authenticated storage transaction state machine.
//!
//! One exclusively locked [`aos_sandbox::Journal`] remains owned for the
//! lifetime of [`StorageTransactionStore`]. Each state transition is an atomic,
//! checksummed journal transaction whose value is independently HMAC-authenticated.
//! A mutation must be marked [`DurableStoragePhase::Ambiguous`] before a future
//! helper may invoke ZFS. An expired or strictly superseded Prepared intent can
//! become an authenticated [`DurableStoragePhase::Aborted`] tombstone. Recovery
//! exposes ambiguous work only for re-observation; this module contains no API
//! that returns or reissues mutation argv.

#[allow(
    dead_code,
    reason = "held Repair guard awaits live Storage session and worker quiescence"
)]
mod repair_guard;
mod workspace_projection;

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, MediaType, NodeId,
    ObjectDescriptor, ObjectDigest, SandboxId,
};
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};

use crate::authorization::SealedStorageAdmission;
use crate::broker::FreshWorkspacePinAuthority;
use crate::catalog_transition::{
    CatalogReservation, PhysicalWorkspaceProjection, StorageCatalogTransitionProvider,
    VerifiedPhysicalCatalogSnapshotV1,
};
use crate::guest_root_attempt::GuestRootPublicationAttemptV1;
use crate::resolver::protected_catalog::{
    StorageResolverPolicyBindingV1, StorageResolverPolicyCatalogBindingV1,
};
use crate::snapshot_metadata::{CatalogCommitSupplementV1, CheckedSnapshotMetadataRecordV1};
use crate::workspace_catalog::{
    DurablePortableWorkspaceMetadataV1, StorageWorkspacePublicationIntentV1,
};
use crate::workspace_pin::{
    BeginWorkspacePinAttemptV1, MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE, WorkspaceDatasetObservationV1,
    WorkspacePinActionV1, WorkspacePinAttemptPhaseV1, WorkspacePinAttemptV1,
    WorkspacePinHostScopeV1, WorkspacePinObservationV1, WorkspacePinRecoveryDispositionV1,
    WorkspaceRootPinProofV1, attempt_record, derive_attempt_id, load_attempts,
};
use crate::workspace_repair::{
    StorageWorkspacePinRepairIntentV1, WorkspacePinRepairIntentPredecessorV1, load_repair_intents,
    repair_intent_record,
};
use crate::{CatalogBindingV1, CatalogPlanV1, PostconditionPolicyV1, ResolvedCatalogCommitmentV1};

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 8] = b"AOSSTX01";
const VERSION: u16 = 1;
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.storage.state.record.v1\0";
const MUTATION_DOMAIN: &[u8] = b"aos.sandbox.storage.mutation.v1\0";
const POSTCONDITION_DOMAIN: &[u8] = b"aos.sandbox.storage.postcondition.v1\0";
const RESOURCE_HANDLE_DOMAIN: &[u8] = b"aos.sandbox.storage.resource-handle.v1\0";
const HELD_SNAPSHOT_STATE_DOMAIN: &[u8] =
    b"aos.sandbox.storage.held-snapshot-materialized-state.v1\0";
const RUNTIME_CONFIGURATION_DOMAIN: &[u8] = b"aos.sandbox.storage.runtime-configuration.v1\0";
const RUNTIME_CONFIGURATION_MAGIC: &[u8; 8] = b"AOSSCFG1";
const RUNTIME_CONFIGURATION_VERSION: u16 = 1;
const RUNTIME_CONFIGURATION_KEY: &[u8] = b"current";
const RESOLVER_POLICY_FLOOR_DOMAIN: &[u8] = b"aos.sandbox.storage.resolver-policy-floor.v1\0";
const RESOLVER_POLICY_FLOOR_MAGIC: &[u8; 8] = b"AOSRPF01";
const RESOLVER_POLICY_FLOOR_VERSION: u16 = 1;
const RESOLVER_POLICY_FLOOR_KEY: &[u8] = b"current";
const PUBLICATION_INTENT_DOMAIN: &[u8] = b"aos.sandbox.storage.publication-intent.v1\0";
const PUBLICATION_INTENT_MAGIC: &[u8; 8] = b"AOSSPI01";
const PUBLICATION_INTENT_VERSION: u16 = 1;
const ATOMIC_SNAPSHOT_MAGIC: &[u8; 8] = b"AOSASR01";
const ATOMIC_SNAPSHOT_VERSION_V2: u16 = 2;
const ATOMIC_SNAPSHOT_VERSION_V3: u16 = 3;
const ATOMIC_SNAPSHOT_DOMAIN_V2: &[u8] = b"aos.sandbox.storage.atomic-snapshot-state.v1\0";
const ATOMIC_SNAPSHOT_DOMAIN_V3: &[u8] = b"aos.sandbox.storage.atomic-snapshot-state.v3\0";
const ATOMIC_SNAPSHOT_KEY_PREFIX: &[u8; 16] = b"atomic-snapshot/";
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024;
const MAXIMUM_PREPARATION_RECORD_BYTES: usize = 128 * 1024;
// The grouped program retains every selected source and destination name.
const MAXIMUM_ATOMIC_SNAPSHOT_RECORD_BYTES: usize = 600_000 + 256;
pub(crate) const MAXIMUM_WORKSPACE_PUBLICATION_INTENT_RECORD_BYTES: usize =
    MAXIMUM_PREPARATION_RECORD_BYTES;
const FIXED_PREFIX_BYTES: usize = 8 + 2 + 1 + 16 + 16 + 16 + 32 + 32 + 8 + 32 + 32 + 4;
const RESULT_BYTES: usize = 8 + 32 + 32 + 1 + 32 + 32 + 8;
const MAC_BYTES: usize = 32;
const RESULT_HAS_STORAGE_HANDLE: u8 = 1;
const RESULT_HAS_VERSION_HANDLE: u8 = 1 << 1;
const RESULT_HAS_OBJECT_GUID: u8 = 1 << 2;
const MAXIMUM_OPERATIONS: usize = 256;
const MATERIALIZED_RECORDS_PER_OPERATION: usize = 8;
const GLOBAL_MATERIALIZED_RECORDS: usize = 3;
const MAXIMUM_JOURNAL_RECORD_BYTES: usize = MAXIMUM_ATOMIC_SNAPSHOT_RECORD_BYTES;

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

    /// Authenticates one workspace-pin record using its embedded exact location.
    ///
    /// The untrusted record's attempt ID is covered both by the body MAC and by
    /// the record-location domain. The returned value has also passed complete
    /// canonical and semantic validation.
    pub(crate) fn open_workspace_pin_attempt(
        &self,
        bytes: &[u8],
    ) -> Result<WorkspacePinAttemptV1, StorageStateError> {
        crate::workspace_pin::decode_attempt(bytes, self.key_id, &self.secret)
    }

    /// Authenticates one retained workspace-pin repair intent.
    pub(crate) fn open_workspace_pin_repair_intent(
        &self,
        bytes: &[u8],
    ) -> Result<StorageWorkspacePinRepairIntentV1, StorageStateError> {
        crate::workspace_repair::decode_intent(bytes, self.key_id, &self.secret)
    }

    /// Seals an exact guest-root attempt at its effect-operation location.
    pub(crate) fn seal_guest_root_publication_attempt(
        &self,
        attempt: crate::guest_root_attempt::GuestRootPublicationAttemptV1,
    ) -> Result<Vec<u8>, StorageStateError> {
        crate::guest_root_attempt::encode_attempt(attempt, self.key_id, &self.secret)
    }

    /// Authenticates a guest-root attempt against its journal key.
    pub(crate) fn open_guest_root_publication_attempt(
        &self,
        effect_operation: [u8; 16],
        bytes: &[u8],
    ) -> Result<crate::guest_root_attempt::GuestRootPublicationAttemptV1, StorageStateError> {
        crate::guest_root_attempt::decode_attempt(
            bytes,
            effect_operation,
            self.key_id,
            &self.secret,
        )
    }

    /// Authenticates one workspace publication intent at its exact location.
    pub(crate) fn open_workspace_publication_intent(
        &self,
        operation_id: [u8; 16],
        bytes: &[u8],
    ) -> Result<StorageWorkspacePublicationIntentV1, StorageStateError> {
        decode_publication_intent(self, &operation_id, bytes)
    }

    #[cfg(test)]
    pub(crate) fn retag_workspace_publication_intent_for_test(
        &self,
        bytes: &mut [u8],
    ) -> Result<(), StorageStateError> {
        let payload_length = bytes
            .len()
            .checked_sub(MAC_BYTES)
            .ok_or(StorageStateError::CorruptRecord)?;
        let operation_id: [u8; 16] = bytes
            .get(26..42)
            .and_then(|value| value.try_into().ok())
            .ok_or(StorageStateError::CorruptRecord)?;
        let tag = publication_intent_tag(self, &operation_id, &bytes[..payload_length])?;
        bytes[payload_length..].copy_from_slice(&tag);
        Ok(())
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
    /// The inactive intent was durably retired before any mutation was attempted.
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomicDatasetSnapshotPhaseV1 {
    Prepared = 1,
    Ambiguous = 2,
    Committed = 3,
}

#[derive(Clone)]
struct AtomicDatasetSnapshotRecordV1 {
    phase: AtomicDatasetSnapshotPhaseV1,
    program: crate::DormantAtomicDatasetSnapshotV1,
    observation: Option<ObjectDigest>,
    sandbox_id: [u8; 16],
    request_id: [u8; 16],
    semantic_digest: ObjectDigest,
    transport_digest: ObjectDigest,
    post_head: Option<CatalogBindingV1>,
}

pub(crate) struct AtomicDatasetSnapshotInventoryV1 {
    phase: AtomicDatasetSnapshotPhaseV1,
    program: crate::DormantAtomicDatasetSnapshotV1,
    observation: Option<ObjectDigest>,
    sandbox_id: [u8; 16],
    request_id: [u8; 16],
    semantic_digest: ObjectDigest,
    transport_digest: ObjectDigest,
    post_head: Option<CatalogBindingV1>,
    member_guids: Option<Vec<u64>>,
}

impl AtomicDatasetSnapshotInventoryV1 {
    pub(crate) const fn phase(&self) -> AtomicDatasetSnapshotPhaseV1 {
        self.phase
    }

    pub(crate) const fn program(&self) -> &crate::DormantAtomicDatasetSnapshotV1 {
        &self.program
    }

    pub(crate) const fn sandbox_id(&self) -> [u8; 16] {
        self.sandbox_id
    }

    pub(crate) const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub(crate) const fn semantic_digest(&self) -> ObjectDigest {
        self.semantic_digest
    }

    pub(crate) const fn transport_digest(&self) -> ObjectDigest {
        self.transport_digest
    }

    pub(crate) const fn observation(&self) -> Option<ObjectDigest> {
        self.observation
    }

    /// Returns the protected post-catalog head committed with the group result.
    pub(crate) const fn post_head(&self) -> Option<CatalogBindingV1> {
        self.post_head
    }

    pub(crate) fn member_guids(&self) -> Option<&[u64]> {
        self.member_guids.as_deref()
    }
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
    /// The exact request expired or was superseded and retired before mutation.
    Aborted {
        /// Deterministic identity of the retired mutation intent.
        mutation_digest: ObjectDigest,
    },
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

/// Selects the exact authenticated state preceding a workspace-pin repair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkspacePinRepairPredecessorV1 {
    /// A committed active creation has never published a pin attempt.
    MissingInitial {
        creation: Box<CommittedStorageResultV1>,
        creation_record_digest: ObjectDigest,
        physical_catalog_head: CatalogBindingV1,
    },
    /// The exact globally latest workspace attempt precedes this repair.
    ExistingAttempt(Box<WorkspacePinAttemptV1>),
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

/// Carries one fresh, independently reauthenticated durable resolver view.
///
/// Its fields are private so row vectors or hashes cannot be promoted by a
/// caller. Construction reloads both the physical head and every operation
/// record directly from the protected journal and cross-validates them.
pub(crate) struct VerifiedStorageResolverJournalV1 {
    physical: VerifiedPhysicalCatalogSnapshotV1,
    genesis: CatalogBindingV1,
    records: BTreeMap<[u8; 16], VerifiedStorageResolverOperationV1>,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedStorageResolverOperationV1 {
    catalog: ResolvedCatalogCommitmentV1,
    result: CommittedStorageResultV1,
    sandbox_id: [u8; 16],
    request_digest: ObjectDigest,
}

impl VerifiedStorageResolverJournalV1 {
    #[cfg(test)]
    pub(crate) fn held_snapshot_for_test(
        physical: VerifiedPhysicalCatalogSnapshotV1,
        operations: Vec<(
            [u8; 16],
            ResolvedCatalogCommitmentV1,
            Option<[u8; 32]>,
            Option<[u8; 32]>,
            Option<u64>,
        )>,
    ) -> Self {
        let genesis = physical.binding();
        let records = operations
            .into_iter()
            .map(
                |(operation_id, catalog, storage_handle, version_handle, object_guid)| {
                    let result = CommittedStorageResultV1 {
                        operation_id,
                        catalog: catalog.binding(),
                        result_digest: ObjectDigest::from_bytes([1; 32]),
                        storage_handle,
                        immutable_version_handle: version_handle,
                        object_guid,
                    };
                    (
                        operation_id,
                        VerifiedStorageResolverOperationV1 {
                            catalog,
                            result,
                            sandbox_id: [2; 16],
                            request_digest: ObjectDigest::from_bytes([3; 32]),
                        },
                    )
                },
            )
            .collect();
        Self {
            physical,
            genesis,
            records,
        }
    }

    pub(crate) const fn physical(&self) -> &VerifiedPhysicalCatalogSnapshotV1 {
        &self.physical
    }

    pub(crate) const fn genesis(&self) -> CatalogBindingV1 {
        self.genesis
    }

    pub(crate) fn operation(
        &self,
        operation_id: &[u8; 16],
    ) -> Option<&VerifiedStorageResolverOperationV1> {
        self.records.get(operation_id)
    }

    pub(crate) fn operations(
        &self,
    ) -> impl Iterator<Item = (&[u8; 16], &VerifiedStorageResolverOperationV1)> {
        self.records.iter()
    }
}

impl VerifiedStorageResolverOperationV1 {
    pub(crate) const fn catalog(&self) -> &ResolvedCatalogCommitmentV1 {
        &self.catalog
    }

    pub(crate) const fn result(&self) -> CommittedStorageResultV1 {
        self.result
    }

    pub(crate) const fn sandbox_id(&self) -> [u8; 16] {
        self.sandbox_id
    }

    pub(crate) const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }
}

enum PreparedRecord {
    Existing(BeginStorageTransaction),
    New(Box<DurableRecord>),
}

/// Carries the exact preparation replacement committed with first Apply admission.
pub(crate) struct CatalogPreparationConsumption {
    expected_head: CatalogBindingV1,
    prepared_record: Vec<u8>,
    consumed_record: Vec<u8>,
}

/// Retains the highest trusted resolver-policy publication admitted locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageResolverPolicyFloorV1 {
    generation: u64,
    catalog_digest: ObjectDigest,
}

impl StorageResolverPolicyFloorV1 {
    const fn from_binding(binding: StorageResolverPolicyCatalogBindingV1) -> Self {
        Self {
            generation: binding.generation(),
            catalog_digest: binding.digest(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) const fn catalog_digest(self) -> ObjectDigest {
        self.catalog_digest
    }
}

/// Reports whether trusted policy admission advanced or replayed the floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageResolverPolicyAdmissionOutcomeV1 {
    Advanced,
    Replay,
}

impl CatalogPreparationConsumption {
    pub(crate) fn new(
        expected_head: CatalogBindingV1,
        prepared_record: Vec<u8>,
        consumed_record: Vec<u8>,
    ) -> Result<Self, StorageStateError> {
        if prepared_record.is_empty()
            || consumed_record.is_empty()
            || prepared_record == consumed_record
            || prepared_record.len() > MAXIMUM_PREPARATION_RECORD_BYTES
            || consumed_record.len() > MAXIMUM_PREPARATION_RECORD_BYTES
        {
            return Err(StorageStateError::InvalidValue);
        }

        Ok(Self {
            expected_head,
            prepared_record,
            consumed_record,
        })
    }
}

/// Owns the exclusive catalog transaction lock and authenticated journal state.
pub struct StorageTransactionStore {
    journal: Journal,
    key: StorageStateKey,
    records: BTreeMap<[u8; 16], DurableRecord>,
    catalog_transitions: StorageCatalogTransitionProvider,
    runtime_configuration: Option<ObjectDigest>,
    resolver_policy_floor: Option<StorageResolverPolicyFloorV1>,
    publication_intents: BTreeMap<[u8; 16], StorageWorkspacePublicationIntentV1>,
    pin_attempts: BTreeMap<[u8; 16], WorkspacePinAttemptV1>,
    repair_intents: BTreeMap<[u8; 16], StorageWorkspacePinRepairIntentV1>,
    guest_root_attempts: BTreeMap<[u8; 16], GuestRootPublicationAttemptV1>,
    atomic_snapshots: BTreeMap<[u8; 16], AtomicDatasetSnapshotRecordV1>,
    repair_guards: BTreeMap<[u8; 16], repair_guard::StorageRepairGuardRecordV1>,
    commit_failed: bool,
    #[cfg(test)]
    fail_after_next_journal_commit: bool,
}

type CatalogPreparationRecord = ([u8; 16], Vec<u8>);

impl StorageTransactionStore {
    /// Durably consumes one admitted guest-root effect before worker dispatch.
    ///
    /// An uncertain commit poisons the transaction store. Reopen can observe
    /// the exact attempt but never returns this effect as dispatchable again.
    pub(crate) fn begin_guest_root_publication_attempt(
        &mut self,
        attempt: GuestRootPublicationAttemptV1,
        sealed: &SealedStorageAdmission,
        current_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>, StorageStateError> {
        self.ensure_authority_readable()?;
        attempt.validate()?;
        if current_boottime_nanoseconds == 0
            || attempt.effect_deadline_boottime_nanoseconds <= current_boottime_nanoseconds
            || attempt.phase != crate::guest_root_attempt::GuestRootAttemptPhaseV1::Ambiguous
            || self
                .guest_root_attempts
                .contains_key(&attempt.effect_operation)
            || self.records.contains_key(&attempt.effect_operation)
            || self.guest_root_attempts.values().any(|existing| {
                existing.expected_proof.workspace_handle == attempt.expected_proof.workspace_handle
                    && !existing.permits_fresh_retry(attempt, current_boottime_nanoseconds)
            })
            || self
                .journal
                .get(RecordNamespace::Effect, &attempt.request_id)
                .is_some()
            || self
                .journal
                .get(
                    RecordNamespace::AuthorityPublication,
                    &attempt.effect_operation,
                )
                .is_some()
            || sealed.current_fence.is_empty()
            || sealed.effect.is_empty()
            || sealed.operation_fence.is_empty()
            || sealed.current_fence.len() > MAXIMUM_RECORD_BYTES
            || sealed.effect.len() > MAXIMUM_RECORD_BYTES
            || sealed.operation_fence.len() > MAXIMUM_RECORD_BYTES
            || Sha256::digest(&sealed.effect).as_slice() != attempt.sealed_effect_digest
            || Sha256::digest(&sealed.operation_fence).as_slice() != attempt.operation_fence_digest
        {
            return Err(StorageStateError::Equivocation);
        }
        let proof = attempt.expected_proof;
        let creation = self
            .records
            .get(&proof.creation_operation)
            .filter(|record| record.phase == DurableStoragePhase::Committed)
            .and_then(|record| record.result)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let publication = self
            .publication_intents
            .get(&proof.creation_operation)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if creation.storage_handle() != Some(proof.workspace_handle)
            || creation.object_guid() != Some(proof.dataset_guid)
            || publication.assignment_digest().as_bytes() != &proof.assignment_digest
            || publication.root_image().digest().as_bytes() != &proof.root_image_digest
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        let sealed_attempt = self.key.seal_guest_root_publication_attempt(attempt)?;
        let transaction = JournalTransaction::new(
            guest_root_attempt_transaction_id(attempt.effect_operation),
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    proof.sandbox.to_vec(),
                    sealed.current_fence.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    attempt.request_id.to_vec(),
                    sealed.effect.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    attempt.effect_operation.to_vec(),
                    sealed.operation_fence.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::StorageGuestRootPublicationAttempt,
                    attempt.effect_operation.to_vec(),
                    sealed_attempt.clone(),
                ),
            ],
        )?;
        self.commit_journal_verified(&transaction)?;
        self.guest_root_attempts
            .insert(attempt.effect_operation, attempt);
        Ok(sealed_attempt)
    }

    pub(crate) fn atomic_dataset_snapshot_inventory(
        &self,
    ) -> Result<Vec<AtomicDatasetSnapshotInventoryV1>, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self
            .atomic_snapshots
            .values()
            .map(|record| AtomicDatasetSnapshotInventoryV1 {
                phase: record.phase,
                program: record.program.clone(),
                observation: record.observation,
                sandbox_id: record.sandbox_id,
                request_id: record.request_id,
                semantic_digest: record.semantic_digest,
                transport_digest: record.transport_digest,
                post_head: record.post_head,
                member_guids: self
                    .catalog_transitions
                    .atomic_group_member_guids(record.program.operation())
                    .map(<[u64]>::to_vec),
            })
            .collect())
    }

    pub(crate) fn prepare_authorized_atomic_dataset_snapshot(
        &mut self,
        program: crate::DormantAtomicDatasetSnapshotV1,
        sandbox_id: [u8; 16],
        request_id: [u8; 16],
        semantic_digest: ObjectDigest,
        transport_digest: ObjectDigest,
        sealed: SealedStorageAdmission,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        let operation = program.operation();
        if operation == [0; 16]
            || sandbox_id == [0; 16]
            || request_id == [0; 16]
            || semantic_digest.as_bytes() == &[0; 32]
            || transport_digest.as_bytes() == &[0; 32]
            || self.atomic_snapshots.contains_key(&operation)
            || self.records.contains_key(&operation)
            || self
                .journal
                .get(RecordNamespace::AuthorityPublication, &operation)
                .is_some()
            || self
                .journal
                .get(RecordNamespace::Effect, &request_id)
                .is_some()
            || sealed.current_fence.is_empty()
            || sealed.effect.is_empty()
            || sealed.operation_fence.is_empty()
            || sealed.current_fence.len() > MAXIMUM_RECORD_BYTES
            || sealed.effect.len() > MAXIMUM_RECORD_BYTES
            || sealed.operation_fence.len() > MAXIMUM_RECORD_BYTES
        {
            return Err(StorageStateError::Equivocation);
        }
        let reservation = self.catalog_transitions.reserve_atomic_group(
            &program,
            semantic_digest,
            self.key.key_id,
            &self.key.secret,
        )?;
        let record = AtomicDatasetSnapshotRecordV1 {
            phase: AtomicDatasetSnapshotPhaseV1::Prepared,
            program,
            observation: None,
            sandbox_id,
            request_id,
            semantic_digest,
            transport_digest,
            post_head: None,
        };
        let ambiguous = AtomicDatasetSnapshotRecordV1 {
            phase: AtomicDatasetSnapshotPhaseV1::Ambiguous,
            ..record.clone()
        };
        let placeholder_head_digest = if record.program.catalog_head().as_bytes() == &[1; 32] {
            [2; 32]
        } else {
            [1; 32]
        };
        let committed = AtomicDatasetSnapshotRecordV1 {
            phase: AtomicDatasetSnapshotPhaseV1::Committed,
            observation: Some(ObjectDigest::from_bytes([1; 32])),
            post_head: Some(
                CatalogBindingV1::from_publisher(
                    record
                        .program
                        .catalog_generation()
                        .checked_add(1)
                        .ok_or(StorageStateError::InvalidValue)?,
                    ObjectDigest::from_bytes(placeholder_head_digest),
                )
                .map_err(|_| StorageStateError::InvalidValue)?,
            ),
            ..record.clone()
        };
        let prepared = JournalTransaction::new(
            atomic_snapshot_transaction_id(operation, AtomicDatasetSnapshotPhaseV1::Prepared),
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    sandbox_id.to_vec(),
                    sealed.current_fence,
                ),
                JournalRecord::put(RecordNamespace::Effect, request_id.to_vec(), sealed.effect),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    operation.to_vec(),
                    sealed.operation_fence,
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    atomic_snapshot_record_key(operation),
                    encode_atomic_snapshot_record(&record, &self.key)?,
                ),
                StorageCatalogTransitionProvider::reservation_record(&reservation),
            ],
        )?;
        if prepared.records().iter().any(|record| {
            record
                .value()
                .is_some_and(|value| value.len() > MAXIMUM_JOURNAL_RECORD_BYTES)
        }) {
            return Err(StorageStateError::InvalidValue);
        }
        let mut committed_capacity_records = vec![JournalRecord::put(
            RecordNamespace::Effect,
            atomic_snapshot_record_key(operation),
            encode_atomic_snapshot_record(&committed, &self.key)?,
        )];
        committed_capacity_records
            .extend(StorageCatalogTransitionProvider::group_effect_capacity_records(operation));
        let committed_capacity = JournalTransaction::new(
            atomic_snapshot_transaction_id(operation, AtomicDatasetSnapshotPhaseV1::Committed),
            committed_capacity_records,
        )?;
        self.journal.preflight_transactions(&[
            prepared.clone(),
            atomic_snapshot_transaction(&ambiguous, &self.key)?,
            committed_capacity,
        ])?;
        self.commit_journal(&prepared)?;
        self.catalog_transitions.install_reservation(reservation);
        self.atomic_snapshots.insert(operation, record);
        Ok(())
    }

    pub(crate) fn mark_atomic_dataset_snapshot_ambiguous(
        &mut self,
        operation: [u8; 16],
        program: ObjectDigest,
    ) -> Result<crate::DormantAtomicDatasetSnapshotV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let current = self
            .atomic_snapshots
            .get(&operation)
            .filter(|record| {
                record.phase == AtomicDatasetSnapshotPhaseV1::Prepared
                    && record.program.commitment() == program
                    && record.observation.is_none()
            })
            .cloned()
            .ok_or(StorageStateError::InvalidTransition)?;
        let record = AtomicDatasetSnapshotRecordV1 {
            phase: AtomicDatasetSnapshotPhaseV1::Ambiguous,
            ..current
        };
        self.publish_atomic_snapshot(&record)?;
        self.atomic_snapshots.insert(operation, record.clone());
        Ok(record.program)
    }

    pub(crate) fn atomic_dataset_snapshot_recovery(
        &self,
        operation: [u8; 16],
    ) -> Result<
        (
            AtomicDatasetSnapshotPhaseV1,
            crate::DormantAtomicDatasetSnapshotV1,
            Option<ObjectDigest>,
        ),
        StorageStateError,
    > {
        self.ensure_authority_readable()?;
        let record = self
            .atomic_snapshots
            .get(&operation)
            .ok_or(StorageStateError::InvalidTransition)?;
        Ok((record.phase, record.program.clone(), record.observation))
    }

    pub(crate) fn existing_atomic_dataset_snapshot(
        &self,
        operation: [u8; 16],
    ) -> Result<
        Option<(
            AtomicDatasetSnapshotPhaseV1,
            crate::DormantAtomicDatasetSnapshotV1,
            Option<ObjectDigest>,
        )>,
        StorageStateError,
    > {
        self.ensure_authority_readable()?;
        Ok(self
            .atomic_snapshots
            .get(&operation)
            .map(|record| (record.phase, record.program.clone(), record.observation)))
    }

    pub(crate) fn commit_atomic_dataset_snapshot(
        &mut self,
        operation: [u8; 16],
        program: ObjectDigest,
        observation: ObjectDigest,
    ) -> Result<(), StorageStateError> {
        self.commit_legacy_atomic_dataset_snapshot(operation, program, observation)
    }

    /// Commits the original result and observed grouped physical transition atomically.
    pub(crate) fn commit_atomic_dataset_snapshot_with_evidence(
        &mut self,
        operation: [u8; 16],
        program: ObjectDigest,
        observation: ObjectDigest,
        member_guids: &[u64],
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        let current = self
            .atomic_snapshots
            .get(&operation)
            .filter(|record| {
                record.phase == AtomicDatasetSnapshotPhaseV1::Ambiguous
                    && record.program.commitment() == program
                    && record.program.format_version() == 2
                    && record.observation.is_none()
            })
            .cloned()
            .ok_or(StorageStateError::InvalidTransition)?;
        let transition = self.catalog_transitions.prepare_atomic_group_transition(
            &current.program,
            current.semantic_digest,
            observation,
            member_guids,
            self.key.key_id,
            &self.key.secret,
        )?;
        let post_head = transition.result_binding();
        let record = AtomicDatasetSnapshotRecordV1 {
            phase: AtomicDatasetSnapshotPhaseV1::Committed,
            observation: Some(observation),
            post_head: Some(post_head),
            ..current
        };
        let mut records = vec![JournalRecord::put(
            RecordNamespace::Effect,
            atomic_snapshot_record_key(operation),
            encode_atomic_snapshot_record(&record, &self.key)?,
        )];
        records.extend(transition.records());
        let journal = JournalTransaction::new(
            atomic_snapshot_transaction_id(operation, AtomicDatasetSnapshotPhaseV1::Committed),
            records,
        )?;
        self.commit_journal(&journal)?;
        self.catalog_transitions.install_transition(transition);
        self.atomic_snapshots.insert(operation, record);
        Ok(())
    }

    fn commit_legacy_atomic_dataset_snapshot(
        &mut self,
        operation: [u8; 16],
        program: ObjectDigest,
        observation: ObjectDigest,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        if observation.as_bytes() == &[0; 32] {
            return Err(StorageStateError::InvalidValue);
        }
        let current = self
            .atomic_snapshots
            .get(&operation)
            .filter(|record| {
                record.phase == AtomicDatasetSnapshotPhaseV1::Ambiguous
                    && record.program.commitment() == program
                    && record.observation.is_none()
            })
            .cloned()
            .ok_or(StorageStateError::InvalidTransition)?;
        if current.program.format_version() != 1 {
            return Err(StorageStateError::InvalidTransition);
        }
        let record = AtomicDatasetSnapshotRecordV1 {
            phase: AtomicDatasetSnapshotPhaseV1::Committed,
            observation: Some(observation),
            post_head: None,
            ..current
        };
        self.publish_atomic_snapshot(&record)?;
        self.atomic_snapshots.insert(operation, record);
        Ok(())
    }

    fn publish_atomic_snapshot(
        &mut self,
        record: &AtomicDatasetSnapshotRecordV1,
    ) -> Result<(), StorageStateError> {
        let transaction = atomic_snapshot_transaction(record, &self.key)?;
        self.commit_journal(&transaction)
    }

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
    pub(crate) fn open_runtime_for_test(
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
        let records = load_durable_records(&journal, &key)?;
        let runtime_configuration = load_runtime_configuration(&journal, &key)?;
        let resolver_policy_floor = load_resolver_policy_floor(&journal, &key)?;
        let publication_intents = load_publication_intents(&journal, &key)?;
        let pin_attempts = load_attempts(&journal, key.key_id, &key.secret)?;
        let repair_intents = load_repair_intents(&journal, key.key_id, &key.secret)?;
        let guest_root_attempts = load_guest_root_attempts(&journal, &key)?;
        let atomic_snapshots = load_atomic_snapshot_records(&journal, &key)?;
        let repair_guards = repair_guard::load(&journal, &key)?;
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
        validate_durable_records(&records, &catalog_transitions, &key)?;
        if records
            .keys()
            .any(|operation| atomic_snapshots.contains_key(operation))
        {
            return Err(StorageStateError::CorruptRecord);
        }
        validate_atomic_snapshot_catalog_join(&atomic_snapshots, &catalog_transitions)?;
        catalog_transitions
            .validate_operation_set(records.keys().chain(atomic_snapshots.keys()).copied())?;
        validate_publication_intent_set(&records, &publication_intents)?;
        validate_repair_intent_set(
            &journal,
            &records,
            &publication_intents,
            &pin_attempts,
            &repair_intents,
        )?;
        validate_guest_root_attempt_set(
            &journal,
            &records,
            &publication_intents,
            &guest_root_attempts,
        )?;
        let store = Self {
            journal,
            key,
            records,
            catalog_transitions,
            runtime_configuration,
            resolver_policy_floor,
            publication_intents,
            pin_attempts,
            repair_intents,
            guest_root_attempts,
            atomic_snapshots,
            repair_guards,
            commit_failed: false,
            #[cfg(test)]
            fail_after_next_journal_commit: false,
        };
        let mut attempts_per_workspace = BTreeMap::<[u8; 32], [bool; 4]>::new();
        for attempt in store.pin_attempts.values() {
            store.validate_pin_attempt_context(attempt)?;
            let ordinals = attempts_per_workspace
                .entry(attempt.workspace_handle())
                .or_default();
            let ordinal = usize::from(attempt.attempt_ordinal() - 1);
            if ordinals[ordinal] {
                return Err(StorageStateError::CorruptRecord);
            }
            ordinals[ordinal] = true;
        }
        if attempts_per_workspace.values().any(|ordinals| {
            ordinals
                .iter()
                .position(|present| !present)
                .is_some_and(|first_gap| ordinals[first_gap + 1..].contains(&true))
        }) {
            return Err(StorageStateError::CorruptRecord);
        }
        store.validate_snapshot_metadata_authority_set()?;
        Ok(store)
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
            && self.resolver_policy_floor.is_none()
            && self.publication_intents.is_empty()
            && self.pin_attempts.is_empty()
            && self.atomic_snapshots.is_empty()
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

    pub(crate) fn workspace_pin_attempts(
        &self,
    ) -> Result<Vec<WorkspacePinAttemptV1>, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self.pin_attempts.values().cloned().collect())
    }

    pub(crate) fn workspace_pin_attempt_record(
        &self,
        attempt: &WorkspacePinAttemptV1,
    ) -> Result<Vec<u8>, StorageStateError> {
        self.ensure_authority_readable()?;
        if self.pin_attempts.get(&attempt.attempt_id()) != Some(attempt) {
            return Err(StorageStateError::InvalidTransition);
        }
        self.journal
            .get(
                RecordNamespace::StorageWorkspacePinAttempt,
                &attempt.attempt_id(),
            )
            .map(ToOwned::to_owned)
            .ok_or(StorageStateError::MissingAuthorityLink)
    }

    pub(crate) fn workspace_pin_repair_intent(
        &self,
        repair_operation_id: [u8; 16],
    ) -> Result<Option<StorageWorkspacePinRepairIntentV1>, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self.repair_intents.get(&repair_operation_id).cloned())
    }

    pub(crate) fn workspace_pin_repair_intents(
        &self,
    ) -> Result<Vec<StorageWorkspacePinRepairIntentV1>, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self.repair_intents.values().cloned().collect())
    }

    pub(crate) fn latest_workspace_pin_attempt(
        &self,
        creation_operation_id: [u8; 16],
    ) -> Result<Option<WorkspacePinAttemptV1>, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self
            .pin_attempts
            .values()
            .filter(|attempt| attempt.creation_operation_id() == creation_operation_id)
            .max_by_key(|attempt| attempt.attempt_ordinal())
            .cloned())
    }

    pub(crate) fn workspace_creation_for_pin_repair(
        &self,
        workspace_handle: [u8; 32],
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let mut matching_creations = Vec::new();
        for result in self.records.values().filter_map(|record| {
            (record.phase == DurableStoragePhase::Committed)
                .then_some(record.result)
                .flatten()
                .filter(|result| result.storage_handle() == Some(workspace_handle))
        }) {
            let entry = self.committed_recovery_entry(result)?;
            let catalog = self.recover_catalog(entry)?;
            if matches!(
                catalog.plan(),
                CatalogPlanV1::CreateWorkspace { .. } | CatalogPlanV1::Clone { .. }
            ) {
                matching_creations.push(result);
            }
        }

        let mut matching_creations = matching_creations.into_iter();
        let result = matching_creations
            .next()
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if matching_creations.next().is_some() {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        if !self.workspace_creation_is_active(result.operation_id(), workspace_handle)? {
            return Err(StorageStateError::InvalidTransition);
        }
        Ok(result)
    }

    pub(crate) fn workspace_creation_record(
        &self,
        creation: CommittedStorageResultV1,
    ) -> Result<Vec<u8>, StorageStateError> {
        self.ensure_authority_readable()?;
        self.committed_recovery_entry(creation)?;
        let bytes = self
            .journal
            .get(RecordNamespace::Operation, &creation.operation_id())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let opened = decode_record(bytes, &self.key)?;
        if opened.result != Some(creation)
            || self.records.get(&creation.operation_id()) != Some(&opened)
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(bytes.to_vec())
    }

    pub(crate) fn missing_initial_repair_attempt_id(
        &self,
        creation: CommittedStorageResultV1,
        repair_operation_id: [u8; 16],
    ) -> Result<[u8; 16], StorageStateError> {
        self.ensure_authority_readable()?;
        let workspace_handle = creation
            .storage_handle()
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if self.committed_recovery_entry(creation)?.operation_id() == repair_operation_id
            || self.pin_attempts.values().any(|attempt| {
                attempt.workspace_handle() == workspace_handle
                    || attempt.creation_operation_id() == creation.operation_id()
            })
        {
            return Err(StorageStateError::InvalidTransition);
        }
        derive_attempt_id(
            &self.key.secret,
            repair_operation_id,
            workspace_handle,
            WorkspacePinActionV1::Ensure,
            1,
        )
    }

    pub(crate) fn workspace_pin_repair_intent_record(
        &self,
        intent: &StorageWorkspacePinRepairIntentV1,
    ) -> Result<Vec<u8>, StorageStateError> {
        self.ensure_authority_readable()?;
        if self.repair_intents.get(&intent.repair_operation_id()) != Some(intent) {
            return Err(StorageStateError::InvalidTransition);
        }
        self.journal
            .get(
                RecordNamespace::StorageWorkspacePinRepairIntent,
                &intent.repair_operation_id(),
            )
            .map(ToOwned::to_owned)
            .ok_or(StorageStateError::MissingAuthorityLink)
    }

    pub(crate) fn workspace_publication_intent_record(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Vec<u8>, StorageStateError> {
        self.ensure_authority_readable()?;
        if !self.publication_intents.contains_key(&operation_id) {
            return Err(StorageStateError::MissingAuthorityLink);
        }
        self.journal
            .get(
                RecordNamespace::StorageWorkspacePublicationIntent,
                &operation_id,
            )
            .map(ToOwned::to_owned)
            .ok_or(StorageStateError::MissingAuthorityLink)
    }

    pub(crate) fn workspace_creation_catalog(
        &self,
        intent: &StorageWorkspacePinRepairIntentV1,
    ) -> Result<ResolvedCatalogCommitmentV1, StorageStateError> {
        self.ensure_authority_readable()?;
        if self.repair_intents.get(&intent.repair_operation_id()) != Some(intent) {
            return Err(StorageStateError::InvalidTransition);
        }
        let attempt = self
            .pin_attempts
            .get(&intent.repair_attempt_id())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        self.workspace_creation_catalog_for_attempt(attempt)
    }

    pub(crate) fn workspace_creation_catalog_for_attempt(
        &self,
        attempt: &WorkspacePinAttemptV1,
    ) -> Result<ResolvedCatalogCommitmentV1, StorageStateError> {
        self.ensure_authority_readable()?;
        if self.pin_attempts.get(&attempt.attempt_id()) != Some(attempt)
            || attempt.action() != WorkspacePinActionV1::Ensure
        {
            return Err(StorageStateError::InvalidTransition);
        }
        let creation = self
            .records
            .get(&attempt.creation_operation_id())
            .filter(|record| {
                record.phase == DurableStoragePhase::Committed
                    && record.result.is_some_and(|result| {
                        result.catalog() == attempt.creation_result_catalog()
                            && result.result_digest() == attempt.creation_result_digest()
                            && result.storage_handle() == Some(attempt.workspace_handle())
                    })
            })
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(&creation.catalog_bytes)
            .map_err(|_| StorageStateError::CorruptRecord)?;
        if catalog.binding() != creation.catalog {
            return Err(StorageStateError::CorruptRecord);
        }
        Ok(catalog)
    }

    pub(crate) fn workspace_creation_is_active(
        &self,
        creation_operation_id: [u8; 16],
        workspace_handle: [u8; 32],
    ) -> Result<bool, StorageStateError> {
        self.ensure_authority_readable()?;
        for projection in self.catalog_transitions.workspace_projection()? {
            match projection {
                PhysicalWorkspaceProjection::Active { operation_id, .. }
                    if operation_id == creation_operation_id =>
                {
                    let result = self.projected_committed_result(operation_id)?;
                    return Ok(result.storage_handle() == Some(workspace_handle));
                }
                PhysicalWorkspaceProjection::Retired { object_guid, .. } => {
                    if self
                        .managed_workspace_creation(object_guid)?
                        .is_some_and(|creation| {
                            creation.operation_id() == creation_operation_id
                                && creation.storage_handle() == Some(workspace_handle)
                        })
                    {
                        return Ok(false);
                    }
                }
                _ => {}
            }
        }
        Ok(false)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_workspace_pin_repair(
        &mut self,
        sandbox_id: [u8; 16],
        predecessor: &WorkspacePinRepairPredecessorV1,
        intent: StorageWorkspacePinRepairIntentV1,
        attempt: WorkspacePinAttemptV1,
        sealed_current_fence: Vec<u8>,
        sealed_pending_effect: Vec<u8>,
        sealed_completed_effect: Vec<u8>,
        sealed_operation_fence: Vec<u8>,
        authority: FreshWorkspacePinAuthority,
    ) -> Result<BeginWorkspacePinAttemptV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let predecessor_matches = match predecessor {
            WorkspacePinRepairPredecessorV1::MissingInitial {
                creation,
                creation_record_digest,
                physical_catalog_head,
            } => {
                let creation_record = self.workspace_creation_record(**creation)?;
                self.catalog_head_binding()? == *physical_catalog_head
                    && digest_bytes(&creation_record) == *creation_record_digest
                    && creation.storage_handle() == Some(attempt.workspace_handle())
                    && creation.operation_id() == attempt.creation_operation_id()
                    && creation.catalog() == attempt.creation_result_catalog()
                    && creation.result_digest() == attempt.creation_result_digest()
                    && attempt.attempt_ordinal() == 1
                    && self.pin_attempts.values().all(|candidate| {
                        candidate.workspace_handle() != attempt.workspace_handle()
                            && candidate.creation_operation_id() != attempt.creation_operation_id()
                    })
                    && intent.predecessor()
                        == WorkspacePinRepairIntentPredecessorV1::MissingInitial {
                            creation_record_digest: *creation_record_digest,
                        }
            }
            WorkspacePinRepairPredecessorV1::ExistingAttempt(expected_latest) => {
                let current_latest = self
                    .pin_attempts
                    .values()
                    .filter(|candidate| candidate.workspace_handle() == attempt.workspace_handle())
                    .max_by_key(|candidate| candidate.attempt_ordinal());
                let expected_record_digest = ObjectDigest::from_bytes(
                    Sha256::digest(self.workspace_pin_attempt_record(expected_latest)?).into(),
                );
                current_latest == Some(expected_latest)
                    && expected_latest.action() == WorkspacePinActionV1::Ensure
                    && expected_latest.expected_pin().is_none()
                    && expected_latest.attempt_ordinal() < MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE
                    && attempt.attempt_ordinal()
                        == expected_latest
                            .attempt_ordinal()
                            .checked_add(1)
                            .ok_or(StorageStateError::InvalidTransition)?
                    && attempt.creation_operation_id() == expected_latest.creation_operation_id()
                    && attempt.creation_result_catalog()
                        == expected_latest.creation_result_catalog()
                    && attempt.creation_result_digest() == expected_latest.creation_result_digest()
                    && attempt.workspace_handle() == expected_latest.workspace_handle()
                    && attempt.workspace_assignment_digest()
                        == expected_latest.workspace_assignment_digest()
                    && attempt.dataset_name() == expected_latest.dataset_name()
                    && attempt.dataset_guid() == expected_latest.dataset_guid()
                    && attempt.identity_range_start() == expected_latest.identity_range_start()
                    && attempt.identity_range_size() == expected_latest.identity_range_size()
                    && intent.predecessor()
                        == WorkspacePinRepairIntentPredecessorV1::ExistingAttempt {
                            attempt_id: expected_latest.attempt_id(),
                            phase: expected_latest.phase(),
                            record_digest: expected_record_digest,
                        }
            }
        };
        if !predecessor_matches
            || !self.workspace_creation_is_active(
                attempt.creation_operation_id(),
                attempt.workspace_handle(),
            )?
            || attempt.action() != WorkspacePinActionV1::Ensure
            || attempt.phase() != WorkspacePinAttemptPhaseV1::Ambiguous
            || attempt.effect_operation_id() != intent.repair_operation_id()
            || attempt.expected_pin().is_some()
            || intent.repair_attempt_id() != attempt.attempt_id()
            || intent.repair_attempt_ordinal() != attempt.attempt_ordinal()
            || intent.creation_operation_id() != attempt.creation_operation_id()
            || intent.creation_result_catalog() != attempt.creation_result_catalog()
            || intent.creation_result_digest() != attempt.creation_result_digest()
            || intent.workspace_handle() != attempt.workspace_handle()
            || intent.repair_assignment_digest() != attempt.effect_assignment_digest()
            || intent.operation_fence_digest() != attempt.operation_fence_digest()
            || intent.admitted_effect_record() != sealed_pending_effect
            || intent.operation_fence_digest()
                != ObjectDigest::from_bytes(Sha256::digest(&sealed_operation_fence).into())
            || intent.publication_intent_record_digest()
                != ObjectDigest::from_bytes(
                    Sha256::digest(
                        self.workspace_publication_intent_record(attempt.creation_operation_id())?,
                    )
                    .into(),
                )
            || attempt.attempt_id() != authority.attempt_id()
            || attempt.authority_digest()? != authority.attempt_digest()
            || sandbox_id == [0; 16]
            || sealed_current_fence.is_empty()
            || sealed_pending_effect.is_empty()
            || sealed_completed_effect.is_empty()
            || sealed_operation_fence.is_empty()
            || sealed_current_fence.len() > MAXIMUM_RECORD_BYTES
            || sealed_pending_effect.len() > MAXIMUM_RECORD_BYTES
            || sealed_completed_effect.len() > MAXIMUM_RECORD_BYTES
            || sealed_operation_fence.len() > MAXIMUM_RECORD_BYTES
            || sealed_completed_effect.as_slice() == sealed_pending_effect.as_slice()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        if let Some(existing_intent) = self.repair_intents.get(&intent.repair_operation_id()) {
            let existing_attempt = self
                .pin_attempts
                .get(&existing_intent.repair_attempt_id())
                .ok_or(StorageStateError::MissingAuthorityLink)?;
            if existing_intent != &intent || !existing_attempt.same_authorized_effect(&attempt) {
                return Err(StorageStateError::Equivocation);
            }
            return Ok(BeginWorkspacePinAttemptV1::ObserveOnly(
                existing_attempt.clone(),
            ));
        }
        if self.records.contains_key(&intent.repair_operation_id())
            || self
                .journal
                .get(
                    RecordNamespace::AuthorityPublication,
                    &intent.repair_operation_id(),
                )
                .is_some()
            || self
                .journal
                .get(RecordNamespace::Effect, &intent.request_id())
                .is_some()
            || self.pin_attempts.contains_key(&attempt.attempt_id())
            || self.pin_attempts.values().any(|candidate| {
                candidate.workspace_handle() == attempt.workspace_handle()
                    && candidate.attempt_ordinal() == attempt.attempt_ordinal()
            })
        {
            return Err(StorageStateError::Equivocation);
        }

        let attempt = attempt.with_authority_receipt(authority.into_sealed_receipt())?;
        let transaction = JournalTransaction::new(
            workspace_pin_repair_transaction_id(intent.repair_operation_id()),
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    sandbox_id.to_vec(),
                    sealed_current_fence,
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    intent.request_id().to_vec(),
                    sealed_pending_effect,
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    intent.repair_operation_id().to_vec(),
                    sealed_operation_fence,
                ),
                repair_intent_record(&intent, self.key.key_id, &self.key.secret)?,
                attempt_record(&attempt, self.key.key_id, &self.key.secret)?,
            ],
        )?;
        let capacity_completion = attempt.capacity_completion()?;
        let satisfied = JournalTransaction::new(
            pin_attempt_transaction_id(&capacity_completion),
            vec![
                attempt_record(&capacity_completion, self.key.key_id, &self.key.secret)?,
                JournalRecord::put(
                    RecordNamespace::Effect,
                    intent.request_id().to_vec(),
                    sealed_completed_effect,
                ),
            ],
        )?;
        self.journal
            .preflight_transactions(&[transaction.clone(), satisfied])?;

        self.commit_journal_verified(&transaction)?;

        self.repair_intents
            .insert(intent.repair_operation_id(), intent);
        self.pin_attempts
            .insert(attempt.attempt_id(), attempt.clone());
        if self.validate_pin_attempt_context(&attempt).is_err() {
            self.commit_failed = true;
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(BeginWorkspacePinAttemptV1::Dispatch(attempt))
    }

    #[cfg(test)]
    pub(crate) fn retain_workspace_pin_repair_for_test(
        &mut self,
        sandbox_id: [u8; 16],
        intent: StorageWorkspacePinRepairIntentV1,
        attempt: WorkspacePinAttemptV1,
        sealed_current_fence: Vec<u8>,
        sealed_live_effect: Vec<u8>,
        sealed_operation_fence: Vec<u8>,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        if intent.repair_attempt_id() != attempt.attempt_id()
            || intent.repair_operation_id() != attempt.effect_operation_id()
            || intent.request_id() == [0; 16]
            || sealed_current_fence.is_empty()
            || sealed_live_effect.is_empty()
            || sealed_operation_fence.is_empty()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        let transaction = JournalTransaction::new(
            [0xd7; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    sandbox_id.to_vec(),
                    sealed_current_fence,
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    intent.request_id().to_vec(),
                    sealed_live_effect,
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    intent.repair_operation_id().to_vec(),
                    sealed_operation_fence,
                ),
                repair_intent_record(&intent, self.key.key_id, &self.key.secret)?,
                attempt_record(&attempt, self.key.key_id, &self.key.secret)?,
            ],
        )?;
        self.commit_journal(&transaction)?;
        self.repair_intents
            .insert(intent.repair_operation_id(), intent);
        self.pin_attempts.insert(attempt.attempt_id(), attempt);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn replace_workspace_pin_repair_intent_for_test(
        &mut self,
        transaction_id: [u8; 16],
        intent: StorageWorkspacePinRepairIntentV1,
    ) -> Result<(), StorageStateError> {
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![repair_intent_record(
                &intent,
                self.key.key_id,
                &self.key.secret,
            )?],
        )?;
        self.commit_journal(&transaction)?;
        self.repair_intents
            .insert(intent.repair_operation_id(), intent);
        Ok(())
    }

    pub(crate) fn require_satisfied_workspace_pin_effect(
        &self,
        effect_operation_id: [u8; 16],
        workspace_handle: [u8; 32],
        action: WorkspacePinActionV1,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        let latest = self
            .pin_attempts
            .values()
            .filter(|attempt| attempt.workspace_handle() == workspace_handle)
            .max_by_key(|attempt| attempt.attempt_ordinal())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if latest.effect_operation_id() != effect_operation_id
            || latest.action() != action
            || latest.phase() != WorkspacePinAttemptPhaseV1::Satisfied
        {
            return Err(StorageStateError::InvalidTransition);
        }
        Ok(())
    }

    // Publication follows the creation identity, while a repair has its own
    // effect identity. Never fall back past a newer non-satisfied attempt.
    pub(crate) fn satisfied_workspace_ensure_pin_for_active_creation(
        &self,
        creation_operation_id: [u8; 16],
        workspace_handle: [u8; 32],
    ) -> Result<WorkspaceRootPinProofV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let latest = self
            .pin_attempts
            .values()
            .filter(|attempt| attempt.workspace_handle() == workspace_handle)
            .max_by_key(|attempt| attempt.attempt_ordinal())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        self.satisfied_workspace_ensure_pin(&latest, creation_operation_id, workspace_handle)
    }

    /// Recovers the historical satisfied Ensure proof for a retired creation.
    ///
    /// RemoveAndDestroy may follow a newer non-satisfied Ensure while retaining
    /// the most recent satisfied pin. This lookup is deliberately scoped to the
    /// retired creation rather than the globally latest workspace attempt used
    /// for active publication.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError`] when authority state is unavailable, no
    /// matching satisfied Ensure exists, or its creation or repair links do not
    /// match the requested retired workspace.
    pub(crate) fn satisfied_workspace_ensure_pin_for_creation_history(
        &self,
        creation_operation_id: [u8; 16],
        workspace_handle: [u8; 32],
    ) -> Result<WorkspaceRootPinProofV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let latest = self
            .pin_attempts
            .values()
            .filter(|attempt| {
                attempt.creation_operation_id() == creation_operation_id
                    && attempt.workspace_handle() == workspace_handle
                    && attempt.action() == WorkspacePinActionV1::Ensure
                    && attempt.phase() == WorkspacePinAttemptPhaseV1::Satisfied
            })
            .max_by_key(|attempt| attempt.attempt_ordinal())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        self.satisfied_workspace_ensure_pin(latest, creation_operation_id, workspace_handle)
    }

    fn satisfied_workspace_ensure_pin(
        &self,
        latest: &WorkspacePinAttemptV1,
        creation_operation_id: [u8; 16],
        workspace_handle: [u8; 32],
    ) -> Result<WorkspaceRootPinProofV1, StorageStateError> {
        if latest.creation_operation_id() != creation_operation_id
            || latest.workspace_handle() != workspace_handle
            || latest.action() != WorkspacePinActionV1::Ensure
            || latest.phase() != WorkspacePinAttemptPhaseV1::Satisfied
        {
            return Err(StorageStateError::InvalidTransition);
        }
        if latest.effect_operation_id() != creation_operation_id {
            let intent = self
                .repair_intents
                .get(&latest.effect_operation_id())
                .ok_or(StorageStateError::MissingAuthorityLink)?;
            if intent.repair_attempt_id() != latest.attempt_id()
                || intent.repair_operation_id() != latest.effect_operation_id()
                || intent.repair_attempt_ordinal() != latest.attempt_ordinal()
                || intent.creation_operation_id() != creation_operation_id
                || intent.workspace_handle() != workspace_handle
            {
                return Err(StorageStateError::AuthorityLinkMismatch);
            }
        }
        latest
            .satisfied_pin()
            .cloned()
            .ok_or(StorageStateError::MissingAuthorityLink)
    }

    pub(crate) fn plan_workspace_pin_ensure(
        &self,
        result: CommittedStorageResultV1,
        effect_assignment_digest: ObjectDigest,
        host_scope: WorkspacePinHostScopeV1,
        clock_provenance: [u8; 16],
        effect_deadline_boottime_nanoseconds: u64,
    ) -> Result<WorkspacePinAttemptV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let record = self
            .records
            .get(&result.operation_id())
            .filter(|record| {
                record.phase == DurableStoragePhase::Committed && record.result == Some(result)
            })
            .ok_or(StorageStateError::InvalidTransition)?;
        let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(&record.catalog_bytes)
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let dataset_name = match catalog.plan() {
            CatalogPlanV1::CreateWorkspace { destination, .. }
            | CatalogPlanV1::Clone { destination, .. } => destination.name(),
            _ => return Err(StorageStateError::InvalidTransition),
        };
        let intent = self
            .publication_intents
            .get(&record.operation_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if effect_assignment_digest != intent.assignment_digest() {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        let operation_fence_digest = self.operation_fence_digest(record.operation_id)?;
        let workspace_handle = result
            .storage_handle()
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let dataset_guid = result
            .object_guid()
            .filter(|guid| *guid != 0)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let attempt_id = derive_attempt_id(
            &self.key.secret,
            record.operation_id,
            workspace_handle,
            WorkspacePinActionV1::Ensure,
            1,
        )?;
        let common = (
            attempt_id,
            record.operation_id,
            operation_fence_digest,
            workspace_handle,
            dataset_guid,
        );
        WorkspacePinAttemptV1::new_ambiguous(
            common.0,
            1,
            WorkspacePinActionV1::Ensure,
            common.1,
            common.1,
            common.2,
            effect_assignment_digest,
            intent.assignment_digest(),
            result.catalog(),
            result.result_digest(),
            common.3,
            host_scope.kernel_boot_id(),
            host_scope.mount_namespace_device(),
            host_scope.mount_namespace_inode(),
            clock_provenance,
            effect_deadline_boottime_nanoseconds,
            dataset_name.to_owned(),
            common.4,
            intent.identity_range_start(),
            intent.identity_range_size(),
            intent.portable_metadata().root_policy(),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_workspace_pin_repair(
        &self,
        expected_latest: &WorkspacePinAttemptV1,
        repair_operation_id: [u8; 16],
        operation_fence_digest: ObjectDigest,
        repair_assignment_digest: ObjectDigest,
        host_scope: WorkspacePinHostScopeV1,
        clock_provenance: [u8; 16],
        effect_deadline_boottime_nanoseconds: u64,
    ) -> Result<WorkspacePinAttemptV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let latest = self
            .pin_attempts
            .values()
            .filter(|attempt| attempt.workspace_handle() == expected_latest.workspace_handle())
            .max_by_key(|attempt| attempt.attempt_ordinal())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if latest != expected_latest
            || latest.action() != WorkspacePinActionV1::Ensure
            || latest.expected_pin().is_some()
            || !self.workspace_creation_is_active(
                latest.creation_operation_id(),
                latest.workspace_handle(),
            )?
            || repair_operation_id == latest.creation_operation_id()
            || repair_operation_id == latest.effect_operation_id()
        {
            return Err(StorageStateError::InvalidTransition);
        }
        let repair_ordinal = latest
            .attempt_ordinal()
            .checked_add(1)
            .filter(|ordinal| *ordinal <= MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE)
            .ok_or(StorageStateError::InvalidTransition)?;
        let attempt_id = derive_attempt_id(
            &self.key.secret,
            repair_operation_id,
            latest.workspace_handle(),
            WorkspacePinActionV1::Ensure,
            repair_ordinal,
        )?;
        WorkspacePinAttemptV1::new_ambiguous(
            attempt_id,
            repair_ordinal,
            WorkspacePinActionV1::Ensure,
            repair_operation_id,
            latest.creation_operation_id(),
            operation_fence_digest,
            repair_assignment_digest,
            latest.workspace_assignment_digest(),
            latest.creation_result_catalog(),
            latest.creation_result_digest(),
            latest.workspace_handle(),
            host_scope.kernel_boot_id(),
            host_scope.mount_namespace_device(),
            host_scope.mount_namespace_inode(),
            clock_provenance,
            effect_deadline_boottime_nanoseconds,
            latest.dataset_name().to_owned(),
            latest.dataset_guid(),
            latest.identity_range_start(),
            latest.identity_range_size(),
            latest.root_policy(),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_missing_initial_workspace_pin_repair(
        &self,
        creation: CommittedStorageResultV1,
        repair_operation_id: [u8; 16],
        operation_fence_digest: ObjectDigest,
        repair_assignment_digest: ObjectDigest,
        host_scope: WorkspacePinHostScopeV1,
        clock_provenance: [u8; 16],
        effect_deadline_boottime_nanoseconds: u64,
    ) -> Result<WorkspacePinAttemptV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let entry = self.committed_recovery_entry(creation)?;
        let catalog = self.recover_catalog(entry)?;
        let dataset_name = match catalog.plan() {
            CatalogPlanV1::CreateWorkspace { destination, .. }
            | CatalogPlanV1::Clone { destination, .. } => destination.name(),
            _ => return Err(StorageStateError::InvalidTransition),
        };
        let workspace_handle = creation
            .storage_handle()
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let dataset_guid = creation
            .object_guid()
            .filter(|guid| *guid != 0)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let publication = self
            .publication_intents
            .get(&creation.operation_id())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if repair_operation_id == creation.operation_id()
            || !self.workspace_creation_is_active(creation.operation_id(), workspace_handle)?
            || self.pin_attempts.values().any(|attempt| {
                attempt.workspace_handle() == workspace_handle
                    || attempt.creation_operation_id() == creation.operation_id()
            })
        {
            return Err(StorageStateError::InvalidTransition);
        }
        let attempt_id = derive_attempt_id(
            &self.key.secret,
            repair_operation_id,
            workspace_handle,
            WorkspacePinActionV1::Ensure,
            1,
        )?;
        WorkspacePinAttemptV1::new_ambiguous(
            attempt_id,
            1,
            WorkspacePinActionV1::Ensure,
            repair_operation_id,
            creation.operation_id(),
            operation_fence_digest,
            repair_assignment_digest,
            publication.assignment_digest(),
            creation.catalog(),
            creation.result_digest(),
            workspace_handle,
            host_scope.kernel_boot_id(),
            host_scope.mount_namespace_device(),
            host_scope.mount_namespace_inode(),
            clock_provenance,
            effect_deadline_boottime_nanoseconds,
            dataset_name.to_owned(),
            dataset_guid,
            publication.identity_range_start(),
            publication.identity_range_size(),
            publication.portable_metadata().root_policy(),
            None,
        )
    }

    pub(crate) fn begin_workspace_pin_attempt(
        &mut self,
        attempt: WorkspacePinAttemptV1,
        authority: FreshWorkspacePinAuthority,
    ) -> Result<BeginWorkspacePinAttemptV1, StorageStateError> {
        self.ensure_authority_readable()?;
        if attempt.action() != WorkspacePinActionV1::Ensure
            || attempt.phase() != WorkspacePinAttemptPhaseV1::Ambiguous
            || attempt.attempt_id() != authority.attempt_id()
            || attempt.authority_digest()? != authority.attempt_digest()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        self.validate_pin_attempt_context(&attempt)?;
        if let Some(existing) = self.pin_attempts.get(&attempt.attempt_id()) {
            if !existing.same_authorized_effect(&attempt) {
                return Err(StorageStateError::Equivocation);
            }
            return Ok(match existing.phase() {
                WorkspacePinAttemptPhaseV1::Ambiguous => {
                    BeginWorkspacePinAttemptV1::ObserveOnly(existing.clone())
                }
                WorkspacePinAttemptPhaseV1::Satisfied => {
                    BeginWorkspacePinAttemptV1::Satisfied(existing.clone())
                }
            });
        }
        if self
            .pin_attempts
            .values()
            .filter(|existing| existing.workspace_handle() == attempt.workspace_handle())
            .count()
            >= usize::from(MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE)
            || self.pin_attempts.values().any(|existing| {
                existing.workspace_handle() == attempt.workspace_handle()
                    && existing.attempt_ordinal() == attempt.attempt_ordinal()
            })
        {
            return Err(StorageStateError::InvalidTransition);
        }

        let attempt = attempt.with_authority_receipt(authority.into_sealed_receipt())?;

        self.preflight_pin_attempt(&attempt)?;
        let transaction = JournalTransaction::new(
            pin_attempt_transaction_id(&attempt),
            vec![attempt_record(&attempt, self.key.key_id, &self.key.secret)?],
        )?;
        self.commit_journal(&transaction)?;
        self.pin_attempts
            .insert(attempt.attempt_id(), attempt.clone());
        Ok(BeginWorkspacePinAttemptV1::Dispatch(attempt))
    }

    pub(crate) fn plan_workspace_pin_remove_and_destroy(
        &self,
        operation_id: [u8; 16],
        effect_assignment_digest: ObjectDigest,
        host_scope: WorkspacePinHostScopeV1,
        clock_provenance: [u8; 16],
        effect_deadline_boottime_nanoseconds: u64,
        expected_pin: WorkspaceRootPinProofV1,
    ) -> Result<WorkspacePinAttemptV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let destruction = self
            .records
            .get(&operation_id)
            .filter(|record| record.phase == DurableStoragePhase::Prepared)
            .ok_or(StorageStateError::InvalidTransition)?;
        let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(&destruction.catalog_bytes)
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let CatalogPlanV1::DestroyDataset { dataset } = catalog.plan() else {
            return Err(StorageStateError::InvalidTransition);
        };
        let creation = self
            .managed_workspace_creation(dataset.guid())?
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if creation.storage_handle() != Some(dataset.storage_handle()) {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        let intent = self
            .publication_intents
            .get(&creation.operation_id())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let satisfied_ensure = self
            .pin_attempts
            .values()
            .filter(|attempt| {
                attempt.workspace_handle() == dataset.storage_handle()
                    && attempt.action() == WorkspacePinActionV1::Ensure
                    && attempt.phase() == WorkspacePinAttemptPhaseV1::Satisfied
            })
            .max_by_key(|attempt| attempt.attempt_ordinal())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if satisfied_ensure.satisfied_pin() != Some(&expected_pin) {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        let attempt_ordinal = self
            .pin_attempts
            .values()
            .filter(|attempt| attempt.workspace_handle() == dataset.storage_handle())
            .map(WorkspacePinAttemptV1::attempt_ordinal)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .filter(|ordinal| *ordinal <= MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE)
            .ok_or(StorageStateError::InvalidTransition)?;
        let operation_fence_digest = self.operation_fence_digest(operation_id)?;
        let attempt_id = derive_attempt_id(
            &self.key.secret,
            operation_id,
            dataset.storage_handle(),
            WorkspacePinActionV1::RemoveAndDestroy,
            attempt_ordinal,
        )?;
        WorkspacePinAttemptV1::new_ambiguous(
            attempt_id,
            attempt_ordinal,
            WorkspacePinActionV1::RemoveAndDestroy,
            operation_id,
            creation.operation_id(),
            operation_fence_digest,
            effect_assignment_digest,
            intent.assignment_digest(),
            creation.catalog(),
            creation.result_digest(),
            dataset.storage_handle(),
            host_scope.kernel_boot_id(),
            host_scope.mount_namespace_device(),
            host_scope.mount_namespace_inode(),
            clock_provenance,
            effect_deadline_boottime_nanoseconds,
            dataset.name().to_owned(),
            dataset.guid(),
            intent.identity_range_start(),
            intent.identity_range_size(),
            intent.portable_metadata().root_policy(),
            Some(expected_pin),
        )
    }

    pub(crate) fn begin_workspace_pin_remove_and_destroy(
        &mut self,
        attempt: WorkspacePinAttemptV1,
        mutation_digest: ObjectDigest,
        authority: FreshWorkspacePinAuthority,
    ) -> Result<BeginWorkspacePinAttemptV1, StorageStateError> {
        self.ensure_authority_readable()?;
        if attempt.action() != WorkspacePinActionV1::RemoveAndDestroy
            || attempt.phase() != WorkspacePinAttemptPhaseV1::Ambiguous
            || attempt.attempt_id() != authority.attempt_id()
            || attempt.authority_digest()? != authority.attempt_digest()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        self.validate_pin_attempt_context(&attempt)?;
        let current = self
            .exact_current(attempt.effect_operation_id(), mutation_digest)?
            .clone();
        if let Some(existing) = self.pin_attempts.get(&attempt.attempt_id()) {
            if !existing.same_authorized_effect(&attempt) {
                return Err(StorageStateError::Equivocation);
            }
            return Ok(match existing.phase() {
                WorkspacePinAttemptPhaseV1::Ambiguous => {
                    BeginWorkspacePinAttemptV1::ObserveOnly(existing.clone())
                }
                WorkspacePinAttemptPhaseV1::Satisfied => {
                    BeginWorkspacePinAttemptV1::Satisfied(existing.clone())
                }
            });
        }
        if current.phase != DurableStoragePhase::Prepared
            || self.pin_attempts.values().any(|existing| {
                existing.workspace_handle() == attempt.workspace_handle()
                    && existing.attempt_ordinal() == attempt.attempt_ordinal()
            })
        {
            return Err(StorageStateError::InvalidTransition);
        }

        let attempt = attempt.with_authority_receipt(authority.into_sealed_receipt())?;

        let mut ambiguous = current;
        ambiguous.phase = DurableStoragePhase::Ambiguous;
        let transaction = JournalTransaction::new(
            pin_attempt_transaction_id(&attempt),
            vec![
                attempt_record(&attempt, self.key.key_id, &self.key.secret)?,
                JournalRecord::put(
                    RecordNamespace::Operation,
                    ambiguous.operation_id.to_vec(),
                    encode_record(&ambiguous, &self.key)?,
                ),
            ],
        )?;
        let completion = self.effect_completion_capacity_transaction(&ambiguous)?;
        let pin_satisfied = self.pin_satisfied_capacity_transaction(&attempt)?;
        self.journal
            .preflight_transactions(&[transaction.clone(), completion, pin_satisfied])?;
        self.commit_journal(&transaction)?;
        self.records.insert(ambiguous.operation_id, ambiguous);
        self.pin_attempts
            .insert(attempt.attempt_id(), attempt.clone());
        Ok(BeginWorkspacePinAttemptV1::Dispatch(attempt))
    }

    pub(crate) fn complete_workspace_pin_attempt(
        &mut self,
        attempt_id: [u8; 16],
        dataset: &WorkspaceDatasetObservationV1,
        pin: &WorkspacePinObservationV1,
    ) -> Result<WorkspacePinRecoveryDispositionV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let current = self
            .pin_attempts
            .get(&attempt_id)
            .ok_or(StorageStateError::InvalidTransition)?;
        let latest = self
            .pin_attempts
            .values()
            .filter(|attempt| attempt.workspace_handle() == current.workspace_handle())
            .max_by_key(|attempt| attempt.attempt_ordinal())
            .ok_or(StorageStateError::InvalidTransition)?;
        if latest.attempt_id() != current.attempt_id() {
            return Err(StorageStateError::InvalidTransition);
        }
        let disposition = current.classify(dataset, pin);
        let observed_pin = match (disposition, pin) {
            (
                WorkspacePinRecoveryDispositionV1::CompletePublication,
                WorkspacePinObservationV1::Present(proof),
            ) => Some(proof.clone()),
            (WorkspacePinRecoveryDispositionV1::CompleteRetirement, _) => None,
            _ => return Ok(disposition),
        };
        if current.phase() == WorkspacePinAttemptPhaseV1::Satisfied {
            return Ok(disposition);
        }
        let satisfied = current.satisfy(observed_pin)?;
        self.validate_pin_attempt_context(&satisfied)?;
        let transaction = JournalTransaction::new(
            pin_attempt_transaction_id(&satisfied),
            vec![attempt_record(
                &satisfied,
                self.key.key_id,
                &self.key.secret,
            )?],
        )?;
        self.commit_journal(&transaction)?;
        self.pin_attempts.insert(attempt_id, satisfied);
        Ok(disposition)
    }

    pub(crate) fn complete_workspace_pin_repair_attempt(
        &mut self,
        attempt_id: [u8; 16],
        dataset: &WorkspaceDatasetObservationV1,
        pin: &WorkspacePinObservationV1,
        sealed_completed_effect: Vec<u8>,
    ) -> Result<WorkspacePinRecoveryDispositionV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let current = self
            .pin_attempts
            .get(&attempt_id)
            .ok_or(StorageStateError::InvalidTransition)?;
        let latest = self
            .pin_attempts
            .values()
            .filter(|attempt| attempt.workspace_handle() == current.workspace_handle())
            .max_by_key(|attempt| attempt.attempt_ordinal())
            .ok_or(StorageStateError::InvalidTransition)?;
        let intent = self
            .repair_intents
            .get(&current.effect_operation_id())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let live_effect = self
            .journal
            .get(RecordNamespace::Effect, &intent.request_id())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if latest.attempt_id() != current.attempt_id()
            || current.action() != WorkspacePinActionV1::Ensure
            || current.effect_operation_id() == current.creation_operation_id()
            || intent.repair_attempt_id() != current.attempt_id()
            || sealed_completed_effect.is_empty()
            || sealed_completed_effect.len() > MAXIMUM_RECORD_BYTES
            || sealed_completed_effect.as_slice() == intent.admitted_effect_record()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        let disposition = current.classify(dataset, pin);
        let WorkspacePinObservationV1::Present(observed_pin) = pin else {
            return Ok(disposition);
        };
        if disposition != WorkspacePinRecoveryDispositionV1::CompletePublication {
            return Ok(disposition);
        }
        if current.phase() == WorkspacePinAttemptPhaseV1::Satisfied {
            if live_effect != sealed_completed_effect.as_slice() {
                return Err(StorageStateError::AuthorityLinkMismatch);
            }
            return Ok(disposition);
        }
        if live_effect != intent.admitted_effect_record() {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        let satisfied = current.satisfy(Some(observed_pin.clone()))?;
        self.validate_pin_attempt_context(&satisfied)?;
        let transaction = JournalTransaction::new(
            pin_attempt_transaction_id(&satisfied),
            vec![
                attempt_record(&satisfied, self.key.key_id, &self.key.secret)?,
                JournalRecord::put(
                    RecordNamespace::Effect,
                    intent.request_id().to_vec(),
                    sealed_completed_effect,
                ),
            ],
        )?;
        self.commit_journal_verified(&transaction)?;
        self.pin_attempts.insert(attempt_id, satisfied);
        Ok(disposition)
    }

    pub(crate) fn workspace_projection(
        &self,
    ) -> Result<Vec<StorageWorkspaceProjection>, StorageStateError> {
        self.workspace_projection_plan()?.ready_projection()
    }

    pub(crate) fn managed_workspace_creation(
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
        let transaction_id = finish_nonzero_transaction_id(hash);
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
                    (DurableStoragePhase::Aborted, None) => {
                        BeginStorageTransaction::Aborted { mutation_digest }
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
            (record.phase != DurableStoragePhase::Aborted
                && catalog_forks(record.catalog, catalog.binding()))
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

    pub(crate) fn catalog_head_binding(&self) -> Result<CatalogBindingV1, StorageStateError> {
        self.ensure_authority_readable()?;
        self.catalog_transitions
            .head_binding()
            .ok_or(StorageStateError::InvalidTransition)
    }

    /// Returns the protected journal head for a read-only authority cut.
    pub(crate) fn authority_head_sequence(&self) -> Result<u64, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(self.journal.snapshot_sequence())
    }

    /// Commits the current protected materialized state for a held-snapshot cut.
    ///
    /// This covers the ordered namespace, key, and value of every retained
    /// record plus the journal sequence. It is not a hash of append history or
    /// a substitute for reloading and validating the physical catalog. The
    /// exclusive journal lock and the pre/post cut comparison keep this view
    /// stable across the read-only worker dispatch.
    pub(crate) fn held_snapshot_materialized_state_digest(
        &self,
    ) -> Result<ObjectDigest, StorageStateError> {
        self.ensure_authority_readable()?;
        Ok(materialized_state_digest(
            self.journal.snapshot_sequence(),
            self.journal.all_records(),
        ))
    }

    /// Reloads the durable physical head and operation records for resolution.
    ///
    /// The method deliberately ignores the provider and record caches. Both
    /// views are authenticated again from the exclusively locked journal, and
    /// every committed result is rejoined to the freshly verified transition
    /// chain before the opaque source is returned.
    pub(crate) fn verified_resolver_journal(
        &self,
    ) -> Result<VerifiedStorageResolverJournalV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let physical = StorageCatalogTransitionProvider::load_resolver_snapshot(
            &self.journal,
            self.key.key_id,
            &self.key.secret,
        )?;
        let provider = StorageCatalogTransitionProvider::load(
            &self.journal,
            self.key.key_id,
            &self.key.secret,
        )?;
        if provider.head_binding() != Some(physical.binding()) {
            return Err(StorageStateError::CorruptRecord);
        }
        let genesis = provider
            .genesis_binding()
            .ok_or(StorageStateError::CorruptRecord)?;
        let durable = load_durable_records(&self.journal, &self.key)?;
        let atomic = load_atomic_snapshot_records(&self.journal, &self.key)?;
        validate_durable_records(&durable, &provider, &self.key)?;
        if durable
            .keys()
            .any(|operation| atomic.contains_key(operation))
        {
            return Err(StorageStateError::CorruptRecord);
        }
        validate_atomic_snapshot_catalog_join(&atomic, &provider)?;
        provider.validate_operation_set(durable.keys().chain(atomic.keys()).copied())?;
        let mut records = BTreeMap::new();
        for record in durable.into_values() {
            let Some(result) = record.result else {
                continue;
            };
            let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(&record.catalog_bytes)
                .map_err(|_| StorageStateError::CorruptRecord)?;
            records.insert(
                record.operation_id,
                VerifiedStorageResolverOperationV1 {
                    catalog,
                    result,
                    sandbox_id: record.sandbox_id,
                    request_digest: record.request_digest,
                },
            );
        }
        Ok(VerifiedStorageResolverJournalV1 {
            physical,
            genesis,
            records,
        })
    }

    pub(crate) fn catalog_preparation_record(
        &self,
        operation_id: &[u8; 16],
    ) -> Result<Option<&[u8]>, StorageStateError> {
        self.authority_record(RecordNamespace::StorageCatalogPreparation, operation_id)
    }

    pub(crate) fn catalog_preparation_records(
        &self,
    ) -> Result<Vec<CatalogPreparationRecord>, StorageStateError> {
        self.ensure_authority_readable()?;
        self.journal
            .records(RecordNamespace::StorageCatalogPreparation)
            .map(|(key, value)| {
                let operation_id = key
                    .try_into()
                    .map_err(|_| StorageStateError::CorruptRecord)?;
                Ok((operation_id, value.to_vec()))
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) const fn resolver_policy_floor(&self) -> Option<StorageResolverPolicyFloorV1> {
        self.resolver_policy_floor
    }

    pub(crate) fn admit_resolver_policy_catalog(
        &mut self,
        binding: StorageResolverPolicyCatalogBindingV1,
    ) -> Result<StorageResolverPolicyAdmissionOutcomeV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let durable_floor = self.fresh_resolver_policy_floor()?;
        if let Some(current) = durable_floor {
            if binding.generation() < current.generation
                || (binding.generation() == current.generation
                    && binding.digest() != current.catalog_digest)
            {
                return Err(StorageStateError::Rollback);
            }
            if binding.generation() == current.generation {
                return Ok(StorageResolverPolicyAdmissionOutcomeV1::Replay);
            }
        }

        let floor = StorageResolverPolicyFloorV1::from_binding(binding);
        let transaction = JournalTransaction::new(
            resolver_policy_floor_transaction_id(floor),
            vec![resolver_policy_floor_record(&self.key, floor)?],
        )?;
        self.commit_journal(&transaction)?;
        self.resolver_policy_floor = Some(floor);
        Ok(StorageResolverPolicyAdmissionOutcomeV1::Advanced)
    }

    pub(crate) fn validate_historical_resolver_policy(
        &self,
        binding: StorageResolverPolicyBindingV1,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        let floor = self
            .fresh_resolver_policy_floor()?
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if floor.generation < binding.generation()
            || (floor.generation == binding.generation()
                && floor.catalog_digest != binding.catalog_digest())
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_fresh_resolver_policy(
        &self,
        binding: StorageResolverPolicyBindingV1,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        let floor = self
            .fresh_resolver_policy_floor()?
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if binding.generation() != floor.generation
            || binding.catalog_digest() != floor.catalog_digest
        {
            return Err(StorageStateError::Rollback);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn retain_catalog_preparation(
        &mut self,
        operation_id: [u8; 16],
        sandbox_id: [u8; 16],
        request_id: [u8; 16],
        expected_head: CatalogBindingV1,
        sealed_fence: Vec<u8>,
        sealed_effect: Vec<u8>,
        sealed_operation_fence: Vec<u8>,
        sealed_preparation: Vec<u8>,
        policy_binding: StorageResolverPolicyBindingV1,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        if operation_id == [0; 16]
            || sandbox_id == [0; 16]
            || request_id == [0; 16]
            || sealed_fence.is_empty()
            || sealed_effect.is_empty()
            || sealed_operation_fence.is_empty()
            || sealed_preparation.is_empty()
            || sealed_fence.len() > MAXIMUM_RECORD_BYTES
            || sealed_effect.len() > MAXIMUM_RECORD_BYTES
            || sealed_operation_fence.len() > MAXIMUM_RECORD_BYTES
            || sealed_preparation.len() > MAXIMUM_PREPARATION_RECORD_BYTES
        {
            return Err(StorageStateError::InvalidValue);
        }
        if self.catalog_transitions.head_binding() != Some(expected_head) {
            return Err(StorageStateError::InvalidTransition);
        }
        self.validate_fresh_resolver_policy(policy_binding)?;
        if self.records.contains_key(&operation_id)
            || self
                .journal
                .get(RecordNamespace::StorageCatalogPreparation, &operation_id)
                .is_some()
            || self
                .journal
                .get(RecordNamespace::AuthorityPublication, &operation_id)
                .is_some()
            || self
                .journal
                .get(RecordNamespace::Effect, &request_id)
                .is_some()
        {
            return Err(StorageStateError::Equivocation);
        }
        let records = vec![
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
            JournalRecord::put(
                RecordNamespace::StorageCatalogPreparation,
                operation_id.to_vec(),
                sealed_preparation,
            ),
        ];
        let transaction =
            JournalTransaction::new(catalog_preparation_transaction_id(operation_id), records)?;
        self.commit_journal(&transaction)?;
        Ok(())
    }

    fn fresh_resolver_policy_floor(
        &self,
    ) -> Result<Option<StorageResolverPolicyFloorV1>, StorageStateError> {
        let durable = load_resolver_policy_floor(&self.journal, &self.key)?;
        if durable != self.resolver_policy_floor {
            return Err(StorageStateError::CorruptRecord);
        }
        Ok(durable)
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
    #[allow(clippy::unwrap_used)]
    pub(crate) fn put_resolver_policy_floor_for_test(
        &mut self,
        generation: u64,
        catalog_digest: ObjectDigest,
    ) {
        let floor = StorageResolverPolicyFloorV1 {
            generation,
            catalog_digest,
        };
        let record = resolver_policy_floor_record(&self.key, floor).unwrap();
        let transaction = JournalTransaction::new([229; 16], vec![record]).unwrap();
        self.journal.commit(&transaction).unwrap();
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn put_authority_record_with_transaction_for_test(
        &mut self,
        transaction_id: [u8; 16],
        namespace: RecordNamespace,
        key: &[u8],
        value: Vec<u8>,
    ) {
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(namespace, key.to_vec(), value)],
        )
        .unwrap();
        self.journal.commit(&transaction).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn fail_after_next_journal_commit_for_test(&mut self) {
        self.fail_after_next_journal_commit = true;
    }

    #[cfg(test)]
    pub(crate) fn journal_sequence_for_test(&self) -> u64 {
        self.journal.snapshot_sequence()
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
        self.begin_authorized(
            operation_id,
            request_digest,
            catalog,
            sandbox_id,
            request_id,
            sealed_fence,
            sealed_effect,
            sealed_operation_fence,
            publication_intent,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_authorized_with_consumed_preparation(
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
        preparation: CatalogPreparationConsumption,
    ) -> Result<BeginStorageTransaction, StorageStateError> {
        self.begin_authorized(
            operation_id,
            request_digest,
            catalog,
            sandbox_id,
            request_id,
            sealed_fence,
            sealed_effect,
            sealed_operation_fence,
            publication_intent,
            Some(preparation),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_authorized(
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
        preparation: Option<CatalogPreparationConsumption>,
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
            let metadata = intent.portable_metadata();
            if catalog.root_policy() != Some(metadata.root_policy())
                || metadata.request_id() != request_id
                || metadata.request_digest() != request_digest
                || metadata.assignment().sandbox().as_bytes() != &sandbox_id
                || metadata.assignment().digest() != intent.assignment_digest()
            {
                return Err(StorageStateError::AuthorityLinkMismatch);
            }
        }
        if let Some(preparation) = preparation.as_ref() {
            if self.catalog_transitions.head_binding() != Some(preparation.expected_head) {
                return Err(StorageStateError::InvalidTransition);
            }
            if self
                .journal
                .get(RecordNamespace::Effect, &request_id)
                .is_some()
            {
                return Err(StorageStateError::Equivocation);
            }
            if self
                .journal
                .get(RecordNamespace::StorageCatalogPreparation, &operation_id)
                != Some(preparation.prepared_record.as_slice())
            {
                return Err(StorageStateError::AuthorityLinkMismatch);
            }
        }
        let record = match self.prepare_record(operation_id, request_digest, catalog)? {
            PreparedRecord::Existing(outcome) => {
                if preparation.is_some() {
                    // A first-Apply transition must create the operation and
                    // replace Prepared in the same journal transaction.
                    return Err(StorageStateError::AuthorityLinkMismatch);
                }
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
        if let Some(preparation) = preparation {
            linked_records.push(JournalRecord::put(
                RecordNamespace::StorageCatalogPreparation,
                operation_id.to_vec(),
                preparation.consumed_record,
            ));
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

    /// Durably retires one exact Prepared intent without crossing Ambiguous.
    ///
    /// The authenticated operation tombstone and deletion of its sole pending
    /// physical-catalog reservation are one journal transaction. Authority,
    /// preparation, and workspace-publication records remain retained history.
    ///
    /// # Errors
    ///
    /// Returns [`StorageStateError::InvalidTransition`] unless `entry` and
    /// `catalog` identify the exact current Prepared operation and reservation.
    /// Returns [`StorageStateError::Journal`] if the atomic publication fails;
    /// an uncertain failure poisons the cached authority view until reopen.
    pub(crate) fn abort_prepared_exact(
        &mut self,
        entry: StorageRecoveryEntry,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<(), StorageStateError> {
        self.ensure_authority_readable()?;
        let current = self
            .records
            .get(&entry.operation_id)
            .filter(|record| recovery_entry(record) == entry)
            .ok_or(StorageStateError::InvalidTransition)?;
        if current.phase != DurableStoragePhase::Prepared
            || current.result.is_some()
            || current.request_digest != entry.request_digest
            || current.mutation_digest != entry.mutation_digest
            || current.catalog != catalog.binding()
            || current.catalog_bytes != catalog.canonical_bytes()
        {
            return Err(StorageStateError::InvalidTransition);
        }

        let reservation_deletion = self.catalog_transitions.aborted_reservation_record(
            current.operation_id,
            current.request_digest,
            current.mutation_digest,
            catalog,
            self.key.key_id,
            &self.key.secret,
        )?;
        let operation_id = current.operation_id;
        let mut aborted = current.clone();
        aborted.phase = DurableStoragePhase::Aborted;

        self.publish_with(aborted, vec![reservation_deletion])?;
        self.catalog_transitions.install_abort(operation_id);
        Ok(())
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
        self.preflight_effect_capacity(&record)?;
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_observed(
        &mut self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        observed: &PostconditionPolicyV1,
        observed_object_guid: Option<u64>,
        zfs_observation_digest: ObjectDigest,
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        self.commit_observed_with_supplement(
            operation_id,
            mutation_digest,
            catalog,
            observed,
            observed_object_guid,
            zfs_observation_digest,
            CatalogCommitSupplementV1::None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_observed_with_supplement(
        &mut self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        observed: &PostconditionPolicyV1,
        observed_object_guid: Option<u64>,
        zfs_observation_digest: ObjectDigest,
        supplement: CatalogCommitSupplementV1,
    ) -> Result<CommittedStorageResultV1, StorageStateError> {
        self.ensure_authority_readable()?;
        let mut record = self.exact_current(operation_id, mutation_digest)?.clone();
        if record.phase != DurableStoragePhase::Ambiguous
            || record.catalog != catalog.binding()
            || record.catalog_bytes != catalog.canonical_bytes()
        {
            return Err(StorageStateError::InvalidTransition);
        }

        let transition = self
            .catalog_transitions
            .prepare_transition_with_supplement(
                operation_id,
                mutation_digest,
                catalog,
                observed_object_guid,
                zfs_observation_digest,
                supplement,
                self.key.key_id,
                &self.key.secret,
            )?;
        if let Some(metadata) = transition.snapshot_metadata() {
            self.validate_snapshot_metadata_authority(metadata, &record, catalog)?;
        }
        let verified = VerifiedStorageResultV1::verify_observation(
            operation_id,
            record.request_digest,
            catalog,
            observed,
            observed_object_guid,
            transition.result_binding(),
            transition.observation_digest(),
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
                (existing.phase != DurableStoragePhase::Aborted
                    && catalog_forks(existing.catalog, verified.result_catalog))
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

        let completion_transaction = self.effect_completion_capacity_transaction(prepared)?;

        self.journal
            .preflight_transactions(&[ambiguous_transaction, completion_transaction])?;
        Ok(())
    }

    fn effect_completion_capacity_transaction(
        &self,
        prepared: &DurableRecord,
    ) -> Result<JournalTransaction, StorageStateError> {
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
        JournalTransaction::new(
            transaction_id(prepared.operation_id, DurableStoragePhase::Committed),
            completion_records,
        )
        .map_err(Into::into)
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
        // The closed Repair guard conservatively freezes every Storage state
        // transition, not only writes that visibly name its workspace.
        if self.has_held_repair_guard() {
            return Err(StorageStateError::InvalidTransition);
        }
        self.commit_journal_unfenced(transaction)
    }

    /// Reports a MAC-authenticated, restart-persistent Repair hold.
    pub(crate) fn has_held_repair_guard(&self) -> bool {
        self.repair_guards
            .values()
            .any(repair_guard::StorageRepairGuardRecordV1::is_held)
    }

    // Only the closed guard resolver may call this while a held row exists.
    fn commit_journal_unfenced(
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

    // These effects cannot publish their cached state until every committed
    // record is visible under its exact namespace and key.
    fn commit_journal_verified(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<(), StorageStateError> {
        self.commit_journal(transaction)?;
        if transaction
            .records()
            .iter()
            .any(|record| self.journal.get(record.namespace(), record.key()) != record.value())
        {
            self.commit_failed = true;
            return Err(aos_sandbox::JournalError::Poisoned.into());
        }
        Ok(())
    }

    fn operation_fence_digest(
        &self,
        operation_id: [u8; 16],
    ) -> Result<ObjectDigest, StorageStateError> {
        let bytes = self
            .journal
            .get(RecordNamespace::AuthorityPublication, &operation_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        Ok(ObjectDigest::from_bytes(Sha256::digest(bytes).into()))
    }

    fn validate_pin_attempt_context(
        &self,
        attempt: &WorkspacePinAttemptV1,
    ) -> Result<(), StorageStateError> {
        let creation = self
            .records
            .get(&attempt.creation_operation_id())
            .filter(|record| record.phase == DurableStoragePhase::Committed)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let result = creation
            .result
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let intent = self
            .publication_intents
            .get(&creation.operation_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let creation_catalog =
            ResolvedCatalogCommitmentV1::from_canonical_bytes(&creation.catalog_bytes)
                .map_err(|_| StorageStateError::CorruptRecord)?;
        let creation_dataset_name = match creation_catalog.plan() {
            CatalogPlanV1::CreateWorkspace { destination, .. }
            | CatalogPlanV1::Clone { destination, .. } => destination.name(),
            _ => return Err(StorageStateError::AuthorityLinkMismatch),
        };
        if result.catalog() != attempt.creation_result_catalog()
            || result.result_digest() != attempt.creation_result_digest()
            || result.storage_handle() != Some(attempt.workspace_handle())
            || result.object_guid() != Some(attempt.dataset_guid())
            || creation_dataset_name != attempt.dataset_name()
            || intent.assignment_digest() != attempt.workspace_assignment_digest()
            || intent.identity_range_start() != attempt.identity_range_start()
            || intent.identity_range_size() != attempt.identity_range_size()
            || self.operation_fence_digest(attempt.effect_operation_id())?
                != attempt.operation_fence_digest()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        match attempt.action() {
            WorkspacePinActionV1::Ensure
                if attempt.effect_operation_id() == attempt.creation_operation_id()
                    && attempt.effect_assignment_digest()
                        == attempt.workspace_assignment_digest() =>
            {
                Ok(())
            }
            WorkspacePinActionV1::Ensure => {
                let repair = self
                    .repair_intents
                    .get(&attempt.effect_operation_id())
                    .filter(|repair| repair.repair_attempt_id() == attempt.attempt_id())
                    .ok_or(StorageStateError::MissingAuthorityLink)?;
                if repair.creation_operation_id() != attempt.creation_operation_id()
                    || repair.workspace_handle() != attempt.workspace_handle()
                    || repair.repair_assignment_digest() != attempt.effect_assignment_digest()
                    || repair.operation_fence_digest() != attempt.operation_fence_digest()
                {
                    return Err(StorageStateError::AuthorityLinkMismatch);
                }
                Ok(())
            }
            WorkspacePinActionV1::RemoveAndDestroy => {
                let destruction = self
                    .records
                    .get(&attempt.effect_operation_id())
                    .ok_or(StorageStateError::MissingAuthorityLink)?;
                let catalog =
                    ResolvedCatalogCommitmentV1::from_canonical_bytes(&destruction.catalog_bytes)
                        .map_err(|_| StorageStateError::CorruptRecord)?;
                let CatalogPlanV1::DestroyDataset { dataset } = catalog.plan() else {
                    return Err(StorageStateError::AuthorityLinkMismatch);
                };
                if !matches!(
                    destruction.phase,
                    DurableStoragePhase::Prepared
                        | DurableStoragePhase::Ambiguous
                        | DurableStoragePhase::Committed
                ) || dataset.name() != attempt.dataset_name()
                    || dataset.guid() != attempt.dataset_guid()
                    || dataset.storage_handle() != attempt.workspace_handle()
                    || attempt.expected_pin().is_none()
                {
                    return Err(StorageStateError::AuthorityLinkMismatch);
                }
                Ok(())
            }
        }
    }

    fn validate_snapshot_metadata_authority(
        &self,
        metadata: CheckedSnapshotMetadataRecordV1,
        snapshot_record: &DurableRecord,
        snapshot_catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<(), StorageStateError> {
        let CatalogPlanV1::Snapshot { source, .. } = snapshot_catalog.plan() else {
            return Err(StorageStateError::AuthorityLinkMismatch);
        };
        if metadata.operation_id() != snapshot_record.operation_id
            || metadata.request_digest() != snapshot_record.request_digest
            || metadata.mutation_digest() != snapshot_record.mutation_digest
            || metadata.request_catalog() != snapshot_record.catalog
            || metadata.source_dataset_guid() != source.guid()
            || metadata.source_storage_handle() != source.storage_handle()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        let source_operation_id = metadata.source_creation_operation_id();
        let source_record = self
            .records
            .get(&source_operation_id)
            .filter(|record| record.phase == DurableStoragePhase::Committed)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let source_result = source_record
            .result
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let source_catalog =
            ResolvedCatalogCommitmentV1::from_canonical_bytes(&source_record.catalog_bytes)
                .map_err(|_| StorageStateError::CorruptRecord)?;
        let source_name = match source_catalog.plan() {
            CatalogPlanV1::CreateWorkspace { destination, .. }
            | CatalogPlanV1::Clone { destination, .. } => destination.name(),
            _ => return Err(StorageStateError::AuthorityLinkMismatch),
        };
        if source_result.storage_handle() != Some(source.storage_handle())
            || source_result.object_guid() != Some(source.guid())
            || source_result.immutable_version_handle().is_some()
            || source_name != source.name()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        let publication = self
            .publication_intents
            .get(&source_operation_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let publication_bytes = self
            .journal
            .get(
                RecordNamespace::StorageWorkspacePublicationIntent,
                &source_operation_id,
            )
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if publication.request_catalog() != source_record.catalog
            || digest_bytes(publication_bytes) != metadata.source_publication_record_digest()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        let pin_attempt_id = metadata.source_pin_attempt_id();
        let pin_attempt = self
            .pin_attempts
            .get(&pin_attempt_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        self.validate_pin_attempt_context(pin_attempt)?;
        let pin_bytes = self
            .journal
            .get(RecordNamespace::StorageWorkspacePinAttempt, &pin_attempt_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let pin_root = pin_attempt
            .satisfied_pin()
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if pin_attempt.action() != WorkspacePinActionV1::Ensure
            || pin_attempt.phase() != WorkspacePinAttemptPhaseV1::Satisfied
            || pin_attempt.creation_operation_id() != source_operation_id
            || pin_attempt.creation_result_catalog() != source_result.catalog()
            || pin_attempt.creation_result_digest() != source_result.result_digest()
            || pin_attempt.workspace_handle() != source.storage_handle()
            || pin_attempt.dataset_guid() != source.guid()
            || pin_attempt.dataset_name() != source.name()
            || pin_root.root_attributes() != metadata.root_attributes()
            || metadata.maximum_portable_uid() >= pin_attempt.identity_range_size()
            || metadata.maximum_portable_gid() >= pin_attempt.identity_range_size()
            || digest_bytes(pin_bytes) != metadata.source_pin_record_digest()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok(())
    }

    fn validate_snapshot_metadata_authority_set(&self) -> Result<(), StorageStateError> {
        for record in self.records.values() {
            let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(&record.catalog_bytes)
                .map_err(|_| StorageStateError::CorruptRecord)?;
            let evidence = self.catalog_transitions.validates_operation_transition(
                record.format_version,
                record.operation_id,
                record.request_digest,
                record.mutation_digest,
                &catalog,
                record.phase,
                record.result.map(|result| result.catalog),
                self.key.key_id,
                &self.key.secret,
            )?;
            match (catalog.plan(), record.phase, evidence) {
                (
                    CatalogPlanV1::Snapshot { .. },
                    DurableStoragePhase::Committed,
                    Some(evidence),
                ) => self
                    .validate_snapshot_metadata_authority(
                        evidence
                            .snapshot_metadata
                            .ok_or(StorageStateError::CorruptRecord)?,
                        record,
                        &catalog,
                    )
                    .map_err(|_| StorageStateError::CorruptRecord)?,
                (CatalogPlanV1::Snapshot { .. }, _, None) => {}
                (CatalogPlanV1::Snapshot { .. }, _, Some(_)) => {
                    return Err(StorageStateError::CorruptRecord);
                }
                (_, _, Some(evidence)) if evidence.snapshot_metadata.is_some() => {
                    return Err(StorageStateError::CorruptRecord);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn preflight_pin_attempt(
        &self,
        attempt: &WorkspacePinAttemptV1,
    ) -> Result<(), StorageStateError> {
        let ambiguous = JournalTransaction::new(
            pin_attempt_transaction_id(attempt),
            vec![attempt_record(attempt, self.key.key_id, &self.key.secret)?],
        )?;
        let satisfied = self.pin_satisfied_capacity_transaction(attempt)?;
        self.journal
            .preflight_transactions(&[ambiguous, satisfied])?;
        Ok(())
    }

    fn pin_satisfied_capacity_transaction(
        &self,
        attempt: &WorkspacePinAttemptV1,
    ) -> Result<JournalTransaction, StorageStateError> {
        let completion = attempt.capacity_completion()?;
        JournalTransaction::new(
            pin_attempt_transaction_id(&completion),
            vec![attempt_record(
                &completion,
                self.key.key_id,
                &self.key.secret,
            )?],
        )
        .map_err(Into::into)
    }

    pub(crate) fn ensure_authority_readable(&self) -> Result<(), StorageStateError> {
        if self.commit_failed {
            Err(aos_sandbox::JournalError::Poisoned.into())
        } else {
            Ok(())
        }
    }

    /// Reports whether an uncertain commit invalidated the in-memory projection.
    pub(crate) const fn requires_reopen(&self) -> bool {
        self.commit_failed
    }

    pub(crate) fn poison_after_committed_repair_failure(&mut self) {
        self.commit_failed = true;
    }
}

fn materialized_state_digest<'a>(
    sequence: u64,
    records: impl Iterator<Item = (RecordNamespace, &'a [u8], &'a [u8])>,
) -> ObjectDigest {
    let mut hash = Sha256::new();
    hash.update(HELD_SNAPSHOT_STATE_DOMAIN);
    hash.update(sequence.to_be_bytes());
    for (namespace, key, value) in records {
        hash.update([namespace as u8]);
        hash.update((key.len() as u64).to_be_bytes());
        hash.update(key);
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    ObjectDigest::from_bytes(hash.finalize().into())
}

fn load_guest_root_attempts(
    journal: &Journal,
    key: &StorageStateKey,
) -> Result<BTreeMap<[u8; 16], GuestRootPublicationAttemptV1>, StorageStateError> {
    let mut attempts = BTreeMap::new();
    for (record_key, bytes) in journal.records(RecordNamespace::StorageGuestRootPublicationAttempt)
    {
        let operation: [u8; 16] = record_key
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let attempt = key.open_guest_root_publication_attempt(operation, bytes)?;
        if attempts.insert(operation, attempt).is_some() {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    Ok(attempts)
}

fn guest_root_attempt_transaction_id(effect_operation: [u8; 16]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.storage.guest-root-attempt-transaction.v1\0");
    hash.update(effect_operation);
    let digest = hash.finalize();
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    if transaction_id == [0; 16] {
        transaction_id[0] = 1;
    }
    transaction_id
}

fn validate_guest_root_attempt_set(
    journal: &Journal,
    records: &BTreeMap<[u8; 16], DurableRecord>,
    publications: &BTreeMap<[u8; 16], StorageWorkspacePublicationIntentV1>,
    attempts: &BTreeMap<[u8; 16], GuestRootPublicationAttemptV1>,
) -> Result<(), StorageStateError> {
    for attempt in attempts.values() {
        let proof = attempt.expected_proof;
        let creation = records
            .get(&proof.creation_operation)
            .filter(|record| record.phase == DurableStoragePhase::Committed)
            .and_then(|record| record.result)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let publication = publications
            .get(&proof.creation_operation)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let sealed_effect = journal
            .get(RecordNamespace::Effect, &attempt.request_id)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let sealed_fence = journal
            .get(
                RecordNamespace::AuthorityPublication,
                &attempt.effect_operation,
            )
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if records.contains_key(&attempt.effect_operation)
            || creation.storage_handle() != Some(proof.workspace_handle)
            || creation.object_guid() != Some(proof.dataset_guid)
            || publication.assignment_digest().as_bytes() != &proof.assignment_digest
            || publication.root_image().digest().as_bytes() != &proof.root_image_digest
            || Sha256::digest(sealed_effect).as_slice() != attempt.sealed_effect_digest
            || Sha256::digest(sealed_fence).as_slice() != attempt.operation_fence_digest
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
    }
    Ok(())
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

fn load_durable_records(
    journal: &Journal,
    key: &StorageStateKey,
) -> Result<BTreeMap<[u8; 16], DurableRecord>, StorageStateError> {
    let mut records = BTreeMap::new();
    for (record_key, bytes) in journal.records(RecordNamespace::Operation) {
        let record = decode_record(bytes, key)?;
        if record_key != record.operation_id
            || records.insert(record.operation_id, record).is_some()
        {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    Ok(records)
}

fn atomic_snapshot_record_key(operation: [u8; 16]) -> Vec<u8> {
    [ATOMIC_SNAPSHOT_KEY_PREFIX.as_slice(), operation.as_slice()].concat()
}

fn atomic_snapshot_transaction_id(
    operation: [u8; 16],
    phase: AtomicDatasetSnapshotPhaseV1,
) -> [u8; 16] {
    let hash = Sha256::new()
        .chain_update(b"aos.sandbox.storage.atomic-snapshot-transaction.v1\0")
        .chain_update(operation)
        .chain_update([phase as u8]);
    finish_nonzero_transaction_id(hash)
}

fn atomic_snapshot_transaction(
    record: &AtomicDatasetSnapshotRecordV1,
    key: &StorageStateKey,
) -> Result<JournalTransaction, StorageStateError> {
    let operation = record.program.operation();
    JournalTransaction::new(
        atomic_snapshot_transaction_id(operation, record.phase),
        vec![JournalRecord::put(
            RecordNamespace::Effect,
            atomic_snapshot_record_key(operation),
            encode_atomic_snapshot_record(record, key)?,
        )],
    )
    .map_err(Into::into)
}

fn encode_atomic_snapshot_record(
    record: &AtomicDatasetSnapshotRecordV1,
    key: &StorageStateKey,
) -> Result<Vec<u8>, StorageStateError> {
    let version = if record.post_head.is_some() {
        if record.phase != AtomicDatasetSnapshotPhaseV1::Committed
            || record.observation.is_none()
            || record.post_head.is_some_and(|head| {
                record.program.format_version() != 2
                    || record.program.catalog_generation().checked_add(1) != Some(head.generation())
                    || record.program.catalog_head() == head.digest()
            })
        {
            return Err(StorageStateError::InvalidValue);
        }
        ATOMIC_SNAPSHOT_VERSION_V3
    } else {
        ATOMIC_SNAPSHOT_VERSION_V2
    };
    let program = record
        .program
        .canonical_bytes()
        .map_err(|_| StorageStateError::InvalidValue)?;
    let program_length =
        u32::try_from(program.len()).map_err(|_| StorageStateError::InvalidValue)?;
    let mut bytes = Vec::with_capacity(104 + program.len());
    bytes.extend_from_slice(ATOMIC_SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.push(record.phase as u8);
    bytes.extend_from_slice(&key.key_id);
    bytes.extend_from_slice(&record.sandbox_id);
    bytes.extend_from_slice(&record.request_id);
    bytes.extend_from_slice(record.semantic_digest.as_bytes());
    bytes.extend_from_slice(record.transport_digest.as_bytes());
    bytes.extend_from_slice(&program_length.to_be_bytes());
    bytes.extend_from_slice(&program);
    bytes.extend_from_slice(
        record
            .observation
            .unwrap_or(ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
    if let Some(head) = record.post_head {
        bytes.extend_from_slice(&head.generation().to_be_bytes());
        bytes.extend_from_slice(head.digest().as_bytes());
    }
    let mut mac =
        HmacSha256::new_from_slice(&key.secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(if version == ATOMIC_SNAPSHOT_VERSION_V3 {
        ATOMIC_SNAPSHOT_DOMAIN_V3
    } else {
        ATOMIC_SNAPSHOT_DOMAIN_V2
    });
    mac.update(&record.program.operation());
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    Ok(bytes)
}

fn decode_atomic_snapshot_record(
    operation: [u8; 16],
    encoded: &[u8],
    key: &StorageStateKey,
) -> Result<AtomicDatasetSnapshotRecordV1, StorageStateError> {
    let body_length = encoded
        .len()
        .checked_sub(MAC_BYTES)
        .ok_or(StorageStateError::CorruptRecord)?;
    let (body, tag) = encoded.split_at(body_length);
    let version = body
        .get(8..10)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes)
        .ok_or(StorageStateError::CorruptRecord)?;
    let domain = match version {
        ATOMIC_SNAPSHOT_VERSION_V2 => ATOMIC_SNAPSHOT_DOMAIN_V2,
        ATOMIC_SNAPSHOT_VERSION_V3 => ATOMIC_SNAPSHOT_DOMAIN_V3,
        _ => return Err(StorageStateError::CorruptRecord),
    };
    let mut mac =
        HmacSha256::new_from_slice(&key.secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(domain);
    mac.update(&operation);
    mac.update(body);
    mac.verify_slice(tag)
        .map_err(|_| StorageStateError::CorruptRecord)?;
    let mut body = body;
    if take(&mut body, 8)? != ATOMIC_SNAPSHOT_MAGIC
        || u16::from_be_bytes(take_array(&mut body)?) != version
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let phase = match take(&mut body, 1)?[0] {
        1 => AtomicDatasetSnapshotPhaseV1::Prepared,
        2 => AtomicDatasetSnapshotPhaseV1::Ambiguous,
        3 => AtomicDatasetSnapshotPhaseV1::Committed,
        _ => return Err(StorageStateError::CorruptRecord),
    };
    if take(&mut body, 16)? != key.key_id {
        return Err(StorageStateError::CorruptRecord);
    }
    let sandbox_id = take_array(&mut body)?;
    let request_id = take_array(&mut body)?;
    let semantic_digest = ObjectDigest::from_bytes(take_array(&mut body)?);
    let transport_digest = ObjectDigest::from_bytes(take_array(&mut body)?);
    if sandbox_id == [0; 16]
        || request_id == [0; 16]
        || semantic_digest.as_bytes() == &[0; 32]
        || transport_digest.as_bytes() == &[0; 32]
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let program_length = usize::try_from(u32::from_be_bytes(take_array(&mut body)?))
        .map_err(|_| StorageStateError::CorruptRecord)?;
    let program = crate::DormantAtomicDatasetSnapshotV1::from_canonical_bytes(take(
        &mut body,
        program_length,
    )?)
    .map_err(|_| StorageStateError::CorruptRecord)?;
    let observation = ObjectDigest::from_bytes(take_array(&mut body)?);
    let post_head = if version == ATOMIC_SNAPSHOT_VERSION_V3 {
        let generation = u64::from_be_bytes(take_array(&mut body)?);
        let digest = ObjectDigest::from_bytes(take_array(&mut body)?);
        Some(
            CatalogBindingV1::from_publisher(generation, digest)
                .map_err(|_| StorageStateError::CorruptRecord)?,
        )
    } else {
        None
    };
    if !body.is_empty() || program.operation() != operation {
        return Err(StorageStateError::CorruptRecord);
    }
    let observation = match (phase, observation.as_bytes() == &[0; 32]) {
        (AtomicDatasetSnapshotPhaseV1::Committed, false) => Some(observation),
        (
            AtomicDatasetSnapshotPhaseV1::Prepared | AtomicDatasetSnapshotPhaseV1::Ambiguous,
            true,
        ) => None,
        _ => return Err(StorageStateError::CorruptRecord),
    };
    if post_head.is_some_and(|head| {
        phase != AtomicDatasetSnapshotPhaseV1::Committed
            || program.format_version() != 2
            || program.catalog_generation().checked_add(1) != Some(head.generation())
            || program.catalog_head() == head.digest()
    }) {
        return Err(StorageStateError::CorruptRecord);
    }
    let record = AtomicDatasetSnapshotRecordV1 {
        phase,
        program,
        observation,
        sandbox_id,
        request_id,
        semantic_digest,
        transport_digest,
        post_head,
    };
    if encode_atomic_snapshot_record(&record, key)? != encoded {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(record)
}

fn load_atomic_snapshot_records(
    journal: &Journal,
    key: &StorageStateKey,
) -> Result<BTreeMap<[u8; 16], AtomicDatasetSnapshotRecordV1>, StorageStateError> {
    let mut records = BTreeMap::new();
    for (record_key, bytes) in journal.records(RecordNamespace::Effect) {
        let Some(operation) = record_key
            .strip_prefix(ATOMIC_SNAPSHOT_KEY_PREFIX)
            .and_then(|value| <[u8; 16]>::try_from(value).ok())
        else {
            continue;
        };
        let record = decode_atomic_snapshot_record(operation, bytes, key)?;
        if records.insert(operation, record).is_some() {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    Ok(records)
}

fn validate_atomic_snapshot_catalog_join(
    records: &BTreeMap<[u8; 16], AtomicDatasetSnapshotRecordV1>,
    catalog: &StorageCatalogTransitionProvider,
) -> Result<(), StorageStateError> {
    for (operation, record) in records {
        if *operation != record.program.operation() {
            return Err(StorageStateError::CorruptRecord);
        }
        let committed = match record.phase {
            AtomicDatasetSnapshotPhaseV1::Prepared | AtomicDatasetSnapshotPhaseV1::Ambiguous => {
                None
            }
            AtomicDatasetSnapshotPhaseV1::Committed if record.program.format_version() == 1 => None,
            AtomicDatasetSnapshotPhaseV1::Committed => Some((
                record.observation.ok_or(StorageStateError::CorruptRecord)?,
                record.post_head.ok_or(StorageStateError::CorruptRecord)?,
            )),
        };
        catalog.validate_atomic_group_record(&record.program, record.semantic_digest, committed)?;
    }
    Ok(())
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], StorageStateError> {
    if bytes.len() < length {
        return Err(StorageStateError::CorruptRecord);
    }
    let (value, rest) = bytes.split_at(length);
    *bytes = rest;
    Ok(value)
}

fn take_array<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], StorageStateError> {
    take(bytes, N)?
        .try_into()
        .map_err(|_| StorageStateError::CorruptRecord)
}

fn validate_durable_records(
    records: &BTreeMap<[u8; 16], DurableRecord>,
    catalog_transitions: &StorageCatalogTransitionProvider,
    key: &StorageStateKey,
) -> Result<(), StorageStateError> {
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
                if committed_result_with_key(key, &verified)? != result {
                    return Err(StorageStateError::CorruptRecord);
                }
            }
            (None, None) => {}
            _ => return Err(StorageStateError::CorruptRecord),
        }
    }
    Ok(())
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
        let metadata = intent.portable_metadata();
        if catalog.root_policy() != Some(metadata.root_policy())
            || metadata.request_id() != record.request_id
            || metadata.request_digest() != record.request_digest
            || metadata.assignment().sandbox().as_bytes() != &record.sandbox_id
            || metadata.assignment().digest() != intent.assignment_digest()
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

fn validate_repair_intent_set(
    journal: &Journal,
    records: &BTreeMap<[u8; 16], DurableRecord>,
    publication_intents: &BTreeMap<[u8; 16], StorageWorkspacePublicationIntentV1>,
    pin_attempts: &BTreeMap<[u8; 16], WorkspacePinAttemptV1>,
    repair_intents: &BTreeMap<[u8; 16], StorageWorkspacePinRepairIntentV1>,
) -> Result<(), StorageStateError> {
    for intent in repair_intents.values() {
        if records.contains_key(&intent.repair_operation_id())
            || journal
                .get(RecordNamespace::Effect, &intent.request_id())
                .is_none()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        let operation_fence = journal
            .get(
                RecordNamespace::AuthorityPublication,
                &intent.repair_operation_id(),
            )
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if digest_bytes(operation_fence) != intent.operation_fence_digest()
            || digest_bytes(intent.admitted_effect_record())
                != intent.admitted_effect_record_digest()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        let creation = records
            .get(&intent.creation_operation_id())
            .filter(|record| record.phase == DurableStoragePhase::Committed)
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let creation_result = creation
            .result
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let publication_record = journal
            .get(
                RecordNamespace::StorageWorkspacePublicationIntent,
                &intent.creation_operation_id(),
            )
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        if creation_result.catalog() != intent.creation_result_catalog()
            || creation_result.result_digest() != intent.creation_result_digest()
            || creation_result.storage_handle() != Some(intent.workspace_handle())
            || publication_intents
                .get(&intent.creation_operation_id())
                .is_none()
            || digest_bytes(publication_record) != intent.publication_intent_record_digest()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }

        let repair_attempt = pin_attempts
            .get(&intent.repair_attempt_id())
            .ok_or(StorageStateError::MissingAuthorityLink)?;
        let predecessor_is_valid = match intent.predecessor() {
            WorkspacePinRepairIntentPredecessorV1::MissingInitial {
                creation_record_digest,
            } => {
                let creation_record = journal
                    .get(RecordNamespace::Operation, &intent.creation_operation_id())
                    .ok_or(StorageStateError::MissingAuthorityLink)?;
                digest_bytes(creation_record) == creation_record_digest
                    && intent.repair_attempt_ordinal() == 1
                    && pin_attempts.values().all(|attempt| {
                        (attempt.workspace_handle() != intent.workspace_handle()
                            && attempt.creation_operation_id() != intent.creation_operation_id())
                            || attempt.attempt_ordinal() != 1
                            || attempt.attempt_id() == intent.repair_attempt_id()
                    })
            }
            WorkspacePinRepairIntentPredecessorV1::ExistingAttempt {
                attempt_id,
                phase,
                record_digest,
            } => {
                let latest_ensure = pin_attempts
                    .get(&attempt_id)
                    .ok_or(StorageStateError::MissingAuthorityLink)?;
                let latest_ensure_record = journal
                    .get(RecordNamespace::StorageWorkspacePinAttempt, &attempt_id)
                    .ok_or(StorageStateError::MissingAuthorityLink)?;
                latest_ensure.action() == WorkspacePinActionV1::Ensure
                    && latest_ensure.phase() == phase
                    && latest_ensure.creation_operation_id() == intent.creation_operation_id()
                    && latest_ensure.workspace_handle() == intent.workspace_handle()
                    && digest_bytes(latest_ensure_record) == record_digest
                    && latest_ensure
                        .attempt_ordinal()
                        .checked_add(1)
                        .is_some_and(|ordinal| ordinal == intent.repair_attempt_ordinal())
            }
        };
        if !predecessor_is_valid
            || repair_attempt.action() != WorkspacePinActionV1::Ensure
            || repair_attempt.effect_operation_id() != intent.repair_operation_id()
            || repair_attempt.creation_operation_id() != intent.creation_operation_id()
            || repair_attempt.operation_fence_digest() != intent.operation_fence_digest()
            || repair_attempt.effect_assignment_digest() != intent.repair_assignment_digest()
            || repair_attempt.creation_result_catalog() != intent.creation_result_catalog()
            || repair_attempt.creation_result_digest() != intent.creation_result_digest()
            || repair_attempt.workspace_handle() != intent.workspace_handle()
            || repair_attempt.attempt_ordinal() != intent.repair_attempt_ordinal()
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
    }

    for attempt in pin_attempts.values().filter(|attempt| {
        attempt.action() == WorkspacePinActionV1::Ensure
            && attempt.effect_operation_id() != attempt.creation_operation_id()
    }) {
        let matching = repair_intents
            .values()
            .filter(|intent| intent.repair_attempt_id() == attempt.attempt_id())
            .count();
        if matching != 1 {
            return Err(StorageStateError::MissingAuthorityLink);
        }
    }
    Ok(())
}

fn requires_workspace_publication(plan: &CatalogPlanV1) -> bool {
    matches!(
        plan,
        CatalogPlanV1::CreateWorkspace { .. } | CatalogPlanV1::Clone { .. }
    )
}

fn digest_bytes(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

fn publication_intent_record(
    key: &StorageStateKey,
    intent: &StorageWorkspacePublicationIntentV1,
) -> Result<JournalRecord, StorageStateError> {
    let record_key = intent.operation_id().to_vec();
    let media_type = intent.root_image().media_type().as_str().as_bytes();
    let media_length =
        u16::try_from(media_type.len()).map_err(|_| StorageStateError::InvalidValue)?;
    let version = PUBLICATION_INTENT_VERSION;
    let mut bytes = Vec::with_capacity(512 + media_type.len());
    bytes.extend_from_slice(PUBLICATION_INTENT_MAGIC);
    bytes.extend_from_slice(&version.to_be_bytes());
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
    let metadata = intent.portable_metadata();
    bytes.extend_from_slice(&metadata.request_id());
    bytes.extend_from_slice(metadata.request_digest().as_bytes());
    let assignment = metadata.assignment();
    bytes.extend_from_slice(assignment.sandbox().as_bytes());
    bytes.extend_from_slice(assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(&assignment.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(assignment.digest().as_bytes());
    bytes.extend_from_slice(metadata.node().as_bytes());
    bytes.extend_from_slice(&metadata.root_policy().canonical_bytes());
    put_u32_bytes(&mut bytes, metadata.manifest_bytes())?;
    put_u32_bytes(&mut bytes, metadata.sandbox_spec_bytes())?;
    let tag = publication_intent_tag(key, &record_key, &bytes)?;
    bytes.extend_from_slice(&tag);
    if bytes.len() > MAXIMUM_WORKSPACE_PUBLICATION_INTENT_RECORD_BYTES {
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
    if bytes.len() > MAXIMUM_WORKSPACE_PUBLICATION_INTENT_RECORD_BYTES || bytes.len() < 197 {
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
    if decoder.take(8)? != PUBLICATION_INTENT_MAGIC {
        return Err(StorageStateError::CorruptRecord);
    }
    let version = decoder.u16()?;
    if version != PUBLICATION_INTENT_VERSION || decoder.array::<16>()? != key.key_id {
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
    let request_id = decoder.array()?;
    let request_digest = ObjectDigest::from_bytes(decoder.array()?);
    let assignment = BrokerAssignment::new(
        SandboxId::from_bytes(decoder.array()?),
        IncarnationId::from_bytes(decoder.array()?),
        AssignmentEpoch::new(decoder.u64()?),
        DesiredGeneration::new(decoder.u64()?),
        ObjectDigest::from_bytes(decoder.array()?),
    )
    .map_err(|_| StorageStateError::CorruptRecord)?;
    let node = NodeId::from_bytes(decoder.array()?);
    let root_policy =
        crate::root_policy::WorkspaceRootPolicyV1::from_canonical_bytes(decoder.take(64)?)
            .map_err(|_| StorageStateError::CorruptRecord)?;
    let manifest_bytes = decoder.u32_bytes(48 * 1024)?.to_vec();
    let sandbox_spec_bytes = decoder.u32_bytes(16 * 1024)?.to_vec();
    let portable_metadata = DurablePortableWorkspaceMetadataV1::new(
        request_id,
        request_digest,
        assignment,
        node,
        root_policy,
        manifest_bytes,
        sandbox_spec_bytes,
    )
    .map_err(|_| StorageStateError::CorruptRecord)?;
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
        portable_metadata,
    )
    .map_err(|_| StorageStateError::CorruptRecord)
}

fn put_u32_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), StorageStateError> {
    let length = u32::try_from(value.len()).map_err(|_| StorageStateError::InvalidValue)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
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

fn load_resolver_policy_floor(
    journal: &Journal,
    key: &StorageStateKey,
) -> Result<Option<StorageResolverPolicyFloorV1>, StorageStateError> {
    let mut records = journal.records(RecordNamespace::StorageResolverPolicyFloor);
    let Some((record_key, bytes)) = records.next() else {
        return Ok(None);
    };
    if record_key != RESOLVER_POLICY_FLOOR_KEY || records.next().is_some() {
        return Err(StorageStateError::CorruptRecord);
    }
    decode_resolver_policy_floor(key, bytes).map(Some)
}

fn resolver_policy_floor_record(
    key: &StorageStateKey,
    floor: StorageResolverPolicyFloorV1,
) -> Result<JournalRecord, StorageStateError> {
    if floor.generation == 0 || floor.catalog_digest.as_bytes() == &[0; 32] {
        return Err(StorageStateError::InvalidValue);
    }
    let mut bytes = Vec::with_capacity(98);
    bytes.extend_from_slice(RESOLVER_POLICY_FLOOR_MAGIC);
    bytes.extend_from_slice(&RESOLVER_POLICY_FLOOR_VERSION.to_be_bytes());
    bytes.extend_from_slice(&key.key_id);
    bytes.extend_from_slice(&floor.generation.to_be_bytes());
    bytes.extend_from_slice(floor.catalog_digest.as_bytes());
    let tag = resolver_policy_floor_tag(key, &bytes)?;
    bytes.extend_from_slice(&tag);
    Ok(JournalRecord::put(
        RecordNamespace::StorageResolverPolicyFloor,
        RESOLVER_POLICY_FLOOR_KEY.to_vec(),
        bytes,
    ))
}

fn decode_resolver_policy_floor(
    key: &StorageStateKey,
    bytes: &[u8],
) -> Result<StorageResolverPolicyFloorV1, StorageStateError> {
    if bytes.len() != 98
        || &bytes[..8] != RESOLVER_POLICY_FLOOR_MAGIC
        || u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| StorageStateError::CorruptRecord)?,
        ) != RESOLVER_POLICY_FLOOR_VERSION
        || bytes[10..26] != key.key_id
    {
        return Err(StorageStateError::CorruptRecord);
    }
    resolver_policy_floor_mac(key, &bytes[..66])?
        .verify_slice(&bytes[66..])
        .map_err(|_| StorageStateError::CorruptRecord)?;
    let floor = StorageResolverPolicyFloorV1 {
        generation: u64::from_be_bytes(
            bytes[26..34]
                .try_into()
                .map_err(|_| StorageStateError::CorruptRecord)?,
        ),
        catalog_digest: ObjectDigest::from_bytes(
            bytes[34..66]
                .try_into()
                .map_err(|_| StorageStateError::CorruptRecord)?,
        ),
    };
    if floor.generation == 0 || floor.catalog_digest.as_bytes() == &[0; 32] {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(floor)
}

fn resolver_policy_floor_tag(
    key: &StorageStateKey,
    payload: &[u8],
) -> Result<[u8; 32], StorageStateError> {
    Ok(resolver_policy_floor_mac(key, payload)?
        .finalize()
        .into_bytes()
        .into())
}

fn resolver_policy_floor_mac(
    key: &StorageStateKey,
    payload: &[u8],
) -> Result<HmacSha256, StorageStateError> {
    let mut mac =
        HmacSha256::new_from_slice(&key.secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(RESOLVER_POLICY_FLOOR_DOMAIN);
    mac.update(&[RecordNamespace::StorageResolverPolicyFloor as u8]);
    mac.update(&(RESOLVER_POLICY_FLOOR_KEY.len() as u32).to_be_bytes());
    mac.update(RESOLVER_POLICY_FLOOR_KEY);
    mac.update(payload);
    Ok(mac)
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
        maximum_records_per_transaction: 7,
        maximum_transaction_bytes: MAXIMUM_JOURNAL_RECORD_BYTES * 7,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: MAXIMUM_JOURNAL_RECORD_BYTES
            * (MAXIMUM_OPERATIONS * MATERIALIZED_RECORDS_PER_OPERATION
                + MAXIMUM_OPERATIONS * MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE as usize
                + MAXIMUM_OPERATIONS * 2
                + GLOBAL_MATERIALIZED_RECORDS)
            + repair_guard::RECORD_BYTES * MAXIMUM_OPERATIONS,
        maximum_materialized_records: MAXIMUM_OPERATIONS * MATERIALIZED_RECORDS_PER_OPERATION
            + MAXIMUM_OPERATIONS * MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE as usize
            + MAXIMUM_OPERATIONS * 2
            + GLOBAL_MATERIALIZED_RECORDS
            + MAXIMUM_OPERATIONS,
    }
}

fn latest_generation(records: &BTreeMap<[u8; 16], DurableRecord>) -> u64 {
    records
        .values()
        .flat_map(|record| {
            [
                (record.phase != DurableStoragePhase::Aborted)
                    .then_some(record.catalog.generation()),
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
    finish_nonzero_transaction_id(hash)
}

fn catalog_preparation_transaction_id(operation_id: [u8; 16]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.storage.catalog-preparation-transaction.v1\0");
    hash.update(operation_id);
    finish_nonzero_transaction_id(hash)
}

fn resolver_policy_floor_transaction_id(floor: StorageResolverPolicyFloorV1) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.storage.resolver-policy-floor-transaction.v1\0");
    hash.update(floor.generation.to_be_bytes());
    hash.update(floor.catalog_digest.as_bytes());
    finish_nonzero_transaction_id(hash)
}

fn pin_attempt_transaction_id(attempt: &WorkspacePinAttemptV1) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.storage.workspace-pin-transaction.v1\0");
    hash.update(attempt.attempt_id());
    hash.update([match attempt.phase() {
        WorkspacePinAttemptPhaseV1::Ambiguous => 1,
        WorkspacePinAttemptPhaseV1::Satisfied => 2,
    }]);
    finish_nonzero_transaction_id(hash)
}

fn workspace_pin_repair_transaction_id(repair_operation_id: [u8; 16]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.storage.workspace-pin-repair-transaction.v1\0");
    hash.update(repair_operation_id);
    finish_nonzero_transaction_id(hash)
}

fn finish_nonzero_transaction_id(hash: Sha256) -> [u8; 16] {
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
        DurableStoragePhase::Aborted => 4,
    }
}

fn encode_record(
    record: &DurableRecord,
    key: &StorageStateKey,
) -> Result<Vec<u8>, StorageStateError> {
    if record.format_version != VERSION {
        return Err(StorageStateError::CorruptRecord);
    }
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
        let flags = (u8::from(result.storage_handle.is_some()) * RESULT_HAS_STORAGE_HANDLE)
            | (u8::from(result.immutable_version_handle.is_some()) * RESULT_HAS_VERSION_HANDLE)
            | (u8::from(result.object_guid.is_some()) * RESULT_HAS_OBJECT_GUID);
        bytes.push(flags);
        bytes.extend_from_slice(&result.storage_handle.unwrap_or([0; 32]));
        bytes.extend_from_slice(&result.immutable_version_handle.unwrap_or([0; 32]));
        bytes.extend_from_slice(&result.object_guid.unwrap_or(0).to_be_bytes());
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
    if version != VERSION {
        return Err(StorageStateError::CorruptRecord);
    }
    let phase = match cursor.u8()? {
        1 => DurableStoragePhase::Prepared,
        2 => DurableStoragePhase::Ambiguous,
        3 => DurableStoragePhase::Committed,
        4 => DurableStoragePhase::Aborted,
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
        let identity = decode_result_identity(&mut cursor)?;
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
    fn u32_bytes(&mut self, maximum: usize) -> Result<&'a [u8], StorageStateError> {
        let length = usize::try_from(self.u32()?).map_err(|_| StorageStateError::CorruptRecord)?;
        if length > maximum {
            return Err(StorageStateError::CorruptRecord);
        }
        self.take(length)
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
    use aos_sandbox_core::model::{
        AssignmentManifestV1, IdentityProfile, NetworkKind, NetworkProfile, ResourceProfile,
        SandboxAncestry, SandboxSpec, UnmappableIdentityPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, CanonicalAssignmentManifestV1, DesiredGeneration,
        FeatureRef, IncarnationId, NamespaceGeneration, NodeId, PortableMediaType, ProjectId,
        ResourceVector, SandboxId, descriptor_for_bytes, encode_sandbox_spec,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::broker::FreshWorkspacePinAuthority;
    use crate::resolver::inventory::ProtectedStorageInventoryV1;
    use crate::resolver::policy::ProtectedStorageResolverPolicyV1;
    use crate::resolver::protected_catalog::StorageResolverPolicyCatalogBindingV1;
    use crate::root_policy::WorkspaceRootPolicyV1;
    use crate::workspace_catalog::DurablePortableWorkspaceMetadataV1;
    use crate::workspace_pin::{
        WorkspaceDatasetObservationV1, WorkspacePinHostScopeV1, WorkspacePinObservationV1,
        WorkspacePinRecoveryDispositionV1, WorkspaceRootPinProofV1,
    };
    use crate::workspace_repair::{StorageWorkspacePinRepairIntentV1, repair_intent_record};
    use crate::{
        ActiveHoldEvidence, CatalogPlanV1, HoldId, ManagedDatasetRoot, PlannedDataset,
        PlannedSnapshot, ProjectAncestorPolicyV1, ReservationPolicy, ResolvedDataset,
        ResolvedSnapshot, StorageDomainsV1, StorageOperation, WorkspaceSpacePolicyV1,
        ZfsTransaction,
    };

    pub(super) fn key(byte: u8) -> StorageStateKey {
        StorageStateKey::new([byte; 16], [byte.wrapping_add(1); 32]).unwrap()
    }

    #[test]
    fn held_snapshot_state_digest_binds_sequence_namespace_and_record_boundaries() {
        let baseline = materialized_state_digest(
            7,
            [(
                RecordNamespace::StorageCatalogHead,
                b"a".as_slice(),
                b"bc".as_slice(),
            )]
            .into_iter(),
        );
        for changed in [
            materialized_state_digest(
                8,
                [(
                    RecordNamespace::StorageCatalogHead,
                    b"a".as_slice(),
                    b"bc".as_slice(),
                )]
                .into_iter(),
            ),
            materialized_state_digest(
                7,
                [(
                    RecordNamespace::StorageCatalogTransition,
                    b"a".as_slice(),
                    b"bc".as_slice(),
                )]
                .into_iter(),
            ),
            materialized_state_digest(
                7,
                [(
                    RecordNamespace::StorageCatalogHead,
                    b"ab".as_slice(),
                    b"c".as_slice(),
                )]
                .into_iter(),
            ),
            materialized_state_digest(
                7,
                [(
                    RecordNamespace::StorageCatalogHead,
                    b"a".as_slice(),
                    b"bd".as_slice(),
                )]
                .into_iter(),
            ),
        ] {
            assert_ne!(baseline, changed);
        }
    }

    #[test]
    fn atomic_snapshot_post_head_is_versioned_and_mac_bound() {
        let key = key(61);
        let program = crate::lifecycle_atomic_snapshot::sample_atomic_snapshot_program_for_test();
        let record = AtomicDatasetSnapshotRecordV1 {
            phase: AtomicDatasetSnapshotPhaseV1::Committed,
            program,
            observation: Some(ObjectDigest::from_bytes([62; 32])),
            sandbox_id: [63; 16],
            request_id: [64; 16],
            semantic_digest: ObjectDigest::from_bytes([65; 32]),
            transport_digest: ObjectDigest::from_bytes([66; 32]),
            post_head: None,
        };
        let legacy = encode_atomic_snapshot_record(&record, &key).unwrap();
        assert!(
            decode_atomic_snapshot_record([1; 16], &legacy, &key)
                .unwrap()
                .post_head
                .is_none()
        );

        let post_head =
            CatalogBindingV1::from_publisher(10, ObjectDigest::from_bytes([67; 32])).unwrap();
        let checkpointed = AtomicDatasetSnapshotRecordV1 {
            post_head: Some(post_head),
            ..record
        };
        let encoded = encode_atomic_snapshot_record(&checkpointed, &key).unwrap();
        assert_eq!(&encoded[8..10], &3_u16.to_be_bytes());
        assert_eq!(
            decode_atomic_snapshot_record([1; 16], &encoded, &key)
                .unwrap()
                .post_head,
            Some(post_head)
        );
        let mut corrupted = encoded.clone();
        let last_body_byte = corrupted.len() - MAC_BYTES - 1;
        corrupted[last_body_byte] ^= 1;
        assert!(decode_atomic_snapshot_record([1; 16], &corrupted, &key).is_err());

        let wrong_generation = AtomicDatasetSnapshotRecordV1 {
            post_head: Some(
                CatalogBindingV1::from_publisher(11, ObjectDigest::from_bytes([67; 32])).unwrap(),
            ),
            ..checkpointed
        };
        assert!(encode_atomic_snapshot_record(&wrong_generation, &key).is_err());
    }

    fn resolver_policy_binding(
        generation: u64,
        marker: u8,
    ) -> StorageResolverPolicyCatalogBindingV1 {
        StorageResolverPolicyCatalogBindingV1::from_parts_for_test(
            generation,
            ObjectDigest::from_bytes([marker; 32]),
        )
    }

    #[test]
    fn trusted_policy_floor_is_authenticated_monotone_and_replay_stable() {
        let directory = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let first = resolver_policy_binding(7, 41);
        let next = resolver_policy_binding(8, 42);

        assert_eq!(
            store.admit_resolver_policy_catalog(first).unwrap(),
            StorageResolverPolicyAdmissionOutcomeV1::Advanced
        );
        let after_first = store.journal_sequence_for_test();
        assert_eq!(
            store.admit_resolver_policy_catalog(first).unwrap(),
            StorageResolverPolicyAdmissionOutcomeV1::Replay
        );
        assert_eq!(store.journal_sequence_for_test(), after_first);
        for rejected in [
            resolver_policy_binding(6, 40),
            resolver_policy_binding(7, 99),
        ] {
            assert!(matches!(
                store.admit_resolver_policy_catalog(rejected),
                Err(StorageStateError::Rollback)
            ));
            assert_eq!(store.journal_sequence_for_test(), after_first);
        }

        assert_eq!(
            store.admit_resolver_policy_catalog(next).unwrap(),
            StorageResolverPolicyAdmissionOutcomeV1::Advanced
        );
        drop(store);
        let reopened = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(
            reopened.resolver_policy_floor(),
            Some(StorageResolverPolicyFloorV1 {
                generation: 8,
                catalog_digest: ObjectDigest::from_bytes([42; 32]),
            })
        );
    }

    #[test]
    fn fresh_floor_reload_detects_cached_deletion_and_substitution() {
        let directory = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let binding = resolver_policy_binding(7, 41);
        store.admit_resolver_policy_catalog(binding).unwrap();

        store.remove_authority_record_for_test(
            RecordNamespace::StorageResolverPolicyFloor,
            RESOLVER_POLICY_FLOOR_KEY,
        );
        assert!(matches!(
            store.admit_resolver_policy_catalog(binding),
            Err(StorageStateError::CorruptRecord)
        ));

        drop(store);
        let mut reopened =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        reopened.put_authority_record_for_test(
            RecordNamespace::StorageResolverPolicyFloor,
            RESOLVER_POLICY_FLOOR_KEY,
            vec![0; 98],
        );
        drop(reopened);
        assert!(matches!(
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0),
            Err(StorageStateError::CorruptRecord)
        ));
    }

    #[test]
    fn policy_floor_rejects_wrong_location_and_authentication_key() {
        let wrong_location = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(wrong_location.path(), key(1), 0).unwrap();
        let floor = StorageResolverPolicyFloorV1 {
            generation: 7,
            catalog_digest: ObjectDigest::from_bytes([41; 32]),
        };
        let bytes = resolver_policy_floor_record(&store.key, floor)
            .unwrap()
            .value()
            .unwrap()
            .to_vec();
        store.put_authority_record_for_test(
            RecordNamespace::StorageResolverPolicyFloor,
            b"wrong",
            bytes,
        );
        drop(store);
        assert!(matches!(
            StorageTransactionStore::open_for_test(wrong_location.path(), key(1), 0),
            Err(StorageStateError::CorruptRecord)
        ));

        let wrong_key = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(wrong_key.path(), key(1), 0).unwrap();
        store
            .admit_resolver_policy_catalog(resolver_policy_binding(7, 41))
            .unwrap();
        drop(store);
        assert!(matches!(
            StorageTransactionStore::open_for_test(wrong_key.path(), key(2), 0),
            Err(StorageStateError::CorruptRecord)
        ));
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

    pub(super) fn catalog(generation: u64, destination_name: &str) -> ResolvedCatalogCommitmentV1 {
        catalog_with_physical_identity(generation, destination_name, 10, 15)
    }

    #[test]
    fn transaction_record_rejects_authenticated_unknown_version() {
        let state_key = key(1);
        let catalog = catalog(7, "tank/aos/project/work");
        let record = DurableRecord {
            format_version: VERSION,
            phase: DurableStoragePhase::Prepared,
            operation_id: [31; 16],
            sandbox_id: [32; 16],
            request_id: [33; 16],
            request_digest: digest(34),
            mutation_digest: digest(35),
            catalog: catalog.binding(),
            postcondition_digest: postcondition_digest(catalog.canonical_bytes()),
            catalog_bytes: catalog.canonical_bytes().to_vec(),
            result: None,
        };
        let mut encoded = encode_record(&record, &state_key).unwrap();
        encoded[8..10].copy_from_slice(&2_u16.to_be_bytes());
        let body_length = encoded.len() - MAC_BYTES;
        let mut mac = HmacSha256::new_from_slice(&state_key.secret).unwrap();
        mac.update(RECORD_DOMAIN);
        mac.update(&encoded[..body_length]);
        encoded[body_length..].copy_from_slice(&mac.finalize().into_bytes());

        assert!(matches!(
            decode_record(&encoded, &state_key),
            Err(StorageStateError::CorruptRecord)
        ));
    }

    pub(super) fn publication_intent(
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
        publication_intent_with_authority(
            operation_id,
            catalog,
            marker,
            range_start,
            range_size,
            SandboxId::from_bytes([marker.wrapping_sub(2); 16]),
            [marker.wrapping_sub(1); 16],
            digest(marker.wrapping_sub(3)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn publication_intent_with_authority(
        operation_id: [u8; 16],
        catalog: &ResolvedCatalogCommitmentV1,
        marker: u8,
        range_start: u32,
        range_size: u32,
        sandbox: SandboxId,
        request_id: [u8; 16],
        request_digest: ObjectDigest,
    ) -> StorageWorkspacePublicationIntentV1 {
        let incarnation = IncarnationId::from_bytes([marker.wrapping_add(2); 16]);
        let node = NodeId::from_bytes([marker.wrapping_add(3); 16]);
        let root_image = ObjectDescriptor::new(
            MediaType::new(PortableMediaType::View.as_str().to_owned()).unwrap(),
            digest(marker.wrapping_add(1)),
            u64::from(marker) + 1,
        );
        let environment = ObjectDescriptor::new(
            MediaType::new(PortableMediaType::Environment.as_str().to_owned()).unwrap(),
            digest(marker.wrapping_add(4)),
            u64::from(marker) + 2,
        );
        let spec = SandboxSpec::new(
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            IdentityProfile::PrivateUserns {
                id_range_size: std::num::NonZeroU32::new(range_size).unwrap(),
                unmappable_policy: UnmappableIdentityPolicy::Reject,
                required_features: Vec::new(),
            },
            ResourceProfile::new(Vec::new()).unwrap(),
            environment.clone(),
            root_image.clone(),
            Vec::new(),
            NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let spec_bytes = encode_sandbox_spec(&spec);
        let spec_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned()).unwrap(),
            &spec_bytes,
        );
        let manifest = CanonicalAssignmentManifestV1::new(
            AssignmentManifestV1::new(
                sandbox,
                ProjectId::from_bytes([marker.wrapping_add(5); 16]),
                SandboxAncestry::new(sandbox, Vec::new()).unwrap(),
                incarnation,
                node,
                AssignmentEpoch::new(u64::from(marker) + 1),
                DesiredGeneration::new(u64::from(marker) + 1),
                NamespaceGeneration::new(u64::from(marker) + 1),
                spec_descriptor,
                ObjectDescriptor::new(
                    MediaType::new(PortableMediaType::Policy.as_str().to_owned()).unwrap(),
                    digest(marker.wrapping_add(6)),
                    u64::from(marker) + 3,
                ),
                environment,
                root_image.clone(),
                Vec::new(),
                digest(marker.wrapping_add(7)),
                ResourceVector::ZERO,
                Vec::new(),
            )
            .unwrap(),
        );
        let assignment = manifest.broker_assignment().unwrap();
        let portable_metadata = DurablePortableWorkspaceMetadataV1::new(
            request_id,
            request_digest,
            assignment,
            node,
            catalog.root_policy().unwrap(),
            manifest.canonical_bytes().to_vec(),
            spec_bytes,
        )
        .unwrap();
        StorageWorkspacePublicationIntentV1::from_authenticated_parts(
            operation_id,
            catalog.binding(),
            assignment.digest(),
            root_image,
            range_start,
            range_size,
            portable_metadata,
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
        ResolvedCatalogCommitmentV1::new_for_test(
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

    fn execution_catalog_for_root(
        generation: u64,
        pool: &str,
        root_name: &str,
        root_guid: u64,
        ancestor_name: &str,
        ancestor_guid: u64,
        destination_name: &str,
    ) -> (ResolvedCatalogCommitmentV1, ResolvedDataset) {
        let root = ManagedDatasetRoot::from_catalog(pool, root_name, root_guid).unwrap();
        let ancestor = ResolvedDataset::from_catalog(
            root.clone(),
            ancestor_name,
            ancestor_guid,
            [u8::try_from(root_guid).unwrap(); 32],
            domains(),
        )
        .unwrap();
        let policy = ProjectAncestorPolicyV1::new(ancestor.clone(), 65_536, 8, 16).unwrap();
        let destination = PlannedDataset::from_catalog(root, destination_name, domains()).unwrap();
        let catalog = ResolvedCatalogCommitmentV1::new_execution_v1(
            generation,
            domains(),
            CatalogPlanV1::CreateWorkspace {
                destination,
                space: WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap(),
                ancestor: policy,
            },
            Some(WorkspaceRootPolicyV1::create_initialize()),
            None,
        )
        .unwrap();
        (catalog, ancestor)
    }

    pub(super) fn destroy_dataset_catalog(
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
        ResolvedCatalogCommitmentV1::new_for_test(
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
        ResolvedCatalogCommitmentV1::new_for_test(
            generation,
            domains(),
            CatalogPlanV1::Snapshot {
                source,
                destination,
            },
        )
        .unwrap()
    }

    pub(super) fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    pub(super) fn initialize(
        store: &mut StorageTransactionStore,
        catalog: &ResolvedCatalogCommitmentV1,
    ) {
        store
            .initialize_catalog_from_protected_snapshot(
                catalog.generation() - 1,
                std::slice::from_ref(catalog),
            )
            .unwrap();
    }

    fn clone_test_store(source: &TempDir) -> (TempDir, StorageTransactionStore) {
        let destination = TempDir::new().unwrap();
        fs::copy(
            source.path().join("storage-state.journal"),
            destination.path().join("storage-state.journal"),
        )
        .unwrap();
        let store = StorageTransactionStore::open_for_test(destination.path(), key(1), 0).unwrap();
        (destination, store)
    }

    pub(super) fn workspace_pin_proof(
        workspace_handle: [u8; 32],
        dataset_name: &str,
        dataset_guid: u64,
    ) -> WorkspaceRootPinProofV1 {
        use std::fmt::Write as _;

        let mut mount_point = "/run/aos/sandbox-pins/workspaces/".to_owned();
        for byte in workspace_handle {
            write!(mount_point, "{byte:02x}").unwrap();
        }

        WorkspaceRootPinProofV1::new(
            [4; 16],
            5,
            6,
            7,
            "/".to_owned(),
            mount_point,
            "zfs".to_owned(),
            dataset_name.to_owned(),
            dataset_guid,
            8,
            9,
            WorkspaceRootPolicyV1::create_initialize().root_attributes(),
        )
        .unwrap()
    }

    pub(super) fn prepare_workspace_remove_attempt(
        store: &mut StorageTransactionStore,
    ) -> (WorkspacePinAttemptV1, ObjectDigest) {
        let create = catalog(7, "tank/aos/project/work");
        initialize(store, &create);
        let create_operation = [101; 16];
        let intent = publication_intent(create_operation, &create, 106);
        let assignment_digest = intent.assignment_digest();
        let BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin_authorized_with_publication(
                create_operation,
                digest(103),
                &create,
                [104; 16],
                [105; 16],
                vec![1; 8],
                vec![2; 8],
                vec![3; 8],
                Some(intent),
            )
            .unwrap()
        else {
            panic!("workspace creation fixture was not prepared")
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
                digest(106),
            )
            .unwrap();
        let host_scope = WorkspacePinHostScopeV1::new([4; 16], 5, 6).unwrap();
        let ensure = store
            .plan_workspace_pin_ensure(creation, assignment_digest, host_scope, [10; 16], 1_000)
            .unwrap();
        store
            .begin_workspace_pin_attempt(
                ensure.clone(),
                FreshWorkspacePinAuthority::new_for_test(
                    ensure.attempt_id(),
                    ensure.authority_digest().unwrap(),
                ),
            )
            .unwrap();
        let proof = workspace_pin_proof(
            creation.storage_handle().unwrap(),
            "tank/aos/project/work",
            101,
        );
        store
            .complete_workspace_pin_attempt(
                ensure.attempt_id(),
                &WorkspaceDatasetObservationV1::Exact {
                    name: "tank/aos/project/work".to_owned(),
                    guid: 101,
                },
                &WorkspacePinObservationV1::Present(proof.clone()),
            )
            .unwrap();

        let destroy = destroy_dataset_catalog(
            9,
            "tank/aos/project/work",
            101,
            creation.storage_handle().unwrap(),
        );
        let destroy_operation = [107; 16];
        let BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin_authorized_with_publication(
                destroy_operation,
                digest(108),
                &destroy,
                [104; 16],
                [109; 16],
                vec![4; 8],
                vec![5; 8],
                vec![6; 8],
                None,
            )
            .unwrap()
        else {
            panic!("workspace destruction fixture was not prepared")
        };
        let remove = store
            .plan_workspace_pin_remove_and_destroy(
                destroy_operation,
                digest(110),
                host_scope,
                [10; 16],
                1_000,
                proof,
            )
            .unwrap();
        (remove, mutation_digest)
    }

    #[test]
    fn fresh_resolver_reload_validates_global_chain_before_selecting_one_root() {
        let directory = TempDir::new().unwrap();
        let (selected_execution, selected_ancestor) = execution_catalog_for_root(
            7,
            "tank",
            "tank/aos-selected",
            41,
            "tank/aos-selected/project",
            42,
            "tank/aos-selected/project/workspace-future",
        );
        let (other_execution, other_ancestor) = execution_catalog_for_root(
            7,
            "vault",
            "vault/aos-other",
            43,
            "vault/aos-other/project",
            44,
            "vault/aos-other/project/workspace-created",
        );
        let selected_catalog = ResolvedCatalogCommitmentV1::new_for_test(
            7,
            domains(),
            selected_execution.plan().clone(),
        )
        .unwrap();
        let other_catalog =
            ResolvedCatalogCommitmentV1::new_for_test(7, domains(), other_execution.plan().clone())
                .unwrap();
        let other_dataset = ResolvedDataset::from_catalog(
            other_ancestor.root().clone(),
            "vault/aos-other/project/existing",
            45,
            [46; 32],
            domains(),
        )
        .unwrap();
        let other_quota_catalog = ResolvedCatalogCommitmentV1::new_for_test(
            7,
            domains(),
            CatalogPlanV1::SetQuota {
                dataset: other_dataset.clone(),
                space: WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap(),
                ancestor: ProjectAncestorPolicyV1::new(other_ancestor.clone(), 65_536, 8, 16)
                    .unwrap(),
            },
        )
        .unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        store
            .initialize_catalog_from_protected_snapshot(
                6,
                &[
                    selected_catalog.clone(),
                    other_catalog.clone(),
                    other_quota_catalog.clone(),
                ],
            )
            .unwrap();
        let BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin([45; 16], digest(46), &other_quota_catalog)
            .unwrap()
        else {
            panic!("other-root quota update did not prepare")
        };
        store
            .mark_mutation_ambiguous([45; 16], mutation_digest)
            .unwrap();
        let committed = store
            .commit_observed(
                [45; 16],
                mutation_digest,
                &other_quota_catalog,
                &other_quota_catalog.plan().postcondition(),
                Some(other_dataset.guid()),
                digest(48),
            )
            .unwrap();
        let other_handle = committed.storage_handle().unwrap();
        drop(store);

        let reopened = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let verified = reopened.verified_resolver_journal().unwrap();
        assert_eq!(verified.physical().roots().len(), 2);
        assert!(verified.operation(&[45; 16]).is_some());

        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([49; 16]),
            IncarnationId::from_bytes([50; 16]),
            AssignmentEpoch::new(51),
            DesiredGeneration::new(52),
            digest(53),
        )
        .unwrap();
        let policy = ProtectedStorageResolverPolicyV1::new(
            assignment,
            selected_ancestor.root().clone(),
            domains(),
            ProjectAncestorPolicyV1::new(selected_ancestor.clone(), 65_536, 8, 16).unwrap(),
            4096,
            1024,
        )
        .unwrap();
        let inventory =
            ProtectedStorageInventoryV1::from_verified_journal(verified, &policy).unwrap();

        assert_eq!(inventory.root(), selected_ancestor.root());
        assert_eq!(
            inventory.dataset(&selected_ancestor.storage_handle()),
            Some(&selected_ancestor)
        );
        assert!(inventory.dataset(&other_handle).is_none());
        assert_eq!(other_handle, other_dataset.storage_handle());
        assert!(inventory.name_is_occupied(other_dataset.name()));
    }

    #[test]
    fn fresh_resolver_reload_rejects_orphan_physical_reservations_and_transitions() {
        for commit_transition in [false, true] {
            let directory = TempDir::new().unwrap();
            let catalog = catalog(7, "tank/aos/project/work");
            let operation_id = if commit_transition {
                [61; 16]
            } else {
                [62; 16]
            };
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            store
                .initialize_catalog_from_protected_snapshot(6, std::slice::from_ref(&catalog))
                .unwrap();
            let BeginStorageTransaction::Prepared { mutation_digest } =
                store.begin(operation_id, digest(63), &catalog).unwrap()
            else {
                panic!("catalog operation did not prepare")
            };
            if commit_transition {
                store
                    .mark_mutation_ambiguous(operation_id, mutation_digest)
                    .unwrap();
                store
                    .commit_observed(
                        operation_id,
                        mutation_digest,
                        &catalog,
                        &catalog.plan().postcondition(),
                        Some(64),
                        digest(65),
                    )
                    .unwrap();
            }

            store.remove_authority_record_for_test(RecordNamespace::Operation, &operation_id);

            assert!(matches!(
                store.verified_resolver_journal(),
                Err(StorageStateError::CorruptRecord)
            ));
        }
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
        let first = publication_intent(operation_id, &catalog, 47);
        let substituted = publication_intent_at(
            operation_id,
            &catalog,
            47,
            first.identity_range_start() + 65_536,
            65_536,
        );
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
    fn publication_intent_rejects_cross_link_substitution_before_durable_write() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);

        let operation_id = [171; 16];
        let request_digest = digest(172);
        let sandbox = SandboxId::from_bytes([173; 16]);
        let request_id = [174; 16];
        let marker = 175;
        let range_start = u32::from(marker) * 65_536;
        let sequence = store.journal_sequence_for_test();
        let candidates = [
            publication_intent_with_authority(
                operation_id,
                &catalog,
                marker,
                range_start,
                65_536,
                sandbox,
                [176; 16],
                request_digest,
            ),
            publication_intent_with_authority(
                operation_id,
                &catalog,
                marker,
                range_start,
                65_536,
                sandbox,
                request_id,
                digest(177),
            ),
            publication_intent_with_authority(
                operation_id,
                &catalog,
                marker,
                range_start,
                65_536,
                SandboxId::from_bytes([178; 16]),
                request_id,
                request_digest,
            ),
        ];

        for candidate in candidates {
            assert!(matches!(
                store.begin_authorized_with_publication(
                    operation_id,
                    request_digest,
                    &catalog,
                    *sandbox.as_bytes(),
                    request_id,
                    vec![1; 8],
                    vec![2; 8],
                    vec![3; 8],
                    Some(candidate),
                ),
                Err(StorageStateError::AuthorityLinkMismatch)
            ));
            assert_eq!(store.journal_sequence_for_test(), sequence);
            assert_eq!(store.phase(operation_id).unwrap(), None);
        }
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
        let first = publication_intent_at(first_operation, &catalog, 52, range_start, 65_536);
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
                operation_id[0].wrapping_add(5),
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
    fn active_pin_selection_is_global_while_retirement_history_is_creation_scoped() {
        let directory = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let workspace_handle = [9; 32];
        let creation_catalog = catalog(7, "tank/aos/project/work").binding();
        let intended_creation = [61; 16];
        let foreign_creation = [62; 16];
        let proof = workspace_pin_proof(workspace_handle, "tank/aos/project/work", 101);
        let attempt = |attempt_id, ordinal, creation_operation_id| {
            WorkspacePinAttemptV1::new_ambiguous(
                attempt_id,
                ordinal,
                WorkspacePinActionV1::Ensure,
                creation_operation_id,
                creation_operation_id,
                digest(63),
                digest(64),
                digest(65),
                creation_catalog,
                digest(66),
                workspace_handle,
                [4; 16],
                5,
                6,
                [10; 16],
                1_000,
                "tank/aos/project/work".to_owned(),
                101,
                65_536,
                65_536,
                WorkspaceRootPolicyV1::create_initialize(),
                None,
            )
            .unwrap()
        };

        let intended = attempt([67; 16], 1, intended_creation)
            .satisfy(Some(proof.clone()))
            .unwrap();
        let foreign = attempt([68; 16], 2, foreign_creation)
            .satisfy(Some(proof.clone()))
            .unwrap();
        store.pin_attempts.insert(intended.attempt_id(), intended);
        store.pin_attempts.insert(foreign.attempt_id(), foreign);

        assert!(matches!(
            store.satisfied_workspace_ensure_pin_for_active_creation(
                intended_creation,
                workspace_handle,
            ),
            Err(StorageStateError::InvalidTransition)
        ));
        assert_eq!(
            store
                .satisfied_workspace_ensure_pin_for_creation_history(
                    intended_creation,
                    workspace_handle,
                )
                .unwrap(),
            proof
        );

        let pending = attempt([69; 16], 3, intended_creation);
        store.pin_attempts.insert(pending.attempt_id(), pending);
        assert!(matches!(
            store.satisfied_workspace_ensure_pin_for_active_creation(
                intended_creation,
                workspace_handle,
            ),
            Err(StorageStateError::InvalidTransition)
        ));
        assert_eq!(
            store
                .satisfied_workspace_ensure_pin_for_creation_history(
                    intended_creation,
                    workspace_handle,
                )
                .unwrap(),
            proof
        );
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
        assert!(store.workspace_projection().unwrap().is_empty());

        let host_scope = WorkspacePinHostScopeV1::new([4; 16], 5, 6).unwrap();
        let ensure = store
            .plan_workspace_pin_ensure(
                creation,
                publication_intent(create_operation, &create, 65).assignment_digest(),
                host_scope,
                [10; 16],
                1_000,
            )
            .unwrap();
        let ensure_authority = FreshWorkspacePinAuthority::new_for_test(
            ensure.attempt_id(),
            ensure.authority_digest().unwrap(),
        );
        store
            .begin_workspace_pin_attempt(ensure.clone(), ensure_authority)
            .unwrap();
        let proof = workspace_pin_proof(
            creation.storage_handle().unwrap(),
            "tank/aos/project/work",
            101,
        );
        store
            .complete_workspace_pin_attempt(
                ensure.attempt_id(),
                &WorkspaceDatasetObservationV1::Exact {
                    name: "tank/aos/project/work".to_owned(),
                    guid: 101,
                },
                &WorkspacePinObservationV1::Present(proof.clone()),
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
            .begin_authorized_with_publication(
                destroy_operation,
                digest(68),
                &destroy,
                [70; 16],
                [71; 16],
                vec![4; 8],
                vec![5; 8],
                vec![6; 8],
                None,
            )
            .unwrap()
        else {
            panic!("managed workspace destruction was not prepared")
        };
        let remove = store
            .plan_workspace_pin_remove_and_destroy(
                destroy_operation,
                digest(72),
                host_scope,
                [10; 16],
                1_000,
                proof,
            )
            .unwrap();
        assert_eq!(remove.attempt_ordinal(), 2);
        let remove_authority = FreshWorkspacePinAuthority::new_for_test(
            remove.attempt_id(),
            remove.authority_digest().unwrap(),
        );
        assert!(matches!(
            store
                .begin_workspace_pin_remove_and_destroy(
                    remove.clone(),
                    mutation_digest,
                    remove_authority,
                )
                .unwrap(),
            BeginWorkspacePinAttemptV1::Dispatch(_)
        ));
        assert!(store.workspace_projection().unwrap().is_empty());
        store
            .commit_observed(
                destroy_operation,
                mutation_digest,
                &destroy,
                &destroy.plan().postcondition(),
                None,
                digest(69),
            )
            .unwrap();
        assert!(store.workspace_projection().unwrap().is_empty());
        assert_eq!(
            store
                .complete_workspace_pin_attempt(
                    remove.attempt_id(),
                    &WorkspaceDatasetObservationV1::Absent,
                    &WorkspacePinObservationV1::Absent,
                )
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::CompleteRetirement
        );
        let retirement = store
            .records
            .get(&destroy_operation)
            .and_then(|record| record.result)
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
    fn pin_ensure_attempt_is_durable_before_dispatch_and_recovery_is_observation_only() {
        let directory = TempDir::new().unwrap();
        let create = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &create);
        let operation_id = [91; 16];
        let intent = publication_intent(operation_id, &create, 96);
        let assignment_digest = intent.assignment_digest();
        let BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin_authorized_with_publication(
                operation_id,
                digest(93),
                &create,
                [94; 16],
                [95; 16],
                vec![1; 8],
                vec![2; 8],
                vec![3; 8],
                Some(intent),
            )
            .unwrap()
        else {
            panic!("managed workspace creation was not prepared")
        };
        store
            .mark_mutation_ambiguous(operation_id, mutation_digest)
            .unwrap();
        let creation = store
            .commit_observed(
                operation_id,
                mutation_digest,
                &create,
                &create.plan().postcondition(),
                Some(101),
                digest(96),
            )
            .unwrap();
        let host_scope = WorkspacePinHostScopeV1::new([4; 16], 5, 6).unwrap();
        let attempt = store
            .plan_workspace_pin_ensure(creation, assignment_digest, host_scope, [10; 16], 1_000)
            .unwrap();
        let authority = FreshWorkspacePinAuthority::new_for_test(
            attempt.attempt_id(),
            attempt.authority_digest().unwrap(),
        );
        let before = store.journal_sequence_for_test();
        assert!(matches!(
            store
                .begin_workspace_pin_attempt(attempt.clone(), authority)
                .unwrap(),
            BeginWorkspacePinAttemptV1::Dispatch(_)
        ));
        assert!(store.journal_sequence_for_test() > before);

        drop(store);
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let recovered_attempts = store.workspace_pin_attempts().unwrap();
        assert_eq!(recovered_attempts.len(), 1);
        assert_eq!(
            recovered_attempts[0].phase(),
            WorkspacePinAttemptPhaseV1::Ambiguous
        );

        let replay_authority = FreshWorkspacePinAuthority::new_for_test(
            attempt.attempt_id(),
            attempt.authority_digest().unwrap(),
        );
        let after_ambiguous = store.journal_sequence_for_test();
        assert!(matches!(
            store
                .begin_workspace_pin_attempt(attempt.clone(), replay_authority)
                .unwrap(),
            BeginWorkspacePinAttemptV1::ObserveOnly(_)
        ));
        assert_eq!(store.journal_sequence_for_test(), after_ambiguous);

        let dataset = WorkspaceDatasetObservationV1::Exact {
            name: "tank/aos/project/work".to_owned(),
            guid: 101,
        };
        assert_eq!(
            store
                .complete_workspace_pin_attempt(
                    attempt.attempt_id(),
                    &dataset,
                    &WorkspacePinObservationV1::Absent,
                )
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::AwaitFreshRepair
        );
        assert_eq!(store.journal_sequence_for_test(), after_ambiguous);

        let proof = workspace_pin_proof(
            creation.storage_handle().unwrap(),
            "tank/aos/project/work",
            101,
        );
        assert_eq!(
            store
                .complete_workspace_pin_attempt(
                    attempt.attempt_id(),
                    &dataset,
                    &WorkspacePinObservationV1::Present(proof.clone()),
                )
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::CompletePublication
        );
        drop(store);
        let mut reopened =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(
            reopened
                .complete_workspace_pin_attempt(
                    attempt.attempt_id(),
                    &dataset,
                    &WorkspacePinObservationV1::Present(proof),
                )
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::CompletePublication
        );
    }

    #[test]
    fn repair_intent_reopens_and_superseded_attempt_cannot_complete_late() {
        let directory = TempDir::new().unwrap();
        let create = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &create);
        let creation_operation_id = [141; 16];
        let publication = publication_intent(creation_operation_id, &create, 146);
        let workspace_assignment_digest = publication.assignment_digest();
        let BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin_authorized_with_publication(
                creation_operation_id,
                digest(143),
                &create,
                [144; 16],
                [145; 16],
                vec![1; 8],
                vec![2; 8],
                vec![3; 8],
                Some(publication.clone()),
            )
            .unwrap()
        else {
            panic!("managed workspace creation was not prepared")
        };
        store
            .mark_mutation_ambiguous(creation_operation_id, mutation_digest)
            .unwrap();
        let creation = store
            .commit_observed(
                creation_operation_id,
                mutation_digest,
                &create,
                &create.plan().postcondition(),
                Some(101),
                digest(146),
            )
            .unwrap();
        let host_scope = WorkspacePinHostScopeV1::new([4; 16], 5, 6).unwrap();
        let initial = store
            .plan_workspace_pin_ensure(
                creation,
                workspace_assignment_digest,
                host_scope,
                [10; 16],
                1_000,
            )
            .unwrap();
        let authority = FreshWorkspacePinAuthority::new_for_test(
            initial.attempt_id(),
            initial.authority_digest().unwrap(),
        );
        store
            .begin_workspace_pin_attempt(initial.clone(), authority)
            .unwrap();

        let repair_operation_id = [147; 16];
        let repair_request_id = [148; 16];
        let repair_assignment_digest = digest(149);
        let sealed_effect = vec![5; 8];
        let sealed_operation_fence = vec![6; 8];
        let operation_fence_digest = digest_bytes(&sealed_operation_fence);
        let workspace_handle = creation.storage_handle().unwrap();
        let repair_attempt_id = derive_attempt_id(
            &store.key.secret,
            repair_operation_id,
            workspace_handle,
            WorkspacePinActionV1::Ensure,
            2,
        )
        .unwrap();
        let repair = WorkspacePinAttemptV1::new_ambiguous(
            repair_attempt_id,
            2,
            WorkspacePinActionV1::Ensure,
            repair_operation_id,
            creation_operation_id,
            operation_fence_digest,
            repair_assignment_digest,
            workspace_assignment_digest,
            creation.catalog(),
            creation.result_digest(),
            workspace_handle,
            host_scope.kernel_boot_id(),
            host_scope.mount_namespace_device(),
            host_scope.mount_namespace_inode(),
            [11; 16],
            2_000,
            "tank/aos/project/work".to_owned(),
            101,
            publication.identity_range_start(),
            publication.identity_range_size(),
            create.root_policy().unwrap(),
            None,
        )
        .unwrap()
        .with_authority_receipt(vec![0xa5])
        .unwrap();
        let publication_record = store
            .journal
            .get(
                RecordNamespace::StorageWorkspacePublicationIntent,
                &creation_operation_id,
            )
            .unwrap();
        let initial_record = store
            .journal
            .get(
                RecordNamespace::StorageWorkspacePinAttempt,
                &initial.attempt_id(),
            )
            .unwrap();
        let intent = StorageWorkspacePinRepairIntentV1::new_for_test(
            repair_operation_id,
            repair_request_id,
            digest(150),
            digest(151),
            repair_assignment_digest,
            sealed_effect.clone(),
            operation_fence_digest,
            creation_operation_id,
            creation.catalog(),
            creation.result_digest(),
            digest_bytes(publication_record),
            workspace_handle,
            initial.attempt_id(),
            initial.phase(),
            digest_bytes(initial_record),
            repair.attempt_id(),
            repair.attempt_ordinal(),
        )
        .unwrap();
        let transaction = JournalTransaction::new(
            [152; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    repair_request_id.to_vec(),
                    sealed_effect,
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    repair_operation_id.to_vec(),
                    sealed_operation_fence,
                ),
                repair_intent_record(&intent, store.key.key_id, &store.key.secret).unwrap(),
                attempt_record(&repair, store.key.key_id, &store.key.secret).unwrap(),
            ],
        )
        .unwrap();
        store.commit_journal(&transaction).unwrap();
        drop(store);

        let mut reopened =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(reopened.workspace_pin_attempts().unwrap().len(), 2);
        let before = reopened.journal_sequence_for_test();
        let proof = workspace_pin_proof(workspace_handle, "tank/aos/project/work", 101);
        assert!(matches!(
            reopened.complete_workspace_pin_attempt(
                initial.attempt_id(),
                &WorkspaceDatasetObservationV1::Exact {
                    name: "tank/aos/project/work".to_owned(),
                    guid: 101,
                },
                &WorkspacePinObservationV1::Present(proof.clone()),
            ),
            Err(StorageStateError::InvalidTransition)
        ));
        assert_eq!(reopened.journal_sequence_for_test(), before);
        assert_eq!(
            reopened
                .complete_workspace_pin_attempt(
                    repair.attempt_id(),
                    &WorkspaceDatasetObservationV1::Exact {
                        name: "tank/aos/project/work".to_owned(),
                        guid: 101,
                    },
                    &WorkspacePinObservationV1::Present(proof.clone()),
                )
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::CompletePublication
        );
        let repaired = reopened
            .pin_attempts
            .get(&repair.attempt_id())
            .unwrap()
            .clone();
        let second_repair_operation_id = [153; 16];
        let second_repair_request_id = [154; 16];
        let second_repair_assignment_digest = digest(155);
        let second_sealed_effect = vec![7; 8];
        let second_sealed_operation_fence = vec![8; 8];
        let second_operation_fence_digest = digest_bytes(&second_sealed_operation_fence);
        let second_repair_attempt_id = derive_attempt_id(
            &reopened.key.secret,
            second_repair_operation_id,
            workspace_handle,
            WorkspacePinActionV1::Ensure,
            3,
        )
        .unwrap();
        let second_repair = WorkspacePinAttemptV1::new_ambiguous(
            second_repair_attempt_id,
            3,
            WorkspacePinActionV1::Ensure,
            second_repair_operation_id,
            creation_operation_id,
            second_operation_fence_digest,
            second_repair_assignment_digest,
            workspace_assignment_digest,
            creation.catalog(),
            creation.result_digest(),
            workspace_handle,
            host_scope.kernel_boot_id(),
            host_scope.mount_namespace_device(),
            host_scope.mount_namespace_inode(),
            [12; 16],
            3_000,
            "tank/aos/project/work".to_owned(),
            101,
            publication.identity_range_start(),
            publication.identity_range_size(),
            create.root_policy().unwrap(),
            None,
        )
        .unwrap()
        .with_authority_receipt(vec![0xa6])
        .unwrap();
        let publication_record = reopened
            .journal
            .get(
                RecordNamespace::StorageWorkspacePublicationIntent,
                &creation_operation_id,
            )
            .unwrap();
        let repaired_record = reopened
            .journal
            .get(
                RecordNamespace::StorageWorkspacePinAttempt,
                &repaired.attempt_id(),
            )
            .unwrap();
        let second_intent = StorageWorkspacePinRepairIntentV1::new_for_test(
            second_repair_operation_id,
            second_repair_request_id,
            digest(156),
            digest(157),
            second_repair_assignment_digest,
            second_sealed_effect.clone(),
            second_operation_fence_digest,
            creation_operation_id,
            creation.catalog(),
            creation.result_digest(),
            digest_bytes(publication_record),
            workspace_handle,
            repaired.attempt_id(),
            repaired.phase(),
            digest_bytes(repaired_record),
            second_repair.attempt_id(),
            second_repair.attempt_ordinal(),
        )
        .unwrap();

        let reordered_intent = StorageWorkspacePinRepairIntentV1::new_for_test(
            second_repair_operation_id,
            second_repair_request_id,
            digest(156),
            digest(157),
            second_repair_assignment_digest,
            second_sealed_effect.clone(),
            second_operation_fence_digest,
            creation_operation_id,
            creation.catalog(),
            creation.result_digest(),
            digest_bytes(publication_record),
            workspace_handle,
            initial.attempt_id(),
            initial.phase(),
            digest_bytes(
                reopened
                    .journal
                    .get(
                        RecordNamespace::StorageWorkspacePinAttempt,
                        &initial.attempt_id(),
                    )
                    .unwrap(),
            ),
            second_repair.attempt_id(),
            second_repair.attempt_ordinal(),
        )
        .unwrap();
        let (reordered_directory, mut reordered_store) = clone_test_store(&directory);
        let reordered_transaction = JournalTransaction::new(
            [164; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    second_repair_request_id.to_vec(),
                    second_sealed_effect.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    second_repair_operation_id.to_vec(),
                    second_sealed_operation_fence.clone(),
                ),
                repair_intent_record(
                    &reordered_intent,
                    reordered_store.key.key_id,
                    &reordered_store.key.secret,
                )
                .unwrap(),
                attempt_record(
                    &second_repair,
                    reordered_store.key.key_id,
                    &reordered_store.key.secret,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        reordered_store
            .commit_journal(&reordered_transaction)
            .unwrap();
        drop(reordered_store);
        assert!(matches!(
            StorageTransactionStore::open_for_test(reordered_directory.path(), key(1), 0),
            Err(StorageStateError::AuthorityLinkMismatch)
        ));

        let gap_operation_id = [165; 16];
        let gap_request_id = [166; 16];
        let gap_assignment_digest = digest(167);
        let gap_effect = vec![12; 8];
        let gap_fence = vec![13; 8];
        let gap_fence_digest = digest_bytes(&gap_fence);
        let gap_attempt_id = derive_attempt_id(
            &reopened.key.secret,
            gap_operation_id,
            workspace_handle,
            WorkspacePinActionV1::Ensure,
            4,
        )
        .unwrap();
        let gap_attempt = WorkspacePinAttemptV1::new_ambiguous(
            gap_attempt_id,
            4,
            WorkspacePinActionV1::Ensure,
            gap_operation_id,
            creation_operation_id,
            gap_fence_digest,
            gap_assignment_digest,
            workspace_assignment_digest,
            creation.catalog(),
            creation.result_digest(),
            workspace_handle,
            host_scope.kernel_boot_id(),
            host_scope.mount_namespace_device(),
            host_scope.mount_namespace_inode(),
            [14; 16],
            4_000,
            "tank/aos/project/work".to_owned(),
            101,
            publication.identity_range_start(),
            publication.identity_range_size(),
            publication.portable_metadata().root_policy(),
            None,
        )
        .unwrap()
        .with_authority_receipt(vec![0xa7])
        .unwrap();
        let gap_intent = StorageWorkspacePinRepairIntentV1::new_for_test(
            gap_operation_id,
            gap_request_id,
            digest(168),
            digest(169),
            gap_assignment_digest,
            gap_effect.clone(),
            gap_fence_digest,
            creation_operation_id,
            creation.catalog(),
            creation.result_digest(),
            digest_bytes(publication_record),
            workspace_handle,
            repaired.attempt_id(),
            repaired.phase(),
            digest_bytes(repaired_record),
            gap_attempt.attempt_id(),
            gap_attempt.attempt_ordinal(),
        )
        .unwrap();
        let (gap_directory, mut gap_store) = clone_test_store(&directory);
        let gap_transaction = JournalTransaction::new(
            [170; 16],
            vec![
                JournalRecord::put(RecordNamespace::Effect, gap_request_id.to_vec(), gap_effect),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    gap_operation_id.to_vec(),
                    gap_fence,
                ),
                repair_intent_record(&gap_intent, gap_store.key.key_id, &gap_store.key.secret)
                    .unwrap(),
                attempt_record(&gap_attempt, gap_store.key.key_id, &gap_store.key.secret).unwrap(),
            ],
        )
        .unwrap();
        gap_store.commit_journal(&gap_transaction).unwrap();
        drop(gap_store);
        assert!(matches!(
            StorageTransactionStore::open_for_test(gap_directory.path(), key(1), 0),
            Err(StorageStateError::AuthorityLinkMismatch | StorageStateError::CorruptRecord)
        ));

        let transaction = JournalTransaction::new(
            [158; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    second_repair_request_id.to_vec(),
                    second_sealed_effect,
                ),
                JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    second_repair_operation_id.to_vec(),
                    second_sealed_operation_fence,
                ),
                repair_intent_record(&second_intent, reopened.key.key_id, &reopened.key.secret)
                    .unwrap(),
                attempt_record(&second_repair, reopened.key.key_id, &reopened.key.secret).unwrap(),
            ],
        )
        .unwrap();
        reopened.commit_journal(&transaction).unwrap();
        drop(reopened);

        let mut reopened =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(reopened.workspace_pin_attempts().unwrap().len(), 3);
        assert_eq!(
            reopened
                .complete_workspace_pin_attempt(
                    second_repair.attempt_id(),
                    &WorkspaceDatasetObservationV1::Exact {
                        name: "tank/aos/project/work".to_owned(),
                        guid: 101,
                    },
                    &WorkspacePinObservationV1::Present(proof.clone()),
                )
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::CompletePublication
        );

        let destroy = destroy_dataset_catalog(
            9,
            "tank/aos/project/work",
            101,
            creation.storage_handle().unwrap(),
        );
        let destroy_operation_id = [159; 16];
        let BeginStorageTransaction::Prepared { mutation_digest } = reopened
            .begin_authorized_with_publication(
                destroy_operation_id,
                digest(160),
                &destroy,
                [144; 16],
                [161; 16],
                vec![9; 8],
                vec![10; 8],
                vec![11; 8],
                None,
            )
            .unwrap()
        else {
            panic!("managed workspace destruction was not prepared")
        };
        let remove = reopened
            .plan_workspace_pin_remove_and_destroy(
                destroy_operation_id,
                digest(162),
                host_scope,
                [13; 16],
                4_000,
                proof,
            )
            .unwrap();
        assert_eq!(remove.attempt_ordinal(), 4);
        let authority = FreshWorkspacePinAuthority::new_for_test(
            remove.attempt_id(),
            remove.authority_digest().unwrap(),
        );
        assert!(matches!(
            reopened
                .begin_workspace_pin_remove_and_destroy(remove.clone(), mutation_digest, authority,)
                .unwrap(),
            BeginWorkspacePinAttemptV1::Dispatch(_)
        ));
        reopened
            .commit_observed(
                destroy_operation_id,
                mutation_digest,
                &destroy,
                &destroy.plan().postcondition(),
                None,
                digest(163),
            )
            .unwrap();
        assert_eq!(
            reopened
                .complete_workspace_pin_attempt(
                    remove.attempt_id(),
                    &WorkspaceDatasetObservationV1::Absent,
                    &WorkspacePinObservationV1::Absent,
                )
                .unwrap(),
            WorkspacePinRecoveryDispositionV1::CompleteRetirement
        );
        drop(reopened);
        let reopened = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert!(matches!(
            reopened.workspace_projection().unwrap().as_slice(),
            [StorageWorkspaceProjection::Retired { .. }]
        ));
    }

    #[test]
    fn combined_destroy_preflight_rejects_capacity_before_any_ambiguous_state() {
        let reference = TempDir::new().unwrap();
        let admitted_bytes = {
            let mut store =
                StorageTransactionStore::open_for_test(reference.path(), key(1), 0).unwrap();
            let (attempt, mutation_digest) = prepare_workspace_remove_attempt(&mut store);
            let authority = FreshWorkspacePinAuthority::new_for_test(
                attempt.attempt_id(),
                attempt.authority_digest().unwrap(),
            );
            assert!(matches!(
                store
                    .begin_workspace_pin_remove_and_destroy(attempt, mutation_digest, authority,)
                    .unwrap(),
                BeginWorkspacePinAttemptV1::Dispatch(_)
            ));
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
        let (attempt, mutation_digest) = prepare_workspace_remove_attempt(&mut store);
        let authorized_attempt = attempt.with_authority_receipt(vec![0xa5]).unwrap();
        let mut ambiguous = store
            .exact_current(attempt.effect_operation_id(), mutation_digest)
            .unwrap()
            .clone();
        ambiguous.phase = DurableStoragePhase::Ambiguous;
        let initial_transaction = JournalTransaction::new(
            pin_attempt_transaction_id(&authorized_attempt),
            vec![
                attempt_record(&authorized_attempt, store.key.key_id, &store.key.secret).unwrap(),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    ambiguous.operation_id.to_vec(),
                    encode_record(&ambiguous, &store.key).unwrap(),
                ),
            ],
        )
        .unwrap();
        assert!(
            store
                .journal
                .preflight_transactions(std::slice::from_ref(&initial_transaction))
                .is_ok()
        );

        let before_sequence = store.journal_sequence_for_test();
        let prior_attempts = store.workspace_pin_attempts().unwrap();
        let authority = FreshWorkspacePinAuthority::new_for_test(
            attempt.attempt_id(),
            attempt.authority_digest().unwrap(),
        );
        assert!(matches!(
            store.begin_workspace_pin_remove_and_destroy(
                attempt.clone(),
                mutation_digest,
                authority,
            ),
            Err(StorageStateError::Journal(JournalError::JournalTooLarge))
        ));
        assert_eq!(store.journal_sequence_for_test(), before_sequence);
        assert_eq!(store.workspace_pin_attempts().unwrap(), prior_attempts);
        assert_eq!(
            store.phase(attempt.effect_operation_id()).unwrap(),
            Some(DurableStoragePhase::Prepared)
        );
    }

    #[test]
    fn remove_uses_latest_satisfied_pin_ordinal_not_attempt_id_order() {
        let directory = TempDir::new().unwrap();
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        let (_initial_remove, _) = prepare_workspace_remove_attempt(&mut store);
        let first = store
            .workspace_pin_attempts()
            .unwrap()
            .into_iter()
            .find(|attempt| attempt.action() == WorkspacePinActionV1::Ensure)
            .unwrap();
        let second_attempt_id = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(second_attempt_id < first.attempt_id());

        let mut mount_point = "/run/aos/sandbox-pins/workspaces/".to_owned();
        for byte in first.workspace_handle() {
            use std::fmt::Write as _;
            write!(mount_point, "{byte:02x}").unwrap();
        }
        let latest_proof = WorkspaceRootPinProofV1::new(
            first.host_boot_id(),
            first.host_mount_namespace_device(),
            first.host_mount_namespace_inode(),
            17,
            "/".to_owned(),
            mount_point,
            "zfs".to_owned(),
            first.dataset_name().to_owned(),
            first.dataset_guid(),
            18,
            19,
            first.root_policy().root_attributes(),
        )
        .unwrap();
        let latest = WorkspacePinAttemptV1::new_ambiguous(
            second_attempt_id,
            2,
            WorkspacePinActionV1::Ensure,
            first.effect_operation_id(),
            first.creation_operation_id(),
            first.operation_fence_digest(),
            first.effect_assignment_digest(),
            first.workspace_assignment_digest(),
            first.creation_result_catalog(),
            first.creation_result_digest(),
            first.workspace_handle(),
            first.host_boot_id(),
            first.host_mount_namespace_device(),
            first.host_mount_namespace_inode(),
            first.clock_provenance(),
            first.effect_deadline_boottime_nanoseconds(),
            first.dataset_name().to_owned(),
            first.dataset_guid(),
            first.identity_range_start(),
            first.identity_range_size(),
            first.root_policy(),
            None,
        )
        .unwrap()
        .with_authority_receipt(vec![0xa6])
        .unwrap()
        .satisfy(Some(latest_proof.clone()))
        .unwrap();
        store.validate_pin_attempt_context(&latest).unwrap();
        let transaction = JournalTransaction::new(
            pin_attempt_transaction_id(&latest),
            vec![attempt_record(&latest, store.key.key_id, &store.key.secret).unwrap()],
        )
        .unwrap();
        store.commit_journal(&transaction).unwrap();
        store.pin_attempts.insert(latest.attempt_id(), latest);

        let destroy_operation = [107; 16];
        let planned = store
            .plan_workspace_pin_remove_and_destroy(
                destroy_operation,
                digest(110),
                WorkspacePinHostScopeV1::new([4; 16], 5, 6).unwrap(),
                [10; 16],
                1_000,
                latest_proof.clone(),
            )
            .unwrap();
        assert_eq!(planned.attempt_ordinal(), 3);
        assert_eq!(planned.expected_pin(), Some(&latest_proof));
        assert!(matches!(
            store.plan_workspace_pin_remove_and_destroy(
                destroy_operation,
                digest(110),
                WorkspacePinHostScopeV1::new([4; 16], 5, 6).unwrap(),
                [10; 16],
                1_000,
                first.satisfied_pin().unwrap().clone(),
            ),
            Err(StorageStateError::AuthorityLinkMismatch)
        ));
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
                    digest(57 + index),
                    catalog,
                    [58 + index; 16],
                    [59 + index; 16],
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
                digest(60),
                &third,
                [61; 16],
                [62; 16],
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
            store.authority_record(RecordNamespace::DesiredState, &[59; 16]),
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
    fn physical_catalog_chain_recovers_every_production_transition_kind() {
        let directory = TempDir::new().unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [1; 32], domains())
                .unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap();
        let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap();
        let seed_workspace = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project/seed",
            100,
            [30; 32],
            domains(),
        )
        .unwrap();
        let workspace = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project/work",
            101,
            [31; 32],
            domains(),
        )
        .unwrap();
        let snapshot =
            ResolvedSnapshot::from_catalog(seed_workspace.clone(), "revision-1", 201, [32; 32])
                .unwrap();
        let clone = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project/clone",
            301,
            [33; 32],
            domains(),
        )
        .unwrap();
        let hold_id = HoldId::from_bytes([34; 16]).unwrap();
        let bootstrap_snapshot_context = ResolvedCatalogCommitmentV1::new_for_test(
            7,
            domains(),
            CatalogPlanV1::HoldSnapshot {
                snapshot: snapshot.clone(),
                hold_id,
            },
        )
        .unwrap();
        let catalogs = vec![
            ResolvedCatalogCommitmentV1::new_for_test(
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
            ResolvedCatalogCommitmentV1::new_for_test(
                9,
                domains(),
                CatalogPlanV1::HoldSnapshot {
                    snapshot: snapshot.clone(),
                    hold_id,
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new_for_test(
                11,
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
            ResolvedCatalogCommitmentV1::new_for_test(
                13,
                domains(),
                CatalogPlanV1::SetQuota {
                    dataset: clone.clone(),
                    space: WorkspaceSpacePolicyV1::new(8192, ReservationPolicy::None).unwrap(),
                    ancestor: ancestor.clone(),
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new_for_test(
                15,
                domains(),
                CatalogPlanV1::DestroyDataset {
                    dataset: clone.clone(),
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new_for_test(
                17,
                domains(),
                CatalogPlanV1::ReleaseHold {
                    snapshot: snapshot.clone(),
                    hold_id,
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new_for_test(
                19,
                domains(),
                CatalogPlanV1::DestroySnapshot {
                    snapshot: snapshot.clone(),
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new_for_test(
                21,
                domains(),
                CatalogPlanV1::DestroyDataset {
                    dataset: seed_workspace,
                },
            )
            .unwrap(),
            ResolvedCatalogCommitmentV1::new_for_test(
                23,
                domains(),
                CatalogPlanV1::DestroyDataset { dataset: workspace },
            )
            .unwrap(),
        ];
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        store
            .initialize_catalog_from_protected_snapshot(
                6,
                &[catalogs[0].clone(), bootstrap_snapshot_context],
            )
            .unwrap();

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
    fn prepared_abort_is_durable_replayable_and_releases_catalog_lineage() {
        let directory = TempDir::new().unwrap();
        let retired_catalog = catalog(7, "tank/aos/project/retired");
        let replacement_catalog = catalog(7, "tank/aos/project/replacement");
        let retired_operation = [81; 16];
        let replacement_operation = [91; 16];
        let retired_range = (u32::from(85_u8) * 65_536, 65_536);
        let retired_mutation = {
            let mut store =
                StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
            initialize(&mut store, &retired_catalog);

            let BeginStorageTransaction::Prepared { mutation_digest } = store
                .begin_authorized_with_publication(
                    retired_operation,
                    digest(82),
                    &retired_catalog,
                    [83; 16],
                    [84; 16],
                    vec![1; 8],
                    vec![2; 8],
                    vec![3; 8],
                    Some(publication_intent(retired_operation, &retired_catalog, 85)),
                )
                .unwrap()
            else {
                panic!("retired operation was not prepared")
            };
            let entry = store.current_recovery_entry(retired_operation).unwrap();

            store.abort_prepared_exact(entry, &retired_catalog).unwrap();

            assert_eq!(
                store.phase(retired_operation).unwrap(),
                Some(DurableStoragePhase::Aborted)
            );
            assert!(
                store
                    .authority_record(
                        RecordNamespace::StorageCatalogReservation,
                        &retired_operation,
                    )
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .authority_record(RecordNamespace::DesiredState, &[83; 16])
                    .unwrap()
                    .is_some()
            );
            assert!(
                store
                    .authority_record(RecordNamespace::Effect, &[84; 16])
                    .unwrap()
                    .is_some()
            );
            assert!(
                store
                    .authority_record(RecordNamespace::AuthorityPublication, &retired_operation)
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                store.workspace_identity_range(retired_operation).unwrap(),
                Some(retired_range)
            );
            assert!(store.workspace_projection().unwrap().is_empty());
            assert!(store.workspace_pin_attempts().unwrap().is_empty());
            assert!(matches!(
                store.begin_authorized_with_publication(
                    retired_operation,
                    digest(82),
                    &retired_catalog,
                    [83; 16],
                    [84; 16],
                    vec![1; 8],
                    vec![2; 8],
                    vec![3; 8],
                    Some(publication_intent(retired_operation, &retired_catalog, 85)),
                ),
                Ok(BeginStorageTransaction::Aborted {
                    mutation_digest: replayed
                }) if replayed == mutation_digest
            ));

            assert!(matches!(
                store.begin_authorized_with_publication(
                    replacement_operation,
                    digest(92),
                    &replacement_catalog,
                    [93; 16],
                    [94; 16],
                    vec![4; 8],
                    vec![5; 8],
                    vec![6; 8],
                    Some(publication_intent(
                        replacement_operation,
                        &replacement_catalog,
                        95,
                    )),
                ),
                Ok(BeginStorageTransaction::Prepared { .. })
            ));
            mutation_digest
        };

        let reopened = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(
            reopened.phase(retired_operation).unwrap(),
            Some(DurableStoragePhase::Aborted)
        );
        assert_eq!(
            reopened.phase(replacement_operation).unwrap(),
            Some(DurableStoragePhase::Prepared)
        );
        assert_eq!(
            reopened
                .workspace_identity_range(retired_operation)
                .unwrap(),
            Some(retired_range)
        );
        assert!(reopened.workspace_projection().unwrap().is_empty());
        assert!(reopened.workspace_pin_attempts().unwrap().is_empty());
        assert!(matches!(
            reopened
                .recovery_entries()
                .unwrap()
                .find(|entry| entry.operation_id() == retired_operation),
            Some(entry)
                if entry.phase() == DurableStoragePhase::Aborted
                    && entry.mutation_digest() == retired_mutation
        ));
    }

    #[test]
    fn abort_rejects_nonprepared_or_inexact_operation() {
        let directory = TempDir::new().unwrap();
        let prepared_catalog = catalog(7, "tank/aos/project/work");
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &prepared_catalog);
        let BeginStorageTransaction::Prepared { mutation_digest } = store
            .begin([39; 16], digest(40), &prepared_catalog)
            .unwrap()
        else {
            panic!("operation was not prepared")
        };
        let entry = store.current_recovery_entry([39; 16]).unwrap();
        let other_catalog = catalog(7, "tank/aos/project/other");

        assert!(matches!(
            store.abort_prepared_exact(entry, &other_catalog),
            Err(StorageStateError::InvalidTransition)
        ));
        store
            .mark_mutation_ambiguous([39; 16], mutation_digest)
            .unwrap();
        assert!(matches!(
            store.abort_prepared_exact(entry, &prepared_catalog),
            Err(StorageStateError::InvalidTransition)
        ));
    }

    #[test]
    fn abort_post_commit_failure_poisons_cache_and_reopens_aborted() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let operation_id = [51; 16];
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);
        store.begin(operation_id, digest(52), &catalog).unwrap();
        let entry = store.current_recovery_entry(operation_id).unwrap();
        store.fail_after_next_journal_commit_for_test();

        assert!(matches!(
            store.abort_prepared_exact(entry, &catalog),
            Err(StorageStateError::Journal(JournalError::Io(_)))
        ));
        assert!(matches!(
            store.phase(operation_id),
            Err(StorageStateError::Journal(JournalError::Poisoned))
        ));
        drop(store);

        let reopened = StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        assert_eq!(
            reopened.phase(operation_id).unwrap(),
            Some(DurableStoragePhase::Aborted)
        );
        assert!(
            reopened
                .authority_record(RecordNamespace::StorageCatalogReservation, &operation_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reopen_rejects_aborted_operation_with_restored_reservation() {
        let directory = TempDir::new().unwrap();
        let catalog = catalog(7, "tank/aos/project/work");
        let operation_id = [61; 16];
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);
        store.begin(operation_id, digest(62), &catalog).unwrap();
        let reservation = store
            .authority_record(RecordNamespace::StorageCatalogReservation, &operation_id)
            .unwrap()
            .unwrap()
            .to_vec();
        let entry = store.current_recovery_entry(operation_id).unwrap();
        store.abort_prepared_exact(entry, &catalog).unwrap();

        store.put_authority_record_for_test(
            RecordNamespace::StorageCatalogReservation,
            &operation_id,
            reservation,
        );
        drop(store);

        assert!(matches!(
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0),
            Err(StorageStateError::CorruptRecord)
        ));
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
    fn snapshot_prepares_before_the_observed_metadata_commit() {
        let directory = TempDir::new().unwrap();
        let catalog = snapshot_catalog(7);
        let operation_id = [47; 16];
        let request_digest = digest(48);
        let mut store =
            StorageTransactionStore::open_for_test(directory.path(), key(1), 0).unwrap();
        initialize(&mut store, &catalog);
        let before = store.journal_sequence_for_test();

        assert!(matches!(
            store.begin(operation_id, request_digest, &catalog).unwrap(),
            BeginStorageTransaction::Prepared { .. }
        ));
        assert!(store.journal_sequence_for_test() > before);
        assert_eq!(
            store.phase(operation_id).unwrap(),
            Some(DurableStoragePhase::Prepared)
        );
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
            let mut bytes = Vec::with_capacity(1 + 32 + 32 + 8);
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
