//! Immutable publisher-admission records and identifiers.
//!
//! These values are controller-internal protected state, not portable objects or
//! network authority. All digests are domain separated and every transition is
//! represented by an immutable successor record rather than an `authorized`
//! boolean.

use aos_sandbox_core::{
    ObjectDescriptor, ObjectDigest, OperationId, PublicationReservationId, PublisherChallengeV1,
    PublisherInstanceId,
};
use sha2::{Digest as _, Sha256};

/// Hard bounds for one complete publisher authority replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionLimits {
    /// Maximum retained semantic heads, terminal facts, and checkpoint.
    pub maximum_records: usize,
    /// Maximum bytes in one canonical record payload.
    pub maximum_record_bytes: usize,
    /// Maximum aggregate full-log bytes or compact floor plus suffix bytes.
    pub maximum_materialized_bytes: usize,
    /// Maximum simultaneously outstanding completion permits.
    pub maximum_outstanding_permits: usize,
    /// Maximum admission-plan or local-message bytes.
    pub maximum_protocol_bytes: usize,
}

impl AdmissionLimits {
    /// Validates limits against fixed implementation ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`super::AdmissionError::InvalidLimits`] for zero or excessive
    /// limits.
    pub fn validate(self) -> Result<Self, super::AdmissionError> {
        if self.maximum_records == 0
            || self.maximum_records > 1_000_000
            || self.maximum_record_bytes == 0
            || self.maximum_record_bytes > 16 * 1024 * 1024
            || self.maximum_materialized_bytes == 0
            || self.maximum_materialized_bytes > 512 * 1024 * 1024
            || self.maximum_outstanding_permits == 0
            || self.maximum_outstanding_permits > 65_536
            || self.maximum_protocol_bytes == 0
            || self.maximum_protocol_bytes > 1024 * 1024
        {
            return Err(super::AdmissionError::InvalidLimits);
        }
        Ok(self)
    }
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            maximum_records: 65_536,
            maximum_record_bytes: 1024 * 1024,
            maximum_materialized_bytes: 256 * 1024 * 1024,
            maximum_outstanding_permits: 4096,
            maximum_protocol_bytes: 64 * 1024,
        }
    }
}

/// Monotone controller authority epoch preserved by failover checkpoints.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicationAuthorityEpoch(u64);

impl PublicationAuthorityEpoch {
    /// Constructs a nonzero authority epoch.
    ///
    /// # Errors
    ///
    /// Returns [`super::AdmissionError::InvalidIdentity`] for zero.
    pub fn new(value: u64) -> Result<Self, super::AdmissionError> {
        if value == 0 {
            return Err(super::AdmissionError::InvalidIdentity("authority epoch"));
        }
        Ok(Self(value))
    }

    /// Returns the integer epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the checked immediate successor.
    ///
    /// # Errors
    ///
    /// Returns [`super::AdmissionError::GenerationExhausted`] on overflow.
    pub fn checked_next(self) -> Result<Self, super::AdmissionError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(super::AdmissionError::GenerationExhausted)
    }
}

/// Identifies one retained one-shot completion permit.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicationPermitId([u8; 16]);

impl PublicationPermitId {
    /// Validates one nonzero permit identity.
    ///
    /// # Errors
    ///
    /// Returns [`super::AdmissionError::InvalidIdentity`] for the zero sentinel.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, super::AdmissionError> {
        if bytes == [0; 16] {
            return Err(super::AdmissionError::InvalidIdentity("completion permit"));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact permit bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Selects the closed protected record family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProtectedRecordKindV1 {
    /// Controller-authorized source release.
    SourceRelease = 1,
    /// Exact challenge consumption.
    ChallengeConsumption = 2,
    /// Publication admission decision.
    AdmissionDecision = 3,
    /// Capacity reservation or residency successor.
    Accounting = 4,
    /// Prepared private artifact.
    PreparedArtifact = 5,
    /// One-shot completion permit.
    CompletionPermit = 6,
    /// Terminal catalog completion receipt.
    CompletionReceipt = 7,
    /// Rollback-resistant authority checkpoint.
    AuthorityCheckpoint = 8,
    /// Conflict/uncertainty poison latch.
    Poison = 9,
    /// Protected publication-root registry successor.
    RootRegistry = 10,
    /// Durable catalog eviction and residency release.
    CatalogEviction = 11,
    /// Fenced physical/catalog recovery observation.
    RecoveryObservation = 12,
    /// Exact pre-inode materialization intent.
    PreparationIntent = 13,
}

impl ProtectedRecordKindV1 {
    pub(super) fn from_code(code: u8) -> Result<Self, super::ProtectedRecordCodecError> {
        match code {
            1 => Ok(Self::SourceRelease),
            2 => Ok(Self::ChallengeConsumption),
            3 => Ok(Self::AdmissionDecision),
            4 => Ok(Self::Accounting),
            5 => Ok(Self::PreparedArtifact),
            6 => Ok(Self::CompletionPermit),
            7 => Ok(Self::CompletionReceipt),
            8 => Ok(Self::AuthorityCheckpoint),
            9 => Ok(Self::Poison),
            10 => Ok(Self::RootRegistry),
            11 => Ok(Self::CatalogEviction),
            12 => Ok(Self::RecoveryObservation),
            13 => Ok(Self::PreparationIntent),
            _ => Err(super::ProtectedRecordCodecError::UnknownKind),
        }
    }
}

/// Commits every deterministic input before private-inode creation begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactPreparationIntentV1 {
    /// Publication operation.
    pub operation: OperationId,
    /// Publisher execution that owns the attempt.
    pub publisher_instance: PublisherInstanceId,
    /// Admission decision authorizing the attempt.
    pub decision_digest: ObjectDigest,
    /// Exact selected protected root record.
    pub root_record_digest: ObjectDigest,
    /// Selected publication-root generation.
    pub root_generation: u64,
    /// Exact requested content descriptor.
    pub content: ObjectDescriptor,
    /// Digest of the controller-derived private name.
    pub private_name_digest: ObjectDigest,
    /// Digest of the controller-derived final name.
    pub final_name_digest: ObjectDigest,
    /// Maximum physical allocation admitted for the attempt.
    pub maximum_allocated_bytes: u64,
    /// Domain-separated commitment to this complete intent.
    pub intent_digest: ObjectDigest,
}

/// States one durable admission operation without erasing obligations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDecisionStateV1 {
    /// Capacity and authority were committed before materialization.
    Admitted,
    /// The exact artifact was prepared but has no completion permit.
    ArtifactPrepared,
    /// A one-shot completion permit is outstanding.
    CompletionPermitted,
    /// Revocation denies new work while an existing permit remains outstanding.
    RevocationPending,
    /// Catalog completion and residency conversion committed.
    Completed,
    /// A definitely pre-effect operation released its reservation.
    Aborted,
    /// Physical or durable outcome is unresolved and remains fully charged.
    Uncertain,
    /// A contradiction permanently denies authority until protected recovery.
    Poisoned,
}

/// Retains exact consumption of one publisher challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeConsumptionV1 {
    /// Live publisher execution that registered the challenge.
    pub publisher_instance: PublisherInstanceId,
    /// Exact unpredictable challenge.
    pub challenge: PublisherChallengeV1,
    /// Domain-separated canonical admission-request commitment.
    pub request_commitment: ObjectDigest,
    /// Idempotent publication operation.
    pub operation: OperationId,
    /// Capacity reservation identity.
    pub reservation: PublicationReservationId,
    /// Digest of the immutable admission decision consuming the challenge.
    pub decision_digest: ObjectDigest,
}

/// Stores one exact controller admission and its provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionDecisionV1 {
    /// Publication operation.
    pub operation: OperationId,
    /// Reservation retained through every uncertain state.
    pub reservation: PublicationReservationId,
    /// Publisher execution authorized to begin work.
    pub publisher_instance: PublisherInstanceId,
    /// Complete canonical admission request.
    pub canonical_request: Vec<u8>,
    /// Complete canonical publisher-domain plan.
    pub canonical_plan: Vec<u8>,
    /// Digest of fresh current-runtime binding evidence.
    pub runtime_binding_digest: ObjectDigest,
    /// Exact protected source-release record digest.
    pub source_release_digest: ObjectDigest,
    /// Exact global root-registry checkpoint digest.
    pub root_registry_digest: ObjectDigest,
    /// Exact global root-registry checkpoint generation.
    pub root_registry_generation: u64,
    /// Selected protected publication-root record digest.
    pub selected_root_digest: ObjectDigest,
    /// Selected protected publication-root generation.
    pub selected_root_generation: u64,
    /// Controller authority epoch that admitted the operation.
    pub authority_epoch: PublicationAuthorityEpoch,
    /// Current immutable successor state.
    pub state: AdmissionDecisionStateV1,
    /// Domain-separated digest of all preceding fields except `state`.
    pub decision_digest: ObjectDigest,
}

/// Commits the exact sealed private artifact before a completion permit exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactCommitmentV1 {
    /// Publication operation.
    pub operation: OperationId,
    /// Publisher execution that owns the pinned artifact.
    pub publisher_instance: PublisherInstanceId,
    /// Admission decision authorizing materialization.
    pub decision_digest: ObjectDigest,
    /// Durable pre-inode intent consumed by this observation.
    pub preparation_intent_digest: ObjectDigest,
    /// Selected publication root generation.
    pub root_generation: u64,
    /// Exact requested content descriptor.
    pub content: ObjectDescriptor,
    /// Fs-verity SHA-256 measurement observed on the pinned inode.
    pub verity_sha256: [u8; 32],
    /// Digest of the controller-derived private name.
    pub private_name_digest: ObjectDigest,
    /// Digest of the controller-derived canonical final name.
    pub final_name_digest: ObjectDigest,
    /// Exact copied byte count.
    pub bytes: u64,
    /// Exact allocated resident bytes observed for the sealed inode.
    pub allocated_bytes: u64,
    /// Domain-separated commitment to this complete prepared artifact.
    pub artifact_digest: ObjectDigest,
}

/// States a one-shot completion permit without deleting its history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionPermitStateV1 {
    /// Exact completion may proceed once.
    Outstanding,
    /// Revocation is pending, but the exact irrevocable completion remains allowed.
    RevocationPending,
    /// Exact completion was committed and cannot repeat.
    Spent,
    /// Recovery proved no effect could occur and retired the permit.
    RetiredWithoutEffect,
    /// Outcome is ambiguous; the permit and reservation remain charged.
    Uncertain,
}

/// Retains controller-owned permission for exactly one naming/catalog completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionPermitV1 {
    /// One-shot permit identity.
    pub permit: PublicationPermitId,
    /// Publication operation.
    pub operation: OperationId,
    /// Capacity reservation converted only by the terminal receipt.
    pub reservation: PublicationReservationId,
    /// Exact prepared artifact.
    pub artifact_digest: ObjectDigest,
    /// Exact admission decision.
    pub decision_digest: ObjectDigest,
    /// Authorized live publisher execution.
    pub publisher_instance: PublisherInstanceId,
    /// Root generation selected by admission and artifact preparation.
    pub root_generation: u64,
    /// Epoch that owns this outstanding obligation.
    pub authority_epoch: PublicationAuthorityEpoch,
    /// Current immutable successor state.
    pub state: CompletionPermitStateV1,
    /// Digest of the permit identity and immutable bindings.
    pub permit_digest: ObjectDigest,
}

/// Commits terminal catalog visibility and exact accounting conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionReceiptV1 {
    /// Spent completion permit.
    pub permit: PublicationPermitId,
    /// Publication operation.
    pub operation: OperationId,
    /// Exact artifact made visible.
    pub artifact_digest: ObjectDigest,
    /// Immutable committed catalog generation.
    pub catalog_generation: u64,
    /// Digest of the complete committed catalog entry.
    pub catalog_entry_digest: ObjectDigest,
    /// Complete typed canonical catalog entry.
    pub catalog_entry: super::CommittedReadEntryV1,
    /// Physical bytes charged to residency.
    pub resident_bytes: u64,
    /// Domain-separated terminal receipt digest.
    pub receipt_digest: ObjectDigest,
}

/// Commits durable unpinned catalog eviction and residency release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogEvictionReceiptV1 {
    /// Publication operation whose resident entry was removed.
    pub operation: OperationId,
    /// Exact removed canonical catalog entry.
    pub catalog_entry_digest: ObjectDigest,
    /// Catalog generation that contained the entry.
    pub prior_catalog_generation: u64,
    /// Exact successor catalog generation after removal.
    pub eviction_catalog_generation: u64,
    /// Exact allocated bytes released from residency.
    pub released_bytes: u64,
    /// Canonical commitment to this complete eviction fact.
    pub eviction_digest: ObjectDigest,
}

/// Selects the closed durable result of one trusted recovery observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryObservationKindCodeV1 {
    /// No effect existed before an artifact or permit could escape.
    NoEffect,
    /// The exact private artifact remains retained.
    PrivateArtifact,
    /// A fenced search proved exact physical and catalog absence.
    AbsentAfterFence,
    /// The final object remains quarantined without its catalog entry.
    FinalCatalogAbsent,
    /// The exact missing catalog obligation was durably repaired.
    FinalCatalogRepaired,
    /// The exact final object and catalog entry were already committed.
    Committed,
    /// Physical or catalog facts contradicted retained authority.
    Contradiction,
}

/// Commits trusted physical custody and any executor fence used by recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryObservationReceiptV1 {
    /// Operation observed under recovery custody.
    pub operation: OperationId,
    /// Closed observed outcome.
    pub outcome: RecoveryObservationKindCodeV1,
    /// Exact retained artifact, absent only for a pre-artifact no-effect fact.
    pub artifact_digest: Option<ObjectDigest>,
    /// Exact durable catalog entry for committed or repaired outcomes.
    pub catalog_entry_digest: Option<ObjectDigest>,
    /// Catalog predecessor committed by a pre-effect repair authorization.
    pub repair_prior_catalog_generation: u64,
    /// Exact committed fenced-absence receipt consumed by a repair completion.
    pub repair_authorization_digest: Option<ObjectDigest>,
    /// Exact selected protected root observed under descriptor custody.
    pub physical_root_digest: ObjectDigest,
    /// Commitment minted while the trusted adapter retained physical custody.
    pub physical_observation_digest: ObjectDigest,
    /// Exact old executor identity covered by the protected recovery fence.
    pub executor_instance: Option<PublisherInstanceId>,
    /// Protected executor fence, required for post-permit absence/final facts.
    pub executor_fence_digest: Option<ObjectDigest>,
    /// Domain-separated commitment to this complete recovery fact.
    pub receipt_digest: ObjectDigest,
}

/// Selects recovery behavior without manufacturing new authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDispositionV1 {
    /// Exact terminal state is already committed.
    NoWork,
    /// Only observe private/final/catalog state; no effect is authorized.
    ObserveOnly,
    /// An inconsistent or foreign artifact must remain isolated.
    Quarantine,
    /// Protected state is contradictory and all authority is denied.
    Poisoned,
}

/// Summarizes one rollback-protected authority frontier for failover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCheckpointV1 {
    /// Authority epoch represented by this checkpoint.
    pub epoch: PublicationAuthorityEpoch,
    /// Monotone protected record sequence.
    pub sequence: u64,
    /// Digest of the complete canonical materialized state.
    pub state_digest: ObjectDigest,
    /// Digest of sorted outstanding permit digests.
    pub outstanding_digest: ObjectDigest,
    /// Number of outstanding, pending-revocation, or uncertain permits.
    pub outstanding_count: u32,
    /// Whether this frontier is fail-closed after ambiguity or conflict.
    pub poisoned: bool,
}

/// Carries one canonical protected-store mutation for a later journal adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerMutation {
    /// Closed record family.
    pub kind: ProtectedRecordKindV1,
    /// Exact immutable record key.
    pub key: Vec<u8>,
    /// Canonical protected record bytes.
    pub value: Vec<u8>,
}

pub(crate) fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) fn validate_nonzero(
    fields: &[(&'static str, &[u8])],
) -> Result<(), super::AdmissionError> {
    for (name, bytes) in fields {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(super::AdmissionError::InvalidIdentity(name));
        }
    }
    Ok(())
}
