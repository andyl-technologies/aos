//! In-memory AOSSPL01 records and immutable recovery projections.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SourceProviderAuthorityV1, SourceProviderMethod, SourceProviderSigningKeyV1,
    SourceProviderStatus,
};

use super::{evidence::BackendEvidenceV1, reopen::ReopenIdentityV1};
use crate::NormalizedAcquisitionIntentV1;

/// Identifies the closed durable record kinds in the SourceProvider namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecordKind {
    AuthorityHead = 1,
    CatalogHead = 2,
    SessionHead = 3,
    Attempt = 4,
    Acquisition = 5,
    Release = 6,
    SessionHistory = 7,
}

impl RecordKind {
    /// Decodes one closed record-kind discriminant.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] for an unknown discriminant.
    pub fn decode(value: u8) -> Result<Self, super::LedgerFormatErrorV1> {
        match value {
            1 => Ok(Self::AuthorityHead),
            2 => Ok(Self::CatalogHead),
            3 => Ok(Self::SessionHead),
            4 => Ok(Self::Attempt),
            5 => Ok(Self::Acquisition),
            6 => Ok(Self::Release),
            7 => Ok(Self::SessionHistory),
            _ => Err(super::LedgerFormatErrorV1::Corrupt("unknown record kind")),
        }
    }
}

/// Contains one hostile-decoded canonical AOSSPL record body.
pub enum DecodedRecordV1 {
    Authority(AuthorityHeadRecordV1),
    Catalog(CatalogHeadRecordV1),
    Session(HolderSessionHeadRecordV1),
    SessionHistory(HolderSessionHeadRecordV1),
    Attempt(AttemptRecordV1),
    Acquisition(AcquisitionRecordV1),
    Release(ReleaseRecordV1),
}

/// Controls whether the provider can admit new acquisitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProviderAuthorityStateV1 {
    /// Acquire, Release, and Inventory may be admitted.
    Active = 1,
    /// Only Release and Inventory may be admitted.
    AcquireClosed = 2,
    /// No new requests may be admitted.
    Retired = 3,
}

/// Identifies one durable provider attempt state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProviderAttemptStateV1 {
    /// The request and its sequence were synced before any effect.
    Reserved = 1,
    /// The exact response was synced and may be replayed.
    Completed = 2,
    /// Large frames were discarded after the session became unusable.
    Retired = 3,
}

/// Identifies one durable acquisition lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProviderAcquisitionStateV1 {
    /// The acquire effect is reserved but has no complete observation.
    Applying = 1,
    /// The backend retains a genuinely unresolved durable operation.
    Pending = 2,
    /// A signed lease and an exact backend selection are active.
    Active = 3,
    /// Release was durably reserved before backend mutation.
    Releasing = 4,
    /// An exact release tombstone terminates the lineage.
    Released = 5,
    /// Contradictory evidence requires manual reconciliation.
    Faulted = 6,
}

/// Identifies one durable release record state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProviderReleaseStateV1 {
    /// Backend release is reserved but not durably completed.
    Intent = 1,
    /// Persistent evidence proves the exact lease release completed.
    Tombstone = 2,
}

/// Stores physical source-root identity without a live descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRootIdentityV1 {
    pub kernel_boot_id: [u8; 16],
    pub device: u64,
    pub inode: u64,
    pub unique_mount_id: u64,
}

impl SourceRootIdentityV1 {
    /// Constructs a stable physical descriptor observation.
    ///
    /// This value contains no descriptor or execution authority.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] when any identity component is
    /// the reserved zero sentinel.
    pub fn new(
        kernel_boot_id: [u8; 16],
        device: u64,
        inode: u64,
        unique_mount_id: u64,
    ) -> Result<Self, super::LedgerFormatErrorV1> {
        if kernel_boot_id == [0; 16] || device == 0 || inode == 0 || unique_mount_id == 0 {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "invalid source-root identity",
            ));
        }
        Ok(Self {
            kernel_boot_id,
            device,
            inode,
            unique_mount_id,
        })
    }

    /// Returns the boot ID in which the source root was observed.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Returns the observed device number.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the observed inode number.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the kernel-lifetime unique mount identity.
    #[must_use]
    pub const fn unique_mount_id(&self) -> u64 {
        self.unique_mount_id
    }
}

/// Stores the provider-wide authority and inventory head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityHeadRecordV1 {
    pub revision: u64,
    pub state: ProviderAuthorityStateV1,
    pub provider: SourceProviderAuthorityV1,
    pub trust_generation: u64,
    pub trust_digest: ObjectDigest,
    pub revocation_generation: u64,
    pub revocation_digest: ObjectDigest,
    pub valid_from_seconds: i64,
    pub valid_until_seconds: i64,
    pub route_id: [u8; 16],
    pub route_generation: u64,
    pub route_digest: ObjectDigest,
    pub resource_namespace_digest: ObjectDigest,
    pub proof_class_capabilities: u8,
    pub supports_recursive: bool,
    pub supports_kernel_coupled: bool,
    pub provider_hello_signer: SourceProviderSigningKeyV1,
    pub provider_outcome_signer: SourceProviderSigningKeyV1,
    pub catalog_generation: u64,
    pub catalog_digest: ObjectDigest,
    pub inventory_generation: u64,
    pub inventory_state_digest: ObjectDigest,
    pub last_lease_issue_generation: u64,
    pub last_release_generation: u64,
    pub active_lease_count: u64,
}

/// Stores one immutable catalog generation and authenticated publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogHeadRecordV1 {
    pub revision: u64,
    pub provider: SourceProviderAuthorityV1,
    pub resource_namespace_digest: ObjectDigest,
    pub catalog_generation: u64,
    pub catalog_digest: ObjectDigest,
    pub publisher_authority_id: [u8; 16],
    pub publication_generation: u64,
    pub publication_receipt_digest: ObjectDigest,
    pub predecessor_catalog_generation: u64,
    pub predecessor_catalog_digest: ObjectDigest,
    pub catalog_floor_generation: u64,
    pub catalog_floor_digest: ObjectDigest,
    pub publication_seconds: i64,
    pub publication_trust_generation: u64,
    pub publication_trust_digest: ObjectDigest,
    pub publication_revocation_generation: u64,
    pub publication_revocation_digest: ObjectDigest,
    pub publisher_signer: SourceProviderSigningKeyV1,
    pub canonical_publication: Vec<u8>,
}

/// Stores the verified actual writer identity for a holder session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriterIdentityV1 {
    pub uid: u32,
    pub gid: u32,
    pub tgid: u32,
    pub start_time_ticks: u64,
    pub cgroup_digest: ObjectDigest,
}

/// Stores a current or immutable historical holder-session transcript head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HolderSessionHeadRecordV1 {
    pub revision: u64,
    pub session_generation: u64,
    pub provider: SourceProviderAuthorityV1,
    pub holder: SourceProviderAuthorityV1,
    pub session_binding: ObjectDigest,
    pub predecessor_session_binding: Option<ObjectDigest>,
    pub supersession_evidence_digest: Option<ObjectDigest>,
    pub boot_id: [u8; 16],
    pub root_process_instance: [u8; 16],
    pub provider_process_instance: [u8; 16],
    pub provider_process_id: u32,
    pub provider_start_time_ticks: u64,
    pub provider_execution_commitment: ObjectDigest,
    pub root_writer: WriterIdentityV1,
    pub route_id: [u8; 16],
    pub route_generation: u64,
    pub route_digest: ObjectDigest,
    pub resource_namespace_digest: ObjectDigest,
    pub trust_generation: u64,
    pub trust_digest: ObjectDigest,
    pub revocation_generation: u64,
    pub revocation_digest: ObjectDigest,
    pub signers: [SourceProviderSigningKeyV1; 4],
    pub signer_set_commitment: ObjectDigest,
    pub request_sequence_floor: u64,
    pub response_sequence_floor: u64,
    pub acquisition_sequence_floor: u64,
    pub next_acquisition_sequence: u64,
    pub next_request_sequence: u64,
    pub next_response_sequence: u64,
    pub pending_attempt_digest: Option<ObjectDigest>,
    pub last_completed_attempt_digest: Option<ObjectDigest>,
    pub root_hello_digest: ObjectDigest,
    pub provider_hello_digest: ObjectDigest,
    pub root_hello: Vec<u8>,
    pub provider_hello: Vec<u8>,
}

/// Identifies an attempt across holder signing-key rotations.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttemptKeyV1 {
    pub provider_id: [u8; 16],
    pub holder_id: [u8; 16],
    pub root_record_key_id: [u8; 16],
    pub method: u8,
    pub request_id: [u8; 16],
}

/// Stores one reserved, completed, or retired request attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptRecordV1 {
    pub revision: u64,
    pub state: ProviderAttemptStateV1,
    pub provider: SourceProviderAuthorityV1,
    pub holder: SourceProviderAuthorityV1,
    pub root_record_signer: SourceProviderSigningKeyV1,
    pub method: SourceProviderMethod,
    pub status: Option<SourceProviderStatus>,
    pub request_id: [u8; 16],
    pub signed_request_digest: ObjectDigest,
    pub typed_request_digest: ObjectDigest,
    pub operation_intent_digest: ObjectDigest,
    pub acquisition_sequence: u64,
    pub attempt_digest: ObjectDigest,
    pub session_binding: ObjectDigest,
    pub request_sequence: u64,
    pub response_sequence: Option<u64>,
    pub deadline_seconds: i64,
    pub verified_at_seconds: i64,
    pub current_valid_until_seconds: i64,
    pub proof_class_capabilities: u8,
    pub supports_recursive: bool,
    pub supports_kernel_coupled: bool,
    pub root_process_instance: [u8; 16],
    pub provider_process_instance: [u8; 16],
    pub signer_set_commitment: ObjectDigest,
    pub recovery_predecessor_attempt_digest: Option<ObjectDigest>,
    pub recovery_predecessor_session_binding: Option<ObjectDigest>,
    pub recovery_fence_digest: Option<ObjectDigest>,
    pub recovery_fence_class: u8,
    pub recovery_revocation_generation: u64,
    pub recovery_revocation_digest: ObjectDigest,
    pub signed_request_digest_again: ObjectDigest,
    pub response_digest: Option<ObjectDigest>,
    pub descriptor_commitment: ObjectDigest,
    pub result_digest: Option<ObjectDigest>,
    pub response_catalog_generation: u64,
    pub response_catalog_digest: ObjectDigest,
    pub signed_request: Vec<u8>,
    pub completed_response: Vec<u8>,
}

/// Identifies one provider acquisition within a holder authority.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AcquisitionKeyV1 {
    pub provider_id: [u8; 16],
    pub holder_id: [u8; 16],
    pub acquisition_id: ObjectDigest,
}

/// Retains one lease in the immutable succession chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseLineageV1 {
    pub issue_generation: u64,
    pub lease_id: [u8; 16],
    pub lease_digest: ObjectDigest,
    pub attempt_digest: ObjectDigest,
}

/// Stores one acquisition's durable effect, lease, backend, and reopen state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionRecordV1 {
    pub revision: u64,
    pub state: ProviderAcquisitionStateV1,
    pub provider: SourceProviderAuthorityV1,
    pub holder: SourceProviderAuthorityV1,
    pub acquisition_id: ObjectDigest,
    pub acquisition_sequence: u64,
    pub effect_id: [u8; 16],
    pub normalized_intent: NormalizedAcquisitionIntentV1,
    pub effect_attempt_digest: ObjectDigest,
    pub current_attempt_digest: ObjectDigest,
    pub lease_attempt_digest: Option<ObjectDigest>,
    pub lease_issue_generation: u64,
    pub lease_id: Option<[u8; 16]>,
    pub lease_digest: Option<ObjectDigest>,
    pub lease_history: Vec<LeaseLineageV1>,
    pub resource_namespace_digest: ObjectDigest,
    pub resource_id: [u8; 32],
    pub resource_generation: u64,
    pub resource_digest: ObjectDigest,
    pub catalog_generation: u64,
    pub catalog_digest: ObjectDigest,
    pub selection_generation: u64,
    pub selection_digest: ObjectDigest,
    pub proof_class: u8,
    pub proof_digest: ObjectDigest,
    pub resource_commitment: ObjectDigest,
    pub backend_id: [u8; 32],
    pub backend_lineage_digest: ObjectDigest,
    pub backend_evidence: Option<BackendEvidenceV1>,
    pub reopen_identity: Option<ReopenIdentityV1>,
    pub source_root: Option<SourceRootIdentityV1>,
    pub release_effect_id: Option<[u8; 16]>,
    pub signed_lease: Vec<u8>,
}

/// Identifies the unique release lineage for an acquisition.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ReleaseKeyV1 {
    pub provider_id: [u8; 16],
    pub holder_id: [u8; 16],
    pub acquisition_id: ObjectDigest,
}

/// Stores one release intent or exact durable tombstone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseRecordV1 {
    pub revision: u64,
    pub state: ProviderReleaseStateV1,
    pub provider: SourceProviderAuthorityV1,
    pub holder: SourceProviderAuthorityV1,
    pub acquisition_id: ObjectDigest,
    pub acquisition_sequence: u64,
    pub lease_id: [u8; 16],
    pub lease_digest: ObjectDigest,
    pub effect_id: [u8; 16],
    pub release_generation: u64,
    pub effect_attempt_digest: ObjectDigest,
    pub attempt_digest: ObjectDigest,
    pub backend_id: [u8; 32],
    pub backend_lineage_digest: ObjectDigest,
    pub backend_evidence: Option<BackendEvidenceV1>,
    pub release_observation_digest: Option<ObjectDigest>,
    pub released_seconds: Option<i64>,
    pub receipt_digest: Option<ObjectDigest>,
    pub signed_receipt: Vec<u8>,
    pub acquisition_record_digest: ObjectDigest,
}

/// Describes recovery work without restoring effect, signing, or descriptor authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderRecoveryWorkV1 {
    /// An Acquire reservation requires backend observation before any retry.
    ObserveApplying {
        /// Identifies the durable acquisition.
        acquisition_id: ObjectDigest,
        /// Identifies the exact reserved effect.
        effect_id: [u8; 16],
    },
    /// A superseding-session Acquire rebind was reserved before reopen.
    ObserveAcquireRebind {
        /// Identifies the retained active acquisition.
        acquisition_id: ObjectDigest,
        /// Identifies the exact reserved rebind request.
        attempt_digest: ObjectDigest,
    },
    /// A completed Pending disposition retains unresolved backend progress.
    ObservePending {
        /// Identifies the durable acquisition.
        acquisition_id: ObjectDigest,
        /// Commits the stable backend operation to observe without effect authority.
        backend_id: [u8; 32],
    },
    /// A Release reservation requires backend observation before any retry.
    ObserveReleasing {
        /// Identifies the durable acquisition.
        acquisition_id: ObjectDigest,
        /// Identifies the exact reserved effect.
        effect_id: [u8; 16],
    },
    /// An active acquisition requires fresh exact backend reopen validation.
    ReopenActive {
        /// Identifies the durable acquisition.
        acquisition_id: ObjectDigest,
        /// Commits the stable backend selection to revalidate.
        backend_id: [u8; 32],
    },
    /// A reserved Inventory attempt cannot recreate signing authority.
    ObserveInventoryReservation {
        /// Commits the exact retained attempt requiring operator recovery.
        attempt_digest: ObjectDigest,
    },
}

/// Summarizes a completely validated provider ledger after hostile replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredProviderLedgerV1 {
    pub authority: AuthorityHeadRecordV1,
    pub catalog: CatalogHeadRecordV1,
    pub catalog_history: BTreeMap<u64, CatalogHeadRecordV1>,
    pub sessions: BTreeMap<([u8; 16], [u8; 16]), HolderSessionHeadRecordV1>,
    pub session_history: BTreeMap<([u8; 16], [u8; 16], ObjectDigest), HolderSessionHeadRecordV1>,
    pub attempts: BTreeMap<AttemptKeyV1, AttemptRecordV1>,
    pub acquisitions: BTreeMap<AcquisitionKeyV1, AcquisitionRecordV1>,
    pub releases: BTreeMap<ReleaseKeyV1, ReleaseRecordV1>,
    pub recovery_work: Vec<ProviderRecoveryWorkV1>,
}

impl RecoveredProviderLedgerV1 {
    /// Returns the current durable provider authority state.
    #[must_use]
    pub const fn authority_state(&self) -> ProviderAuthorityStateV1 {
        self.authority.state
    }

    /// Returns the current provider authority.
    #[must_use]
    pub const fn provider(&self) -> &SourceProviderAuthorityV1 {
        &self.authority.provider
    }

    /// Returns the current provider catalog generation.
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog.catalog_generation
    }

    /// Returns the current global inventory generation.
    #[must_use]
    pub const fn inventory_generation(&self) -> u64 {
        self.authority.inventory_generation
    }

    /// Returns immutable unresolved recovery work.
    #[must_use]
    pub fn recovery_work(&self) -> &[ProviderRecoveryWorkV1] {
        &self.recovery_work
    }
}
