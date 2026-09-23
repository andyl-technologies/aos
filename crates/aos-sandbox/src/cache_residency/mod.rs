//! Dormant node-local immutable cache residency semantics.
//!
//! This partition implements the pure SBX-CACHE-01 model without selecting a
//! backend or activating a service. It separates disclosure/isolation identity,
//! reservation, residency, source retention, logical leases, kernel references,
//! backing registrations, publication admission, eviction, scrub, and read
//! handoff authority. Canonical formats retain exact recovery evidence but no
//! host path or operating-system descriptor.
//!
//! The intended effect ordering is:
//!
//! ```text
//! authorize -> reserve -> prepare immutable destination -> commit catalog+pins
//!           -> authorize read handoff independently
//! ```
//!
//! Eviction uses a separately frozen candidate set and never treats unlink as
//! secure erasure. Physical bytes are credited only after independent backing
//! reclamation evidence.

pub mod accounting;
pub mod admission;
pub mod catalog;
mod controller_adapter;
mod controller_bootstrap;
pub mod domain;
#[cfg(target_os = "linux")]
mod effect_owner;
pub mod eviction;
pub mod format;
pub mod pin;
mod protected_journal;
mod protected_owner;
pub mod read_authority;
pub mod recovery;
pub mod scrub;

pub use accounting::{
    AccountingError, AccountingLimitsV1, CacheAccountingV1, CacheReservationId, CacheReservationV1,
    CacheUsageV1, NodeCacheQuotaV1, ProjectCacheQuotaV1, ReservationStateV1,
};
pub use admission::{
    AbortedAdmissionV1, AdmissionError, AdmissionLimitsV1, AdmissionProgressV1, AdmissionStageV1,
    CacheAdmissionStateV1, ImmutableAdmissionPlanV1, PreparedArtifactV1, PublicationCommitV1,
    SourceAuthorizationV1, WatermarkRequirementV1, initial_pin_set_digest,
};
pub use catalog::{
    BackingObjectIdentityV1, CatalogEntryV1, CatalogError, CatalogPresenceV1, CoalescingOutcomeV1,
    ImmutableSealV1, LookupMemoLimitsV1, LookupMemoV1, LookupMemoValueV1, SealProfileV1,
    canonical_name_digest,
};
pub use controller_adapter::{
    CacheResidencyAuthorityRequestV1, CacheResidencyControllerCommitV1,
    CacheResidencyControllerRecordV1, cache_residency_controller_commit_v1,
};
pub use controller_bootstrap::{
    CacheReplayControllerBootstrapErrorV1, CacheReplayControllerBootstrapOwnerV1,
};
pub use domain::{
    AuthorizedLookupKey, BackingIsolationV1, CacheAuthorityError, CacheAuthorityOwner,
    CacheAuthorityPurposeV1, CacheAuthorityScopeV1, CacheDomainError, CacheIsolationPolicyV1,
    CacheNodeIdV1, LookupAuthorityScopeV1, PhysicalPartitionId, ProtectedBackingIdentityV1,
    ResidencyEnforcementV1, VerifiedCacheCapabilityV1,
};
#[cfg(target_os = "linux")]
pub use effect_owner::{
    CacheEffectObservationV1, CacheLookupV1, CacheMaterializationOutcomeV1,
    CacheMaterializationRecoveryFailureV1, CacheOrphanResolutionFailureV1,
    CacheOrphanResolutionPendingV1, CacheOwnerAdmissionV1, CacheOwnerCurrentnessV1,
    CacheOwnerErrorV1, CacheOwnerEvictionAdmissionV1, CacheOwnerLimitsV1,
    CacheOwnerOutcomeUnknownV1, CacheOwnerPinActionV1, CacheOwnerPinAdmissionV1, CacheOwnerPinIdV1,
    CacheOwnerRecoveryFailureV1, DormantCacheOwnerV1, EvictedCacheObjectV1,
};
#[cfg(target_os = "linux")]
pub(crate) use effect_owner::{
    cache_lifecycle_availability_effect_v1, cache_owner_effect_commitment_v1,
};
pub use eviction::{
    AuthorizedUnlinkV1, EvictionCandidateStateV1, EvictionCandidateV1, EvictionError,
    EvictionProgressV1, EvictionRetryAuthorityV1, FrozenEvictionPlanV1, ReclamationEvidenceV1,
    UnlinkAdmissionV1, UnlinkObservationV1, UnlinkOutcomeV1,
};
pub use format::{
    AuthorizedIdempotencyReplayV1, CacheCheckpointV1, CacheDurableRecordV1, CacheFormatError,
    CacheHistoryFloorV1, CacheIdempotencyBindingV1, CacheIdempotencyCompactionFloorV1,
    CacheIdempotencyIndexV1, CacheIdempotencyOutcomeV1, CacheMethodV1, CacheRecordKindV1,
    atomic_projection_digest, decode_checkpoint, decode_floor, decode_idempotency,
    decode_idempotency_floor, decode_record, encode_checkpoint, encode_floor, encode_idempotency,
    encode_idempotency_floor, encode_record,
};
pub use pin::{
    CachePinId, CachePinKindV1, CachePinLedgerV1, CachePinV1, PinCompactionFloorV1,
    PinDrainEvidenceV1, PinDrainOutcomeV1, PinError, ReleasedCachePinV1,
    decode_pin_compaction_floor, encode_pin_compaction_floor,
};
pub use protected_journal::{
    AppliedCacheResidencyTransactionV1, CacheResidencyColdObservationV1,
    CacheResidencyColdRecoveryV1, CacheResidencyCommitOutcomeV1, CacheResidencyOutcomeUnknownV1,
    CacheResidencyPostcommitCapabilityV1, CacheResidencyProtectedJournalEnvelopeV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedJournalKeyV1,
    CacheResidencyProtectedJournalProjectionV1, CacheResidencyProtectedJournalSchemaV1,
    CacheResidencyProtectedJournalSnapshotV1, CacheResidencyProtectedJournalV1,
    CacheResidencyProtectedRecordKindV1, CacheResidencyRecoveryV1, CacheResidencyReplayValidatorV1,
    CacheResidencyTransactionKindV1, PreparedCacheResidencyTransactionV1,
    ValidatedCacheResidencyPostcommitV1, cache_residency_protected_key_v1,
};
pub(crate) use protected_journal::{
    CacheResidencyReplayPartitionEvidenceV1, cache_residency_reducer_envelope_v1,
};
pub(crate) use protected_owner::CacheLifecycleBootInventoryV1;
pub use protected_owner::{
    CacheResidencyAuthorizedControllerV1, CacheResidencyAuthorizedPayloadV1,
    CacheResidencyProtectedColdOutcomeV1, CacheResidencyProtectedOpenReportV1,
    CacheResidencyProtectedOwnerV1,
};
pub use read_authority::{
    CurrentReadAuthorityV1, DescriptorHandoffPlanV1, DescriptorHandoffReceiptV1,
    ReadAuthorityError, ReadBackingObservationV1, confirm_descriptor_handoff,
    prepare_descriptor_handoff,
};
pub use recovery::{
    CacheAtomicObjectPayloadV1, CacheGlobalRecoveryStateV1, CacheLookupStateV1, CachePoisonLatchV1,
    CacheReadHandoffStateV1, CacheRecoveryInventoryV1, CacheRecoveryLimitsV1, CacheRecoveryWorkV1,
    CacheScrubRecordV1, CacheSubjectFamilyHeadV1, CacheTypedCheckpointV1,
    PendingCancellationOutcomeV1, PendingCancellationV1, RecoveryError, decode_admission_plan,
    decode_admission_progress, decode_atomic_object_payload, decode_atomic_object_record,
    decode_catalog, decode_eviction_candidate, decode_eviction_plan, decode_eviction_progress,
    decode_global_recovery_state, decode_pin, decode_released_pin, decode_reservation,
    decode_scrub_record, decode_typed_checkpoint, encode_admission_plan, encode_admission_progress,
    encode_atomic_object_payload, encode_atomic_object_record, encode_catalog,
    encode_eviction_candidate, encode_eviction_plan, encode_eviction_progress,
    encode_global_recovery_state, encode_pin, encode_released_pin, encode_reservation,
    encode_scrub_record, encode_typed_checkpoint,
};
pub use scrub::{
    BackingObservationV1, ScrubDecisionV1, ScrubError, ScrubEvidenceV1, apply_scrub,
    repair_quarantined,
};
