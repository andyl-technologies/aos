//! Owns node-local Cache algorithms, fixed writers and physical custody.
//!
//! The private Journal binds Cache's five fixed roles to the shared canonical
//! native opening, append and full replay engines. Protocol owns inert wire and
//! historical DATA; Broker owns the genuine Controller and Root borrowers.
//! Protected replay, physical manifests, fixed readonly observations and native
//! Clock custody remain together so no caller can adopt a map or descriptor.
//!
//! Cache accounting, catalog, and partition DATA are owned by
//! `aos_sandbox_protocol::cache_state`. This partition retains the protected
//! SBX-CACHE-01 semantics without selecting a backend or activating a service.
//! It separates disclosure/isolation identity,
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

mod clock;
mod journal;
mod protected_transaction;
mod error;

pub(crate) use journal::{Journal, JournalError};

pub use error::{CacheJournalErrorV1, CacheNativePrefixErrorV1, CacheQ04ErrorV1};
#[cfg(target_os = "linux")]
pub use protected_owner::{
    CacheHeldAppendContextV1, CacheHeldAppendGateV1, CacheHeldAppendGuardV1,
    CacheHeldClosedV1, CacheHeldCurrentnessOriginalV1, CacheHeldCurrentnessSiteV1, CacheHeldPostSiteV1,
    CacheHeldErrorV1, CacheHeldIdentityDataV1, CacheHeldNativeSemanticShapeV1,
    CacheHeldPreRootCutV1, CacheCreateStorageReceivingShapeV1,
    OriginalCreateStorageCacheLoanV1,
};

#[cfg(target_os = "linux")]
pub use protected_owner::CacheGitOperationOriginalV1;

#[cfg(target_os = "linux")]
pub use protected_owner::{
    CacheRootQ04TerminalObservationV1, Q04RootCacheTerminalOutcomeV1,
    Q04RootCacheTerminalRequestV1,
};

#[cfg(target_os = "linux")]
mod root_v8_released_proof;
#[cfg(target_os = "linux")]
pub use root_v8_released_proof::{
    RootV8ReleasedProofV1, RootV8ReleasedProofReadErrorV1,
    read_root_v8_released_proof_original_v1,
    validate_untrusted_root_v8_release_reply_frame_original_v1,
};

#[cfg(target_os = "linux")]
pub use protected_owner::{CacheV8TerminalOriginalV1, CacheV8TerminalContextV1};
#[cfg(target_os = "linux")]
pub use protected_journal::{CacheV8InspectionGuardV1, CacheV8InspectionContextV1};

pub mod admission;
mod authority_record;
mod controller_bootstrap;
#[cfg(target_os = "linux")]
pub(crate) use controller_bootstrap::CONTROLLER_CACHE_ROOT as CONTROLLER_CACHE_READONLY_ROOT_V1;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use controller_bootstrap::CacheSelectedBootstrapImportV1;
pub(crate) use controller_bootstrap::CacheBootstrapImportGeometryV1;
pub mod domain;
#[cfg(target_os = "linux")]
mod physical;
pub mod eviction;
pub mod format;
#[cfg(target_os = "linux")]
mod owner_readback;
pub mod pin;
mod protected_journal;
mod protected_owner;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use protected_owner::{CacheDeleteNativeOriginalV1, CacheDeleteNativePayloadsV1};
#[cfg(target_os = "linux")]
pub(crate) use protected_owner::{
    CacheHeldSelectionOriginalV1,
    };
pub(crate) use protected_owner::PROTECTED_CACHE_ROOT;
#[cfg(target_os = "linux")]
pub(crate) use protected_owner::InitializerJournal;
pub(crate) use protected_owner::CacheReplayManifestGeometryV1;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use protected_owner::initialization::{
    q04_capture_pricing::{OriginalQ04CachePreflightLoanV1, OriginalQ04CacheCaptureShapeV1},
    original_q04::{OriginalQ04CacheOwnerCutV1, CacheQ04RecipeCaptureBorrowV1, CacheQ04AppendOriginalBorrowV1, CacheQ04SigningBorrowV1, CacheQ04UnsignedSigningBorrowV1, CacheQ04ReleaseBindingBorrowV1, CacheQ04TerminalBorrowV1},
};
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use protected_owner::Q04CachePrepareReadbackV1;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use journal::CacheQ04TransactionRecipesV1;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use aos_sandbox_protocol::cache_state::hold_state::q04_recipes::Q04CacheTerminalPhaseV1;
mod public_pin;
pub mod read_authority;
pub mod recovery;
pub mod scrub;
#[cfg(target_os = "linux")]
mod signer_readback;

pub use admission::{
    AbortedAdmissionV1, AdmissionError, AdmissionLimitsV1, AdmissionProgressV1, AdmissionStageV1,
    CacheAdmissionStateV1, ImmutableAdmissionPlanV1, PreparedArtifactV1, PublicationCommitV1,
    SourceAuthorizationV1, WatermarkRequirementV1, initial_pin_set_digest,
};
pub use authority_record::{CacheResidencyAuthorityRequestV1, CacheResidencyControllerRecordV1};
pub use controller_bootstrap::{
    CacheReplayControllerBootstrapErrorV1, CacheReplayControllerBootstrapOwnerV1,
    encode_cache_replay_controller_bundle_v1, encode_cache_replay_genesis_manifest_v1,
};
pub use domain::{
    AuthorizedLookupKey, CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1,
    CacheAuthorityScopeV1, LookupAuthorityScopeV1, VerifiedCacheCapabilityV1,
};
#[cfg(target_os = "linux")]
pub use physical::{
    CacheEffectObservationV1, CacheLookupV1, CacheMaterializationOutcomeV1,
    CacheMaterializationRecoveryFailureV1, CacheOrphanResolutionFailureV1,
    CacheOrphanResolutionPendingV1, CacheOwnerAdmissionV1, CacheOwnerCurrentnessV1,
    CacheOwnerErrorV1, CacheOwnerEvictionAdmissionV1, CacheOwnerHeldSnapshotV1, CacheOwnerLimitsV1,
    CacheOwnerOutcomeUnknownV1, CacheOwnerPinActionV1, CacheOwnerPinAdmissionV1, CacheOwnerPinIdV1,
    CacheOwnerPinPresenceV1, CacheOwnerPinReconciliationStateV1, CacheOwnerPinReconciliationV1,
    CacheOwnerPinSettlementErrorV1, CacheOwnerPinSettlementV1, CacheOwnerPinSnapshotV1,
    CacheOwnerRecoveryFailureV1, CacheOwnerReleaseFailureV1, CacheOwnerReopenTicketV1,
    DormantCacheOwnerV1, EvictedCacheObjectV1,
};
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use physical::{
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
#[cfg(target_os = "linux")]
pub use owner_readback::CacheOwnerReadbackErrorV1;
#[cfg(all(any(test, feature = "test-fixtures"), target_os = "linux"))]
#[doc(hidden)]
pub use owner_readback::sign_test_cache_owner_readback_v2;
pub use pin::{
    CachePinCompactionPhysicalProofV1, CachePinId, CachePinKindV1, CachePinLedgerV1, CachePinV1,
    PinCompactionFloorV1, PinDrainEvidenceV1, PinDrainOutcomeV1, PinError, ReleasedCachePinV1,
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
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use protected_owner::CacheV8SettledClearV1;
#[cfg(all(target_os = "linux", feature = "cache-physical-join-vm-fixture"))]
pub use protected_owner::with_fixed_closed_cache_physical_policy_cut_vm_fixture_v1;
#[doc(hidden)]
pub use protected_owner::{CacheLifecycleBootInventoryV1, release_fixed_closed_policy_cache_hold_after_root_readback_v1};
pub use protected_owner::CurrentProjectPhysicalCacheHeadV1;
pub use protected_owner::{
    CacheResidentInitializationV1, CacheResidentUnavailableV1,
    CacheProjectUsageLoanV1, CacheProjectUsageObservationErrorV1, CacheProjectUsagePartitionV1,
    CacheResidencyAuthorizedControllerV1, CacheResidencyAuthorizedPayloadV1,
    CacheResidencyProtectedColdOutcomeV1, CacheResidencyProtectedOpenReportV1,
    CacheResidencyProtectedOwnerRecoveryV1, CacheResidencyProtectedOwnerV1,
    CacheResidencyRootReadOnlyPolicyHoldV1, CacheResidencyRootReadOnlyReplayV1,
    PublicLogicalPinAcquisitionCommitV1, replay_fixed_root_read_only_cache_journals_v1,
    replay_fixed_root_read_only_cache_policy_hold_v1,
};
#[cfg(target_os = "linux")]
pub use protected_owner::{
    CacheResidencyHeldPhysicalCutErrorV1, CacheResidencyProtectedPinRecoveryV1,
    CacheResidencyWriterReadbackV2, with_fixed_closed_cache_physical_policy_cut_v1,
};
pub use public_pin::{PublicLogicalPinAcquisitionErrorV1, ValidatedPublicLogicalPinAcquisitionV1};
pub use read_authority::{
    CurrentReadAuthorityV1, DescriptorHandoffPlanV1, DescriptorHandoffReceiptV1,
    ReadAuthorityError, ReadBackingObservationV1, confirm_descriptor_handoff,
    prepare_descriptor_handoff,
};
#[cfg(target_os = "linux")]
pub use recovery::CacheLogicalOwnerPinDiscrepancyV1;
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
#[cfg(target_os = "linux")]
pub use signer_readback::{CacheSignerReadbackErrorV1, sign_fixed_signer_cache_owner_readback_v2};

#[cfg(target_os = "linux")]
pub use protected_owner::{CreateStorageCacheCurrentExtentsDataV1, create_storage_cache_current_dynamic_receiving_demand_v1, create_storage_cache_current_dynamic_with_upper_semantic_quote_v1};
#[cfg(target_os = "linux")]
pub use protected_owner::current_cache_fixed_receiving_demand_v1;

// Historical-only selection; it cannot construct any Native Cache original.
#[doc(hidden)]
pub use protected_owner::{actionable_rows_data_v2, actionable_rows_receiving_demand_v2};

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use protected_owner::initialization::original_q04::CacheQ04FinalCompletionBorrowV1;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use protected_journal::{CacheQ04ReadbackContextV1, CacheQ04ReadbackGuardV1};

#[cfg(target_os = "linux")]
pub use physical::delete_metadata::require_deadline_sample_v2 as cache_delete_deadline_sample_data_v2;



#[cfg(target_os = "linux")]
pub use protected_owner::{CacheReleasedOriginalsV1, CacheReleasedShapeV1, release_receiving_demand_v1, release_append_bytes_v1};

#[cfg(target_os = "linux")]
pub use protected_owner::{CacheCurrentAuditOriginalsV1, CacheCurrentAuditShapeV1};

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use protected_owner::initialization::original_q04::{
    CacheQ04AppendContextV1, CacheQ04AppendGateV1, CacheQ04AppendGuardV1,
};



#[cfg(all(feature = "test-fixtures", not(debug_assertions)))]
compile_error!("the private Cache fixture is unavailable in release builds");
