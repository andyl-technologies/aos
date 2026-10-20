//! Protected Native Cache recovery entry and live logical-pin continuations.
//!
//! The sole historical field graph, codec and complete replay loop live in
//! Protocol. This private-wrapper boundary retains the original fresh Native
//! authority validation before final inventory assembly. Historical DATA alone
//! cannot construct this Native inventory, capability or authorized payload.

use std::collections::BTreeMap;

use aos_sandbox_model::{
    AttachmentId, IncarnationId, MediaType, ObjectDescriptor, ObjectDigest, OperationId, ProjectId,
    SandboxId, ViewId,
};

use aos_sandbox_protocol::cache_state::{
    AccountingLimitsV1, BackingObjectIdentityV1, CacheAccountingV1, CacheReservationV1,
    CacheUsageV1, CatalogEntryV1, CatalogPresenceV1, LookupMemoValueV1, NodeCacheQuotaV1,
    PhysicalPartitionId, ProjectCacheQuotaV1, ReservationStateV1, object_descriptor_commitment,
};

use aos_sandbox_protocol::cache_state::admission_data::ImmutableAdmissionPlanDataV1 as ImmutableAdmissionPlanV1;
use aos_sandbox_protocol::cache_state::admission_progress::{AdmissionProgressV1, AdmissionStageV1, WatermarkRequirementV1};
use super::domain::{CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1,
    CacheAuthorityScopeV1, VerifiedCacheCapabilityV1};
use aos_sandbox_protocol::cache_state::eviction_data::{EvictionCandidateStateV1, EvictionCandidateV1,
    EvictionProgressDataV1 as EvictionProgressV1, FrozenEvictionPlanDataV1 as FrozenEvictionPlanV1};
use super::format::{CHECKPOINT_BYTES, CacheCheckpointV1, CacheDurableRecordV1,
    CacheHistoryFloorV1, CacheIdempotencyBindingV1, CacheIdempotencyCompactionFloorV1,
    CacheRecordKindV1, IDEMPOTENCY_FLOOR_BYTES, RECORD_BYTES as DURABLE_RECORD_BYTES,
    atomic_projection_digest};
use aos_sandbox_protocol::cache_state::pin_data::{CachePinId, CachePinKindV1,
    CachePinDataV1 as CachePinV1, PinDrainEvidenceDataV1 as PinDrainEvidenceV1, PinDrainOutcomeV1};
use super::pin::PinError;
use aos_sandbox_protocol::cache_state::pin_floor::PinCompactionFloorDataV1 as PinCompactionFloorV1;
use aos_sandbox_protocol::cache_state::pin_ledger::ReleasedCachePinDataV1 as ReleasedCachePinV1;
use aos_sandbox_protocol::cache_state::scrub_data::BackingObservationV1;
use aos_sandbox_protocol::cache_state::recovery as data;

mod representation;
pub(in crate::cache_residency) use representation::{CacheReplayRepresentationPhaseV1,
    general_replay_representation_bound_v1};
mod logical_pin;
#[cfg(target_os = "linux")]
mod owner_reconcile;
#[cfg(target_os = "linux")]
pub use owner_reconcile::CacheLogicalOwnerPinDiscrepancyV1;
mod cancellation;
pub use cancellation::PendingCancellationV1;

pub use data::{CacheAtomicObjectPayloadV1, CacheGlobalRecoveryStateV1,
    CacheLookupStateV1, CachePoisonLatchV1, CacheReadHandoffStateV1,
    CacheRecoveryLimitsV1, CacheRecoveryWorkV1, CacheScrubRecordV1,
    CacheSubjectFamilyHeadV1, CacheTypedCheckpointV1, PendingCancellationOutcomeV1};
pub(crate) use data::CacheRecoverySelectionV1;
use data::{aggregate_projections, RecoveredAccountingProjection, canonical_payload_digest,
    validate_typed_continuity};

/// Retains the actual Native authority join for a complete historical inventory.
///
/// Historical inventory DATA cannot construct this wrapper.
///
/// ```compile_fail
/// fn issue(data: aos_sandbox_protocol::cache_state::recovery::CacheRecoveryInventoryDataV1) {
///     let _ = aos_sandbox_controller_domain::cache_residency::recovery::CacheRecoveryInventoryV1(data);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheRecoveryInventoryV1(data::CacheRecoveryInventoryDataV1);

impl std::ops::Deref for CacheRecoveryInventoryV1 {
    type Target = data::CacheRecoveryInventoryDataV1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CacheRecoveryInventoryV1 {
    pub(crate) fn into_parsed_history_data_v1(self) -> data::CacheRecoveryInventoryDataV1 {
        self.0
    }

    pub(crate) const fn protected_replay_binding(&self) -> ObjectDigest {
        self.0.protected_replay_binding()
    }

    /// Derives historical replay scope DATA without issuing current authority.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for an invalid historical checkpoint or anchor.
    pub fn replay_authority_scope(
        partition: PhysicalPartitionId,
        typed_checkpoint_bytes: &[u8],
        prior_typed_checkpoint_bytes: Option<&[u8]>,
        floor: CacheHistoryFloorV1,
        valid_until: u64,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<CacheAuthorityScopeV1, RecoveryError> {
        data::CacheRecoveryInventoryDataV1::replay_authority_scope(
            partition, typed_checkpoint_bytes, prior_typed_checkpoint_bytes,
            floor, valid_until, limits,
        ).map_err(RecoveryError::from)
    }

    /// Replays the exact historical prefix under the original Native authority join.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for invalid history or current capability.
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        typed_checkpoint_bytes: &[u8],
        prior_typed_checkpoint_bytes: Option<&[u8]>,
        floor: CacheHistoryFloorV1,
        records: impl IntoIterator<Item = Vec<u8>>,
        limits: CacheRecoveryLimitsV1,
        now: u64,
    ) -> Result<Self, RecoveryError> {
        Self::from_verified_selected(
            owner, capability, partition, typed_checkpoint_bytes,
            prior_typed_checkpoint_bytes, floor, records, limits, now,
            &mut CacheRecoverySelectionV1::Ordinary,
        )
    }

    /// Replays the exact historical prefix under the original Native authority join.
    pub(crate) fn from_verified_selected(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        typed_checkpoint_bytes: &[u8],
        prior_typed_checkpoint_bytes: Option<&[u8]>,
        floor: CacheHistoryFloorV1,
        records: impl IntoIterator<Item = Vec<u8>>,
        limits: CacheRecoveryLimitsV1,
        now: u64,
        selection: &mut CacheRecoverySelectionV1,
    ) -> Result<Self, RecoveryError> {
        let assembly = data::prepare_historical_recovery_data_v1(
            partition, typed_checkpoint_bytes, prior_typed_checkpoint_bytes,
            floor, records, limits, capability.scope().valid_until(),
            capability.record_digest(),
        )?;
        owner.validate_for_effect_at(
            capability, CacheAuthorityPurposeV1::Replay,
            assembly.authority_scope_data_v1(), now,
        )?;
        Ok(Self(assembly.finish_data_v1(selection)?))
    }

    /// Replays the exact historical prefix under the original Native authority join.
    pub(crate) fn from_authority_session(
        partition: PhysicalPartitionId,
        typed_checkpoint_bytes: &[u8],
        prior_typed_checkpoint_bytes: Option<&[u8]>,
        floor: CacheHistoryFloorV1,
        records: impl IntoIterator<Item = Vec<u8>>,
        limits: CacheRecoveryLimitsV1,
        authority_scope: CacheAuthorityScopeV1,
        authority_record: ObjectDigest,
    ) -> Result<Self, RecoveryError> {
        Self::from_authority_session_selected(
            partition, typed_checkpoint_bytes, prior_typed_checkpoint_bytes,
            floor, records, limits, authority_scope, authority_record,
            &mut CacheRecoverySelectionV1::Ordinary,
        )
    }

    /// Replays the exact historical prefix under the original Native authority join.
    pub(crate) fn from_authority_session_selected(
        partition: PhysicalPartitionId,
        typed_checkpoint_bytes: &[u8],
        prior_typed_checkpoint_bytes: Option<&[u8]>,
        floor: CacheHistoryFloorV1,
        records: impl IntoIterator<Item = Vec<u8>>,
        limits: CacheRecoveryLimitsV1,
        authority_scope: CacheAuthorityScopeV1,
        authority_record: ObjectDigest,
        selection: &mut CacheRecoverySelectionV1,
    ) -> Result<Self, RecoveryError> {
        let assembly = data::prepare_historical_recovery_data_v1(
            partition, typed_checkpoint_bytes, prior_typed_checkpoint_bytes,
            floor, records, limits, authority_scope.valid_until(), authority_record,
        )?;
        if assembly.authority_scope_data_v1() != authority_scope {
            return Err(RecoveryError::AnchorMismatch);
        }
        Ok(Self(assembly.finish_data_v1(selection)?))
    }
}

/// Reports bounded recovery and anchored-history failures.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// Recovery limits are zero or exceed the hard profile.
    #[error("cache recovery limits are invalid")]
    InvalidLimits,
    /// Checkpoint/floor cross-links disagree.
    #[error("cache recovery anchor mismatch")]
    AnchorMismatch,
    /// Retained record sequence or predecessor links are not contiguous.
    #[error("cache retained history is broken")]
    BrokenHistory,
    /// A subject generation repeated or moved backwards.
    #[error("cache subject history rolled back")]
    SubjectRollback,
    /// A history sequence counter cannot advance.
    #[error("cache history sequence is exhausted")]
    HistoryOverflow,
    /// Replay count or work bounds are exhausted.
    #[error("cache recovery capacity is exhausted")]
    Capacity,
    /// Canonical record/checkpoint/floor validation failed.
    #[error(transparent)]
    Format(#[from] super::format::CacheFormatError),
    /// Protected replay authority verification failed.
    #[error(transparent)]
    Authority(#[from] CacheAuthorityError),
    /// A planned pin transition failed exact ledger or drain validation.
    #[error(transparent)]
    Pin(#[from] PinError),
    /// Atomic catalog/reservation/pin/progress projections disagree.
    #[error("cache recovery atomic projection commitment mismatches")]
    ProjectionMismatch,
    /// Typed payload does not reconstruct its committed projections.
    #[error("cache recovery typed reducer payload mismatches")]
    PayloadMismatch,
    /// Canonical typed payload framing, lengths, or closed codes are malformed.
    #[error("cache recovery typed payload is malformed")]
    MalformedPayload,
    /// A reservation, operation, pin, or backing identity has two owners.
    #[error("cache recovery global identity uniqueness is violated")]
    IdentityConflict,
}

impl From<data::RecoveryError> for RecoveryError {
    fn from(error: data::RecoveryError) -> Self {
        match error {
            data::RecoveryError::InvalidLimits => Self::InvalidLimits,
            data::RecoveryError::AnchorMismatch => Self::AnchorMismatch,
            data::RecoveryError::BrokenHistory => Self::BrokenHistory,
            data::RecoveryError::SubjectRollback => Self::SubjectRollback,
            data::RecoveryError::HistoryOverflow => Self::HistoryOverflow,
            data::RecoveryError::Capacity => Self::Capacity,
            data::RecoveryError::ProjectionMismatch => Self::ProjectionMismatch,
            data::RecoveryError::PayloadMismatch => Self::PayloadMismatch,
            data::RecoveryError::MalformedPayload => Self::MalformedPayload,
            data::RecoveryError::IdentityConflict => Self::IdentityConflict,
            data::RecoveryError::Format(error) => Self::Format(error),
            data::RecoveryError::Authority(error) => Self::Authority(error.into()),
            data::RecoveryError::Pin(error) => Self::Pin(error.into()),
        }
    }
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_scrub_record(
    scrub: &CacheScrubRecordV1,
    partition: PhysicalPartitionId,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_scrub_record(scrub, partition, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_scrub_record(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<CacheScrubRecordV1, RecoveryError> {
    data::decode_scrub_record(partition, bytes, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_admission_plan(
    plan: &ImmutableAdmissionPlanV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_admission_plan(plan, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_admission_plan(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<ImmutableAdmissionPlanV1, RecoveryError> {
    data::decode_admission_plan(partition, bytes, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_reservation(
    reservation: &CacheReservationV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_reservation(reservation, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_reservation(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<CacheReservationV1, RecoveryError> {
    data::decode_reservation(partition, bytes, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_catalog(
    catalog: &CatalogEntryV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_catalog(catalog, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_catalog(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<CatalogEntryV1, RecoveryError> {
    data::decode_catalog(partition, bytes, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_pin(pin: &CachePinV1, maximum_bytes: usize) -> Result<Vec<u8>, RecoveryError> {
    data::encode_pin(pin, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_pin(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<CachePinV1, RecoveryError> {
    data::decode_pin(partition, bytes, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_released_pin(
    released: &ReleasedCachePinV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_released_pin(released, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_released_pin(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<ReleasedCachePinV1, RecoveryError> {
    data::decode_released_pin(partition, bytes, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_admission_progress(
    progress: &AdmissionProgressV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_admission_progress(progress, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_admission_progress(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<AdmissionProgressV1, RecoveryError> {
    data::decode_admission_progress(bytes, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_eviction_plan(
    plan: &FrozenEvictionPlanV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_eviction_plan(plan, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_eviction_plan(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    maximum_bytes: usize,
    maximum_candidates: usize,
) -> Result<FrozenEvictionPlanV1, RecoveryError> {
    data::decode_eviction_plan(partition, bytes, maximum_bytes, maximum_candidates).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_eviction_progress(
    progress: &EvictionProgressV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_eviction_progress(progress, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_eviction_progress(
    plan: &FrozenEvictionPlanV1,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<EvictionProgressV1, RecoveryError> {
    data::decode_eviction_progress(plan, bytes, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_eviction_candidate(
    candidate: &EvictionCandidateV1,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_eviction_candidate(candidate, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_eviction_candidate(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<EvictionCandidateV1, RecoveryError> {
    data::decode_eviction_candidate(bytes, maximum_bytes).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_atomic_object_payload(
    payload: &CacheAtomicObjectPayloadV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_atomic_object_payload(payload, limits).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_atomic_object_payload(
    partition: PhysicalPartitionId,
    record: CacheDurableRecordV1,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheAtomicObjectPayloadV1, RecoveryError> {
    data::decode_atomic_object_payload(partition, record, bytes, limits).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_atomic_object_record(
    payload: &CacheAtomicObjectPayloadV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_atomic_object_record(payload, limits).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_atomic_object_record(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheAtomicObjectPayloadV1, RecoveryError> {
    data::decode_atomic_object_record(partition, bytes, limits).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_global_recovery_state(
    state: &CacheGlobalRecoveryStateV1,
    partition: PhysicalPartitionId,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_global_recovery_state(state, partition, limits).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_global_recovery_state(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheGlobalRecoveryStateV1, RecoveryError> {
    data::decode_global_recovery_state(partition, bytes, limits).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn encode_typed_checkpoint(
    checkpoint: &CacheTypedCheckpointV1,
    partition: PhysicalPartitionId,
    limits: CacheRecoveryLimitsV1,
) -> Result<Vec<u8>, RecoveryError> {
    data::encode_typed_checkpoint(checkpoint, partition, limits).map_err(RecoveryError::from)
}

/// Executes the sole canonical historical codec with Native error projection.
///
/// # Errors
///
/// Returns [`RecoveryError`] for the corresponding malformed historical DATA.
pub fn decode_typed_checkpoint(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<CacheTypedCheckpointV1, RecoveryError> {
    data::decode_typed_checkpoint(partition, bytes, limits).map_err(RecoveryError::from)
}

pub(super) fn genesis_checkpoint_project_count(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<usize, RecoveryError> {
    data::genesis_checkpoint_project_count(partition, bytes, limits).map_err(RecoveryError::from)
}

#[cfg(all(test, target_os = "linux"))]
mod currentness_tests;
