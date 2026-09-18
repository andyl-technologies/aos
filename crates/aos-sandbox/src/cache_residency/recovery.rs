//! Bounded replay validation and fail-closed recovery work classification.
//!
//! Recovery never recreates current authority or silently repeats an effect.
//! It validates an exact checkpoint/floor anchor and contiguous retained event
//! chain, then emits observation-only work for unresolved physical outcomes.
//! Any contradiction yields a poison requirement rather than optimistic repair.
//!
//! The canonical protected envelopes have the following bounded shape:
//!
//! ```text
//! AOSCOR01 | v1 | record length | durable record | payload length | typed payload | digest
//! AOSTCP01 | v1 | checkpoint | typed baselines | per-family heads | digest
//! ```

use std::collections::BTreeMap;

use aos_sandbox_core::{
    AttachmentId, IncarnationId, MediaType, ObjectDescriptor, ObjectDigest, OperationId, ProjectId,
    SandboxId, ViewId,
};

use super::accounting::{
    AccountingLimitsV1, CacheAccountingV1, CacheReservationV1, CacheUsageV1, NodeCacheQuotaV1,
    ProjectCacheQuotaV1, ReservationStateV1,
};
use super::admission::{
    AdmissionProgressV1, AdmissionStageV1, ImmutableAdmissionPlanV1, WatermarkRequirementV1,
    initial_pin_set_digest,
};
use super::catalog::{
    BackingObjectIdentityV1, CatalogEntryV1, CatalogPresenceV1, LookupMemoValueV1,
};
use super::domain::{
    CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheAuthorityScopeV1,
    PhysicalPartitionId, VerifiedCacheCapabilityV1, object_descriptor_commitment,
};
use super::eviction::{
    EvictionCandidateStateV1, EvictionCandidateV1, EvictionProgressV1, FrozenEvictionPlanV1,
    validate_eviction_candidate,
};
use super::format::{
    CHECKPOINT_BYTES, CacheCheckpointV1, CacheDurableRecordV1, CacheHistoryFloorV1,
    CacheIdempotencyBindingV1, CacheIdempotencyCompactionFloorV1, CacheRecordKindV1,
    IDEMPOTENCY_FLOOR_BYTES, RECORD_BYTES as DURABLE_RECORD_BYTES, atomic_projection_digest,
    decode_checkpoint, decode_idempotency, decode_idempotency_floor_persisted, decode_record,
    encode_checkpoint, encode_idempotency, encode_idempotency_floor, encode_record,
};
use super::pin::{
    CachePinId, CachePinKindV1, CachePinLedgerV1, CachePinV1, PIN_FLOOR_BYTES,
    PinCompactionFloorV1, PinDrainEvidenceV1, PinDrainOutcomeV1, ReleasedCachePinV1,
    decode_pin_compaction_floor_persisted, encode_pin_compaction_floor,
};
use super::read_authority::{DescriptorHandoffPlanV1, DescriptorHandoffReceiptV1};
use super::scrub::{BackingObservationV1, ScrubEvidenceV1, scrub_subject};

mod accounting_projection;
mod canonical;
mod checkpoint;
mod classification;
mod codec;
mod global;
mod reducer;
mod replay;
mod state;
mod transition;

use accounting_projection::*;
use canonical::*;
use checkpoint::{
    decode_atomic_payload_components, encode_atomic_payload_components, typed_checkpoint_digest,
    validate_checkpoint_successor, validate_typed_checkpoint,
};
pub use checkpoint::{decode_typed_checkpoint, encode_typed_checkpoint};
use classification::{classify_work, push_recovery_work};
pub use codec::*;
use global::{handoff_is_terminal, lookup_is_terminal, validate_global_transition};
use reducer::validate_scrub_component;
use replay::*;
use state::validate_pending_cancellation;
pub use state::{PendingCancellationOutcomeV1, PendingCancellationV1};
use transition::*;

const ATOMIC_RECORD_MAGIC: &[u8; 8] = b"AOSCOR01";
const ATOMIC_PAYLOAD_MAGIC: &[u8; 8] = b"AOSCAP01";
const TYPED_CHECKPOINT_MAGIC: &[u8; 8] = b"AOSTCP01";
const CODEC_VERSION: u16 = 1;
const MAXIMUM_COMPONENT_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_EVICTION_CANDIDATES: usize = 65_536;

/// Supplies typed reducer state committed by one canonical durable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheAtomicObjectPayloadV1 {
    /// Canonical event header and history link.
    pub record: CacheDurableRecordV1,
    /// Exact immutable plan retained for this object.
    pub plan: ImmutableAdmissionPlanV1,
    /// Exact current reservation generation.
    pub reservation: CacheReservationV1,
    /// Exact current catalog generation, if publication occurred.
    pub catalog: Option<CatalogEntryV1>,
    /// Complete bounded active pin set for the object.
    pub pins: Vec<CachePinV1>,
    /// Complete bounded released-pin tombstones above the compaction floor.
    pub released_pins: Vec<ReleasedCachePinV1>,
    /// Exact current admission progress generation.
    pub progress: AdmissionProgressV1,
    /// Frozen eviction transaction for this object, if one exists.
    pub eviction_plan: Option<FrozenEvictionPlanV1>,
    /// Complete bounded candidate progress belonging to the eviction plan.
    pub eviction_progress: Vec<EvictionProgressV1>,
    /// Latest exact scrub observation and resulting catalog generation.
    pub scrub: Option<CacheScrubRecordV1>,
    /// Complete global state after this event, when the event follows a checkpoint.
    pub global_after: Option<CacheGlobalRecoveryStateV1>,
}

/// Persists exact scrub evidence and its catalog-generation disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheScrubRecordV1 {
    /// Opaque verifier-issued scrub evidence with repeated physical observations.
    pub evidence: ScrubEvidenceV1,
    /// Exact catalog generation evaluated by the scrub.
    pub prior_catalog: CatalogEntryV1,
    /// Exact catalog generation retained after the scrub decision.
    pub resulting_catalog: CatalogEntryV1,
}

impl CacheAtomicObjectPayloadV1 {
    pub(crate) fn canonical_record_digest(
        &self,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<ObjectDigest, RecoveryError> {
        self.validate(limits)?;
        Ok(self.record.digest)
    }

    /// Rebinds a record header to these exact canonical component bytes.
    ///
    /// The supplied record contributes transition metadata; its prior payload
    /// and digest are discarded and recomputed from this typed state.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] if components or rebuilt record are invalid.
    pub fn bind_record(
        mut self,
        record: CacheDurableRecordV1,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, RecoveryError> {
        let limits = limits.validate()?;
        validate_payload_bounds(&self, limits)?;
        let payload = payload_digest_bytes(&encode_atomic_payload_components(&self, limits)?);
        self.record = CacheDurableRecordV1::new(
            record.kind,
            record.state,
            record.sequence,
            record.operation,
            record.subject,
            record.partition,
            record.plan,
            record.model,
            record.authority,
            record.evidence,
            record.catalog_projection,
            record.reservation_projection,
            record.pin_projection,
            record.progress_projection,
            payload,
            record.amount,
            record.generation,
            record.family_predecessor,
            record.predecessor,
        )?;
        self.validate(limits)?;
        Ok(self)
    }

    fn validate(&self, limits: CacheRecoveryLimitsV1) -> Result<(), RecoveryError> {
        self.record.validate()?;
        self.plan
            .validate()
            .map_err(|_| RecoveryError::PayloadMismatch)?;
        self.progress
            .validate()
            .map_err(|_| RecoveryError::PayloadMismatch)?;
        self.reservation
            .validate_record()
            .map_err(|_| RecoveryError::PayloadMismatch)?;
        validate_payload_bounds(self, limits)?;
        if self.reservation.plan_digest != self.plan.digest
            || self.reservation.operation != self.plan.operation
            || self.reservation.descriptor != self.plan.descriptor
            || self.progress.plan_digest != self.plan.digest
            || self.record.partition != self.plan.partition.digest()
            || self.record.plan != self.plan.digest
            || self.record.subject != object_descriptor_commitment(&self.plan.descriptor)
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        if self.record.kind == CacheRecordKindV1::Admission
            && (self.record.state != self.progress.stage as u8
                || self.record.generation != self.progress.generation
                || self.record.evidence != self.progress.evidence)
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        if self.record.kind == CacheRecordKindV1::Admission {
            let stage_shape_valid = match self.progress.stage {
                AdmissionStageV1::Reserved
                | AdmissionStageV1::PrivateDestinationCreated
                | AdmissionStageV1::ContentTransferred
                | AdmissionStageV1::ContentVerified
                | AdmissionStageV1::WritersClosed
                | AdmissionStageV1::SealEnabledAndVerified
                | AdmissionStageV1::InodeSynced
                | AdmissionStageV1::CanonicalNamePublished
                | AdmissionStageV1::ParentSynced => {
                    matches!(
                        self.reservation.state,
                        ReservationStateV1::Reserved | ReservationStateV1::Uncertain
                    ) && self.catalog.is_none()
                        && self.pins.is_empty()
                        && self.released_pins.is_empty()
                }
                AdmissionStageV1::CatalogCommitted => {
                    let initial_pins = initial_pin_set_digest(&self.pins)
                        .map_err(|_| RecoveryError::PayloadMismatch)?;
                    self.reservation.state == ReservationStateV1::Converted
                        && self
                            .catalog
                            .as_ref()
                            .is_some_and(|entry| entry.presence == CatalogPresenceV1::Committed)
                        && self.released_pins.is_empty()
                        && initial_pins == self.plan.initial_pins_digest
                }
                AdmissionStageV1::Uncertain => {
                    self.reservation.state == ReservationStateV1::Uncertain
                        && self.catalog.is_none()
                        && self.pins.is_empty()
                        && self.released_pins.is_empty()
                }
                AdmissionStageV1::Quarantined => {
                    matches!(
                        self.reservation.state,
                        ReservationStateV1::Reserved | ReservationStateV1::Uncertain
                    ) && self.catalog.is_none()
                        && self.pins.is_empty()
                        && self.released_pins.is_empty()
                }
                AdmissionStageV1::Aborted => {
                    self.reservation.state == ReservationStateV1::Released
                        && self.catalog.is_none()
                        && self.pins.is_empty()
                        && self.released_pins.is_empty()
                }
            };
            if !stage_shape_valid {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        if self.record.kind == CacheRecordKindV1::Reservation
            && self.record.state != self.reservation.state as u8
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        if let Some(catalog) = &self.catalog {
            catalog
                .clone()
                .validate()
                .map_err(|_| RecoveryError::PayloadMismatch)?;
            let expected_reservation_state = if catalog.presence == CatalogPresenceV1::Evicted {
                ReservationStateV1::Evicted
            } else {
                ReservationStateV1::Converted
            };
            if catalog.partition != self.plan.partition
                || catalog.descriptor != self.plan.descriptor
                || catalog.reservation != self.plan.reservation
                || self.reservation.state != expected_reservation_state
                || (expected_reservation_state == ReservationStateV1::Converted
                    && self.reservation.resident_bytes != catalog.allocated_bytes)
                || (self.record.kind == CacheRecordKindV1::Catalog
                    && self.record.state != catalog.presence as u8)
            {
                return Err(RecoveryError::PayloadMismatch);
            }
        } else if matches!(
            self.reservation.state,
            ReservationStateV1::Converted | ReservationStateV1::Evicted
        ) || self.record.kind == CacheRecordKindV1::Catalog
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        for pin in &self.pins {
            pin.clone()
                .validate()
                .map_err(|_| RecoveryError::PayloadMismatch)?;
            if pin.partition != self.plan.partition
                || pin.object != self.plan.descriptor
                || (pin.kind != CachePinKindV1::SourceRetention
                    && !self
                        .catalog
                        .as_ref()
                        .is_some_and(|entry| entry.presence == CatalogPresenceV1::Committed))
            {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        validate_eviction_components(self)?;
        validate_eviction_record_shape(self)?;
        validate_scrub_component(self)?;
        if let Some(global) = &self.global_after {
            validate_global_recovery_state(global, self.plan.partition, limits)?;
        }
        if self.record.payload != canonical_payload_digest(self, limits)? {
            return Err(RecoveryError::PayloadMismatch);
        }
        Ok(())
    }
}

fn validate_eviction_record_shape(
    payload: &CacheAtomicObjectPayloadV1,
) -> Result<(), RecoveryError> {
    match payload.record.kind {
        CacheRecordKindV1::EvictionPlan => {
            if !valid_eviction_plan_record_shape(payload) {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        CacheRecordKindV1::EvictionProgress => {
            let index = usize::try_from(payload.record.amount)
                .map_err(|_| RecoveryError::PayloadMismatch)?;
            if !payload
                .eviction_progress
                .get(index)
                .is_some_and(|progress| payload.record.state == progress.state as u8)
            {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        _ => {}
    }
    Ok(())
}

fn valid_eviction_plan_record_shape(payload: &CacheAtomicObjectPayloadV1) -> bool {
    let Some(plan) = &payload.eviction_plan else {
        return false;
    };
    payload.record.state == 1
        && payload.record.authority == plan.authority_digest
        && payload.record.evidence == plan.digest
        && payload.record.amount == plan.candidates.len() as u64
}

fn validate_payload_bounds(
    payload: &CacheAtomicObjectPayloadV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<(), RecoveryError> {
    if payload.pins.len() > limits.maximum_subjects
        || payload.released_pins.len() > limits.maximum_subjects
        || payload.eviction_progress.len() > MAXIMUM_EVICTION_CANDIDATES
    {
        return Err(RecoveryError::Capacity);
    }
    Ok(())
}

/// Bounds replay allocations and retained recovery work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheRecoveryLimitsV1 {
    /// Maximum retained event records after the active floor.
    pub maximum_records: usize,
    /// Maximum latest subjects materialized during replay.
    pub maximum_subjects: usize,
    /// Maximum unresolved work items returned to an operator/reconciler.
    pub maximum_work_items: usize,
    /// Maximum bytes accepted for one canonical typed record or checkpoint.
    pub maximum_payload_bytes: usize,
}

impl CacheRecoveryLimitsV1 {
    /// Validates fixed recovery ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::InvalidLimits`] for zero or excessive bounds.
    pub fn validate(self) -> Result<Self, RecoveryError> {
        if self.maximum_records == 0
            || self.maximum_records > 1_000_000
            || self.maximum_subjects == 0
            || self.maximum_subjects > 1_000_000
            || self.maximum_work_items == 0
            || self.maximum_work_items > 65_536
            || self.maximum_payload_bytes < 16
            || self.maximum_payload_bytes > MAXIMUM_COMPONENT_BYTES
        {
            return Err(RecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

impl Default for CacheRecoveryLimitsV1 {
    fn default() -> Self {
        Self {
            maximum_records: 262_144,
            maximum_subjects: 65_536,
            maximum_work_items: 16_384,
            maximum_payload_bytes: MAXIMUM_COMPONENT_BYTES,
        }
    }
}

/// Retains the independent generation head for one subject and record family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheSubjectFamilyHeadV1 {
    /// Stable object subject commitment.
    pub subject: ObjectDigest,
    /// Closed durable record family.
    pub kind: CacheRecordKindV1,
    /// Latest independently monotone family generation.
    pub generation: u64,
    /// Digest of the record at that family generation.
    pub record_digest: ObjectDigest,
}

/// Permanently retains the first poison event that closed cache authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachePoisonLatchV1 {
    /// Operation that first established the contradiction.
    pub operation: OperationId,
    /// Exact first poison record, retained across every later checkpoint.
    pub record_digest: ObjectDigest,
}

/// Retains one reconstructible descriptor-handoff generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheReadHandoffStateV1 {
    /// Operation that prepared the handoff.
    pub operation: OperationId,
    /// Current read-authority decision commitment.
    pub authority: ObjectDigest,
    /// Catalog generation handed off.
    pub catalog: ObjectDigest,
    /// Exact retained physical pin.
    pub pin: CachePinId,
    /// Complete immutable object descriptor.
    pub descriptor: ObjectDescriptor,
    /// Opaque backing identity.
    pub backing: BackingObjectIdentityV1,
    /// Pre-handoff physical observation.
    pub preparation_evidence: ObjectDigest,
    /// Optional opaque receipt commitment proving completion.
    pub receipt_evidence: Option<ObjectDigest>,
    /// Authority-bound observed cancellation, mutually exclusive with receipt.
    pub cancellation: Option<PendingCancellationV1>,
    /// Last time a new handoff was permitted.
    pub valid_until: u64,
    /// Canonical handoff or receipt commitment.
    pub digest: ObjectDigest,
}

impl CacheReadHandoffStateV1 {
    /// Captures an exact opaque handoff plan before the descriptor effect.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for a sentinel operation or malformed plan.
    pub fn prepared(
        operation: OperationId,
        plan: &DescriptorHandoffPlanV1,
    ) -> Result<Self, RecoveryError> {
        let mut state = Self {
            operation,
            authority: plan.authority_digest(),
            catalog: plan.catalog_digest(),
            pin: plan.pin(),
            descriptor: plan.descriptor().clone(),
            backing: plan.backing(),
            preparation_evidence: plan.physical_evidence(),
            receipt_evidence: None,
            cancellation: None,
            valid_until: plan.valid_until(),
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        state.digest = handoff_state_digest(&state);
        validate_handoff_state(&state)?;
        Ok(state)
    }

    /// Attaches the opaque receipt issued for this exact handoff plan.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] if the receipt belongs to another plan or
    /// this state already has a receipt.
    pub fn with_receipt(
        &self,
        plan: &DescriptorHandoffPlanV1,
        receipt: DescriptorHandoffReceiptV1,
    ) -> Result<Self, RecoveryError> {
        if self.receipt_evidence.is_some()
            || self.cancellation.is_some()
            || self.digest != handoff_state_digest(self)
            || receipt.plan_digest() != plan.digest()
            || self.authority != plan.authority_digest()
            || self.catalog != plan.catalog_digest()
            || self.pin != plan.pin()
            || self.descriptor != *plan.descriptor()
            || self.backing != plan.backing()
            || self.preparation_evidence != plan.physical_evidence()
            || self.valid_until != plan.valid_until()
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        let mut state = self.clone();
        state.receipt_evidence = Some(receipt.digest());
        state.digest = handoff_state_digest(&state);
        validate_handoff_state(&state)?;
        Ok(state)
    }

    /// Terminates an unreceipted handoff after authority-bound no-effect observation.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] if the handoff is already terminal or the
    /// cancellation does not name this exact pending generation and deadline.
    pub fn with_cancellation(
        &self,
        cancellation: PendingCancellationV1,
    ) -> Result<Self, RecoveryError> {
        if self.receipt_evidence.is_some()
            || self.cancellation.is_some()
            || cancellation.target != self.digest
            || cancellation.target_valid_until != self.valid_until
        {
            return Err(RecoveryError::PayloadMismatch);
        }
        let mut state = self.clone();
        state.cancellation = Some(cancellation);
        state.digest = handoff_state_digest(&state);
        validate_handoff_state(&state)?;
        Ok(state)
    }
}

/// Retains one authority-scoped positive, negative, or in-flight lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheLookupStateV1 {
    /// Opaque full authorized-lookup-key commitment.
    pub key: ObjectDigest,
    /// Retained positive or bounded negative result, if completed.
    pub value: Option<LookupMemoValueV1>,
    /// Number of coalesced waiters on an incomplete lookup.
    pub waiters: u32,
    /// Bytes reserved for incomplete coalesced work.
    pub in_flight_bytes: u64,
    /// Authority-bound cancellation of incomplete coalesced work.
    pub cancellation: Option<PendingCancellationV1>,
}

impl CacheLookupStateV1 {
    /// Terminates incomplete coalesced work under exact cancellation authority.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] if the lookup is already terminal or the
    /// cancellation names another authorization-scoped lookup.
    pub fn with_cancellation(
        self,
        cancellation: PendingCancellationV1,
    ) -> Result<Self, RecoveryError> {
        if self.value.is_some() || self.cancellation.is_some() || cancellation.target != self.key {
            return Err(RecoveryError::PayloadMismatch);
        }
        let state = Self {
            waiters: 0,
            in_flight_bytes: 0,
            cancellation: Some(cancellation),
            ..self
        };
        validate_lookup_state(state)?;
        Ok(state)
    }
}

/// Reconstructs global quota, gate, idempotency, handoff, and lookup state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheGlobalRecoveryStateV1 {
    /// Exact protected node quota.
    pub node_quota: NodeCacheQuotaV1,
    /// Complete sorted protected project quotas.
    pub project_quotas: Vec<ProjectCacheQuotaV1>,
    /// Complete sorted outstanding reserve-to-low-water gates.
    pub watermarks: Vec<WatermarkRequirementV1>,
    /// Complete sorted idempotency bindings above the permanent floor.
    pub idempotency: Vec<CacheIdempotencyBindingV1>,
    /// Permanent compacted pin-identity floor.
    pub pin_floor: Option<PinCompactionFloorV1>,
    /// Permanent compacted idempotency-key floor.
    pub idempotency_floor: Option<CacheIdempotencyCompactionFloorV1>,
    /// Complete sorted handoff/receipt state.
    pub handoffs: Vec<CacheReadHandoffStateV1>,
    /// Complete sorted authority-scoped lookup state.
    pub lookups: Vec<CacheLookupStateV1>,
    /// Permanent poison latch.
    pub poison: Option<CachePoisonLatchV1>,
    /// Canonical digest of all global state.
    pub digest: ObjectDigest,
}

/// Couples a checkpoint to reconstructible per-subject state and family heads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheTypedCheckpointV1 {
    /// Canonical aggregate checkpoint header.
    pub checkpoint: CacheCheckpointV1,
    /// Exact latest typed state for every subject at the checkpoint.
    pub baselines: Vec<CacheAtomicObjectPayloadV1>,
    /// Exact per-subject, per-family generation heads at the checkpoint.
    pub family_heads: Vec<CacheSubjectFamilyHeadV1>,
    /// Complete canonical global state at the checkpoint.
    pub global: CacheGlobalRecoveryStateV1,
    /// Digest of the complete canonical typed checkpoint.
    pub digest: ObjectDigest,
}

impl CacheTypedCheckpointV1 {
    /// Constructs the aggregate header and typed checkpoint from baselines.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for unsorted/duplicate baselines, invalid
    /// family heads, inconsistent history metadata, or configured bounds.
    pub fn from_baselines(
        sequence: u64,
        history_head: ObjectDigest,
        predecessor: ObjectDigest,
        baselines: Vec<CacheAtomicObjectPayloadV1>,
        family_heads: Vec<CacheSubjectFamilyHeadV1>,
        global: CacheGlobalRecoveryStateV1,
        partition: PhysicalPartitionId,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, RecoveryError> {
        let limits = limits.validate()?;
        if predecessor.as_bytes() != &[0; 32] {
            return Err(RecoveryError::AnchorMismatch);
        }
        if baselines.len() > limits.maximum_subjects || family_heads.len() > limits.maximum_records
        {
            return Err(RecoveryError::Capacity);
        }
        let mut subject_map = BTreeMap::new();
        for baseline in &baselines {
            baseline.validate(limits)?;
            if subject_map
                .insert(baseline.record.subject, baseline.clone())
                .is_some()
            {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        let projections = aggregate_projections(&subject_map)?;
        let (catalog_entries, reservations, pins, pending_effects, charged_bytes) =
            aggregate_counts(&subject_map)?;
        validate_global_recovery_state(&global, partition, limits)?;
        let pending_effects = pending_effects
            .checked_add(global_pending_effects(&global)?)
            .ok_or(RecoveryError::Capacity)?;
        let lookup_entries =
            u64::try_from(global.lookups.len()).map_err(|_| RecoveryError::Capacity)?;
        let checkpoint = CacheCheckpointV1::new(
            sequence,
            history_head,
            atomic_projection_digest(projections.0, projections.1, projections.2, projections.3),
            projections.0,
            projections.1,
            projections.2,
            projections.3,
            catalog_entries,
            reservations,
            pins,
            pending_effects,
            charged_bytes,
            lookup_entries,
            predecessor,
        )?;
        Self::new(
            checkpoint,
            baselines,
            family_heads,
            global,
            partition,
            limits,
        )
    }

    /// Constructs a typed checkpoint over exact per-subject baselines.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for duplicate/inconsistent state or bounds.
    pub(crate) fn new(
        checkpoint: CacheCheckpointV1,
        baselines: Vec<CacheAtomicObjectPayloadV1>,
        family_heads: Vec<CacheSubjectFamilyHeadV1>,
        global: CacheGlobalRecoveryStateV1,
        partition: PhysicalPartitionId,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, RecoveryError> {
        let limits = limits.validate()?;
        if baselines.len() > limits.maximum_subjects || family_heads.len() > limits.maximum_records
        {
            return Err(RecoveryError::Capacity);
        }
        let mut typed = Self {
            checkpoint,
            baselines,
            family_heads,
            global,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        typed.digest = typed_checkpoint_digest(&typed, limits)?;
        validate_typed_checkpoint(&typed, partition, limits)?;
        Ok(typed)
    }

    /// Constructs a monotone successor without permitting floor or poison rollback.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for inconsistent aggregate state, a missing or
    /// regressed permanent floor, poison omission, or an invalid predecessor.
    #[allow(clippy::too_many_arguments)]
    fn successor_from_baselines(
        previous: &Self,
        sequence: u64,
        history_head: ObjectDigest,
        baselines: Vec<CacheAtomicObjectPayloadV1>,
        family_heads: Vec<CacheSubjectFamilyHeadV1>,
        global: CacheGlobalRecoveryStateV1,
        newly_poisoned: Option<CachePoisonLatchV1>,
        partition: PhysicalPartitionId,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, RecoveryError> {
        let limits = limits.validate()?;
        let mut subjects = BTreeMap::new();
        for baseline in &baselines {
            baseline.validate(limits)?;
            if subjects
                .insert(baseline.record.subject, baseline.clone())
                .is_some()
            {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        let projections = aggregate_projections(&subjects)?;
        let counts = aggregate_counts(&subjects)?;
        validate_global_recovery_state(&global, partition, limits)?;
        let pending_effects = counts
            .3
            .checked_add(global_pending_effects(&global)?)
            .ok_or(RecoveryError::Capacity)?;
        let lookup_entries =
            u64::try_from(global.lookups.len()).map_err(|_| RecoveryError::Capacity)?;
        let checkpoint = CacheCheckpointV1::new(
            sequence,
            history_head,
            atomic_projection_digest(projections.0, projections.1, projections.2, projections.3),
            projections.0,
            projections.1,
            projections.2,
            projections.3,
            counts.0,
            counts.1,
            counts.2,
            pending_effects,
            counts.4,
            lookup_entries,
            previous.digest,
        )?;
        let mut global = global;
        global.poison = previous.global.poison.or(newly_poisoned);
        global.digest = global_state_digest(&global, limits)?;
        let next = Self::new(
            checkpoint,
            baselines,
            family_heads,
            global,
            partition,
            limits,
        )?;
        validate_checkpoint_successor(previous, &next)?;
        Ok(next)
    }

    /// Constructs the next checkpoint directly from one validated replay inventory.
    ///
    /// This path carries every reconstructed family head, permanent floor, and
    /// poison latch forward without asking the caller to recreate reducer state.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] if the inventory does not form a monotone
    /// successor of `previous` or violates a configured bound.
    pub fn successor_from_inventory(
        previous: &Self,
        inventory: &CacheRecoveryInventoryV1,
        sequence: u64,
        history_head: ObjectDigest,
        partition: PhysicalPartitionId,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, RecoveryError> {
        if inventory.checkpoint != previous.digest
            || inventory.head_digest != history_head
            || inventory.head_sequence != sequence
            || inventory.replay_authority.as_bytes() == &[0; 32]
            || inventory.replay_binding != replay_inventory_binding(inventory)
        {
            return Err(RecoveryError::AnchorMismatch);
        }
        Self::successor_from_baselines(
            previous,
            sequence,
            history_head,
            inventory.reconstructed.clone(),
            inventory.family_heads.clone(),
            inventory.global.clone(),
            inventory.global.poison,
            partition,
            limits,
        )
    }
}

impl CacheGlobalRecoveryStateV1 {
    /// Constructs and canonicalizes complete bounded global recovery state.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for malformed, duplicate, unsorted, or
    /// over-bound global state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_quota: NodeCacheQuotaV1,
        project_quotas: Vec<ProjectCacheQuotaV1>,
        watermarks: Vec<WatermarkRequirementV1>,
        idempotency: Vec<CacheIdempotencyBindingV1>,
        pin_floor: Option<PinCompactionFloorV1>,
        idempotency_floor: Option<CacheIdempotencyCompactionFloorV1>,
        handoffs: Vec<CacheReadHandoffStateV1>,
        lookups: Vec<CacheLookupStateV1>,
        poison: Option<CachePoisonLatchV1>,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, RecoveryError> {
        let limits = limits.validate()?;
        let mut state = Self {
            node_quota,
            project_quotas,
            watermarks,
            idempotency,
            pin_floor,
            idempotency_floor,
            handoffs,
            lookups,
            poison,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        state.digest = global_state_digest(&state, limits)?;
        validate_global_recovery_state(&state, state.node_quota.partition, limits)?;
        Ok(state)
    }
}

/// Selects observation-only recovery work for one unresolved subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheRecoveryWorkV1 {
    /// Reopen and revalidate a privately prepared artifact; do not publish it.
    ObservePreparedArtifact {
        /// Admission operation.
        operation: OperationId,
        /// Exact latest durable record.
        record_digest: ObjectDigest,
    },
    /// Reconcile an uncertain reservation while retaining its full charge.
    ObserveUncertainReservation {
        /// Admission operation.
        operation: OperationId,
        /// Exact latest durable record.
        record_digest: ObjectDigest,
    },
    /// Reopen a deleting name and determine whether unlink occurred.
    ObserveDeletingObject {
        /// Eviction operation.
        operation: OperationId,
        /// Exact latest durable record.
        record_digest: ObjectDigest,
    },
    /// Re-observe physical reclamation; do not credit bytes yet.
    ObserveRemovedBacking {
        /// Eviction operation.
        operation: OperationId,
        /// Exact latest durable record.
        record_digest: ObjectDigest,
    },
    /// Reconcile a kernel/backing pin only after consumer death and drain proof.
    ObservePhysicalPinDrain {
        /// Operation that last changed the pin.
        operation: OperationId,
        /// Exact active physical pin requiring reconciliation.
        pin: CachePinId,
        /// Exact latest durable record.
        record_digest: ObjectDigest,
    },
    /// Resolve or abort a prepared descriptor handoff before its deadline.
    ObservePendingHandoff {
        /// Immutable handoff operation identity.
        operation: OperationId,
        /// Exact prepared handoff commitment.
        handoff_digest: ObjectDigest,
    },
    /// Complete or cancel one coalesced authorized lookup.
    ObservePendingLookup {
        /// Opaque authorization-scoped lookup identity.
        key: ObjectDigest,
    },
    /// Compact one durably completed descriptor-handoff receipt.
    CompactCompletedHandoff {
        /// Immutable handoff operation identity.
        operation: OperationId,
        /// Exact completed handoff commitment.
        handoff_digest: ObjectDigest,
    },
    /// Compact one terminal positive or negative lookup memo.
    CompactCompletedLookup {
        /// Opaque authorization-scoped lookup identity.
        key: ObjectDigest,
    },
    /// Preserve quarantine and request operator diagnosis.
    DiagnoseQuarantine {
        /// Operation whose observation caused quarantine.
        operation: OperationId,
        /// Exact latest durable record.
        record_digest: ObjectDigest,
    },
    /// Stop authority use and require protected conflict resolution.
    ResolvePoison {
        /// Operation that established contradiction.
        operation: OperationId,
        /// Exact poison record.
        record_digest: ObjectDigest,
    },
}

/// Summarizes a validated retained history and its unresolved work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheRecoveryInventoryV1 {
    /// Exact source typed-checkpoint digest.
    pub checkpoint: ObjectDigest,
    /// Active history-floor digest.
    pub floor: ObjectDigest,
    /// Last validated retained sequence.
    pub head_sequence: u64,
    /// Last validated retained record digest.
    pub head_digest: ObjectDigest,
    /// Observation-only recovery work.
    pub work: Vec<CacheRecoveryWorkV1>,
    /// Whether any poison record closes new authority.
    pub authority_poisoned: bool,
    /// Reconstructed latest catalog projection.
    pub catalog_projection: ObjectDigest,
    /// Reconstructed latest reservation projection.
    pub reservation_projection: ObjectDigest,
    /// Reconstructed latest pin projection.
    pub pin_projection: ObjectDigest,
    /// Reconstructed latest effect-progress projection.
    pub progress_projection: ObjectDigest,
    /// Latest validated typed reducer state for every retained subject.
    pub reconstructed: Vec<CacheAtomicObjectPayloadV1>,
    /// Complete reconstructed per-subject family heads for checkpoint continuation.
    pub family_heads: Vec<CacheSubjectFamilyHeadV1>,
    /// Complete reconstructed global state after the retained suffix.
    pub global: CacheGlobalRecoveryStateV1,
    replay_authority: ObjectDigest,
    replay_binding: ObjectDigest,
}

impl CacheRecoveryInventoryV1 {
    /// Validates anchored history and classifies unresolved latest records.
    ///
    /// Records must be supplied in strictly increasing sequence order beginning
    /// at the floor. The checkpoint and floor are assumed to have been read from
    /// protected storage and are revalidated here before any work is returned.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] for invalid anchors, noncontiguous history,
    /// subject rollback/equivocation, or configured bound exhaustion.
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
        Self::from_authorized(
            partition,
            typed_checkpoint_bytes,
            prior_typed_checkpoint_bytes,
            floor,
            records,
            limits,
            capability.scope().valid_until(),
            capability.record_digest(),
            |authority_scope| {
                owner.validate_for_effect_at(
                    capability,
                    CacheAuthorityPurposeV1::Replay,
                    authority_scope,
                    now,
                )?;
                Ok(())
            },
        )
    }

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
        Self::from_authorized(
            partition,
            typed_checkpoint_bytes,
            prior_typed_checkpoint_bytes,
            floor,
            records,
            limits,
            authority_scope.valid_until(),
            authority_record,
            |derived| {
                if derived != authority_scope {
                    return Err(RecoveryError::AnchorMismatch);
                }
                Ok(())
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_authorized(
        partition: PhysicalPartitionId,
        typed_checkpoint_bytes: &[u8],
        prior_typed_checkpoint_bytes: Option<&[u8]>,
        floor: CacheHistoryFloorV1,
        records: impl IntoIterator<Item = Vec<u8>>,
        limits: CacheRecoveryLimitsV1,
        authority_valid_until: u64,
        authority_record: ObjectDigest,
        validate_authority: impl FnOnce(CacheAuthorityScopeV1) -> Result<(), RecoveryError>,
    ) -> Result<Self, RecoveryError> {
        let limits = limits.validate()?;
        let typed_checkpoint = decode_typed_checkpoint(partition, typed_checkpoint_bytes, limits)?;
        match prior_typed_checkpoint_bytes {
            Some(bytes) => {
                let prior = decode_typed_checkpoint(partition, bytes, limits)?;
                validate_checkpoint_successor(&prior, &typed_checkpoint)?;
            }
            None if typed_checkpoint.checkpoint.predecessor.as_bytes() == &[0; 32] => {}
            None => return Err(RecoveryError::AnchorMismatch),
        }
        let typed_checkpoint_digest = typed_checkpoint.digest;
        let mut global = typed_checkpoint.global.clone();
        let checkpoint = typed_checkpoint.checkpoint;
        floor.validate()?;
        if checkpoint.catalog_entries > limits.maximum_subjects as u64
            || checkpoint.reservations > limits.maximum_subjects as u64
            || checkpoint.pins > limits.maximum_subjects as u64
            || checkpoint.lookup_entries > limits.maximum_subjects as u64
            || checkpoint.pending_effects > limits.maximum_work_items as u64
        {
            return Err(RecoveryError::Capacity);
        }
        if checkpoint.projection
            != atomic_projection_digest(
                checkpoint.catalog_projection,
                checkpoint.reservation_projection,
                checkpoint.pin_projection,
                checkpoint.progress_projection,
            )
        {
            return Err(RecoveryError::ProjectionMismatch);
        }
        if floor.checkpoint != checkpoint.digest
            || floor.retained_history_root != checkpoint.history_head
            || floor.first_retained_sequence
                != checkpoint
                    .sequence
                    .checked_add(1)
                    .ok_or(RecoveryError::HistoryOverflow)?
        {
            return Err(RecoveryError::AnchorMismatch);
        }

        let mut latest = BTreeMap::<ObjectDigest, CacheAtomicObjectPayloadV1>::new();
        for baseline in typed_checkpoint.baselines {
            if latest.insert(baseline.record.subject, baseline).is_some() {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        let mut family_heads = BTreeMap::<(ObjectDigest, u8), (u64, ObjectDigest)>::new();
        for head in typed_checkpoint.family_heads {
            if family_heads
                .insert(
                    (head.subject, head.kind as u8),
                    (head.generation, head.record_digest),
                )
                .is_some()
            {
                return Err(RecoveryError::PayloadMismatch);
            }
        }
        let mut identities = GlobalIdentityIndex::from_subjects(&latest)?;
        let mut retained_pin_tombstones =
            RetainedPinTombstoneIndex::from_subjects(&latest, limits.maximum_records)?;
        let mut projections = ProjectionAccumulator::from_subjects(&latest)?;
        let mut accounting =
            RecoveredAccountingProjection::from_subjects(&global, &latest, limits)?;
        let mut expected_sequence = floor.first_retained_sequence;
        let mut expected_predecessor = checkpoint.history_head;
        let mut record_count = 0usize;
        for bytes in records {
            record_count = record_count.checked_add(1).ok_or(RecoveryError::Capacity)?;
            if record_count > limits.maximum_records {
                return Err(RecoveryError::Capacity);
            }
            let input = decode_atomic_object_record(partition, &bytes, limits)?;
            let record = input.record;
            let next_global = input
                .global_after
                .as_ref()
                .ok_or(RecoveryError::PayloadMismatch)?;
            validate_global_transition(&global, next_global, &input, typed_checkpoint_digest)?;
            global = next_global.clone();
            if record.kind == CacheRecordKindV1::Poison && global.poison.is_none() {
                global.poison = Some(CachePoisonLatchV1 {
                    operation: record.operation,
                    record_digest: record.digest,
                });
                global.digest = global_state_digest(&global, limits)?;
            }
            if record.model
                != atomic_projection_digest(
                    record.catalog_projection,
                    record.reservation_projection,
                    record.pin_projection,
                    record.progress_projection,
                )
            {
                return Err(RecoveryError::ProjectionMismatch);
            }
            if record.sequence != expected_sequence || record.predecessor != expected_predecessor {
                return Err(RecoveryError::BrokenHistory);
            }
            let subject_key = record.subject;
            if let Some(previous) = latest.get(&subject_key) {
                validate_typed_continuity(previous, &input, record.kind)?;
            } else if latest.len() >= limits.maximum_subjects {
                return Err(RecoveryError::Capacity);
            } else if !valid_initial_subject(&input) {
                return Err(RecoveryError::PayloadMismatch);
            }
            let family_key = (subject_key, record.kind as u8);
            if let Some((generation, digest)) = family_heads.get(&family_key) {
                if generation.checked_add(1) != Some(record.generation)
                    || record.family_predecessor != *digest
                {
                    return Err(RecoveryError::SubjectRollback);
                }
            } else if record.generation != 1 || record.family_predecessor.as_bytes() != &[0; 32] {
                return Err(RecoveryError::SubjectRollback);
            }
            family_heads.insert(family_key, (record.generation, record.digest));
            identities.observe(subject_key, &input)?;
            retained_pin_tombstones.replace(
                latest.get(&subject_key),
                &input,
                limits.maximum_records,
            )?;
            retained_pin_tombstones.validate_floor(global.pin_floor)?;
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(RecoveryError::HistoryOverflow)?;
            expected_predecessor = record.digest;
            projections.replace(subject_key, latest.get(&subject_key), &input)?;
            accounting.replace(latest.get(&subject_key), &input, &global)?;
            latest.insert(subject_key, input);
            validate_watermark_gate(&global, projections.charged_bytes)?;
            let current_projections = projections.digests();
            if record.catalog_projection != current_projections.0
                || record.reservation_projection != current_projections.1
                || record.pin_projection != current_projections.2
                || record.progress_projection != current_projections.3
                || record.model
                    != atomic_projection_digest(
                        current_projections.0,
                        current_projections.1,
                        current_projections.2,
                        current_projections.3,
                    )
            {
                return Err(RecoveryError::ProjectionMismatch);
            }
        }

        let mut work = Vec::new();
        for input in latest.values() {
            let remaining = limits.maximum_work_items.saturating_sub(work.len());
            for item in classify_work(input, remaining)? {
                if work.len() >= limits.maximum_work_items {
                    return Err(RecoveryError::Capacity);
                }
                work.push(item);
            }
        }
        for handoff in &global.handoffs {
            let item = if handoff_is_terminal(handoff) {
                CacheRecoveryWorkV1::CompactCompletedHandoff {
                    operation: handoff.operation,
                    handoff_digest: handoff.digest,
                }
            } else {
                CacheRecoveryWorkV1::ObservePendingHandoff {
                    operation: handoff.operation,
                    handoff_digest: handoff.digest,
                }
            };
            push_recovery_work(&mut work, limits.maximum_work_items, item)?;
        }
        for lookup in &global.lookups {
            let item = if lookup_is_terminal(lookup) {
                CacheRecoveryWorkV1::CompactCompletedLookup { key: lookup.key }
            } else {
                CacheRecoveryWorkV1::ObservePendingLookup { key: lookup.key }
            };
            push_recovery_work(&mut work, limits.maximum_work_items, item)?;
        }
        if let Some(poison) = global.poison {
            if work.len() >= limits.maximum_work_items {
                return Err(RecoveryError::Capacity);
            }
            work.push(CacheRecoveryWorkV1::ResolvePoison {
                operation: poison.operation,
                record_digest: poison.record_digest,
            });
        }
        let authority_poisoned = global.poison.is_some();

        let (catalog_projection, reservation_projection, pin_projection, progress_projection) =
            projections.digests();
        let head_sequence = expected_sequence.saturating_sub(1);
        // Protected authority binds the immutable replay anchor. The journal
        // CAS/hash chain and inventory binding authenticate the evolving suffix.
        let subject = replay_authority_subject(
            typed_checkpoint_digest,
            floor.digest,
            floor.first_retained_sequence,
            floor.retained_history_root,
            partition.digest(),
        );
        let authority_scope = CacheAuthorityScopeV1::new(
            partition,
            subject,
            None,
            typed_checkpoint_digest,
            partition.backing().root(),
            floor.first_retained_sequence,
            authority_valid_until,
        )?;
        validate_authority(authority_scope)?;
        let reconstructed = latest.into_values().collect::<Vec<_>>();
        let mut recovered_family_heads = Vec::with_capacity(family_heads.len());
        for ((subject, kind), (generation, record_digest)) in family_heads {
            recovered_family_heads.push(CacheSubjectFamilyHeadV1 {
                subject,
                kind: record_kind(kind)?,
                generation,
                record_digest,
            });
        }
        let mut inventory = Self {
            checkpoint: typed_checkpoint_digest,
            floor: floor.digest,
            head_sequence,
            head_digest: expected_predecessor,
            work,
            authority_poisoned,
            catalog_projection,
            reservation_projection,
            pin_projection,
            progress_projection,
            reconstructed,
            family_heads: recovered_family_heads,
            global,
            replay_authority: authority_record,
            replay_binding: ObjectDigest::from_bytes([0; 32]),
        };
        inventory.replay_binding = replay_inventory_binding(&inventory);
        Ok(inventory)
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
