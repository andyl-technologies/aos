//! Canonical bounded durability formats for cache-residency history.
//!
//! Records are fixed-width binary values with closed kind/state registries,
//! explicit reserved zero bytes, exact predecessors, and domain-separated
//! digests. Checkpoints and floors are separate formats so compaction cannot
//! reinterpret an event as authority. None of these formats contains a host
//! path, file descriptor, device number, inode number, or backend command.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, PrincipalId};
use sha2::{Digest as _, Sha256};

const RECORD_MAGIC: &[u8; 8] = b"AOSCXR01";
const CHECKPOINT_MAGIC: &[u8; 8] = b"AOSCXP01";
const FLOOR_MAGIC: &[u8; 8] = b"AOSCXF01";
const IDEMPOTENCY_MAGIC: &[u8; 8] = b"AOSCXI01";
const VERSION: u16 = 1;
use super::domain::{
    CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheAuthorityScopeV1, PhysicalPartitionId,
    VerifiedCacheCapabilityV1,
};

pub(crate) const RECORD_BYTES: usize = 504;
pub(crate) const CHECKPOINT_BYTES: usize = 328;
const FLOOR_BYTES: usize = 152;
const IDEMPOTENCY_BYTES: usize = 200;
pub(crate) const IDEMPOTENCY_FLOOR_BYTES: usize = 168;

const RECORD_DOMAIN: &[u8] = b"aos.sandbox.cache.durable-record.v1\0";
const CHECKPOINT_DOMAIN: &[u8] = b"aos.sandbox.cache.checkpoint.v1\0";
const FLOOR_DOMAIN: &[u8] = b"aos.sandbox.cache.floor.v1\0";
const IDEMPOTENCY_DOMAIN: &[u8] = b"aos.sandbox.cache.idempotency.v1\0";

/// Selects the closed durable cache record family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CacheRecordKindV1 {
    /// Installs one physical domain and isolation-policy binding.
    Domain = 1,
    /// Installs or updates one project/node quota.
    Quota = 2,
    /// Records a reservation generation.
    Reservation = 3,
    /// Records immutable admission before effects.
    Admission = 4,
    /// Records a committed/deleting/quarantined catalog generation.
    Catalog = 5,
    /// Acquires or releases one logical/source/kernel/backing pin.
    Pin = 6,
    /// Freezes one exact eviction candidate set.
    EvictionPlan = 7,
    /// Records one candidate's eviction progress.
    EvictionProgress = 8,
    /// Records exact scrub evidence and disposition.
    Scrub = 9,
    /// Records a current-authority descriptor handoff.
    ReadHandoff = 10,
    /// Records a bounded negative-cache or coalescing state transition.
    LookupMemo = 11,
    /// Permanently latches contradictory state for operator recovery.
    Poison = 12,
    /// Advances permanent pin or idempotency compaction floors.
    Compaction = 13,
}

impl CacheRecordKindV1 {
    fn from_code(code: u8) -> Result<Self, CacheFormatError> {
        match code {
            1 => Ok(Self::Domain),
            2 => Ok(Self::Quota),
            3 => Ok(Self::Reservation),
            4 => Ok(Self::Admission),
            5 => Ok(Self::Catalog),
            6 => Ok(Self::Pin),
            7 => Ok(Self::EvictionPlan),
            8 => Ok(Self::EvictionProgress),
            9 => Ok(Self::Scrub),
            10 => Ok(Self::ReadHandoff),
            11 => Ok(Self::LookupMemo),
            12 => Ok(Self::Poison),
            13 => Ok(Self::Compaction),
            _ => Err(CacheFormatError::UnknownKind),
        }
    }
}

/// Stores a canonical append-only cache event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheDurableRecordV1 {
    /// Closed record family.
    pub kind: CacheRecordKindV1,
    /// Family-specific closed state code.
    pub state: u8,
    /// Strictly increasing namespace sequence.
    pub sequence: u64,
    /// Idempotent operation owning the transition.
    pub operation: OperationId,
    /// Family-specific stable subject commitment.
    pub subject: ObjectDigest,
    /// Physical partition commitment.
    pub partition: ObjectDigest,
    /// Exact immutable plan or request commitment.
    pub plan: ObjectDigest,
    /// Current aggregate model-projection digest.
    pub model: ObjectDigest,
    /// Authority or pin commitment consumed by the transition.
    pub authority: ObjectDigest,
    /// Physical observation or completion evidence.
    pub evidence: ObjectDigest,
    /// Exact catalog projection atomically installed by this event.
    pub catalog_projection: ObjectDigest,
    /// Exact reservation projection atomically installed by this event.
    pub reservation_projection: ObjectDigest,
    /// Exact pin projection atomically installed by this event.
    pub pin_projection: ObjectDigest,
    /// Exact admission/eviction progress projection atomically installed by this event.
    pub progress_projection: ObjectDigest,
    /// Canonical typed reducer-payload commitment.
    pub payload: ObjectDigest,
    /// Family-specific checked byte/count value.
    pub amount: u64,
    /// Family-specific monotone generation.
    pub generation: u64,
    /// Digest of the preceding record for this subject and family.
    pub family_predecessor: ObjectDigest,
    /// Digest of the immediately preceding namespace record.
    pub predecessor: ObjectDigest,
    /// Digest of this complete record.
    pub digest: ObjectDigest,
}

impl CacheDurableRecordV1 {
    /// Constructs and validates one canonical event.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::InvalidRecord`] for sentinel identities,
    /// sequence/generation zero, unknown family state, or missing commitments.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: CacheRecordKindV1,
        state: u8,
        sequence: u64,
        operation: OperationId,
        subject: ObjectDigest,
        partition: ObjectDigest,
        plan: ObjectDigest,
        model: ObjectDigest,
        authority: ObjectDigest,
        evidence: ObjectDigest,
        catalog_projection: ObjectDigest,
        reservation_projection: ObjectDigest,
        pin_projection: ObjectDigest,
        progress_projection: ObjectDigest,
        payload: ObjectDigest,
        amount: u64,
        generation: u64,
        family_predecessor: ObjectDigest,
        predecessor: ObjectDigest,
    ) -> Result<Self, CacheFormatError> {
        let mut record = Self {
            kind,
            state,
            sequence,
            operation,
            subject,
            partition,
            plan,
            model,
            authority,
            evidence,
            catalog_projection,
            reservation_projection,
            pin_projection,
            progress_projection,
            payload,
            amount,
            generation,
            family_predecessor,
            predecessor,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        record.digest = durable_record_digest(&record);
        record.validate()?;
        Ok(record)
    }

    /// Validates closed shape and the derived digest.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::InvalidRecord`] for malformed facts.
    pub fn validate(&self) -> Result<(), CacheFormatError> {
        if self.state == 0
            || !valid_state(self.kind, self.state)
            || self.sequence == 0
            || self.operation.as_bytes() == &[0; 16]
            || self.subject.as_bytes() == &[0; 32]
            || self.partition.as_bytes() == &[0; 32]
            || self.plan.as_bytes() == &[0; 32]
            || self.model.as_bytes() == &[0; 32]
            || self.authority.as_bytes() == &[0; 32]
            || self.evidence.as_bytes() == &[0; 32]
            || self.catalog_projection.as_bytes() == &[0; 32]
            || self.reservation_projection.as_bytes() == &[0; 32]
            || self.pin_projection.as_bytes() == &[0; 32]
            || self.progress_projection.as_bytes() == &[0; 32]
            || self.payload.as_bytes() == &[0; 32]
            || self.model
                != atomic_projection_digest(
                    self.catalog_projection,
                    self.reservation_projection,
                    self.pin_projection,
                    self.progress_projection,
                )
            || self.generation == 0
            || (self.generation == 1) != (self.family_predecessor.as_bytes() == &[0; 32])
            || (self.sequence == 1) != (self.predecessor.as_bytes() == &[0; 32])
            || self.digest != durable_record_digest(self)
        {
            return Err(CacheFormatError::InvalidRecord);
        }
        Ok(())
    }
}

/// Encodes an event into the exact 504-byte V1 format.
///
/// # Errors
///
/// Returns [`CacheFormatError`] if the record is invalid.
pub fn encode_record(
    record: &CacheDurableRecordV1,
) -> Result<[u8; RECORD_BYTES], CacheFormatError> {
    record.validate()?;
    let mut bytes = [0_u8; RECORD_BYTES];
    bytes[0..8].copy_from_slice(RECORD_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10] = record.kind as u8;
    bytes[11] = record.state;
    bytes[16..24].copy_from_slice(&record.sequence.to_be_bytes());
    bytes[24..40].copy_from_slice(record.operation.as_bytes());
    bytes[40..72].copy_from_slice(record.subject.as_bytes());
    bytes[72..104].copy_from_slice(record.partition.as_bytes());
    bytes[104..136].copy_from_slice(record.plan.as_bytes());
    bytes[136..168].copy_from_slice(record.model.as_bytes());
    bytes[168..200].copy_from_slice(record.authority.as_bytes());
    bytes[200..232].copy_from_slice(record.evidence.as_bytes());
    bytes[232..264].copy_from_slice(record.catalog_projection.as_bytes());
    bytes[264..296].copy_from_slice(record.reservation_projection.as_bytes());
    bytes[296..328].copy_from_slice(record.pin_projection.as_bytes());
    bytes[328..360].copy_from_slice(record.progress_projection.as_bytes());
    bytes[360..392].copy_from_slice(record.payload.as_bytes());
    bytes[392..400].copy_from_slice(&record.amount.to_be_bytes());
    bytes[400..408].copy_from_slice(&record.generation.to_be_bytes());
    bytes[408..440].copy_from_slice(record.family_predecessor.as_bytes());
    bytes[440..472].copy_from_slice(record.predecessor.as_bytes());
    bytes[472..504].copy_from_slice(record.digest.as_bytes());
    Ok(bytes)
}

/// Decodes and revalidates the exact V1 event format.
///
/// # Errors
///
/// Returns [`CacheFormatError`] for wrong length, magic/version, nonzero
/// reserved bytes, unknown kind, malformed fields, or digest mismatch.
pub fn decode_record(bytes: &[u8]) -> Result<CacheDurableRecordV1, CacheFormatError> {
    if bytes.len() != RECORD_BYTES
        || &bytes[0..8] != RECORD_MAGIC
        || read_u16(bytes, 8)? != VERSION
        || bytes[12..16] != [0; 4]
    {
        return Err(CacheFormatError::Malformed);
    }
    let record = CacheDurableRecordV1 {
        kind: CacheRecordKindV1::from_code(bytes[10])?,
        state: bytes[11],
        sequence: read_u64(bytes, 16)?,
        operation: OperationId::from_bytes(read_array(bytes, 24)?),
        subject: ObjectDigest::from_bytes(read_array(bytes, 40)?),
        partition: ObjectDigest::from_bytes(read_array(bytes, 72)?),
        plan: ObjectDigest::from_bytes(read_array(bytes, 104)?),
        model: ObjectDigest::from_bytes(read_array(bytes, 136)?),
        authority: ObjectDigest::from_bytes(read_array(bytes, 168)?),
        evidence: ObjectDigest::from_bytes(read_array(bytes, 200)?),
        catalog_projection: ObjectDigest::from_bytes(read_array(bytes, 232)?),
        reservation_projection: ObjectDigest::from_bytes(read_array(bytes, 264)?),
        pin_projection: ObjectDigest::from_bytes(read_array(bytes, 296)?),
        progress_projection: ObjectDigest::from_bytes(read_array(bytes, 328)?),
        payload: ObjectDigest::from_bytes(read_array(bytes, 360)?),
        amount: read_u64(bytes, 392)?,
        generation: read_u64(bytes, 400)?,
        family_predecessor: ObjectDigest::from_bytes(read_array(bytes, 408)?),
        predecessor: ObjectDigest::from_bytes(read_array(bytes, 440)?),
        digest: ObjectDigest::from_bytes(read_array(bytes, 472)?),
    };
    record.validate()?;
    Ok(record)
}

/// Summarizes a complete validated projection at one history sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheCheckpointV1 {
    /// Last event sequence included in the checkpoint.
    pub sequence: u64,
    /// Digest of the last included event.
    pub history_head: ObjectDigest,
    /// Digest of the complete canonical materialized projection.
    pub projection: ObjectDigest,
    /// Exact catalog projection represented by this checkpoint.
    pub catalog_projection: ObjectDigest,
    /// Exact reservation projection represented by this checkpoint.
    pub reservation_projection: ObjectDigest,
    /// Exact pin projection represented by this checkpoint.
    pub pin_projection: ObjectDigest,
    /// Exact progress projection represented by this checkpoint.
    pub progress_projection: ObjectDigest,
    /// Number of committed/deleting/quarantined catalog objects.
    pub catalog_entries: u64,
    /// Number of retained reservations.
    pub reservations: u64,
    /// Number of retained pin obligations.
    pub pins: u64,
    /// Number of in-progress or ambiguous effects.
    pub pending_effects: u64,
    /// Conservatively charged physical bytes.
    pub charged_bytes: u64,
    /// Bounded retained lookup entries.
    pub lookup_entries: u64,
    /// Prior checkpoint digest, zero only for the first checkpoint.
    pub predecessor: ObjectDigest,
    /// Digest of this exact checkpoint.
    pub digest: ObjectDigest,
}

impl CacheCheckpointV1 {
    /// Constructs a checkpoint over one fully validated projection.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::InvalidCheckpoint`] for sentinel inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        history_head: ObjectDigest,
        projection: ObjectDigest,
        catalog_projection: ObjectDigest,
        reservation_projection: ObjectDigest,
        pin_projection: ObjectDigest,
        progress_projection: ObjectDigest,
        catalog_entries: u64,
        reservations: u64,
        pins: u64,
        pending_effects: u64,
        charged_bytes: u64,
        lookup_entries: u64,
        predecessor: ObjectDigest,
    ) -> Result<Self, CacheFormatError> {
        let mut checkpoint = Self {
            sequence,
            history_head,
            projection,
            catalog_projection,
            reservation_projection,
            pin_projection,
            progress_projection,
            catalog_entries,
            reservations,
            pins,
            pending_effects,
            charged_bytes,
            lookup_entries,
            predecessor,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        checkpoint.digest = checkpoint_digest(&checkpoint);
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    /// Validates checkpoint commitments and checked counts.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::InvalidCheckpoint`] for sentinel or digest
    /// inconsistencies.
    pub fn validate(&self) -> Result<(), CacheFormatError> {
        if self.sequence == 0
            || self.history_head.as_bytes() == &[0; 32]
            || self.projection.as_bytes() == &[0; 32]
            || self.catalog_projection.as_bytes() == &[0; 32]
            || self.reservation_projection.as_bytes() == &[0; 32]
            || self.pin_projection.as_bytes() == &[0; 32]
            || self.progress_projection.as_bytes() == &[0; 32]
            || self.projection
                != atomic_projection_digest(
                    self.catalog_projection,
                    self.reservation_projection,
                    self.pin_projection,
                    self.progress_projection,
                )
            || self.digest != checkpoint_digest(self)
        {
            return Err(CacheFormatError::InvalidCheckpoint);
        }
        Ok(())
    }
}

/// Encodes a checkpoint into the exact 328-byte V1 format.
///
/// # Errors
///
/// Returns [`CacheFormatError`] if the checkpoint is invalid.
pub fn encode_checkpoint(
    checkpoint: &CacheCheckpointV1,
) -> Result<[u8; CHECKPOINT_BYTES], CacheFormatError> {
    checkpoint.validate()?;
    let mut bytes = [0_u8; CHECKPOINT_BYTES];
    bytes[0..8].copy_from_slice(CHECKPOINT_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[16..24].copy_from_slice(&checkpoint.sequence.to_be_bytes());
    bytes[24..56].copy_from_slice(checkpoint.history_head.as_bytes());
    bytes[56..88].copy_from_slice(checkpoint.projection.as_bytes());
    bytes[88..120].copy_from_slice(checkpoint.catalog_projection.as_bytes());
    bytes[120..152].copy_from_slice(checkpoint.reservation_projection.as_bytes());
    bytes[152..184].copy_from_slice(checkpoint.pin_projection.as_bytes());
    bytes[184..216].copy_from_slice(checkpoint.progress_projection.as_bytes());
    let counts = [
        checkpoint.catalog_entries,
        checkpoint.reservations,
        checkpoint.pins,
        checkpoint.pending_effects,
        checkpoint.charged_bytes,
        checkpoint.lookup_entries,
    ];
    for (index, count) in counts.into_iter().enumerate() {
        let start = 216 + index * 8;
        bytes[start..start + 8].copy_from_slice(&count.to_be_bytes());
    }
    bytes[264..296].copy_from_slice(checkpoint.predecessor.as_bytes());
    bytes[296..328].copy_from_slice(checkpoint.digest.as_bytes());
    Ok(bytes)
}

/// Decodes and validates an exact checkpoint.
///
/// # Errors
///
/// Returns [`CacheFormatError`] for malformed framing, reserved bytes, or
/// checkpoint commitments.
pub fn decode_checkpoint(bytes: &[u8]) -> Result<CacheCheckpointV1, CacheFormatError> {
    if bytes.len() != CHECKPOINT_BYTES
        || &bytes[0..8] != CHECKPOINT_MAGIC
        || read_u16(bytes, 8)? != VERSION
        || bytes[10..16] != [0; 6]
    {
        return Err(CacheFormatError::Malformed);
    }
    let checkpoint = CacheCheckpointV1 {
        sequence: read_u64(bytes, 16)?,
        history_head: ObjectDigest::from_bytes(read_array(bytes, 24)?),
        projection: ObjectDigest::from_bytes(read_array(bytes, 56)?),
        catalog_projection: ObjectDigest::from_bytes(read_array(bytes, 88)?),
        reservation_projection: ObjectDigest::from_bytes(read_array(bytes, 120)?),
        pin_projection: ObjectDigest::from_bytes(read_array(bytes, 152)?),
        progress_projection: ObjectDigest::from_bytes(read_array(bytes, 184)?),
        catalog_entries: read_u64(bytes, 216)?,
        reservations: read_u64(bytes, 224)?,
        pins: read_u64(bytes, 232)?,
        pending_effects: read_u64(bytes, 240)?,
        charged_bytes: read_u64(bytes, 248)?,
        lookup_entries: read_u64(bytes, 256)?,
        predecessor: ObjectDigest::from_bytes(read_array(bytes, 264)?),
        digest: ObjectDigest::from_bytes(read_array(bytes, 296)?),
    };
    checkpoint.validate()?;
    Ok(checkpoint)
}

/// Commits compaction to one exact checkpoint and retained history root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheHistoryFloorV1 {
    /// Lowest event sequence required after compaction.
    pub first_retained_sequence: u64,
    /// Exact checkpoint establishing the compacted projection.
    pub checkpoint: ObjectDigest,
    /// Prior floor digest, zero only for the first floor.
    pub predecessor: ObjectDigest,
    /// Root of retained post-checkpoint history.
    pub retained_history_root: ObjectDigest,
    /// Digest of this exact floor.
    pub digest: ObjectDigest,
}

impl CacheHistoryFloorV1 {
    /// Constructs an exact checkpoint-anchored compaction floor.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::InvalidFloor`] for sentinel inputs.
    pub fn new(
        first_retained_sequence: u64,
        checkpoint: ObjectDigest,
        predecessor: ObjectDigest,
        retained_history_root: ObjectDigest,
    ) -> Result<Self, CacheFormatError> {
        let mut floor = Self {
            first_retained_sequence,
            checkpoint,
            predecessor,
            retained_history_root,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        floor.digest = floor_digest(&floor);
        floor.validate()?;
        Ok(floor)
    }

    /// Validates a closed history-floor commitment.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::InvalidFloor`] for zero or digest mismatch.
    pub fn validate(&self) -> Result<(), CacheFormatError> {
        if self.first_retained_sequence == 0
            || self.checkpoint.as_bytes() == &[0; 32]
            || self.retained_history_root.as_bytes() == &[0; 32]
            || self.digest != floor_digest(self)
        {
            return Err(CacheFormatError::InvalidFloor);
        }
        Ok(())
    }

    /// Advances the floor to a later exact checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::InvalidFloor`] unless the checkpoint moves
    /// the retained sequence forward and all derived commitments are valid.
    pub fn successor(&self, checkpoint: &CacheCheckpointV1) -> Result<Self, CacheFormatError> {
        self.validate()?;
        checkpoint.validate()?;
        let first_retained_sequence = checkpoint
            .sequence
            .checked_add(1)
            .ok_or(CacheFormatError::InvalidFloor)?;
        if first_retained_sequence <= self.first_retained_sequence {
            return Err(CacheFormatError::InvalidFloor);
        }
        Self::new(
            first_retained_sequence,
            checkpoint.digest,
            self.digest,
            checkpoint.history_head,
        )
    }
}

/// Encodes a history floor into the exact 152-byte V1 format.
///
/// # Errors
///
/// Returns [`CacheFormatError`] if the floor is invalid.
pub fn encode_floor(floor: &CacheHistoryFloorV1) -> Result<[u8; FLOOR_BYTES], CacheFormatError> {
    floor.validate()?;
    let mut bytes = [0_u8; FLOOR_BYTES];
    bytes[0..8].copy_from_slice(FLOOR_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[16..24].copy_from_slice(&floor.first_retained_sequence.to_be_bytes());
    bytes[24..56].copy_from_slice(floor.checkpoint.as_bytes());
    bytes[56..88].copy_from_slice(floor.predecessor.as_bytes());
    bytes[88..120].copy_from_slice(floor.retained_history_root.as_bytes());
    bytes[120..152].copy_from_slice(floor.digest.as_bytes());
    Ok(bytes)
}

/// Decodes and validates an exact history floor.
///
/// # Errors
///
/// Returns [`CacheFormatError`] for malformed framing or commitments.
pub fn decode_floor(bytes: &[u8]) -> Result<CacheHistoryFloorV1, CacheFormatError> {
    if bytes.len() != FLOOR_BYTES
        || &bytes[0..8] != FLOOR_MAGIC
        || read_u16(bytes, 8)? != VERSION
        || bytes[10..16] != [0; 6]
    {
        return Err(CacheFormatError::Malformed);
    }
    let floor = CacheHistoryFloorV1 {
        first_retained_sequence: read_u64(bytes, 16)?,
        checkpoint: ObjectDigest::from_bytes(read_array(bytes, 24)?),
        predecessor: ObjectDigest::from_bytes(read_array(bytes, 56)?),
        retained_history_root: ObjectDigest::from_bytes(read_array(bytes, 88)?),
        digest: ObjectDigest::from_bytes(read_array(bytes, 120)?),
    };
    floor.validate()?;
    Ok(floor)
}

/// Selects the closed idempotent cache operation method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum CacheMethodV1 {
    /// Reserves and admits immutable content.
    Admit = 1,
    /// Completes immutable catalog publication.
    Commit = 2,
    /// Acquires a correctness pin.
    AcquirePin = 3,
    /// Releases a correctness pin.
    ReleasePin = 4,
    /// Evicts one frozen candidate set.
    Evict = 5,
    /// Scrubs and possibly quarantines backing.
    Scrub = 6,
    /// Creates one independently authorized descriptor handoff.
    Handoff = 7,
}

impl CacheMethodV1 {
    fn from_code(code: u16) -> Result<Self, CacheFormatError> {
        match code {
            1 => Ok(Self::Admit),
            2 => Ok(Self::Commit),
            3 => Ok(Self::AcquirePin),
            4 => Ok(Self::ReleasePin),
            5 => Ok(Self::Evict),
            6 => Ok(Self::Scrub),
            7 => Ok(Self::Handoff),
            _ => Err(CacheFormatError::UnknownMethod),
        }
    }
}

/// Retains one principal/method/key request binding and accepted result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheIdempotencyBindingV1 {
    /// Authenticated principal scope.
    pub principal: PrincipalId,
    /// Closed cache method.
    pub method: CacheMethodV1,
    /// Caller-selected idempotency key.
    pub key: [u8; 16],
    /// Digest of the complete normalized request.
    pub request: ObjectDigest,
    /// Accepted operation identity.
    pub operation: OperationId,
    /// Digest of accepted current or terminal result.
    pub result: ObjectDigest,
    /// Whether the accepted operation reached a terminal result.
    pub terminal: bool,
    /// Monotone result generation.
    pub generation: u64,
    /// Prior binding digest, zero only at generation one.
    pub predecessor: ObjectDigest,
    /// Digest of this exact binding.
    pub digest: ObjectDigest,
}

/// Reports whether an accepted idempotent request was installed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheIdempotencyOutcomeV1 {
    /// The initial accepted result was installed.
    Accepted,
    /// The exact request already has a retained result.
    Replay(CacheIdempotencyBindingV1),
}

/// Binds a retained result replay to a fresh current disclosure decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedIdempotencyReplayV1 {
    binding: CacheIdempotencyBindingV1,
    current_authority: ObjectDigest,
    digest: ObjectDigest,
}

/// Fences a compacted terminal idempotency-key prefix against future reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheIdempotencyCompactionFloorV1 {
    scope: ([u8; 16], u16, [u8; 16]),
    partition: ObjectDigest,
    checkpoint: ObjectDigest,
    generation: u64,
    digest: ObjectDigest,
}

impl CacheIdempotencyCompactionFloorV1 {
    /// Returns the protected checkpoint anchoring the compacted prefix.
    #[must_use]
    pub const fn checkpoint(self) -> ObjectDigest {
        self.checkpoint
    }

    pub(crate) const fn scope(self) -> ([u8; 16], u16, [u8; 16]) {
        self.scope
    }
}

/// Encodes an idempotency compaction floor into its canonical fixed format.
///
/// # Errors
///
/// Returns [`CacheFormatError::InvalidFloor`] for an inconsistent floor.
pub fn encode_idempotency_floor(
    floor: CacheIdempotencyCompactionFloorV1,
) -> Result<[u8; IDEMPOTENCY_FLOOR_BYTES], CacheFormatError> {
    if floor.digest != idempotency_floor_digest(&floor) {
        return Err(CacheFormatError::InvalidFloor);
    }
    let mut bytes = [0_u8; IDEMPOTENCY_FLOOR_BYTES];
    bytes[0..8].copy_from_slice(b"AOSIFL01");
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[16..32].copy_from_slice(&floor.scope.0);
    bytes[32..34].copy_from_slice(&floor.scope.1.to_be_bytes());
    bytes[48..64].copy_from_slice(&floor.scope.2);
    bytes[64..96].copy_from_slice(floor.partition.as_bytes());
    bytes[96..128].copy_from_slice(floor.checkpoint.as_bytes());
    bytes[128..136].copy_from_slice(&floor.generation.to_be_bytes());
    bytes[136..168].copy_from_slice(floor.digest.as_bytes());
    Ok(bytes)
}

/// Recovers an idempotency floor under exact current protected authority.
///
/// # Errors
///
/// Returns [`CacheFormatError`] for malformed bytes, stale scope, or expiry.
pub fn decode_idempotency_floor(
    owner: &CacheAuthorityOwner<'_, '_>,
    capability: &VerifiedCacheCapabilityV1,
    partition: PhysicalPartitionId,
    bytes: &[u8],
    now: u64,
) -> Result<CacheIdempotencyCompactionFloorV1, CacheFormatError> {
    let floor = decode_idempotency_floor_persisted(partition, bytes)?;
    let scope = idempotency_compaction_scope(
        partition,
        floor.scope,
        floor.checkpoint,
        floor.generation,
        capability.scope().valid_until(),
    )?;
    owner
        .validate_for_effect_at(capability, CacheAuthorityPurposeV1::Replay, scope, now)
        .map_err(|_| CacheFormatError::InvalidFloor)?;
    Ok(floor)
}

pub(crate) fn decode_idempotency_floor_persisted(
    partition: PhysicalPartitionId,
    bytes: &[u8],
) -> Result<CacheIdempotencyCompactionFloorV1, CacheFormatError> {
    if bytes.len() != IDEMPOTENCY_FLOOR_BYTES
        || &bytes[0..8] != b"AOSIFL01"
        || read_u16(bytes, 8)? != VERSION
        || bytes[10..16] != [0; 6]
        || bytes[34..48] != [0; 14]
    {
        return Err(CacheFormatError::InvalidFloor);
    }
    let floor = CacheIdempotencyCompactionFloorV1 {
        scope: (
            read_array(bytes, 16)?,
            CacheMethodV1::from_code(read_u16(bytes, 32)?)? as u16,
            read_array(bytes, 48)?,
        ),
        partition: ObjectDigest::from_bytes(read_array(bytes, 64)?),
        checkpoint: ObjectDigest::from_bytes(read_array(bytes, 96)?),
        generation: read_u64(bytes, 128)?,
        digest: ObjectDigest::from_bytes(read_array(bytes, 136)?),
    };
    if floor.scope.0 == [0; 16]
        || floor.scope.2 == [0; 16]
        || floor.partition != partition.digest()
        || floor.checkpoint.as_bytes() == &[0; 32]
        || floor.digest != idempotency_floor_digest(&floor)
    {
        return Err(CacheFormatError::InvalidFloor);
    }
    Ok(floor)
}

impl AuthorizedIdempotencyReplayV1 {
    /// Returns the retained result whose disclosure was freshly authorized.
    #[must_use]
    pub const fn binding(self) -> CacheIdempotencyBindingV1 {
        self.binding
    }

    /// Returns the canonical authorized-replay commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Materializes bounded principal/method/idempotency-key bindings.
#[derive(Clone, Debug)]
pub struct CacheIdempotencyIndexV1 {
    maximum_bindings: usize,
    bindings: BTreeMap<([u8; 16], u16, [u8; 16]), CacheIdempotencyBindingV1>,
    compacted_through: Option<CacheIdempotencyCompactionFloorV1>,
}

impl CacheIdempotencyIndexV1 {
    /// Replays all retained generations into one exact latest-result index.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError`] for invalid limits, malformed bindings,
    /// broken predecessor chains, or bound exhaustion.
    pub fn replay(
        maximum_bindings: usize,
        compacted_through: Option<CacheIdempotencyCompactionFloorV1>,
        bindings: impl IntoIterator<Item = CacheIdempotencyBindingV1>,
    ) -> Result<Self, CacheFormatError> {
        if maximum_bindings == 0 || maximum_bindings > 1_000_000 {
            return Err(CacheFormatError::InvalidIdempotency);
        }
        let mut index = Self {
            maximum_bindings,
            bindings: BTreeMap::new(),
            compacted_through,
        };
        for binding in bindings {
            binding.validate()?;
            let scope = idempotency_scope(&binding);
            if index
                .compacted_through
                .is_some_and(|floor| scope <= floor.scope)
            {
                return Err(CacheFormatError::InvalidIdempotency);
            }
            if let Some(previous) = index.bindings.get(&scope) {
                if binding.generation
                    != previous
                        .generation
                        .checked_add(1)
                        .ok_or(CacheFormatError::InvalidIdempotency)?
                    || binding.predecessor != previous.digest
                    || binding.request != previous.request
                    || binding.operation != previous.operation
                    || previous.terminal
                {
                    return Err(CacheFormatError::InvalidIdempotency);
                }
            } else if binding.generation != 1
                || binding.predecessor.as_bytes() != &[0; 32]
                || index.bindings.len() >= maximum_bindings
            {
                return Err(CacheFormatError::InvalidIdempotency);
            }
            index.bindings.insert(scope, binding);
        }
        Ok(index)
    }

    /// Accepts an initial result or returns the exact retained replay.
    ///
    /// Reusing a scoped key with a different normalized request always fails.
    /// Validation/CAS failures before this call do not consume a key.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::IdempotencyConflict`] for request mismatch,
    /// or [`CacheFormatError::InvalidIdempotency`] for capacity/shape failure.
    pub fn accept(
        &mut self,
        binding: CacheIdempotencyBindingV1,
    ) -> Result<CacheIdempotencyOutcomeV1, CacheFormatError> {
        binding.validate()?;
        if binding.generation != 1 || binding.predecessor.as_bytes() != &[0; 32] {
            return Err(CacheFormatError::InvalidIdempotency);
        }
        let scope = idempotency_scope(&binding);
        if self
            .compacted_through
            .is_some_and(|floor| scope <= floor.scope)
        {
            return Err(CacheFormatError::IdempotencyConflict);
        }
        if let Some(existing) = self.bindings.get(&scope) {
            return if existing.request == binding.request {
                Ok(CacheIdempotencyOutcomeV1::Replay(*existing))
            } else {
                Err(CacheFormatError::IdempotencyConflict)
            };
        }
        if self.bindings.len() >= self.maximum_bindings {
            return Err(CacheFormatError::InvalidIdempotency);
        }
        self.bindings.insert(scope, binding);
        Ok(CacheIdempotencyOutcomeV1::Accepted)
    }

    /// Advances the nonterminal retained result for an exact scoped request.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError`] when the binding is absent, the request
    /// differs, or the retained result is already terminal.
    pub fn advance(
        &mut self,
        principal: PrincipalId,
        method: CacheMethodV1,
        key: [u8; 16],
        request: ObjectDigest,
        result: ObjectDigest,
        terminal: bool,
    ) -> Result<CacheIdempotencyBindingV1, CacheFormatError> {
        let scope = (*principal.as_bytes(), method as u16, key);
        let current = self
            .bindings
            .get(&scope)
            .ok_or(CacheFormatError::InvalidIdempotency)?;
        if current.request != request {
            return Err(CacheFormatError::IdempotencyConflict);
        }
        let successor = current.successor(result, terminal)?;
        self.bindings.insert(scope, successor);
        Ok(successor)
    }

    /// Resolves an exact replay only after a fresh current authority decision.
    ///
    /// The trusted caller supplies a nonzero digest of the current protected
    /// disclosure decision. This method never treats the historical decision
    /// that accepted the operation as present read authority.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError`] when the binding is absent, the normalized
    /// request differs, or current authority was not established.
    pub fn authorize_replay(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        principal: PrincipalId,
        method: CacheMethodV1,
        key: [u8; 16],
        request: ObjectDigest,
        valid_until: u64,
        now: u64,
    ) -> Result<AuthorizedIdempotencyReplayV1, CacheFormatError> {
        let binding = *self
            .bindings
            .get(&(*principal.as_bytes(), method as u16, key))
            .ok_or(CacheFormatError::InvalidIdempotency)?;
        if binding.request != request {
            return Err(CacheFormatError::IdempotencyConflict);
        }
        let scope = CacheAuthorityScopeV1::new(
            partition,
            replay_subject(&binding),
            Some(binding.operation),
            binding.request,
            partition.backing().root(),
            binding.generation,
            valid_until,
        )
        .map_err(|_| CacheFormatError::InvalidIdempotency)?;
        owner
            .validate_for_effect_at(capability, CacheAuthorityPurposeV1::Replay, scope, now)
            .map_err(|_| CacheFormatError::InvalidIdempotency)?;
        let current_authority = capability.record_digest();
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.cache.authorized-idempotency-replay.v1\0");
        hasher.update(binding.digest.as_bytes());
        hasher.update(current_authority.as_bytes());
        let digest = ObjectDigest::from_bytes(hasher.finalize().into());
        Ok(AuthorizedIdempotencyReplayV1 {
            binding,
            current_authority,
            digest,
        })
    }

    /// Compacts a terminal key prefix while retaining a non-reuse floor.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError`] for nonterminal records, a stale floor, or
    /// protected replay capability mismatch.
    pub fn compact_terminal_through(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        principal: PrincipalId,
        method: CacheMethodV1,
        key: [u8; 16],
        checkpoint: ObjectDigest,
        generation: u64,
        valid_until: u64,
        now: u64,
    ) -> Result<CacheIdempotencyCompactionFloorV1, CacheFormatError> {
        let floor_scope = (*principal.as_bytes(), method as u16, key);
        if principal.as_bytes() == &[0; 16]
            || key == [0; 16]
            || checkpoint.as_bytes() == &[0; 32]
            || self
                .compacted_through
                .is_some_and(|floor| floor_scope <= floor.scope)
            || self
                .bindings
                .range(..=floor_scope)
                .any(|(_, binding)| !binding.terminal)
        {
            return Err(CacheFormatError::InvalidIdempotency);
        }
        let authority_scope = idempotency_compaction_scope(
            partition,
            floor_scope,
            checkpoint,
            generation,
            valid_until,
        )?;
        owner
            .validate_for_effect_at(
                capability,
                CacheAuthorityPurposeV1::Replay,
                authority_scope,
                now,
            )
            .map_err(|_| CacheFormatError::InvalidIdempotency)?;
        self.bindings.retain(|scope, _| *scope > floor_scope);
        let floor = CacheIdempotencyCompactionFloorV1 {
            scope: floor_scope,
            partition: partition.digest(),
            checkpoint,
            generation,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        let floor = CacheIdempotencyCompactionFloorV1 {
            digest: idempotency_floor_digest(&floor),
            ..floor
        };
        self.compacted_through = Some(floor);
        Ok(floor)
    }
}

impl CacheIdempotencyBindingV1 {
    /// Constructs the first retained binding for an accepted cache request.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::InvalidIdempotency`] for sentinel inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn initial(
        principal: PrincipalId,
        method: CacheMethodV1,
        key: [u8; 16],
        request: ObjectDigest,
        operation: OperationId,
        result: ObjectDigest,
        terminal: bool,
    ) -> Result<Self, CacheFormatError> {
        let mut binding = Self {
            principal,
            method,
            key,
            request,
            operation,
            result,
            terminal,
            generation: 1,
            predecessor: ObjectDigest::from_bytes([0; 32]),
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        binding.digest = idempotency_digest(&binding);
        binding.validate()?;
        Ok(binding)
    }

    /// Advances the retained result without permitting request/key reuse.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::InvalidIdempotency`] after a terminal result
    /// or if the successor generation cannot be represented.
    pub fn successor(
        &self,
        result: ObjectDigest,
        terminal: bool,
    ) -> Result<Self, CacheFormatError> {
        if self.terminal || result.as_bytes() == &[0; 32] {
            return Err(CacheFormatError::InvalidIdempotency);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(CacheFormatError::InvalidIdempotency)?;
        let mut next = Self {
            principal: self.principal,
            method: self.method,
            key: self.key,
            request: self.request,
            operation: self.operation,
            result,
            terminal,
            generation,
            predecessor: self.digest,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        next.digest = idempotency_digest(&next);
        next.validate()?;
        Ok(next)
    }

    /// Validates exact idempotency scope and successor shape.
    ///
    /// # Errors
    ///
    /// Returns [`CacheFormatError::InvalidIdempotency`] for sentinel or digest
    /// inconsistencies.
    pub fn validate(&self) -> Result<(), CacheFormatError> {
        if self.principal.as_bytes() == &[0; 16]
            || self.key == [0; 16]
            || self.request.as_bytes() == &[0; 32]
            || self.operation.as_bytes() == &[0; 16]
            || self.result.as_bytes() == &[0; 32]
            || self.generation == 0
            || (self.generation == 1) != (self.predecessor.as_bytes() == &[0; 32])
            || self.digest != idempotency_digest(self)
        {
            return Err(CacheFormatError::InvalidIdempotency);
        }
        Ok(())
    }
}

/// Encodes an idempotency binding into the exact 200-byte V1 format.
///
/// # Errors
///
/// Returns [`CacheFormatError`] if the binding is invalid.
pub fn encode_idempotency(
    binding: &CacheIdempotencyBindingV1,
) -> Result<[u8; IDEMPOTENCY_BYTES], CacheFormatError> {
    binding.validate()?;
    let mut bytes = [0_u8; IDEMPOTENCY_BYTES];
    bytes[0..8].copy_from_slice(IDEMPOTENCY_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10..12].copy_from_slice(&(binding.method as u16).to_be_bytes());
    bytes[12] = u8::from(binding.terminal);
    bytes[16..32].copy_from_slice(binding.principal.as_bytes());
    bytes[32..48].copy_from_slice(&binding.key);
    bytes[48..80].copy_from_slice(binding.request.as_bytes());
    bytes[80..96].copy_from_slice(binding.operation.as_bytes());
    bytes[96..128].copy_from_slice(binding.result.as_bytes());
    bytes[128..136].copy_from_slice(&binding.generation.to_be_bytes());
    bytes[136..168].copy_from_slice(binding.predecessor.as_bytes());
    bytes[168..200].copy_from_slice(binding.digest.as_bytes());
    Ok(bytes)
}

/// Decodes and validates an exact idempotency binding.
///
/// # Errors
///
/// Returns [`CacheFormatError`] for malformed framing, unknown method, invalid
/// booleans, reserved bytes, or semantic/digest inconsistency.
pub fn decode_idempotency(bytes: &[u8]) -> Result<CacheIdempotencyBindingV1, CacheFormatError> {
    if bytes.len() != IDEMPOTENCY_BYTES
        || &bytes[0..8] != IDEMPOTENCY_MAGIC
        || read_u16(bytes, 8)? != VERSION
        || bytes[13..16] != [0; 3]
        || bytes[12] > 1
    {
        return Err(CacheFormatError::Malformed);
    }
    let binding = CacheIdempotencyBindingV1 {
        principal: PrincipalId::from_bytes(read_array(bytes, 16)?),
        method: CacheMethodV1::from_code(read_u16(bytes, 10)?)?,
        key: read_array(bytes, 32)?,
        request: ObjectDigest::from_bytes(read_array(bytes, 48)?),
        operation: OperationId::from_bytes(read_array(bytes, 80)?),
        result: ObjectDigest::from_bytes(read_array(bytes, 96)?),
        terminal: bytes[12] == 1,
        generation: read_u64(bytes, 128)?,
        predecessor: ObjectDigest::from_bytes(read_array(bytes, 136)?),
        digest: ObjectDigest::from_bytes(read_array(bytes, 168)?),
    };
    binding.validate()?;
    Ok(binding)
}

/// Reports canonical cache-format failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CacheFormatError {
    /// Framing, length, reserved bytes, or fixed fields are malformed.
    #[error("cache durable format is malformed")]
    Malformed,
    /// A record kind is outside the closed V1 registry.
    #[error("cache durable record kind is unknown")]
    UnknownKind,
    /// A method is outside the closed V1 registry.
    #[error("cache idempotency method is unknown")]
    UnknownMethod,
    /// Event semantics or digest are invalid.
    #[error("cache durable record is invalid")]
    InvalidRecord,
    /// Checkpoint semantics or digest are invalid.
    #[error("cache checkpoint is invalid")]
    InvalidCheckpoint,
    /// Floor semantics or digest are invalid.
    #[error("cache history floor is invalid")]
    InvalidFloor,
    /// Idempotency binding semantics or digest are invalid.
    #[error("cache idempotency binding is invalid")]
    InvalidIdempotency,
    /// A scoped idempotency key was reused with a different normalized request.
    #[error("cache idempotency key conflicts with retained request")]
    IdempotencyConflict,
}

fn durable_record_digest(record: &CacheDurableRecordV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update([record.kind as u8, record.state]);
    hasher.update(record.sequence.to_be_bytes());
    hasher.update(record.operation.as_bytes());
    hasher.update(record.subject.as_bytes());
    hasher.update(record.partition.as_bytes());
    hasher.update(record.plan.as_bytes());
    hasher.update(record.model.as_bytes());
    hasher.update(record.authority.as_bytes());
    hasher.update(record.evidence.as_bytes());
    hasher.update(record.catalog_projection.as_bytes());
    hasher.update(record.reservation_projection.as_bytes());
    hasher.update(record.pin_projection.as_bytes());
    hasher.update(record.progress_projection.as_bytes());
    hasher.update(record.payload.as_bytes());
    hasher.update(record.amount.to_be_bytes());
    hasher.update(record.generation.to_be_bytes());
    hasher.update(record.family_predecessor.as_bytes());
    hasher.update(record.predecessor.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Commits the four projections that must change as one durable transaction.
#[must_use]
pub fn atomic_projection_digest(
    catalog: ObjectDigest,
    reservation: ObjectDigest,
    pins: ObjectDigest,
    progress: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.atomic-projection.v1\0");
    hasher.update(catalog.as_bytes());
    hasher.update(reservation.as_bytes());
    hasher.update(pins.as_bytes());
    hasher.update(progress.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn valid_state(kind: CacheRecordKindV1, state: u8) -> bool {
    match kind {
        CacheRecordKindV1::Domain => (1..=3).contains(&state),
        CacheRecordKindV1::Quota => (1..=2).contains(&state),
        CacheRecordKindV1::Reservation => (1..=5).contains(&state),
        CacheRecordKindV1::Admission => (1..=13).contains(&state),
        CacheRecordKindV1::Catalog => (1..=4).contains(&state),
        CacheRecordKindV1::Pin => (1..=2).contains(&state),
        CacheRecordKindV1::EvictionPlan => state == 1,
        CacheRecordKindV1::EvictionProgress => (1..=8).contains(&state),
        CacheRecordKindV1::Scrub => (1..=3).contains(&state),
        CacheRecordKindV1::ReadHandoff => (1..=4).contains(&state),
        CacheRecordKindV1::LookupMemo => (1..=5).contains(&state),
        CacheRecordKindV1::Poison => state == 1,
        CacheRecordKindV1::Compaction => (1..=2).contains(&state),
    }
}

fn checkpoint_digest(checkpoint: &CacheCheckpointV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_DOMAIN);
    hasher.update(checkpoint.sequence.to_be_bytes());
    hasher.update(checkpoint.history_head.as_bytes());
    hasher.update(checkpoint.projection.as_bytes());
    hasher.update(checkpoint.catalog_projection.as_bytes());
    hasher.update(checkpoint.reservation_projection.as_bytes());
    hasher.update(checkpoint.pin_projection.as_bytes());
    hasher.update(checkpoint.progress_projection.as_bytes());
    hasher.update(checkpoint.catalog_entries.to_be_bytes());
    hasher.update(checkpoint.reservations.to_be_bytes());
    hasher.update(checkpoint.pins.to_be_bytes());
    hasher.update(checkpoint.pending_effects.to_be_bytes());
    hasher.update(checkpoint.charged_bytes.to_be_bytes());
    hasher.update(checkpoint.lookup_entries.to_be_bytes());
    hasher.update(checkpoint.predecessor.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn floor_digest(floor: &CacheHistoryFloorV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(FLOOR_DOMAIN);
    hasher.update(floor.first_retained_sequence.to_be_bytes());
    hasher.update(floor.checkpoint.as_bytes());
    hasher.update(floor.predecessor.as_bytes());
    hasher.update(floor.retained_history_root.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn idempotency_digest(binding: &CacheIdempotencyBindingV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(IDEMPOTENCY_DOMAIN);
    hasher.update(binding.principal.as_bytes());
    hasher.update((binding.method as u16).to_be_bytes());
    hasher.update(binding.key);
    hasher.update(binding.request.as_bytes());
    hasher.update(binding.operation.as_bytes());
    hasher.update(binding.result.as_bytes());
    hasher.update([u8::from(binding.terminal)]);
    hasher.update(binding.generation.to_be_bytes());
    hasher.update(binding.predecessor.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn idempotency_scope(binding: &CacheIdempotencyBindingV1) -> ([u8; 16], u16, [u8; 16]) {
    (
        *binding.principal.as_bytes(),
        binding.method as u16,
        binding.key,
    )
}

fn replay_subject(binding: &CacheIdempotencyBindingV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.idempotency-replay-subject.v1\0");
    hasher.update(binding.digest.as_bytes());
    hasher.update(binding.result.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn idempotency_compaction_scope(
    partition: PhysicalPartitionId,
    floor_scope: ([u8; 16], u16, [u8; 16]),
    checkpoint: ObjectDigest,
    generation: u64,
    valid_until: u64,
) -> Result<CacheAuthorityScopeV1, CacheFormatError> {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.idempotency-compaction-subject.v1\0");
    hasher.update(floor_scope.0);
    hasher.update(floor_scope.1.to_be_bytes());
    hasher.update(floor_scope.2);
    hasher.update(checkpoint.as_bytes());
    let subject = ObjectDigest::from_bytes(hasher.finalize().into());
    CacheAuthorityScopeV1::new(
        partition,
        subject,
        None,
        checkpoint,
        partition.backing().root(),
        generation,
        valid_until,
    )
    .map_err(|_| CacheFormatError::InvalidFloor)
}

fn idempotency_floor_digest(floor: &CacheIdempotencyCompactionFloorV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.idempotency-compaction-floor.v1\0");
    hasher.update(floor.scope.0);
    hasher.update(floor.scope.1.to_be_bytes());
    hasher.update(floor.scope.2);
    hasher.update(floor.partition.as_bytes());
    hasher.update(floor.checkpoint.as_bytes());
    hasher.update(floor.generation.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], CacheFormatError> {
    let end = offset.checked_add(N).ok_or(CacheFormatError::Malformed)?;
    let slice = bytes.get(offset..end).ok_or(CacheFormatError::Malformed)?;
    <[u8; N]>::try_from(slice).map_err(|_| CacheFormatError::Malformed)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, CacheFormatError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, CacheFormatError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}
