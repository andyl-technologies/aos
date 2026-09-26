//! Canonical reconstructing replay records for lifecycle auxiliary projections.
//!
//! ```text
//! AOSLIFA4 | version:2 | kind:1 | reserved:5 | project:16 | operation:16 |
//! operation-revision:8 | operation-record:32 | lineage:16 | revision:8 |
//! predecessor:32 | atomic-join:16 | floor:8 | replay-authority:32 |
//! declared-members:2 | declared-count:2 | reserved:4 | join-digest:32 |
//! payload-length:4 |
//! canonical-payload | digest:32
//! ```
//!
//! Replay reconstructs operation and auxiliary projections from the same
//! declared atomic unit. Opaque journal verification is required before any
//! decoded coordination or retention value can become a protected handle.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, ResourceId, Revision};
use sha2::{Digest as _, Sha256};

use super::auxiliary_payload::{
    LifecycleAuxiliaryPayloadLayoutV1, LifecycleAuxiliaryPayloadV1,
    MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES, decode_lifecycle_auxiliary_payload_with_layout_v1,
    encode_lifecycle_auxiliary_payload_v1,
};
use super::{
    LifecycleCancelIdempotencyIndexV1, LifecycleCancelOutcomeV1, LifecycleCancelRequestV1,
    LifecycleCancellationRecordV1, LifecycleHistoryV1, LifecycleModelError, LifecycleOperationV1,
    LifecycleProtectedRetentionLedgerV1, LifecycleRecordDigestV1, LifecycleReplayVerificationV1,
    LifecycleSemanticCommitFactV1, MAXIMUM_LIFECYCLE_EXPECTATIONS, encode_operation_record_v1,
};

const LEGACY_MAGIC: &[u8; 8] = b"AOSLIFA3";
const LEGACY_VERSION: u16 = 1;
const CURRENT_MAGIC: &[u8; 8] = b"AOSLIFA4";
const CURRENT_VERSION: u16 = 2;
const HEADER_BYTES: usize = 244;
const DIGEST_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleAuxiliaryEnvelopeFormatV1 {
    Legacy,
    Current,
}

impl LifecycleAuxiliaryEnvelopeFormatV1 {
    const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Legacy => LEGACY_MAGIC,
            Self::Current => CURRENT_MAGIC,
        }
    }

    const fn version(self) -> u16 {
        match self {
            Self::Legacy => LEGACY_VERSION,
            Self::Current => CURRENT_VERSION,
        }
    }

    const fn payload_layout(self) -> LifecycleAuxiliaryPayloadLayoutV1 {
        match self {
            Self::Legacy => LifecycleAuxiliaryPayloadLayoutV1::LegacyWithoutHostBoot,
            Self::Current => LifecycleAuxiliaryPayloadLayoutV1::Current,
        }
    }

    const fn digest_domain(self) -> &'static [u8] {
        match self {
            Self::Legacy => b"aos.sandbox.lifecycle.auxiliary-record.v2\0",
            Self::Current => b"aos.sandbox.lifecycle.auxiliary-record.v3\0",
        }
    }
}

/// Maximum auxiliary records retained by one replay window.
pub const MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS: usize = 262_144;
/// Maximum aggregate canonical bytes retained by one auxiliary replay window.
pub const MAXIMUM_LIFECYCLE_AUXILIARY_BYTES: usize = 512 * 1024 * 1024;

/// Selects one closed lifecycle auxiliary record family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleAuxiliaryKindV1 {
    /// Stores the operation snapshot committed by the atomic unit.
    Operation = 0,
    /// Stores coordination, writer-fence, dataset, and thaw state.
    Coordination = 1,
    /// Stores a complete retention-ledger revision.
    RetentionLedger = 2,
    /// Stores an exact suspended-runtime observation.
    SuspendObservation = 3,
    /// Stores an exact post-commit boot inventory.
    BootInventory = 4,
    /// Stores a stable cancel-versus-commit resolution.
    Cancellation = 5,
}

impl LifecycleAuxiliaryKindV1 {
    const fn member_bit(self) -> u16 {
        1_u16 << (self as u8)
    }
}

/// Commits the complete, closed member set of one lifecycle atomic unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleAtomicJoinDigestV1(ObjectDigest);

impl LifecycleAtomicJoinDigestV1 {
    /// Returns the underlying purpose-separated commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }

    fn from_stored(value: ObjectDigest) -> Result<Self, LifecycleModelError> {
        if value.as_bytes() == &[0; 32] {
            Err(LifecycleModelError::CorruptEncoding)
        } else {
            Ok(Self(value))
        }
    }
}

/// Binds one complete canonical payload to exact operation and lineage state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAuxiliaryRecordV1 {
    format: LifecycleAuxiliaryEnvelopeFormatV1,
    project: ProjectId,
    operation: OperationId,
    operation_revision: Revision,
    operation_record: LifecycleRecordDigestV1,
    lineage: ResourceId,
    revision: Revision,
    predecessor: Option<ObjectDigest>,
    payload: LifecycleAuxiliaryPayloadV1,
    encoded_payload: Vec<u8>,
    encoded_payload_length: u32,
    atomic_join: ResourceId,
    replay_floor: Option<Revision>,
    replay_authority: ObjectDigest,
    declared_members: u16,
    declared_count: u16,
    join_digest: Option<LifecycleAtomicJoinDigestV1>,
}

impl LifecycleAuxiliaryRecordV1 {
    /// Constructs one bounded reconstructing, non-authorizing auxiliary record.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel identities,
    /// payload identity mismatch, broken predecessor shape, or invalid floor.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn proposal(
        project: ProjectId,
        operation: OperationId,
        operation_revision: Revision,
        operation_record: LifecycleRecordDigestV1,
        lineage: ResourceId,
        revision: Revision,
        predecessor: Option<ObjectDigest>,
        payload: LifecycleAuxiliaryPayloadV1,
        atomic_join: ResourceId,
        replay_floor: Option<Revision>,
        verification: &LifecycleReplayVerificationV1,
    ) -> Result<Self, LifecycleModelError> {
        if project.as_bytes() == &[0; 16]
            || operation.as_bytes() == &[0; 16]
            || operation_revision.get() == 0
            || operation_revision.get() == u64::MAX
            || lineage.as_bytes() == &[0; 16]
            || revision.get() == 0
            || revision.get() == u64::MAX
            || (revision.get() == 1) != predecessor.is_none()
            || payload
                .operation()
                .is_some_and(|payload_operation| payload_operation != operation)
            || atomic_join.as_bytes() == &[0; 16]
            || replay_floor.is_some_and(|floor| floor.get() == 0 || floor.get() == u64::MAX)
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        let encoded_payload = encode_lifecycle_auxiliary_payload_v1(&payload)?;
        let encoded_payload_length =
            u32::try_from(encoded_payload.len()).map_err(|_| LifecycleModelError::InvalidModel)?;
        Ok(Self {
            format: LifecycleAuxiliaryEnvelopeFormatV1::Current,
            project,
            operation,
            operation_revision,
            operation_record,
            lineage,
            revision,
            predecessor,
            payload,
            encoded_payload,
            encoded_payload_length,
            atomic_join,
            replay_floor,
            replay_authority: verification.authority,
            declared_members: 0,
            declared_count: 0,
            join_digest: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn from_stored(
        project: ProjectId,
        operation: OperationId,
        operation_revision: Revision,
        operation_record: LifecycleRecordDigestV1,
        lineage: ResourceId,
        revision: Revision,
        predecessor: Option<ObjectDigest>,
        payload: LifecycleAuxiliaryPayloadV1,
        atomic_join: ResourceId,
        replay_floor: Option<Revision>,
        verification: &LifecycleReplayVerificationV1,
        declared_members: u16,
        declared_count: u16,
        join_digest: LifecycleAtomicJoinDigestV1,
        format: LifecycleAuxiliaryEnvelopeFormatV1,
        encoded_payload: &[u8],
    ) -> Result<Self, LifecycleModelError> {
        let mut record = Self::proposal(
            project,
            operation,
            operation_revision,
            operation_record,
            lineage,
            revision,
            predecessor,
            payload,
            atomic_join,
            replay_floor,
            verification,
        )?;
        if declared_count == 0
            || usize::from(declared_count) > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || declared_count != declared_members.count_ones() as u16
            || declared_members & LifecycleAuxiliaryKindV1::Operation.member_bit() == 0
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        record.declared_members = declared_members;
        record.declared_count = declared_count;
        record.join_digest = Some(join_digest);
        record.format = format;
        record.encoded_payload = encoded_payload.to_vec();
        record.encoded_payload_length =
            u32::try_from(encoded_payload.len()).map_err(|_| LifecycleModelError::InvalidModel)?;
        Ok(record)
    }

    /// Returns the closed record family.
    #[must_use]
    pub const fn kind(&self) -> LifecycleAuxiliaryKindV1 {
        self.payload.kind()
    }

    /// Returns the owning project.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the joined operation.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the joined operation revision.
    #[must_use]
    pub const fn operation_revision(&self) -> Revision {
        self.operation_revision
    }

    /// Returns the joined operation-record commitment.
    #[must_use]
    pub const fn operation_record(&self) -> LifecycleRecordDigestV1 {
        self.operation_record
    }

    /// Returns the family-local lineage identity.
    #[must_use]
    pub const fn lineage(&self) -> ResourceId {
        self.lineage
    }

    /// Returns the family-local revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the predecessor record commitment.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ObjectDigest> {
        self.predecessor
    }

    /// Borrows the complete reconstructing family payload.
    #[must_use]
    pub const fn payload(&self) -> &LifecycleAuxiliaryPayloadV1 {
        &self.payload
    }

    /// Returns the atomic cross-projection join identity.
    #[must_use]
    pub const fn atomic_join(&self) -> ResourceId {
        self.atomic_join
    }

    /// Returns the replay floor.
    #[must_use]
    pub const fn replay_floor(&self) -> Option<Revision> {
        self.replay_floor
    }

    /// Returns the verifier authority that admitted this record.
    #[must_use]
    pub const fn replay_authority(&self) -> ObjectDigest {
        self.replay_authority
    }

    /// Returns the closed member-family bitmap declared by this join.
    #[must_use]
    pub const fn declared_members(&self) -> u16 {
        self.declared_members
    }

    /// Returns the exact declared member count.
    #[must_use]
    pub const fn declared_count(&self) -> u16 {
        self.declared_count
    }

    /// Returns the complete atomic-unit commitment after binding.
    #[must_use]
    pub const fn join_digest(&self) -> Option<LifecycleAtomicJoinDigestV1> {
        self.join_digest
    }

    /// Returns the canonical envelope commitment.
    #[must_use]
    pub fn complete_digest(&self) -> ObjectDigest {
        auxiliary_record_digest(self)
    }
}

/// Encodes one validated reconstructing auxiliary record.
///
/// # Errors
///
/// Returns [`LifecycleModelError`] for an exceeded ceiling or allocation failure.
pub fn encode_lifecycle_auxiliary_record_v1(
    record: &LifecycleAuxiliaryRecordV1,
) -> Result<Vec<u8>, LifecycleModelError> {
    if record.join_digest.is_none() {
        return Err(LifecycleModelError::InvalidModel);
    }
    let body_length = HEADER_BYTES
        .checked_add(record.encoded_payload.len())
        .ok_or(LifecycleModelError::InvalidModel)?;
    let length = body_length
        .checked_add(DIGEST_BYTES)
        .filter(|value| {
            *value <= HEADER_BYTES + MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES + DIGEST_BYTES
        })
        .ok_or(LifecycleModelError::InvalidModel)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| LifecycleModelError::Allocation)?;
    append_body(&mut encoded, record);
    if encoded.len() != body_length {
        return Err(LifecycleModelError::InvalidModel);
    }
    let digest = auxiliary_digest(&encoded, record.format);
    encoded.extend_from_slice(digest.as_bytes());
    Ok(encoded)
}

/// Decodes one exact reconstructing auxiliary record.
///
/// # Errors
///
/// Returns [`LifecycleModelError::CorruptEncoding`] for malformed canonical bytes.
pub fn decode_lifecycle_auxiliary_record_v1(
    encoded: &[u8],
    verification: &LifecycleReplayVerificationV1,
) -> Result<LifecycleAuxiliaryRecordV1, LifecycleModelError> {
    decode_lifecycle_auxiliary_record_inner_v1(encoded, verification, true)
}

/// Decodes bytes already authenticated by the protected outer journal.
///
/// The outer envelope supplies admission for a newly proposed inner record,
/// so this path verifies every canonical field and the fixed replay authority
/// without requiring the inner digest to pre-exist in the recovered allowlist.
pub(crate) fn decode_lifecycle_auxiliary_record_from_protected_envelope_v1(
    encoded: &[u8],
    verification: &LifecycleReplayVerificationV1,
) -> Result<LifecycleAuxiliaryRecordV1, LifecycleModelError> {
    decode_lifecycle_auxiliary_record_inner_v1(encoded, verification, false)
}

fn decode_lifecycle_auxiliary_record_inner_v1(
    encoded: &[u8],
    verification: &LifecycleReplayVerificationV1,
    require_previously_accepted_digest: bool,
) -> Result<LifecycleAuxiliaryRecordV1, LifecycleModelError> {
    if encoded.len() < HEADER_BYTES + 1 + DIGEST_BYTES
        || encoded.len() > HEADER_BYTES + MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES + DIGEST_BYTES
    {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let (body, stored) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    let format = envelope_format(body)?;
    let digest = auxiliary_digest(body, format);
    if stored != digest.as_bytes()
        || (require_previously_accepted_digest && !verification.accepts_record(digest))
    {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let mut bytes = body;
    if take::<8>(&mut bytes)? != *format.magic()
        || u16::from_be_bytes(take(&mut bytes)?) != format.version()
    {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let kind = decode_kind(take::<1>(&mut bytes)?[0])?;
    if take::<5>(&mut bytes)? != [0; 5] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let project = ProjectId::from_bytes(take(&mut bytes)?);
    let operation = OperationId::from_bytes(take(&mut bytes)?);
    let operation_revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let operation_record =
        LifecycleRecordDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?;
    let lineage = ResourceId::from_bytes(take(&mut bytes)?);
    let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let predecessor = optional_digest(take(&mut bytes)?);
    let atomic_join = ResourceId::from_bytes(take(&mut bytes)?);
    let floor = u64::from_be_bytes(take(&mut bytes)?);
    let replay_authority = ObjectDigest::from_bytes(take(&mut bytes)?);
    if replay_authority != verification.authority {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let declared_members = u16::from_be_bytes(take(&mut bytes)?);
    let declared_count = u16::from_be_bytes(take(&mut bytes)?);
    if take::<4>(&mut bytes)? != [0; 4] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let join_digest =
        LifecycleAtomicJoinDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?;
    let payload_length = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
        .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    if payload_length == 0 || payload_length > MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let payload_bytes = take_slice(&mut bytes, payload_length)?;
    if !bytes.is_empty() {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let payload = decode_lifecycle_auxiliary_payload_with_layout_v1(
        kind,
        payload_bytes,
        format.payload_layout(),
    )?;
    let record = LifecycleAuxiliaryRecordV1::from_stored(
        project,
        operation,
        operation_revision,
        operation_record,
        lineage,
        revision,
        predecessor,
        payload,
        atomic_join,
        (floor != 0).then_some(Revision::new(floor)),
        verification,
        declared_members,
        declared_count,
        join_digest,
        format,
        payload_bytes,
    )
    .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    Ok(record)
}

/// Derives the commitment to one complete, sorted lifecycle atomic unit.
///
/// # Errors
///
/// Returns [`LifecycleModelError::InvalidTransition`] unless the records have
/// one identity/fence, unique families, an operation member, and an exact
/// declared closed set.
pub fn lifecycle_atomic_join_digest_v1(
    records: &[LifecycleAuxiliaryRecordV1],
) -> Result<LifecycleAtomicJoinDigestV1, LifecycleModelError> {
    let first = records
        .first()
        .ok_or(LifecycleModelError::InvalidTransition)?;
    if records.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS {
        return Err(LifecycleModelError::InvalidTransition);
    }
    let mut members = 0_u16;
    let mut previous_kind = None;
    let mut hasher = Sha256::new();
    match first.format {
        LifecycleAuxiliaryEnvelopeFormatV1::Legacy => {
            hasher.update(b"aos.sandbox.lifecycle.atomic-join.v1\0");
        }
        LifecycleAuxiliaryEnvelopeFormatV1::Current => {
            hasher.update(b"aos.sandbox.lifecycle.atomic-join.v2\0");
            hasher.update(first.format.magic());
            hasher.update(first.format.version().to_be_bytes());
        }
    }
    hasher = hasher
        .chain_update(first.project.as_bytes())
        .chain_update(first.atomic_join.as_bytes())
        .chain_update(first.operation.as_bytes())
        .chain_update(first.operation_revision.get().to_be_bytes())
        .chain_update(first.operation_record.digest().as_bytes())
        .chain_update(first.replay_authority.as_bytes());
    for record in records {
        if record.project != first.project
            || record.format != first.format
            || record.atomic_join != first.atomic_join
            || record.operation != first.operation
            || record.operation_revision != first.operation_revision
            || record.operation_record != first.operation_record
            || record.replay_authority != first.replay_authority
            || previous_kind.is_some_and(|previous| previous >= record.kind())
        {
            return Err(LifecycleModelError::InvalidTransition);
        }
        let bit = record.kind().member_bit();
        if members & bit != 0 {
            return Err(LifecycleModelError::InvalidTransition);
        }
        members |= bit;
        previous_kind = Some(record.kind());
        hasher = hasher
            .chain_update([record.kind() as u8])
            .chain_update(record.lineage.as_bytes())
            .chain_update(record.revision.get().to_be_bytes())
            .chain_update(
                record
                    .predecessor
                    .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                    .as_bytes(),
            )
            .chain_update(u64::from(record.encoded_payload_length).to_be_bytes())
            .chain_update(&record.encoded_payload);
    }
    if members & LifecycleAuxiliaryKindV1::Operation.member_bit() == 0 {
        return Err(LifecycleModelError::InvalidTransition);
    }
    let member_count =
        u16::try_from(records.len()).map_err(|_| LifecycleModelError::InvalidTransition)?;
    hasher = hasher
        .chain_update(members.to_be_bytes())
        .chain_update(member_count.to_be_bytes());
    Ok(LifecycleAtomicJoinDigestV1(ObjectDigest::from_bytes(
        hasher.finalize().into(),
    )))
}

/// Binds proposals into one immutable closed atomic member set.
///
/// The proposals are sorted by their closed family. After binding, adding a
/// member changes both the declared bitmap and digest and is therefore rejected.
///
/// # Errors
///
/// Returns [`LifecycleModelError::InvalidTransition`] for inconsistent,
/// duplicate, over-capacity, or operation-less proposals.
pub fn bind_lifecycle_atomic_join_v1(
    mut records: Vec<LifecycleAuxiliaryRecordV1>,
) -> Result<Vec<LifecycleAuxiliaryRecordV1>, LifecycleModelError> {
    records.sort_unstable_by_key(LifecycleAuxiliaryRecordV1::kind);
    if records.iter().any(|record| record.join_digest.is_some()) {
        return Err(LifecycleModelError::InvalidTransition);
    }
    let digest = lifecycle_atomic_join_digest_v1(&records)?;
    let members = records
        .iter()
        .fold(0_u16, |value, record| value | record.kind().member_bit());
    let count = u16::try_from(records.len()).map_err(|_| LifecycleModelError::InvalidTransition)?;
    for record in &mut records {
        record.declared_members = members;
        record.declared_count = count;
        record.join_digest = Some(digest);
    }
    Ok(records)
}

/// Replays bounded auxiliary lineages with exact operation joins.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LifecycleAuxiliaryHistoryV1 {
    pub(super) latest:
        BTreeMap<(ProjectId, ResourceId, LifecycleAuxiliaryKindV1), LifecycleAuxiliaryRecordV1>,
    pub(super) records: BTreeMap<
        (ProjectId, ResourceId, LifecycleAuxiliaryKindV1, Revision),
        LifecycleAuxiliaryRecordV1,
    >,
    pub(super) joins: BTreeMap<(ProjectId, ResourceId), LifecycleAtomicJoinDigestV1>,
    pub(super) order: Vec<(ProjectId, ResourceId, LifecycleAuxiliaryKindV1, Revision)>,
    pub(super) operations: LifecycleHistoryV1,
    pub(super) replay_authority: Option<ObjectDigest>,
    pub(super) replay_floor: Option<Revision>,
    pub(super) retained_bytes: usize,
}

/// Stores a digest-checked materialized auxiliary replay floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAuxiliaryCheckpointV1 {
    pub(super) history: LifecycleAuxiliaryHistoryV1,
    pub(super) digest: ObjectDigest,
    pub(super) accepted_record: Option<ObjectDigest>,
}

/// Returns either the original cancellation result or one closed append unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleCancellationAdmissionV1 {
    /// The exact idempotency key already resolved to this stable outcome.
    Existing(LifecycleCancelOutcomeV1),
    /// These records form the complete atomic unit that must be appended.
    Append(Vec<LifecycleAuxiliaryRecordV1>),
}

impl LifecycleAuxiliaryHistoryV1 {
    /// Creates an empty projection under an already verifier-issued authority.
    #[must_use]
    pub fn under_verification(verification: &LifecycleReplayVerificationV1) -> Self {
        Self {
            replay_authority: Some(verification.authority),
            ..Self::default()
        }
    }

    /// Replays a bounded canonical stream under verifier-issued journal trust.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError`] for malformed, forked, over-capacity,
    /// orphaned, or cross-projection-inconsistent records.
    pub fn replay<'a>(
        records: impl IntoIterator<Item = &'a [u8]>,
        verification: &LifecycleReplayVerificationV1,
    ) -> Result<Self, LifecycleModelError> {
        let mut history = Self::under_verification(verification);
        history.replay_suffix(records, verification)?;
        Ok(history)
    }

    /// Replays a suffix after a digest-checked materialized floor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError`] for a changed checkpoint or invalid suffix.
    pub fn replay_after<'a>(
        checkpoint: &LifecycleAuxiliaryCheckpointV1,
        records: impl IntoIterator<Item = &'a [u8]>,
        verification: &LifecycleReplayVerificationV1,
    ) -> Result<Self, LifecycleModelError> {
        if checkpoint.digest != checkpoint.history.complete_digest()?
            || checkpoint.history.replay_authority != Some(verification.authority)
            || checkpoint
                .accepted_record
                .is_none_or(|digest| !verification.accepts_checkpoint(digest))
        {
            return Err(LifecycleModelError::InvalidTransition);
        }
        let mut history = checkpoint.history.clone();
        history.replay_suffix(records, verification)?;
        Ok(history)
    }

    /// Admits cancellation as one closed operation-plus-resolution append unit.
    ///
    /// The method reads the exact replayed operation fence, resolves the race,
    /// and binds the resulting operation snapshot and cancellation index update
    /// to one immutable atomic join. It performs no append or compensation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidTransition`] for an unknown or
    /// stale operation, ambiguous active effect, conflicting idempotency key,
    /// reused lineage, verifier mismatch, or unrepresentable successor.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_cancellation(
        &self,
        request: LifecycleCancelRequestV1,
        operation_lineage: ResourceId,
        cancellation_lineage: ResourceId,
        atomic_join: ResourceId,
        verification: &LifecycleReplayVerificationV1,
    ) -> Result<LifecycleCancellationAdmissionV1, LifecycleModelError> {
        if self.replay_authority != Some(verification.authority) {
            return Err(LifecycleModelError::InvalidTransition);
        }
        if let Some(outcome) = self.operations.cancellations().lookup(request) {
            return if outcome == LifecycleCancelOutcomeV1::Conflict {
                Err(LifecycleModelError::InvalidTransition)
            } else {
                Ok(LifecycleCancellationAdmissionV1::Existing(outcome))
            };
        }
        let (current, current_record) = self
            .operations
            .operation_record(request.operation_id())
            .ok_or(LifecycleModelError::InvalidTransition)?;
        let mut cancellations = self.operations.cancellations().clone();
        let outcome = cancellations.resolve(request, current, current_record);
        if outcome == LifecycleCancelOutcomeV1::Conflict {
            return Err(LifecycleModelError::InvalidTransition);
        }
        let operation = match &outcome {
            LifecycleCancelOutcomeV1::CanceledBeforeCommit(successor) => successor.clone(),
            LifecycleCancelOutcomeV1::AlreadyCommitted(_)
            | LifecycleCancelOutcomeV1::AlreadyTerminal(_) => current.clone(),
            LifecycleCancelOutcomeV1::Conflict => {
                return Err(LifecycleModelError::InvalidTransition);
            }
        };
        let cancellation = LifecycleCancellationRecordV1::new(request, operation.clone(), outcome)
            .map_err(|_| LifecycleModelError::InvalidTransition)?;
        let operation_record =
            super::format::record_digest(&encode_operation_record_v1(&operation)?)?;
        let operation_key = (
            request.project(),
            operation_lineage,
            LifecycleAuxiliaryKindV1::Operation,
        );
        let previous_operation = self
            .latest
            .get(&operation_key)
            .ok_or(LifecycleModelError::InvalidTransition)?;
        if previous_operation.operation != request.operation_id()
            || previous_operation.operation_revision != current.record_revision()
            || previous_operation.operation_record != current_record
            || !matches!(
                previous_operation.payload(),
                LifecycleAuxiliaryPayloadV1::Operation(previous) if previous == current
            )
            || self.latest.contains_key(&(
                request.project(),
                cancellation_lineage,
                LifecycleAuxiliaryKindV1::Cancellation,
            ))
        {
            return Err(LifecycleModelError::InvalidTransition);
        }
        let operation_revision = previous_operation
            .revision
            .checked_next()
            .map_err(|_| LifecycleModelError::InvalidTransition)?;
        let operation_member = LifecycleAuxiliaryRecordV1::proposal(
            request.project(),
            request.operation_id(),
            operation.record_revision(),
            operation_record,
            operation_lineage,
            operation_revision,
            Some(previous_operation.complete_digest()),
            LifecycleAuxiliaryPayloadV1::Operation(operation),
            atomic_join,
            self.replay_floor,
            verification,
        )?;
        let cancellation_member = LifecycleAuxiliaryRecordV1::proposal(
            request.project(),
            request.operation_id(),
            cancellation.operation().record_revision(),
            operation_record,
            cancellation_lineage,
            Revision::new(1),
            None,
            LifecycleAuxiliaryPayloadV1::Cancellation(cancellation),
            atomic_join,
            self.replay_floor,
            verification,
        )?;
        bind_lifecycle_atomic_join_v1(vec![operation_member, cancellation_member])
            .map(LifecycleCancellationAdmissionV1::Append)
    }

    fn replay_suffix<'a>(
        &mut self,
        records: impl IntoIterator<Item = &'a [u8]>,
        verification: &LifecycleReplayVerificationV1,
    ) -> Result<(), LifecycleModelError> {
        let mut join = Vec::new();
        let mut join_identity = None;
        for encoded in records {
            if encoded.len() > MAXIMUM_LIFECYCLE_AUXILIARY_BYTES {
                return Err(LifecycleModelError::InvalidTransition);
            }
            let record = decode_lifecycle_auxiliary_record_v1(encoded, verification)?;
            let identity = (record.project, record.atomic_join);
            if join_identity.is_some_and(|current| current != identity) {
                self.apply_atomic_join(&join)?;
                join.clear();
            }
            if join.len() >= MAXIMUM_LIFECYCLE_EXPECTATIONS {
                return Err(LifecycleModelError::InvalidTransition);
            }
            join.try_reserve(1)
                .map_err(|_| LifecycleModelError::Allocation)?;
            join_identity = Some(identity);
            join.push(record);
        }
        if !join.is_empty() {
            self.apply_atomic_join(&join)?;
        }
        Ok(())
    }

    /// Applies one complete atomic auxiliary join against exact operation state.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidTransition`] unless all members
    /// share one project, join ID, and operation witness and collectively
    /// satisfy every authoritative semantic reference of that operation.
    pub fn apply_atomic_join(
        &mut self,
        records: &[LifecycleAuxiliaryRecordV1],
    ) -> Result<(), LifecycleModelError> {
        let first = records
            .first()
            .ok_or(LifecycleModelError::InvalidTransition)?;
        let digest = lifecycle_atomic_join_digest_v1(records)?;
        let members = records
            .iter()
            .fold(0_u16, |value, record| value | record.kind().member_bit());
        if records.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || records.iter().any(|record| {
                record.project != first.project
                    || record.atomic_join != first.atomic_join
                    || record.operation != first.operation
                    || record.operation_revision != first.operation_revision
                    || record.operation_record != first.operation_record
                    || record.replay_authority != first.replay_authority
                    || record.replay_floor != first.replay_floor
                    || record.declared_members != members
                    || usize::from(record.declared_count) != records.len()
                    || record.join_digest != Some(digest)
            })
            || self.replay_authority != Some(first.replay_authority)
            || self.joins.contains_key(&(first.project, first.atomic_join))
        {
            return Err(LifecycleModelError::InvalidTransition);
        }
        let mut next = self.clone();
        next.synchronize_floor(first.replay_floor)?;
        for record in records {
            next.retained_bytes = next
                .retained_bytes
                .checked_add(encode_lifecycle_auxiliary_record_v1(record)?.len())
                .filter(|value| *value <= MAXIMUM_LIFECYCLE_AUXILIARY_BYTES)
                .ok_or(LifecycleModelError::InvalidTransition)?;
            next.apply(record.clone())?;
        }
        let operation = next
            .operations
            .operation(first.operation)
            .cloned()
            .ok_or(LifecycleModelError::InvalidTransition)?;
        self.validate_atomic_method_members(records, &operation)?;
        next.authoritative_semantic_commit(&operation)?;
        next.validate_materialized_method_join(&operation)?;
        next.validate_terminal_auxiliaries(&operation)?;
        next.joins
            .insert((first.project, first.atomic_join), digest);
        *self = next;
        Ok(())
    }

    fn validate_atomic_method_members(
        &self,
        records: &[LifecycleAuxiliaryRecordV1],
        operation: &LifecycleOperationV1,
    ) -> Result<(), LifecycleModelError> {
        let Some(commit) = operation.method_semantic_commit() else {
            return Ok(());
        };
        if self
            .operations
            .operation(operation.operation_id())
            .and_then(LifecycleOperationV1::method_semantic_commit)
            == Some(commit)
        {
            return Ok(());
        }
        let LifecycleSemanticCommitFactV1::DeleteSnapshot {
            tombstone,
            retention_release,
            ..
        } = commit.facts()
        else {
            return Ok(());
        };
        if tombstone.digest().as_bytes() == &[0; 32] {
            return Err(LifecycleModelError::InvalidTransition);
        }
        let successor = records.iter().find_map(|record| {
            let LifecycleAuxiliaryPayloadV1::RetentionLedger(ledger) = record.payload() else {
                return None;
            };
            (ledger.revision() == retention_release.successor_revision())
                .then_some((record, ledger))
        });
        let Some((successor_record, successor_ledger)) = successor else {
            return Err(LifecycleModelError::InvalidTransition);
        };
        let predecessor = self.records.values().find_map(|record| {
            let LifecycleAuxiliaryPayloadV1::RetentionLedger(ledger) = record.payload() else {
                return None;
            };
            (record.project == operation.project()
                && record.lineage == successor_record.lineage
                && ledger.revision() == retention_release.predecessor_revision())
            .then_some(ledger)
        });
        let Some(predecessor_ledger) = predecessor else {
            return Err(LifecycleModelError::InvalidTransition);
        };
        let predecessor =
            LifecycleProtectedRetentionLedgerV1::from_authoritative(predecessor_ledger.clone());
        let successor =
            LifecycleProtectedRetentionLedgerV1::from_authoritative(successor_ledger.clone());
        let derived = super::LifecycleSnapshotRetentionReleaseV1::from_protected_ledgers(
            retention_release.snapshot(),
            retention_release.holder(),
            &predecessor,
            &successor,
        )
        .map_err(|_| LifecycleModelError::InvalidTransition)?;
        if derived != *retention_release {
            return Err(LifecycleModelError::InvalidTransition);
        }
        Ok(())
    }

    fn synchronize_floor(&mut self, floor: Option<Revision>) -> Result<(), LifecycleModelError> {
        if floor == self.replay_floor {
            return Ok(());
        }
        let floor = floor.ok_or(LifecycleModelError::InvalidTransition)?;
        if self.replay_floor.is_some_and(|current| floor <= current) {
            return Err(LifecycleModelError::InvalidTransition);
        }
        self.replay_floor = Some(floor);
        let mut retained_joins = Vec::new();
        retained_joins
            .try_reserve_exact(
                self.latest
                    .len()
                    .checked_add(self.records.len())
                    .ok_or(LifecycleModelError::InvalidTransition)?,
            )
            .map_err(|_| LifecycleModelError::Allocation)?;
        retained_joins.extend(
            self.latest
                .values()
                .map(|record| (record.project, record.atomic_join)),
        );
        retained_joins.extend(
            self.records
                .values()
                .filter(|record| self.record_is_materialization_required(record))
                .map(|record| (record.project, record.atomic_join)),
        );
        retained_joins.sort_unstable();
        retained_joins.dedup();
        self.records.retain(|_, record| {
            retained_joins
                .binary_search(&(record.project, record.atomic_join))
                .is_ok()
        });
        self.joins
            .retain(|join, _| retained_joins.binary_search(join).is_ok());
        self.order.retain(|key| self.records.contains_key(key));
        self.retained_bytes = self
            .records
            .values()
            .try_fold(0_usize, |total, record| {
                total.checked_add(encode_lifecycle_auxiliary_record_v1(record).ok()?.len())
            })
            .filter(|value| *value <= MAXIMUM_LIFECYCLE_AUXILIARY_BYTES)
            .ok_or(LifecycleModelError::InvalidTransition)?;
        self.operations
            .compact_materialization()
            .map_err(|_| LifecycleModelError::InvalidTransition)?;
        Ok(())
    }

    pub(super) fn from_checkpoint_records(
        records: Vec<LifecycleAuxiliaryRecordV1>,
        verification: &LifecycleReplayVerificationV1,
    ) -> Result<Self, LifecycleModelError> {
        let mut history = Self::under_verification(verification);
        let mut operation_records = BTreeMap::new();
        let mut latest_operations = BTreeMap::new();
        let mut cancellations = Vec::new();
        cancellations
            .try_reserve_exact(records.len())
            .map_err(|_| LifecycleModelError::Allocation)?;
        let mut offset = 0_usize;

        while offset < records.len() {
            let first = &records[offset];
            let join_identity = (first.project, first.atomic_join);
            let end = records[offset..]
                .iter()
                .position(|record| (record.project, record.atomic_join) != join_identity)
                .map_or(records.len(), |relative| offset + relative);
            let members = &records[offset..end];
            let digest = lifecycle_atomic_join_digest_v1(members)?;
            let member_bits = members
                .iter()
                .fold(0_u16, |bits, record| bits | record.kind().member_bit());
            if history.joins.contains_key(&join_identity)
                || members.iter().any(|record| {
                    record.replay_authority != verification.authority
                        || record.replay_floor != first.replay_floor
                        || record.operation != first.operation
                        || record.operation_revision != first.operation_revision
                        || record.operation_record != first.operation_record
                        || record.declared_members != member_bits
                        || usize::from(record.declared_count) != members.len()
                        || record.join_digest != Some(digest)
                })
            {
                return Err(LifecycleModelError::InvalidTransition);
            }
            history.joins.insert(join_identity, digest);
            offset = end;
        }

        for record in records {
            if let Some(floor) = record.replay_floor {
                if history.replay_floor.is_some_and(|current| floor < current) {
                    return Err(LifecycleModelError::InvalidTransition);
                }
                history.replay_floor = Some(floor);
            }
            history.retained_bytes = history
                .retained_bytes
                .checked_add(encode_lifecycle_auxiliary_record_v1(&record)?.len())
                .filter(|value| *value <= MAXIMUM_LIFECYCLE_AUXILIARY_BYTES)
                .ok_or(LifecycleModelError::InvalidTransition)?;
            let record_key = (
                record.project,
                record.lineage,
                record.kind(),
                record.revision,
            );
            if history.records.insert(record_key, record.clone()).is_some() {
                return Err(LifecycleModelError::InvalidTransition);
            }
            let lineage_key = (record.project, record.lineage, record.kind());
            if history
                .latest
                .get(&lineage_key)
                .is_none_or(|current| current.revision < record.revision)
            {
                history.latest.insert(lineage_key, record.clone());
            }
            history.order.push(record_key);

            if let LifecycleAuxiliaryPayloadV1::Operation(operation) = record.payload() {
                let digest = auxiliary_operation_record_digest(&record)?;
                if operation.project() != record.project
                    || operation.operation_id() != record.operation
                    || operation.record_revision() != record.operation_revision
                    || digest != record.operation_record
                {
                    return Err(LifecycleModelError::InvalidTransition);
                }
                operation_records.insert(
                    (
                        record.operation,
                        record.operation_revision,
                        record.operation_record,
                    ),
                    operation.clone(),
                );
                let replace = latest_operations.get(&record.operation).is_none_or(
                    |current: &LifecycleOperationV1| {
                        current.record_revision() < operation.record_revision()
                    },
                );
                if replace {
                    latest_operations.insert(record.operation, operation.clone());
                }
            } else if let LifecycleAuxiliaryPayloadV1::Cancellation(value) = record.payload() {
                cancellations.push(value.clone());
            }
        }
        if history.records.values().any(|record| {
            !operation_records.contains_key(&(
                record.operation,
                record.operation_revision,
                record.operation_record,
            ))
        }) {
            return Err(LifecycleModelError::InvalidTransition);
        }
        history.operations = LifecycleHistoryV1::from_compacted_operations(
            latest_operations.values(),
            cancellations.iter(),
        )
        .map_err(|_| LifecycleModelError::InvalidTransition)?;
        for operation in history.operations.operations() {
            history.authoritative_semantic_commit(operation)?;
            history.validate_materialized_method_join(operation)?;
            history.validate_terminal_auxiliaries(operation)?;
        }
        Ok(history)
    }

    /// Applies one exact successor after validating its operation join.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidTransition`] for a fork, skipped
    /// revision, orphan operation, reused join, or divergent cancellation key.
    fn apply(&mut self, record: LifecycleAuxiliaryRecordV1) -> Result<(), LifecycleModelError> {
        if let LifecycleAuxiliaryPayloadV1::Operation(operation) = record.payload() {
            let digest = auxiliary_operation_record_digest(&record)?;
            if operation.project() != record.project
                || operation.operation_id() != record.operation
                || operation.record_revision() != record.operation_revision
                || digest != record.operation_record
            {
                return Err(LifecycleModelError::InvalidTransition);
            }
            let already_current = self
                .operations
                .operation_record(operation.operation_id())
                .is_some_and(|(current, current_digest)| {
                    current == operation && current_digest == digest
                });
            if !already_current {
                self.operations
                    .apply_materialized(operation.clone(), digest)
                    .map_err(|_| LifecycleModelError::InvalidTransition)?;
            }
        } else if !self
            .operations
            .operation_record(record.operation)
            .is_some_and(|(operation, digest)| {
                operation.project() == record.project
                    && operation.record_revision() == record.operation_revision
                    && digest == record.operation_record
            })
        {
            return Err(LifecycleModelError::InvalidTransition);
        }
        let key = (record.project, record.lineage, record.kind());
        if self.records.len() >= MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS {
            return Err(LifecycleModelError::InvalidTransition);
        }
        if let Some(previous) = self.latest.get(&key) {
            if !previous
                .revision
                .checked_next()
                .is_ok_and(|next| next == record.revision)
                || record.predecessor != Some(previous.complete_digest())
                || !payload_may_follow(previous.payload(), record.payload())
                || previous
                    .replay_floor
                    .is_some_and(|floor| record.replay_floor.is_none_or(|next| next < floor))
            {
                return Err(LifecycleModelError::InvalidTransition);
            }
        } else if record.revision.get() != 1 || record.predecessor.is_some() {
            return Err(LifecycleModelError::InvalidTransition);
        }
        let mut next = self.clone();
        if let LifecycleAuxiliaryPayloadV1::Cancellation(cancellation) = record.payload() {
            next.operations
                .apply_cancellation_record(cancellation)
                .map_err(|_| LifecycleModelError::InvalidTransition)?;
        }
        let record_key = (
            record.project,
            record.lineage,
            record.kind(),
            record.revision,
        );
        next.latest.insert(key, record.clone());
        next.records.insert(record_key, record);
        next.order.push(record_key);
        *self = next;
        Ok(())
    }

    /// Captures the current bounded materialization as a trusted floor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError`] if a retained operation cannot be
    /// canonically encoded for the checkpoint commitment.
    pub fn checkpoint(&self) -> Result<LifecycleAuxiliaryCheckpointV1, LifecycleModelError> {
        Ok(LifecycleAuxiliaryCheckpointV1 {
            history: self.clone(),
            digest: self.complete_digest()?,
            accepted_record: None,
        })
    }

    /// Borrows reconstructed cancellation-idempotency state.
    #[must_use]
    pub const fn cancellations(&self) -> &LifecycleCancelIdempotencyIndexV1 {
        self.operations.cancellations()
    }

    /// Borrows the coherently replayed operation/idempotency projection.
    #[must_use]
    pub const fn operations(&self) -> &LifecycleHistoryV1 {
        &self.operations
    }
}

fn auxiliary_operation_record_digest(
    record: &LifecycleAuxiliaryRecordV1,
) -> Result<LifecycleRecordDigestV1, LifecycleModelError> {
    let payload = record.encoded_payload.as_slice();
    let length = payload
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    let operation = payload
        .get(4..)
        .filter(|bytes| bytes.len() == length)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    super::format::record_digest(operation)
}

fn payload_may_follow(
    previous: &LifecycleAuxiliaryPayloadV1,
    successor: &LifecycleAuxiliaryPayloadV1,
) -> bool {
    match (previous, successor) {
        (LifecycleAuxiliaryPayloadV1::Operation(_), LifecycleAuxiliaryPayloadV1::Operation(_)) => {
            true
        }
        (
            LifecycleAuxiliaryPayloadV1::Coordination(previous),
            LifecycleAuxiliaryPayloadV1::Coordination(successor),
        ) => {
            previous
                .successor(
                    successor.quiesce(),
                    successor.writer_fence(),
                    successor.dataset_transaction(),
                    successor.phase(),
                )
                .is_ok_and(|derived| derived == *successor)
                || previous
                    .retention_successor(successor.retention_ledger())
                    .is_ok_and(|derived| derived == *successor)
                || previous
                    .manifest_successor(successor.manifest())
                    .is_ok_and(|derived| derived == *successor)
        }
        (
            LifecycleAuxiliaryPayloadV1::RetentionLedger(previous),
            LifecycleAuxiliaryPayloadV1::RetentionLedger(successor),
        ) => {
            previous
                .revision()
                .checked_next()
                .is_ok_and(|revision| revision == successor.revision())
                && successor.predecessor()
                    == Some(
                        LifecycleProtectedRetentionLedgerV1::from_authoritative(previous.clone())
                            .record()
                            .digest(),
                    )
        }
        (
            LifecycleAuxiliaryPayloadV1::BootInventory(previous),
            LifecycleAuxiliaryPayloadV1::BootInventory(successor),
        ) => {
            successor.host_boot() != [0; 16]
                && (previous.host_boot() == [0; 16]
                    || successor.host_boot() == previous.host_boot())
                && successor.operation() == previous.operation()
                && successor.operation_revision() == previous.operation_revision()
                && successor.operation_record() == previous.operation_record()
                && successor.step() == previous.step()
                && successor.step_result() == previous.step_result()
                && successor.fence() == previous.fence()
                && successor.observed_at() > previous.observed_at()
        }
        _ => false,
    }
}

fn append_body(bytes: &mut Vec<u8>, record: &LifecycleAuxiliaryRecordV1) {
    bytes.extend_from_slice(record.format.magic());
    bytes.extend_from_slice(&record.format.version().to_be_bytes());
    bytes.push(record.kind() as u8);
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(record.project.as_bytes());
    bytes.extend_from_slice(record.operation.as_bytes());
    bytes.extend_from_slice(&record.operation_revision.get().to_be_bytes());
    bytes.extend_from_slice(record.operation_record.digest().as_bytes());
    bytes.extend_from_slice(record.lineage.as_bytes());
    bytes.extend_from_slice(&record.revision.get().to_be_bytes());
    bytes.extend_from_slice(
        record
            .predecessor
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
    bytes.extend_from_slice(record.atomic_join.as_bytes());
    bytes.extend_from_slice(&record.replay_floor.map_or(0, Revision::get).to_be_bytes());
    bytes.extend_from_slice(record.replay_authority.as_bytes());
    bytes.extend_from_slice(&record.declared_members.to_be_bytes());
    bytes.extend_from_slice(&record.declared_count.to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(
        record
            .join_digest
            .map_or(ObjectDigest::from_bytes([0; 32]), |digest| digest.digest())
            .as_bytes(),
    );
    bytes.extend_from_slice(&record.encoded_payload_length.to_be_bytes());
    bytes.extend_from_slice(&record.encoded_payload);
}

fn auxiliary_record_digest(record: &LifecycleAuxiliaryRecordV1) -> ObjectDigest {
    let predecessor = record
        .predecessor
        .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]));
    let join_digest = record
        .join_digest
        .map_or(ObjectDigest::from_bytes([0; 32]), |digest| digest.digest());
    let mut hasher = Sha256::new()
        .chain_update(record.format.digest_domain())
        .chain_update(record.format.magic())
        .chain_update(record.format.version().to_be_bytes())
        .chain_update([record.kind() as u8])
        .chain_update([0; 5])
        .chain_update(record.project.as_bytes())
        .chain_update(record.operation.as_bytes())
        .chain_update(record.operation_revision.get().to_be_bytes())
        .chain_update(record.operation_record.digest().as_bytes())
        .chain_update(record.lineage.as_bytes())
        .chain_update(record.revision.get().to_be_bytes())
        .chain_update(predecessor.as_bytes())
        .chain_update(record.atomic_join.as_bytes())
        .chain_update(record.replay_floor.map_or(0, Revision::get).to_be_bytes())
        .chain_update(record.replay_authority.as_bytes())
        .chain_update(record.declared_members.to_be_bytes())
        .chain_update(record.declared_count.to_be_bytes())
        .chain_update([0; 4])
        .chain_update(join_digest.as_bytes())
        .chain_update(record.encoded_payload_length.to_be_bytes());
    hasher.update(&record.encoded_payload);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn auxiliary_digest(bytes: &[u8], format: LifecycleAuxiliaryEnvelopeFormatV1) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(format.digest_domain())
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn envelope_format(body: &[u8]) -> Result<LifecycleAuxiliaryEnvelopeFormatV1, LifecycleModelError> {
    let magic = body.get(..8).ok_or(LifecycleModelError::CorruptEncoding)?;
    let version = u16::from_be_bytes(
        body.get(8..10)
            .and_then(|value| value.try_into().ok())
            .ok_or(LifecycleModelError::CorruptEncoding)?,
    );
    match (magic, version) {
        (value, LEGACY_VERSION) if value == LEGACY_MAGIC => {
            Ok(LifecycleAuxiliaryEnvelopeFormatV1::Legacy)
        }
        (value, CURRENT_VERSION) if value == CURRENT_MAGIC => {
            Ok(LifecycleAuxiliaryEnvelopeFormatV1::Current)
        }
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}

/// Reads the replay-authority field from an outer-journal-authenticated body.
///
/// This bootstrap accessor does not authenticate standalone bytes. Its sole
/// caller has already verified the fixed protected journal framing and uses
/// the value only to retain the stable authority brand across reopen.
pub(crate) fn lifecycle_auxiliary_replay_authority_v1(
    encoded: &[u8],
) -> Result<ObjectDigest, LifecycleModelError> {
    if encoded.len() < HEADER_BYTES + 1 + DIGEST_BYTES {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    envelope_format(encoded)?;
    let authority = encoded
        .get(168..200)
        .and_then(|bytes| bytes.try_into().ok())
        .map(ObjectDigest::from_bytes)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    if authority.as_bytes() == &[0; 32] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    Ok(authority)
}

fn decode_kind(value: u8) -> Result<LifecycleAuxiliaryKindV1, LifecycleModelError> {
    match value {
        0 => Ok(LifecycleAuxiliaryKindV1::Operation),
        1 => Ok(LifecycleAuxiliaryKindV1::Coordination),
        2 => Ok(LifecycleAuxiliaryKindV1::RetentionLedger),
        3 => Ok(LifecycleAuxiliaryKindV1::SuspendObservation),
        4 => Ok(LifecycleAuxiliaryKindV1::BootInventory),
        5 => Ok(LifecycleAuxiliaryKindV1::Cancellation),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}

fn optional_digest(bytes: [u8; 32]) -> Option<ObjectDigest> {
    (bytes != [0; 32]).then_some(ObjectDigest::from_bytes(bytes))
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], LifecycleModelError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], LifecycleModelError> {
    let (head, tail) = bytes
        .split_at_checked(length)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    *bytes = tail;
    Ok(head)
}
