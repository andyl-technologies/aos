//! Borrows canonical auxiliary envelope DATA without reconstructing lifecycle state.
//!
//! ```text
//! AOSLIFA{3,4,5,6,7,8} | exact version | kind | reserved5 | project16 | operation16 |
//! operation-revision8 | operation-record32 | lineage16 | revision8 | predecessor32 |
//! atomic-join16 | floor8 | replay-authority32 | declared-members2 | declared-count2 |
//! reserved4 | join-digest32 | payload-length4 | payload | checksum32
//! ```
//!
//! This framing check authenticates no writer, currentness or Operation relation.
//! Domain retains the complete payload and atomic-join semantic validators.

use super::lifecycle_model::LifecycleModelError;
use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, ResourceId};
use sha2::{Digest as _, Sha256};

const LEGACY_MAGIC: &[u8; 8] = b"AOSLIFA3";
const LEGACY_VERSION: u16 = 1;
const CURRENT_MAGIC: &[u8; 8] = b"AOSLIFA4";
const CURRENT_VERSION: u16 = 2;
const DELETE_BATCH_MAGIC: &[u8; 8] = b"AOSLIFA5";
const DELETE_BATCH_VERSION: u16 = 3;
const SNAPSHOT_SOURCE_MAGIC: &[u8; 8] = b"AOSLIFA6";
const SNAPSHOT_SOURCE_VERSION: u16 = 4;
const STOP_DISPATCH_MAGIC: &[u8; 8] = b"AOSLIFA7";
const STOP_DISPATCH_VERSION: u16 = 5;
const STOP_COMPLETION_MAGIC: &[u8; 8] = b"AOSLIFA8";
const STOP_COMPLETION_VERSION: u16 = 6;
/// Bounds the established canonical auxiliary payload.
pub const MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const HEADER_BYTES: usize = 244;
const DIGEST_BYTES: usize = 32;

/// Selects an exact established auxiliary wire format without semantic authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAuxiliaryEnvelopeFormatV1 {
    /// Selects the established AOSLIFA3 layout.
    Legacy,
    /// Selects the established AOSLIFA4 layout.
    Current,
    /// Selects the established AOSLIFA5 Delete batch layout.
    DeleteBatch,
    /// Selects the established AOSLIFA6 admitted-source layout.
    SnapshotAdmittedSource,
    /// Selects the finite AOSLIFA7 ordinary Stop Operation/Dispatch pair.
    StopDispatch,
    /// Selects the finite AOSLIFA8 unchanged Stop/independent settlement pair.
    StopCompletion,
}

impl LifecycleAuxiliaryEnvelopeFormatV1 {
    /// Returns the canonical format magic.
    pub const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Legacy => LEGACY_MAGIC,
            Self::Current => CURRENT_MAGIC,
            Self::DeleteBatch => DELETE_BATCH_MAGIC,
            Self::SnapshotAdmittedSource => SNAPSHOT_SOURCE_MAGIC,
            Self::StopDispatch => STOP_DISPATCH_MAGIC,
            Self::StopCompletion => STOP_COMPLETION_MAGIC,
        }
    }

    /// Returns the canonical format version.
    pub const fn version(self) -> u16 {
        match self {
            Self::Legacy => LEGACY_VERSION,
            Self::Current => CURRENT_VERSION,
            Self::DeleteBatch => DELETE_BATCH_VERSION,
            Self::SnapshotAdmittedSource => SNAPSHOT_SOURCE_VERSION,
            Self::StopDispatch => STOP_DISPATCH_VERSION,
            Self::StopCompletion => STOP_COMPLETION_VERSION,
        }
    }

    /// Returns the purpose-separated record checksum domain.
    pub const fn digest_domain(self) -> &'static [u8] {
        match self {
            Self::Legacy => b"aos.sandbox.lifecycle.auxiliary-record.v2\0",
            Self::Current => b"aos.sandbox.lifecycle.auxiliary-record.v3\0",
            Self::DeleteBatch => b"aos.sandbox.lifecycle.auxiliary-record.v4\0",
            Self::SnapshotAdmittedSource => b"aos.sandbox.lifecycle.auxiliary-record.v5\0",
            Self::StopDispatch => b"aos.sandbox.lifecycle.auxiliary-record.v6\0",
            Self::StopCompletion => b"aos.sandbox.lifecycle.auxiliary-record.v7\0",
        }
    }
}

impl LifecycleAuxiliaryEnvelopeFormatV1 {
    /// Selects only an exact established magic/version pair.
    ///
    /// # Errors
    /// Rejects truncated, unknown or mismatched format selectors.
    pub fn from_prefix(bytes: &[u8]) -> Result<Self, LifecycleModelError> {
        let magic = bytes.get(..8).ok_or(LifecycleModelError::CorruptEncoding)?;
        let version = u16::from_be_bytes(read(bytes, 8)?);
        match (magic, version) {
            (value, LEGACY_VERSION) if value == LEGACY_MAGIC => Ok(Self::Legacy),
            (value, CURRENT_VERSION) if value == CURRENT_MAGIC => Ok(Self::Current),
            (value, DELETE_BATCH_VERSION) if value == DELETE_BATCH_MAGIC => Ok(Self::DeleteBatch),
            (value, SNAPSHOT_SOURCE_VERSION) if value == SNAPSHOT_SOURCE_MAGIC => {
                Ok(Self::SnapshotAdmittedSource)
            }
            (value, STOP_DISPATCH_VERSION) if value == STOP_DISPATCH_MAGIC => Ok(Self::StopDispatch),
            (value, STOP_COMPLETION_VERSION) if value == STOP_COMPLETION_MAGIC => Ok(Self::StopCompletion),
            _ => Err(LifecycleModelError::CorruptEncoding),
        }
    }
}

/// Borrows checksum-checked auxiliary fields; payload semantics remain unvalidated DATA.
#[derive(Clone, Copy, Debug)]
pub struct LifecycleAuxiliaryFrameDataV1<'bytes> {
    encoded: &'bytes [u8],
    /// Exact established wire format.
    pub format: LifecycleAuxiliaryEnvelopeFormatV1,
    /// Closed auxiliary kind code.
    pub kind: u8,
    /// Encoded project identity.
    pub project: ProjectId,
    /// Encoded operation identity.
    pub operation: OperationId,
    /// Encoded operation revision.
    pub operation_revision: u64,
    /// Encoded operation-record commitment.
    pub operation_record: ObjectDigest,
    /// Encoded auxiliary lineage.
    pub lineage: ResourceId,
    /// Encoded auxiliary revision.
    pub revision: u64,
    /// Optional predecessor commitment.
    pub predecessor: Option<ObjectDigest>,
    /// Encoded atomic-unit identity.
    pub atomic_join: ResourceId,
    /// Encoded optional revision floor; zero means absent.
    pub floor: u64,
    /// Encoded replay brand; not a live authority.
    pub replay_authority: ObjectDigest,
    /// Encoded auxiliary member bitset.
    pub declared_members: u16,
    /// Encoded atomic member count.
    pub declared_count: u16,
    /// Encoded atomic-unit commitment.
    pub join_digest: ObjectDigest,
    /// Borrowed payload without semantic adoption.
    pub payload: &'bytes [u8],
    /// Canonical envelope checksum.
    pub digest: ObjectDigest,
}

impl<'bytes> LifecycleAuxiliaryFrameDataV1<'bytes> {
    /// Borrows the exact complete checksum-checked auxiliary bytes.
    pub const fn encoded_bytes_v1(self) -> &'bytes [u8] { self.encoded }

    /// Decodes the sole auxiliary framing and checksum grammar without allocating.
    ///
    /// # Errors
    /// Rejects noncanonical length, selector, kind, reserved bytes or checksum.
    pub fn decode(encoded: &'bytes [u8]) -> Result<Self, LifecycleModelError> {
        const MAXIMUM_PAYLOAD_BYTES: usize = MAXIMUM_LIFECYCLE_AUXILIARY_PAYLOAD_BYTES;
        if encoded.len() < HEADER_BYTES + 1 + DIGEST_BYTES
            || encoded.len() > HEADER_BYTES + MAXIMUM_PAYLOAD_BYTES + DIGEST_BYTES
        {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        let format = LifecycleAuxiliaryEnvelopeFormatV1::from_prefix(encoded)?;
        let (body, stored) = encoded.split_at(encoded.len() - DIGEST_BYTES);
        let digest = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(format.digest_domain())
                .chain_update(body)
                .finalize()
                .into(),
        );
        if stored != digest.as_bytes()
            || body[10] > 8
            || (body[10] == 7 && format != LifecycleAuxiliaryEnvelopeFormatV1::StopDispatch)
            || (body[10] == 8 && format != LifecycleAuxiliaryEnvelopeFormatV1::StopCompletion)
            || (format == LifecycleAuxiliaryEnvelopeFormatV1::StopDispatch
                && !matches!(body[10], 0 | 7))
            || (format == LifecycleAuxiliaryEnvelopeFormatV1::StopCompletion
                && !matches!(body[10], 0 | 8))
            || body[11..16] != [0; 5]
            || body[204..208] != [0; 4]
        {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        let payload_length = usize::try_from(u32::from_be_bytes(read(body, 240)?))
            .map_err(|_| LifecycleModelError::CorruptEncoding)?;
        if payload_length == 0
            || payload_length > MAXIMUM_PAYLOAD_BYTES
            || HEADER_BYTES.checked_add(payload_length) != Some(body.len())
        {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        let predecessor = ObjectDigest::from_bytes(read(body, 112)?);
        Ok(Self {
            encoded,
            format,
            kind: body[10],
            project: ProjectId::from_bytes(read(body, 16)?),
            operation: OperationId::from_bytes(read(body, 32)?),
            operation_revision: u64::from_be_bytes(read(body, 48)?),
            operation_record: ObjectDigest::from_bytes(read(body, 56)?),
            lineage: ResourceId::from_bytes(read(body, 88)?),
            revision: u64::from_be_bytes(read(body, 104)?),
            predecessor: (predecessor.as_bytes() != &[0; 32]).then_some(predecessor),
            atomic_join: ResourceId::from_bytes(read(body, 144)?),
            floor: u64::from_be_bytes(read(body, 160)?),
            replay_authority: ObjectDigest::from_bytes(read(body, 168)?),
            declared_members: u16::from_be_bytes(read(body, 200)?),
            declared_count: u16::from_be_bytes(read(body, 202)?),
            join_digest: ObjectDigest::from_bytes(read(body, 208)?),
            payload: &body[HEADER_BYTES..],
            digest,
        })
    }
}

fn read<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], LifecycleModelError> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(LifecycleModelError::CorruptEncoding)
}

#[cfg(test)]
mod stop_dispatch_format_tests {
    use super::*;

    fn framed(format: LifecycleAuxiliaryEnvelopeFormatV1, kind: u8) -> Vec<u8> {
        let mut body = vec![0_u8; HEADER_BYTES + 1];
        body[..8].copy_from_slice(format.magic());
        body[8..10].copy_from_slice(&format.version().to_be_bytes());
        body[10] = kind;
        body[240..244].copy_from_slice(&1_u32.to_be_bytes());
        let checksum = Sha256::new().chain_update(format.digest_domain())
            .chain_update(&body).finalize();
        body.extend_from_slice(&checksum);
        body
    }

    #[test]
    fn stop_dispatch_never_widens_the_historical_kind_or_delete_grammar() {
        use LifecycleAuxiliaryEnvelopeFormatV1 as Format;

        assert_eq!(Format::DeleteBatch.magic(), b"AOSLIFA5");
        assert_eq!(Format::DeleteBatch.version(), 3);
        assert!(LifecycleAuxiliaryFrameDataV1::decode(&framed(Format::DeleteBatch, 6)).is_ok());
        assert!(LifecycleAuxiliaryFrameDataV1::decode(&framed(Format::Current, 7)).is_err());
        assert!(LifecycleAuxiliaryFrameDataV1::decode(&framed(Format::DeleteBatch, 7)).is_err());
        assert!(LifecycleAuxiliaryFrameDataV1::decode(&framed(Format::StopDispatch, 6)).is_err());

        for kind in [0, 7] {
            assert!(LifecycleAuxiliaryFrameDataV1::decode(&framed(Format::StopDispatch, kind)).is_ok());
        }
        for kind in 1..=6 {
            assert!(LifecycleAuxiliaryFrameDataV1::decode(&framed(Format::StopDispatch, kind)).is_err());
        }
    }

    #[test]
    fn independent_completion_has_only_its_own_closed_member_family() {
        use LifecycleAuxiliaryEnvelopeFormatV1 as Format;

        for kind in [0, 8] {
            assert!(LifecycleAuxiliaryFrameDataV1::decode(&framed(Format::StopCompletion, kind)).is_ok());
        }
        for kind in 1..=7 {
            assert!(LifecycleAuxiliaryFrameDataV1::decode(&framed(Format::StopCompletion, kind)).is_err());
        }
        for historical in [Format::Legacy, Format::Current, Format::DeleteBatch,
            Format::SnapshotAdmittedSource, Format::StopDispatch] {
            assert!(LifecycleAuxiliaryFrameDataV1::decode(&framed(historical, 8)).is_err());
        }
    }
}

/// Gives the sole Lifecycle protected-domain envelope selector.
pub const LIFECYCLE_PROTECTED_MAGIC_V1: [u8; 8] = *b"AOSLPJ01";
/// Separates Lifecycle protected-domain checksums.
pub const LIFECYCLE_PROTECTED_DOMAIN_V1: &[u8] = b"aos.sandbox.lifecycle.protected-journal.v1\0";
/// Gives the sole canonical Lifecycle key prefix.
pub const LIFECYCLE_PROTECTED_KEY_PREFIX_V1: &[u8] = b"\0aos-lifecycle-v1\0";
/// Bounds a complete Lifecycle protected payload before decoding.
pub const LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1: usize = 128 * 1024 * 1024;

/// Borrows an auxiliary body from one complete canonical protected member.
///
/// It checks framing, key/body identity and checksums only. It does not validate
/// the Lifecycle Operation, its atomic companion set, replay brand or authority.
/// The full Domain reader must separately validate those at the same native cut.
///
/// # Errors
/// Rejects a non-auxiliary key, wrong native transaction, malformed framing,
/// identity mismatch, or a noncanonical auxiliary checksum.
pub fn borrow_lifecycle_auxiliary_member_data_v1<'a>(
    key: &[u8],
    value: &'a [u8],
    transaction: &[u8; 16],
) -> Result<LifecycleAuxiliaryFrameDataV1<'a>, super::DomainLedgerDataError> {
    use super::records::ProtectedReducerPhaseV1;
    use super::records::borrowed::{
        DurableMemberFrameDataV1, ProtectedEnvelopeFrameDataV1, ReducerFrameDataV1,
        borrow_protected_key_data_v1,
    };
    let invalid = || super::DomainLedgerDataError::NonCanonicalRecord;
    let (kind, identity) = borrow_protected_key_data_v1(key, LIFECYCLE_PROTECTED_KEY_PREFIX_V1)?;
    if kind != 5 || identity.len() != 48 || identity.chunks_exact(16).any(|part| part == [0; 16]) {
        return Err(invalid());
    }
    let member = DurableMemberFrameDataV1::decode(
        value,
        LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1,
        LIFECYCLE_PROTECTED_DOMAIN_V1,
    )?;
    if &member.transaction_id != transaction {
        return Err(invalid());
    }
    let envelope = ProtectedEnvelopeFrameDataV1::decode(
        member.envelope,
        key,
        &LIFECYCLE_PROTECTED_MAGIC_V1,
        kind,
        LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1,
        LIFECYCLE_PROTECTED_DOMAIN_V1,
    )?;
    if envelope.revision == 0
        || envelope.revision == u64::MAX
        || (envelope.revision == 1) != envelope.predecessor.is_none()
    {
        return Err(invalid());
    }
    let reducer = ReducerFrameDataV1::decode(
        envelope.payload,
        kind,
        kind,
        LIFECYCLE_PROTECTED_MAXIMUM_PAYLOAD_BYTES_V1,
        LIFECYCLE_PROTECTED_DOMAIN_V1,
    )?;
    let frame = LifecycleAuxiliaryFrameDataV1::decode(reducer.body).map_err(|_| invalid())?;
    if frame.project.as_bytes() != &identity[..16]
        || frame.lineage.as_bytes() != &identity[16..32]
        || frame.operation.as_bytes() != &identity[32..48]
        || (frame.kind == 6 && reducer.phase != ProtectedReducerPhaseV1::Observed)
    {
        return Err(invalid());
    }
    Ok(frame)
}
