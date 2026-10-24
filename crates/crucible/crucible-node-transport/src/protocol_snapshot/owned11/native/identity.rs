//! Restores historical native actor correspondence without live enrollment.

use super::super::{
    state::{HistoricalAuthority, next, tag},
    typed::{Fields, invalid},
};
use super::{policy::HistoricalNativePolicy, shared::NativeLedger};
use crate::{
    ProviderError,
    envelope::Envelope,
    retained_metadata::aliases::MetadataSharedKind,
    transport::{DecodedCompactOriginalFrames, original_frames::FrameDirection},
};
use crucible_node_format::{Id, U64};
use std::rc::Rc;

/// Owns exact historical assigned-Admit identity and its shared literal bank.
pub struct HistoricalNativeAckIdentity {
    /// Identifies a checked historical actor group, never a live actor.
    pub actor_group: usize,
    /// Preserves the full original connection registration fields.
    pub authority: HistoricalAuthority,
    /// Shares the complete historical policy with all corresponding boot roots.
    pub policy: Rc<HistoricalNativePolicy>,
    /// Shares the exact original connection literal bank and its capacities.
    pub frames: Rc<DecodedCompactOriginalFrames>,
    /// Retains the actual assigned Admit request identity.
    pub admit_id: Id,
    /// Retains its actual original connection sequence.
    pub admit_sequence: U64,
    /// Retains its original incoming slot in the literal history.
    pub literal_index: usize,
    /// Retains the complete framed original byte length.
    pub literal_length: usize,
    /// Retains the digest of that complete original header and body.
    pub literal_digest: [u8; 32],
}

impl HistoricalNativeAckIdentity {
    /// Checks the full retained original and literal bank without renewing it.
    pub(super) fn authenticate_original(&self, original: &Envelope) -> Result<(), ProviderError> {
        if original.request_id.0.as_ref() != Some(&self.admit_id)
            || original.sequence != self.admit_sequence
        {
            return Err(invalid());
        }
        let frame = self
            .frames
            .frames()
            .nth(self.literal_index)
            .ok_or_else(invalid)?;
        if frame.direction != FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.len() != self.literal_length
            || frame.bytes.len() < 4
            || blake3::hash(frame.bytes).as_bytes() != &self.literal_digest
        {
            return Err(invalid());
        }
        super::super::correspondence::envelope(original, &frame.bytes[4..])
    }
}

pub(super) fn read(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeAckIdentity>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        "source-private.native-ack-connection-identity/11",
    )?;
    let marker = next(&mut fields)?;
    let layout = std::mem::size_of::<crate::protocol_snapshot::ProtocolCaptureOwner>();
    if ledger.ledger.row(
        crate::retained_metadata::records::MetadataRecordKind::Shared,
        1,
    )? != layout
    {
        return Err(invalid());
    }
    let actor_group = ledger.ledger.shared(
        MetadataSharedKind::ProtocolOwner,
        layout,
        b"historical-source-owner",
        b"",
    )?;
    if marker != b"\"historical-source-owner\"" {
        return Err(invalid());
    }
    let authority = ledger
        .ledger
        .read::<HistoricalAuthority>(next(&mut fields)?, build)?;
    let policy = ledger.policy(next(&mut fields)?, build)?;
    let frames = ledger.frames(next(&mut fields)?, build, MetadataSharedKind::FrameBank)?;
    let admit_id = ledger.ledger.read::<Id>(next(&mut fields)?, build)?;
    let admit_sequence = ledger.ledger.read::<U64>(next(&mut fields)?, build)?;
    let literal_index = ledger.ledger.read::<usize>(next(&mut fields)?, build)?;
    let literal_length = ledger.ledger.read::<usize>(next(&mut fields)?, build)?;
    let mut digest_fields = Fields::array(next(&mut fields)?)?;
    let mut literal_digest = [0u8; 32];
    for byte in &mut literal_digest {
        *byte = ledger
            .ledger
            .read::<u8>(next(&mut digest_fields)?, true)?
            .ok_or_else(invalid)?;
    }
    digest_fields.finish()?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeAckIdentity {
        actor_group,
        authority: authority.ok_or_else(invalid)?,
        policy: policy.ok_or_else(invalid)?,
        frames: frames.ok_or_else(invalid)?,
        admit_id: admit_id.ok_or_else(invalid)?,
        admit_sequence: admit_sequence.ok_or_else(invalid)?,
        literal_index: literal_index.ok_or_else(invalid)?,
        literal_length: literal_length.ok_or_else(invalid)?,
        literal_digest,
    }))
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeAckIdentity,
    actor_group,
    authority,
    policy,
    frames,
    admit_id,
    admit_sequence,
    literal_index,
    literal_length,
    literal_digest
);

pub(crate) mod current17;

/// Names actual fixed local and returned headers of this handwritten reader.
///
/// Empty maps and `Option` payloads remain real controls when `build` is false;
/// no tree entries, backing allocations or owning reconstruction are included.
pub(super) fn borrowed_validation_headers_data() -> usize {
    use std::mem::size_of;

    fn header<T>() -> usize {
        size_of::<Option<T>>() + size_of::<Result<Option<T>, ProviderError>>()
    }

    fn field<T: super::super::typed::HistoricalType>() -> usize {
        header::<T>() + T::borrowed_header_counter_scratch_data()
    }

    field::<HistoricalAuthority>()
        + field::<Id>()
        + field::<U64>()
        + field::<usize>()
        + field::<usize>()
        + field::<u8>()
        + header::<HistoricalNativeAckIdentity>()
        + header::<std::rc::Rc<crate::transport::DecodedCompactOriginalFrames>>()
        + header::<std::rc::Rc<super::policy::HistoricalNativePolicy>>()
        + size_of::<[u8; 32]>()
        + size_of::<std::slice::IterMut<'static, u8>>()
}
