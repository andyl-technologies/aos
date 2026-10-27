//! Explicit edition-eleven envelope for original live-source custody.
//!
//! ```text
//! CNQEMU01 | edition11:u16be | kind:u16be | length:u32be | body
//! 44 quiet | 45 quiet-result952 | 46 retire296 | 47 proposal640
//! 48 accept168 | 49 receipt128 | 50 ACK168 | 51 committed160
//! ```

use super::codec::{Cursor, MAGIC};
use super::{NativeCommandError, NativeControlEdition, NativeFrame};
use crucible_node_format::U64;

fn acceptance(value: &super::NativeLiveAccept) -> Result<Vec<u8>, NativeCommandError> {
    if value.native_digest == [0; 32] || value.archive_digest == [0; 32] {
        return Err(NativeCommandError::Conflict);
    }
    let mut bytes = value.identity.encode()?.to_vec();
    bytes.extend_from_slice(&value.native_digest);
    bytes.extend_from_slice(&value.archive_digest);
    Ok(bytes)
}

fn decode_acceptance(bytes: &[u8]) -> Result<super::NativeLiveAccept, NativeCommandError> {
    if bytes.len() != 168 {
        return Err(NativeCommandError::Conflict);
    }
    let value = super::NativeLiveAccept {
        identity: super::NativeLiveIdentity::decode(&bytes[..104])?,
        native_digest: bytes[104..136]
            .try_into()
            .map_err(|_| NativeCommandError::Conflict)?,
        archive_digest: bytes[136..]
            .try_into()
            .map_err(|_| NativeCommandError::Conflict)?,
    };
    acceptance(&value)?;
    Ok(value)
}

pub(super) fn encode(frame: &NativeFrame) -> Result<Vec<u8>, NativeCommandError> {
    let (kind, body) = match frame {
        NativeFrame::QuietAdvance(quiet) => {
            quiet.validate()?;
            let original = super::encode_command(&quiet.command)?;
            let mut bytes = quiet.preparation.to_vec();
            bytes.extend_from_slice(&quiet.predecessor_commit);
            bytes.extend_from_slice(&quiet.input_batch_sequence.get().to_be_bytes());
            bytes.extend_from_slice(&original);
            (44u16, bytes)
        }
        NativeFrame::QuietProgress(result) => (45, result.bytes().to_vec()),
        NativeFrame::RetireOriginal(retire) => {
            let mut bytes = retire.identity.encode()?.to_vec();
            bytes.extend_from_slice(&retire.final_acknowledgement);
            (46, bytes)
        }
        NativeFrame::RetirementProposed(proposal) => (47, proposal.bytes().to_vec()),
        NativeFrame::AcceptTerminal(value) => (48, acceptance(value)?),
        NativeFrame::RetirementReceipt(value) => (49, value.bytes().to_vec()),
        NativeFrame::AcknowledgeRetirement(value) => (50, acceptance(value)?),
        NativeFrame::RetirementCommitted(value) => (51, value.bytes().to_vec()),
        _ => {
            let mut previous =
                super::encode_frame_for_edition(NativeControlEdition::PrefixObservation, frame)?;
            previous[8..10].copy_from_slice(&11u16.to_be_bytes());
            return Ok(previous);
        }
    };
    if body.len() > super::NODE_CONTROL_MAX_BODY_BYTES {
        return Err(NativeCommandError::ResourceLimit);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(super::NODE_CONTROL_HEADER_BYTES + body.len())
        .map_err(|_| NativeCommandError::ResourceLimit)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&11u16.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<NativeFrame, NativeCommandError> {
    let mut cursor = Cursor(bytes);
    if cursor.take(8)? != MAGIC || cursor.u16()? != 11 {
        return Err(NativeCommandError::Conflict);
    }
    let kind = cursor.u16()?;
    let length = cursor.u32()? as usize;
    if length > super::NODE_CONTROL_MAX_BODY_BYTES || cursor.0.len() != length {
        return Err(NativeCommandError::ResourceLimit);
    }
    let body = cursor.take(length)?;
    Ok(match kind {
        44 => {
            if body.len() < 72 {
                return Err(NativeCommandError::Conflict);
            }
            let quiet = super::NativeQuietCommand {
                preparation: body[..32]
                    .try_into()
                    .map_err(|_| NativeCommandError::Conflict)?,
                predecessor_commit: body[32..64]
                    .try_into()
                    .map_err(|_| NativeCommandError::Conflict)?,
                input_batch_sequence: U64::new(u64::from_be_bytes(
                    body[64..72]
                        .try_into()
                        .map_err(|_| NativeCommandError::Conflict)?,
                )),
                command: super::decode_command(&body[72..])?,
            };
            quiet.validate()?;
            NativeFrame::QuietAdvance(Box::new(quiet))
        }
        45 => NativeFrame::QuietProgress(Box::new(super::NativeQuietProgress::decode(body)?)),
        46 => {
            if body.len() != 296 {
                return Err(NativeCommandError::Conflict);
            }
            NativeFrame::RetireOriginal(Box::new(super::NativeRetireOriginal {
                identity: super::NativeLiveIdentity::decode(&body[..104])?,
                final_acknowledgement: body[104..]
                    .try_into()
                    .map_err(|_| NativeCommandError::Conflict)?,
            }))
        }
        47 => NativeFrame::RetirementProposed(Box::new(super::NativeRetirementProposal::decode(
            body,
        )?)),
        48 => NativeFrame::AcceptTerminal(decode_acceptance(body)?),
        49 => {
            NativeFrame::RetirementReceipt(Box::new(super::NativeRetirementReceipt::decode(body)?))
        }
        50 => NativeFrame::AcknowledgeRetirement(decode_acceptance(body)?),
        51 => NativeFrame::RetirementCommitted(Box::new(super::NativeRetirementCommitted::decode(
            body,
        )?)),
        _ => {
            let mut previous = bytes.to_vec();
            previous[8..10].copy_from_slice(&10u16.to_be_bytes());
            return super::decode_frame_for_edition(
                NativeControlEdition::PrefixObservation,
                &previous,
            );
        }
    })
}
