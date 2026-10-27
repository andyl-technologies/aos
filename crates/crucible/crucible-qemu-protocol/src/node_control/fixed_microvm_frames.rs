//! Closed bootstrap frames for complete original fixed-microvm preparation.
//!
//! Edition seven retains unchanged construction bodies, replacing its initial
//! preparation with the complete root record. It rejects legacy compute frames
//! even if a peer substitutes the header. Native enrollment and effect admission
//! are separate installed interfaces; this codec never creates their authority.

use super::codec::{Cursor, MAGIC};
use super::{
    NODE_CONTROL_HEADER_BYTES, NODE_CONTROL_MAX_BODY_BYTES, NativeCommandError,
    NativeControlEdition, NativeFixedMicrovmPreparation, NativeFrame,
};

const ROOT_PREPARATION_KIND: u16 = 29;

pub(super) fn encode(frame: &NativeFrame) -> Result<Vec<u8>, NativeCommandError> {
    if let NativeFrame::PrepareFixedMicrovm(preparation) = frame {
        let body = preparation.encode()?;
        let length = NODE_CONTROL_HEADER_BYTES
            .checked_add(body.len())
            .ok_or(NativeCommandError::ResourceLimit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&NativeControlEdition::FixedMicrovm.version().to_be_bytes());
        bytes.extend_from_slice(&ROOT_PREPARATION_KIND.to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&body);
        return Ok(bytes);
    }
    if matches!(frame, NativeFrame::PrepareAdministration(_)) {
        return Err(NativeCommandError::Invalid(
            "fixed profile requires complete root preparation",
        ));
    }
    let mut bytes = super::encode_frame_for_edition(NativeControlEdition::Construction, frame)?;
    bytes[8..10].copy_from_slice(&NativeControlEdition::FixedMicrovm.version().to_be_bytes());
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<NativeFrame, NativeCommandError> {
    let mut cursor = Cursor(bytes);
    if cursor.take(8)? != MAGIC {
        return Err(NativeCommandError::Invalid(
            "wrong fixed profile frame magic",
        ));
    }
    if cursor.u16()? != NativeControlEdition::FixedMicrovm.version() {
        return Err(NativeCommandError::Invalid(
            "foreign fixed profile frame edition",
        ));
    }
    let kind = cursor.u16()?;
    let length = cursor.u32()? as usize;
    if length > NODE_CONTROL_MAX_BODY_BYTES || cursor.0.len() != length {
        return Err(NativeCommandError::Invalid(
            "fixed profile frame length mismatch",
        ));
    }
    if kind == ROOT_PREPARATION_KIND {
        return Ok(NativeFrame::PrepareFixedMicrovm(Box::new(
            NativeFixedMicrovmPreparation::decode(cursor.take(length)?)?,
        )));
    }
    let mut previous = bytes.to_vec();
    previous[8..10].copy_from_slice(&NativeControlEdition::Construction.version().to_be_bytes());
    let frame = super::decode_frame_for_edition(NativeControlEdition::Construction, &previous)?;
    if matches!(frame, NativeFrame::PrepareAdministration(_)) {
        return Err(NativeCommandError::Invalid(
            "fixed profile requires complete root preparation",
        ));
    }
    Ok(frame)
}
