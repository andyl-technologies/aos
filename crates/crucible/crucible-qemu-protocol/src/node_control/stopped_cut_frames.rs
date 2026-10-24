//! Bounded edition-ten wrapper over byte-unchanged edition-nine ancestors.
//!
//! ```text
//! CNQEMU01 | edition:u16be=10 | kind:u16be | length:u32be | body
//! kind42 QueryStoppedCut: Query72; kind43 StoppedCut: Query72+Record408
//! ```

use super::codec::{Cursor, MAGIC};
use super::{NativeCommandError, NativeControlEdition, NativeFrame};

pub(super) fn encode(frame: &NativeFrame) -> Result<Vec<u8>, NativeCommandError> {
    let (kind, body) = match frame {
        NativeFrame::QueryStoppedCut(query) => (42u16, query.encode()?.to_vec()),
        NativeFrame::StoppedCut(observation) => (43u16, observation.encode()?.to_vec()),
        _ => {
            let mut bytes =
                super::encode_frame_for_edition(NativeControlEdition::PrefixEffect, frame)?;
            bytes[8..10].copy_from_slice(&10u16.to_be_bytes());
            return Ok(bytes);
        }
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(super::NODE_CONTROL_HEADER_BYTES + body.len())
        .map_err(|_| NativeCommandError::ResourceLimit)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&10u16.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<NativeFrame, NativeCommandError> {
    let mut cursor = Cursor(bytes);
    if cursor.take(8)? != MAGIC || cursor.u16()? != 10 {
        return Err(NativeCommandError::UnsupportedVersion(10));
    }
    let kind = cursor.u16()?;
    let length = cursor.u32()? as usize;
    if length > super::NODE_CONTROL_MAX_BODY_BYTES || cursor.0.len() != length {
        return Err(NativeCommandError::ResourceLimit);
    }
    Ok(match kind {
        42 => NativeFrame::QueryStoppedCut(super::NativeStoppedCutQuery::decode(
            cursor.take(length)?,
        )?),
        43 => NativeFrame::StoppedCut(Box::new(super::NativeStoppedCut::decode(
            cursor.take(length)?,
        )?)),
        _ => {
            let mut prior = bytes.to_vec();
            prior[8..10].copy_from_slice(&9u16.to_be_bytes());
            return super::decode_frame_for_edition(NativeControlEdition::PrefixEffect, &prior);
        }
    })
}
