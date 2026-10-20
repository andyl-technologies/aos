//! Borrows the final Delete Operation's framing without reconstructing its model.
//!
//! ```text
//! AOSLIF04 | version4 | Terminal8 | Succeeded1 | fixed-body-through740 |
//! semantic-fact | expectations60*N | one-step35692 | record-checksum32
//! ```
//!
//! This selector verifies extent, checksum, identities and terminal header DATA.
//! Root still decodes the complete canonical Operation and validates its original
//! Controller anchor, semantic Batch2 fact, physical receipts and native history.

use super::SourceDeleteCurrentDataErrorV1;
use sha2::{Digest as _, Sha256};

/// Checks a checksum-bound final Delete frame without granting lifecycle authority.
///
/// The returned digest identifies the actual encoded Operation. It does not
/// validate step semantics, a writer, native currentness or physical completion.
///
/// # Errors
/// Rejects a different format or terminal header, changed project/operation,
/// invalid progress, malformed extent or a changed record checksum.
pub fn require_source_delete_terminal_operation_frame_v4(
    encoded: &[u8],
    project: &[u8; 16],
    operation: &[u8; 16],
) -> Result<[u8; 32], SourceDeleteCurrentDataErrorV1> {
    let invalid = || SourceDeleteCurrentDataErrorV1::Association;
    let read_u32 = |offset: usize| -> Result<usize, SourceDeleteCurrentDataErrorV1> {
        let value = encoded.get(offset..offset + 4).ok_or_else(invalid)?;
        usize::try_from(u32::from_be_bytes(value.try_into().map_err(|_| invalid())?))
            .map_err(|_| invalid())
    };
    if encoded.len() < 740 + 32
        || encoded.get(..12) != Some(b"AOSLIF04\0\x04\x08\x01".as_slice())
        || encoded.get(272..288) != Some(operation.as_slice())
        || encoded.get(304..320) != Some(project.as_slice())
        || read_u32(400)? != 1
        || read_u32(404)? != 0
        || read_u32(732)? != 1
    {
        return Err(invalid());
    }

    // These are the established D4 wire strides, not allocation ceilings. The
    // full Domain decoder independently validates every counted member.
    let expectations = read_u32(728)?;
    let semantic_bytes = read_u32(736)?;
    let expected = expectations
        .checked_mul(60)
        .and_then(|bytes| bytes.checked_add(semantic_bytes))
        .and_then(|bytes| bytes.checked_add(740 + 35_692 + 32))
        .ok_or_else(invalid)?;
    if expected != encoded.len() {
        return Err(invalid());
    }

    let (body, checksum) = encoded.split_at(encoded.len() - 32);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.operation-record.v1\0")
        .chain_update(body)
        .finalize()
        .into();
    if checksum != digest {
        return Err(invalid());
    }
    Ok(digest)
}
