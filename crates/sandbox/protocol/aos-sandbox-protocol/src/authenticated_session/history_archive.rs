//! Shares the existing immutable signed Session history archive frame as DATA.
//!
//! Native protected writers, checkpoint verification, complete history replay,
//! endpoint lineage, currentness and authorization remain with actual owners.
//! A canonical frame alone establishes none of those properties.
//!
//! ```text
//! purpose-magic[8] | version:u16be=1 | request-id[16] | history-length:u32be |
//! complete stored history | SHA256(purpose-domain || preceding)[32]
//! ```

use sha2::{Digest as _, Sha256};

/// Names the existing original Host request archive key family.
pub const HOST_ORIGINAL_SESSION_KEY_MAGIC_V1: &[u8; 8] = b"AOSBSH01";
/// Names the existing terminal Host Session archive key family.
pub const HOST_TERMINAL_SESSION_KEY_MAGIC_V1: &[u8; 8] = b"AOSBST01";
/// Names the existing original Host request frame.
pub const HOST_ARGUMENT_ARCHIVE_MAGIC_V1: &[u8; 8] = b"AOSHAR01";
/// Domain-separates the existing original Host request frame checksum.
pub const HOST_ARGUMENT_ARCHIVE_DOMAIN_V1: &[u8] =
    b"aos.sandbox.broker-session.host-argument-archive-value.v1\0";
/// Names the existing terminal Host Session frame.
pub const HOST_TERMINAL_ARCHIVE_MAGIC_V1: &[u8; 8] = b"AOSHTA01";
/// Domain-separates the existing terminal Host Session frame checksum.
pub const HOST_TERMINAL_ARCHIVE_DOMAIN_V1: &[u8] =
    b"aos.sandbox.broker-session.host-terminal-archive.v1\0";
/// Counts the existing magic, version, request identity and payload extent.
pub const HISTORY_ARCHIVE_HEADER_BYTES_V1: usize = 8 + 2 + 16 + 4;
/// Counts the existing SHA256 checksum.
pub const HISTORY_ARCHIVE_TRAILER_BYTES_V1: usize = 32;

/// Reports malformed framing, checked width overflow, or output allocation refusal.
#[derive(Debug, thiserror::Error)]
pub enum HistoryArchiveFrameDataErrorV1 {
    /// A field, length, version, request association or checksum was invalid.
    #[error("invalid immutable Session history archive frame")]
    Invalid,
    /// Output backing could not be reserved before encoding.
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
}

/// Encodes the established purpose-separated frame without granting provenance.
///
/// The real native supplier independently pays the exact output and retains the
/// actual stored Session. Purpose magic and domain are comparison format DATA.
///
/// # Errors
/// Refuses zero request identity, empty or oversized payloads, checked length
/// overflow, or inability to reserve the exact output backing.
pub fn encode_history_archive_frame_data_v1(
    request_id: [u8; 16],
    stored_history: &[u8],
    magic: &[u8; 8],
    domain: &[u8],
) -> Result<Vec<u8>, HistoryArchiveFrameDataErrorV1> {
    let invalid = HistoryArchiveFrameDataErrorV1::Invalid;
    let stored_length = u32::try_from(stored_history.len()).map_err(|_| invalid)?;
    if request_id == [0; 16] || stored_history.is_empty() {
        return Err(HistoryArchiveFrameDataErrorV1::Invalid);
    }
    let length = HISTORY_ARCHIVE_HEADER_BYTES_V1
        .checked_add(stored_history.len())
        .and_then(|bytes| bytes.checked_add(HISTORY_ARCHIVE_TRAILER_BYTES_V1))
        .ok_or(HistoryArchiveFrameDataErrorV1::Invalid)?;
    let mut value = Vec::new();
    value.try_reserve_exact(length)?;
    value.extend_from_slice(magic);
    value.extend_from_slice(&1_u16.to_be_bytes());
    value.extend_from_slice(&request_id);
    value.extend_from_slice(&stored_length.to_be_bytes());
    value.extend_from_slice(stored_history);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(domain)
        .chain_update(&value)
        .finalize()
        .into();
    value.extend_from_slice(&digest);
    Ok(value)
}

/// Borrows the exact stored history from the established checked frame.
///
/// This performs no allocation, journal read or signed Session verification.
/// Actual owners separately check native identity, complete checkpoint/history,
/// protected lineage, currentness and the selected finite signed method.
///
/// # Errors
/// Refuses another identity, magic, version, zero payload, inconsistent length,
/// trailing data or a checksum under another purpose domain.
pub fn open_history_archive_frame_data_v1<'a>(
    request_id: [u8; 16],
    value: &'a [u8],
    magic: &[u8; 8],
    domain: &[u8],
) -> Result<&'a [u8], HistoryArchiveFrameDataErrorV1> {
    let invalid = || HistoryArchiveFrameDataErrorV1::Invalid;
    if request_id == [0; 16]
        || value.len() <= HISTORY_ARCHIVE_HEADER_BYTES_V1 + HISTORY_ARCHIVE_TRAILER_BYTES_V1
        || value.get(..8) != Some(magic.as_slice())
        || value.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
        || value.get(10..26) != Some(request_id.as_slice())
    {
        return Err(invalid());
    }
    let stored_length = u32::from_be_bytes(
        value.get(26..30).ok_or_else(invalid)?.try_into().map_err(|_| invalid())?,
    );
    let stored_length = usize::try_from(stored_length).map_err(|_| invalid())?;
    let stored_end = HISTORY_ARCHIVE_HEADER_BYTES_V1
        .checked_add(stored_length)
        .ok_or_else(invalid)?;
    if stored_length == 0
        || stored_end.checked_add(HISTORY_ARCHIVE_TRAILER_BYTES_V1) != Some(value.len())
    {
        return Err(invalid());
    }
    let actual: [u8; 32] = Sha256::new()
        .chain_update(domain)
        .chain_update(value.get(..stored_end).ok_or_else(invalid)?)
        .finalize()
        .into();
    if value.get(stored_end..) != Some(actual.as_slice()) {
        return Err(invalid());
    }
    value.get(HISTORY_ARCHIVE_HEADER_BYTES_V1..stored_end).ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_frame_preserves_existing_bytes_and_rejects_shape_or_purpose_substitution() {
        let request = [7; 16];
        let payload = b"actual retained stored Session";
        let frame = encode_history_archive_frame_data_v1(request, payload,
            HOST_ARGUMENT_ARCHIVE_MAGIC_V1, HOST_ARGUMENT_ARCHIVE_DOMAIN_V1).unwrap();
        assert_eq!(&frame[..8], b"AOSHAR01");
        assert_eq!(&frame[8..10], &[0, 1]);
        assert_eq!(&frame[10..26], &request);
        assert_eq!(&frame[26..30], &(payload.len() as u32).to_be_bytes());
        assert_eq!(open_history_archive_frame_data_v1(request, &frame,
            HOST_ARGUMENT_ARCHIVE_MAGIC_V1, HOST_ARGUMENT_ARCHIVE_DOMAIN_V1).unwrap(), payload);
        assert!(open_history_archive_frame_data_v1(request, &frame,
            HOST_TERMINAL_ARCHIVE_MAGIC_V1, HOST_TERMINAL_ARCHIVE_DOMAIN_V1).is_err());
        for offset in [0, 8, 10, 26, 30, frame.len() - 1] {
            let mut changed = frame.clone();
            changed[offset] ^= 1;
            assert!(open_history_archive_frame_data_v1(request, &changed,
                HOST_ARGUMENT_ARCHIVE_MAGIC_V1, HOST_ARGUMENT_ARCHIVE_DOMAIN_V1).is_err());
        }
        let mut trailing = frame;
        trailing.push(0);
        assert!(open_history_archive_frame_data_v1(request, &trailing,
            HOST_ARGUMENT_ARCHIVE_MAGIC_V1, HOST_ARGUMENT_ARCHIVE_DOMAIN_V1).is_err());
    }
}
