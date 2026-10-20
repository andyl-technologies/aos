//! Encodes the explicit physical-Capture extension of an existing terminal marker.
//!
//! ```text
//! AOSHTC03 || original-terminal-marker:112 || full-AOSCRS02:676 || checksum:32
//! ```
//!
//! The original marker still pins the sole actual terminal Complete and its
//! already settled process admission reservation. These are comparison DATA;
//! only the native same-owner finisher may persist an extension after real
//! Storage completion and independently owed Host posts. No decoder grants
//! permission, releases capacity or converts an unobserved EOF into completion.

use sha2::{Digest as _, Sha256};
use crate::ProtocolValidationError;
use crate::storage_capture_result::{CaptureCompleteRecordDataV2, CAPTURE_COMPLETE_RECORD_BYTES_V2};

/// Fixes the established ordinary execution terminal marker width.
pub const ORIGINAL_TERMINAL_MARKER_BYTES_V3: usize = 112;
/// Bounds the complete versioned Capture extension on that same original key.
pub const CAPTURE_TERMINAL_MARKER_BYTES_V3: usize =
    8 + ORIGINAL_TERMINAL_MARKER_BYTES_V3 + CAPTURE_COMPLETE_RECORD_BYTES_V2 + 32;
const MAGIC: &[u8; 8] = b"AOSHTC03";
const DOMAIN: &[u8] = b"aos.sandbox.host.capture-terminal-marker.v3\0";
const RECORD_START: usize = 8 + ORIGINAL_TERMINAL_MARKER_BYTES_V3;
const CHECKSUM_START: usize = RECORD_START + CAPTURE_COMPLETE_RECORD_BYTES_V2;

/// Borrows one exact ordinary marker or fully checked Capture extension as DATA.
pub struct HostExecutionTerminalMarkerDataV3<'bytes> {
    bytes: &'bytes [u8],
    original: &'bytes [u8; ORIGINAL_TERMINAL_MARKER_BYTES_V3],
    complete: Option<CaptureCompleteRecordDataV2>,
}

impl<'bytes> HostExecutionTerminalMarkerDataV3<'bytes> {
    /// Decodes one exact marker version without native adoption or completion.
    ///
    /// # Errors
    /// Rejects unknown lengths/magic, changed checksum, missing identities or a
    /// full stream result whose settlement differs from original C1 Complete.
    pub fn decode_v3(bytes: &'bytes [u8]) -> Result<Self, ProtocolValidationError> {
        let (original, complete) = match bytes.len() {
            ORIGINAL_TERMINAL_MARKER_BYTES_V3 => (bytes, None),
            CAPTURE_TERMINAL_MARKER_BYTES_V3 => {
                if bytes.get(..8) != Some(MAGIC.as_slice())
                    || bytes.get(CHECKSUM_START..) != Some(checksum(&bytes[..CHECKSUM_START]).as_slice())
                { return Err(invalid()); }
                let record = CaptureCompleteRecordDataV2::decode(&bytes[RECORD_START..CHECKSUM_START])
                    .map_err(|_| invalid())?;
                (&bytes[8..RECORD_START], Some(record))
            }
            _ => return Err(invalid()),
        };
        let original: &[u8; ORIGINAL_TERMINAL_MARKER_BYTES_V3] = original.try_into().map_err(|_| invalid())?;
        // Original byte semantics and offsets stay exactly unchanged.
        if original[..32] == [0; 32] || original[32..48] == [0; 16]
            || original[48..80] == [0; 32] || original[80..112] == [0; 32]
            || complete.as_ref().is_some_and(|record| record.host_settlement_digest.as_bytes() != &original[48..80])
        { return Err(invalid()); }
        Ok(Self { bytes, original, complete })
    }

    /// Borrows the unchanged original process-terminal marker.
    #[must_use]
    pub const fn original_bytes_v3(&self) -> &'bytes [u8; ORIGINAL_TERMINAL_MARKER_BYTES_V3] { self.original }

    /// Borrows genuine-completion comparison DATA only when an extension exists.
    #[must_use]
    pub const fn capture_complete_v3(&self) -> Option<&CaptureCompleteRecordDataV2> { self.complete.as_ref() }

    /// Borrows exact canonical bytes from the caller's original retained storage.
    #[must_use]
    pub const fn canonical_bytes_v3(&self) -> &'bytes [u8] { self.bytes }
}

/// Encodes extension DATA without persisting it or proving native completion.
///
/// # Errors
/// Rejects an extended/foreign predecessor or mismatched complete settlement.
pub fn encode_capture_terminal_marker_data_v3(original: &[u8], complete: CaptureCompleteRecordDataV2)
    -> Result<[u8; CAPTURE_TERMINAL_MARKER_BYTES_V3], ProtocolValidationError> {
    let prior = HostExecutionTerminalMarkerDataV3::decode_v3(original)?;
    if prior.capture_complete_v3().is_some() || original.len() != ORIGINAL_TERMINAL_MARKER_BYTES_V3
        || original.get(48..80) != Some(complete.host_settlement_digest.as_bytes().as_slice())
    { return Err(invalid()); }
    let record = complete.encode().map_err(|_| invalid())?;
    let mut bytes = [0; CAPTURE_TERMINAL_MARKER_BYTES_V3];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..RECORD_START].copy_from_slice(original);
    bytes[RECORD_START..CHECKSUM_START].copy_from_slice(&record);
    let digest = checksum(&bytes[..CHECKSUM_START]);
    bytes[CHECKSUM_START..].copy_from_slice(&digest);
    HostExecutionTerminalMarkerDataV3::decode_v3(&bytes)?;
    Ok(bytes)
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(DOMAIN).chain_update(bytes).finalize().into()
}

fn invalid() -> ProtocolValidationError { ProtocolValidationError::InvalidField("Host Capture terminal marker") }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_preserves_original_marker_and_full_durable_result_exactly() {
        let complete = crate::storage_capture_result::tests::complete();
        let mut original = [1; ORIGINAL_TERMINAL_MARKER_BYTES_V3];
        original[48..80].copy_from_slice(complete.host_settlement_digest.as_bytes());
        let ordinary = HostExecutionTerminalMarkerDataV3::decode_v3(&original).unwrap();
        assert_eq!(ordinary.canonical_bytes_v3(), original);
        assert!(ordinary.capture_complete_v3().is_none());

        let encoded = encode_capture_terminal_marker_data_v3(&original, complete).unwrap();
        let retained = HostExecutionTerminalMarkerDataV3::decode_v3(&encoded).unwrap();
        assert_eq!(retained.original_bytes_v3(), &original);
        assert_eq!(retained.capture_complete_v3(), Some(&complete));
        assert_eq!(retained.canonical_bytes_v3(), encoded);
        assert!(encode_capture_terminal_marker_data_v3(&encoded, complete).is_err());

        for width in 0..encoded.len() {
            if width == ORIGINAL_TERMINAL_MARKER_BYTES_V3 {
                // Legacy112 has no magic. Even a coincidentally valid prefix
                // cannot become Capture completion without the full extension.
                assert!(HostExecutionTerminalMarkerDataV3::decode_v3(&encoded[..width])
                    .is_ok_and(|marker| marker.capture_complete_v3().is_none()));
            } else {
                assert!(HostExecutionTerminalMarkerDataV3::decode_v3(&encoded[..width]).is_err());
            }
        }
        for offset in [0, 8, 56, RECORD_START, CHECKSUM_START] {
            let mut changed = encoded;
            changed[offset] ^= 1;
            assert!(HostExecutionTerminalMarkerDataV3::decode_v3(&changed).is_err());
        }
        original[48] ^= 1;
        assert!(encode_capture_terminal_marker_data_v3(&original, complete).is_err());
        assert!(HostExecutionTerminalMarkerDataV3::decode_v3(&[encoded.as_slice(), &[0]].concat()).is_err());
    }
}
