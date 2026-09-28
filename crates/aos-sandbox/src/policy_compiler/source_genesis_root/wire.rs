//! Bounded data framing for one original Root genesis stream.
//!
//! ```text
//! magic[8] | version:u16=1 | reserved[6] | Root-flight-nonce[16] |
//! fixed phase-specific payload
//! ```
//!
//! Every frame carries the same fresh Root nonce. Decoding any frame produces
//! data only; it cannot adopt an endpoint or create a held Root proof.

use super::controller_readback::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1;
use super::records::{ROOT_SOURCE_GENESIS_INTENT_BYTES_V1, SOURCE_HIERARCHY_FLOOR_BYTES_V1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;

/// Selects the existing normal Root endpoint's bounded genesis flight.
pub const ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1: &[u8; 8] = b"AOSSGQ01";
/// Identifies the actual normal Root flight's initial configuration response.
pub const ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1: &[u8; 8] = b"AOSSGH01";
/// Bounds the canonical per-phase header, including the original flight nonce.
pub const ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1: usize = 32;

/// Identifies a closed phase and its exact nonauthorizing payload width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootSourceGenesisFrameKindV1 {
    /// Supplies an actual Controller signature before Root intent preparation.
    Prepare,
    /// Returns a capacity-backed intent and its current admission expiry.
    Prepared,
    /// Supplies the refreshed actual Controller/Source cut after Source append.
    Anchor,
    /// Returns an exact durable semantic floor, including historical replay.
    Anchored,
    /// Supplies actual final Controller/Source cuts after their durable ACKs.
    Complete,
    /// Confirms the exact anchored Source ACK before ending the original flight.
    Completed,
    /// Acknowledges consumption of Completed before Root releases its writer.
    Finish,
}

impl RootSourceGenesisFrameKindV1 {
    /// Returns the exact bounded payload width for this phase.
    #[must_use]
    pub const fn payload_bytes(self) -> usize {
        match self {
            Self::Prepare | Self::Anchor | Self::Complete => {
                CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1
            }
            Self::Prepared => 8 + ROOT_SOURCE_GENESIS_INTENT_BYTES_V1,
            Self::Anchored => SOURCE_HIERARCHY_FLOOR_BYTES_V1,
            Self::Completed | Self::Finish => 32,
        }
    }

    pub(super) const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Prepare => b"AOSSGP01",
            Self::Prepared => b"AOSSGI01",
            Self::Anchor => b"AOSSGF01",
            Self::Anchored => b"AOSSGA01",
            Self::Complete => b"AOSSGC01",
            Self::Completed => b"AOSSGD01",
            Self::Finish => b"AOSSGE01",
        }
    }
}

/// Encodes one exact phase payload without creating live Root authority.
///
/// # Errors
/// Rejects a zero nonce or a payload with a different phase-specific width.
pub fn encode_root_source_genesis_frame_v1(
    kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, SourceGenesisErrorV1> {
    if nonce == [0; 16] || payload.len() != kind.payload_bytes() {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let mut frame = vec![0; ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload.len()];
    frame[..8].copy_from_slice(kind.magic());
    frame[8..10].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..32].copy_from_slice(&nonce);
    frame[32..].copy_from_slice(payload);
    Ok(frame)
}

/// Borrows a canonical phase payload after exact header and nonce comparison.
///
/// # Errors
/// Rejects a different phase, version, reserved byte, nonce or fixed width.
pub fn decode_root_source_genesis_frame_v1(
    frame: &[u8],
    kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16],
) -> Result<&[u8], SourceGenesisErrorV1> {
    if frame.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + kind.payload_bytes()
        || frame.get(..8) != Some(kind.magic().as_slice())
        || frame[8..10] != 1_u16.to_be_bytes()
        || frame[10..16] != [0; 6]
        || nonce == [0; 16]
        || frame[16..32] != nonce
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(&frame[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_phase_has_exact_width_nonce_and_domain() {
        let kinds = [
            RootSourceGenesisFrameKindV1::Prepare,
            RootSourceGenesisFrameKindV1::Prepared,
            RootSourceGenesisFrameKindV1::Anchor,
            RootSourceGenesisFrameKindV1::Anchored,
            RootSourceGenesisFrameKindV1::Complete,
            RootSourceGenesisFrameKindV1::Completed,
            RootSourceGenesisFrameKindV1::Finish,
        ];
        for kind in kinds {
            let payload = vec![7; kind.payload_bytes()];
            let frame = encode_root_source_genesis_frame_v1(kind, [1; 16], &payload).unwrap();
            assert_eq!(
                decode_root_source_genesis_frame_v1(&frame, kind, [1; 16]).unwrap(),
                payload
            );
            assert!(decode_root_source_genesis_frame_v1(&frame, kind, [2; 16]).is_err());
            assert!(
                decode_root_source_genesis_frame_v1(&frame[..frame.len() - 1], kind, [1; 16])
                    .is_err()
            );
            for other in kinds.into_iter().filter(|other| *other != kind) {
                assert!(decode_root_source_genesis_frame_v1(&frame, other, [1; 16]).is_err());
            }
            for offset in [0, 8, 10, 15, 16, 31] {
                let mut changed = frame.clone();
                changed[offset] ^= 1;
                assert!(decode_root_source_genesis_frame_v1(&changed, kind, [1; 16]).is_err());
            }
        }
    }
}
