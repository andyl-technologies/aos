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
    write_frame_header(&mut frame, kind.magic(), 1, nonce);
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
        || !has_frame_header(frame, kind.magic(), 1, nonce)
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(&frame[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..])
}

// Both modes use this exact header engine. The ordinary entry retains its
// original infallible allocation and fixed-width checks; Q04 alone lends a
// pre-parked output and selects version two with a closed transfer purpose.
fn write_frame_header(frame: &mut [u8], magic: &[u8; 8], version: u16, nonce: [u8; 16]) {
    frame[..8].copy_from_slice(magic);
    frame[8..10].copy_from_slice(&version.to_be_bytes());
    frame[10..16].fill(0);
    frame[16..32].copy_from_slice(&nonce);
}

fn has_frame_header(frame: &[u8], magic: &[u8; 8], version: u16, nonce: [u8; 16]) -> bool {
    frame.len() >= ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
        && frame.get(..8) == Some(magic.as_slice())
        && frame[8..10] == version.to_be_bytes()
        && frame[10..16] == [0; 6]
        && nonce != [0; 16]
        && frame[16..32] == nonce
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(in crate::policy_compiler) enum RootCreateQ04TransferKindV1 {
    PreviewIndex,
    PreviewChunk,
    ClaimIndex,
    ClaimChunk,
    SourceObservation,
    SourceRefresh,
    PreholdIndex,
    PreholdChunk,
    PreholdRecipe,
    Decision,
    PolicyAcknowledgement,
    PolicyAccepted,
    ReleaseAcknowledgement,
    ReleaseAuthorized,
    SettlementAcknowledgement,
    Settled,
    ClearanceAcknowledgement,
    FinalClearance,
}

#[cfg(target_os = "linux")]
impl RootCreateQ04TransferKindV1 {
    fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::PreviewIndex => b"AOSQ4V01",
            Self::PreviewChunk => b"AOSQ4U01",
            Self::ClaimIndex => b"AOSQ4X01",
            Self::ClaimChunk => b"AOSQ4B01",
            Self::SourceObservation => b"AOSQ4O01",
            Self::SourceRefresh => b"AOSQ4H01",
            Self::PreholdIndex => b"AOSQ4N01",
            Self::PreholdChunk => b"AOSQ4M01",
            Self::PreholdRecipe => b"AOSQ4J01",
            Self::Decision => b"AOSQ4D01",
            Self::PolicyAcknowledgement => b"AOSQ4A01",
            Self::PolicyAccepted => b"AOSQ4P01",
            Self::ReleaseAcknowledgement => b"AOSQ4E01",
            Self::ReleaseAuthorized => b"AOSQ4R01",
            Self::SettlementAcknowledgement => b"AOSQ4T01",
            Self::Settled => b"AOSQ4S01",
            Self::ClearanceAcknowledgement => b"AOSQ4F01",
            Self::FinalClearance => b"AOSQ4Z01",
        }
    }

    fn require_payload(self, length: usize) -> bool {
        use crate::policy_compiler::create_q04::{
            CLAIM_CHUNK_BYTES, CLAIM_CHUNK_PREFIX_BYTES, CLAIM_INDEX_BYTES, PREVIEW_INDEX_BYTES,
        };
        match self {
            Self::PreviewIndex | Self::PreholdIndex => length == PREVIEW_INDEX_BYTES,
            Self::ClaimIndex => length == CLAIM_INDEX_BYTES,
            Self::SourceObservation => {
                length == crate::policy_compiler::SOURCE_TREE_GENESIS_READBACK_BYTES_V1
            }
            Self::SourceRefresh => length == CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1,
            Self::PreholdRecipe => length == crate::policy_compiler::create_q04::PREHOLD_RESPONSE_BYTES,
            Self::Decision => length == crate::policy_compiler::create_q04::DECISION_BYTES,
            Self::PolicyAcknowledgement | Self::ReleaseAcknowledgement => length == 408,
            Self::SettlementAcknowledgement => length == 600,
            Self::ClearanceAcknowledgement => length == 728,
            Self::PolicyAccepted | Self::ReleaseAuthorized | Self::Settled | Self::FinalClearance => {
                length == crate::policy_compiler::create_q04::PHASE_BYTES
            }
            Self::PreviewChunk | Self::ClaimChunk | Self::PreholdChunk => {
                length > CLAIM_CHUNK_PREFIX_BYTES
                    && length <= CLAIM_CHUNK_PREFIX_BYTES + CLAIM_CHUNK_BYTES
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(in crate::policy_compiler) fn encode_root_create_q04_transfer_v1(
    output: &mut Vec<u8>,
    kind: RootCreateQ04TransferKindV1,
    original_nonce: [u8; 16],
    payload: &[u8],
) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
    use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

    if !output.is_empty() || original_nonce == [0; 16] || !kind.require_payload(payload.len()) {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload.len();
    output.try_reserve_exact(length)?;
    output.resize(length, 0);
    write_frame_header(output, kind.magic(), 2, original_nonce);
    output[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..].copy_from_slice(payload);
    Ok(())
}

#[cfg(target_os = "linux")]
pub(in crate::policy_compiler) fn decode_root_create_q04_transfer_v1(
    frame: &[u8],
    kind: RootCreateQ04TransferKindV1,
    original_nonce: [u8; 16],
) -> Result<&[u8], crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
    use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

    if !has_frame_header(frame, kind.magic(), 2, original_nonce)
        || !kind.require_payload(frame.len() - ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1)
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn q04_transfers_keep_original_header_and_closed_version_two_purpose() {
        // These inert payloads test framing only. Source observation and
        // signed Claim authentication belong to their actual owner consumers.
        let kinds = [
            (RootCreateQ04TransferKindV1::PreviewIndex, 48),
            (RootCreateQ04TransferKindV1::PreviewChunk, 96 + 3072),
            (RootCreateQ04TransferKindV1::ClaimIndex, 96),
            (RootCreateQ04TransferKindV1::ClaimChunk, 96 + 1),
            (RootCreateQ04TransferKindV1::SourceObservation,
                crate::policy_compiler::SOURCE_TREE_GENESIS_READBACK_BYTES_V1),
            (RootCreateQ04TransferKindV1::SourceRefresh, CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1),
            (RootCreateQ04TransferKindV1::PreholdIndex, 48),
            (RootCreateQ04TransferKindV1::PreholdChunk, 96 + 3072),
            (RootCreateQ04TransferKindV1::PreholdRecipe, crate::policy_compiler::create_q04::PREHOLD_RESPONSE_BYTES),
        ];
        for (kind, width) in kinds {
            let payload = vec![7; width];
            let mut frame = Vec::new();
            encode_root_create_q04_transfer_v1(&mut frame, kind, [1; 16], &payload).unwrap();

            assert_eq!(frame.len(), ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + width);
            assert_eq!(&frame[8..10], &2_u16.to_be_bytes());
            assert_eq!(decode_root_create_q04_transfer_v1(&frame, kind, [1; 16]).unwrap(), payload);
            assert!(decode_root_create_q04_transfer_v1(&frame, kind, [2; 16]).is_err());
            assert!(encode_root_create_q04_transfer_v1(&mut frame, kind, [1; 16], &payload).is_err());
            assert!(decode_root_source_genesis_frame_v1(&frame, RootSourceGenesisFrameKindV1::Prepare, [1; 16]).is_err());

            for offset in [0, 8, 10, 15, 16, 31] {
                let mut changed = frame.clone();
                changed[offset] ^= 1;
                assert!(decode_root_create_q04_transfer_v1(&changed, kind, [1; 16]).is_err());
            }
            if matches!(kind, RootCreateQ04TransferKindV1::PreviewChunk
                | RootCreateQ04TransferKindV1::ClaimChunk | RootCreateQ04TransferKindV1::PreholdChunk)
            {
                assert!(decode_root_create_q04_transfer_v1(&frame[..32 + 96], kind, [1; 16]).is_err());
            } else {
                assert!(decode_root_create_q04_transfer_v1(&frame[..frame.len() - 1], kind, [1; 16]).is_err());
            }
        }
    }
}
