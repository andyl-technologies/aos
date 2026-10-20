//! Checks Create Storage V1 Open, frame, index and chunk envelope DATA.
//!
//! Every decoder borrows caller-owned input. Encoders return fixed arrays or
//! write no variable storage. These checks do not price receipt or allocation,
//! authenticate peers, validate phase bodies, or restore a current invocation.
//! Native must establish its actual installed receiving supplier before reading
//! or allocating variable input; wire representation limits are not that proof.
//!
//! ```text
//! Open = AOSXPQ01 | ControllerNonce[16] | reserved[8]=0 | lane[16] |
//!        seed[32] | Ready[32]
//! frame = AOSXPF01 | version:u16be=1 | kind:u16be | flags:u32be=0 |
//!         lane[16] | sequence:u64be | payload-length:u32be | reserved[4]=0 |
//!         RootNonce[16] | ControllerNonce[16] | checksum[32] | payload
//! index = total:u64be | count:u32be | reserved:u32be=0 | digest[32]
//! chunk = index:u32be | count:u32be | offset:u64be | length:u32be |
//!         reserved:u32be=0 | payload
//! ```
//!
//! The frame checksum covers its first 80 header bytes and exact payload under
//! the frame domain. Index digest meaning remains with the Native bundle owner:
//! this module never substitutes an invented transfer hash for that commitment.
//! The Q04 chunk engine has different private purpose magic/domains, a 96-byte
//! prefix and `u16` counts. This V1 wire codec reuses its established chunk width,
//! not its authority-specific profiles or an unchecked count conversion.

use sha2::{Digest as _, Sha256};

use super::super::create_q04_history::CLAIM_CHUNK_BYTES;
use super::{HistoryErrorV1, nonzero, reader};

/// Holds the exact nonauthorizing Open query width.
pub const OPEN_BYTES: usize = 112;
/// Holds the exact framed-message header width.
pub const FRAME_HEADER_BYTES: usize = 112;
/// Holds the exact indexed-bundle prefix width.
pub const INDEX_BYTES: usize = 48;
/// Holds the exact transfer-chunk prefix width.
pub const CHUNK_HEADER_BYTES: usize = 24;

const OPEN_MAGIC: &[u8; 8] = b"AOSXPQ01";
const FRAME_MAGIC: &[u8; 8] = b"AOSXPF01";
const FRAME_DOMAIN: &[u8] = b"aos.sandbox.create-storage.frame.v1\0";

/// Carries fixed Open correlation DATA without authenticating a Controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenQueryV1 {
    /// The original persisted Controller nonce, never a renewed permission.
    pub controller_nonce: [u8; 16],
    /// The stable original lane identity.
    pub lane: [u8; 16],
    /// The original Controller Intent correlation commitment.
    pub seed: [u8; 32],
    /// The proposed complete InputsReady commitment, untrusted at receipt.
    pub ready: [u8; 32],
}

impl OpenQueryV1 {
    /// Checks one exact nonauthorizing Open without variable allocation.
    ///
    /// # Errors
    ///
    /// Rejects a wrong magic, zero identity, reserved bytes or nonexact length.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *OPEN_MAGIC {
            return Err(HistoryErrorV1::Malformed);
        }
        let controller_nonce = input.array()?;
        input.zeros(8)?;
        let value = Self {
            controller_nonce,
            lane: input.array()?,
            seed: input.array()?,
            ready: input.array()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Encodes one exact Open without allocation or authority issuance.
    ///
    /// # Errors
    ///
    /// Rejects zero nonces, lane or correlation commitments.
    pub fn encode(self) -> Result<[u8; OPEN_BYTES], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; OPEN_BYTES];
        bytes[..8].copy_from_slice(OPEN_MAGIC);
        bytes[8..24].copy_from_slice(&self.controller_nonce);
        bytes[32..48].copy_from_slice(&self.lane);
        bytes[48..80].copy_from_slice(&self.seed);
        bytes[80..112].copy_from_slice(&self.ready);
        Ok(bytes)
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        nonzero(&self.controller_nonce)?;
        nonzero(&self.lane)?;
        nonzero(&self.seed)?;
        nonzero(&self.ready)
    }
}

/// Selects one closed framed-message kind independently of the Open query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum FrameKindV1 {
    /// Root's original post-Open hello.
    Hello = 1,
    /// The complete Ready bundle's bounded transfer index.
    ReadyIndex = 2,
    /// One contiguous Ready bundle chunk.
    ReadyChunk = 3,
    /// The new independently current pre-use role proofs.
    CurrentProofs = 4,
    /// Root's borrowed current-cut use authorization DATA.
    UseAuthorized = 5,
    /// Controller's preappend use reservation DATA.
    UseReserved = 6,
    /// The independently refreshed proofs over the actual reserved successor.
    UseCurrentProofs = 7,
    /// Root's actual UseAdmitted record and its preexisting inputs.
    UseAdmitted = 8,
    /// The signed result bundle's bounded transfer index.
    SignedIndex = 9,
    /// One contiguous signed result bundle chunk.
    SignedChunk = 10,
    /// Root's exact binding of the already completed signed result.
    SignedBound = 11,
    /// The authenticated outcome bundle's bounded transfer index.
    OutcomeIndex = 12,
    /// One contiguous authenticated outcome bundle chunk.
    OutcomeChunk = 13,
    /// A retained exact authenticated outcome reference.
    OutcomeRecorded = 14,
    /// The existing outcome and held-owner release references.
    ReleaseProofs = 15,
    /// Root's already committed close reference.
    Closed = 16,
    /// A same-original-lane recovery query without renewed authority.
    RecoveryQuery = 17,
    /// A retained same-original-lane recovery response.
    RecoveryState = 18,
    /// Root's invitation after its independent Cache signer half has begun.
    CurrentProofsChallenge = 19,
    /// Root's distinct invitation after its independent reserved-use read.
    UseCurrentProofsChallenge = 20,
    /// Root's actual independently recorded positive outcome acknowledgement.
    RootOutcomeRecorded = 21,
}

impl FrameKindV1 {
    fn decode(code: u16) -> Result<Self, HistoryErrorV1> {
        match code {
            1 => Ok(Self::Hello),
            2 => Ok(Self::ReadyIndex),
            3 => Ok(Self::ReadyChunk),
            4 => Ok(Self::CurrentProofs),
            5 => Ok(Self::UseAuthorized),
            6 => Ok(Self::UseReserved),
            7 => Ok(Self::UseCurrentProofs),
            8 => Ok(Self::UseAdmitted),
            9 => Ok(Self::SignedIndex),
            10 => Ok(Self::SignedChunk),
            11 => Ok(Self::SignedBound),
            12 => Ok(Self::OutcomeIndex),
            13 => Ok(Self::OutcomeChunk),
            14 => Ok(Self::OutcomeRecorded),
            15 => Ok(Self::ReleaseProofs),
            16 => Ok(Self::Closed),
            17 => Ok(Self::RecoveryQuery),
            18 => Ok(Self::RecoveryState),
            19 => Ok(Self::CurrentProofsChallenge),
            20 => Ok(Self::UseCurrentProofsChallenge),
            21 => Ok(Self::RootOutcomeRecorded),
            _ => Err(HistoryErrorV1::Malformed),
        }
    }
}

/// Holds fixed correlation fields without asserting a live session or phase loan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameCoordinatesV1 {
    /// The exact expected closed frame kind.
    pub kind: FrameKindV1,
    /// The stable original lane.
    pub lane: [u8; 16],
    /// The next contiguous observed sequence, maintained by the actual caller.
    pub sequence: u64,
    /// The original Root nonce belonging to this invocation.
    pub root_nonce: [u8; 16],
    /// The original persisted Controller nonce.
    pub controller_nonce: [u8; 16],
}

impl FrameCoordinatesV1 {
    fn validate(self) -> Result<(), HistoryErrorV1> {
        nonzero(&self.lane)?;
        nonzero(&self.root_nonce)?;
        nonzero(&self.controller_nonce)?;
        if self.sequence == 0 {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    /// Encodes a fixed header over an exact borrowed payload without allocation.
    ///
    /// The payload's phase schema and installed receiving demand remain upper.
    ///
    /// # Errors
    ///
    /// Rejects zero coordinates or a payload beyond its `u32` wire width.
    pub fn encode_header(self, payload: &[u8]) -> Result<[u8; FRAME_HEADER_BYTES], HistoryErrorV1> {
        self.validate()?;
        let length = u32::try_from(payload.len()).map_err(|_| HistoryErrorV1::Extent)?;
        let mut bytes = [0; FRAME_HEADER_BYTES];
        bytes[..8].copy_from_slice(FRAME_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10..12].copy_from_slice(&(self.kind as u16).to_be_bytes());
        bytes[16..32].copy_from_slice(&self.lane);
        bytes[32..40].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[40..44].copy_from_slice(&length.to_be_bytes());
        bytes[48..64].copy_from_slice(&self.root_nonce);
        bytes[64..80].copy_from_slice(&self.controller_nonce);
        let checksum = frame_checksum(&bytes[..80], payload);
        bytes[80..112].copy_from_slice(&checksum);
        Ok(bytes)
    }
}

/// Borrows a fully checked frame envelope without validating its phase payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameEnvelopeV1<'a> {
    coordinates: FrameCoordinatesV1,
    payload: &'a [u8],
}

impl<'a> FrameEnvelopeV1<'a> {
    /// Checks exact original lane, kind, nonces, next sequence and framed checksum.
    ///
    /// The caller must supply its next observed coordinates from retained state;
    /// copying an unchecked incoming header into `expected` proves no continuity.
    ///
    /// # Errors
    ///
    /// Rejects unknown fields/kinds, a substituted coordinate, invalid exact
    /// extent, overflow, flags, reserved bytes or complete-frame checksum.
    pub fn decode(bytes: &'a [u8], expected: FrameCoordinatesV1) -> Result<Self, HistoryErrorV1> {
        expected.validate()?;
        let mut input = reader(bytes);
        let (coordinates, length, checksum) = decode_frame_prefix(&mut input, expected)?;
        let payload = input.bytes(length)?;
        input.finish()?;
        if frame_checksum(&bytes[..80], payload) != checksum {
            return Err(HistoryErrorV1::Checksum);
        }
        Ok(Self { coordinates, payload })
    }

    /// Checks fixed correlation fields before reading a bounded variable payload.
    ///
    /// The maximum must come from the caller's already admitted actual purpose.
    /// A successful result checks neither the payload checksum nor its semantics;
    /// the caller must still decode the complete original frame with [`Self::decode`].
    /// No received length is a receiving allowance or a native role proof.
    ///
    /// # Errors
    /// Rejects the same malformed header and substituted coordinates as the
    /// complete decoder, or a payload length above the supplied bound.
    pub fn declared_payload_bytes_v1(
        header: &[u8; FRAME_HEADER_BYTES],
        expected: FrameCoordinatesV1,
        maximum: usize,
    ) -> Result<usize, HistoryErrorV1> {
        expected.validate()?;
        let mut input = reader(header);
        let (_, length, _) = decode_frame_prefix(&mut input, expected)?;
        input.finish()?;
        if length > maximum {
            return Err(HistoryErrorV1::Extent);
        }
        Ok(length)
    }

    /// Returns the checked envelope coordinates without a native phase grant.
    pub const fn coordinates(self) -> FrameCoordinatesV1 {
        self.coordinates
    }

    /// Borrows exact payload bytes without granting their phase interpretation.
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

/// Holds exact indexed-bundle geometry and an opaque original bundle commitment.
///
/// This value is not a receiving allowance. Its total is hostile DATA until the
/// actual Native owner derives and prices the complete nested supplier bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferIndexV1 {
    total: u64,
    count: u32,
    digest: [u8; 32],
}

impl TransferIndexV1 {
    /// Constructs canonical geometry without allocating or choosing a bundle domain.
    ///
    /// # Errors
    ///
    /// Rejects zero total/digest or an unrepresentable canonical chunk count.
    pub fn new(total: u64, digest: [u8; 32]) -> Result<Self, HistoryErrorV1> {
        nonzero(&digest)?;
        if total == 0 {
            return Err(HistoryErrorV1::Extent);
        }
        let width = u64::try_from(CLAIM_CHUNK_BYTES).map_err(|_| HistoryErrorV1::Extent)?;
        let count = u32::try_from(total.div_ceil(width)).map_err(|_| HistoryErrorV1::Extent)?;
        Ok(Self { total, count, digest })
    }

    /// Decodes exact geometry, reserved bytes and the opaque bundle commitment.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical counts, zero fields, reserved bytes or nonexact length.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let total = input.u64()?;
        let count = input.u32()?;
        input.zeros(4)?;
        let value = Self::new(total, input.array()?)?;
        input.finish()?;
        if value.count != count {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(value)
    }

    /// Encodes one exact index without allocation.
    pub fn encode(self) -> [u8; INDEX_BYTES] {
        let mut bytes = [0; INDEX_BYTES];
        bytes[..8].copy_from_slice(&self.total.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.count.to_be_bytes());
        bytes[16..].copy_from_slice(&self.digest);
        bytes
    }

    /// Returns the untrusted complete bundle extent.
    pub const fn total(self) -> u64 {
        self.total
    }

    /// Returns the canonical number of established-width chunks.
    pub const fn count(self) -> u32 {
        self.count
    }

    /// Returns the exact original commitment without authenticating its meaning.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    fn chunk_geometry(self, index: u32) -> Result<(u64, usize), HistoryErrorV1> {
        if index >= self.count {
            return Err(HistoryErrorV1::Correlation);
        }
        let width = u64::try_from(CLAIM_CHUNK_BYTES).map_err(|_| HistoryErrorV1::Extent)?;
        let offset = u64::from(index).checked_mul(width).ok_or(HistoryErrorV1::Extent)?;
        let remaining = self.total.checked_sub(offset).ok_or(HistoryErrorV1::Extent)?;
        let length = usize::try_from(remaining.min(width)).map_err(|_| HistoryErrorV1::Extent)?;
        Ok((offset, length))
    }

    /// Encodes a chunk prefix for an exact borrowed payload without allocation.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-range chunk or a noncanonical payload length.
    pub fn encode_chunk_header(
        self,
        index: u32,
        payload: &[u8],
    ) -> Result<[u8; CHUNK_HEADER_BYTES], HistoryErrorV1> {
        let (offset, length) = self.chunk_geometry(index)?;
        if payload.len() != length {
            return Err(HistoryErrorV1::Extent);
        }
        let length = u32::try_from(length).map_err(|_| HistoryErrorV1::Extent)?;
        let mut bytes = [0; CHUNK_HEADER_BYTES];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.count.to_be_bytes());
        bytes[8..16].copy_from_slice(&offset.to_be_bytes());
        bytes[16..20].copy_from_slice(&length.to_be_bytes());
        Ok(bytes)
    }
}

/// Borrows one canonical transfer chunk without allocating reconstruction storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkEnvelopeV1<'a> {
    index: u32,
    payload: &'a [u8],
}

impl<'a> ChunkEnvelopeV1<'a> {
    /// Checks a chunk against its exact original index and next observed position.
    ///
    /// The caller advances `next_index` only after accepting the complete framed
    /// chunk. The final index digest and nested bundle schema stay with the
    /// Native bundle owner; contiguous geometry alone does not validate them.
    ///
    /// # Errors
    ///
    /// Rejects skipped/repeated indices, count or offset substitution, short or
    /// excessive payloads, reserved bytes, noncanonical final coverage or tails.
    pub fn decode(
        bytes: &'a [u8],
        original: TransferIndexV1,
        next_index: u32,
    ) -> Result<Self, HistoryErrorV1> {
        let (expected_offset, expected_length) = original.chunk_geometry(next_index)?;
        let mut input = reader(bytes);
        let index = input.u32()?;
        let count = input.u32()?;
        let offset = input.u64()?;
        let length = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
        input.zeros(4)?;
        if index != next_index || count != original.count || offset != expected_offset {
            return Err(HistoryErrorV1::Correlation);
        }
        if length != expected_length {
            return Err(HistoryErrorV1::Extent);
        }
        let payload = input.bytes(length)?;
        input.finish()?;
        Ok(Self { index, payload })
    }

    /// Returns the checked original chunk position.
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Borrows the complete exact chunk payload without allocation.
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

// Both staged receipt and complete decoding consume this sole header recipe.
// The complete adapter keeps its original payload/EOF/checksum ordering.
fn decode_frame_prefix(
    input: &mut super::BoundedReader<'_, HistoryErrorV1>,
    expected: FrameCoordinatesV1,
) -> Result<(FrameCoordinatesV1, usize, [u8; 32]), HistoryErrorV1> {
    if input.array::<8>()? != *FRAME_MAGIC || input.u16()? != 1 {
        return Err(HistoryErrorV1::Malformed);
    }
    let kind = FrameKindV1::decode(input.u16()?)?;
    input.zeros(4)?;
    let lane = input.array()?;
    let sequence = input.u64()?;
    let length = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
    input.zeros(4)?;
    let coordinates = FrameCoordinatesV1 {
        kind,
        lane,
        sequence,
        root_nonce: input.array()?,
        controller_nonce: input.array()?,
    };
    if coordinates != expected {
        return Err(HistoryErrorV1::Correlation);
    }
    let checksum: [u8; 32] = input.array()?;
    Ok((coordinates, length, checksum))
}

fn frame_checksum(header_without_checksum: &[u8], payload: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(FRAME_DOMAIN)
        .chain_update(header_without_checksum)
        .chain_update(payload)
        .finalize()
        .into()
}

#[cfg(test)]
mod staged_frame_tests {
    use super::*;

    fn coordinates() -> FrameCoordinatesV1 {
        FrameCoordinatesV1 { kind: FrameKindV1::UseAdmitted, lane: [1; 16],
            sequence: 9, root_nonce: [2; 16], controller_nonce: [3; 16] }
    }

    #[test]
    fn staged_header_bounds_length_without_authenticating_payload() {
        let expected = coordinates();
        let payload = [7; 19];
        let header = expected.encode_header(&payload).expect("fixture header");

        assert_eq!(FrameEnvelopeV1::declared_payload_bytes_v1(&header, expected, 19), Ok(19));
        assert!(matches!(FrameEnvelopeV1::declared_payload_bytes_v1(&header, expected, 18),
            Err(HistoryErrorV1::Extent)));
        let mut complete = header.to_vec();
        complete.extend_from_slice(&payload);
        assert_eq!(FrameEnvelopeV1::decode(&complete, expected).expect("complete").payload(), &payload);

        complete[FRAME_HEADER_BYTES] ^= 1;
        assert_eq!(FrameEnvelopeV1::declared_payload_bytes_v1(&header, expected, 19), Ok(19));
        assert!(matches!(FrameEnvelopeV1::decode(&complete, expected), Err(HistoryErrorV1::Checksum)));
    }

    #[test]
    fn staged_header_uses_exact_original_coordinates_and_reserved_fields() {
        let expected = coordinates();
        let mut header = expected.encode_header(&[7]).expect("fixture header");
        let mut substituted = expected;
        substituted.sequence += 1;

        assert!(matches!(FrameEnvelopeV1::declared_payload_bytes_v1(&header, substituted, 1),
            Err(HistoryErrorV1::Correlation)));
        header[44] = 1;
        assert!(matches!(FrameEnvelopeV1::declared_payload_bytes_v1(&header, expected, 1),
            Err(HistoryErrorV1::Malformed)));
    }
}
