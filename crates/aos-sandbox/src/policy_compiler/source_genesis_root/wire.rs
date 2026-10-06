//! Bounded data framing for one original Root genesis stream.
//!
//! ```text
//! magic[8] | version:u16=1 | reserved[6] | Root-flight-nonce[16] |
//! fixed phase-specific payload
//! ```
//!
//! Every frame carries the same fresh Root nonce. Decoding any frame produces
//! data only; it cannot adopt an endpoint or create a held Root proof.
//! The selected Project recipe preserves V3 legacy frames and uses V4 only
//! for expanded resource records. Terminal floor commitments remain V3.

use super::controller_readback::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1;
use super::records::{ROOT_SOURCE_GENESIS_INTENT_BYTES_V1, SOURCE_HIERARCHY_FLOOR_BYTES_V1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;

/// Selects the existing normal Root endpoint's bounded genesis flight.
pub const ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1: &[u8; 8] = b"AOSSGQ01";
/// Identifies the actual normal Root flight's initial configuration response.
pub const ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1: &[u8; 8] = b"AOSSGH01";
/// Bounds the canonical per-phase header, including the original flight nonce.
pub const ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1: usize = 32;

/// Selects the existing Root endpoint's closed first-successor purpose.
pub const ROOT_FIRST_SOURCE_SUCCESSOR_QUERY_MAGIC_V2: &[u8; 8] = b"AOSSSQ02";

/// Identifies the first-successor configuration hello on the original flight.
pub const ROOT_FIRST_SOURCE_SUCCESSOR_HELLO_MAGIC_V2: &[u8; 8] = b"AOSSSH02";
/// Selects only the explicit mixed-family successor endpoint recipe.
pub const ROOT_PROJECT_SOURCE_SUCCESSOR_QUERY_MAGIC_V3: &[u8; 8] = b"AOSSSQ03";
/// Identifies the mixed successor hello on the same original endpoint.
pub const ROOT_PROJECT_SOURCE_SUCCESSOR_HELLO_MAGIC_V3: &[u8; 8] = b"AOSSSH03";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum FirstSuccessorWireRecipeV3 { StrictV2, MixedV3 }

impl FirstSuccessorWireRecipeV3 {
    pub(super) const fn version(self) -> u16 {
        match self { Self::StrictV2 => 2, Self::MixedV3 => 3 }
    }

    pub(super) const fn magic(self, phase: RootFirstSourceSuccessorFrameKindV2) -> &'static [u8; 8] {
        if matches!(self, Self::StrictV2) { return phase.magic(); }
        match phase {
            RootFirstSourceSuccessorFrameKindV2::Prepare => b"AOSCFP03",
            RootFirstSourceSuccessorFrameKindV2::Prepared => b"AOSCFI03",
            RootFirstSourceSuccessorFrameKindV2::Anchor => b"AOSCFA03",
            RootFirstSourceSuccessorFrameKindV2::Anchored => b"AOSCFR03",
            RootFirstSourceSuccessorFrameKindV2::Complete => b"AOSCFC03",
            RootFirstSourceSuccessorFrameKindV2::Completed => b"AOSCFD03",
            RootFirstSourceSuccessorFrameKindV2::Finish => b"AOSCFE03",
        }
    }
}

/// Selects one exact first-successor frame, never a genesis or Q04 frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootFirstSourceSuccessorFrameKindV2 {
    /// Supplies the genuine held Controller/Source cut before preparation.
    Prepare,
    /// Returns the exact persisted original admission intent.
    Prepared,
    /// Supplies the genuine Source receipt after its native atomic append.
    Anchor,
    /// Returns the exact revision-two Root floor.
    Anchored,
    /// Supplies the actual Controller Complete and Source ACK join.
    Complete,
    /// Confirms the three exact completion commitments under the Root lock.
    Completed,
    /// Ends the same original flight after its current-ancestry consumer.
    Finish,
}

impl RootFirstSourceSuccessorFrameKindV2 {
    /// Returns the fixed bounded payload width selected by this phase.
    pub const fn payload_bytes(self) -> usize {
        match self {
            Self::Prepare | Self::Anchor | Self::Complete => 2560,
            Self::Prepared => 1248,
            Self::Anchored => 688,
            Self::Completed | Self::Finish => 96,
        }
    }

    pub(super) const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Prepare => b"AOSCFP02",
            Self::Prepared => b"AOSCFI02",
            Self::Anchor => b"AOSCFA02",
            Self::Anchored => b"AOSCFR02",
            Self::Complete => b"AOSCFC02",
            Self::Completed => b"AOSCFD02",
            Self::Finish => b"AOSCFE02",
        }
    }
}

/// Encodes a bounded first-successor frame without creating a live loan.
///
/// # Errors
/// Rejects a zero nonce, changed fixed width, or a populated output slot.
pub fn encode_root_first_source_successor_frame_v2(
    output: &mut Vec<u8>,
    phase: RootFirstSourceSuccessorFrameKindV2,
    nonce: [u8; 16],
    payload: &[u8],
) -> Result<(), SourceGenesisErrorV1> {
    encode_first_successor_with_recipe(output, phase, nonce, payload, FirstSuccessorWireRecipeV3::StrictV2)
}

/// Encodes only the reserved version-three mixed successor purpose.
///
/// # Errors
/// Rejects sentinel nonce, wrong exact width, growth or an occupied output.
pub fn encode_root_project_source_successor_frame_v3(
    output: &mut Vec<u8>, phase: RootFirstSourceSuccessorFrameKindV2,
    nonce: [u8; 16], payload: &[u8],
) -> Result<(), SourceGenesisErrorV1> {
    encode_first_successor_with_recipe(output, phase, nonce, payload, FirstSuccessorWireRecipeV3::MixedV3)
}

pub(super) fn encode_first_successor_with_recipe(
    output: &mut Vec<u8>, phase: RootFirstSourceSuccessorFrameKindV2,
    nonce: [u8; 16], payload: &[u8], recipe: FirstSuccessorWireRecipeV3,
) -> Result<(), SourceGenesisErrorV1> {
    if !output.is_empty() || nonce == [0; 16] || payload.len() != phase.payload_bytes() {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload.len();
    if length > 4096 {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    output.try_reserve_exact(length).map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    output.resize(length, 0);
    write_frame_header(output, recipe.magic(phase), recipe.version(), nonce);
    output[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..].copy_from_slice(payload);
    Ok(())
}

/// Borrows one exact version-two first-successor payload as comparison data.
///
/// # Errors
/// Rejects a foreign purpose, phase, nonce, reserved byte or payload width.
pub fn decode_root_first_source_successor_frame_v2(
    frame: &[u8],
    phase: RootFirstSourceSuccessorFrameKindV2,
    nonce: [u8; 16],
) -> Result<&[u8], SourceGenesisErrorV1> {
    decode_first_successor_with_recipe(frame, phase, nonce, FirstSuccessorWireRecipeV3::StrictV2)
}

/// Borrows the exact reserved version-three mixed successor payload.
///
/// # Errors
/// Rejects strict/foreign purpose, version, nonce, padding or exact width.
pub fn decode_root_project_source_successor_frame_v3(
    frame: &[u8], phase: RootFirstSourceSuccessorFrameKindV2, nonce: [u8; 16],
) -> Result<&[u8], SourceGenesisErrorV1> {
    decode_first_successor_with_recipe(frame, phase, nonce, FirstSuccessorWireRecipeV3::MixedV3)
}

pub(super) fn decode_first_successor_with_recipe(
    frame: &[u8], phase: RootFirstSourceSuccessorFrameKindV2, nonce: [u8; 16], recipe: FirstSuccessorWireRecipeV3,
) -> Result<&[u8], SourceGenesisErrorV1> {
    if frame.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + phase.payload_bytes()
        || frame.len() > 4096
        || !has_frame_header(frame, recipe.magic(phase), recipe.version(), nonce)
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(&frame[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..])
}

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

    const fn resource_magic_v2(self) -> &'static [u8; 8] {
        match self {
            Self::Prepare => b"AOSSGP02",
            Self::Prepared => b"AOSSGI02",
            Self::Anchor => b"AOSSGF02",
            Self::Anchored => b"AOSSGA02",
            Self::Complete => b"AOSSGC02",
            Self::Completed => b"AOSSGD02",
            Self::Finish => b"AOSSGE02",
        }
    }

    pub(in crate::policy_compiler) const fn payload_bytes_for_resource(self, resource: bool) -> usize {
        match self {
            Self::Completed | Self::Finish => self.payload_bytes(),
            _ if resource => self.payload_bytes() + 176,
            _ => self.payload_bytes(),
        }
    }

    pub(super) const fn project_magic_v3(self) -> &'static [u8; 8] {
        match self {
            Self::Prepare => b"AOSSGP03",
            Self::Prepared => b"AOSSGI03",
            Self::Anchor => b"AOSSGF03",
            Self::Anchored => b"AOSSGA03",
            Self::Complete => b"AOSSGC03",
            Self::Completed => b"AOSSGD03",
            Self::Finish => b"AOSSGE03",
        }
    }

    pub(super) const fn project_magic_v4(self) -> &'static [u8; 8] {
        match self {
            Self::Prepare => b"AOSSGP04",
            Self::Prepared => b"AOSSGI04",
            Self::Anchor => b"AOSSGF04",
            Self::Anchored => b"AOSSGA04",
            Self::Complete => b"AOSSGC04",
            Self::Completed => b"AOSSGD04",
            Self::Finish => b"AOSSGE04",
        }
    }

    const fn resource_payload_bytes(self) -> Option<usize> {
        match self {
            Self::Completed | Self::Finish => None,
            _ => Some(self.payload_bytes() + 176),
        }
    }
}

/// Selects only the same endpoint's approval-free mixed initial-project purpose.
pub const ROOT_SOURCE_PROJECT_GENESIS_QUERY_MAGIC_V3: &[u8; 8] = b"AOSSGQ03";
/// Identifies only the selected original mixed initial-project hello.
pub const ROOT_SOURCE_PROJECT_GENESIS_HELLO_MAGIC_V3: &[u8; 8] = b"AOSSGH03";

/// Encodes selected comparison DATA into an already resident bounded frame.
///
/// # Errors
/// Rejects foreign width, sentinel nonce or an occupied output slot.
pub fn encode_root_source_project_genesis_frame_v3(
    output: &mut Vec<u8>, kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16], payload: &[u8],
) -> Result<(), SourceGenesisErrorV1> {
    let resource_version = kind.resource_payload_bytes() == Some(payload.len());
    if !output.is_empty() || nonce == [0; 16]
        || (!resource_version && payload.len() != kind.payload_bytes()) {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload.len();
    output.try_reserve_exact(length).map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    output.resize(length, 0);
    // Completion/Finish retain their shared 32-byte floor commitment recipe.
    // Expanded typed records use the distinct resource header, never padding.
    write_frame_header(output,
        if resource_version { kind.project_magic_v4() } else { kind.project_magic_v3() },
        if resource_version { 4 } else { 3 }, nonce);
    output[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..].copy_from_slice(payload);
    Ok(())
}

/// Borrows an exact selected legacy or full-resource Project phase payload.
///
/// # Errors
/// Rejects old-purpose frames, changed nonce, reserved bytes or fixed width.
pub fn decode_root_source_project_genesis_frame_v3(
    frame: &[u8], kind: RootSourceGenesisFrameKindV1, nonce: [u8; 16],
) -> Result<&[u8], SourceGenesisErrorV1> {
    let header = frame.get(..ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1)
        .ok_or(SourceGenesisErrorV1::NonCanonical)?;
    let payload_bytes = root_source_project_genesis_payload_bytes_v3(header, kind, nonce)?;
    if frame.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload_bytes {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(&frame[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..])
}

/// Selects an exact Project payload width from its original-nonce header DATA.
///
/// This framing check does not authenticate the sender or mint a held proof.
/// Expanded records use V4; terminal floor commitments keep their shared V3
/// recipe and still require the actual original completed owner join.
///
/// # Errors
/// Rejects another purpose, phase, version, nonce, reserved byte or sentinel.
pub fn root_source_project_genesis_payload_bytes_v3(
    header: &[u8], kind: RootSourceGenesisFrameKindV1, nonce: [u8; 16],
) -> Result<usize, SourceGenesisErrorV1> {
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    if has_frame_header(header, kind.project_magic_v3(), 3, nonce) {
        return Ok(kind.payload_bytes());
    }
    if has_frame_header(header, kind.project_magic_v4(), 4, nonce) {
        return kind.resource_payload_bytes().ok_or(SourceGenesisErrorV1::NonCanonical);
    }
    Err(SourceGenesisErrorV1::NonCanonical)
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

/// Encodes an exact strict legacy or full-resource genesis phase as DATA.
///
/// # Errors
/// Rejects a sentinel nonce or a width outside the selected phase recipes.
pub fn encode_root_source_genesis_frame_v2(
    kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, SourceGenesisErrorV1> {
    if payload.len() == kind.payload_bytes() {
        return encode_root_source_genesis_frame_v1(kind, nonce, payload);
    }
    if nonce == [0; 16] || payload.len() != kind.payload_bytes_for_resource(true) {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let mut frame = vec![0; ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload.len()];
    write_frame_header(&mut frame, kind.resource_magic_v2(), 2, nonce);
    frame[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..].copy_from_slice(payload);
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

/// Borrows a strict legacy or full-resource payload after exact framing checks.
///
/// # Errors
/// Rejects foreign purpose, nonce, version, reserved bytes or exact width.
pub fn decode_root_source_genesis_frame_v2(
    frame: &[u8],
    kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16],
) -> Result<&[u8], SourceGenesisErrorV1> {
    if frame.len() == ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + kind.payload_bytes() {
        return decode_root_source_genesis_frame_v1(frame, kind, nonce);
    }
    if frame.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + kind.payload_bytes_for_resource(true)
        || !has_frame_header(frame, kind.resource_magic_v2(), 2, nonce)
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(&frame[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..])
}

pub(in crate::policy_compiler) fn strict_genesis_payload_bytes_from_header(
    header: &[u8], kind: RootSourceGenesisFrameKindV1, nonce: [u8; 16],
) -> Result<usize, SourceGenesisErrorV1> {
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    if has_frame_header(header, kind.magic(), 1, nonce) {
        return Ok(kind.payload_bytes());
    }
    if kind.payload_bytes_for_resource(true) != kind.payload_bytes()
        && has_frame_header(header, kind.resource_magic_v2(), 2, nonce) {
        return Ok(kind.payload_bytes_for_resource(true));
    }
    Err(SourceGenesisErrorV1::NonCanonical)
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
    fn resource_magic(self) -> Option<&'static [u8; 8]> {
        match self {
            Self::SourceObservation => Some(b"AOSQ4O02"),
            Self::SourceRefresh => Some(b"AOSQ4H02"),
            _ => None,
        }
    }

    fn resource_payload_bytes(self) -> Option<usize> {
        match self {
            Self::SourceObservation => Some(crate::policy_compiler::SOURCE_TREE_GENESIS_READBACK_BYTES_V2),
            Self::SourceRefresh => Some(super::controller_readback::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2),
            _ => None,
        }
    }

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

    let resource_magic = kind.resource_magic()
        .filter(|_| kind.resource_payload_bytes() == Some(payload.len()));
    if !output.is_empty() || original_nonce == [0; 16]
        || (resource_magic.is_none() && !kind.require_payload(payload.len())) {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload.len();
    output.try_reserve_exact(length)?;
    output.resize(length, 0);
    write_frame_header(output, resource_magic.unwrap_or(kind.magic()),
        if resource_magic.is_some() { 3 } else { 2 }, original_nonce);
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

    let Some(payload) = frame.get(ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..) else {
        return Err(CreateQ04ErrorV1::ChangedCut);
    };
    let legacy = has_frame_header(frame, kind.magic(), 2, original_nonce)
        && kind.require_payload(payload.len());
    let resource = kind.resource_magic().is_some_and(|magic|
        has_frame_header(frame, magic, 3, original_nonce)
            && kind.resource_payload_bytes() == Some(payload.len()));
    if !legacy && !resource {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    Ok(payload)
}

pub(in crate::policy_compiler) fn q04_genesis_refresh_payload_bytes_from_header(
    header: &[u8], original_nonce: [u8; 16],
) -> Result<usize, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
    use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let kind = RootCreateQ04TransferKindV1::SourceRefresh;
    if has_frame_header(header, kind.magic(), 2, original_nonce) {
        return Ok(CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1);
    }
    if kind.resource_magic().is_some_and(|magic| has_frame_header(header, magic, 3, original_nonce)) {
        return kind.resource_payload_bytes().ok_or(CreateQ04ErrorV1::ChangedCut);
    }
    Err(CreateQ04ErrorV1::ChangedCut)
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
