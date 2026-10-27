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

use crate::source_genesis_geometry::{
    CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1, CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2,
    ROOT_SOURCE_GENESIS_INTENT_BYTES_V1, SOURCE_HIERARCHY_FLOOR_BYTES_V1,
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1, SOURCE_TREE_GENESIS_READBACK_BYTES_V2,
};

/// Reports malformed or unavailable canonical genesis framing DATA.
#[derive(Debug, thiserror::Error)]
pub enum SourceGenesisWireErrorV1 {
    /// The nonce, purpose, version, padding, width or output state is invalid.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
}

/// Reports Q04 framing refusal while retaining its actual allocation cause.
#[derive(Debug, thiserror::Error)]
pub enum Q04TransferWireErrorV1 {
    /// The original nonce, phase, purpose, padding or exact width changed.
    #[error("the original Q04 continuation cut changed")]
    ChangedCut,
    /// The original output buffer could not reserve its required storage.
    #[error(transparent)]
    Allocation(std::collections::TryReserveError),
}

/// Returns checked bytes for the canonical wire's additional control planes.
///
/// The two forwarding lanes retain nested legacy/resource encoder, decoder and
/// width Results. The remaining lanes cover the closed Q04/header operations
/// and the classifier's actual by-value array iterator. This is a conservative
/// shared control envelope, not a charge for each frame or decoded phase.
///
/// Frame-buffer backing, native owner fields, caller argument carriers and
/// upper diagnostic Result projections belong to their existing payer. A
/// caller includes this envelope once before entering the wire operations and
/// replaces any overlapping local canonical-control quote.
///
/// Returns None if the compiled control-byte sum overflows.
pub fn wire_control_bytes_v1() -> Option<usize> {
    use std::mem::{size_of, size_of_val};

    let genesis_forwarding = [
        size_of::<Result<Vec<u8>, SourceGenesisWireErrorV1>>(),
        size_of::<Result<Vec<u8>, SourceGenesisWireErrorV1>>(),
        size_of::<Result<&[u8], SourceGenesisWireErrorV1>>(),
        size_of::<Result<&[u8], SourceGenesisWireErrorV1>>(),
        size_of::<Result<(), SourceGenesisWireErrorV1>>(),
        size_of::<Result<(), SourceGenesisWireErrorV1>>(),
        size_of::<Result<usize, SourceGenesisWireErrorV1>>(),
        size_of::<Result<usize, SourceGenesisWireErrorV1>>(),
        size_of::<Result<RootSourceGenesisFrameKindV1, SourceGenesisWireErrorV1>>(),
    ];
    let q04_operations = [
        size_of::<Result<(), Q04TransferWireErrorV1>>(),
        size_of::<Result<&[u8], Q04TransferWireErrorV1>>(),
        size_of::<Result<usize, Q04TransferWireErrorV1>>(),
        size_of::<Result<RootCreateQ04TransferKindV1, Q04TransferWireErrorV1>>(),
    ];
    let header_classification = [
        size_of_val(&Q04_TRANSFER_KINDS),
        size_of::<std::array::IntoIter<
            RootCreateQ04TransferKindV1,
            { Q04_TRANSFER_KINDS.len() },
        >>(),
        size_of::<RootCreateQ04TransferKindV1>(),
        size_of::<Option<RootCreateQ04TransferKindV1>>(),
        size_of::<Option<RootSourceGenesisFrameKindV1>>(),
        size_of::<Option<usize>>(),
        size_of::<Option<usize>>(),
        size_of::<Option<&[u8; 8]>>(),
        // Additional private metadata-call arguments and its boolean return.
        size_of::<(&[u8], u16, [u8; 16], bool)>(),
        // The new exact-header entries receive these independent arguments.
        size_of::<(&[u8], [u8; 16])>(),
        size_of::<(&[u8], RootCreateQ04TransferKindV1, [u8; 16], usize)>(),
        // Fixed-width method receiver and the two resource-match booleans.
        size_of::<RootCreateQ04TransferKindV1>(),
        size_of::<bool>(),
        size_of::<bool>(),
    ];

    genesis_forwarding
        .into_iter()
        .chain(q04_operations)
        .chain(header_classification)
        .try_fold(0usize, usize::checked_add)
}

/// Selects the existing normal Root endpoint's bounded genesis flight.
pub const ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1: &[u8; 8] = b"AOSSGQ01";
/// Selects only strict full-resource Global genesis on the existing Root endpoint.
pub const ROOT_SOURCE_RESOURCE_GENESIS_QUERY_MAGIC_V2: &[u8; 8] = b"AOSSGQ02";
/// Identifies the actual normal Root flight's initial configuration response.
pub const ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1: &[u8; 8] = b"AOSSGH01";
/// Bounds the canonical per-phase header, including the original flight nonce.
pub const ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1: usize = 32;
/// Bounds the existing original-flight frame without enlarging its capacity.
pub const ROOT_SOURCE_GENESIS_MAXIMUM_FRAME_BYTES_V1: usize = 4096;

/// Selects the existing Root endpoint's closed first-successor purpose.
pub const ROOT_FIRST_SOURCE_SUCCESSOR_QUERY_MAGIC_V2: &[u8; 8] = b"AOSSSQ02";

/// Identifies the first-successor configuration hello on the original flight.
pub const ROOT_FIRST_SOURCE_SUCCESSOR_HELLO_MAGIC_V2: &[u8; 8] = b"AOSSSH02";
/// Selects only the explicit mixed-family successor endpoint recipe.
pub const ROOT_PROJECT_SOURCE_SUCCESSOR_QUERY_MAGIC_V3: &[u8; 8] = b"AOSSSQ03";
/// Identifies the mixed successor hello on the same original endpoint.
pub const ROOT_PROJECT_SOURCE_SUCCESSOR_HELLO_MAGIC_V3: &[u8; 8] = b"AOSSSH03";

/// Selects strict or mixed framing DATA without selecting a native owner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FirstSuccessorWireRecipeV3 {
    /// Selects the original strict successor frame grammar.
    StrictV2,
    /// Selects the distinct mixed-family successor frame grammar.
    MixedV3,
}

impl FirstSuccessorWireRecipeV3 {
    const fn resource_version(self) -> u16 {
        match self {
            Self::StrictV2 => 4,
            Self::MixedV3 => 5,
        }
    }

    const fn resource_magic(self, phase: RootFirstSourceSuccessorFrameKindV2) -> &'static [u8; 8] {
        match (self, phase) {
            (Self::StrictV2, RootFirstSourceSuccessorFrameKindV2::Prepare) => b"AOSCFP04",
            (Self::StrictV2, RootFirstSourceSuccessorFrameKindV2::Prepared) => b"AOSCFI04",
            (Self::StrictV2, RootFirstSourceSuccessorFrameKindV2::Anchor) => b"AOSCFA04",
            (Self::StrictV2, RootFirstSourceSuccessorFrameKindV2::Complete) => b"AOSCFC04",
            (Self::MixedV3, RootFirstSourceSuccessorFrameKindV2::Prepare) => b"AOSCFP05",
            (Self::MixedV3, RootFirstSourceSuccessorFrameKindV2::Prepared) => b"AOSCFI05",
            (Self::MixedV3, RootFirstSourceSuccessorFrameKindV2::Anchor) => b"AOSCFA05",
            (Self::MixedV3, RootFirstSourceSuccessorFrameKindV2::Complete) => b"AOSCFC05",
            _ => self.magic(phase),
        }
    }

    /// Returns the canonical legacy framing version for this recipe.
    pub const fn version(self) -> u16 {
        match self {
            Self::StrictV2 => 2,
            Self::MixedV3 => 3,
        }
    }

    /// Returns the canonical phase tag for this nonauthorizing recipe.
    pub const fn magic(self, phase: RootFirstSourceSuccessorFrameKindV2) -> &'static [u8; 8] {
        if matches!(self, Self::StrictV2) {
            return phase.magic();
        }
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

    /// Returns the closed full-resource width without granting admission.
    pub const fn payload_bytes_for_resource(self, resource: bool) -> usize {
        if resource
            && matches!(
                self,
                Self::Prepare | Self::Prepared | Self::Anchor | Self::Complete
            )
        {
            self.payload_bytes() + 176
        } else {
            self.payload_bytes()
        }
    }

    /// Returns the canonical comparison frame tag for this phase.
    pub const fn magic(self) -> &'static [u8; 8] {
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
) -> Result<(), SourceGenesisWireErrorV1> {
    encode_first_successor_with_recipe(
        output,
        phase,
        nonce,
        payload,
        FirstSuccessorWireRecipeV3::StrictV2,
    )
}

/// Encodes the closed legacy or full-resource mixed successor recipe.
///
/// # Errors
/// Rejects sentinel nonce, wrong exact width, growth or an occupied output.
pub fn encode_root_project_source_successor_frame_v3(
    output: &mut Vec<u8>,
    phase: RootFirstSourceSuccessorFrameKindV2,
    nonce: [u8; 16],
    payload: &[u8],
) -> Result<(), SourceGenesisWireErrorV1> {
    encode_first_successor_with_recipe(
        output,
        phase,
        nonce,
        payload,
        FirstSuccessorWireRecipeV3::MixedV3,
    )
}

/// Encodes the selected bounded successor grammar as comparison DATA.
///
/// # Errors
/// Refuses a foreign phase, nonce, version, padding, width or occupied output.
pub fn encode_first_successor_with_recipe(
    output: &mut Vec<u8>,
    phase: RootFirstSourceSuccessorFrameKindV2,
    nonce: [u8; 16],
    payload: &[u8],
    recipe: FirstSuccessorWireRecipeV3,
) -> Result<(), SourceGenesisWireErrorV1> {
    let resource = phase.payload_bytes_for_resource(true) != phase.payload_bytes()
        && payload.len() == phase.payload_bytes_for_resource(true);
    if !output.is_empty()
        || nonce == [0; 16]
        || (!resource && payload.len() != phase.payload_bytes())
    {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
    }
    let length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload.len();
    if length > ROOT_SOURCE_GENESIS_MAXIMUM_FRAME_BYTES_V1 {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
    }
    output
        .try_reserve_exact(length)
        .map_err(|_| SourceGenesisWireErrorV1::NonCanonical)?;
    output.resize(length, 0);
    write_frame_header(
        output,
        if resource {
            recipe.resource_magic(phase)
        } else {
            recipe.magic(phase)
        },
        if resource {
            recipe.resource_version()
        } else {
            recipe.version()
        },
        nonce,
    );
    output[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..].copy_from_slice(payload);
    Ok(())
}

/// Borrows a closed legacy or full-resource strict payload as comparison data.
///
/// # Errors
/// Rejects a foreign purpose, phase, nonce, reserved byte or payload width.
pub fn decode_root_first_source_successor_frame_v2(
    frame: &[u8],
    phase: RootFirstSourceSuccessorFrameKindV2,
    nonce: [u8; 16],
) -> Result<&[u8], SourceGenesisWireErrorV1> {
    decode_first_successor_with_recipe(frame, phase, nonce, FirstSuccessorWireRecipeV3::StrictV2)
}

/// Borrows the closed legacy or full-resource mixed successor payload.
///
/// # Errors
/// Rejects strict/foreign purpose, version, nonce, padding or exact width.
pub fn decode_root_project_source_successor_frame_v3(
    frame: &[u8],
    phase: RootFirstSourceSuccessorFrameKindV2,
    nonce: [u8; 16],
) -> Result<&[u8], SourceGenesisWireErrorV1> {
    decode_first_successor_with_recipe(frame, phase, nonce, FirstSuccessorWireRecipeV3::MixedV3)
}

/// Borrows the payload of the selected bounded successor grammar.
///
/// # Errors
/// Refuses a foreign phase, nonce, version, padding, width or occupied output.
pub fn decode_first_successor_with_recipe(
    frame: &[u8],
    phase: RootFirstSourceSuccessorFrameKindV2,
    nonce: [u8; 16],
    recipe: FirstSuccessorWireRecipeV3,
) -> Result<&[u8], SourceGenesisWireErrorV1> {
    let legacy = frame.len() == ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + phase.payload_bytes()
        && has_frame_header(frame, recipe.magic(phase), recipe.version(), nonce);
    let resource = phase.payload_bytes_for_resource(true) != phase.payload_bytes()
        && frame.len()
            == ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + phase.payload_bytes_for_resource(true)
        && has_frame_header(
            frame,
            recipe.resource_magic(phase),
            recipe.resource_version(),
            nonce,
        );
    if frame.len() > ROOT_SOURCE_GENESIS_MAXIMUM_FRAME_BYTES_V1 || (!legacy && !resource) {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
    }
    Ok(&frame[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..])
}

/// Returns a closed full-resource successor body width from framing DATA.
///
/// This performs sizing only. Complete signature and held-owner joins remain
/// mandatory after the complete body arrives on the original stream.
///
/// # Errors
/// Rejects a non-resource purpose, unknown version, nonce or padding.
pub fn root_resource_successor_payload_bytes_v4(
    header: &[u8],
    phase: RootFirstSourceSuccessorFrameKindV2,
    nonce: [u8; 16],
    mixed: bool,
) -> Result<usize, SourceGenesisWireErrorV1> {
    let recipe = if mixed {
        FirstSuccessorWireRecipeV3::MixedV3
    } else {
        FirstSuccessorWireRecipeV3::StrictV2
    };
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
        || phase.payload_bytes_for_resource(true) == phase.payload_bytes()
        || !has_frame_header(
            header,
            recipe.resource_magic(phase),
            recipe.resource_version(),
            nonce,
        )
    {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
    }
    Ok(phase.payload_bytes_for_resource(true))
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

    /// Returns the canonical comparison frame tag for this phase.
    pub const fn magic(self) -> &'static [u8; 8] {
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

    /// Returns the phase width for the legacy or full-resource DATA grammar.
    pub const fn payload_bytes_for_resource(self, resource: bool) -> usize {
        match self {
            Self::Completed | Self::Finish => self.payload_bytes(),
            _ if resource => self.payload_bytes() + 176,
            _ => self.payload_bytes(),
        }
    }

    /// Returns the legacy mixed-Project frame tag for this phase.
    pub const fn project_magic_v3(self) -> &'static [u8; 8] {
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

    /// Returns the full-resource mixed-Project frame tag for this phase.
    pub const fn project_magic_v4(self) -> &'static [u8; 8] {
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
    output: &mut Vec<u8>,
    kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16],
    payload: &[u8],
) -> Result<(), SourceGenesisWireErrorV1> {
    let resource_version = kind.resource_payload_bytes() == Some(payload.len());
    if !output.is_empty()
        || nonce == [0; 16]
        || (!resource_version && payload.len() != kind.payload_bytes())
    {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
    }
    let length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload.len();
    output
        .try_reserve_exact(length)
        .map_err(|_| SourceGenesisWireErrorV1::NonCanonical)?;
    output.resize(length, 0);
    // Completion/Finish retain their shared 32-byte floor commitment recipe.
    // Expanded typed records use the distinct resource header, never padding.
    write_frame_header(
        output,
        if resource_version {
            kind.project_magic_v4()
        } else {
            kind.project_magic_v3()
        },
        if resource_version { 4 } else { 3 },
        nonce,
    );
    output[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..].copy_from_slice(payload);
    Ok(())
}

/// Borrows an exact selected legacy or full-resource Project phase payload.
///
/// # Errors
/// Rejects old-purpose frames, changed nonce, reserved bytes or fixed width.
pub fn decode_root_source_project_genesis_frame_v3(
    frame: &[u8],
    kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16],
) -> Result<&[u8], SourceGenesisWireErrorV1> {
    let header = frame
        .get(..ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1)
        .ok_or(SourceGenesisWireErrorV1::NonCanonical)?;
    let payload_bytes = root_source_project_genesis_payload_bytes_v3(header, kind, nonce)?;
    if frame.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload_bytes {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
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
    header: &[u8],
    kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16],
) -> Result<usize, SourceGenesisWireErrorV1> {
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
    }
    if has_frame_header(header, kind.project_magic_v3(), 3, nonce) {
        return Ok(kind.payload_bytes());
    }
    if has_frame_header(header, kind.project_magic_v4(), 4, nonce) {
        return kind
            .resource_payload_bytes()
            .ok_or(SourceGenesisWireErrorV1::NonCanonical);
    }
    Err(SourceGenesisWireErrorV1::NonCanonical)
}

/// Encodes one exact phase payload without creating live Root authority.
///
/// # Errors
/// Rejects a zero nonce or a payload with a different phase-specific width.
pub fn encode_root_source_genesis_frame_v1(
    kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, SourceGenesisWireErrorV1> {
    if nonce == [0; 16] || payload.len() != kind.payload_bytes() {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
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
) -> Result<Vec<u8>, SourceGenesisWireErrorV1> {
    if payload.len() == kind.payload_bytes() {
        return encode_root_source_genesis_frame_v1(kind, nonce, payload);
    }
    if nonce == [0; 16] || payload.len() != kind.payload_bytes_for_resource(true) {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
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
) -> Result<&[u8], SourceGenesisWireErrorV1> {
    if frame.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + kind.payload_bytes()
        || !has_frame_header(frame, kind.magic(), 1, nonce)
    {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
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
) -> Result<&[u8], SourceGenesisWireErrorV1> {
    if frame.len() == ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + kind.payload_bytes() {
        return decode_root_source_genesis_frame_v1(frame, kind, nonce);
    }
    if frame.len()
        != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + kind.payload_bytes_for_resource(true)
        || !has_frame_header(frame, kind.resource_magic_v2(), 2, nonce)
    {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
    }
    Ok(&frame[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..])
}

/// Selects an allowed legacy genesis reply from an exact original-nonce header.
///
/// This retains the original V1-only gate. A returned phase is comparison DATA;
/// it cannot adopt a stream or create Prepared, Anchored or Completed custody.
///
/// # Errors
/// Refuses non-header input, a non-V1 frame, changed nonce/padding or a phase
/// outside the caller's closed allowed set.
pub fn root_source_genesis_reply_phase_v1(
    header: &[u8],
    allowed: &[RootSourceGenesisFrameKindV1],
    nonce: [u8; 16],
) -> Result<RootSourceGenesisFrameKindV1, SourceGenesisWireErrorV1> {
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
        || !has_frame_metadata(header, 1, nonce)
    {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
    }
    allowed
        .iter()
        .copied()
        .find(|phase| header.get(..8) == Some(phase.magic().as_slice()))
        .ok_or(SourceGenesisWireErrorV1::NonCanonical)
}

/// Bounds a resource-Global phase through the shared strict header validator.
///
/// # Errors
/// Rejects wrong phase, nonce or version, including a shortened resource record.
pub fn root_source_resource_genesis_payload_bytes_v2(
    header: &[u8],
    kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16],
) -> Result<usize, SourceGenesisWireErrorV1> {
    let bytes = strict_genesis_payload_bytes_from_header(header, kind, nonce)?;
    if bytes != kind.payload_bytes_for_resource(true) {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
    }
    Ok(bytes)
}

/// Returns a strict genesis payload width from an exact canonical header.
///
/// # Errors
/// Refuses a foreign phase, nonce, version, padding, width or occupied output.
pub fn strict_genesis_payload_bytes_from_header(
    header: &[u8],
    kind: RootSourceGenesisFrameKindV1,
    nonce: [u8; 16],
) -> Result<usize, SourceGenesisWireErrorV1> {
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 {
        return Err(SourceGenesisWireErrorV1::NonCanonical);
    }
    if has_frame_header(header, kind.magic(), 1, nonce) {
        return Ok(kind.payload_bytes());
    }
    if kind.payload_bytes_for_resource(true) != kind.payload_bytes()
        && has_frame_header(header, kind.resource_magic_v2(), 2, nonce)
    {
        return Ok(kind.payload_bytes_for_resource(true));
    }
    Err(SourceGenesisWireErrorV1::NonCanonical)
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
        && has_frame_metadata(frame, version, nonce)
}

// Both private callers establish a complete header before these exact checks.
fn has_frame_metadata(frame: &[u8], version: u16, nonce: [u8; 16]) -> bool {
    frame[8..10] == version.to_be_bytes()
        && frame[10..16] == [0; 6]
        && nonce != [0; 16]
        && frame[16..32] == nonce
}

/// Names one closed Q04 transfer phase as framing DATA only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootCreateQ04TransferKindV1 {
    /// Selects the preview index payload grammar.
    PreviewIndex,
    /// Selects the preview chunk payload grammar.
    PreviewChunk,
    /// Selects the claim index payload grammar.
    ClaimIndex,
    /// Selects the claim chunk payload grammar.
    ClaimChunk,
    /// Selects the source observation payload grammar.
    SourceObservation,
    /// Selects the source refresh payload grammar.
    SourceRefresh,
    /// Selects the prehold index payload grammar.
    PreholdIndex,
    /// Selects the prehold chunk payload grammar.
    PreholdChunk,
    /// Selects the prehold recipe payload grammar.
    PreholdRecipe,
    /// Selects the decision payload grammar.
    Decision,
    /// Selects the policy acknowledgement payload grammar.
    PolicyAcknowledgement,
    /// Selects the policy accepted payload grammar.
    PolicyAccepted,
    /// Selects the release acknowledgement payload grammar.
    ReleaseAcknowledgement,
    /// Selects the release authorized payload grammar.
    ReleaseAuthorized,
    /// Selects the settlement acknowledgement payload grammar.
    SettlementAcknowledgement,
    /// Selects the settled payload grammar.
    Settled,
    /// Selects the clearance acknowledgement payload grammar.
    ClearanceAcknowledgement,
    /// Selects the final clearance payload grammar.
    FinalClearance,
}

// This closed registry is shared by classification and its control quote.
const Q04_TRANSFER_KINDS: [RootCreateQ04TransferKindV1; 18] = [
    RootCreateQ04TransferKindV1::PreviewIndex,
    RootCreateQ04TransferKindV1::PreviewChunk,
    RootCreateQ04TransferKindV1::ClaimIndex,
    RootCreateQ04TransferKindV1::ClaimChunk,
    RootCreateQ04TransferKindV1::SourceObservation,
    RootCreateQ04TransferKindV1::SourceRefresh,
    RootCreateQ04TransferKindV1::PreholdIndex,
    RootCreateQ04TransferKindV1::PreholdChunk,
    RootCreateQ04TransferKindV1::PreholdRecipe,
    RootCreateQ04TransferKindV1::Decision,
    RootCreateQ04TransferKindV1::PolicyAcknowledgement,
    RootCreateQ04TransferKindV1::PolicyAccepted,
    RootCreateQ04TransferKindV1::ReleaseAcknowledgement,
    RootCreateQ04TransferKindV1::ReleaseAuthorized,
    RootCreateQ04TransferKindV1::SettlementAcknowledgement,
    RootCreateQ04TransferKindV1::Settled,
    RootCreateQ04TransferKindV1::ClearanceAcknowledgement,
    RootCreateQ04TransferKindV1::FinalClearance,
];

impl RootCreateQ04TransferKindV1 {
    /// Returns the distinct full-resource tag when this phase has one.
    #[must_use]
    pub fn resource_magic(self) -> Option<&'static [u8; 8]> {
        match self {
            Self::SourceObservation => Some(b"AOSQ4O02"),
            Self::SourceRefresh => Some(b"AOSQ4H02"),
            _ => None,
        }
    }

    /// Returns the full-resource packet width when this phase has one.
    #[must_use]
    pub fn resource_payload_bytes(self) -> Option<usize> {
        match self {
            Self::SourceObservation => Some(SOURCE_TREE_GENESIS_READBACK_BYTES_V2),
            Self::SourceRefresh => Some(CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2),
            _ => None,
        }
    }

    /// Returns the canonical legacy Q04 phase tag.
    #[must_use]
    pub fn magic(self) -> &'static [u8; 8] {
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

    /// Returns a fixed payload width, or None for an index-bounded chunk.
    ///
    /// This is framing DATA only; a chunk's actual length still requires its
    /// original index/total/count comparison before its consumer accepts it.
    #[must_use]
    pub fn fixed_payload_bytes(self) -> Option<usize> {
        use crate::domain_ledger::create_q04_history::{
            CLAIM_INDEX_BYTES, DECISION_BYTES, PHASE_BYTES, PREHOLD_RESPONSE_BYTES,
            PREVIEW_INDEX_BYTES,
        };

        match self {
            Self::PreviewIndex | Self::PreholdIndex => Some(PREVIEW_INDEX_BYTES),
            Self::ClaimIndex => Some(CLAIM_INDEX_BYTES),
            Self::SourceObservation => Some(SOURCE_TREE_GENESIS_READBACK_BYTES_V1),
            Self::SourceRefresh => Some(CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1),
            Self::PreholdRecipe => Some(PREHOLD_RESPONSE_BYTES),
            Self::Decision => Some(DECISION_BYTES),
            Self::PolicyAcknowledgement | Self::ReleaseAcknowledgement => Some(408),
            Self::SettlementAcknowledgement => Some(600),
            Self::ClearanceAcknowledgement => Some(728),
            Self::PolicyAccepted
            | Self::ReleaseAuthorized
            | Self::Settled
            | Self::FinalClearance => Some(PHASE_BYTES),
            Self::PreviewChunk | Self::ClaimChunk | Self::PreholdChunk => None,
        }
    }

    /// Checks the existing fixed width or nonempty bounded chunk interval.
    #[must_use]
    pub fn require_payload(self, length: usize) -> bool {
        use crate::domain_ledger::create_q04_history::{
            CLAIM_CHUNK_BYTES, CLAIM_CHUNK_PREFIX_BYTES,
        };

        match self.fixed_payload_bytes() {
            Some(expected) => length == expected,
            None => {
                length > CLAIM_CHUNK_PREFIX_BYTES
                    && length <= CLAIM_CHUNK_PREFIX_BYTES + CLAIM_CHUNK_BYTES
            }
        }
    }
}

/// Classifies an exact Q04 header at byte zero of its original frame.
///
/// This compares only bounded framing DATA. It cannot adopt a stream, advance
/// an original flight, verify a Claim, or create a phase or native lender.
///
/// # Errors
/// Refuses a non-header length, foreign tag/version, reserved byte or nonce.
pub fn q04_transfer_kind_from_header_v1(
    header: &[u8],
    original_nonce: [u8; 16],
) -> Result<RootCreateQ04TransferKindV1, Q04TransferWireErrorV1> {
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 {
        return Err(Q04TransferWireErrorV1::ChangedCut);
    }
    for kind in Q04_TRANSFER_KINDS {
        let resource = match kind.resource_magic() {
            Some(magic) => has_frame_header(header, magic, 3, original_nonce),
            None => false,
        };
        if has_frame_header(header, kind.magic(), 2, original_nonce) || resource {
            return Ok(kind);
        }
    }
    Err(Q04TransferWireErrorV1::ChangedCut)
}

/// Checks an actual index-derived payload width against its exact Q04 header.
///
/// Fixed packets and resource packets use the same registry as full decoding.
/// A variable chunk remains bounded here and still requires the consumer's
/// genuine index/total/count comparison. No payload or owner is constructed.
///
/// # Errors
/// Refuses a foreign header, nonce, phase or fixed/resource/chunk width.
pub fn q04_transfer_payload_bytes_from_header_v1(
    header: &[u8],
    kind: RootCreateQ04TransferKindV1,
    original_nonce: [u8; 16],
    expected_payload_bytes: usize,
) -> Result<usize, Q04TransferWireErrorV1> {
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 {
        return Err(Q04TransferWireErrorV1::ChangedCut);
    }
    let legacy = has_frame_header(header, kind.magic(), 2, original_nonce)
        && kind.require_payload(expected_payload_bytes);
    let resource = match kind.resource_magic() {
        Some(magic) => {
            has_frame_header(header, magic, 3, original_nonce)
                && kind.resource_payload_bytes() == Some(expected_payload_bytes)
        }
        None => false,
    };
    if !legacy && !resource {
        return Err(Q04TransferWireErrorV1::ChangedCut);
    }
    Ok(expected_payload_bytes)
}

/// Encodes the closed Q04 transfer grammar into the original output buffer.
///
/// # Errors
/// Refuses invalid framing or an occupied output, and retains the actual
/// allocation error if the original buffer cannot reserve its required storage.
pub fn encode_root_create_q04_transfer_v1(
    output: &mut Vec<u8>,
    kind: RootCreateQ04TransferKindV1,
    original_nonce: [u8; 16],
    payload: &[u8],
) -> Result<(), Q04TransferWireErrorV1> {
    let resource_magic = kind
        .resource_magic()
        .filter(|_| kind.resource_payload_bytes() == Some(payload.len()));
    if !output.is_empty()
        || original_nonce == [0; 16]
        || (resource_magic.is_none() && !kind.require_payload(payload.len()))
    {
        return Err(Q04TransferWireErrorV1::ChangedCut);
    }
    let length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload.len();
    output
        .try_reserve_exact(length)
        .map_err(Q04TransferWireErrorV1::Allocation)?;
    output.resize(length, 0);
    write_frame_header(
        output,
        resource_magic.unwrap_or(kind.magic()),
        if resource_magic.is_some() { 3 } else { 2 },
        original_nonce,
    );
    output[ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..].copy_from_slice(payload);
    Ok(())
}

/// Borrows a Q04 payload after checking its exact phase and original nonce.
///
/// # Errors
/// Refuses a foreign phase, nonce, version, padding, width or occupied output.
pub fn decode_root_create_q04_transfer_v1(
    frame: &[u8],
    kind: RootCreateQ04TransferKindV1,
    original_nonce: [u8; 16],
) -> Result<&[u8], Q04TransferWireErrorV1> {
    let Some(payload) = frame.get(ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1..) else {
        return Err(Q04TransferWireErrorV1::ChangedCut);
    };
    let legacy = has_frame_header(frame, kind.magic(), 2, original_nonce)
        && kind.require_payload(payload.len());
    let resource = kind.resource_magic().is_some_and(|magic| {
        has_frame_header(frame, magic, 3, original_nonce)
            && kind.resource_payload_bytes() == Some(payload.len())
    });
    if !legacy && !resource {
        return Err(Q04TransferWireErrorV1::ChangedCut);
    }
    Ok(payload)
}

/// Returns the exact legacy or resource Q04 refresh payload width.
///
/// # Errors
/// Refuses a foreign phase, nonce, version, padding, width or occupied output.
pub fn q04_genesis_refresh_payload_bytes_from_header(
    header: &[u8],
    original_nonce: [u8; 16],
) -> Result<usize, Q04TransferWireErrorV1> {
    if header.len() != ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 {
        return Err(Q04TransferWireErrorV1::ChangedCut);
    }
    let kind = RootCreateQ04TransferKindV1::SourceRefresh;
    if has_frame_header(header, kind.magic(), 2, original_nonce) {
        return Ok(CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1);
    }
    if kind
        .resource_magic()
        .is_some_and(|magic| has_frame_header(header, magic, 3, original_nonce))
    {
        return kind
            .resource_payload_bytes()
            .ok_or(Q04TransferWireErrorV1::ChangedCut);
    }
    Err(Q04TransferWireErrorV1::ChangedCut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successor_resource_frames_keep_closed_widths_and_legacy_terminals() {
        let phases = [
            RootFirstSourceSuccessorFrameKindV2::Prepare,
            RootFirstSourceSuccessorFrameKindV2::Prepared,
            RootFirstSourceSuccessorFrameKindV2::Anchor,
            RootFirstSourceSuccessorFrameKindV2::Complete,
        ];

        for recipe in [
            FirstSuccessorWireRecipeV3::StrictV2,
            FirstSuccessorWireRecipeV3::MixedV3,
        ] {
            for phase in phases {
                let payload = vec![7; phase.payload_bytes_for_resource(true)];
                let mut frame = Vec::new();
                encode_first_successor_with_recipe(&mut frame, phase, [1; 16], &payload, recipe)
                    .unwrap();

                assert_eq!(&frame[8..10], &recipe.resource_version().to_be_bytes());
                assert_eq!(
                    decode_first_successor_with_recipe(&frame, phase, [1; 16], recipe).unwrap(),
                    payload
                );
                assert!(
                    decode_first_successor_with_recipe(
                        &frame[..frame.len() - 1],
                        phase,
                        [1; 16],
                        recipe
                    )
                    .is_err()
                );
                assert_eq!(
                    root_resource_successor_payload_bytes_v4(
                        &frame[..32],
                        phase,
                        [1; 16],
                        recipe == FirstSuccessorWireRecipeV3::MixedV3
                    )
                    .unwrap(),
                    payload.len()
                );
            }

            let phase = RootFirstSourceSuccessorFrameKindV2::Completed;
            let mut frame = Vec::new();
            encode_first_successor_with_recipe(&mut frame, phase, [1; 16], &[7; 96], recipe)
                .unwrap();
            assert_eq!(&frame[8..10], &recipe.version().to_be_bytes());
            assert!(
                root_resource_successor_payload_bytes_v4(
                    &frame[..32],
                    phase,
                    [1; 16],
                    recipe == FirstSuccessorWireRecipeV3::MixedV3
                )
                .is_err()
            );
        }
    }

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

    #[test]
    fn q04_transfers_keep_original_header_and_closed_version_two_purpose() {
        // These inert payloads test framing only. Source observation and
        // signed Claim authentication belong to their actual owner consumers.
        let kinds = [
            (RootCreateQ04TransferKindV1::PreviewIndex, 48),
            (RootCreateQ04TransferKindV1::PreviewChunk, 96 + 3072),
            (RootCreateQ04TransferKindV1::ClaimIndex, 96),
            (RootCreateQ04TransferKindV1::ClaimChunk, 96 + 1),
            (
                RootCreateQ04TransferKindV1::SourceObservation,
                SOURCE_TREE_GENESIS_READBACK_BYTES_V1,
            ),
            (
                RootCreateQ04TransferKindV1::SourceRefresh,
                CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1,
            ),
            (RootCreateQ04TransferKindV1::PreholdIndex, 48),
            (RootCreateQ04TransferKindV1::PreholdChunk, 96 + 3072),
            (
                RootCreateQ04TransferKindV1::PreholdRecipe,
                crate::domain_ledger::create_q04_history::PREHOLD_RESPONSE_BYTES,
            ),
        ];
        for (kind, width) in kinds {
            let payload = vec![7; width];
            let mut frame = Vec::new();
            encode_root_create_q04_transfer_v1(&mut frame, kind, [1; 16], &payload).unwrap();

            assert_eq!(
                frame.len(),
                ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + width
            );
            assert_eq!(&frame[8..10], &2_u16.to_be_bytes());
            assert_eq!(
                decode_root_create_q04_transfer_v1(&frame, kind, [1; 16]).unwrap(),
                payload
            );
            assert!(decode_root_create_q04_transfer_v1(&frame, kind, [2; 16]).is_err());
            assert!(
                encode_root_create_q04_transfer_v1(&mut frame, kind, [1; 16], &payload).is_err()
            );
            assert!(
                decode_root_source_genesis_frame_v1(
                    &frame,
                    RootSourceGenesisFrameKindV1::Prepare,
                    [1; 16]
                )
                .is_err()
            );

            for offset in [0, 8, 10, 15, 16, 31] {
                let mut changed = frame.clone();
                changed[offset] ^= 1;
                assert!(decode_root_create_q04_transfer_v1(&changed, kind, [1; 16]).is_err());
            }
            if matches!(
                kind,
                RootCreateQ04TransferKindV1::PreviewChunk
                    | RootCreateQ04TransferKindV1::ClaimChunk
                    | RootCreateQ04TransferKindV1::PreholdChunk
            ) {
                assert!(
                    decode_root_create_q04_transfer_v1(&frame[..32 + 96], kind, [1; 16]).is_err()
                );
            } else {
                assert!(
                    decode_root_create_q04_transfer_v1(&frame[..frame.len() - 1], kind, [1; 16])
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn q04_header_classification_keeps_resource_and_chunk_boundaries() {
        let nonce = [9; 16];
        for (kind, width) in [
            (
                RootCreateQ04TransferKindV1::SourceObservation,
                SOURCE_TREE_GENESIS_READBACK_BYTES_V2,
            ),
            (RootCreateQ04TransferKindV1::PolicyAcknowledgement, 408),
            (RootCreateQ04TransferKindV1::ClaimChunk, 97),
        ] {
            let mut frame = Vec::new();
            encode_root_create_q04_transfer_v1(&mut frame, kind, nonce, &vec![7; width]).unwrap();
            let header = &frame[..ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1];

            assert_eq!(
                q04_transfer_kind_from_header_v1(header, nonce).unwrap(),
                kind
            );
            assert_eq!(
                q04_transfer_payload_bytes_from_header_v1(header, kind, nonce, width).unwrap(),
                width
            );
            assert!(
                q04_transfer_payload_bytes_from_header_v1(header, kind, nonce, width - 1).is_err()
            );
            assert!(q04_transfer_kind_from_header_v1(&header[..31], nonce).is_err());
            assert!(q04_transfer_kind_from_header_v1(header, [8; 16]).is_err());
            assert!(
                q04_transfer_payload_bytes_from_header_v1(
                    header,
                    RootCreateQ04TransferKindV1::FinalClearance,
                    nonce,
                    width,
                )
                .is_err()
            );
        }
    }
}
