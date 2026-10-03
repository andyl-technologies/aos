//! Distinct pre-Requested Source closure archives and pure owner comparisons.
//!
//! Copied floor bytes and signed claims are DATA, not admission, never-Issued
//! evidence, current signer eligibility, a Root terminal or pin discharge.
//! The actual Sandbox owner must decode and join its existing Source5 floor.
//!
//! ```text
//! AOSSPL01/envelope9, kind8, state=revision=phase1/2/3:
//! AOSNPC01 | version:u16be=1 | kind:u8=1 | phase:u8 | reserved[4]=0 |
//! F_length:u32be | opaque_F | U_length:u32be=1221 | U |
//! Z_length:u32be=0/1285 | Z | ACK_length:u32be=0/712 | ACK
//! record widths = F+1317 / F+2602 / F+3314
//! ```

use aos_sandbox_source_provider_protocol::{
    PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1, SIGNED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1,
    PreparedSourceNoEscapeClosureV1, SignedSourceNoEscapeClosureV1,
    recovery_pre_requested::{ROOT_NO_ESCAPE_ACK_BYTES_V1, SignedRootNoEscapeAckV1},
};

use super::original_source_owner::OriginalSourceOwnerDataV5;
use crate::ledger::{
    LedgerFormatErrorV1, codec::Decoder, format, model::RecordKind,
    native_held_completion::SourceNativeHeldMutationV1,
};

pub(crate) mod graph;

pub use graph::{
    classify_original_source_pre_requested_cold_v1,
    propose_original_source_pre_requested_closed_v1,
    propose_original_source_pre_requested_closure_stored_v1,
    propose_original_source_pre_requested_root_acknowledged_v1,
    validate_original_source_pre_requested_cold_records_v1,
};

const MAGIC: &[u8; 8] = b"AOSNPC01";
const MINIMUM_FLOOR_DATA_BYTES: usize = 907;
const ENVELOPE_BYTES: usize = 64;
const BODY_HEADER_BYTES: usize = 16;
const LENGTH_FIELD_BYTES: usize = 4;
const PREPARED_FIXED_BYTES: usize = ENVELOPE_BYTES
    + BODY_HEADER_BYTES
    + 4 * LENGTH_FIELD_BYTES
    + PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1;

/// Bounds copied floor DATA without asserting canonicality or membership.
pub const MAXIMUM_SOURCE_PRE_REQUESTED_COLD_FLOOR_DATA_BYTES_V1: usize = 30_413;

/// Fixes each archive phase's encoded width excluding opaque copied floor DATA.
pub const SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1: [usize; 3] = [
    PREPARED_FIXED_BYTES,
    PREPARED_FIXED_BYTES + SIGNED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1,
    PREPARED_FIXED_BYTES + SIGNED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1 + ROOT_NO_ESCAPE_ACK_BYTES_V1,
];

/// Bounds the largest complete envelope9 archive value, excluding its key.
pub const MAXIMUM_SOURCE_PRE_REQUESTED_COLD_ARCHIVE_BYTES_V1: usize =
    SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1[2]
        + MAXIMUM_SOURCE_PRE_REQUESTED_COLD_FLOOR_DATA_BYTES_V1;

const _: () = assert!(SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1[0] == 1317);
const _: () = assert!(SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1[1] == 2602);
const _: () = assert!(SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1[2] == 3314);
const _: () = assert!(MAXIMUM_SOURCE_PRE_REQUESTED_COLD_ARCHIVE_BYTES_V1 == 33_727);

/// Names the three irreversible archive DATA shapes without proving their origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SourcePreRequestedColdPhaseV1 {
    /// The exact unsigned closure and terminal owner commitments are retained.
    ClosedPrepared = 1,
    /// The query-independent signature claim is retained beside its preparation.
    ClosureStored = 2,
    /// A Root acknowledgement claim is retained beside the immutable closure.
    RootAcknowledged = 3,
}

/// Retains bounded pre-Requested closure DATA in a distinct native archive profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePreRequestedColdArchiveV1 {
    initial_source_floor: Vec<u8>,
    prepared: PreparedSourceNoEscapeClosureV1,
    signed: Option<SignedSourceNoEscapeClosureV1>,
    acknowledgement: Option<SignedRootNoEscapeAckV1>,
}

impl SourcePreRequestedColdArchiveV1 {
    /// Constructs a bounded DATA archive without decoding or admitting its floor.
    ///
    /// Signatures remain unverified claims. The acknowledgement's current query,
    /// enrolled role and actual Root terminal are independent owner obligations.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-bound floor capsule, acknowledgement without closure,
    /// substituted preparation or inconsistent stable Source acknowledgement joins.
    pub fn new_untrusted(
        initial_source_floor: Vec<u8>,
        prepared: PreparedSourceNoEscapeClosureV1,
        signed: Option<SignedSourceNoEscapeClosureV1>,
        acknowledgement: Option<SignedRootNoEscapeAckV1>,
    ) -> Result<Self, LedgerFormatErrorV1> {
        if !(MINIMUM_FLOOR_DATA_BYTES..=MAXIMUM_SOURCE_PRE_REQUESTED_COLD_FLOOR_DATA_BYTES_V1)
            .contains(&initial_source_floor.len())
        {
            return Err(LedgerFormatErrorV1::LimitExceeded("cold copied floor DATA"));
        }
        if acknowledgement.is_some() && signed.is_none() {
            return Err(corrupt("cold acknowledgement without closure"));
        }
        if let Some(signed) = &signed {
            if signed.prepared() != &prepared {
                return Err(corrupt("cold signed preparation changed"));
            }
            if let Some(acknowledgement) = &acknowledgement {
                let facts = acknowledgement.facts();
                let claims = prepared.claims();
                if facts.signed_source_archive != signed.digest()
                    || facts.original_root_prepared != claims.original_root_prepared
                    || facts.original_source_floor != claims.original_source_floor
                {
                    return Err(corrupt("cold acknowledgement Source references"));
                }
            }
        }

        Ok(Self {
            initial_source_floor,
            prepared,
            signed,
            acknowledgement,
        })
    }

    /// Decodes only the full envelope9/body1 profile as nonauthorizing DATA.
    ///
    /// All field bounds and the complete body end are checked before cloning
    /// the opaque capsule or allocating nested witnesses.
    ///
    /// # Errors
    ///
    /// Rejects another profile, malformed key/header/digest, mismatched phase,
    /// impossible field lengths, malformed nested claims or noncanonical bytes.
    pub fn from_canonical_bytes(key: &[u8], bytes: &[u8]) -> Result<Self, LedgerFormatErrorV1> {
        if key.len() != 40
            || key.get(..8) != Some(b"AOSNCK02".as_slice())
            || key.get(8..) == Some([0_u8; 32].as_slice())
        {
            return Err(corrupt("cold archive key"));
        }
        if bytes.len() > MAXIMUM_SOURCE_PRE_REQUESTED_COLD_ARCHIVE_BYTES_V1 {
            return Err(LedgerFormatErrorV1::LimitExceeded("cold archive value"));
        }
        let envelope = format::decode_envelope_version(key, bytes, Some(9))?;
        let phase = match envelope.state {
            1 => SourcePreRequestedColdPhaseV1::ClosedPrepared,
            2 => SourcePreRequestedColdPhaseV1::ClosureStored,
            3 => SourcePreRequestedColdPhaseV1::RootAcknowledged,
            _ => return Err(corrupt("cold archive phase")),
        };
        if envelope.revision != u64::from(envelope.state)
            || envelope.body.get(..8) != Some(MAGIC.as_slice())
            || envelope.body.get(8..16)
                != Some([0, 1, 1, envelope.state, 0, 0, 0, 0].as_slice())
        {
            return Err(corrupt("cold archive body header"));
        }

        let mut reader = Decoder::new(envelope.body);
        reader.take(BODY_HEADER_BYTES)?;
        let floor_length =
            reader.bounded_len(MAXIMUM_SOURCE_PRE_REQUESTED_COLD_FLOOR_DATA_BYTES_V1)?;
        if floor_length < MINIMUM_FLOOR_DATA_BYTES {
            return Err(corrupt("cold copied floor DATA width"));
        }
        let floor = reader.take(floor_length)?;
        let prepared_bytes = fixed_field(&mut reader, PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1)?;
        let signed_width = if phase == SourcePreRequestedColdPhaseV1::ClosedPrepared {
            0
        } else {
            SIGNED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1
        };
        let signed_bytes = fixed_field(&mut reader, signed_width)?;
        let acknowledgement_width = if phase == SourcePreRequestedColdPhaseV1::RootAcknowledged {
            ROOT_NO_ESCAPE_ACK_BYTES_V1
        } else {
            0
        };
        let acknowledgement_bytes = fixed_field(&mut reader, acknowledgement_width)?;
        reader.finish()?;

        let prepared = PreparedSourceNoEscapeClosureV1::from_canonical_bytes(prepared_bytes)
            .map_err(|_| corrupt("cold prepared closure format"))?;
        let signed = if signed_width == 0 {
            None
        } else {
            Some(
                SignedSourceNoEscapeClosureV1::from_canonical_bytes(signed_bytes)
                    .map_err(|_| corrupt("cold signed closure format"))?,
            )
        };
        let acknowledgement = if acknowledgement_width == 0 {
            None
        } else {
            Some(
                SignedRootNoEscapeAckV1::from_canonical_bytes(acknowledgement_bytes)
                    .map_err(|_| corrupt("cold acknowledgement format"))?,
            )
        };
        let value = Self::new_untrusted(floor.to_vec(), prepared, signed, acknowledgement)?;
        if super::native_completion_key_v2(value.prepared.claims().acquisition_id) != key
            || value.to_canonical_bytes() != bytes
        {
            return Err(corrupt("cold archive canonical bytes"));
        }

        Ok(value)
    }

    /// Encodes this immutable bounded DATA without creating a journal transaction.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let phase = self.phase() as u8;
        let fixed = SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1[usize::from(phase - 1)];
        let mut body = Vec::with_capacity(fixed + self.initial_source_floor.len() - ENVELOPE_BYTES);
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&[0, 1, 1, phase, 0, 0, 0, 0]);
        append_field(&mut body, &self.initial_source_floor);
        append_field(&mut body, self.prepared.as_canonical_bytes());
        let signed = self
            .signed
            .as_ref()
            .map(SignedSourceNoEscapeClosureV1::to_canonical_bytes);
        append_field(&mut body, signed.as_deref().unwrap_or_default());
        let acknowledgement = self
            .acknowledgement
            .as_ref()
            .map(SignedRootNoEscapeAckV1::to_canonical_bytes);
        append_field(&mut body, acknowledgement.as_deref().unwrap_or_default());

        format::encode_envelope_version(
            RecordKind::NativeCompletion,
            phase,
            u64::from(phase),
            &super::native_completion_key_v2(self.prepared.claims().acquisition_id),
            &body,
            9,
        )
    }

    /// Returns the phase derived from the retained immutable artifact shape.
    #[must_use]
    pub const fn phase(&self) -> SourcePreRequestedColdPhaseV1 {
        if self.acknowledgement.is_some() {
            SourcePreRequestedColdPhaseV1::RootAcknowledged
        } else if self.signed.is_some() {
            SourcePreRequestedColdPhaseV1::ClosureStored
        } else {
            SourcePreRequestedColdPhaseV1::ClosedPrepared
        }
    }

    /// Borrows opaque copied floor DATA for the actual Sandbox owner's typed checks.
    #[must_use]
    pub fn initial_source_floor_bytes(&self) -> &[u8] {
        &self.initial_source_floor
    }

    /// Borrows exact unsigned closure DATA, not a prepared owner token.
    #[must_use]
    pub const fn prepared(&self) -> &PreparedSourceNoEscapeClosureV1 {
        &self.prepared
    }

    /// Borrows the unverified query-independent signature claim.
    #[must_use]
    pub const fn signed(&self) -> Option<&SignedSourceNoEscapeClosureV1> {
        self.signed.as_ref()
    }

    /// Borrows the unverified Root acknowledgement claim.
    #[must_use]
    pub const fn acknowledgement(&self) -> Option<&SignedRootNoEscapeAckV1> {
        self.acknowledgement.as_ref()
    }
}

/// Retains an exact preparation-only retirement quartet without a valid after graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourcePreRequestedRetirementV1 {
    original: OriginalSourceOwnerDataV5,
    mutations: [SourceNativeHeldMutationV1; 4],
}

impl OriginalSourcePreRequestedRetirementV1 {
    pub(super) fn from_parts(
        original: OriginalSourceOwnerDataV5,
        mutations: [SourceNativeHeldMutationV1; 4],
    ) -> Self {
        Self {
            original,
            mutations,
        }
    }

    /// Borrows the validated before graph's Applying comparison DATA.
    #[must_use]
    pub const fn original(&self) -> &OriginalSourceOwnerDataV5 {
        &self.original
    }

    /// Borrows Attempt, Acquisition, Holder and History mutations in semantic order.
    #[must_use]
    pub const fn mutations(&self) -> &[SourceNativeHeldMutationV1; 4] {
        &self.mutations
    }
}

/// Retains one exact cold owner-only proposal without funding or commit authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePreRequestedColdTransactionV1 {
    archive: SourcePreRequestedColdArchiveV1,
    mutations: Vec<SourceNativeHeldMutationV1>,
}

impl SourcePreRequestedColdTransactionV1 {
    /// Returns the checked prospective archive DATA phase.
    #[must_use]
    pub const fn phase(&self) -> SourcePreRequestedColdPhaseV1 {
        self.archive.phase()
    }

    /// Borrows the checked archive DATA, not a current readback.
    #[must_use]
    pub const fn archive(&self) -> &SourcePreRequestedColdArchiveV1 {
        &self.archive
    }

    /// Borrows exact owner PUT mutations in sorted key order.
    #[must_use]
    pub fn mutations(&self) -> &[SourceNativeHeldMutationV1] {
        &self.mutations
    }
}

// A hint selects a decoder only. Every caller must fully decode before skipping
// legacy interpretation; the hint alone is never graph validity or authority.
pub(crate) fn is_cold(bytes: &[u8]) -> bool {
    bytes.get(8..10) == Some(9_u16.to_be_bytes().as_slice())
}

fn fixed_field<'bytes>(
    reader: &mut Decoder<'bytes>,
    expected: usize,
) -> Result<&'bytes [u8], LedgerFormatErrorV1> {
    if reader.u32()? as usize != expected {
        return Err(corrupt("cold fixed artifact width"));
    }
    reader.take(expected)
}

fn append_field(bytes: &mut Vec<u8>, field: &[u8]) {
    // Every field is privately bounded below u32::MAX before retention.
    bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
    bytes.extend_from_slice(field);
}

fn corrupt(reason: &'static str) -> LedgerFormatErrorV1 {
    LedgerFormatErrorV1::Corrupt(reason)
}
