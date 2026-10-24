//! Canonical Q04 packets and comparison recipes without native authority.
//!
//! The retained ACK, Claim, Preview and Prehold views borrow the original bytes.
//! Their signatures authenticate DATA only. Native Authority, Controller, Source
//! and Cache owners independently retain currentness, accounting and phase.
//!
//! ```text
//! AOSQ4A01/E01/T01/F01 | canonical ACK body | signature[64]
//! AOSQ4L01/N01 | version | reserved | lengths | original fields | signature[64]
//! AOSQ4V01 | version | reserved | lengths | original preview fields
//! ```

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::create_q04_history::{
    CLAIM_CHUNK_BYTES, MAXIMUM_CLAIM_BYTES, Q04CutIdentityV1, Q04HistoryDataErrorV1, chunk_count,
    claim_chunk_count,
};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use ed25519_dalek::Signature;
use sha2::{Digest as _, Sha256};

mod binding;
pub mod challenge;
pub use aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::Q04DataErrorV1 as PolicyQ04DataErrorV1;
pub use aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::*;
pub use binding::*;
mod inert_history;
pub use inert_history::{RootInertHistoryScanV1, require_inert_root_open_history_v1,
    inert_root_open_history_scan_demand_v1, root_history_data_control_bytes_v1};
mod root_records;
mod root_suffix;
pub use root_records::*;
pub use root_suffix::*;

const CLAIM_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.claim.signature.v1\0";
const CLAIM_INDEX_DOMAIN: &[u8] = b"aos.sandbox.create-q04.claim-index.v1\0";
const PREHOLD_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.create-q04.prefund-request.signature.v1\0";
const PREHOLD_REQUEST_DOMAIN: &[u8] = b"aos.sandbox.create-q04.prefund-request.v1\0";
const ORIGINAL_PRECUT_DOMAIN: &[u8] = b"aos.sandbox.create-q04.original-precut.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Q04AcknowledgementKindV1 {
    Policy,
    Release,
    Settlement,
    Clearance,
}

impl Q04AcknowledgementKindV1 {
    pub fn body_bytes(self) -> usize {
        match self {
            Self::Policy | Self::Release => 344,
            Self::Settlement => 536,
            Self::Clearance => 664,
        }
    }

    pub fn phase(self) -> u8 {
        match self {
            Self::Policy => 1,
            Self::Release => 2,
            Self::Settlement => 3,
            Self::Clearance => 4,
        }
    }

    pub fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Policy => b"AOSQ4A01",
            Self::Release => b"AOSQ4E01",
            Self::Settlement => b"AOSQ4T01",
            Self::Clearance => b"AOSQ4F01",
        }
    }

    pub fn signature_domain(self) -> &'static [u8] {
        match self {
            Self::Policy => b"aos.sandbox.create-q04.policy-ack.signature.v1\0",
            Self::Release => b"aos.sandbox.create-q04.release-ack.signature.v1\0",
            Self::Settlement => b"aos.sandbox.create-q04.settlement-ack.signature.v1\0",
            Self::Clearance => b"aos.sandbox.create-q04.clearance-ack.signature.v1\0",
        }
    }
}

// One body recipe serves nonissuing capacity shapes and actual signed ACKs.
// The caller retains the output allocation before this fallible encoding and
// supplies actual current sequence/clear observations only on the live path.
pub fn encode_q04_acknowledgement_data_v1(
    output: &mut Vec<u8>,
    kind: Q04AcknowledgementKindV1,
    identity: &Q04CutIdentityV1,
    controller_sequence: u64,
    consumed_gate: ObjectDigest,
    pairs: [ObjectDigest; 6],
    clear_fields: Option<[ObjectDigest; 4]>,
) -> Result<(), PolicyQ04DataErrorV1> {
    if !output.is_empty() || (kind == Q04AcknowledgementKindV1::Clearance) != clear_fields.is_some()
    {
        return Err(PolicyQ04DataErrorV1::ChangedCut);
    }
    output.try_reserve_exact(kind.body_bytes() + 64)?;
    output.resize(kind.body_bytes(), 0);
    output[16..24].copy_from_slice(&identity.bytes()[88..96]);
    output[24..40].copy_from_slice(&identity.nonce());
    output[40..72].copy_from_slice(identity.digest().as_bytes());
    output[72..76].copy_from_slice(&identity.bytes()[80..84]);
    output[76..84].copy_from_slice(&controller_sequence.to_be_bytes());
    output[84..100].copy_from_slice(identity.operation().as_bytes());
    output[100..116].copy_from_slice(identity.sandbox().as_bytes());
    output[116..124].copy_from_slice(&identity.accepted_generation().to_be_bytes());
    output[128..160].copy_from_slice(identity.desired_precondition().as_bytes());
    output[160..192].copy_from_slice(identity.effect_plan_digest().as_bytes());
    output[192..224].copy_from_slice(identity.binding().as_bytes());
    output[224..232].copy_from_slice(&identity.epoch().to_be_bytes());
    output[232..248].copy_from_slice(&identity.publication_id());
    output[248..280].copy_from_slice(identity.policy_current().as_bytes());
    output[280..312].copy_from_slice(consumed_gate.as_bytes());
    output[312..344].copy_from_slice(identity.gen1_floor().as_bytes());
    if kind.body_bytes() >= 536 {
        for (index, pair) in pairs.into_iter().enumerate() {
            let start = 344 + index * 32;
            output[start..start + 32].copy_from_slice(pair.as_bytes());
        }
    }
    if let Some(fields) = clear_fields {
        for (index, field) in fields.into_iter().enumerate() {
            let start = 536 + index * 32;
            output[start..start + 32].copy_from_slice(field.as_bytes());
        }
    }
    finish_q04_acknowledgement_body_v1(kind, output, identity)
}

// Signature provenance over an original owned packet is comparison DATA.
// Actual current owners, fixed pins and phase/native joins remain separate.
pub struct Q04AcknowledgementV1<'packet> {
    kind: Q04AcknowledgementKindV1,
    bytes: &'packet [u8],
}

impl<'packet> Q04AcknowledgementV1<'packet> {
    pub fn verify(
        kind: Q04AcknowledgementKindV1,
        bytes: &'packet [u8],
        signer: &crate::controller_readback::PinnedControllerHoldSignerV1,
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, PolicyQ04DataErrorV1> {
        if bytes.len() != kind.body_bytes() + 64 {
            return Err(PolicyQ04DataErrorV1::Bounds);
        }
        let body = &bytes[..kind.body_bytes()];
        require_acknowledgement_body(kind, body, identity)?;
        if read_u64(body, 16)? != signer.generation() {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }

        let signature = Signature::from_bytes(&fixed(bytes, kind.body_bytes()));
        signer
            .verifying_key()
            .verify_strict(&acknowledgement_signature_preimage(kind, body)?, &signature)?;
        Ok(Self { kind, bytes })
    }

    pub fn bytes(&self) -> &'packet [u8] {
        self.bytes
    }

    pub fn kind(&self) -> Q04AcknowledgementKindV1 {
        self.kind
    }

    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.bytes).into())
    }

    pub fn controller_sequence(&self) -> u64 {
        u64::from_be_bytes(fixed(self.bytes, 76))
    }
}

// The enclosing original owner already parks this exact body buffer. The
// helper borrows it through validation/allocation/signing, including failure;
// it does not consume a packet into a callee-local Result or mint live custody.

pub fn prepare_q04_acknowledgement_v1(
    kind: Q04AcknowledgementKindV1,
    body: &mut Vec<u8>,
    identity: &Q04CutIdentityV1,
) -> Result<Vec<u8>, PolicyQ04DataErrorV1> {
    finish_q04_acknowledgement_body_v1(kind, body, identity)?;

    let preimage = acknowledgement_signature_preimage(kind, body)?;
    body.try_reserve_exact(64)?;
    Ok(preimage)
}

// The caller retains this named preimage through the append, as before.
// Capacity and every fallible preparation step have already completed.

// The same body/header checks may advise fixed-width future capacity DATA.
// Only the real signer above appends an authentic signature; body formation
// does not produce an acknowledgement, permission or positive observation.
pub fn finish_q04_acknowledgement_body_v1(
    kind: Q04AcknowledgementKindV1,
    body: &mut Vec<u8>,
    identity: &Q04CutIdentityV1,
) -> Result<(), PolicyQ04DataErrorV1> {
    if body.len() != kind.body_bytes() {
        return Err(PolicyQ04DataErrorV1::Bounds);
    }
    body[..8].copy_from_slice(kind.magic());
    body[8..10].copy_from_slice(&1_u16.to_be_bytes());
    body[10] = kind.phase();
    body[11..16].fill(0);
    require_acknowledgement_body(kind, body, identity)?;

    Ok(())
}

pub fn require_acknowledgement_body(
    kind: Q04AcknowledgementKindV1,
    body: &[u8],
    identity: &Q04CutIdentityV1,
) -> Result<(), PolicyQ04DataErrorV1> {
    if body.len() != kind.body_bytes()
        || body[..8] != *kind.magic()
        || body[8..10] != 1_u16.to_be_bytes()
        || body[10] != kind.phase()
        || body[11..16] != [0; 5]
        || body[16..24] != identity.bytes()[88..96]
        || body[24..40] != identity.nonce()
        || body[40..72] != *identity.digest().as_bytes()
        || body[72..76] != identity.bytes()[80..84]
        || read_u64(body, 76)? == 0
        || body[84..100] != *identity.operation().as_bytes()
        || body[100..116] != *identity.sandbox().as_bytes()
        || body[116..124] != identity.accepted_generation().to_be_bytes()
        || body[124..128] != [0; 4]
        || body[128..160] != identity.bytes()[232..264]
        || body[160..192] != identity.bytes()[264..296]
        || body[192..224] != *identity.binding().as_bytes()
        || body[224..232] != identity.epoch().to_be_bytes()
        || body[232..248] != identity.publication_id()
        || body[248..280] != *identity.policy_current().as_bytes()
        || nonzero::<32>(body, 280).is_err()
        || body[312..344] != *identity.gen1_floor().as_bytes()
    {
        return Err(PolicyQ04DataErrorV1::ChangedCut);
    }

    if matches!(
        kind,
        Q04AcknowledgementKindV1::Settlement | Q04AcknowledgementKindV1::Clearance
    ) {
        for offset in (344..536).step_by(32) {
            nonzero::<32>(body, offset)?;
        }
    }
    if kind == Q04AcknowledgementKindV1::Clearance {
        for offset in (536..664).step_by(32) {
            nonzero::<32>(body, offset)?;
        }
    }
    Ok(())
}

pub fn acknowledgement_signature_preimage(
    kind: Q04AcknowledgementKindV1,
    body: &[u8],
) -> Result<Vec<u8>, PolicyQ04DataErrorV1> {
    signed_record_preimage(kind.signature_domain(), body)
}

pub fn signed_record_preimage(domain: &[u8], body: &[u8]) -> Result<Vec<u8>, PolicyQ04DataErrorV1> {
    let size = domain
        .len()
        .checked_add(body.len())
        .ok_or(PolicyQ04DataErrorV1::Bounds)?;
    let mut preimage = Vec::new();
    preimage.try_reserve_exact(size)?;
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(body);
    Ok(preimage)
}

// The view borrows the actual parked complete packet. Neither decode nor
// signature verification owns the writers, supplies currentness or admits a
// project. Root's same-flight consumer repeats those independent joins.
pub struct Q04ClaimV1<'packet> {
    bytes: &'packet [u8],
    fields: [&'packet [u8]; CLAIM_FIELDS],
}

impl<'packet> Q04ClaimV1<'packet> {
    pub fn decode(
        bytes: &'packet [u8],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, PolicyQ04DataErrorV1> {
        if bytes.len() < CLAIM_PREFIX_BYTES + 64 || bytes.len() > MAXIMUM_CLAIM_BYTES {
            return Err(PolicyQ04DataErrorV1::Bounds);
        }
        let fields = claim_body_fields(&bytes[..bytes.len() - 64], identity)?;
        Ok(Self { bytes, fields })
    }

    pub fn verify(
        bytes: &'packet [u8],
        signer: &crate::controller_readback::PinnedControllerHoldSignerV1,
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, PolicyQ04DataErrorV1> {
        let claim = Self::decode(bytes, identity)?;
        if identity.bytes()[88..96] != signer.generation().to_be_bytes() {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }
        let signature_offset = bytes.len() - 64;
        let signature = Signature::from_bytes(&fixed(bytes, signature_offset));
        signer
            .verifying_key()
            .verify_strict(
                &signed_record_preimage(CLAIM_SIGNATURE_DOMAIN, &bytes[..signature_offset])?,
                &signature,
            )
            .map_err(PolicyQ04DataErrorV1::ClaimSignature)?;
        Ok(claim)
    }

    pub fn fields(&self) -> &[&'packet [u8]; CLAIM_FIELDS] {
        &self.fields
    }

    pub fn bytes(&self) -> &'packet [u8] {
        self.bytes
    }
}

// The caller parks this buffer before the first allocation. Only unsigned
// DATA is constructed here; each existing field codec remains responsible
// for its canonical format and independently authenticated semantic checks.
pub fn encode_q04_claim_body_v1(
    body: &mut Vec<u8>,
    fields: [&[u8]; CLAIM_FIELDS],
    identity: &Q04CutIdentityV1,
) -> Result<(), PolicyQ04DataErrorV1> {
    if !body.is_empty() {
        return Err(PolicyQ04DataErrorV1::ChangedCut);
    }
    require_claim_field_bounds(&fields, identity)?;
    encode_length_prefixed_fields(body, b"AOSQ4L01", fields, MAXIMUM_CLAIM_BYTES - 64)?;
    claim_body_fields(body, identity)?;
    Ok(())
}

pub fn prepare_q04_claim_v1(
    body: &mut Vec<u8>,
    identity: &Q04CutIdentityV1,
) -> Result<Vec<u8>, PolicyQ04DataErrorV1> {
    claim_body_fields(body, identity)?;
    let preimage = signed_record_preimage(CLAIM_SIGNATURE_DOMAIN, body)?;
    body.try_reserve_exact(64)?;
    Ok(preimage)
}

pub fn claim_body_fields<'body>(
    body: &'body [u8],
    identity: &Q04CutIdentityV1,
) -> Result<[&'body [u8]; CLAIM_FIELDS], PolicyQ04DataErrorV1> {
    if body.len() < CLAIM_PREFIX_BYTES
        || body
            .len()
            .checked_add(64)
            .is_none_or(|size| size > MAXIMUM_CLAIM_BYTES)
        || body[..8] != *b"AOSQ4L01"
        || body[8..10] != 1_u16.to_be_bytes()
        || body[10..16] != [0; 6]
    {
        return Err(PolicyQ04DataErrorV1::Bounds);
    }

    let fields = decode_length_prefixed_fields(body)?;
    require_claim_field_bounds(&fields, identity)?;
    Ok(fields)
}

pub fn require_claim_field_bounds(
    fields: &[&[u8]; CLAIM_FIELDS],
    identity: &Q04CutIdentityV1,
) -> Result<(), PolicyQ04DataErrorV1> {
    if fields.iter().any(|field| field.is_empty())
        || fields[..7].iter().any(|field| field.len() > 64 * 1024)
        || fields[7].len() > 3 * 1024
        || fields[8].len() != CLOSED_POLICY_BINDING_BYTES_V2
        || fields[9].len() != crate::controller_project_readback::CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1
        || fields[10].len()
            != crate::controller_readback::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1
        || !matches!(
            fields[11].len(),
            aos_sandbox_protocol::source_genesis_geometry::SOURCE_TREE_GENESIS_READBACK_BYTES_V1
                | aos_sandbox_protocol::source_genesis_geometry::SOURCE_TREE_GENESIS_READBACK_BYTES_V2
        )
        || fields[12].len() != aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BYTES_V2
        || fields[13] != identity.bytes()
    {
        return Err(PolicyQ04DataErrorV1::ChangedCut);
    }
    Ok(())
}

// This recipe borrows the same complete parked Claim. It owns only the fixed
// index DATA; it cannot replace native membership, signature or currentness.
pub struct Q04ClaimStorageRecipeV1<'packet> {
    claim: &'packet [u8],
    index: [u8; CLAIM_INDEX_BYTES],
}

impl<'packet> Q04ClaimStorageRecipeV1<'packet> {
    pub fn new(
        claim: &Q04ClaimV1<'packet>,
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, PolicyQ04DataErrorV1> {
        if claim.fields()[13] != identity.bytes() {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }
        let count = claim_chunk_count(claim.bytes().len())?;
        let total = u32::try_from(claim.bytes().len()).map_err(|_| PolicyQ04DataErrorV1::Bounds)?;

        let mut index = [0; CLAIM_INDEX_BYTES];
        index[..8].copy_from_slice(b"AOSQ4X01");
        index[8..10].copy_from_slice(&1_u16.to_be_bytes());
        index[16..48].copy_from_slice(identity.digest().as_bytes());
        index[48..52].copy_from_slice(&total.to_be_bytes());
        index[52..54].copy_from_slice(&count.to_be_bytes());
        let digest = Sha256::new()
            .chain_update(CLAIM_INDEX_DOMAIN)
            .chain_update(&index[..64])
            .chain_update(claim.bytes())
            .finalize();
        index[64..96].copy_from_slice(&digest);
        Ok(Self {
            claim: claim.bytes(),
            index,
        })
    }

    // There is intentionally no header-only digest verification. The
    // comparison includes every byte of the reconstructed signed Claim.
    pub fn verify_index(
        bytes: &[u8],
        claim: &Q04ClaimV1<'packet>,
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, PolicyQ04DataErrorV1> {
        let recipe = Self::new(claim, identity)?;
        if bytes != recipe.index.as_slice() {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }
        Ok(recipe)
    }

    pub fn index_bytes(&self) -> &[u8; CLAIM_INDEX_BYTES] {
        &self.index
    }

    pub fn chunk_count(&self) -> u16 {
        u16::from_be_bytes(fixed(&self.index, 52))
    }

    // The caller parks the output before this first possible allocation. All
    // chunk fields derive from the one immutable original packet, not a second
    // copy, callback or caller-supplied digest/count.
    pub fn encode_chunk(
        &self,
        chunk: u16,
        output: &mut Vec<u8>,
    ) -> Result<(), PolicyQ04DataErrorV1> {
        if !output.is_empty() {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }
        Q04ChunkPurposeV1::Claim.encode_chunk(self.claim, fixed(&self.index, 16), chunk, output)
    }
}

pub struct Q04ClaimChunkV1<'chunk> {
    chunk: Q04OrderedChunkV1<'chunk>,
}

impl<'chunk> Q04ClaimChunkV1<'chunk> {
    pub fn decode(
        bytes: &'chunk [u8],
        original_index: &[u8],
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, PolicyQ04DataErrorV1> {
        let (indexed_total, indexed_count) = claim_index_shape(original_index, identity)?;
        let chunk = Q04ChunkPurposeV1::Claim.decode_chunk(
            bytes,
            *identity.digest().as_bytes(),
            indexed_total,
            indexed_count,
        )?;
        Ok(Self { chunk })
    }

    // Original chunk order and exact offsets are checked before growing the
    // caller-owned reconstruction. Complete index/signature checks follow.
    pub fn append_to(&self, output: &mut Vec<u8>) -> Result<(), PolicyQ04DataErrorV1> {
        self.chunk.append_to(output)
    }
}

// Reading the fixed index's shape only bounds reconstruction. Its final
// digest is deliberately not verified until the complete Claim is present.
/// Reads the fixed Claim index shape before reconstruction.
///
/// # Errors
/// Returns a bounds error when the framing, identity, or chunk count differs.
pub fn claim_index_shape(
    bytes: &[u8],
    identity: &Q04CutIdentityV1,
) -> Result<(usize, u16), PolicyQ04DataErrorV1> {
    if bytes.len() != CLAIM_INDEX_BYTES
        || bytes[..8] != *b"AOSQ4X01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[16..48] != *identity.digest().as_bytes()
        || bytes[54..64] != [0; 10]
    {
        return Err(PolicyQ04DataErrorV1::Bounds);
    }
    let total = usize::try_from(read_u32(bytes, 48)?).map_err(|_| PolicyQ04DataErrorV1::Bounds)?;
    let count = u16::from_be_bytes(fixed(bytes, 52));
    if count != claim_chunk_count(total)? {
        return Err(PolicyQ04DataErrorV1::Bounds);
    }
    Ok((total, count))
}

pub struct Q04PreholdInputDataV1<'packet> {
    bytes: &'packet [u8],
    fields: [&'packet [u8]; PREHOLD_FIELDS],
}

impl<'packet> Q04PreholdInputDataV1<'packet> {
    pub fn decode(bytes: &'packet [u8]) -> Result<Self, PolicyQ04DataErrorV1> {
        if bytes.len() < PREHOLD_PREFIX_BYTES + 64 || bytes.len() > MAXIMUM_PREHOLD_BYTES {
            return Err(PolicyQ04DataErrorV1::Bounds);
        }
        let fields = prehold_body_fields(&bytes[..bytes.len() - 64])?;
        Ok(Self { bytes, fields })
    }

    pub fn verify(
        bytes: &'packet [u8],
        signer: &crate::controller_readback::PinnedControllerHoldSignerV1,
    ) -> Result<Self, PolicyQ04DataErrorV1> {
        let request = Self::decode(bytes)?;
        if read_u64(request.fields[0], 32)? != signer.generation() {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }
        let signature_offset = bytes.len() - 64;
        let signature = Signature::from_bytes(&fixed(bytes, signature_offset));
        signer
            .verifying_key()
            .verify_strict(
                &signed_record_preimage(PREHOLD_SIGNATURE_DOMAIN, &bytes[..signature_offset])?,
                &signature,
            )
            .map_err(PolicyQ04DataErrorV1::PreholdSignature)?;
        Ok(request)
    }

    pub fn fields(&self) -> &[&'packet [u8]; PREHOLD_FIELDS] {
        &self.fields
    }

    pub fn bytes(&self) -> &'packet [u8] {
        self.bytes
    }

    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(PREHOLD_REQUEST_DOMAIN)
                .chain_update(self.bytes)
                .finalize()
                .into(),
        )
    }
}

pub fn encode_q04_prehold_body_v1(
    output: &mut Vec<u8>,
    fields: [&[u8]; PREHOLD_FIELDS],
) -> Result<(), PolicyQ04DataErrorV1> {
    if !output.is_empty() {
        return Err(PolicyQ04DataErrorV1::ChangedCut);
    }
    require_prehold_fields(&fields)?;
    encode_length_prefixed_fields(output, b"AOSQ4N01", fields, MAXIMUM_PREHOLD_BYTES - 64)?;
    prehold_body_fields(output)?;
    Ok(())
}

// Only the genuine private Controller donor invokes this DATA serializer.
// The actual buffer is resident before allocation/signing; all original
// ledger/current-source/name/clock bookends remain in that donor and caller.

pub fn prepare_q04_prehold_body_v1(output: &mut Vec<u8>) -> Result<Vec<u8>, PolicyQ04DataErrorV1> {
    prehold_body_fields(output)?;
    let preimage = signed_record_preimage(PREHOLD_SIGNATURE_DOMAIN, output)?;
    output.try_reserve_exact(64)?;
    Ok(preimage)
}

pub fn prehold_body_fields(body: &[u8]) -> Result<[&[u8]; PREHOLD_FIELDS], PolicyQ04DataErrorV1> {
    if body.len() < PREHOLD_PREFIX_BYTES
        || body
            .len()
            .checked_add(64)
            .is_none_or(|size| size > MAXIMUM_PREHOLD_BYTES)
        || body[..8] != *b"AOSQ4N01"
        || body[8..10] != 1_u16.to_be_bytes()
        || body[10..16] != [0; 6]
    {
        return Err(PolicyQ04DataErrorV1::Bounds);
    }
    let fields = decode_length_prefixed_fields(body)?;
    require_prehold_fields(&fields)?;
    Ok(fields)
}

pub fn require_prehold_fields(
    fields: &[&[u8]; PREHOLD_FIELDS],
) -> Result<(), PolicyQ04DataErrorV1> {
    if fields[0].len() != PREHOLD_METADATA_BYTES
        || fields[1..4]
            .iter()
            .any(|field| field.is_empty() || field.len() > 64 * 1024)
        || fields[4].len() != CLOSED_POLICY_BINDING_BYTES_V2
        || fields[5].len()
            != crate::controller_project_readback::CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1
    {
        return Err(PolicyQ04DataErrorV1::Bounds);
    }
    let metadata = fields[0];
    if nonzero::<16>(metadata, 0).is_err()
        || read_u64(metadata, 24)?.checked_sub(read_u64(metadata, 16)?) != Some(60_000_000_000)
        || read_u64(metadata, 32)? == 0
        || read_u64(metadata, 40)? != 1
        || (48..176)
            .step_by(32)
            .any(|offset| nonzero::<32>(metadata, offset).is_err())
        || (464..512)
            .step_by(8)
            .any(|offset| read_u64(metadata, offset).map_or(true, |value| value == 0))
    {
        return Err(PolicyQ04DataErrorV1::ChangedCut);
    }
    for offset in (176..464).step_by(48) {
        ProtectedJournalNamesV1::from_bytes(&metadata[offset..offset + 48])
            .map_err(PolicyQ04DataErrorV1::from)?;
    }
    Ok(())
}

// The exact sixteen-tag whitelist excludes request signatures, B664/CTP03,
// Stage fields, new transaction IDs and all own-future publication heads.
// Hashing the full request here would reintroduce Tli's identity cycle.
pub fn q04_original_precut_digest_v1(
    request: &Q04PreholdInputDataV1<'_>,
    preview: &Q04PreviewV1<'_>,
    controller_complete: &[u8],
    source_observation: &[u8],
    state_names: ProtectedJournalNamesV1,
    state_sequence: u64,
) -> Result<ObjectDigest, PolicyQ04DataErrorV1> {
    require_genesis_observation_pair_widths(controller_complete, source_observation)?;
    if state_sequence == 0 {
        return Err(PolicyQ04DataErrorV1::Bounds);
    }
    let original = request.fields();
    let preview = preview.fields();
    let names = state_names.to_bytes();
    let sequence = state_sequence.to_be_bytes();
    let fields = [
        original[0],
        original[1],
        original[2],
        original[3],
        preview[2],
        preview[3],
        preview[4],
        preview[5],
        preview[6],
        preview[7],
        preview[8],
        controller_complete,
        source_observation,
        preview[0],
        &names,
        &sequence,
    ];
    let mut digest = Sha256::new().chain_update(ORIGINAL_PRECUT_DOMAIN);
    for (index, field) in fields.into_iter().enumerate() {
        let tag = u8::try_from(index + 1).map_err(|_| PolicyQ04DataErrorV1::Bounds)?;
        let length = u32::try_from(field.len()).map_err(|_| PolicyQ04DataErrorV1::Bounds)?;
        digest.update([tag]);
        digest.update(length.to_be_bytes());
        digest.update(field);
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

// This is shape DATA only. Root authenticates both complete packets on the
// current original owner before any caller may consume their semantic joins.
pub fn require_genesis_observation_pair_widths(
    controller: &[u8],
    source: &[u8],
) -> Result<(), PolicyQ04DataErrorV1> {
    let legacy = controller.len() == aos_sandbox_protocol::source_genesis_geometry::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1
        && source.len() == aos_sandbox_protocol::source_genesis_geometry::SOURCE_TREE_GENESIS_READBACK_BYTES_V1;
    let resource = controller.len() == aos_sandbox_protocol::source_genesis_geometry::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2
        && source.len() == aos_sandbox_protocol::source_genesis_geometry::SOURCE_TREE_GENESIS_READBACK_BYTES_V2;
    if legacy || resource {
        Ok(())
    } else {
        Err(PolicyQ04DataErrorV1::Bounds)
    }
}

// This canonical pre-envelope seed excludes the final Cut and every future
// native/publication/phase identity. Both owners borrow the same actual
// original inputs and independently compare this nonauthorizing DATA hash.
pub fn q04_publication_precut_seed_v1(
    original_precut: ObjectDigest,
    root_before: ObjectDigest,
    controller_before: ObjectDigest,
    floor: ObjectDigest,
    ancestry: ObjectDigest,
    policy_before: ObjectDigest,
) -> Result<ObjectDigest, PolicyQ04DataErrorV1> {
    let fields = [
        original_precut,
        root_before,
        controller_before,
        floor,
        ancestry,
        policy_before,
    ];
    if fields.iter().any(|value| value.as_bytes() == &[0; 32]) {
        return Err(PolicyQ04DataErrorV1::ChangedCut);
    }
    let mut digest =
        Sha256::new().chain_update(b"aos.sandbox.create-q04.publication-precut-seed.v1\0");
    for field in fields {
        digest.update(field.as_bytes());
    }
    digest.update(1_u64.to_be_bytes());
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

pub struct Q04PreholdTransferRecipeV1<'packet> {
    request: &'packet [u8],
    index: [u8; PREVIEW_INDEX_BYTES],
}

impl<'packet> Q04PreholdTransferRecipeV1<'packet> {
    pub fn new(request: &Q04PreholdInputDataV1<'packet>) -> Result<Self, PolicyQ04DataErrorV1> {
        let index = bounded_input_transfer_index(
            request.bytes,
            PREHOLD_REQUEST_DOMAIN,
            MAXIMUM_PREHOLD_BYTES,
        )?;
        Ok(Self {
            request: request.bytes,
            index,
        })
    }

    pub fn verify_index(
        original_index: &[u8],
        request: &Q04PreholdInputDataV1<'packet>,
    ) -> Result<Self, PolicyQ04DataErrorV1> {
        let recipe = Self::new(request)?;
        if original_index != recipe.index.as_slice() {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }
        Ok(recipe)
    }

    pub fn index_bytes(&self) -> &[u8; PREVIEW_INDEX_BYTES] {
        &self.index
    }

    pub fn chunk_count(&self) -> u16 {
        u16::from_be_bytes(fixed(&self.index, 36))
    }

    pub fn encode_chunk(
        &self,
        index: u16,
        output: &mut Vec<u8>,
    ) -> Result<(), PolicyQ04DataErrorV1> {
        Q04ChunkPurposeV1::Prehold.encode_chunk(self.request, fixed(&self.index, 0), index, output)
    }
}

pub struct Q04PreholdChunkV1<'chunk> {
    chunk: Q04OrderedChunkV1<'chunk>,
}

impl<'chunk> Q04PreholdChunkV1<'chunk> {
    pub fn decode(
        bytes: &'chunk [u8],
        original_index: &[u8],
    ) -> Result<Self, PolicyQ04DataErrorV1> {
        let (total, count) = prehold_index_shape(original_index)?;
        let chunk = Q04ChunkPurposeV1::Prehold.decode_chunk(
            bytes,
            fixed(original_index, 0),
            total,
            count,
        )?;
        Ok(Self { chunk })
    }

    pub fn append_to(&self, output: &mut Vec<u8>) -> Result<(), PolicyQ04DataErrorV1> {
        self.chunk.append_to(output)
    }
}

pub fn prehold_index_shape(bytes: &[u8]) -> Result<(usize, u16), PolicyQ04DataErrorV1> {
    bounded_input_transfer_shape(bytes, PREHOLD_PREFIX_BYTES + 64, MAXIMUM_PREHOLD_BYTES)
}

pub use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutRecipeV1;

/// Computes a candidate's exact bounded resource vector with the caller's diagnostic.
///
/// The expansion evaluates the candidate once and preserves the complete
/// canonical dimension order. It performs no allocation or native admission.
/// An unbounded dimension returns the supplied changed-cut error in the same
/// Result expression; no wrapper function, callback or lower error is created.
#[macro_export]
macro_rules! q04_candidate_capacity_v1 {
    ($candidate:expr, $changed_cut:expr) => {{
        'candidate_capacity: {
            use aos_sandbox_model::{ResourceDimension, ResourceLimit};

            let candidate = $candidate;
            let mut values = [0; ResourceDimension::COUNT];
            for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
                let ResourceLimit::Bounded(value) = candidate.hard_resources().accounting_ceilings().get(dimension) else {
                    break 'candidate_capacity Err($changed_cut);
                };
                values[index] = value;
            }
            break 'candidate_capacity Ok(aos_sandbox_model::ResourceVector::new(values));
        }
    }};
}
