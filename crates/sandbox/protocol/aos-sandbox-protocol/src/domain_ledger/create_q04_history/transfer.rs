//! Owns bounded Q04 transfer and untrusted preview comparison DATA.
//!
//! The original packet, ordered chunk and scalar stage recipes are shared by
//! native senders and observers. These values contain no live stream, phase,
//! writer, financial admission or issuing authority.
//!
//! ```text
//! AOSQ4V01 | version=1 | lengths[9] | original preview fields
//! AOSQ4B01/AOSQ4U01/AOSQ4M01 | original digest | ordered chunk | checksum
//! ```

use super::{CLAIM_CHUNK_BYTES, MAXIMUM_CLAIM_BYTES, Q04HistoryDataErrorV1, chunk_count};
use crate::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_model::{ObjectDigest, bounded_codec::BoundedReader};
use sha2::{Digest as _, Sha256};
/// Preserves the existing canonical packet or binding comparison failure.
#[derive(Debug, thiserror::Error)]
pub enum Q04DataErrorV1 {
    /// A closed proposal or stage was noncanonical.
    #[error("the closed policy candidate is unauthenticated")]
    UnauthenticatedCandidate,
    /// An original Q04 field, phase or identity changed.
    #[error("the original Q04 continuation cut changed")]
    ChangedCut,
    /// An original packet exceeded its canonical bound.
    #[error("the original Q04 input or suffix exceeds its bound")]
    Bounds,
    /// A protected scalar or required nonzero field was malformed.
    #[error("the Q04 protected DATA boundary changed")]
    ProtectedBoundary,
    /// Retains the original bounded allocation failure.
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
    /// Retains the ACK's independent signature failure.
    #[error(transparent)]
    AcknowledgementSignature(#[from] ed25519_dalek::SignatureError),
    /// Retains the complete Claim's independent signature failure.
    #[error(transparent)]
    ClaimSignature(ed25519_dalek::SignatureError),
    /// Retains the Prehold's independent signature failure.
    #[error(transparent)]
    PreholdSignature(ed25519_dalek::SignatureError),
    /// Retains the canonical history field failure.
    #[error(transparent)]
    History(#[from] Q04HistoryDataErrorV1),
    /// Retains the protected-name decoder failure.
    #[error(transparent)]
    ProtectedHistory(#[from] crate::domain_ledger::ProtectedHistoryDataErrorV1),
    /// Retains the exact transaction constructor failure.
    #[error(transparent)]
    Transaction(#[from] crate::domain_ledger::JournalTransactionDataError),
}

pub use super::{CLAIM_CHUNK_PREFIX_BYTES, CLAIM_INDEX_BYTES, PREVIEW_INDEX_BYTES};
/// Bounds the canonical maximum preview bytes representation.
pub const MAXIMUM_PREVIEW_BYTES: usize = 266_068;
/// Bounds the canonical prehold metadata bytes representation.
pub const PREHOLD_METADATA_BYTES: usize = 512;
/// Bounds the canonical maximum prehold bytes representation.
pub const MAXIMUM_PREHOLD_BYTES: usize = 198_252;
/// Bounds the canonical prehold fields representation.
pub const PREHOLD_FIELDS: usize = 6;
/// Bounds the canonical prehold prefix bytes representation.
pub const PREHOLD_PREFIX_BYTES: usize = 16 + PREHOLD_FIELDS * 4;
/// Bounds the canonical preview fields representation.
pub const PREVIEW_FIELDS: usize = 9;
/// Bounds the canonical preview prefix bytes representation.
pub const PREVIEW_PREFIX_BYTES: usize = 16 + PREVIEW_FIELDS * 4;
/// Bounds the canonical claim fields representation.
pub const CLAIM_FIELDS: usize = 14;
/// Bounds the canonical claim prefix bytes representation.
pub const CLAIM_PREFIX_BYTES: usize = 16 + CLAIM_FIELDS * 4;
const CLAIM_CHUNK_DOMAIN: &[u8] = b"aos.sandbox.create-q04.claim-chunk.v1\0";
const PREVIEW_DOMAIN: &[u8] = b"aos.sandbox.create-q04.preview.v1\0";
const PREVIEW_CHUNK_DOMAIN: &[u8] = b"aos.sandbox.create-q04.preview-chunk.v1\0";
const PREHOLD_CHUNK_DOMAIN: &[u8] = b"aos.sandbox.create-q04.prefund-chunk.v1\0";

/// Supplies root-derived CAS fields while the protected writer remains held.
///
/// A controller may use these bytes to construct a proposal, but the root
/// session rechecks every field at commit. These copied fields do not
/// establish the other owners' current heads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedPolicyRootCasBaseV2 {
    /// Identifies the Root-derived issuer owner compared at commit.
    pub issuer_owner: [u8; 16],
    /// Names the preceding binding, or zero before the first generation.
    pub predecessor: ObjectDigest,
    /// Names the required next binding generation.
    pub next_generation: u64,
    /// Names the deployment signer generation selected by Root.
    pub deployment_signer_generation: u64,
    /// Names the project signer generation selected by Root.
    pub project_signer_generation: u64,
}

/// Retains one Root-issued base and challenge before other writers are acquired.
///
/// These are copied stage coordinates. Root independently rechecks its held
/// journal, original socket and signed-source identity before any mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedClosedPolicyRootBaseV2 {
    /// Contains the copied proposal comparison base.
    pub base: ClosedPolicyRootCasBaseV2,
    /// Binds the stage to the original nonzero Root challenge.
    pub challenge: [u8; 16],
    /// Identifies the nonzero stage issuance epoch.
    pub issue_epoch: u64,
}

impl StagedClosedPolicyRootBaseV2 {
    /// Reconstructs an untrusted socket stage for later Root revalidation.
    ///
    /// # Errors
    ///
    /// Rejects a zero challenge or issuance epoch.
    pub fn from_untrusted_remote_fields(
        base: ClosedPolicyRootCasBaseV2,
        challenge: [u8; 16],
        issue_epoch: u64,
    ) -> Result<Self, Q04DataErrorV1> {
        if challenge == [0; 16] || issue_epoch == 0 {
            return Err(Q04DataErrorV1::UnauthenticatedCandidate);
        }
        Ok(Self {
            base,
            challenge,
            issue_epoch,
        })
    }

    /// Returns the Root-supplied CAS base for nonauthorizing proposal construction.
    #[must_use]
    pub const fn base(self) -> ClosedPolicyRootCasBaseV2 {
        self.base
    }

    /// Returns the Root-minted challenge bound to the protected stage.
    #[must_use]
    pub const fn challenge(self) -> [u8; 16] {
        self.challenge
    }

    /// Returns the monotone Root stage issuance epoch.
    #[must_use]
    pub const fn issue_epoch(self) -> u64 {
        self.issue_epoch
    }
}

impl ClosedPolicyRootCasBaseV2 {
    /// Decodes root-supplied CAS fields without treating them as authority.
    ///
    /// The root session compares these fields to its protected journal when
    /// committing the proposal. A caller cannot authorize a binding by
    /// constructing this value.
    ///
    /// # Errors
    ///
    /// Rejects missing identities, generations, or an impossible predecessor.
    pub fn from_untrusted_remote_fields(
        issuer_owner: [u8; 16],
        predecessor: ObjectDigest,
        next_generation: u64,
        deployment_signer_generation: u64,
        project_signer_generation: u64,
    ) -> Result<Self, Q04DataErrorV1> {
        if issuer_owner == [0; 16]
            || next_generation == 0
            || deployment_signer_generation == 0
            || project_signer_generation == 0
            || (next_generation == 1) != (predecessor.as_bytes() == &[0; 32])
        {
            return Err(Q04DataErrorV1::UnauthenticatedCandidate);
        }
        Ok(Self {
            issuer_owner,
            predecessor,
            next_generation,
            deployment_signer_generation,
            project_signer_generation,
        })
    }

    /// Returns the root-derived controller owner commitment.
    #[must_use]
    pub const fn issuer_owner(self) -> [u8; 16] {
        self.issuer_owner
    }

    /// Returns the exact current root predecessor commitment.
    #[must_use]
    pub const fn predecessor(self) -> ObjectDigest {
        self.predecessor
    }

    /// Returns the required next root CAS and handoff epoch.
    #[must_use]
    pub const fn next_generation(self) -> u64 {
        self.next_generation
    }

    /// Returns the root-pinned deployment signer generation.
    #[must_use]
    pub const fn deployment_signer_generation(self) -> u64 {
        self.deployment_signer_generation
    }

    /// Returns the root-pinned project signer generation.
    #[must_use]
    pub const fn project_signer_generation(self) -> u64 {
        self.project_signer_generation
    }
}

fn chunk_range(
    total: usize,
    index: u16,
    count: u16,
    maximum: usize,
) -> Result<std::ops::Range<usize>, Q04DataErrorV1> {
    if count != chunk_count(total, maximum)? || index >= count {
        return Err(Q04DataErrorV1::Bounds);
    }
    let start = usize::from(index)
        .checked_mul(CLAIM_CHUNK_BYTES)
        .ok_or(Q04DataErrorV1::Bounds)?;
    let end = start
        .checked_add(CLAIM_CHUNK_BYTES)
        .ok_or(Q04DataErrorV1::Bounds)?
        .min(total);
    Ok(start..end)
}

// Both transfers share coordinates, bounds and ordered reconstruction. The
// purpose selects its own canonical bytes/domain; Preview never needs a fake
// Cut or a Claim index to reuse this engine.
/// Selects the closed, independently hashed canonical chunk DATA format.
#[derive(Clone, Copy)]
pub enum Q04ChunkPurposeV1 {
    /// Transfers one complete signed Claim.
    Claim,
    /// Transfers one untrusted Root Preview.
    Preview,
    /// Transfers one signed original Prehold request.
    Prehold,
}

// Both public framing and full decoding expand this one DATA comparison in
// place. The complete decoder has no second helper Result or range calculation.
macro_rules! decode_chunk_prefix_v1 {
    ($purpose:ident, $bytes:ident, $index:ident, $count:ident, $total:ident, $range:ident) => {
        if $bytes[..8] != *$purpose.magic()
            || $bytes[8..10] != 1_u16.to_be_bytes()
            || $bytes[10..16] != [0; 6]
            || $bytes[16..48] == [0; 32]
            || $bytes[88..96] != [0; 8]
        {
            return Err(Q04DataErrorV1::Bounds);
        }
        let $index = u16::from_be_bytes(fixed($bytes, 48));
        let $count = u16::from_be_bytes(fixed($bytes, 50));
        let $total = usize::try_from(read_u32($bytes, 52)?).map_err(|_| Q04DataErrorV1::Bounds)?;
        let $range = chunk_range($total, $index, $count, $purpose.maximum())?;
    };
}

impl Q04ChunkPurposeV1 {
    /// Returns the canonical magic bytes for this closed purpose.
    pub fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Claim => b"AOSQ4B01",
            Self::Preview => b"AOSQ4U01",
            Self::Prehold => b"AOSQ4M01",
        }
    }

    fn maximum(self) -> usize {
        match self {
            Self::Claim => MAXIMUM_CLAIM_BYTES,
            Self::Preview => MAXIMUM_PREVIEW_BYTES,
            Self::Prehold => MAXIMUM_PREHOLD_BYTES,
        }
    }

    fn chunk_digest(self, header: &[u8], payload: &[u8]) -> [u8; 32] {
        let (domain, start): (&[u8], usize) = match self {
            Self::Claim => (CLAIM_CHUNK_DOMAIN, 16),
            Self::Preview => (PREVIEW_CHUNK_DOMAIN, 0),
            Self::Prehold => (PREHOLD_CHUNK_DOMAIN, 0),
        };
        Sha256::new()
            .chain_update(domain)
            .chain_update(&header[start..56])
            .chain_update(payload)
            .finalize()
            .into()
    }

    /// Encodes one bounded chunk from the same original packet.
    ///
    /// # Errors
    ///
    /// Refuses a nonempty output, zero comparison digest, invalid chunk range or
    /// allocation failure.
    pub fn encode_chunk(
        self,
        original: &[u8],
        comparison_digest: [u8; 32],
        index: u16,
        output: &mut Vec<u8>,
    ) -> Result<(), Q04DataErrorV1> {
        if !output.is_empty() || comparison_digest == [0; 32] {
            return Err(Q04DataErrorV1::ChangedCut);
        }
        let count = chunk_count(original.len(), self.maximum())?;
        let range = chunk_range(original.len(), index, count, self.maximum())?;
        let payload = &original[range];
        let total = u32::try_from(original.len()).map_err(|_| Q04DataErrorV1::Bounds)?;

        let mut header = [0; CLAIM_CHUNK_PREFIX_BYTES];
        header[..8].copy_from_slice(self.magic());
        header[8..10].copy_from_slice(&1_u16.to_be_bytes());
        header[16..48].copy_from_slice(&comparison_digest);
        header[48..50].copy_from_slice(&index.to_be_bytes());
        header[50..52].copy_from_slice(&count.to_be_bytes());
        header[52..56].copy_from_slice(&total.to_be_bytes());
        let digest = self.chunk_digest(&header, payload);
        header[56..88].copy_from_slice(&digest);

        output.try_reserve_exact(CLAIM_CHUNK_PREFIX_BYTES + payload.len())?;
        output.extend_from_slice(&header);
        output.extend_from_slice(payload);
        Ok(())
    }

    /// Determines one exact encoded frame width from its complete fixed prefix.
    ///
    /// This checks framing DATA only. A native observer still retains the full
    /// frame and verifies its payload digest and indexed-original relation.
    ///
    /// # Errors
    ///
    /// Rejects a malformed purpose, header, reserved field or bounded range.
    pub fn frame_bytes_from_prefix_v1(self, bytes: &[u8]) -> Result<usize, Q04DataErrorV1> {
        if bytes.len() != CLAIM_CHUNK_PREFIX_BYTES {
            return Err(Q04DataErrorV1::Bounds);
        }
        decode_chunk_prefix_v1!(self, bytes, _index, _count, _total, range);
        CLAIM_CHUNK_PREFIX_BYTES
            .checked_add(range.len())
            .ok_or(Q04DataErrorV1::Bounds)
    }

    /// Checks a complete chunk against its indexed original and checksum.
    ///
    /// # Errors
    ///
    /// Rejects malformed headers, a changed original digest, inconsistent total or
    /// count, an incorrect payload width, or a mismatched checksum.
    pub fn decode_chunk<'chunk>(
        self,
        bytes: &'chunk [u8],
        comparison_digest: [u8; 32],
        indexed_total: usize,
        indexed_count: u16,
    ) -> Result<Q04OrderedChunkV1<'chunk>, Q04DataErrorV1> {
        if bytes.len() < CLAIM_CHUNK_PREFIX_BYTES
            || bytes.len() > CLAIM_CHUNK_PREFIX_BYTES + CLAIM_CHUNK_BYTES
            || comparison_digest == [0; 32]
            || bytes[16..48] != comparison_digest
        {
            return Err(Q04DataErrorV1::Bounds);
        }
        decode_chunk_prefix_v1!(self, bytes, index, count, total, range);
        let payload = &bytes[CLAIM_CHUNK_PREFIX_BYTES..];
        if count != indexed_count
            || total != indexed_total
            || payload.len() != range.len()
            || bytes[56..88] != self.chunk_digest(bytes, payload)
        {
            return Err(Q04DataErrorV1::ChangedCut);
        }

        Ok(Q04OrderedChunkV1 {
            index,
            payload,
            maximum: self.maximum(),
        })
    }
}

/// Borrows one decoded ordered chunk without owning or authenticating a live flight.
pub struct Q04OrderedChunkV1<'chunk> {
    index: u16,
    payload: &'chunk [u8],
    maximum: usize,
}

impl Q04OrderedChunkV1<'_> {
    /// Returns the checked ordinal within the original transfer.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Borrows the payload checked against the original transfer index.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    /// Appends this chunk at its exact reconstruction offset.
    ///
    /// # Errors
    ///
    /// Refuses an out-of-order output length, a packet exceeding its maximum, or
    /// allocation failure.
    pub fn append_to(&self, output: &mut Vec<u8>) -> Result<(), Q04DataErrorV1> {
        let offset = usize::from(self.index)
            .checked_mul(CLAIM_CHUNK_BYTES)
            .ok_or(Q04DataErrorV1::Bounds)?;
        if output.len() != offset
            || output
                .len()
                .checked_add(self.payload.len())
                .is_none_or(|size| size > self.maximum)
        {
            return Err(Q04DataErrorV1::ChangedCut);
        }
        output.try_reserve_exact(self.payload.len())?;
        output.extend_from_slice(self.payload);
        Ok(())
    }
}

// The Preview borrows only a complete original transfer. All source fields
// remain untrusted DATA until the independent pins, same original Root peer,
// completed gen1 cut and actual held owners have each been rechecked.
/// Borrows one complete bounded, untrusted Preview packet.
pub struct Q04PreviewV1<'preview> {
    bytes: &'preview [u8],
    fields: [&'preview [u8]; PREVIEW_FIELDS],
}

impl<'preview> Q04PreviewV1<'preview> {
    /// Borrows a complete Preview after checking its fields and original nonce.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, invalid field widths, noncanonical metadata,
    /// protected names, stage coordinates, or a different original nonce.
    pub fn decode(bytes: &'preview [u8], original_nonce: [u8; 16]) -> Result<Self, Q04DataErrorV1> {
        if bytes.len() < PREVIEW_PREFIX_BYTES
            || bytes.len() > MAXIMUM_PREVIEW_BYTES
            || bytes[..8] != *b"AOSQ4V01"
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(Q04DataErrorV1::Bounds);
        }
        let fields = decode_length_prefixed_fields(bytes)?;
        require_preview_fields(&fields, original_nonce)?;
        Ok(Self { bytes, fields })
    }

    /// Borrows the original packet fields without copying their bytes.
    pub fn fields(&self) -> &[&'preview [u8]; PREVIEW_FIELDS] {
        &self.fields
    }

    /// Borrows the complete original packet bytes.
    pub fn bytes(&self) -> &'preview [u8] {
        self.bytes
    }

    /// Decodes the Preview's copied stage coordinates.
    ///
    /// # Errors
    ///
    /// Rejects a malformed stage width, zero issuer or signer generations, an
    /// inconsistent predecessor, zero challenge, or zero issuance epoch.
    pub fn staged(&self) -> Result<StagedClosedPolicyRootBaseV2, Q04DataErrorV1> {
        preview_stage(self.fields[1])
    }
}

/// Encodes the nine Preview fields into an empty output.
///
/// # Errors
///
/// Refuses nonempty output, invalid Preview fields or nonce, an excessive
/// encoded length, or allocation failure.
pub fn encode_q04_preview_body_v1(
    output: &mut Vec<u8>,
    fields: [&[u8]; PREVIEW_FIELDS],
    original_nonce: [u8; 16],
) -> Result<(), Q04DataErrorV1> {
    if !output.is_empty() {
        return Err(Q04DataErrorV1::ChangedCut);
    }
    require_preview_fields(&fields, original_nonce)?;
    encode_length_prefixed_fields(output, b"AOSQ4V01", fields, MAXIMUM_PREVIEW_BYTES)?;
    Q04PreviewV1::decode(output, original_nonce)?;
    Ok(())
}

fn require_preview_fields(
    fields: &[&[u8]; PREVIEW_FIELDS],
    original_nonce: [u8; 16],
) -> Result<(), Q04DataErrorV1> {
    if fields[0].len() != 120
        || fields[1].len() != 128
        || fields[2].len() != 224
        || fields[3..7]
            .iter()
            .any(|field| field.is_empty() || field.len() > 64 * 1024)
        || fields[7].len() != 328
        || fields[8].is_empty()
        || fields[8].len() > 3 * 1024
        || original_nonce == [0; 16]
    {
        return Err(Q04DataErrorV1::Bounds);
    }
    let metadata = fields[0];
    if nonzero::<16>(metadata, 0).is_err()
        || read_u64(metadata, 24)?.checked_sub(read_u64(metadata, 16)?) != Some(65_000_000_000)
        || read_u64(metadata, 32)? == 0
        || nonzero::<32>(metadata, 88).is_err()
    {
        return Err(Q04DataErrorV1::ChangedCut);
    }
    ProtectedJournalNamesV1::from_bytes(&metadata[40..88]).map_err(Q04DataErrorV1::from)?;
    let staged = preview_stage(fields[1])?;
    if staged.challenge() != original_nonce || nonzero::<32>(fields[1], 96).is_err() {
        return Err(Q04DataErrorV1::ChangedCut);
    }
    Ok(())
}

fn preview_stage(bytes: &[u8]) -> Result<StagedClosedPolicyRootBaseV2, Q04DataErrorV1> {
    if bytes.len() != 128 {
        return Err(Q04DataErrorV1::Bounds);
    }
    let base = ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields(
        fixed(bytes, 0),
        ObjectDigest::from_bytes(fixed(bytes, 16)),
        read_u64(bytes, 48)?,
        read_u64(bytes, 56)?,
        read_u64(bytes, 64)?,
    )?;
    Ok(StagedClosedPolicyRootBaseV2::from_untrusted_remote_fields(
        base,
        fixed(bytes, 72),
        read_u64(bytes, 88)?,
    )?)
}

// The retained packet and transfer index stay in the enclosing invocation.
// Shape bounds permit reconstruction; complete-domain comparison happens
// only after all original chunks have arrived in their exact order.
/// Computes the canonical transfer index from the same immutable Preview bytes.
pub struct Q04PreviewTransferRecipeV1<'preview> {
    preview: &'preview [u8],
    index: [u8; PREVIEW_INDEX_BYTES],
}

impl<'preview> Q04PreviewTransferRecipeV1<'preview> {
    /// Computes the transfer index for this complete Preview.
    ///
    /// # Errors
    ///
    /// Rejects a Preview length that cannot be represented by the bounded chunk
    /// count or the fixed index length field.
    pub fn new(preview: &Q04PreviewV1<'preview>) -> Result<Self, Q04DataErrorV1> {
        let index =
            bounded_input_transfer_index(preview.bytes, PREVIEW_DOMAIN, MAXIMUM_PREVIEW_BYTES)?;
        Ok(Self {
            preview: preview.bytes,
            index,
        })
    }

    /// Compares an index with the complete retained Preview.
    ///
    /// # Errors
    ///
    /// Rejects unrepresentable Preview dimensions or an index differing from the
    /// one computed over the original bytes.
    pub fn verify_index(
        original_index: &[u8],
        preview: &Q04PreviewV1<'preview>,
    ) -> Result<Self, Q04DataErrorV1> {
        let recipe = Self::new(preview)?;
        if original_index != recipe.index.as_slice() {
            return Err(Q04DataErrorV1::ChangedCut);
        }
        Ok(recipe)
    }

    /// Borrows the canonical fixed transfer index.
    pub fn index_bytes(&self) -> &[u8; PREVIEW_INDEX_BYTES] {
        &self.index
    }

    /// Returns the canonical chunk count stored in the index.
    pub fn chunk_count(&self) -> u16 {
        u16::from_be_bytes(fixed(&self.index, 36))
    }

    /// Encodes one indexed chunk from this retained Preview.
    ///
    /// # Errors
    ///
    /// Refuses a nonempty output, invalid chunk index or allocation failure.
    pub fn encode_chunk(&self, index: u16, output: &mut Vec<u8>) -> Result<(), Q04DataErrorV1> {
        Q04ChunkPurposeV1::Preview.encode_chunk(self.preview, fixed(&self.index, 0), index, output)
    }
}

/// Borrows a Preview chunk checked against its actual transfer index.
pub struct Q04PreviewChunkV1<'chunk> {
    chunk: Q04OrderedChunkV1<'chunk>,
}

impl<'chunk> Q04PreviewChunkV1<'chunk> {
    /// Checks a complete Preview chunk against its transfer index.
    ///
    /// # Errors
    ///
    /// Rejects a malformed index or chunk, changed indexed coordinates, or an
    /// incorrect chunk checksum.
    pub fn decode(bytes: &'chunk [u8], original_index: &[u8]) -> Result<Self, Q04DataErrorV1> {
        let (total, count) = preview_index_shape(original_index)?;
        let chunk = Q04ChunkPurposeV1::Preview.decode_chunk(
            bytes,
            fixed(original_index, 0),
            total,
            count,
        )?;
        Ok(Self { chunk })
    }

    /// Copies the original first metadata coordinates from a decoded first chunk.
    ///
    /// Later chunks return `None`. This compares only the Preview header and
    /// first field framing; it does not authenticate a complete Preview or cut.
    ///
    /// # Errors
    ///
    /// Rejects a truncated or malformed first Preview prefix or metadata field.
    pub fn first_metadata_data_v1(&self) -> Result<Option<[u8; 32]>, Q04DataErrorV1> {
        if self.chunk.index != 0 {
            return Ok(None);
        }
        let payload = self.chunk.payload;
        let metadata_end = PREVIEW_PREFIX_BYTES
            .checked_add(32)
            .ok_or(Q04DataErrorV1::Bounds)?;
        if payload.len() < metadata_end
            || payload[..8] != *b"AOSQ4V01"
            || payload[8..10] != 1_u16.to_be_bytes()
            || payload[10..16] != [0; 6]
            || read_u32(payload, 16)? != 120
        {
            return Err(Q04DataErrorV1::Bounds);
        }
        Ok(Some(fixed(payload, PREVIEW_PREFIX_BYTES)))
    }

    /// Appends this Preview chunk at its exact reconstruction offset.
    ///
    /// # Errors
    ///
    /// Refuses an out-of-order output length, a Preview exceeding its maximum, or
    /// allocation failure.
    pub fn append_to(&self, output: &mut Vec<u8>) -> Result<(), Q04DataErrorV1> {
        self.chunk.append_to(output)
    }
}

/// Checks a Preview index and returns its total bytes and chunk count.
///
/// # Errors
///
/// Rejects the wrong index width, nonzero reserved bytes, a zero digest, or
/// inconsistent bounded total and chunk count.
pub fn preview_index_shape(bytes: &[u8]) -> Result<(usize, u16), Q04DataErrorV1> {
    bounded_input_transfer_shape(bytes, PREVIEW_PREFIX_BYTES, MAXIMUM_PREVIEW_BYTES)
}

// Preview and prehold share the same fixed index coordinates and strict
// reconstruction bounds. Their complete-packet domains remain distinct.
/// Hashes an original packet into its fixed transfer index.
///
/// # Errors
///
/// Rejects an empty or oversized original, an unrepresentable total length,
/// or a chunk count exceeding the canonical bound.
pub fn bounded_input_transfer_index(
    original: &[u8],
    domain: &[u8],
    maximum: usize,
) -> Result<[u8; PREVIEW_INDEX_BYTES], Q04DataErrorV1> {
    let count = chunk_count(original.len(), maximum)?;
    let total = u32::try_from(original.len()).map_err(|_| Q04DataErrorV1::Bounds)?;
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(original)
        .finalize();
    let mut index = [0; PREVIEW_INDEX_BYTES];
    index[..32].copy_from_slice(&digest);
    index[32..36].copy_from_slice(&total.to_be_bytes());
    index[36..38].copy_from_slice(&count.to_be_bytes());
    Ok(index)
}

/// Checks a transfer index against its packet length bounds.
///
/// # Errors
///
/// Rejects the wrong index width, nonzero reserved bytes, a zero digest, or
/// a total and chunk count outside the supplied bounds.
pub fn bounded_input_transfer_shape(
    bytes: &[u8],
    minimum: usize,
    maximum: usize,
) -> Result<(usize, u16), Q04DataErrorV1> {
    if bytes.len() != PREVIEW_INDEX_BYTES
        || bytes[38..48] != [0; 10]
        || nonzero::<32>(bytes, 0).is_err()
    {
        return Err(Q04DataErrorV1::Bounds);
    }
    let total = usize::try_from(read_u32(bytes, 32)?).map_err(|_| Q04DataErrorV1::Bounds)?;
    let count = u16::from_be_bytes(fixed(bytes, 36));
    if total < minimum || count != chunk_count(total, maximum)? {
        return Err(Q04DataErrorV1::Bounds);
    }
    Ok((total, count))
}

// This packet authenticates original comparison DATA only. Neither its
// signature nor its capacity reply supplies currentness, a logical hold or a
// publication permit. The same original owners remain independently required.

/// Borrows every field from a complete length-prefixed body.
///
/// # Errors
///
/// Rejects an overflowing prefix or field length, truncated fields, or bytes
/// remaining after the final declared field.
pub fn decode_length_prefixed_fields<const COUNT: usize>(
    body: &[u8],
) -> Result<[&[u8]; COUNT], Q04DataErrorV1> {
    let lengths = COUNT.checked_mul(4).ok_or(Q04DataErrorV1::Bounds)?;
    let prefix = 16_usize
        .checked_add(lengths)
        .ok_or(Q04DataErrorV1::Bounds)?;
    if body.len() < prefix {
        return Err(Q04DataErrorV1::Bounds);
    }
    let mut fields = [&[] as &[u8]; COUNT];
    let mut cursor = prefix;
    for (index, field) in fields.iter_mut().enumerate() {
        let length =
            usize::try_from(read_u32(body, 16 + index * 4)?).map_err(|_| Q04DataErrorV1::Bounds)?;
        let end = cursor.checked_add(length).ok_or(Q04DataErrorV1::Bounds)?;
        *field = body.get(cursor..end).ok_or(Q04DataErrorV1::Bounds)?;
        cursor = end;
    }
    if cursor != body.len() {
        return Err(Q04DataErrorV1::Bounds);
    }
    Ok(fields)
}

/// Appends a versioned header and its length-prefixed fields.
///
/// # Errors
///
/// Rejects representation overflow, an encoded size above the supplied
/// maximum, a field length exceeding u32, or allocation failure.
pub fn encode_length_prefixed_fields<const COUNT: usize>(
    output: &mut Vec<u8>,
    magic: &[u8; 8],
    fields: [&[u8]; COUNT],
    maximum: usize,
) -> Result<(), Q04DataErrorV1> {
    let lengths = COUNT.checked_mul(4).ok_or(Q04DataErrorV1::Bounds)?;
    let prefix = 16_usize
        .checked_add(lengths)
        .ok_or(Q04DataErrorV1::Bounds)?;
    let size = fields.iter().try_fold(prefix, |size, field| {
        size.checked_add(field.len()).ok_or(Q04DataErrorV1::Bounds)
    })?;
    if size > maximum {
        return Err(Q04DataErrorV1::Bounds);
    }
    output.try_reserve_exact(size)?;
    output.extend_from_slice(magic);
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.extend_from_slice(&[0; 6]);
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| Q04DataErrorV1::Bounds)?;
        output.extend_from_slice(&length.to_be_bytes());
    }
    for field in fields {
        output.extend_from_slice(field);
    }
    Ok(())
}

/// Compares a byte field's nonzero presence with its required state.
///
/// # Errors
///
/// Rejects an all-zero field when presence is required, or any nonzero byte
/// when absence is required.
pub fn require_presence(bytes: &[u8], present: bool) -> Result<(), Q04DataErrorV1> {
    if bytes.iter().any(|byte| *byte != 0) != present {
        return Err(Q04DataErrorV1::ProtectedBoundary);
    }
    Ok(())
}

/// Copies a checked fixed-width field containing a nonzero byte.
///
/// # Errors
///
/// Rejects an overflowing or truncated range, or an all-zero field.
pub fn nonzero<const SIZE: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; SIZE], Q04DataErrorV1> {
    let end = offset
        .checked_add(SIZE)
        .ok_or(Q04DataErrorV1::ProtectedBoundary)?;
    let mut reader = BoundedReader::new(bytes, |_| Q04DataErrorV1::ProtectedBoundary);
    let prefix = reader.bytes(end)?;
    let field = &prefix[offset..end];

    require_presence(field, true)?;
    field
        .try_into()
        .map_err(|_| Q04DataErrorV1::ProtectedBoundary)
}

/// Copies a fixed field after the caller has checked the containing format.
///
/// # Panics
///
/// Panics if the requested field lies outside the caller-validated bytes.
pub fn fixed<const SIZE: usize>(bytes: &[u8], offset: usize) -> [u8; SIZE] {
    let mut field = [0; SIZE];
    field.copy_from_slice(&bytes[offset..offset + SIZE]);
    field
}

/// Reads one bounded big-endian 32-bit integer.
///
/// # Errors
///
/// Rejects an overflowing offset or fewer than four bytes at that offset.
pub fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Q04DataErrorV1> {
    Ok(u32::from_be_bytes(read_integer_bytes(bytes, offset)?))
}

/// Reads one bounded big-endian 64-bit integer.
///
/// # Errors
///
/// Rejects an overflowing offset or fewer than eight bytes at that offset.
pub fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Q04DataErrorV1> {
    Ok(u64::from_be_bytes(read_integer_bytes(bytes, offset)?))
}

/// Copies a bounded fixed-width integer representation.
///
/// # Errors
///
/// Rejects an overflowing offset or a truncated field.
pub fn read_integer_bytes<const SIZE: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; SIZE], Q04DataErrorV1> {
    let end = offset
        .checked_add(SIZE)
        .ok_or(Q04DataErrorV1::ProtectedBoundary)?;
    let mut reader = BoundedReader::new(bytes, |_| Q04DataErrorV1::ProtectedBoundary);
    let prefix = reader.bytes(end)?;
    prefix[offset..end]
        .try_into()
        .map_err(|_| Q04DataErrorV1::ProtectedBoundary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_and_full_decoder_share_exact_last_chunk_width() {
        let body = vec![7; CLAIM_CHUNK_BYTES + 19];
        let mut encoded = Vec::new();
        Q04ChunkPurposeV1::Preview
            .encode_chunk(&body, [3; 32], 1, &mut encoded)
            .unwrap();

        let frame = Q04ChunkPurposeV1::Preview
            .frame_bytes_from_prefix_v1(&encoded[..CLAIM_CHUNK_PREFIX_BYTES])
            .unwrap();
        let decoded = Q04ChunkPurposeV1::Preview
            .decode_chunk(&encoded, [3; 32], body.len(), 2)
            .unwrap();

        assert_eq!(frame, CLAIM_CHUNK_PREFIX_BYTES + 19);
        assert_eq!(frame, encoded.len());
        assert_eq!(decoded.payload, &body[CLAIM_CHUNK_BYTES..]);
        encoded.pop();
        assert!(matches!(
            Q04ChunkPurposeV1::Preview.decode_chunk(&encoded, [3; 32], body.len(), 2),
            Err(Q04DataErrorV1::ChangedCut)
        ));
    }

    #[test]
    fn fixed_prefix_refuses_reserved_fields_and_inconsistent_chunk_count() {
        let mut encoded = Vec::new();
        Q04ChunkPurposeV1::Claim
            .encode_chunk(&[5; 17], [3; 32], 0, &mut encoded)
            .unwrap();
        let mut prefix: [u8; CLAIM_CHUNK_PREFIX_BYTES] =
            encoded[..CLAIM_CHUNK_PREFIX_BYTES].try_into().unwrap();
        prefix[88] = 1;
        assert!(
            Q04ChunkPurposeV1::Claim
                .frame_bytes_from_prefix_v1(&prefix)
                .is_err()
        );
        prefix[88] = 0;
        prefix[50..52].copy_from_slice(&2_u16.to_be_bytes());
        assert!(
            Q04ChunkPurposeV1::Claim
                .frame_bytes_from_prefix_v1(&prefix)
                .is_err()
        );
    }
}
