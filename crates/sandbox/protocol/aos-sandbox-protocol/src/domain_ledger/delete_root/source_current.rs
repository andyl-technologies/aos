//! Encodes the independent Delete-purpose Source pending observation DATA.
//!
//! ```text
//! query128 = AOSSDQ01 | version1/reserved | nonce/project/operation |
//!            batch-digest | boot | started | cutoff
//! body384  = AOSSDC01 | version1/reserved | generation/query/clock |
//!            names/NEXT/end | native-COMMIT64 | batch/project/operation |
//!            Tree-generation/commitment/head/lineage-head
//! reply456 = AOSSDR01 | body384 | Ed25519-signature64
//! ```
//!
//! The actual Source service independently reads its complete current native
//! journal and signs these bytes. Root independently checks its fixed signer,
//! original query, held C17 fence and current floor/six-domain conjunction.
//! Decoding or comparing this DATA creates no fence, grant or receiving loan.

use sha2::{Digest as _, Sha256};
use super::super::{delete_batch::DeleteBatchViewV1, protected_names::ProtectedJournalNamesV1};

mod terminal_operation;
pub use terminal_operation::require_source_delete_terminal_operation_frame_v4;

/// Selects only the new fixed Delete-purpose Source query.
pub const SOURCE_DELETE_CURRENT_QUERY_MAGIC_V1: &[u8; 8] = b"AOSSDQ01";
/// Selects only its corresponding signed Source reply.
pub const SOURCE_DELETE_CURRENT_REPLY_MAGIC_V1: &[u8; 8] = b"AOSSDR01";
/// Gives the exact complete fixed query extent.
pub const SOURCE_DELETE_CURRENT_QUERY_BYTES_V1: usize = 128;
/// Gives the complete signed body extent.
pub const SOURCE_DELETE_CURRENT_BODY_BYTES_V1: usize = 384;
/// Gives the body and signature extent, excluding the outer selector.
pub const SOURCE_DELETE_CURRENT_PACKET_BYTES_V1: usize = 448;
/// Gives the outer selector, body and signature extent.
pub const SOURCE_DELETE_CURRENT_REPLY_BYTES_V1: usize = 456;
/// Bounds this purpose's independently retained original Root flight horizon.
pub const SOURCE_DELETE_CURRENT_MAXIMUM_DURATION_NANOSECONDS_V1: u64 = 65_000_000_000;
/// Separates the new purpose's signature from every existing Source recipe.
pub const SOURCE_DELETE_CURRENT_SIGNATURE_DOMAIN_V1: &[u8] = b"aos.sandbox.delete-root.source-pending.signature.v1\0";
const QUERY_DOMAIN: &[u8] = b"aos.sandbox.delete-root.source-pending.query.v1\0";
const BATCH_DOMAIN: &[u8] = b"aos.sandbox.delete-root.source-pending.batch.v1\0";

/// Selects the distinct finite phases on the same Source readonly engine.
///
/// This is wire comparison DATA. Neither variant grants a signer, current
/// native owner, receiving original, append, recovery or lifecycle permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceDeleteCurrentPurposeDataV3 {
    /// Observes the original Planned pending COMMIT before any readiness append.
    Planned,
    /// Observes canonical Batch2 at current native EOF; Root validates its Operation join.
    ControllerCommitted,
    /// Observes the final Operation/hold-removal COMMIT and immutable Batch2.
    /// Root separately validates the complete Operation and physical receipts.
    Terminal4,
}

impl SourceDeleteCurrentPurposeDataV3 {
    /// Returns the exact finite query selector, with no automatic version fallback.
    #[must_use]
    pub const fn query_magic_v3(self) -> &'static [u8; 8] {
        match self { Self::Planned => SOURCE_DELETE_CURRENT_QUERY_MAGIC_V1,
            Self::ControllerCommitted => b"AOSSDQ03", Self::Terminal4 => b"AOSSDQ04" }
    }

    /// Returns the corresponding exact reply selector.
    #[must_use]
    pub const fn reply_magic_v3(self) -> &'static [u8; 8] {
        match self { Self::Planned => SOURCE_DELETE_CURRENT_REPLY_MAGIC_V1,
            Self::ControllerCommitted => b"AOSSDR03", Self::Terminal4 => b"AOSSDR04" }
    }

    const fn body_magic_v3(self) -> &'static [u8; 8] {
        match self { Self::Planned => b"AOSSDC01", Self::ControllerCommitted => b"AOSSDC03", Self::Terminal4 => b"AOSSDC04" }
    }

    const fn version_v3(self) -> u16 {
        match self { Self::Planned => 1, Self::ControllerCommitted => 3, Self::Terminal4 => 4 }
    }

    /// Returns the purpose-separated signature domain used by the actual signer.
    #[must_use]
    pub const fn signature_domain_v3(self) -> &'static [u8] {
        match self { Self::Planned => SOURCE_DELETE_CURRENT_SIGNATURE_DOMAIN_V1,
            Self::ControllerCommitted => b"aos.sandbox.delete-root.source-controller-committed.signature.v3\0",
            Self::Terminal4 => b"aos.sandbox.delete-root.source-terminal.signature.v4\0" }
    }

    const fn query_domain_v3(self) -> &'static [u8] {
        match self { Self::Planned => QUERY_DOMAIN,
            Self::ControllerCommitted => b"aos.sandbox.delete-root.source-controller-committed.query.v3\0",
            Self::Terminal4 => b"aos.sandbox.delete-root.source-terminal.query.v4\0" }
    }

    /// Selects an exact query magic without accepting another version or purpose.
    #[must_use]
    pub fn from_query_magic_v4(magic: &[u8; 8]) -> Option<Self> {
        [Self::Planned, Self::ControllerCommitted, Self::Terminal4]
            .into_iter().find(|purpose| purpose.query_magic_v3() == magic)
    }
}

/// Bounds all actual finite-purpose signature messages, including the body.
///
/// This is representation DATA, not signer or receiving authority.
pub const SOURCE_DELETE_CURRENT_SIGNATURE_MESSAGE_MAXIMUM_BYTES_V3: usize =
    SourceDeleteCurrentPurposeDataV3::ControllerCommitted.signature_domain_v3().len()
        + SOURCE_DELETE_CURRENT_BODY_BYTES_V1;

const _: () = assert!(SourceDeleteCurrentPurposeDataV3::Terminal4.signature_domain_v3().len()
    + SOURCE_DELETE_CURRENT_BODY_BYTES_V1 <= SOURCE_DELETE_CURRENT_SIGNATURE_MESSAGE_MAXIMUM_BYTES_V3);

/// Identifies the specific passive canonical validation refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceDeleteCurrentDataErrorV1 {
    /// Framing, version, reserved bytes, extent or an identity is malformed.
    #[error("Delete Source observation framing is noncanonical")]
    Format,
    /// The original clock window or observed sample is invalid.
    #[error("Delete Source observation clock is outside its original window")]
    Clock,
    /// The current native COMMIT does not end at the declared complete cut.
    #[error("Delete Source observation native cut is inconsistent")]
    Native,
    /// Current Tree or lineage comparison identities are absent.
    #[error("Delete Source observation Tree or lineage is absent")]
    Tree,
    /// Canonical batch or query/reply association differs.
    #[error("Delete Source observation batch or query differs")]
    Association,
}

/// Commits the complete structurally canonical pending batch for this purpose.
///
/// # Errors
/// Rejects malformed canonical batch bytes before hashing any commitment.
pub fn source_delete_current_batch_digest_v1(bytes: &[u8]) -> Result<[u8; 32], SourceDeleteCurrentDataErrorV1> {
    let batch = DeleteBatchViewV1::decode(bytes).map_err(|_| SourceDeleteCurrentDataErrorV1::Association)?;
    Ok(Sha256::new().chain_update(BATCH_DOMAIN).chain_update(batch.bytes()).finalize().into())
}

/// Commits a canonical ControllerCommitted payload for the distinct Source phase.
///
/// # Errors
/// Rejects malformed payloads and every state except ControllerCommitted(2).
pub fn source_delete_controller_committed_batch_digest_v3(bytes: &[u8])
    -> Result<[u8; 32], SourceDeleteCurrentDataErrorV1>
{
    let record = super::super::delete_batch::LifecycleDeleteBatchRecordViewDataV3::decode(bytes)
        .map_err(|_| SourceDeleteCurrentDataErrorV1::Association)?;
    if record.state != 2 { return Err(SourceDeleteCurrentDataErrorV1::Association); }
    Ok(Sha256::new().chain_update(b"aos.sandbox.delete-root.source-controller-committed.batch.v3\0")
        .chain_update(bytes).finalize().into())
}

/// Contains only the fresh Root challenge and exact canonical batch association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDeleteCurrentQueryDataV1 {
    /// The actual fresh Root entropy nonce, retained for this flight only.
    pub nonce: [u8; 16],
    /// The project decoded from the actual canonical pending batch.
    pub project: [u8; 16],
    /// The operation decoded from that same batch.
    pub operation: [u8; 16],
    /// The named-purpose commitment of the complete canonical batch.
    pub batch: [u8; 32],
    /// The boot identity from the original fresh Root paired kernel sample.
    pub boot: [u8; 16],
    /// That original sample's BOOTTIME nanoseconds.
    pub started: u64,
    /// The original bounded flight deadline, additionally clamped to C17 expiry.
    pub cutoff: u64,
}

impl SourceDeleteCurrentQueryDataV1 {
    /// Decodes the exact fixed query without accepting a Controller position.
    ///
    /// # Errors
    /// Rejects nonexact framing, zero identities or an invalid original horizon.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceDeleteCurrentDataErrorV1> {
        Self::decode_for_purpose_v3(bytes, SourceDeleteCurrentPurposeDataV3::Planned)
    }

    /// Decodes one explicitly selected finite phase without adopting old bytes.
    ///
    /// # Errors
    /// Rejects another selector/version, inexact fields or invalid original horizon.
    pub fn decode_for_purpose_v3(bytes: &[u8], purpose: SourceDeleteCurrentPurposeDataV3)
        -> Result<Self, SourceDeleteCurrentDataErrorV1> {
        header_for_purpose_v3(bytes, SOURCE_DELETE_CURRENT_QUERY_BYTES_V1, purpose.query_magic_v3(), purpose)?;
        let value = Self { nonce: array(bytes, 16)?, project: array(bytes, 32)?, operation: array(bytes, 48)?,
            batch: array(bytes, 64)?, boot: array(bytes, 96)?, started: u64::from_be_bytes(array(bytes, 112)?),
            cutoff: u64::from_be_bytes(array(bytes, 120)?) };
        value.require_canonical()?;
        Ok(value)
    }

    /// Encodes the complete fixed query into caller-owned storage.
    ///
    /// # Errors
    /// Rejects the same noncanonical identities or original horizon as decode.
    pub fn encode(self) -> Result<[u8; SOURCE_DELETE_CURRENT_QUERY_BYTES_V1], SourceDeleteCurrentDataErrorV1> {
        self.encode_for_purpose_v3(SourceDeleteCurrentPurposeDataV3::Planned)
    }

    /// Encodes exactly the named phase while preserving the original cutoff.
    ///
    /// # Errors
    /// Rejects invalid identity, boot or original horizon fields.
    pub fn encode_for_purpose_v3(self, purpose: SourceDeleteCurrentPurposeDataV3)
        -> Result<[u8; SOURCE_DELETE_CURRENT_QUERY_BYTES_V1], SourceDeleteCurrentDataErrorV1> {
        self.require_canonical()?;
        let mut bytes = [0; SOURCE_DELETE_CURRENT_QUERY_BYTES_V1];
        encode_header_for_purpose_v3(&mut bytes, purpose.query_magic_v3(), purpose);
        bytes[16..32].copy_from_slice(&self.nonce);
        bytes[32..48].copy_from_slice(&self.project);
        bytes[48..64].copy_from_slice(&self.operation);
        bytes[64..96].copy_from_slice(&self.batch);
        bytes[96..112].copy_from_slice(&self.boot);
        bytes[112..120].copy_from_slice(&self.started.to_be_bytes());
        bytes[120..].copy_from_slice(&self.cutoff.to_be_bytes());
        Ok(bytes)
    }

    /// Commits the exact complete original query, including its fresh nonce.
    ///
    /// # Errors
    /// Rejects a noncanonical fixed query before computing its digest.
    pub fn digest_v1(self) -> Result<[u8; 32], SourceDeleteCurrentDataErrorV1> {
        self.digest_for_purpose_v3(SourceDeleteCurrentPurposeDataV3::Planned)
    }

    /// Commits one exact phase's query using its distinct canonical domain.
    ///
    /// # Errors
    /// Rejects malformed query DATA before hashing.
    pub fn digest_for_purpose_v3(self, purpose: SourceDeleteCurrentPurposeDataV3)
        -> Result<[u8; 32], SourceDeleteCurrentDataErrorV1> {
        Ok(Sha256::new().chain_update(purpose.query_domain_v3())
            .chain_update(self.encode_for_purpose_v3(purpose)?).finalize().into())
    }

    fn require_canonical(self) -> Result<(), SourceDeleteCurrentDataErrorV1> {
        if [self.nonce, self.project, self.operation, self.boot].iter().any(|value| *value == [0; 16])
            || self.batch == [0; 32] { return Err(SourceDeleteCurrentDataErrorV1::Format); }
        if self.started == 0 || self.cutoff <= self.started
            || self.cutoff.checked_sub(self.started).is_none_or(|duration|
                duration > SOURCE_DELETE_CURRENT_MAXIMUM_DURATION_NANOSECONDS_V1) {
            return Err(SourceDeleteCurrentDataErrorV1::Clock);
        }
        Ok(())
    }
}

/// Contains the independent Source native cut and complete current Tree identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDeleteCurrentReplyFieldsV1 {
    /// The generation of the actual private retained Source signing key.
    pub generation: u64,
    /// The digest of this exact fresh Root query.
    pub query: [u8; 32],
    /// The boot identity from the fresh paired Source kernel sample.
    pub boot: [u8; 16],
    /// That sample's Unix wall-clock second.
    pub wall_seconds: i64,
    /// That sample's BOOTTIME nanoseconds.
    pub boottime_nanoseconds: u64,
    /// The independently observed Source directory, file and lock identities.
    pub names: ProtectedJournalNamesV1,
    /// The exact complete Source native NEXT.
    pub next: u64,
    /// The exact captured Source native file end.
    pub end: u64,
    /// The actual parser's last COMMIT transaction/digest/sequence/end DATA.
    pub pending_native: [u8; 64],
    /// The named-purpose digest recomputed from the complete actual pending row.
    pub batch: [u8; 32],
    /// The actual canonical pending batch project.
    pub project: [u8; 16],
    /// The actual canonical pending batch operation.
    pub operation: [u8; 16],
    /// The generation of the complete independently replayed current Tree.
    pub tree_generation: u64,
    /// The canonical commitment recomputed from that complete current Tree.
    pub tree_commitment: [u8; 32],
    /// Its actual protected Tree envelope head.
    pub tree_head: [u8; 32],
    /// Its actual immutable closed lineage envelope head.
    pub lineage_head: [u8; 32],
}

impl SourceDeleteCurrentReplyFieldsV1 {
    /// Encodes this complete passive signed body.
    ///
    /// # Errors
    /// Rejects malformed native coordinates, identities, clocks or Tree fields.
    pub fn encode_body(self) -> Result<[u8; SOURCE_DELETE_CURRENT_BODY_BYTES_V1], SourceDeleteCurrentDataErrorV1> {
        self.encode_body_for_purpose_v3(SourceDeleteCurrentPurposeDataV3::Planned)
    }

    /// Encodes the actual current cut under its explicit finite phase domain.
    ///
    /// # Errors
    /// Rejects malformed native/currentness, clock or complete Tree fields.
    pub fn encode_body_for_purpose_v3(self, purpose: SourceDeleteCurrentPurposeDataV3)
        -> Result<[u8; SOURCE_DELETE_CURRENT_BODY_BYTES_V1], SourceDeleteCurrentDataErrorV1> {
        self.require_canonical_for_purpose_v3(purpose)?;
        let mut bytes = [0; SOURCE_DELETE_CURRENT_BODY_BYTES_V1];
        encode_header_for_purpose_v3(&mut bytes, purpose.body_magic_v3(), purpose);
        bytes[16..24].copy_from_slice(&self.generation.to_be_bytes());
        bytes[24..56].copy_from_slice(&self.query);
        bytes[56..72].copy_from_slice(&self.boot);
        bytes[72..80].copy_from_slice(&self.wall_seconds.to_be_bytes());
        bytes[80..88].copy_from_slice(&self.boottime_nanoseconds.to_be_bytes());
        bytes[88..136].copy_from_slice(&self.names.to_bytes());
        bytes[136..144].copy_from_slice(&self.next.to_be_bytes());
        bytes[144..152].copy_from_slice(&self.end.to_be_bytes());
        bytes[152..216].copy_from_slice(&self.pending_native);
        bytes[216..248].copy_from_slice(&self.batch);
        bytes[248..264].copy_from_slice(&self.project);
        bytes[264..280].copy_from_slice(&self.operation);
        bytes[280..288].copy_from_slice(&self.tree_generation.to_be_bytes());
        bytes[288..320].copy_from_slice(&self.tree_commitment);
        bytes[320..352].copy_from_slice(&self.tree_head);
        bytes[352..].copy_from_slice(&self.lineage_head);
        Ok(bytes)
    }

    /// Decodes only the exact body DATA without verifying a signer or currentness.
    ///
    /// # Errors
    /// Rejects framing, malformed names or the same invalid fields as encode.
    pub fn decode_body(bytes: &[u8]) -> Result<Self, SourceDeleteCurrentDataErrorV1> {
        Self::decode_body_for_purpose_v3(bytes, SourceDeleteCurrentPurposeDataV3::Planned)
    }

    /// Decodes only the named current-cut phase without signature authority.
    ///
    /// # Errors
    /// Rejects a different phase/version, framing or invalid complete fields.
    pub fn decode_body_for_purpose_v3(bytes: &[u8], purpose: SourceDeleteCurrentPurposeDataV3)
        -> Result<Self, SourceDeleteCurrentDataErrorV1> {
        header_for_purpose_v3(bytes, SOURCE_DELETE_CURRENT_BODY_BYTES_V1, purpose.body_magic_v3(), purpose)?;
        let value = Self { generation: u64::from_be_bytes(array(bytes, 16)?), query: array(bytes, 24)?,
            boot: array(bytes, 56)?, wall_seconds: i64::from_be_bytes(array(bytes, 72)?),
            boottime_nanoseconds: u64::from_be_bytes(array(bytes, 80)?),
            names: ProtectedJournalNamesV1::from_bytes(&array::<48>(bytes, 88)?).map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?,
            next: u64::from_be_bytes(array(bytes, 136)?), end: u64::from_be_bytes(array(bytes, 144)?),
            pending_native: array(bytes, 152)?, batch: array(bytes, 216)?, project: array(bytes, 248)?,
            operation: array(bytes, 264)?, tree_generation: u64::from_be_bytes(array(bytes, 280)?),
            tree_commitment: array(bytes, 288)?, tree_head: array(bytes, 320)?, lineage_head: array(bytes, 352)? };
        value.require_canonical_for_purpose_v3(purpose)?;
        Ok(value)
    }

    /// Compares the actual original query and independently configured generation.
    ///
    /// # Errors
    /// Rejects a changed query/project/operation/batch/generation or a sample
    /// outside the original boot, start and already-clamped cutoff.
    pub fn require_query(self, query: SourceDeleteCurrentQueryDataV1, generation: u64)
        -> Result<(), SourceDeleteCurrentDataErrorV1> {
        self.require_query_for_purpose_v3(query, generation, SourceDeleteCurrentPurposeDataV3::Planned)
    }

    /// Compares the same original query under exactly the selected phase.
    ///
    /// # Errors
    /// Rejects a changed purpose commitment, identity, generation or clock horizon.
    pub fn require_query_for_purpose_v3(self, query: SourceDeleteCurrentQueryDataV1, generation: u64,
        purpose: SourceDeleteCurrentPurposeDataV3) -> Result<(), SourceDeleteCurrentDataErrorV1> {
        self.require_canonical_for_purpose_v3(purpose)?;
        if self.query != query.digest_for_purpose_v3(purpose)? || self.project != query.project || self.operation != query.operation
            || self.batch != query.batch || self.generation != generation {
            return Err(SourceDeleteCurrentDataErrorV1::Association);
        }
        if self.boot != query.boot || self.boottime_nanoseconds < query.started
            || self.boottime_nanoseconds >= query.cutoff { return Err(SourceDeleteCurrentDataErrorV1::Clock); }
        Ok(())
    }

    fn require_canonical_for_purpose_v3(self, purpose: SourceDeleteCurrentPurposeDataV3) -> Result<(), SourceDeleteCurrentDataErrorV1> {
        ProtectedJournalNamesV1::from_bytes(&self.names.to_bytes()).map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?;
        if self.generation == 0 || self.query == [0; 32] || self.boot == [0; 16]
            || self.project == [0; 16] || self.operation == [0; 16] || self.batch == [0; 32] {
            return Err(SourceDeleteCurrentDataErrorV1::Format);
        }
        let sequence = u64::from_be_bytes(array(&self.pending_native, 48)?);
        let end = u64::from_be_bytes(array(&self.pending_native, 56)?);
        let wrong_transaction = match purpose {
            SourceDeleteCurrentPurposeDataV3::Planned => self.pending_native[..16] != self.operation,
            SourceDeleteCurrentPurposeDataV3::ControllerCommitted | SourceDeleteCurrentPurposeDataV3::Terminal4 => self.pending_native[..16] == [0; 16],
        };
        if wrong_transaction || self.pending_native[16..48] == [0; 32]
            || sequence == 0 || sequence.checked_add(1) != Some(self.next) || end == 0 || end != self.end {
            return Err(SourceDeleteCurrentDataErrorV1::Native);
        }
        if self.boottime_nanoseconds == 0 { return Err(SourceDeleteCurrentDataErrorV1::Clock); }
        if self.tree_generation == 0 || [self.tree_commitment, self.tree_head, self.lineage_head].iter()
            .any(|value| *value == [0; 32]) { return Err(SourceDeleteCurrentDataErrorV1::Tree); }
        Ok(())
    }
}

/// Contains the exact signed DATA packet without granting signer authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDeleteCurrentReplyDataV1 {
    /// The complete independently derived signed body fields.
    pub fields: SourceDeleteCurrentReplyFieldsV1,
    /// The raw Ed25519 signature; Root must verify its own retained public pin.
    pub signature: [u8; 64],
}

impl SourceDeleteCurrentReplyDataV1 {
    /// Encodes a structurally canonical body and signature, without signing.
    ///
    /// # Errors
    /// Rejects malformed fields or an absent signature.
    pub fn encode(self) -> Result<[u8; SOURCE_DELETE_CURRENT_PACKET_BYTES_V1], SourceDeleteCurrentDataErrorV1> {
        self.encode_for_purpose_v3(SourceDeleteCurrentPurposeDataV3::Planned)
    }

    /// Encodes only the explicitly selected body/signature DATA phase.
    ///
    /// # Errors
    /// Rejects malformed fields or an absent signature without signing anything.
    pub fn encode_for_purpose_v3(self, purpose: SourceDeleteCurrentPurposeDataV3)
        -> Result<[u8; SOURCE_DELETE_CURRENT_PACKET_BYTES_V1], SourceDeleteCurrentDataErrorV1> {
        if self.signature == [0; 64] { return Err(SourceDeleteCurrentDataErrorV1::Format); }
        let mut bytes = [0; SOURCE_DELETE_CURRENT_PACKET_BYTES_V1];
        bytes[..SOURCE_DELETE_CURRENT_BODY_BYTES_V1].copy_from_slice(&self.fields.encode_body_for_purpose_v3(purpose)?);
        bytes[SOURCE_DELETE_CURRENT_BODY_BYTES_V1..].copy_from_slice(&self.signature);
        Ok(bytes)
    }

    /// Decodes exact packet DATA while leaving signature verification to Root.
    ///
    /// # Errors
    /// Rejects a nonexact packet, malformed body or absent signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceDeleteCurrentDataErrorV1> {
        Self::decode_for_purpose_v3(bytes, SourceDeleteCurrentPurposeDataV3::Planned)
    }

    /// Decodes only the named signed DATA phase, leaving pin verification to Root.
    ///
    /// # Errors
    /// Rejects another phase/version, inexact framing or absent signature.
    pub fn decode_for_purpose_v3(bytes: &[u8], purpose: SourceDeleteCurrentPurposeDataV3)
        -> Result<Self, SourceDeleteCurrentDataErrorV1> {
        if bytes.len() != SOURCE_DELETE_CURRENT_PACKET_BYTES_V1 { return Err(SourceDeleteCurrentDataErrorV1::Format); }
        let value = Self { fields: SourceDeleteCurrentReplyFieldsV1::decode_body_for_purpose_v3(&bytes[..SOURCE_DELETE_CURRENT_BODY_BYTES_V1], purpose)?,
            signature: array(bytes, SOURCE_DELETE_CURRENT_BODY_BYTES_V1)? };
        if value.signature == [0; 64] { return Err(SourceDeleteCurrentDataErrorV1::Format); }
        Ok(value)
    }
}

fn header_for_purpose_v3(bytes: &[u8], length: usize, magic: &[u8; 8], purpose: SourceDeleteCurrentPurposeDataV3) -> Result<(), SourceDeleteCurrentDataErrorV1> {
    if bytes.len() != length || &bytes[..8] != magic || bytes[8..10] != purpose.version_v3().to_be_bytes()
        || bytes[10..16] != [0; 6] { return Err(SourceDeleteCurrentDataErrorV1::Format); }
    Ok(())
}

fn encode_header_for_purpose_v3(bytes: &mut [u8], magic: &[u8; 8], purpose: SourceDeleteCurrentPurposeDataV3) {
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&purpose.version_v3().to_be_bytes());
}

fn array<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], SourceDeleteCurrentDataErrorV1> {
    bytes.get(start..start.checked_add(N).ok_or(SourceDeleteCurrentDataErrorV1::Format)?)
        .and_then(|bytes| bytes.try_into().ok()).ok_or(SourceDeleteCurrentDataErrorV1::Format)
}

#[cfg(test)]
mod tests;
