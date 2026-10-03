//! Canonical local-Root instance, genesis intent, and semantic floor data.
//!
//! ```text
//! AOSSDI01 | version:u16=1 | reserved[6] | Root-created instance[32] | checksum[32]
//! AOSSGI01 | version:u16=1 | reserved[6] | instance[32] | project[16] |
//! source-uid:u32 | reserved:u32 | nonce[16] | Controller acceptance[608] |
//! independently pinned role tuple[32] | predecessor-floor[32]=0 | checksum[32]
//! AOSHGF01 | version:u16=1 | reserved[6] | semantic-revision:u64=1 |
//! predecessor-floor[32]=0 | Source immutable receipt[672] | role tuple[32] | checksum[32]
//! ```
//!
//! ACKs, pending fences, physical names, and frame sequences are not part of
//! the narrowly defined genesis materialization. This authenticates neither
//! the complete Source journal nor an unrelated project's currentness.

use aos_sandbox_core::{ObjectDigest, ProjectId};

use crate::hierarchy::genesis_profile::{
    ControllerSourceGenesisAcceptanceRecordV1, SourceGenesisErrorV1, digest_at, hash, take,
};
use crate::hierarchy::source_genesis::SourceTreeGenesisReceiptV1;

pub(super) const INSTANCE_KEY: &[u8] = b"\0aos-source-genesis-root-instance-v1\0";
pub(super) const PINS_KEY: &[u8] = b"\0aos-source-genesis-root-pins-v1\0";
pub(super) const INTENT_PREFIX: &[u8] = b"\0aos-source-genesis-intent-v1\0";
pub(super) const FLOOR_PREFIX: &[u8] = b"\0aos-source-hierarchy-floor-v1\0";
const INSTANCE_MAGIC: &[u8; 8] = b"AOSSDI01";
const INTENT_MAGIC: &[u8; 8] = b"AOSSGI01";
const FLOOR_MAGIC: &[u8; 8] = b"AOSHGF01";
const INSTANCE_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.root-instance.v1\0";
const INTENT_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.root-intent.v1\0";
const FLOOR_DOMAIN: &[u8] = b"aos.sandbox.source-hierarchy.semantic-floor.v1\0";

/// Bounds the exact Root-owned durable deployment-instance row.
pub const SOURCE_GENESIS_DEPLOYMENT_INSTANCE_BYTES_V1: usize = 80;
/// Bounds the exact Root prepare intent retained before Source mutation.
pub const ROOT_SOURCE_GENESIS_INTENT_BYTES_V1: usize = 792;
/// Bounds one initial semantic per-project Root hierarchy floor.
pub const SOURCE_HIERARCHY_FLOOR_BYTES_V1: usize = 792;

pub(super) fn instance_bytes(instance: [u8; 32]) -> Result<[u8; 80], SourceGenesisErrorV1> {
    if instance == [0; 32] {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let mut bytes = [0; 80];
    header(&mut bytes, INSTANCE_MAGIC);
    bytes[16..48].copy_from_slice(&instance);
    let checksum = hash(INSTANCE_DOMAIN, &bytes[..48]);
    bytes[48..].copy_from_slice(checksum.as_bytes());
    Ok(bytes)
}

pub(super) fn decode_instance(bytes: &[u8]) -> Result<[u8; 32], SourceGenesisErrorV1> {
    require_header(bytes, INSTANCE_MAGIC, 80)?;
    let instance = take(bytes, 16)?;
    if instance == [0; 32] || instance_bytes(instance)?.as_slice() != bytes {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(instance)
}

/// Carries canonical prepare data, never an independently held Root proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootSourceGenesisIntentRecordV1 {
    bytes: [u8; ROOT_SOURCE_GENESIS_INTENT_BYTES_V1],
    acceptance: ControllerSourceGenesisAcceptanceRecordV1,
}

impl RootSourceGenesisIntentRecordV1 {
    // Canonical DATA construction is shared with independent Source replay;
    // it cannot construct the live borrowed intent consumed by an append.
    pub(crate) fn new(
        instance: [u8; 32],
        source_uid: u32,
        nonce: [u8; 16],
        acceptance: ControllerSourceGenesisAcceptanceRecordV1,
        roles: ObjectDigest,
    ) -> Result<Self, SourceGenesisErrorV1> {
        let mut bytes = [0; ROOT_SOURCE_GENESIS_INTENT_BYTES_V1];
        header(&mut bytes, INTENT_MAGIC);
        bytes[16..48].copy_from_slice(&instance);
        bytes[48..64].copy_from_slice(acceptance.project().as_bytes());
        bytes[64..68].copy_from_slice(&source_uid.to_be_bytes());
        bytes[72..88].copy_from_slice(&nonce);
        bytes[88..696].copy_from_slice(acceptance.record_bytes());
        bytes[696..728].copy_from_slice(roles.as_bytes());
        let checksum = hash(INTENT_DOMAIN, &bytes[..760]);
        bytes[760..].copy_from_slice(checksum.as_bytes());
        Self::from_record_bytes(&bytes)
    }

    /// Decodes data only, without granting permission to mutate Source.
    ///
    /// # Errors
    /// Rejects noncanonical framing, sentinels, or changed acceptance bindings.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        require_header(bytes, INTENT_MAGIC, ROOT_SOURCE_GENESIS_INTENT_BYTES_V1)?;
        let acceptance =
            ControllerSourceGenesisAcceptanceRecordV1::from_record_bytes(&bytes[88..696])?;
        let record = Self {
            bytes: take(bytes, 0)?,
            acceptance,
        };
        if record.instance() == [0; 32]
            || record.project() != record.acceptance.project()
            || record.source_uid() == 0
            || bytes[68..72] != [0; 4]
            || record.nonce() == [0; 16]
            || record.roles().as_bytes() == &[0; 32]
            || bytes[728..760] != [0; 32]
            || hash(INTENT_DOMAIN, &bytes[..760]).as_bytes() != &take::<32>(bytes, 760)?
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(record)
    }

    /// Returns Root's durable, non-caller-selected instance identity.
    #[must_use]
    pub fn instance(&self) -> [u8; 32] {
        array_at(&self.bytes, 16)
    }

    /// Returns the exact initial project selected by the administrative input.
    #[must_use]
    pub fn project(&self) -> ProjectId {
        self.acceptance.project()
    }

    /// Returns the Source filesystem owner selected by privileged configuration.
    #[must_use]
    pub fn source_uid(&self) -> u32 {
        u32::from_be_bytes(array_at(&self.bytes, 64))
    }

    /// Returns the Root-owned challenge retained before the Source append.
    #[must_use]
    pub fn nonce(&self) -> [u8; 16] {
        array_at(&self.bytes, 72)
    }

    /// Returns the immutable Controller acceptance commitment.
    #[must_use]
    pub fn acceptance(&self) -> ObjectDigest {
        self.acceptance.digest()
    }

    /// Borrows the complete original accepted input record.
    #[must_use]
    pub const fn accepted_input(&self) -> &ControllerSourceGenesisAcceptanceRecordV1 {
        &self.acceptance
    }

    /// Returns the independently protected role tuple commitment.
    #[must_use]
    pub fn roles(&self) -> ObjectDigest {
        digest_at(&self.bytes, 696)
    }

    /// Returns the canonical immutable intent commitment.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        hash(INTENT_DOMAIN, &self.bytes)
    }

    /// Borrows the complete canonical data frame.
    #[must_use]
    pub const fn record_bytes(&self) -> &[u8; ROOT_SOURCE_GENESIS_INTENT_BYTES_V1] {
        &self.bytes
    }
}

/// Carries one Root-protected semantic floor as data, not a live read-hold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceHierarchyFloorRecordV1 {
    bytes: [u8; SOURCE_HIERARCHY_FLOOR_BYTES_V1],
    receipt: SourceTreeGenesisReceiptV1,
}

impl SourceHierarchyFloorRecordV1 {
    // Rebuilding this DATA commitment validates a Source ACK, not Root custody.
    pub(crate) fn new(
        receipt: SourceTreeGenesisReceiptV1,
        roles: ObjectDigest,
    ) -> Result<Self, SourceGenesisErrorV1> {
        let mut bytes = [0; SOURCE_HIERARCHY_FLOOR_BYTES_V1];
        header(&mut bytes, FLOOR_MAGIC);
        bytes[16..24].copy_from_slice(&1_u64.to_be_bytes());
        bytes[56..728].copy_from_slice(&receipt.encode());
        bytes[728..760].copy_from_slice(roles.as_bytes());
        let checksum = hash(FLOOR_DOMAIN, &bytes[..760]);
        bytes[760..].copy_from_slice(checksum.as_bytes());
        Self::from_record_bytes(&bytes)
    }

    /// Decodes the initial semantic profile without minting a held floor proof.
    ///
    /// # Errors
    /// Rejects unsupported successors, sentinel roles, or changed receipt bytes.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        require_header(bytes, FLOOR_MAGIC, SOURCE_HIERARCHY_FLOOR_BYTES_V1)?;
        let receipt = SourceTreeGenesisReceiptV1::decode(&bytes[56..728])?;
        if bytes[16..24] != 1_u64.to_be_bytes()
            || bytes[24..56] != [0; 32]
            || bytes[728..760] == [0; 32]
            || hash(FLOOR_DOMAIN, &bytes[..760]).as_bytes() != &take::<32>(bytes, 760)?
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(Self {
            bytes: take(bytes, 0)?,
            receipt,
        })
    }

    /// Returns the Root-owned deployment instance retained by the receipt.
    #[must_use]
    pub fn instance(&self) -> [u8; 32] {
        self.receipt.instance()
    }
    /// Returns the exact project whose genesis state is anchored.
    #[must_use]
    pub fn project(&self) -> ProjectId {
        self.receipt.project()
    }
    /// Returns the semantic revision; diagnostic frame counts are not floors.
    #[must_use]
    pub const fn semantic_revision(&self) -> u64 {
        1
    }
    /// Returns the absent predecessor for the initial floor.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ObjectDigest> {
        None
    }
    /// Returns the exact immutable receipt commitment.
    #[must_use]
    pub fn receipt_digest(&self) -> ObjectDigest {
        self.receipt.digest()
    }
    /// Returns the canonical Tree member head.
    #[must_use]
    pub fn tree_head(&self) -> ObjectDigest {
        self.receipt.tree_head()
    }
    /// Returns the canonical seed-lineage member head.
    #[must_use]
    pub fn lineage_head(&self) -> ObjectDigest {
        self.receipt.lineage_head()
    }
    /// Returns only the explicitly bounded genesis materialization commitment.
    #[must_use]
    pub fn materialization(&self) -> ObjectDigest {
        self.receipt.materialization()
    }
    /// Borrows the actual immutable Source receipt retained by Root.
    #[must_use]
    pub const fn receipt(&self) -> &SourceTreeGenesisReceiptV1 {
        &self.receipt
    }
    /// Returns the original independently pinned role tuple commitment.
    #[must_use]
    pub fn roles(&self) -> ObjectDigest {
        digest_at(&self.bytes, 728)
    }
    /// Returns the exact canonical semantic floor commitment.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        hash(FLOOR_DOMAIN, &self.bytes)
    }
    /// Borrows the canonical data; these bytes alone grant no authority.
    #[must_use]
    pub const fn record_bytes(&self) -> &[u8; SOURCE_HIERARCHY_FLOOR_BYTES_V1] {
        &self.bytes
    }
}

pub(super) fn project_key(prefix: &[u8], project: ProjectId) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(project.as_bytes());
    key
}

fn header(bytes: &mut [u8], magic: &[u8; 8]) {
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
}

fn require_header(
    bytes: &[u8],
    magic: &[u8; 8],
    length: usize,
) -> Result<(), SourceGenesisErrorV1> {
    if bytes.len() != length
        || bytes.get(..8) != Some(magic.as_slice())
        || bytes[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(())
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut array = [0; N];
    array.copy_from_slice(&bytes[offset..offset + N]);
    array
}
