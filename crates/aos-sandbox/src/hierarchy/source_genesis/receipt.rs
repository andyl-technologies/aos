//! Immutable Source genesis receipt data, never a live ancestry authority.
//!
//! ```text
//! AOSSGR01 | version:u16be | reserved[6]=0 | Root-instance[32] |
//! Root-intent-digest[32] | Controller-acceptance-digest[32] | project[16] |
//! exact AOSCSE01[224] | exact AOSPSC02[224] | Tree-head[32] |
//! seed-lineage-head[32] | semantic-materialization[32]
//! ```
//!
//! The final commitment covers length-framed canonical Tree and lineage
//! members plus the preceding 640 receipt bytes. It excludes only its own
//! digest, pending/ACK rows, physical names and diagnostic frame positions;
//! it does not authenticate unrelated Source journal contents.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::super::genesis_profile::SourceGenesisErrorV1;
use super::super::source_seed::{
    CONTROLLER_SOURCE_TREE_SEED_BODY_BYTES_V1, decode_source_tree_seed_body_v1,
};

/// Bounds the immutable, explicitly versioned Source genesis receipt.
pub const SOURCE_TREE_GENESIS_RECEIPT_BYTES_V1: usize = 672;
const PREFIX_BYTES: usize = 640;
const MAGIC: &[u8; 8] = b"AOSSGR01";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.source-tree-genesis.receipt.v1\0";
const MATERIALIZATION_DOMAIN: &[u8] = b"aos.sandbox.source-tree-genesis.materialization.v1\0";

/// Retains exact genesis data without granting currentness or append authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceTreeGenesisReceiptV1 {
    bytes: [u8; SOURCE_TREE_GENESIS_RECEIPT_BYTES_V1],
}

impl SourceTreeGenesisReceiptV1 {
    /// Decodes canonical data, not a Root floor or an authenticated observation.
    ///
    /// # Errors
    ///
    /// Rejects another width/version, reserved bytes, sentinel commitments,
    /// malformed administrative packets, or a different seed project.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        let bytes: [u8; SOURCE_TREE_GENESIS_RECEIPT_BYTES_V1] = bytes
            .try_into()
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        if &bytes[..8] != MAGIC
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
            || bytes[112..128] == [0; 16]
            || [16, 48, 80, 576, 608, 640]
                .iter()
                .any(|offset| bytes[*offset..*offset + 32] == [0; 32])
            || &bytes[128..136] != b"AOSCSE01"
            || bytes[136..138] != 1_u16.to_be_bytes()
            || bytes[138..140] != [0; 2]
            || bytes[140..148] == [0; 8]
            || &bytes[352..360] != b"AOSPSC02"
            || bytes[360..362] != 2_u16.to_be_bytes()
            || bytes[362..364] != [0; 2]
            || bytes[364..372] == [0; 8]
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let seed = decode_source_tree_seed_body_v1(
            &bytes[128..128 + CONTROLLER_SOURCE_TREE_SEED_BODY_BYTES_V1],
        )
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let authorization =
            crate::publisher_policy::parse_unverified_project_authorization_claims_v2(
                &bytes[352..576],
            )
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        if seed.project().as_bytes() != &bytes[112..128]
            || authorization.project != seed.project()
            || authorization.request_id != seed.request_id()
            || authorization.epoch != seed.epoch()
            || authorization.limits != seed.limits()
            || authorization.publisher_generation != seed.publisher_generation()
            || authorization.publisher_head_digest != seed.publisher_head()
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(Self { bytes })
    }

    /// Returns the exact canonical immutable receipt bytes.
    #[must_use]
    pub const fn encode(&self) -> [u8; SOURCE_TREE_GENESIS_RECEIPT_BYTES_V1] {
        self.bytes
    }

    /// Returns the deployment instance owning the independent Root anchor.
    #[must_use]
    pub fn instance(&self) -> [u8; 32] {
        self.array(16)
    }

    /// Returns the exact prepared Root intent commitment.
    #[must_use]
    pub fn intent_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.array(48))
    }

    /// Returns the immutable held Controller acceptance commitment.
    #[must_use]
    pub fn acceptance_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.array(80))
    }

    /// Returns the administrative seed project.
    #[must_use]
    pub fn project(&self) -> ProjectId {
        ProjectId::from_bytes(self.array(112))
    }

    /// Returns the original administrative seven-limit signed seed packet.
    #[must_use]
    pub fn seed_packet(&self) -> [u8; 224] {
        self.array(128)
    }

    /// Returns the exact signed project authorization packet.
    #[must_use]
    pub fn auth_packet(&self) -> [u8; 224] {
        self.array(352)
    }

    /// Returns the canonical initial Tree envelope head.
    #[must_use]
    pub fn tree_head(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.array(576))
    }

    /// Returns the canonical seed lineage envelope head.
    #[must_use]
    pub fn lineage_head(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.array(608))
    }

    /// Returns the narrow genesis materialization commitment.
    #[must_use]
    pub fn materialization(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.array(640))
    }

    /// Returns a domain-separated commitment to all immutable receipt bytes.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(RECEIPT_DOMAIN)
                .chain_update(self.bytes)
                .finalize()
                .into(),
        )
    }

    pub(super) fn from_owner_fields(
        instance: [u8; 32],
        intent: ObjectDigest,
        acceptance: &super::super::genesis_profile::ControllerSourceGenesisAcceptanceRecordV1,
        tree_head: ObjectDigest,
        lineage_head: ObjectDigest,
        tree_member: &[u8],
        lineage_member: &[u8],
    ) -> Result<Self, SourceGenesisErrorV1> {
        let mut bytes = [0; SOURCE_TREE_GENESIS_RECEIPT_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(&instance);
        bytes[48..80].copy_from_slice(intent.as_bytes());
        bytes[80..112].copy_from_slice(acceptance.digest().as_bytes());
        bytes[112..128].copy_from_slice(acceptance.project().as_bytes());
        bytes[128..352].copy_from_slice(acceptance.seed_packet());
        bytes[352..576].copy_from_slice(acceptance.auth_packet());
        bytes[576..608].copy_from_slice(tree_head.as_bytes());
        bytes[608..640].copy_from_slice(lineage_head.as_bytes());
        let materialization = materialization(tree_member, lineage_member, &bytes[..PREFIX_BYTES]);
        bytes[640..].copy_from_slice(materialization.as_bytes());
        Self::decode(&bytes)
    }

    pub(crate) fn matches_members(&self, tree: &[u8], lineage: &[u8]) -> bool {
        self.materialization() == materialization(tree, lineage, &self.bytes[..PREFIX_BYTES])
    }

    fn array<const N: usize>(&self, offset: usize) -> [u8; N] {
        let mut bytes = [0; N];
        bytes.copy_from_slice(&self.bytes[offset..offset + N]);
        bytes
    }
}

fn materialization(tree: &[u8], lineage: &[u8], receipt_prefix: &[u8]) -> ObjectDigest {
    let mut hash = Sha256::new().chain_update(MATERIALIZATION_DOMAIN);
    for bytes in [tree, lineage, receipt_prefix] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    ObjectDigest::from_bytes(hash.finalize().into())
}
