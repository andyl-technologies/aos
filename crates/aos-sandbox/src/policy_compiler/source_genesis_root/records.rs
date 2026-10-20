//! Adapts canonical Source-owned Root genesis DATA to native errors.
//!
//! Root writers, independent pins and currentness remain with their actual
//! native owner. Decoded instance, intent and floor bytes grant no authority.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use aos_sandbox_ledger_replay::genesis::SourceTreeGenesisReceiptV1;
use aos_sandbox_ledger_replay::replay::root_genesis_records as canonical;

pub(super) use canonical::{INSTANCE_KEY, PINS_KEY, INTENT_PREFIX, FLOOR_PREFIX};
pub use canonical::{SOURCE_GENESIS_DEPLOYMENT_INSTANCE_BYTES_V1,
    ROOT_SOURCE_GENESIS_INTENT_BYTES_V1, SOURCE_HIERARCHY_FLOOR_BYTES_V1,
    ROOT_SOURCE_GENESIS_INTENT_BYTES_V2, SOURCE_HIERARCHY_FLOOR_BYTES_V2};

pub(super) fn instance_bytes(instance: [u8; 32]) -> Result<[u8; 80], SourceGenesisErrorV1> {
    canonical::instance_bytes(instance).map_err(SourceGenesisErrorV1::from)
}

pub(super) fn decode_instance(bytes: &[u8]) -> Result<[u8; 32], SourceGenesisErrorV1> {
    canonical::decode_instance(bytes).map_err(SourceGenesisErrorV1::from)
}

/// Retains canonical saved Root intent DATA without native authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootSourceGenesisIntentRecordV1(canonical::RootSourceGenesisIntentRecordV1);

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
        canonical::RootSourceGenesisIntentRecordV1::new(instance, source_uid, nonce, acceptance, roles)
            .map(Self).map_err(SourceGenesisErrorV1::from)
    }

    /// Decodes data only, without granting permission to mutate Source.
    ///
    /// # Errors
    /// Rejects noncanonical framing, sentinels, or changed acceptance bindings.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        canonical::RootSourceGenesisIntentRecordV1::from_record_bytes(bytes)
            .map(Self).map_err(SourceGenesisErrorV1::from)
    }

    /// Returns Root's durable, non-caller-selected instance identity.
    #[must_use]
    pub fn instance(&self) -> [u8; 32] {
        self.0.instance()
    }

    /// Returns the exact initial project selected by the administrative input.
    #[must_use]
    pub fn project(&self) -> ProjectId {
        self.0.project()
    }

    /// Returns the Source filesystem owner selected by privileged configuration.
    #[must_use]
    pub fn source_uid(&self) -> u32 {
        self.0.source_uid()
    }

    /// Returns the Root-owned challenge retained before the Source append.
    #[must_use]
    pub fn nonce(&self) -> [u8; 16] {
        self.0.nonce()
    }

    /// Returns the immutable Controller acceptance commitment.
    #[must_use]
    pub fn acceptance(&self) -> ObjectDigest {
        self.0.acceptance()
    }

    /// Borrows the complete original accepted input record.
    #[must_use]
    pub const fn accepted_input(&self) -> &ControllerSourceGenesisAcceptanceRecordV1 {
        self.0.accepted_input()
    }

    /// Returns the independently protected role tuple commitment.
    #[must_use]
    pub fn roles(&self) -> ObjectDigest {
        self.0.roles()
    }

    /// Returns the canonical immutable intent commitment.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        self.0.digest()
    }

    /// Borrows the complete canonical data frame.
    #[must_use]
    pub fn record_bytes(&self) -> &[u8] {
        self.0.record_bytes()
    }
}

/// Retains canonical saved initial floor DATA without native authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceHierarchyFloorRecordV1(canonical::SourceHierarchyFloorRecordV1);

impl SourceHierarchyFloorRecordV1 {
    // Rebuilding this DATA commitment validates a Source ACK, not Root custody.
    pub(crate) fn new(
        receipt: SourceTreeGenesisReceiptV1,
        roles: ObjectDigest,
    ) -> Result<Self, SourceGenesisErrorV1> {
        canonical::SourceHierarchyFloorRecordV1::new(receipt, roles)
            .map(Self).map_err(SourceGenesisErrorV1::from)
    }

    /// Decodes the initial semantic profile without minting a held floor proof.
    ///
    /// # Errors
    /// Rejects unsupported successors, sentinel roles, or changed receipt bytes.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        canonical::SourceHierarchyFloorRecordV1::from_record_bytes(bytes)
            .map(Self).map_err(SourceGenesisErrorV1::from)
    }

    /// Returns the Root-owned deployment instance retained by the receipt.
    #[must_use]
    pub fn instance(&self) -> [u8; 32] {
        self.0.instance()
    }

    /// Returns the exact project whose genesis state is anchored.
    #[must_use]
    pub fn project(&self) -> ProjectId {
        self.0.project()
    }

    /// Returns the semantic revision; diagnostic frame counts are not floors.
    #[must_use]
    pub const fn semantic_revision(&self) -> u64 {
        self.0.semantic_revision()
    }

    /// Returns the absent predecessor for the initial floor.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ObjectDigest> {
        self.0.predecessor()
    }

    /// Returns the exact immutable receipt commitment.
    #[must_use]
    pub fn receipt_digest(&self) -> ObjectDigest {
        self.0.receipt_digest()
    }

    /// Returns the canonical Tree member head.
    #[must_use]
    pub fn tree_head(&self) -> ObjectDigest {
        self.0.tree_head()
    }

    /// Returns the canonical seed-lineage member head.
    #[must_use]
    pub fn lineage_head(&self) -> ObjectDigest {
        self.0.lineage_head()
    }

    /// Returns only the explicitly bounded genesis materialization commitment.
    #[must_use]
    pub fn materialization(&self) -> ObjectDigest {
        self.0.materialization()
    }

    /// Borrows the actual immutable Source receipt retained by Root.
    #[must_use]
    pub const fn receipt(&self) -> &SourceTreeGenesisReceiptV1 {
        self.0.receipt()
    }

    /// Returns the original independently pinned role tuple commitment.
    #[must_use]
    pub fn roles(&self) -> ObjectDigest {
        self.0.roles()
    }

    /// Returns the exact canonical semantic floor commitment.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        self.0.digest()
    }

    /// Borrows the canonical data; these bytes alone grant no authority.
    #[must_use]
    pub fn record_bytes(&self) -> &[u8] {
        self.0.record_bytes()
    }
}
