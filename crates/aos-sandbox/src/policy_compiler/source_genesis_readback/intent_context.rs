//! Untrusted replay context checked against the actual Source receipt and nonce.
//!
//! ```text
//! AOSSGX01 | version:u16=1 | reserved[6] | Source-uid:u32 |
//! reserved:u32 | Root-role-tuple[32] | Controller-acceptance[608]
//! AOSSGX02 retains SGC02[784] in the same 56-byte context prefix.
//! ```
//!
//! Root derives these data from its retained intent or floor. They grant no
//! custody: the independent Source reader reconstructs the original canonical
//! intent with its own durable instance and pending nonce, then compares the
//! receipt commitment. A fresh observation challenge never replaces that nonce.

use aos_sandbox_core::ObjectDigest;

use crate::hierarchy::SourceTreeGenesisReceiptV1;
use crate::hierarchy::genesis_profile::{
    ControllerSourceGenesisAcceptanceRecordV1, SourceGenesisErrorV1,
};
use crate::journal::source_tree_genesis::SourceGenesisPendingV1;
use crate::policy_compiler::{RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1};

/// Bounds the data-only original intent comparison context.
pub const SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1: usize = 664;
/// Bounds comparison context carrying the complete resource acceptance.
pub const SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V2: usize = 840;

/// Carries comparison data without authenticating Root or granting mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceTreeGenesisIntentContextV1 {
    source_uid: u32,
    roles: ObjectDigest,
    acceptance: ControllerSourceGenesisAcceptanceRecordV1,
}

impl SourceTreeGenesisIntentContextV1 {
    pub(crate) fn new(
        source_uid: u32,
        roles: ObjectDigest,
        acceptance: ControllerSourceGenesisAcceptanceRecordV1,
    ) -> Result<Self, SourceGenesisErrorV1> {
        if source_uid == 0 || roles.as_bytes() == &[0; 32] {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(Self {
            source_uid,
            roles,
            acceptance,
        })
    }

    /// Decodes bounded comparison data, never a retained Root proof.
    ///
    /// # Errors
    /// Rejects another format/width, reserved bytes, sentinel UID/roles or
    /// a noncanonical original Controller acceptance.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        let resource_version = bytes.len() == SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V2
            && bytes.get(..8) == Some(b"AOSSGX02".as_slice())
            && bytes.get(8..16) == Some([0, 2, 0, 0, 0, 0, 0, 0].as_slice());
        let legacy = bytes.len() == SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1
            && bytes.get(..8) == Some(b"AOSSGX01".as_slice())
            && bytes.get(8..16) == Some([0, 1, 0, 0, 0, 0, 0, 0].as_slice());
        if !legacy && !resource_version {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        if bytes[20..24] != [0; 4] {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let source_uid = u32::from_be_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
        );
        let roles = ObjectDigest::from_bytes(
            bytes[24..56]
                .try_into()
                .map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
        );
        let context = Self::new(
            source_uid,
            roles,
            ControllerSourceGenesisAcceptanceRecordV1::from_record_bytes(&bytes[56..])?,
        )?;
        if context.acceptance.resource_envelope().is_some() != resource_version {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(context)
    }

    /// Returns the canonical bounded data frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let resource_version = self.acceptance.resource_envelope().is_some();
        let mut bytes = vec![0; 56 + self.acceptance.record_bytes().len()];
        bytes[..8].copy_from_slice(if resource_version { b"AOSSGX02" } else { b"AOSSGX01" });
        bytes[8..10].copy_from_slice(&(if resource_version { 2_u16 } else { 1 }).to_be_bytes());
        bytes[16..20].copy_from_slice(&self.source_uid.to_be_bytes());
        bytes[24..56].copy_from_slice(self.roles.as_bytes());
        bytes[56..].copy_from_slice(self.acceptance.record_bytes());
        bytes
    }

    /// Returns the claimed UID, which the fixed signer checks independently.
    #[must_use]
    pub const fn source_uid(&self) -> u32 {
        self.source_uid
    }

    /// Returns the claimed project, which must match the actual selected receipt.
    #[must_use]
    pub fn project(&self) -> aos_sandbox_core::ProjectId {
        self.acceptance.project()
    }

    /// Selects only the complete resource packet framing, not current authority.
    #[must_use]
    pub fn has_resource_authorization(&self) -> bool {
        self.acceptance.resource_envelope().is_some()
    }

    pub(crate) fn require_actual_receipt(
        &self,
        receipt: &SourceTreeGenesisReceiptV1,
        pending: Option<&SourceGenesisPendingV1>,
    ) -> Result<(), SourceGenesisErrorV1> {
        if receipt.project() != self.acceptance.project()
            || receipt.acceptance_digest() != self.acceptance.digest()
            || &receipt.seed_packet() != self.acceptance.seed_packet()
            || receipt.auth_packet() != self.acceptance.auth_packet()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        if let Some(pending) = pending {
            let original = RootSourceGenesisIntentRecordV1::new(
                pending.instance,
                self.source_uid,
                pending.nonce,
                self.acceptance.clone(),
                self.roles,
            )?;
            if pending.project != receipt.project()
                || pending.instance != receipt.instance()
                || pending.receipt != receipt.digest()
                || pending.intent != receipt.intent_digest()
                || original.digest() != receipt.intent_digest()
            {
                return Err(SourceGenesisErrorV1::Conflict);
            }
        }
        Ok(())
    }

    pub(crate) fn require_actual_ack(
        &self,
        receipt: &SourceTreeGenesisReceiptV1,
        root_floor: ObjectDigest,
    ) -> Result<(), SourceGenesisErrorV1> {
        // Once ACK removes the pending nonce, its exact floor commitment
        // independently preserves the original receipt and Root role tuple.
        if SourceHierarchyFloorRecordV1::new(receipt.clone(), self.roles)?.digest() != root_floor {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        Ok(())
    }
}
