//! Versioned public-ledger receipt binding for a completed Storage Repair.
//!
//! This format is deliberately not dispatchable. A future terminal CAS must
//! supply a fresh challenged post-proof Inventory result and commit this exact
//! receipt with the predecessor archive, public Effect, Operation, Sandbox
//! projection, and protected current head. Cold recovery must verify every
//! retained commitment before projecting success.
//!
//! ```text
//! AOSOTL01 | operation-id[16] | sandbox-id[16] | owner-id[16]
//! owner-key-generation:u64be | proof-digest[32] | owner-record-digest[32]
//! predecessor-projection-digest[32] | successor-projection-digest[32]
//! successor-current-digest[32] | physical-version[32]
//! fresh-request-id[16] | fresh-packet-digest[32] | checksum[32]
//! archive = "AOSOAR01" | operation-id[16] | sandbox-id[16] |
//!           predecessor-head-digest[32] | receipt-digest[32] |
//!           predecessor-len:u32be | predecessor-projection | checksum[32]
//! ```

use aos_proto::aos::sandbox::local::v1::RepairStorageWorkspacePinRequest;
use aos_sandbox_core::operator_recovery_effect::{
    OperatorRecoveryEffectIntentV1, verify_operator_recovery_effect_intent_v1,
};
use aos_sandbox_core::{OperationId, ProjectId};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::{MAXIMUM_RESPONSE_BYTES, decode_storage_resource_inventory_response};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::super::probe_challenge::{self, ProbeStageV1};
use super::super::receipt::{
    ProtectedStorageRepairReceiptVerifierV2, VerifiedRetainedRepairReceiptV3,
    verified_retained_repair_receipt_v3,
};
use super::super::{
    CURRENT_HEAD_DOMAIN_V2, FENCE_DOMAIN, OperatorRecoveryIssuanceErrorV1,
    ProtectedOperatorRecoverySignerV1, REQUEST_DOMAIN, StorageRepairIssuanceV2, hash,
    issuance_key_v2,
};
use super::StoredProofV2;
use crate::controller::recovery_current_key;
use crate::controller_query::MAXIMUM_PUBLIC_RESOURCE_BYTES;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionPlanV1, PublicProjectionStoreV1,
};
use crate::lifecycle::LifecycleAuthenticatedStorageInventoryV1;
use crate::{Journal, JournalRecord, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSOTL01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-terminal-ledger-receipt.v1\0";
const CURRENT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-terminal-current.v1\0";
const FRESH_PACKET_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-terminal-fresh-packet.v1\0";
const RECEIPT_BYTES: usize = 336;
const ARCHIVE_MAGIC: &[u8; 8] = b"AOSOAR01";
const ARCHIVE_PREFIX: &[u8] = b"storage-repair-predecessor-v1/";
const ARCHIVE_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-predecessor-archive.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-terminal-receipt-link.v1\0";
const ARCHIVE_HEADER_BYTES: usize = 8 + 16 + 16 + 32 + 32 + 4;
const ARCHIVE_TRAILER_BYTES: usize = 32;
// AOSPRJ01 has a fixed 96-byte header ahead of the bounded resource body.
const MAXIMUM_ARCHIVED_PROJECTION_BYTES: usize = MAXIMUM_PUBLIC_RESOURCE_BYTES + 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BoundRepairLedgerReceiptV1 {
    pub(super) operation_id: [u8; 16],
    pub(super) sandbox_id: [u8; 16],
    pub(super) owner_id: [u8; 16],
    pub(super) owner_key_generation: u64,
    pub(super) proof_digest: [u8; 32],
    pub(super) owner_record_digest: [u8; 32],
    pub(super) predecessor_projection_digest: [u8; 32],
    pub(super) successor_projection_digest: [u8; 32],
    pub(super) successor_current_digest: [u8; 32],
    pub(super) physical_version: [u8; 32],
    pub(super) fresh_request_id: [u8; 16],
    pub(super) fresh_packet_digest: [u8; 32],
}

impl BoundRepairLedgerReceiptV1 {
    /// Joins one challenged fresh Inventory to the still-current sealed owner proof.
    ///
    /// The exact predecessor projection is read from protected custody. This
    /// remains a nonterminal preparation: its caller must atomically retain
    /// that predecessor and commit a current Storage fence with the public
    /// Effect, Operation, successor projection, and protected head.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_current_verified_rows(
        journal: &mut Journal,
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
        operation_id: OperationId,
        storage_request_body: &[u8],
        predecessor_projection: &[u8],
        successor_projection: &PublicProjectionPlanV1,
        successor_current: &[u8],
        fresh: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        signer
            .credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        owner.recheck()?;
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;

        let issuance_key = issuance_key_v2(*operation_id.as_bytes());
        let issued = StorageRepairIssuanceV2::decode(
            &issuance_key,
            journal
                .get(RecordNamespace::OperatorRecovery, &issuance_key)
                .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
            signer.verifier(),
            signer.key_id(),
            signer.generation(),
        )?;
        let intent =
            verify_operator_recovery_effect_intent_v1(&issued.signed_intent, signer.verifier())
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let current = journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(intent.target_id),
            )
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        if intent.recovery_operation_id != *operation_id.as_bytes()
            || hash(CURRENT_HEAD_DOMAIN_V2, &[current]) != issued.current_head_digest
            || journal.get(
                RecordNamespace::DesiredState,
                successor_projection.desired_key(),
            ) != Some(predecessor_projection)
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let owner_facts = verified_retained_repair_receipt_v3(journal, &intent, owner)?;
        let proof = super::read_sealed_proof_v2(
            journal,
            &issued,
            intent.effect_id,
            owner_facts.signed_pair_digest,
        )?;
        probe_challenge::read(
            journal,
            &issued,
            intent.effect_id,
            ProbeStageV1::Terminal,
            owner_facts.signed_pair_digest,
        )?
        .matches_outcome(fresh)?;
        let receipt = Self::from_verified_rows(
            &proof,
            &owner_facts,
            &intent,
            storage_request_body,
            intent.target_id,
            predecessor_projection,
            successor_projection,
            successor_current,
            fresh,
        )?;

        signer
            .credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        owner.recheck()?;
        Ok(receipt)
    }

    /// Binds authenticated owner rows and a complete signed Inventory outcome.
    ///
    /// This is still not terminal authority. A later CAS must prove that the
    /// request ID was durably reserved after the proof and that this outcome
    /// remains the latest live physical readback at commit time.
    #[allow(dead_code, reason = "fresh post-proof challenge is not installed")]
    pub(super) fn from_verified_rows(
        proof: &StoredProofV2,
        owner: &VerifiedRetainedRepairReceiptV3,
        intent: &OperatorRecoveryEffectIntentV1,
        storage_request_body: &[u8],
        sandbox_id: [u8; 16],
        predecessor_projection: &[u8],
        successor_projection: &PublicProjectionPlanV1,
        successor_current: &[u8],
        fresh: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        let inventory = LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(fresh)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if proof.signed_pair_digest != owner.signed_pair_digest
            || proof.operation_id != intent.recovery_operation_id
            || proof.effect_id != intent.effect_id
            || sandbox_id != intent.target_id
            || inventory.source_version() != 3
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        verify_fresh_physical_target(owner, intent, storage_request_body, fresh)?;
        let record = Self {
            operation_id: proof.operation_id,
            sandbox_id,
            owner_id: owner.owner_id,
            owner_key_generation: owner.owner_key_generation,
            proof_digest: hash(super::PROOF_DOMAIN, &[&proof.encode()]),
            owner_record_digest: owner.record_digest,
            predecessor_projection_digest: Sha256::digest(predecessor_projection).into(),
            successor_projection_digest: Sha256::digest(successor_projection.desired_value())
                .into(),
            successor_current_digest: hash(CURRENT_DOMAIN, &[successor_current]),
            physical_version: owner.resulting_physical_version,
            fresh_request_id: fresh.request().request_id(),
            fresh_packet_digest: hash(FRESH_PACKET_DOMAIN, &[fresh.canonical_packet()]),
        };
        Self::decode(&record.encode())
    }

    pub(super) fn encode(self) -> [u8; RECEIPT_BYTES] {
        let mut bytes = [0; RECEIPT_BYTES];
        let mut cursor = 0;
        let owner_key_generation = self.owner_key_generation.to_be_bytes();
        for field in [
            MAGIC.as_slice(),
            self.operation_id.as_slice(),
            self.sandbox_id.as_slice(),
            self.owner_id.as_slice(),
            owner_key_generation.as_slice(),
            self.proof_digest.as_slice(),
            self.owner_record_digest.as_slice(),
            self.predecessor_projection_digest.as_slice(),
            self.successor_projection_digest.as_slice(),
            self.successor_current_digest.as_slice(),
            self.physical_version.as_slice(),
            self.fresh_request_id.as_slice(),
            self.fresh_packet_digest.as_slice(),
        ] {
            bytes[cursor..cursor + field.len()].copy_from_slice(field);
            cursor += field.len();
        }
        let checksum = hash(CHECKSUM_DOMAIN, &[&bytes[..cursor]]);
        bytes[cursor..].copy_from_slice(&checksum);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        if bytes.len() != RECEIPT_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let mut cursor = 8;
        let mut take = |length: usize| {
            let start = cursor;
            cursor += length;
            bytes.get(start..cursor)
        };
        let record = Self {
            operation_id: exact(take(16))?,
            sandbox_id: exact(take(16))?,
            owner_id: exact(take(16))?,
            owner_key_generation: u64::from_be_bytes(exact(take(8))?),
            proof_digest: exact(take(32))?,
            owner_record_digest: exact(take(32))?,
            predecessor_projection_digest: exact(take(32))?,
            successor_projection_digest: exact(take(32))?,
            successor_current_digest: exact(take(32))?,
            physical_version: exact(take(32))?,
            fresh_request_id: exact(take(16))?,
            fresh_packet_digest: exact(take(32))?,
        };
        if record.operation_id == [0; 16]
            || record.sandbox_id == [0; 16]
            || record.owner_id == [0; 16]
            || record.owner_key_generation == 0
            || record.fresh_request_id == [0; 16]
            || [
                record.proof_digest,
                record.owner_record_digest,
                record.predecessor_projection_digest,
                record.successor_projection_digest,
                record.successor_current_digest,
                record.physical_version,
                record.fresh_packet_digest,
            ]
            .contains(&[0; 32])
            || bytes.get(cursor..) != Some(hash(CHECKSUM_DOMAIN, &[&bytes[..cursor]]).as_slice())
            || record.encode().as_slice() != bytes
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(record)
    }

    /// Rechecks retained proof, owner, projection, and head after cold reopen.
    ///
    /// This deliberately does not authenticate the fresh post-proof query or
    /// public Effect/Operation. Those are separate prerequisites for success.
    #[allow(dead_code, reason = "terminal public ledger path remains closed")]
    pub(super) fn verify_retained_rows_except_freshness(
        self,
        journal: &Journal,
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
    ) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        Self::decode(&self.encode())?;
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let issuance_key = issuance_key_v2(self.operation_id);
        let issued = StorageRepairIssuanceV2::decode(
            &issuance_key,
            journal
                .get(RecordNamespace::OperatorRecovery, &issuance_key)
                .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
            signer.verifier(),
            signer.key_id(),
            signer.generation(),
        )?;
        let intent =
            verify_operator_recovery_effect_intent_v1(&issued.signed_intent, signer.verifier())
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let proof_key = [super::PREFIX, self.operation_id.as_slice()].concat();
        let proof = StoredProofV2::decode(
            journal
                .get(RecordNamespace::OperatorRecovery, &proof_key)
                .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
        )?;
        let owner_facts = verified_retained_repair_receipt_v3(journal, &intent, owner)?;
        let projection = PublicProjectionStoreV1::new(journal)
            .get(PublicProjectionKindV1::Sandbox, self.sandbox_id)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let successor_current = journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(self.sandbox_id),
            )
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;

        if intent.recovery_operation_id != self.operation_id
            || intent.target_id != self.sandbox_id
            || projection.project() != ProjectId::from_bytes(intent.project_id)
            || projection.operation() != OperationId::from_bytes(self.operation_id)
            || projection.revision().as_bytes() != &self.successor_projection_digest
            || proof.operation_id != self.operation_id
            || proof.effect_id != intent.effect_id
            || proof.current_head_digest != issued.current_head_digest
            || hash(super::PROOF_DOMAIN, &[&proof.encode()]) != self.proof_digest
            || proof.signed_pair_digest != owner_facts.signed_pair_digest
            || owner_facts.record_digest != self.owner_record_digest
            || owner_facts.owner_id != self.owner_id
            || owner_facts.owner_key_generation != self.owner_key_generation
            || owner_facts.resulting_physical_version != self.physical_version
            || hash(CURRENT_DOMAIN, &[successor_current]) != self.successor_current_digest
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        signer
            .credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        owner.recheck()
    }

    /// Prepares the immutable predecessor archive for the later terminal CAS.
    ///
    /// The returned record grants no completion authority on its own. The
    /// caller must recheck Storage currentness and commit this record with the
    /// public Effect, Operation, desired projection, receipt, and head while
    /// the exact predecessor still holds.
    #[allow(dead_code, reason = "terminal public ledger path remains closed")]
    pub(super) fn prepare_predecessor_archive(
        self,
        journal: &Journal,
        successor_projection: &PublicProjectionPlanV1,
        expected_predecessor_head_digest: [u8; 32],
    ) -> Result<JournalRecord, OperatorRecoveryIssuanceErrorV1> {
        Self::decode(&self.encode())?;
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        self.check_proof_head(journal, expected_predecessor_head_digest)?;

        let current = journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(self.sandbox_id),
            )
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        if hash(CURRENT_HEAD_DOMAIN_V2, &[current]) != expected_predecessor_head_digest {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let predecessor = PublicProjectionStoreV1::new(journal)
            .get(PublicProjectionKindV1::Sandbox, self.sandbox_id)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        if predecessor.revision().as_bytes() != &self.predecessor_projection_digest
            || !successor_projection.identifies(
                PublicProjectionKindV1::Sandbox,
                predecessor.project(),
                OperationId::from_bytes(self.operation_id),
                self.sandbox_id,
            )
            || Sha256::digest(successor_projection.desired_value()).as_slice()
                != self.successor_projection_digest
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let predecessor_bytes = journal
            .get(
                RecordNamespace::DesiredState,
                successor_projection.desired_key(),
            )
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let archive = RepairPredecessorArchiveV1::new(
            self,
            expected_predecessor_head_digest,
            predecessor_bytes,
        )?;
        let key = archive_key(self.operation_id);
        let encoded = archive.encode()?;
        if let Some(existing) = journal.get(RecordNamespace::OperatorRecovery, &key) {
            RepairPredecessorArchiveV1::decode(existing, self, expected_predecessor_head_digest)?;
            if existing != encoded {
                return Err(OperatorRecoveryIssuanceErrorV1::Binding);
            }
        }

        Ok(JournalRecord::put(
            RecordNamespace::OperatorRecovery,
            key,
            encoded,
        ))
    }

    /// Reads an exact retained predecessor after the joint terminal commit.
    ///
    /// This verifies the archive link only. The caller must also authenticate
    /// the receipt, public ledger, and successor protected head on cold reopen.
    #[allow(dead_code, reason = "terminal public ledger path remains closed")]
    pub(super) fn read_predecessor_archive(
        self,
        journal: &Journal,
        expected_predecessor_head_digest: [u8; 32],
    ) -> Result<Vec<u8>, OperatorRecoveryIssuanceErrorV1> {
        Self::decode(&self.encode())?;
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        self.check_proof_head(journal, expected_predecessor_head_digest)?;
        let key = archive_key(self.operation_id);
        let bytes = journal
            .get(RecordNamespace::OperatorRecovery, &key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let archive =
            RepairPredecessorArchiveV1::decode(bytes, self, expected_predecessor_head_digest)?;
        Ok(archive.predecessor_projection)
    }

    fn check_proof_head(
        self,
        journal: &Journal,
        expected_predecessor_head_digest: [u8; 32],
    ) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        let proof_key = [super::PREFIX, self.operation_id.as_slice()].concat();
        let proof = StoredProofV2::decode(
            journal
                .get(RecordNamespace::OperatorRecovery, &proof_key)
                .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
        )?;
        if proof.operation_id != self.operation_id
            || proof.current_head_digest != expected_predecessor_head_digest
            || hash(super::PROOF_DOMAIN, &[&proof.encode()]) != self.proof_digest
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(())
    }
}

/// Exact predecessor bytes retained under the same transaction as public success.
struct RepairPredecessorArchiveV1 {
    operation_id: [u8; 16],
    sandbox_id: [u8; 16],
    predecessor_head_digest: [u8; 32],
    receipt_digest: [u8; 32],
    predecessor_projection: Vec<u8>,
}

impl RepairPredecessorArchiveV1 {
    fn new(
        receipt: BoundRepairLedgerReceiptV1,
        predecessor_head_digest: [u8; 32],
        predecessor_projection: &[u8],
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        if predecessor_head_digest == [0; 32]
            || predecessor_projection.is_empty()
            || predecessor_projection.len() > MAXIMUM_ARCHIVED_PROJECTION_BYTES
            || Sha256::digest(predecessor_projection).as_slice()
                != receipt.predecessor_projection_digest
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let archive = Self {
            operation_id: receipt.operation_id,
            sandbox_id: receipt.sandbox_id,
            predecessor_head_digest,
            receipt_digest: hash(RECEIPT_DOMAIN, &[&receipt.encode()]),
            predecessor_projection: predecessor_projection.to_vec(),
        };
        archive.encode()?;
        Ok(archive)
    }

    fn encode(&self) -> Result<Vec<u8>, OperatorRecoveryIssuanceErrorV1> {
        let projection_len = u32::try_from(self.predecessor_projection.len())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let capacity = ARCHIVE_HEADER_BYTES
            .checked_add(self.predecessor_projection.len())
            .and_then(|size| size.checked_add(ARCHIVE_TRAILER_BYTES))
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(ARCHIVE_MAGIC);
        bytes.extend_from_slice(&self.operation_id);
        bytes.extend_from_slice(&self.sandbox_id);
        bytes.extend_from_slice(&self.predecessor_head_digest);
        bytes.extend_from_slice(&self.receipt_digest);
        bytes.extend_from_slice(&projection_len.to_be_bytes());
        bytes.extend_from_slice(&self.predecessor_projection);
        bytes.extend_from_slice(&hash(ARCHIVE_DOMAIN, &[&bytes]));
        Ok(bytes)
    }

    fn decode(
        bytes: &[u8],
        receipt: BoundRepairLedgerReceiptV1,
        expected_predecessor_head_digest: [u8; 32],
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        if bytes.len() < ARCHIVE_HEADER_BYTES + ARCHIVE_TRAILER_BYTES
            || bytes.len()
                > ARCHIVE_HEADER_BYTES + MAXIMUM_ARCHIVED_PROJECTION_BYTES + ARCHIVE_TRAILER_BYTES
            || bytes.get(..8) != Some(ARCHIVE_MAGIC.as_slice())
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let projection_len = u32::from_be_bytes(exact(bytes.get(104..108))?) as usize;
        let expected_len = ARCHIVE_HEADER_BYTES
            .checked_add(projection_len)
            .and_then(|size| size.checked_add(ARCHIVE_TRAILER_BYTES))
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        if bytes.len() != expected_len {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let archive = Self {
            operation_id: exact(bytes.get(8..24))?,
            sandbox_id: exact(bytes.get(24..40))?,
            predecessor_head_digest: exact(bytes.get(40..72))?,
            receipt_digest: exact(bytes.get(72..104))?,
            predecessor_projection: bytes[ARCHIVE_HEADER_BYTES..expected_len - 32].to_vec(),
        };
        if archive.operation_id != receipt.operation_id
            || archive.sandbox_id != receipt.sandbox_id
            || archive.predecessor_head_digest != expected_predecessor_head_digest
            || archive.receipt_digest != hash(RECEIPT_DOMAIN, &[&receipt.encode()])
            || archive.encode()?.as_slice() != bytes
            || Sha256::digest(&archive.predecessor_projection).as_slice()
                != receipt.predecessor_projection_digest
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(archive)
    }
}

fn archive_key(operation_id: [u8; 16]) -> Vec<u8> {
    [ARCHIVE_PREFIX, operation_id.as_slice()].concat()
}

fn verify_fresh_physical_target(
    owner: &VerifiedRetainedRepairReceiptV3,
    intent: &OperatorRecoveryEffectIntentV1,
    storage_request_body: &[u8],
    fresh: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = fresh.result() else {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    };
    verify_fresh_physical_target_body(owner, intent, storage_request_body, exact_body)
}

fn verify_fresh_physical_target_body(
    owner: &VerifiedRetainedRepairReceiptV3,
    intent: &OperatorRecoveryEffectIntentV1,
    storage_request_body: &[u8],
    exact_body: &[u8],
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    let request = RepairStorageWorkspacePinRequest::decode_from_slice(storage_request_body)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let fence = request
        .fence
        .as_option()
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let fence_digest = hash(
        FENCE_DOMAIN,
        &[
            &fence.sandbox_id,
            &fence.incarnation_id,
            &fence.assignment_epoch.to_be_bytes(),
            &fence.desired_generation.to_be_bytes(),
            &fence.assignment_digest,
        ],
    );
    if request.encode_to_vec() != storage_request_body
        || hash(REQUEST_DOMAIN, &[storage_request_body]) != intent.effect_id
        || request.operation_id.as_slice() != intent.recovery_operation_id
        || request.storage_handle.len() != 32
        || fence.sandbox_id.as_slice() != intent.target_id
        || fence.desired_generation != intent.current_generation
        || fence_digest != intent.current_fence_digest
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let inventory = decode_storage_resource_inventory_response(exact_body, MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let mut matching_workspaces = inventory
        .workspaces()
        .iter()
        .filter(|workspace| workspace.workspace_handle().as_slice() == request.storage_handle);
    let workspace = matching_workspaces
        .next()
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    if matching_workspaces.next().is_some()
        || workspace.fence().sandbox_id().as_slice() != fence.sandbox_id
        || workspace.fence().incarnation_id().as_slice() != fence.incarnation_id
        || workspace.fence().assignment_epoch() != fence.assignment_epoch
        || workspace.fence().desired_generation() != fence.desired_generation
        || workspace.fence().assignment_digest().as_slice() != fence.assignment_digest
        || *workspace.resource_digest() != owner.resulting_physical_version
        || inventory.catalog_generation() < owner.owner_catalog_generation
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let request_digest: [u8; 32] = Sha256::digest(storage_request_body).into();
    let mut matching_commits = inventory
        .operator_repair_commits()
        .iter()
        .filter(|commit| commit.operation_id() == &intent.recovery_operation_id);
    let commit = matching_commits
        .next()
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    if matching_commits.next().is_some()
        || commit.workspace_handle().as_slice() != request.storage_handle
        || commit.request_digest() != &request_digest
        || commit.effect_commit_digest() != &owner.effect_commit_digest
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(())
}

fn exact<const N: usize>(bytes: Option<&[u8]>) -> Result<[u8; N], OperatorRecoveryIssuanceErrorV1> {
    bytes
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Descriptor, InventoryStorageResourcesResponse,
        StorageOperatorRepairCommitRecordV1, StorageWorkspaceInventoryRecord,
    };
    use aos_sandbox_core::operator_recovery_effect::{
        OperatorRecoveryEffectActionV1, OperatorRecoveryEffectTargetV1,
    };

    use super::*;
    use crate::{JournalLimits, JournalTransaction};

    fn sample() -> BoundRepairLedgerReceiptV1 {
        BoundRepairLedgerReceiptV1 {
            operation_id: [1; 16],
            sandbox_id: [2; 16],
            owner_id: [3; 16],
            owner_key_generation: 4,
            proof_digest: [5; 32],
            owner_record_digest: [6; 32],
            predecessor_projection_digest: [7; 32],
            successor_projection_digest: [8; 32],
            successor_current_digest: [9; 32],
            physical_version: [10; 32],
            fresh_request_id: [11; 16],
            fresh_packet_digest: [12; 32],
        }
    }

    #[test]
    fn terminal_receipt_rejects_substitution_and_incomplete_freshness() {
        let encoded = sample().encode();
        assert_eq!(BoundRepairLedgerReceiptV1::decode(&encoded), Ok(sample()));

        for offset in [0, 8, 24, 40, 56, 64, 96, 128, 160, 192, 224, 256, 272, 304] {
            let mut changed = encoded;
            changed[offset] ^= 1;
            assert!(
                BoundRepairLedgerReceiptV1::decode(&changed).is_err(),
                "{offset}"
            );
        }
        let mut no_fresh_query = sample();
        no_fresh_query.fresh_request_id = [0; 16];
        assert!(BoundRepairLedgerReceiptV1::decode(&no_fresh_query.encode()).is_err());
    }

    #[test]
    fn predecessor_archive_reopens_exactly_and_rejects_cross_owner_replay() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::getuid().as_raw();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-predecessor.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();

        let predecessor = b"exact predecessor projection";
        let predecessor_head_digest = [17; 32];
        let proof = StoredProofV2 {
            operation_id: [1; 16],
            effect_id: [22; 32],
            current_head_digest: predecessor_head_digest,
            before_packet_digest: [23; 32],
            after_packet_digest: [24; 32],
            signed_pair_digest: [25; 32],
        };
        let mut receipt = sample();
        receipt.proof_digest = hash(super::super::PROOF_DOMAIN, &[&proof.encode()]);
        receipt.predecessor_projection_digest = Sha256::digest(predecessor).into();
        let archive =
            RepairPredecessorArchiveV1::new(receipt, predecessor_head_digest, predecessor).unwrap();
        let bytes = archive.encode().unwrap();
        let records = vec![
            JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                archive_key(receipt.operation_id),
                bytes.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                [super::super::PREFIX, receipt.operation_id.as_slice()].concat(),
                proof.encode().to_vec(),
            ),
        ];
        journal
            .commit(&JournalTransaction::new([18; 16], records).unwrap())
            .unwrap();
        drop(journal);

        let (journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-predecessor.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        assert_eq!(
            receipt.read_predecessor_archive(&journal, predecessor_head_digest),
            Ok(predecessor.to_vec())
        );
        assert!(
            receipt
                .read_predecessor_archive(&journal, [19; 32])
                .is_err()
        );
        let mut changed_owner = receipt;
        changed_owner.owner_id = [20; 16];
        assert!(
            changed_owner
                .read_predecessor_archive(&journal, predecessor_head_digest)
                .is_err()
        );
        let mut changed_fresh_query = receipt;
        changed_fresh_query.fresh_packet_digest = [21; 32];
        assert!(
            changed_fresh_query
                .read_predecessor_archive(&journal, predecessor_head_digest)
                .is_err()
        );
        for offset in [0, 8, 24, 40, 72, 104, 108, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                RepairPredecessorArchiveV1::decode(&changed, receipt, predecessor_head_digest)
                    .is_err(),
                "{offset}"
            );
        }
    }

    #[test]
    fn fresh_target_requires_exact_owner_version_fence_and_durable_commit() {
        let fence = AssignmentFence {
            sandbox_id: vec![2; 16],
            incarnation_id: vec![3; 16],
            assignment_epoch: 4,
            desired_generation: 7,
            assignment_digest: vec![8; 32],
            ..Default::default()
        };
        let request = RepairStorageWorkspacePinRequest {
            operation_id: vec![1; 16],
            storage_handle: vec![6; 32],
            fence: Some(fence.clone()).into(),
            ..Default::default()
        };
        let request_body = request.encode_to_vec();
        let request_digest: [u8; 32] = Sha256::digest(&request_body).into();
        let intent = OperatorRecoveryEffectIntentV1 {
            recovery_operation_id: [1; 16],
            target_id: [2; 16],
            action: OperatorRecoveryEffectActionV1::Repair,
            target_kind: OperatorRecoveryEffectTargetV1::Sandbox,
            principal_id: [3; 16],
            project_id: [4; 16],
            capability_id: [5; 16],
            expected_version_digest: [6; 32],
            evidence_digest: [7; 32],
            request_digest: [8; 32],
            authorization_digest: [9; 32],
            current_fence_digest: hash(
                FENCE_DOMAIN,
                &[
                    &fence.sandbox_id,
                    &fence.incarnation_id,
                    &fence.assignment_epoch.to_be_bytes(),
                    &fence.desired_generation.to_be_bytes(),
                    &fence.assignment_digest,
                ],
            ),
            effect_id: hash(REQUEST_DOMAIN, &[&request_body]),
            attempt: 1,
            current_generation: 7,
        };
        let owner = VerifiedRetainedRepairReceiptV3 {
            record_digest: [10; 32],
            signed_pair_digest: [11; 32],
            resulting_physical_version: [12; 32],
            effect_commit_digest: [13; 32],
            owner_catalog_generation: 16,
            owner_id: [14; 16],
            owner_key_generation: 18,
        };
        let workspace = StorageWorkspaceInventoryRecord {
            workspace_handle: vec![6; 32],
            fence: Some(fence).into(),
            root_image: Some(Descriptor {
                media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                sha256: vec![15; 32],
                encoded_size: 4,
                ..Default::default()
            })
            .into(),
            resource_kernel_boot_id: vec![19; 16],
            root_device: 20,
            root_inode: 21,
            dataset_guid: 22,
            creation_operation_id: vec![23; 16],
            uid_range_start: 65_536,
            uid_range_size: 65_536,
            resource_digest: vec![12; 32],
            ..Default::default()
        };
        let commit = StorageOperatorRepairCommitRecordV1 {
            operation_id: vec![1; 16],
            workspace_handle: vec![6; 32],
            request_digest: request_digest.to_vec(),
            effect_commit_digest: vec![13; 32],
            ..Default::default()
        };
        let mut inventory = InventoryStorageResourcesResponse {
            kernel_boot_id: vec![19; 16],
            broker_instance_id: vec![24; 16],
            journal_sequence: 25,
            catalog_generation: 16,
            workspaces: vec![workspace],
            operator_repair_commits: vec![commit],
            lifecycle_source: vec![26; 32],
            lifecycle_source_version: 3,
            lifecycle_catalog_head: vec![27; 32],
            lifecycle_catalog_generation: 16,
            ..Default::default()
        };

        let check = |inventory: &InventoryStorageResourcesResponse,
                     owner: &VerifiedRetainedRepairReceiptV3| {
            verify_fresh_physical_target_body(
                owner,
                &intent,
                &request_body,
                &inventory.encode_to_vec(),
            )
        };
        assert_eq!(check(&inventory, &owner), Ok(()));

        inventory.workspaces[0].resource_digest = vec![28; 32];
        assert!(check(&inventory, &owner).is_err());
        inventory.workspaces[0].resource_digest = vec![12; 32];
        inventory.operator_repair_commits[0].effect_commit_digest = vec![29; 32];
        assert!(check(&inventory, &owner).is_err());
        inventory.operator_repair_commits[0].effect_commit_digest = vec![13; 32];
        inventory.catalog_generation = 15;
        assert!(check(&inventory, &owner).is_err());
        inventory.catalog_generation = 16;
        inventory.operator_repair_commits.clear();
        assert!(check(&inventory, &owner).is_err());
    }
}
