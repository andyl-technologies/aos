//! Versioned public-ledger receipt binding for a completed Storage Repair.
//!
//! This format is deliberately not dispatchable. A future terminal CAS must
//! supply a fresh challenged post-proof Inventory result and commit this exact
//! receipt with the public Effect, Operation, Sandbox projection, and protected
//! current head. Cold recovery must verify every retained commitment before
//! projecting success.
//!
//! ```text
//! AOSOTL01 | operation-id[16] | sandbox-id[16] | owner-id[16]
//! owner-key-generation:u64be | proof-digest[32] | owner-record-digest[32]
//! predecessor-projection-digest[32] | successor-projection-digest[32]
//! successor-current-digest[32] | physical-version[32]
//! fresh-request-id[16] | fresh-packet-digest[32] | checksum[32]
//! ```

use aos_sandbox_core::operator_recovery_effect::verify_operator_recovery_effect_intent_v1;
use aos_sandbox_core::{OperationId, ProjectId};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use sha2::{Digest as _, Sha256};

use super::super::receipt::{
    ProtectedStorageRepairReceiptVerifierV2, VerifiedRetainedRepairReceiptV3,
    verified_retained_repair_receipt_v3,
};
use super::super::{
    OperatorRecoveryIssuanceErrorV1, ProtectedOperatorRecoverySignerV1, StorageRepairIssuanceV2,
    hash, issuance_key_v2,
};
use super::StoredProofV2;
use crate::controller::recovery_current_key;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionPlanV1, PublicProjectionStoreV1,
};
use crate::lifecycle::LifecycleAuthenticatedStorageInventoryV1;
use crate::{Journal, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSOTL01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-terminal-ledger-receipt.v1\0";
const CURRENT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-terminal-current.v1\0";
const FRESH_PACKET_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-terminal-fresh-packet.v1\0";
const RECEIPT_BYTES: usize = 336;

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
    /// Binds authenticated owner rows and a complete signed Inventory outcome.
    ///
    /// This is still not terminal authority. A later CAS must prove that the
    /// request ID was durably reserved after the proof and that this outcome
    /// remains the latest live physical readback at commit time.
    #[allow(dead_code, reason = "fresh post-proof challenge is not installed")]
    pub(super) fn from_verified_rows(
        proof: &StoredProofV2,
        owner: &VerifiedRetainedRepairReceiptV3,
        sandbox_id: [u8; 16],
        predecessor_projection: &[u8],
        successor_projection: &PublicProjectionPlanV1,
        successor_current: &[u8],
        fresh: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        let inventory = LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(fresh)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if proof.signed_pair_digest != owner.signed_pair_digest
            || proof.operation_id == [0; 16]
            || sandbox_id == [0; 16]
            || inventory.source_version() != 3
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
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
}

fn exact<const N: usize>(bytes: Option<&[u8]>) -> Result<[u8; N], OperatorRecoveryIssuanceErrorV1> {
    bytes
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
