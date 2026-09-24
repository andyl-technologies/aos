//! Closed Repair proof sealing under exact protected issuance and current head.
//!
//! This is a terminal *proof* CAS, not a public operation completion. It
//! atomically retains the checked before/after/receipt relationship while the
//! protected recovery head still equals the issued predecessor. A later
//! lifecycle integration must include the public ledger and successor head in
//! one terminal transaction, after a fresh live inventory query.
//!
//! ```text
//! storage-repair-proof-v2/<operation-id[16]>:
//! AOSOTP02 | operation-id[16] | effect-id[32] | current-head-digest[32]
//!          | before-packet-digest[32] | after-packet-digest[32]
//!          | signed-pair-digest[32]
//! ```

use aos_sandbox_core::OperationId;
use aos_sandbox_core::operator_recovery_effect::{
    OperatorRecoveryEffectIntentV1, verify_operator_recovery_effect_intent_v1,
};
use aos_sandbox_core::operator_recovery_effect_v2::{
    OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2, OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

use super::before;
use super::probe_challenge::{self, ProbeStageV1};
use super::receipt::ProtectedStorageRepairReceiptVerifierV2;
use super::{
    CURRENT_HEAD_DOMAIN_V2, OperatorRecoveryIssuanceErrorV1, ProtectedOperatorRecoverySignerV1,
    StorageRepairIssuanceV2, hash, issuance_key_v2,
};
use crate::controller::{
    ActivatedOperationCompiler, NodeController, SingleNodeEffectExecutor, recovery_current_key,
};
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSOTP02";
const PREFIX: &[u8] = b"storage-repair-proof-v2/";
const RECORD_BYTES: usize = 184;
const AFTER_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-after-packet.v1\0";
const PAIR_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-signed-pair.v2\0";
const PROOF_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-terminal-proof.v2\0";
const COMMIT_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-proof-commit.v2\0";

mod ledger_receipt;
mod successor_commit;

fn issued_intent(
    journal: &Journal,
    signer: &ProtectedOperatorRecoverySignerV1,
    operation_id: OperationId,
) -> Result<
    (StorageRepairIssuanceV2, OperatorRecoveryEffectIntentV1),
    OperatorRecoveryIssuanceErrorV1,
> {
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
    Ok((issued, intent))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StoredProofV2 {
    operation_id: [u8; 16],
    effect_id: [u8; 32],
    current_head_digest: [u8; 32],
    before_packet_digest: [u8; 32],
    after_packet_digest: [u8; 32],
    signed_pair_digest: [u8; 32],
}

impl StoredProofV2 {
    fn encode(&self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        let mut cursor = 0;
        for field in [
            MAGIC.as_slice(),
            self.operation_id.as_slice(),
            self.effect_id.as_slice(),
            self.current_head_digest.as_slice(),
            self.before_packet_digest.as_slice(),
            self.after_packet_digest.as_slice(),
            self.signed_pair_digest.as_slice(),
        ] {
            bytes[cursor..cursor + field.len()].copy_from_slice(field);
            cursor += field.len();
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        if bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let record = Self {
            operation_id: array(bytes, 8)?,
            effect_id: array(bytes, 24)?,
            current_head_digest: array(bytes, 56)?,
            before_packet_digest: array(bytes, 88)?,
            after_packet_digest: array(bytes, 120)?,
            signed_pair_digest: array(bytes, 152)?,
        };
        if record.operation_id == [0; 16]
            || [
                record.effect_id,
                record.current_head_digest,
                record.before_packet_digest,
                record.after_packet_digest,
                record.signed_pair_digest,
            ]
            .contains(&[0; 32])
            || record.encode().as_slice() != bytes
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(record)
    }
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Seals exact V2 physical proof under the unchanged protected predecessor.
    ///
    /// The public operation and current head remain untouched. This method
    /// admits only independently authenticated before/after broker outcomes,
    /// the broker inventory's durable attempt digest, and the owner-signed
    /// evidence pair. Replaying identical proof is idempotent.
    ///
    /// # Errors
    ///
    /// Rejects missing pre-effect custody, changed issuance or current head,
    /// stale session order, mismatched physical readback, changed signed pair,
    /// or an uncertain protected proof commit.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal_storage_repair_terminal_proof_v2(
        &mut self,
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
        operation_id: OperationId,
        storage_request_body: &[u8],
        before: &AuthenticatedBrokerMethodOutcomeV1,
        after: &AuthenticatedBrokerMethodOutcomeV1,
        signed_probe_attestation: &[u8],
        signed_evidence: &[u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
        signed_receipt: &[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
    ) -> Result<[u8; 32], OperatorRecoveryIssuanceErrorV1> {
        self.retain_storage_repair_receipt_v3(
            signer,
            owner,
            operation_id,
            storage_request_body,
            before,
            after,
            signed_probe_attestation,
            signed_evidence,
            signed_receipt,
        )?;
        let journal = self.reconciler.journal_mut();
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let (issued, intent) = issued_intent(journal, signer, operation_id)?;
        let retained_before = before::read(journal, &issued, intent.effect_id)?;
        retained_before.matches_outcome(before)?;
        let pair_digest = hash(PAIR_DOMAIN, &[signed_evidence, signed_receipt]);
        probe_challenge::read(
            journal,
            &issued,
            intent.effect_id,
            ProbeStageV1::After,
            pair_digest,
        )?
        .matches_outcome(after)?;
        let current_key = recovery_current_key(intent.target_id);
        let current = journal
            .get(RecordNamespace::OperatorRecovery, &current_key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        if hash(CURRENT_HEAD_DOMAIN_V2, &[current]) != issued.current_head_digest {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let proof = StoredProofV2 {
            operation_id: intent.recovery_operation_id,
            effect_id: intent.effect_id,
            current_head_digest: issued.current_head_digest,
            before_packet_digest: retained_before.packet_digest(),
            after_packet_digest: hash(AFTER_DOMAIN, &[after.canonical_packet()]),
            signed_pair_digest: pair_digest,
        };
        reserve(journal, &proof, &current_key, issued.current_head_digest)?;
        signer
            .credential
            .recheck()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        owner.recheck()?;
        Ok(hash(PROOF_DOMAIN, &[&proof.encode()]))
    }
}

fn reserve(
    journal: &mut Journal,
    proof: &StoredProofV2,
    current_key: &[u8],
    expected_head: [u8; 32],
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let current = journal
        .get(RecordNamespace::OperatorRecovery, current_key)
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    if hash(CURRENT_HEAD_DOMAIN_V2, &[current]) != expected_head {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let key = [PREFIX, proof.operation_id.as_slice()].concat();
    let encoded = proof.encode();
    StoredProofV2::decode(&encoded)?;
    if let Some(existing) = journal.get(RecordNamespace::OperatorRecovery, &key) {
        StoredProofV2::decode(existing)?;
        return if existing == encoded {
            Ok(())
        } else {
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        };
    }
    let digest = hash(COMMIT_DOMAIN, &[&proof.operation_id]);
    let transaction_id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::OperatorRecovery,
            key.clone(),
            encoded.to_vec(),
        )],
    )
    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let _ = journal.commit(&transaction);
    if journal.get(RecordNamespace::OperatorRecovery, &key) != Some(encoded.as_slice()) {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)
}

/// Rechecks the retained proof identity before a new post-proof live query.
pub(super) fn read_sealed_proof_v2(
    journal: &mut Journal,
    issued: &StorageRepairIssuanceV2,
    effect_id: [u8; 32],
    signed_pair_digest: [u8; 32],
) -> Result<StoredProofV2, OperatorRecoveryIssuanceErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let key = [PREFIX, issued.operation_id.as_slice()].concat();
    let proof = StoredProofV2::decode(
        journal
            .get(RecordNamespace::OperatorRecovery, &key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
    )?;
    if proof.operation_id != issued.operation_id
        || proof.effect_id != effect_id
        || proof.current_head_digest != issued.current_head_digest
        || proof.signed_pair_digest != signed_pair_digest
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(proof)
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], OperatorRecoveryIssuanceErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;
    use crate::JournalLimits;

    fn sample(current_head_digest: [u8; 32]) -> StoredProofV2 {
        StoredProofV2 {
            operation_id: [1; 16],
            effect_id: [2; 32],
            current_head_digest,
            before_packet_digest: [4; 32],
            after_packet_digest: [5; 32],
            signed_pair_digest: [6; 32],
        }
    }

    #[test]
    fn proof_record_rejects_legacy_version_and_changed_pair() {
        let proof = sample([3; 32]);
        let bytes = proof.encode();
        assert_eq!(StoredProofV2::decode(&bytes), Ok(proof));
        let mut legacy = bytes;
        legacy[..8].copy_from_slice(b"AOSOTP01");
        assert!(StoredProofV2::decode(&legacy).is_err());
        let mut missing = bytes;
        missing[152..184].fill(0);
        assert!(StoredProofV2::decode(&missing).is_err());
    }

    #[test]
    fn proof_cas_replays_exactly_and_rejects_stale_head() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-proof.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let current_key = recovery_current_key([7; 16]);
        let initial = JournalTransaction::new(
            [8; 16],
            vec![JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                current_key.clone(),
                b"current-a".to_vec(),
            )],
        )
        .unwrap();
        journal.commit(&initial).unwrap();
        let head = hash(CURRENT_HEAD_DOMAIN_V2, &[b"current-a"]);
        let proof = sample(head);
        let issued = StorageRepairIssuanceV2 {
            operation_id: proof.operation_id,
            public_request_digest: [11; 32],
            current_head_digest: head,
            inventory_commitment: [12; 32],
            inventory_head: [13; 32],
            inventory_generation: 14,
            controller_key_id: [15; 16],
            controller_key_generation: 16,
            signed_intent: [17; super::super::OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
        };
        assert!(
            read_sealed_proof_v2(
                &mut journal,
                &issued,
                proof.effect_id,
                proof.signed_pair_digest
            )
            .is_err()
        );
        assert_eq!(reserve(&mut journal, &proof, &current_key, head), Ok(()));
        assert_eq!(
            read_sealed_proof_v2(
                &mut journal,
                &issued,
                proof.effect_id,
                proof.signed_pair_digest
            ),
            Ok(proof)
        );
        assert!(read_sealed_proof_v2(&mut journal, &issued, proof.effect_id, [19; 32]).is_err());
        assert_eq!(reserve(&mut journal, &proof, &current_key, head), Ok(()));
        let mut changed = proof;
        changed.signed_pair_digest = [9; 32];
        assert_eq!(
            reserve(&mut journal, &changed, &current_key, head),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );

        drop(journal);
        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-proof.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        assert_eq!(reserve(&mut reopened, &proof, &current_key, head), Ok(()));
        assert_eq!(
            read_sealed_proof_v2(
                &mut reopened,
                &issued,
                proof.effect_id,
                proof.signed_pair_digest
            ),
            Ok(proof)
        );
        let successor = JournalTransaction::new(
            [10; 16],
            vec![JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                current_key.clone(),
                b"current-b".to_vec(),
            )],
        )
        .unwrap();
        reopened.commit(&successor).unwrap();
        assert_eq!(
            reserve(&mut reopened, &proof, &current_key, head),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
    }
}
