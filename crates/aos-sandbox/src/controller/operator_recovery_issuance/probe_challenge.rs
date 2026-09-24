//! Protected fresh-query challenges for operator Storage inventory.
//!
//! A broker-signed historical inventory cannot answer a controller-generated
//! request ID that was durably committed only after issuance. Until a proof is
//! sealed, a cold retry replaces the challenge and invalidates earlier reads.
//!
//! ```text
//! storage-repair-query-v1/<stage:u8>/<operation-id[16]>:
//! AOSORQ01 | stage:u8 | reserved[7] | operation-id[16] | effect-id[32]
//!          | current-head-digest[32] | request-id[16] | signed-pair-digest[32]
//! ```

use aos_sandbox_core::OperationId;
use aos_sandbox_core::operator_recovery_effect::verify_operator_recovery_effect_intent_v1;
use aos_sandbox_core::operator_recovery_effect_v2::{
    OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2, OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use rand::{TryRngCore as _, rngs::OsRng};

use super::before;
use super::receipt::ProtectedStorageRepairReceiptVerifierV2;
use super::{
    CURRENT_HEAD_DOMAIN_V2, OperatorRecoveryIssuanceErrorV1, ProtectedOperatorRecoverySignerV1,
    StorageRepairIssuanceV2, hash, issuance_key_v2,
};
use crate::controller::{
    ActivatedOperationCompiler, NodeController, SingleNodeEffectExecutor, recovery_current_key,
};
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSORQ01";
const PREFIX: &[u8] = b"storage-repair-query-v1/";
const RECORD_BYTES: usize = 144;
const PAIR_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-signed-pair.v2\0";
const COMMIT_DOMAIN: &[u8] = b"aos.sandbox.operator-storage-repair-query-commit.v1\0";
const PROOF_PREFIX: &[u8] = b"storage-repair-proof-v2/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum ProbeStageV1 {
    Before = 1,
    After = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StoredProbeChallengeV1 {
    stage: ProbeStageV1,
    operation_id: [u8; 16],
    effect_id: [u8; 32],
    current_head_digest: [u8; 32],
    request_id: [u8; 16],
    signed_pair_digest: [u8; 32],
}

impl StoredProbeChallengeV1 {
    fn encode(self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = self.stage as u8;
        bytes[16..32].copy_from_slice(&self.operation_id);
        bytes[32..64].copy_from_slice(&self.effect_id);
        bytes[64..96].copy_from_slice(&self.current_head_digest);
        bytes[96..112].copy_from_slice(&self.request_id);
        bytes[112..144].copy_from_slice(&self.signed_pair_digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes[9..16] != [0; 7]
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let stage = match bytes[8] {
            1 => ProbeStageV1::Before,
            2 => ProbeStageV1::After,
            _ => return Err(OperatorRecoveryIssuanceErrorV1::Binding),
        };
        let record = Self {
            stage,
            operation_id: array(bytes, 16)?,
            effect_id: array(bytes, 32)?,
            current_head_digest: array(bytes, 64)?,
            request_id: array(bytes, 96)?,
            signed_pair_digest: array(bytes, 112)?,
        };
        if record.operation_id == [0; 16]
            || record.effect_id == [0; 32]
            || record.current_head_digest == [0; 32]
            || record.request_id == [0; 16]
            || (stage == ProbeStageV1::Before && record.signed_pair_digest != [0; 32])
            || (stage == ProbeStageV1::After && record.signed_pair_digest == [0; 32])
            || record.encode().as_slice() != bytes
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(record)
    }

    pub(super) fn matches_outcome(
        self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        self.matches_request_id(outcome.request().request_id())
    }

    fn matches_request_id(
        self,
        request_id: [u8; 16],
    ) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        if request_id != self.request_id {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(())
    }
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Reserves a fresh request ID before the authenticated pre-effect query.
    ///
    /// # Errors
    ///
    /// Rejects stale issuance, a previously retained before packet, or an
    /// uncertain protected challenge commit.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    pub(crate) fn reserve_storage_repair_before_query_v1(
        &mut self,
        signer: &ProtectedOperatorRecoverySignerV1,
        operation_id: OperationId,
    ) -> Result<[u8; 16], OperatorRecoveryIssuanceErrorV1> {
        let journal = self.reconciler.journal_mut();
        let (issued, effect_id) = current_issuance(journal, signer, operation_id)?;
        let before_key = [
            b"storage-repair-before-v1/".as_slice(),
            operation_id.as_bytes(),
        ]
        .concat();
        if journal
            .get(RecordNamespace::OperatorRecovery, &before_key)
            .is_some()
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        reserve(journal, ProbeStageV1::Before, &issued, effect_id, [0; 32])
    }

    /// Reserves a new post-effect query ID after verifying the owner receipt.
    ///
    /// Cold retries replace an unused challenge; a sealed proof forbids any
    /// replacement. The new outcome must answer this exact request ID.
    ///
    /// # Errors
    ///
    /// Rejects stale issuance, absent pre-effect custody, an invalid signed
    /// pair, an existing terminal proof, or uncertain protected persistence.
    #[allow(dead_code, reason = "public operator Repair route remains closed")]
    pub(crate) fn reserve_storage_repair_after_query_v1(
        &mut self,
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
        operation_id: OperationId,
        signed_evidence: &[u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2],
        signed_receipt: &[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2],
    ) -> Result<[u8; 16], OperatorRecoveryIssuanceErrorV1> {
        let journal = self.reconciler.journal_mut();
        let (issued, effect_id) = current_issuance(journal, signer, operation_id)?;
        let intent =
            verify_operator_recovery_effect_intent_v1(&issued.signed_intent, signer.verifier())
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        before::read(journal, &issued, effect_id)?;
        owner.verify_wire_receipt(&intent, signed_evidence, signed_receipt)?;

        let proof_key = [PROOF_PREFIX, operation_id.as_bytes()].concat();
        if journal
            .get(RecordNamespace::OperatorRecovery, &proof_key)
            .is_some()
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let pair_digest = hash(PAIR_DOMAIN, &[signed_evidence, signed_receipt]);
        reserve(
            journal,
            ProbeStageV1::After,
            &issued,
            effect_id,
            pair_digest,
        )
    }
}

fn current_issuance(
    journal: &mut Journal,
    signer: &ProtectedOperatorRecoverySignerV1,
    operation_id: OperationId,
) -> Result<(StorageRepairIssuanceV2, [u8; 32]), OperatorRecoveryIssuanceErrorV1> {
    signer
        .credential
        .recheck()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let key = issuance_key_v2(*operation_id.as_bytes());
    let issued = StorageRepairIssuanceV2::decode(
        &key,
        journal
            .get(RecordNamespace::OperatorRecovery, &key)
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
    if hash(CURRENT_HEAD_DOMAIN_V2, &[current]) != issued.current_head_digest {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok((issued, intent.effect_id))
}

pub(super) fn read(
    journal: &mut Journal,
    issued: &StorageRepairIssuanceV2,
    effect_id: [u8; 32],
    stage: ProbeStageV1,
    pair_digest: [u8; 32],
) -> Result<StoredProbeChallengeV1, OperatorRecoveryIssuanceErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let key = key(stage, issued.operation_id);
    let record = StoredProbeChallengeV1::decode(
        journal
            .get(RecordNamespace::OperatorRecovery, &key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
    )?;
    if record.stage != stage
        || record.operation_id != issued.operation_id
        || record.effect_id != effect_id
        || record.current_head_digest != issued.current_head_digest
        || record.signed_pair_digest != pair_digest
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(record)
}

fn reserve(
    journal: &mut Journal,
    stage: ProbeStageV1,
    issued: &StorageRepairIssuanceV2,
    effect_id: [u8; 32],
    pair_digest: [u8; 32],
) -> Result<[u8; 16], OperatorRecoveryIssuanceErrorV1> {
    let mut request_id = [0; 16];
    OsRng
        .try_fill_bytes(&mut request_id)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if request_id == [0; 16] {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let record = StoredProbeChallengeV1 {
        stage,
        operation_id: issued.operation_id,
        effect_id,
        current_head_digest: issued.current_head_digest,
        request_id,
        signed_pair_digest: pair_digest,
    };
    let encoded = record.encode();
    StoredProbeChallengeV1::decode(&encoded)?;
    let key = key(stage, issued.operation_id);
    if journal
        .get(RecordNamespace::OperatorRecovery, &key)
        .is_some()
    {
        let previous = read(journal, issued, effect_id, stage, pair_digest)?;
        if previous.request_id == request_id {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
    }
    let digest = hash(COMMIT_DOMAIN, &[&encoded]);
    let transaction_id = digest[..16]
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
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    Ok(request_id)
}

fn key(stage: ProbeStageV1, operation_id: [u8; 16]) -> Vec<u8> {
    [PREFIX, &[stage as u8], operation_id.as_slice()].concat()
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], OperatorRecoveryIssuanceErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;
    use crate::JournalLimits;

    fn sample() -> (StorageRepairIssuanceV2, [u8; 32]) {
        (
            StorageRepairIssuanceV2 {
                operation_id: [1; 16],
                public_request_digest: [2; 32],
                current_head_digest: [3; 32],
                inventory_commitment: [4; 32],
                inventory_head: [5; 32],
                inventory_generation: 6,
                controller_key_id: [7; 16],
                controller_key_generation: 8,
                signed_intent: [9; super::super::OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
            },
            [10; 32],
        )
    }

    #[test]
    fn query_challenge_rejects_wrong_stage_and_old_record_version() {
        let record = StoredProbeChallengeV1 {
            stage: ProbeStageV1::Before,
            operation_id: [1; 16],
            effect_id: [2; 32],
            current_head_digest: [3; 32],
            request_id: [4; 16],
            signed_pair_digest: [0; 32],
        };
        assert_eq!(StoredProbeChallengeV1::decode(&record.encode()), Ok(record));
        let mut legacy = record.encode();
        legacy[..8].copy_from_slice(b"AOSORQ00");
        assert!(StoredProbeChallengeV1::decode(&legacy).is_err());
        let mut wrong_stage = record.encode();
        wrong_stage[8] = ProbeStageV1::After as u8;
        assert!(StoredProbeChallengeV1::decode(&wrong_stage).is_err());
    }

    #[test]
    fn cold_retry_replaces_unsealed_challenge_and_rejects_old_pair() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-query.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let (issued, effect_id) = sample();
        let first = reserve(
            &mut journal,
            ProbeStageV1::After,
            &issued,
            effect_id,
            [11; 32],
        )
        .unwrap();
        assert_eq!(
            reserve(
                &mut journal,
                ProbeStageV1::After,
                &issued,
                effect_id,
                [12; 32]
            ),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
        let second = reserve(
            &mut journal,
            ProbeStageV1::After,
            &issued,
            effect_id,
            [11; 32],
        )
        .unwrap();
        assert_ne!(first, second);
        assert!(
            read(
                &mut journal,
                &issued,
                effect_id,
                ProbeStageV1::After,
                [12; 32]
            )
            .is_err()
        );
        let retained = read(
            &mut journal,
            &issued,
            effect_id,
            ProbeStageV1::After,
            [11; 32],
        )
        .unwrap();
        assert_eq!(
            retained.matches_request_id(first),
            Err(OperatorRecoveryIssuanceErrorV1::Binding)
        );
        assert_eq!(retained.matches_request_id(second), Ok(()));

        drop(journal);
        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "operator-query.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        assert_eq!(
            read(
                &mut reopened,
                &issued,
                effect_id,
                ProbeStageV1::After,
                [11; 32]
            )
            .unwrap()
            .request_id,
            second
        );
    }
}
