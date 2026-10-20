//! Generation-bound physical evidence and receipts for operator Repair.
//!
//! These packets are distinct from the legacy `AOSORR01` receipt. In
//! particular, the catalog generation remains separate from the owner's
//! signing-key generation, and neither old packet nor old journal bytes can
//! acquire version-two meaning.
//!
//! ```text
//! evidence = AOSOEV02 | intent-digest[32] | owner-id[16]
//!            | owner-key-generation:u64be | probe-epoch:u32be
//!            | absence-probe-digest[32] | before-catalog-generation:u64be
//!            | before-inventory-digest[32] | effect-commit-digest[32]
//!            | after-inventory-digest[32] | resulting-version[32]
//!            | after-catalog-generation:u64be | signature[64]
//! receipt  = AOSORR02 | intent-digest[32] | owner-id[16]
//!            | owner-key-generation:u64be | signed-evidence-digest[32]
//!            | before-inventory-digest[32] | after-inventory-digest[32]
//!            | resulting-version[32] | terminal-result-digest[32]
//!            | effect-commit-digest[32] | after-catalog-generation:u64be
//!            | signature[64]
//! ```

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::operator_recovery_effect::{
    OperatorRecoveryEffectErrorV1, OperatorRecoveryEffectIntentV1,
    verify_operator_recovery_effect_intent_v1,
};
use crate::operator_recovery_packet::{array, sign_packet, verify_packet};

const EVIDENCE_MAGIC: &[u8; 8] = b"AOSOEV02";
const RECEIPT_MAGIC: &[u8; 8] = b"AOSORR02";
const EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-effect-evidence.v2\0";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-effect-receipt.v2\0";
const EVIDENCE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-effect-evidence-digest.v2\0";
const EVIDENCE_PAYLOAD_BYTES: usize = 244;
const RECEIPT_PAYLOAD_BYTES: usize = 264;

/// Exact version-two evidence packet size, including its owner signature.
pub const OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2: usize = EVIDENCE_PAYLOAD_BYTES + 64;
/// Exact version-two receipt packet size, including its owner signature.
pub const OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2: usize = RECEIPT_PAYLOAD_BYTES + 64;

/// Attests separately read physical facts retained by the Storage owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorRecoveryEffectEvidenceV2 {
    /// Exact protected controller intent commitment.
    pub intent_digest: [u8; 32],
    /// Independently pinned Storage owner identity.
    pub owner_id: [u8; 16],
    /// Generation of the dedicated Storage owner signing key.
    pub owner_key_generation: u64,
    /// Bounded durable absence-probe epoch before effect dispatch.
    pub probe_epoch: u32,
    /// Digest of the fresh dataset-present/pin-absent probe.
    pub absence_probe_digest: [u8; 32],
    /// Physical catalog generation observed before effect dispatch.
    pub before_catalog_generation: u64,
    /// Domain-separated commitment to the protected before observation.
    pub before_inventory_digest: [u8; 32],
    /// Digest of the separately read durable Storage attempt record.
    pub effect_commit_digest: [u8; 32],
    /// Digest of the exact fresh physical inventory response.
    pub after_inventory_digest: [u8; 32],
    /// Physical resource version selected from that inventory.
    pub resulting_version: [u8; 32],
    /// Physical catalog generation at the post-effect readback.
    pub after_catalog_generation: u64,
}

impl OperatorRecoveryEffectEvidenceV2 {
    /// Rejects absent identities, facts, or monotone counters.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or regressed protected facts.
    pub fn validate(&self) -> Result<(), OperatorRecoveryEffectErrorV1> {
        if self.owner_id == [0; 16]
            || self.owner_key_generation == 0
            || self.probe_epoch == 0
            || self.before_catalog_generation == 0
            || self.after_catalog_generation < self.before_catalog_generation
            || [
                self.intent_digest,
                self.absence_probe_digest,
                self.before_inventory_digest,
                self.effect_commit_digest,
                self.after_inventory_digest,
                self.resulting_version,
            ]
            .contains(&[0; 32])
        {
            return Err(OperatorRecoveryEffectErrorV1::InvalidField);
        }
        Ok(())
    }

    fn payload(&self) -> [u8; EVIDENCE_PAYLOAD_BYTES] {
        let mut output = [0; EVIDENCE_PAYLOAD_BYTES];
        let mut cursor = 0;
        for field in [
            EVIDENCE_MAGIC.as_slice(),
            self.intent_digest.as_slice(),
            self.owner_id.as_slice(),
            self.owner_key_generation.to_be_bytes().as_slice(),
            self.probe_epoch.to_be_bytes().as_slice(),
            self.absence_probe_digest.as_slice(),
            self.before_catalog_generation.to_be_bytes().as_slice(),
            self.before_inventory_digest.as_slice(),
            self.effect_commit_digest.as_slice(),
            self.after_inventory_digest.as_slice(),
            self.resulting_version.as_slice(),
            self.after_catalog_generation.to_be_bytes().as_slice(),
        ] {
            output[cursor..cursor + field.len()].copy_from_slice(field);
            cursor += field.len();
        }
        output
    }
}

/// Attests a terminal Repair result and commits the separate evidence packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorRecoveryEffectReceiptV2 {
    /// Exact protected controller intent commitment.
    pub intent_digest: [u8; 32],
    /// Independently pinned Storage owner identity.
    pub owner_id: [u8; 16],
    /// Generation of the dedicated Storage owner signing key.
    pub owner_key_generation: u64,
    /// Commitment to the exact separately signed evidence packet.
    pub signed_evidence_digest: [u8; 32],
    /// Domain-separated before-effect physical observation commitment.
    pub before_inventory_digest: [u8; 32],
    /// Exact fresh post-effect physical inventory commitment.
    pub after_inventory_digest: [u8; 32],
    /// Resulting checked target resource version.
    pub resulting_version: [u8; 32],
    /// Digest of the checked terminal result.
    pub terminal_result_digest: [u8; 32],
    /// Digest of the durable Storage attempt record.
    pub effect_commit_digest: [u8; 32],
    /// Physical catalog generation at post-effect readback.
    pub owner_generation: u64,
}

impl OperatorRecoveryEffectReceiptV2 {
    /// Rejects absent identities, commitments, or generations.
    ///
    /// # Errors
    ///
    /// Returns an error when a required signed field is missing.
    pub fn validate(&self) -> Result<(), OperatorRecoveryEffectErrorV1> {
        if self.owner_id == [0; 16]
            || self.owner_key_generation == 0
            || self.owner_generation == 0
            || [
                self.intent_digest,
                self.signed_evidence_digest,
                self.before_inventory_digest,
                self.after_inventory_digest,
                self.resulting_version,
                self.terminal_result_digest,
                self.effect_commit_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(OperatorRecoveryEffectErrorV1::InvalidField);
        }
        Ok(())
    }

    fn payload(&self) -> [u8; RECEIPT_PAYLOAD_BYTES] {
        let mut output = [0; RECEIPT_PAYLOAD_BYTES];
        let mut cursor = 0;
        for field in [
            RECEIPT_MAGIC.as_slice(),
            self.intent_digest.as_slice(),
            self.owner_id.as_slice(),
            self.owner_key_generation.to_be_bytes().as_slice(),
            self.signed_evidence_digest.as_slice(),
            self.before_inventory_digest.as_slice(),
            self.after_inventory_digest.as_slice(),
            self.resulting_version.as_slice(),
            self.terminal_result_digest.as_slice(),
            self.effect_commit_digest.as_slice(),
            self.owner_generation.to_be_bytes().as_slice(),
        ] {
            output[cursor..cursor + field.len()].copy_from_slice(field);
            cursor += field.len();
        }
        output
    }
}

/// Signs separately retained physical evidence under the dedicated owner key.
///
/// # Errors
///
/// Returns an error for missing or regressed physical facts.
pub fn sign_operator_recovery_effect_evidence_v2(
    evidence: &OperatorRecoveryEffectEvidenceV2,
    key: &SigningKey,
) -> Result<[u8; OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2], OperatorRecoveryEffectErrorV1> {
    evidence.validate()?;
    Ok(sign_packet(evidence.payload(), EVIDENCE_DOMAIN, key))
}

/// Verifies evidence under a deployment-pinned owner key and generation.
///
/// # Errors
///
/// Rejects legacy packets, invalid signatures, changed intent or owner, and
/// any signing-key generation other than the independently pinned one.
pub fn verify_operator_recovery_effect_evidence_v2(
    packet: &[u8],
    key: &VerifyingKey,
    intent: &OperatorRecoveryEffectIntentV1,
    owner_id: [u8; 16],
    owner_key_generation: u64,
) -> Result<OperatorRecoveryEffectEvidenceV2, OperatorRecoveryEffectErrorV1> {
    let bytes = verify_packet::<OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2>(
        packet,
        EVIDENCE_PAYLOAD_BYTES,
        EVIDENCE_DOMAIN,
        key,
    )?;
    if &bytes[..8] != EVIDENCE_MAGIC {
        return Err(OperatorRecoveryEffectErrorV1::InvalidEncoding);
    }
    let mut cursor = 8;
    let mut take = |length: usize| {
        let start = cursor;
        cursor += length;
        &bytes[start..cursor]
    };
    let evidence = OperatorRecoveryEffectEvidenceV2 {
        intent_digest: array(take(32))?,
        owner_id: array(take(16))?,
        owner_key_generation: u64::from_be_bytes(array(take(8))?),
        probe_epoch: u32::from_be_bytes(array(take(4))?),
        absence_probe_digest: array(take(32))?,
        before_catalog_generation: u64::from_be_bytes(array(take(8))?),
        before_inventory_digest: array(take(32))?,
        effect_commit_digest: array(take(32))?,
        after_inventory_digest: array(take(32))?,
        resulting_version: array(take(32))?,
        after_catalog_generation: u64::from_be_bytes(array(take(8))?),
    };
    evidence.validate()?;
    if evidence.intent_digest != intent.digest()?
        || evidence.owner_id != owner_id
        || evidence.owner_key_generation != owner_key_generation
    {
        return Err(OperatorRecoveryEffectErrorV1::BindingMismatch);
    }
    Ok(evidence)
}

/// Signs a generation-bound receipt for exact separately signed evidence.
///
/// # Errors
///
/// Returns an error for missing receipt commitments or owner generation.
pub fn sign_operator_recovery_effect_receipt_v2(
    receipt: &OperatorRecoveryEffectReceiptV2,
    key: &SigningKey,
) -> Result<[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2], OperatorRecoveryEffectErrorV1> {
    receipt.validate()?;
    Ok(sign_packet(receipt.payload(), RECEIPT_DOMAIN, key))
}

/// Verifies a receipt and its separate evidence under a pinned owner generation.
///
/// This checks signed pair consistency only. A controller must still compare
/// the evidence against independently authenticated physical observations.
///
/// # Errors
///
/// Rejects a legacy or altered packet, changed key generation, owner, intent,
/// terminal result, or evidence commitment.
pub fn verify_operator_recovery_effect_receipt_v2(
    receipt_packet: &[u8],
    evidence_packet: &[u8],
    key: &VerifyingKey,
    intent: &OperatorRecoveryEffectIntentV1,
    owner_id: [u8; 16],
    owner_key_generation: u64,
    terminal_result_digest: [u8; 32],
) -> Result<
    (
        OperatorRecoveryEffectReceiptV2,
        OperatorRecoveryEffectEvidenceV2,
    ),
    OperatorRecoveryEffectErrorV1,
> {
    let evidence = verify_operator_recovery_effect_evidence_v2(
        evidence_packet,
        key,
        intent,
        owner_id,
        owner_key_generation,
    )?;
    let bytes = verify_packet::<OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES_V2>(
        receipt_packet,
        RECEIPT_PAYLOAD_BYTES,
        RECEIPT_DOMAIN,
        key,
    )?;
    if &bytes[..8] != RECEIPT_MAGIC {
        return Err(OperatorRecoveryEffectErrorV1::InvalidEncoding);
    }
    let mut cursor = 8;
    let mut take = |length: usize| {
        let start = cursor;
        cursor += length;
        &bytes[start..cursor]
    };
    let receipt = OperatorRecoveryEffectReceiptV2 {
        intent_digest: array(take(32))?,
        owner_id: array(take(16))?,
        owner_key_generation: u64::from_be_bytes(array(take(8))?),
        signed_evidence_digest: array(take(32))?,
        before_inventory_digest: array(take(32))?,
        after_inventory_digest: array(take(32))?,
        resulting_version: array(take(32))?,
        terminal_result_digest: array(take(32))?,
        effect_commit_digest: array(take(32))?,
        owner_generation: u64::from_be_bytes(array(take(8))?),
    };
    receipt.validate()?;
    if receipt.intent_digest != intent.digest()?
        || receipt.owner_id != owner_id
        || receipt.owner_key_generation != owner_key_generation
        || receipt.signed_evidence_digest != evidence_digest_v2(evidence_packet)
        || receipt.before_inventory_digest != evidence.before_inventory_digest
        || receipt.after_inventory_digest != evidence.after_inventory_digest
        || receipt.resulting_version != evidence.resulting_version
        || receipt.effect_commit_digest != evidence.effect_commit_digest
        || receipt.owner_generation != evidence.after_catalog_generation
        || receipt.terminal_result_digest != terminal_result_digest
    {
        return Err(OperatorRecoveryEffectErrorV1::BindingMismatch);
    }
    Ok((receipt, evidence))
}

/// Commits the exact separately signed evidence packet for a receipt.
#[must_use]
pub fn evidence_digest_v2(packet: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(EVIDENCE_DIGEST_DOMAIN)
        .chain_update(packet)
        .finalize()
        .into()
}

/// Holds independently obtained current facts for a generation-bound completion.
///
/// None of these fields may be copied from the presented evidence or receipt.
/// The caller must retain the controller target head through its terminal CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorRecoveryEffectCurrentnessV2 {
    /// Exact intent durably issued under the current controller head.
    pub issued_intent: OperatorRecoveryEffectIntentV1,
    /// Independently pinned physical owner identity.
    pub owner_id: [u8; 16],
    /// Independently pinned owner signing-key generation.
    pub owner_key_generation: u64,
    /// Durable pre-effect probe epoch.
    pub probe_epoch: u32,
    /// Digest of the independently admitted pre-effect absence probe.
    pub absence_probe_digest: [u8; 32],
    /// Catalog generation of that pre-effect probe.
    pub before_catalog_generation: u64,
    /// Before-effect commitment independently read from protected state.
    pub before_inventory_digest: [u8; 32],
    /// Digest of the independently read durable Storage attempt record.
    pub effect_commit_digest: [u8; 32],
    /// Digest of a fresh authenticated post-effect physical inventory.
    pub after_inventory_digest: [u8; 32],
    /// Resulting resource version selected from that inventory.
    pub resulting_version: [u8; 32],
    /// Digest of independently retained terminal result bytes.
    pub terminal_result_digest: [u8; 32],
    /// Catalog generation of the post-effect inventory.
    pub after_catalog_generation: u64,
}

/// Verifies both signatures against independently supplied physical currentness.
///
/// # Errors
///
/// Rejects any changed issuance, owner identity/generation, probe, durable
/// attempt, physical inventory, resulting version, or terminal result.
pub fn verify_operator_recovery_effect_completion_v2(
    signed_intent: &[u8],
    controller_key: &VerifyingKey,
    signed_evidence: &[u8],
    signed_receipt: &[u8],
    owner_key: &VerifyingKey,
    current: &OperatorRecoveryEffectCurrentnessV2,
) -> Result<OperatorRecoveryEffectReceiptV2, OperatorRecoveryEffectErrorV1> {
    current.issued_intent.validate()?;
    let intent = verify_operator_recovery_effect_intent_v1(signed_intent, controller_key)?;
    if intent != current.issued_intent {
        return Err(OperatorRecoveryEffectErrorV1::BindingMismatch);
    }
    let (receipt, evidence) = verify_operator_recovery_effect_receipt_v2(
        signed_receipt,
        signed_evidence,
        owner_key,
        &intent,
        current.owner_id,
        current.owner_key_generation,
        current.terminal_result_digest,
    )?;
    if evidence.probe_epoch != current.probe_epoch
        || evidence.absence_probe_digest != current.absence_probe_digest
        || evidence.before_catalog_generation != current.before_catalog_generation
        || evidence.before_inventory_digest != current.before_inventory_digest
        || evidence.effect_commit_digest != current.effect_commit_digest
        || evidence.after_inventory_digest != current.after_inventory_digest
        || evidence.resulting_version != current.resulting_version
        || evidence.after_catalog_generation != current.after_catalog_generation
    {
        return Err(OperatorRecoveryEffectErrorV1::BindingMismatch);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;

    use super::*;
    use crate::operator_recovery_effect::{
        OperatorRecoveryEffectActionV1, OperatorRecoveryEffectTargetV1,
        sign_operator_recovery_effect_intent_v1,
    };

    fn intent() -> OperatorRecoveryEffectIntentV1 {
        OperatorRecoveryEffectIntentV1 {
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
            current_fence_digest: [10; 32],
            effect_id: [11; 32],
            attempt: 1,
            current_generation: 12,
        }
    }

    #[test]
    fn evidence_packet_keeps_exact_v2_domain_and_signature_bytes() {
        let key = SigningKey::from_bytes(&[22; 32]);
        let intent = intent();
        let evidence = OperatorRecoveryEffectEvidenceV2 {
            intent_digest: intent.digest().unwrap(),
            owner_id: [13; 16],
            owner_key_generation: 4,
            probe_epoch: 1,
            absence_probe_digest: [14; 32],
            before_catalog_generation: 2,
            before_inventory_digest: [15; 32],
            effect_commit_digest: [16; 32],
            after_inventory_digest: [17; 32],
            resulting_version: [18; 32],
            after_catalog_generation: 3,
        };
        let payload = evidence.payload();
        let packet = sign_operator_recovery_effect_evidence_v2(&evidence, &key).unwrap();
        let mut message = Vec::from(EVIDENCE_DOMAIN.as_ref());
        message.extend_from_slice(&payload);

        assert_eq!(&packet[..EVIDENCE_PAYLOAD_BYTES], &payload);
        assert_eq!(
            &packet[EVIDENCE_PAYLOAD_BYTES..],
            key.sign(&message).to_bytes()
        );
        assert_eq!(
            verify_packet::<OPERATOR_RECOVERY_EFFECT_EVIDENCE_BYTES_V2>(
                &packet,
                EVIDENCE_PAYLOAD_BYTES,
                RECEIPT_DOMAIN,
                &key.verifying_key(),
            ),
            Err(OperatorRecoveryEffectErrorV1::InvalidSignature)
        );
    }

    #[test]
    fn generation_bound_pair_rejects_rotation_and_legacy_packet() {
        let key = SigningKey::from_bytes(&[31; 32]);
        let intent = intent();
        let evidence = OperatorRecoveryEffectEvidenceV2 {
            intent_digest: intent.digest().unwrap(),
            owner_id: [13; 16],
            owner_key_generation: 4,
            probe_epoch: 1,
            absence_probe_digest: [14; 32],
            before_catalog_generation: 2,
            before_inventory_digest: [15; 32],
            effect_commit_digest: [16; 32],
            after_inventory_digest: [17; 32],
            resulting_version: [18; 32],
            after_catalog_generation: 3,
        };
        let signed_evidence = sign_operator_recovery_effect_evidence_v2(&evidence, &key).unwrap();
        let receipt = OperatorRecoveryEffectReceiptV2 {
            intent_digest: evidence.intent_digest,
            owner_id: evidence.owner_id,
            owner_key_generation: evidence.owner_key_generation,
            signed_evidence_digest: evidence_digest_v2(&signed_evidence),
            before_inventory_digest: evidence.before_inventory_digest,
            after_inventory_digest: evidence.after_inventory_digest,
            resulting_version: evidence.resulting_version,
            terminal_result_digest: [19; 32],
            effect_commit_digest: evidence.effect_commit_digest,
            owner_generation: evidence.after_catalog_generation,
        };
        let signed_receipt = sign_operator_recovery_effect_receipt_v2(&receipt, &key).unwrap();
        let verify = |generation, evidence: &[u8], receipt: &[u8]| {
            verify_operator_recovery_effect_receipt_v2(
                receipt,
                evidence,
                &key.verifying_key(),
                &intent,
                [13; 16],
                generation,
                [19; 32],
            )
        };
        assert_eq!(
            verify(4, &signed_evidence, &signed_receipt),
            Ok((receipt, evidence))
        );
        assert!(verify(5, &signed_evidence, &signed_receipt).is_err());
        assert!(verify(4, &[0; 288], &signed_receipt).is_err());
        let mut altered = signed_evidence;
        altered[120] ^= 1;
        assert!(verify(4, &altered, &signed_receipt).is_err());

        let controller_key = SigningKey::from_bytes(&[32; 32]);
        let signed_intent =
            sign_operator_recovery_effect_intent_v1(&intent, &controller_key).unwrap();
        let current = OperatorRecoveryEffectCurrentnessV2 {
            issued_intent: intent,
            owner_id: evidence.owner_id,
            owner_key_generation: evidence.owner_key_generation,
            probe_epoch: evidence.probe_epoch,
            absence_probe_digest: evidence.absence_probe_digest,
            before_catalog_generation: evidence.before_catalog_generation,
            before_inventory_digest: evidence.before_inventory_digest,
            effect_commit_digest: evidence.effect_commit_digest,
            after_inventory_digest: evidence.after_inventory_digest,
            resulting_version: evidence.resulting_version,
            terminal_result_digest: receipt.terminal_result_digest,
            after_catalog_generation: evidence.after_catalog_generation,
        };
        let complete = |current: &OperatorRecoveryEffectCurrentnessV2| {
            verify_operator_recovery_effect_completion_v2(
                &signed_intent,
                &controller_key.verifying_key(),
                &signed_evidence,
                &signed_receipt,
                &key.verifying_key(),
                current,
            )
        };
        assert_eq!(complete(&current), Ok(receipt));
        let mut stale = current;
        stale.effect_commit_digest = [33; 32];
        assert_eq!(
            complete(&stale),
            Err(OperatorRecoveryEffectErrorV1::BindingMismatch)
        );
        stale = current;
        stale.owner_key_generation += 1;
        assert!(complete(&stale).is_err());
    }
}
