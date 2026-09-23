//! Signed, fixed-width authority and outcome contracts for operator recovery.
//!
//! ```text
//! intent  = AOSOREI1 || recovery[16] || target[16] || action:u8 || kind:u8
//!           || reserved[6] || principal[16] || project[16] || capability[16]
//!           || expected_version[32] || evidence[32] || request[32]
//!           || authorization[32] || current_fence[32] || effect[32]
//!           || attempt:u32be || generation:u64be || controller_signature[64]
//! receipt = AOSORR01 || intent_digest[32] || owner[16]
//!           || before_inventory[32] || after_inventory[32]
//!           || resulting_version[32] || terminal_result[32]
//!           || effect_commit[32] || owner_generation:u64be || owner_signature[64]
//! ```
//!
//! This format grants no authority by itself. A protected controller must
//! derive the intent from a current authorization and durable effect issuance;
//! a separately pinned physical owner must sign the receipt only after
//! verifying the effect and resulting inventory. Neither key may be reused
//! from an unrelated broker or attach credential.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

const INTENT_MAGIC: &[u8; 8] = b"AOSOREI1";
const RECEIPT_MAGIC: &[u8; 8] = b"AOSORR01";
const INTENT_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-effect-intent.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-effect-receipt.v1\0";
const INTENT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.operator-recovery-effect-intent-digest.v1\0";
const INTENT_PAYLOAD_BYTES: usize = 300;
const RECEIPT_PAYLOAD_BYTES: usize = 224;

/// Exact encoded intent size, including its controller signature.
pub const OPERATOR_RECOVERY_EFFECT_INTENT_BYTES: usize = INTENT_PAYLOAD_BYTES + 64;
/// Exact encoded owner receipt size, including its owner signature.
pub const OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES: usize = RECEIPT_PAYLOAD_BYTES + 64;

/// Selects an effectful recovery action that requires physical owner evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorRecoveryEffectActionV1 {
    /// Reobserves and converges the protected target.
    Reconcile,
    /// Performs a protected corrective effect and verifies its postcondition.
    Repair,
}

impl OperatorRecoveryEffectActionV1 {
    const fn code(self) -> u8 {
        match self {
            Self::Reconcile => 3,
            Self::Repair => 4,
        }
    }

    fn from_code(code: u8) -> Result<Self, OperatorRecoveryEffectErrorV1> {
        match code {
            3 => Ok(Self::Reconcile),
            4 => Ok(Self::Repair),
            _ => Err(OperatorRecoveryEffectErrorV1::InvalidField),
        }
    }
}

/// Selects the closed protected target resource family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorRecoveryEffectTargetV1 {
    /// A sandbox resource.
    Sandbox,
    /// An operation resource.
    Operation,
}

impl OperatorRecoveryEffectTargetV1 {
    const fn code(self) -> u8 {
        match self {
            Self::Sandbox => 1,
            Self::Operation => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, OperatorRecoveryEffectErrorV1> {
        match code {
            1 => Ok(Self::Sandbox),
            2 => Ok(Self::Operation),
            _ => Err(OperatorRecoveryEffectErrorV1::InvalidField),
        }
    }
}

/// Commits one current-authorized, durably issued Reconcile or Repair attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorRecoveryEffectIntentV1 {
    /// New recovery operation identity.
    pub recovery_operation_id: [u8; 16],
    /// Exact target resource identity.
    pub target_id: [u8; 16],
    /// Effectful action being requested.
    pub action: OperatorRecoveryEffectActionV1,
    /// Protected resource family, never selected by untrusted input.
    pub target_kind: OperatorRecoveryEffectTargetV1,
    /// Authorized operator identity.
    pub principal_id: [u8; 16],
    /// Authorized project boundary.
    pub project_id: [u8; 16],
    /// Current capability identity used for this request.
    pub capability_id: [u8; 16],
    /// Digest of the exact expected target resource-version bytes.
    pub expected_version_digest: [u8; 32],
    /// Digest of the exact checked evidence descriptor.
    pub evidence_digest: [u8; 32],
    /// Durable public request commitment.
    pub request_digest: [u8; 32],
    /// Protected current authorization decision commitment.
    pub authorization_digest: [u8; 32],
    /// Protected owner-specific currentness and lease fence.
    pub current_fence_digest: [u8; 32],
    /// Durable effect-issuance identity.
    pub effect_id: [u8; 32],
    /// Exact one-based attempt number.
    pub attempt: u32,
    /// Protected target desired generation at issuance.
    pub current_generation: u64,
}

impl OperatorRecoveryEffectIntentV1 {
    /// Rejects sentinel fields before signing or accepting an effect intent.
    ///
    /// # Errors
    ///
    /// Returns an error when any identity, digest, or monotone counter is absent.
    pub fn validate(&self) -> Result<(), OperatorRecoveryEffectErrorV1> {
        if [
            self.recovery_operation_id,
            self.target_id,
            self.principal_id,
            self.project_id,
            self.capability_id,
        ]
        .contains(&[0; 16])
            || [
                self.expected_version_digest,
                self.evidence_digest,
                self.request_digest,
                self.authorization_digest,
                self.current_fence_digest,
                self.effect_id,
            ]
            .contains(&[0; 32])
            || self.attempt == 0
            || self.current_generation == 0
        {
            return Err(OperatorRecoveryEffectErrorV1::InvalidField);
        }
        Ok(())
    }

    /// Returns the domain-separated commitment used by the owner receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when the intent contains sentinel fields.
    pub fn digest(&self) -> Result<[u8; 32], OperatorRecoveryEffectErrorV1> {
        self.validate()?;
        Ok(Sha256::new()
            .chain_update(INTENT_DIGEST_DOMAIN)
            .chain_update(self.payload())
            .finalize()
            .into())
    }

    fn payload(&self) -> [u8; INTENT_PAYLOAD_BYTES] {
        let mut output = [0; INTENT_PAYLOAD_BYTES];
        let mut cursor = 0;
        for part in [
            INTENT_MAGIC.as_slice(),
            &self.recovery_operation_id,
            &self.target_id,
            &[self.action.code()],
            &[self.target_kind.code()],
            &[0; 6],
            &self.principal_id,
            &self.project_id,
            &self.capability_id,
            &self.expected_version_digest,
            &self.evidence_digest,
            &self.request_digest,
            &self.authorization_digest,
            &self.current_fence_digest,
            &self.effect_id,
            &self.attempt.to_be_bytes(),
            &self.current_generation.to_be_bytes(),
        ] {
            output[cursor..cursor + part.len()].copy_from_slice(part);
            cursor += part.len();
        }
        output
    }
}

/// Signs a protected effect intent using a dedicated controller recovery key.
///
/// # Errors
///
/// Returns an error for sentinel intent fields.
pub fn sign_operator_recovery_effect_intent_v1(
    intent: &OperatorRecoveryEffectIntentV1,
    key: &SigningKey,
) -> Result<[u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES], OperatorRecoveryEffectErrorV1> {
    intent.validate()?;
    Ok(sign_packet::<
        INTENT_PAYLOAD_BYTES,
        OPERATOR_RECOVERY_EFFECT_INTENT_BYTES,
    >(intent.payload(), INTENT_DOMAIN, key))
}

/// Verifies a controller intent under an independently pinned recovery key.
///
/// # Errors
///
/// Returns an error for malformed bytes, an invalid signature, or sentinel fields.
pub fn verify_operator_recovery_effect_intent_v1(
    packet: &[u8],
    key: &VerifyingKey,
) -> Result<OperatorRecoveryEffectIntentV1, OperatorRecoveryEffectErrorV1> {
    let bytes = verify_packet::<OPERATOR_RECOVERY_EFFECT_INTENT_BYTES>(
        packet,
        INTENT_PAYLOAD_BYTES,
        INTENT_DOMAIN,
        key,
    )?;
    if &bytes[..8] != INTENT_MAGIC || bytes[42..48] != [0; 6] {
        return Err(OperatorRecoveryEffectErrorV1::InvalidEncoding);
    }
    let mut cursor = 8;
    let mut take = |length: usize| {
        let start = cursor;
        cursor += length;
        &bytes[start..cursor]
    };
    let recovery_operation_id = array(take(16))?;
    let target_id = array(take(16))?;
    let action = OperatorRecoveryEffectActionV1::from_code(take(1)[0])?;
    let target_kind = OperatorRecoveryEffectTargetV1::from_code(take(1)[0])?;
    let _ = take(6);
    let intent = OperatorRecoveryEffectIntentV1 {
        recovery_operation_id,
        target_id,
        action,
        target_kind,
        principal_id: array(take(16))?,
        project_id: array(take(16))?,
        capability_id: array(take(16))?,
        expected_version_digest: array(take(32))?,
        evidence_digest: array(take(32))?,
        request_digest: array(take(32))?,
        authorization_digest: array(take(32))?,
        current_fence_digest: array(take(32))?,
        effect_id: array(take(32))?,
        attempt: u32::from_be_bytes(array(take(4))?),
        current_generation: u64::from_be_bytes(array(take(8))?),
    };
    intent.validate()?;
    Ok(intent)
}

/// Attests one physical owner's exact post-effect inventory and terminal result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorRecoveryEffectReceiptV1 {
    /// Commitment to the exact signed intent and its current authorization.
    pub intent_digest: [u8; 32],
    /// Independently pinned physical owner identity.
    pub owner_id: [u8; 16],
    /// Owner-observed inventory immediately before the effect.
    pub before_inventory_digest: [u8; 32],
    /// Owner-observed inventory after the effect and readback.
    pub after_inventory_digest: [u8; 32],
    /// Resulting checked target resource version.
    pub resulting_version: [u8; 32],
    /// Digest of the exact checked terminal result bytes.
    pub terminal_result_digest: [u8; 32],
    /// Owner's durable effect-commit receipt commitment.
    pub effect_commit_digest: [u8; 32],
    /// Owner's protected generation at post-effect readback.
    pub owner_generation: u64,
}

impl OperatorRecoveryEffectReceiptV1 {
    /// Rejects sentinel fields before signing or accepting an owner receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when any identity, digest, or owner generation is absent.
    pub fn validate(&self) -> Result<(), OperatorRecoveryEffectErrorV1> {
        if self.owner_id == [0; 16]
            || [
                self.intent_digest,
                self.before_inventory_digest,
                self.after_inventory_digest,
                self.resulting_version,
                self.terminal_result_digest,
                self.effect_commit_digest,
            ]
            .contains(&[0; 32])
            || self.owner_generation == 0
        {
            return Err(OperatorRecoveryEffectErrorV1::InvalidField);
        }
        Ok(())
    }

    fn payload(&self) -> [u8; RECEIPT_PAYLOAD_BYTES] {
        let mut output = [0; RECEIPT_PAYLOAD_BYTES];
        let mut cursor = 0;
        for part in [
            RECEIPT_MAGIC.as_slice(),
            &self.intent_digest,
            &self.owner_id,
            &self.before_inventory_digest,
            &self.after_inventory_digest,
            &self.resulting_version,
            &self.terminal_result_digest,
            &self.effect_commit_digest,
            &self.owner_generation.to_be_bytes(),
        ] {
            output[cursor..cursor + part.len()].copy_from_slice(part);
            cursor += part.len();
        }
        output
    }
}

/// Signs a physical post-effect receipt using a dedicated owner recovery key.
///
/// # Errors
///
/// Returns an error for sentinel receipt fields.
pub fn sign_operator_recovery_effect_receipt_v1(
    receipt: &OperatorRecoveryEffectReceiptV1,
    key: &SigningKey,
) -> Result<[u8; OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES], OperatorRecoveryEffectErrorV1> {
    receipt.validate()?;
    Ok(sign_packet::<
        RECEIPT_PAYLOAD_BYTES,
        OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES,
    >(receipt.payload(), RECEIPT_DOMAIN, key))
}

/// Verifies an owner receipt against the exact intent and terminal result.
///
/// The caller must also compare the owner identity, inventory, resulting
/// resource, and current authority with protected owner state. A valid
/// signature is not by itself proof that the target was repaired.
///
/// # Errors
///
/// Returns an error for malformed bytes, an invalid signature, sentinel fields,
/// or a different intent or terminal result.
pub fn verify_operator_recovery_effect_receipt_v1(
    packet: &[u8],
    key: &VerifyingKey,
    intent: &OperatorRecoveryEffectIntentV1,
    terminal_result_digest: [u8; 32],
) -> Result<OperatorRecoveryEffectReceiptV1, OperatorRecoveryEffectErrorV1> {
    let bytes = verify_packet::<OPERATOR_RECOVERY_EFFECT_RECEIPT_BYTES>(
        packet,
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
    let receipt = OperatorRecoveryEffectReceiptV1 {
        intent_digest: array(take(32))?,
        owner_id: array(take(16))?,
        before_inventory_digest: array(take(32))?,
        after_inventory_digest: array(take(32))?,
        resulting_version: array(take(32))?,
        terminal_result_digest: array(take(32))?,
        effect_commit_digest: array(take(32))?,
        owner_generation: u64::from_be_bytes(array(take(8))?),
    };
    receipt.validate()?;
    if receipt.intent_digest != intent.digest()?
        || receipt.terminal_result_digest != terminal_result_digest
    {
        return Err(OperatorRecoveryEffectErrorV1::BindingMismatch);
    }
    Ok(receipt)
}

fn sign_packet<const PAYLOAD: usize, const PACKET: usize>(
    payload: [u8; PAYLOAD],
    domain: &[u8],
    key: &SigningKey,
) -> [u8; PACKET] {
    let mut message = Vec::with_capacity(domain.len() + PAYLOAD);
    message.extend_from_slice(domain);
    message.extend_from_slice(&payload);
    let signature = key.sign(&message).to_bytes();
    let mut packet = [0; PACKET];
    packet[..PAYLOAD].copy_from_slice(&payload);
    packet[PAYLOAD..].copy_from_slice(&signature);
    packet
}

fn verify_packet<const PACKET: usize>(
    packet: &[u8],
    payload_bytes: usize,
    domain: &[u8],
    key: &VerifyingKey,
) -> Result<[u8; PACKET], OperatorRecoveryEffectErrorV1> {
    let bytes: [u8; PACKET] = packet
        .try_into()
        .map_err(|_| OperatorRecoveryEffectErrorV1::InvalidEncoding)?;
    let signature_bytes: [u8; 64] = bytes[payload_bytes..]
        .try_into()
        .map_err(|_| OperatorRecoveryEffectErrorV1::InvalidEncoding)?;
    let mut message = Vec::with_capacity(domain.len() + payload_bytes);
    message.extend_from_slice(domain);
    message.extend_from_slice(&bytes[..payload_bytes]);
    key.verify_strict(&message, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| OperatorRecoveryEffectErrorV1::InvalidSignature)?;
    Ok(bytes)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], OperatorRecoveryEffectErrorV1> {
    bytes
        .try_into()
        .map_err(|_| OperatorRecoveryEffectErrorV1::InvalidEncoding)
}

/// Reports a malformed or unauthenticated recovery effect artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OperatorRecoveryEffectErrorV1 {
    /// The exact fixed-width encoding is invalid.
    #[error("operator recovery effect artifact has invalid encoding")]
    InvalidEncoding,
    /// A required semantic field is absent.
    #[error("operator recovery effect artifact has an invalid field")]
    InvalidField,
    /// The dedicated signing key did not sign these exact bytes.
    #[error("operator recovery effect signature is invalid")]
    InvalidSignature,
    /// The owner receipt does not name the expected intent or terminal result.
    #[error("operator recovery effect receipt binding does not match")]
    BindingMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_repair_receipt_binds_intent_and_terminal_result() {
        let controller_key = SigningKey::from_bytes(&[1; 32]);
        let owner_key = SigningKey::from_bytes(&[2; 32]);
        let intent = OperatorRecoveryEffectIntentV1 {
            recovery_operation_id: [1; 16],
            target_id: [2; 16],
            action: OperatorRecoveryEffectActionV1::Repair,
            target_kind: OperatorRecoveryEffectTargetV1::Operation,
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
            current_generation: 1,
        };
        let signed_intent = sign_operator_recovery_effect_intent_v1(&intent, &controller_key)
            .expect("valid intent");
        assert_eq!(
            verify_operator_recovery_effect_intent_v1(
                &signed_intent,
                &controller_key.verifying_key()
            )
            .expect("signed intent"),
            intent
        );

        let receipt = OperatorRecoveryEffectReceiptV1 {
            intent_digest: intent.digest().expect("intent digest"),
            owner_id: [12; 16],
            before_inventory_digest: [13; 32],
            after_inventory_digest: [14; 32],
            resulting_version: [15; 32],
            terminal_result_digest: [16; 32],
            effect_commit_digest: [17; 32],
            owner_generation: 2,
        };
        let signed_receipt =
            sign_operator_recovery_effect_receipt_v1(&receipt, &owner_key).expect("valid receipt");
        assert_eq!(
            verify_operator_recovery_effect_receipt_v1(
                &signed_receipt,
                &owner_key.verifying_key(),
                &intent,
                [16; 32],
            )
            .expect("signed receipt"),
            receipt
        );
        assert_eq!(
            verify_operator_recovery_effect_receipt_v1(
                &signed_receipt,
                &owner_key.verifying_key(),
                &intent,
                [18; 32],
            ),
            Err(OperatorRecoveryEffectErrorV1::BindingMismatch)
        );
        let different_action = OperatorRecoveryEffectIntentV1 {
            action: OperatorRecoveryEffectActionV1::Reconcile,
            ..intent
        };
        assert_eq!(
            verify_operator_recovery_effect_receipt_v1(
                &signed_receipt,
                &owner_key.verifying_key(),
                &different_action,
                [16; 32],
            ),
            Err(OperatorRecoveryEffectErrorV1::BindingMismatch)
        );
        let mut tampered = signed_receipt;
        tampered[60] ^= 1;
        assert_eq!(
            verify_operator_recovery_effect_receipt_v1(
                &tampered,
                &owner_key.verifying_key(),
                &intent,
                [16; 32],
            ),
            Err(OperatorRecoveryEffectErrorV1::InvalidSignature)
        );
    }
}
