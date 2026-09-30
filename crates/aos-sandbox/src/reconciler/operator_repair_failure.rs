//! DATA-only recognition of the original Repair precondition failure receipt.
//!
//! This decoder grants neither currentness nor physical effect authority. The
//! Controller's separate cold validator joins its signed hold, owner pair,
//! archived original admission, and exact terminal public rows before projection.
//!
//! ```text
//! AOSORF01 | reason:u8 | zero[7] | operation[16] | commitments[192]
//!          | signed-held-header[652] | owner-witness[208]
//!          | predecessor-sequence:u64be | completion-wall:i64be | checksum[32]
//! ```

use aos_sandbox_core::OperationId;
use sha2::{Digest as _, Sha256};

use super::{EffectReceipt, Journal, ReconcilerError};

pub(crate) const RECEIPT_BYTES: usize = 1132;
pub(crate) const RECEIPT_DOMAIN: &[u8] =
    b"aos.sandbox.operator-repair-original-precondition-failure.v1\0";

/// Contains strictly decoded historical DATA, never a live held owner.
pub(crate) struct RepairPreconditionFailureReceiptV1([u8; RECEIPT_BYTES]);

impl RepairPreconditionFailureReceiptV1 {
    /// Decodes the fixed historical frame without granting heldness.
    ///
    /// # Errors
    ///
    /// Rejects wrong size/version/reason, sentinel commitments or checksum mismatch.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ()> {
        let bytes: [u8; RECEIPT_BYTES] = bytes.try_into().map_err(|_| ())?;
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(RECEIPT_DOMAIN)
            .chain_update(&bytes[..1100])
            .finalize()
            .into();
        if &bytes[..8] != b"AOSORF01"
            || bytes[8..16] != [1, 0, 0, 0, 0, 0, 0, 0]
            || bytes[16..32] == [0; 16]
            || bytes[1100..] != checksum
            || u64::from_be_bytes(bytes[1084..1092].try_into().map_err(|_| ())?) == 0
            || [32, 64, 96, 128, 160, 192].iter().any(|offset| {
                bytes[*offset..*offset + 32] == [0; 32]
            })
        {
            return Err(());
        }

        Ok(Self(bytes))
    }

    /// Returns the complete retained DATA frame.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the original public operation identity.
    pub(crate) fn operation(&self) -> OperationId {
        let mut id = [0; 16];
        id.copy_from_slice(&self.0[16..32]);
        OperationId::from_bytes(id)
    }

    /// Returns the versioned commitment used by the exact Controller ACK.
    pub(crate) fn digest(&self) -> [u8; 32] {
        Sha256::new().chain_update(RECEIPT_DOMAIN).chain_update(self.0).finalize().into()
    }
}

/// Recognizes the method-specific codec without accepting a malformed marker.
pub(super) fn classify(receipt: &EffectReceipt) -> Result<bool, ReconcilerError> {
    if !receipt.as_bytes().starts_with(b"AOSORF01") {
        return Ok(false);
    }

    RepairPreconditionFailureReceiptV1::decode(receipt.as_bytes())
        .map_err(|()| ReconcilerError::CorruptLedger("invalid Repair failure receipt"))?;
    Ok(true)
}

/// Independently checks the original public admission and actual signed decision.
pub(super) fn validate(journal: &Journal, operation: OperationId) -> Result<(), ReconcilerError> {
    #[cfg(target_os = "linux")]
    return crate::controller::verify_operator_storage_repair_failure_v1(journal, operation)
        .map_err(|_| ReconcilerError::CorruptLedger("Repair failure decision does not match its original custody"));
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (journal, operation);
        Err(ReconcilerError::CorruptLedger("Repair failure owner is unsupported"))
    }
}

/// Rejects failure receipts in every other method, state, or effect graph.
pub(super) fn validate_operation(
    journal: &Journal,
    operation_id: OperationId,
    operation: super::OperationRecord,
) -> Result<(), ReconcilerError> {
    for step in 0..operation.effect_count {
        let effect = super::decode_effect(journal.get(super::RecordNamespace::Effect,
            &super::effect_key(operation_id, step))
            .ok_or(ReconcilerError::CorruptLedger("missing effect record"))?)?;
        if let super::EffectState::Applied { receipt, .. } = &effect.state {
            if classify(receipt)? {
                if step != 0 || operation.effect_count != 1
                    || operation.state != super::OperationState::PermanentlyBlocked
                    || !super::is_operator_storage_repair_effect_v1(&effect.plan)?
                {
                    return Err(ReconcilerError::CorruptLedger("Repair failure has a nonexact public graph"));
                }
                validate(journal, operation_id)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_alone_and_every_truncated_frame_are_not_decisions() {
        let bytes = [0; RECEIPT_BYTES];
        for length in 0..RECEIPT_BYTES {
            assert!(RepairPreconditionFailureReceiptV1::decode(&bytes[..length]).is_err());
        }
        assert!(RepairPreconditionFailureReceiptV1::decode(b"AOSORF01").is_err());
    }

    #[test]
    fn data_checksum_covers_full_witness_and_all_original_commitments() {
        // A codec-only frame deliberately carries no valid cryptographic hold.
        // Passing this decoder never makes it a Prepared decision or live owner.
        let mut data = [1; RECEIPT_BYTES];
        data[..8].copy_from_slice(b"AOSORF01");
        data[8..16].copy_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(RECEIPT_DOMAIN).chain_update(&data[..1100]).finalize().into();
        data[1100..].copy_from_slice(&checksum);
        assert!(RepairPreconditionFailureReceiptV1::decode(&data).is_ok());

        for offset in [16, 32, 64, 96, 128, 160, 192, 224, 875, 876, 1083, 1084, 1092, 1131] {
            let mut substituted = data;
            substituted[offset] ^= 1;
            assert!(RepairPreconditionFailureReceiptV1::decode(&substituted).is_err());
        }
    }
}
