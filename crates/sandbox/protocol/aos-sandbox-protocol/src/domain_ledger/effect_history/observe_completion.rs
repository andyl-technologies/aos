//! Version7 completed reserved-child DATA over the unchanged inert version4 row.
//!
//! ```text
//! version:u8=7 | AOSCOE01 | planned-length:u32BE | companion-length:u32BE |
//! exact-version4-Planned-row | exact-AOSEXE01[40] | exact-AOSCOC01
//! ```
//!
//! This closed extension has only Applied attempt1. It does not make the inert
//! child dispatchable or accept an ordinary receipt without complete evidence.

use super::{EffectHistoryDataError, EffectLedgerRecord, EffectReceipt, EffectState,
    RESERVED_OBSERVE_EFFECT_VERSION, decode_effect, encode_effect};
use crate::domain_ledger::execution_observe_reservation::{ControllerExecutionObserveReservationV1,
    completion::{ObserveChildCompletionDataV1, MAXIMUM_COMPLETION_BYTES}};

/// Identifies the complete signed first-Observe child completion extension.
pub const COMPLETED_OBSERVE_EFFECT_VERSION: u8 = 7;
const MAGIC: &[u8; 8] = b"AOSCOE01";
const HEADER: usize = 1 + 8 + 4 + 4;
const RECEIPT: usize = 40;

fn invalid() -> EffectHistoryDataError {
    EffectHistoryDataError::CorruptLedger("invalid completed reserved Observe effect")
}

/// Encodes the exact completed inert child and its full signed evidence.
///
/// # Errors
/// Rejects any non-reserved plan, dispatch or metadata, any state other than
/// Applied attempt1, an inexact receipt, or invalid complete historical evidence.
pub fn encode_completed_observe_effect_v1(record: &EffectLedgerRecord, completion: &ObserveChildCompletionDataV1)
    -> Result<Vec<u8>, EffectHistoryDataError>
{
    let (plan, state, dispatch, metadata) = record.clone().into_parts();
    let EffectState::Applied { attempt: 1, receipt } = state else { return Err(invalid()); };
    if !plan.is_reserved_observe() || dispatch.is_some() || metadata.is_some() || receipt.as_bytes().len() != RECEIPT {
        return Err(invalid());
    }
    let reservation = ControllerExecutionObserveReservationV1::decode(
        plan.request().get(8..24).ok_or_else(invalid)?, plan.request()).map_err(|_| invalid())?;
    ObserveChildCompletionDataV1::decode(&reservation, receipt.as_bytes(), completion.bytes()).map_err(|_| invalid())?;
    let pending = encode_effect(&EffectLedgerRecord::from_parts((plan, EffectState::Planned, None, None)))?;
    let length = HEADER.checked_add(pending.len()).and_then(|n| n.checked_add(RECEIPT))
        .and_then(|n| n.checked_add(completion.bytes().len())).ok_or_else(invalid)?;
    let mut bytes = Vec::with_capacity(length);
    bytes.push(COMPLETED_OBSERVE_EFFECT_VERSION);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&u32::try_from(pending.len()).map_err(|_| invalid())?.to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(completion.bytes().len()).map_err(|_| invalid())?.to_be_bytes());
    bytes.extend_from_slice(&pending);
    bytes.extend_from_slice(receipt.as_bytes());
    bytes.extend_from_slice(completion.bytes());
    Ok(bytes)
}

/// Decodes a completed child with its fully validated signed-history companion.
///
/// # Errors
/// Rejects malformed lengths, an embedded row other than canonical inert
/// version4 Planned, any incomplete signature/source/lease/receipt binding or
/// trailing bytes. Actual protected source equality remains the native owner's check.
pub fn decode_completed_observe_effect_v1(bytes: &[u8])
    -> Result<(EffectLedgerRecord, ObserveChildCompletionDataV1), EffectHistoryDataError>
{
    if bytes.len() < HEADER + RECEIPT || bytes.first() != Some(&COMPLETED_OBSERVE_EFFECT_VERSION)
        || bytes.get(1..9) != Some(MAGIC.as_slice()) { return Err(invalid()); }
    let pending_length = u32::from_be_bytes(bytes[9..13].try_into().map_err(|_| invalid())?) as usize;
    let completion_length = u32::from_be_bytes(bytes[13..17].try_into().map_err(|_| invalid())?) as usize;
    if completion_length > MAXIMUM_COMPLETION_BYTES { return Err(invalid()); }
    let pending_end = HEADER.checked_add(pending_length).ok_or_else(invalid)?;
    let receipt_end = pending_end.checked_add(RECEIPT).ok_or_else(invalid)?;
    if receipt_end.checked_add(completion_length) != Some(bytes.len())
        || bytes.get(HEADER) != Some(&RESERVED_OBSERVE_EFFECT_VERSION) { return Err(invalid()); }
    // The nested version is checked BEFORE the shared decoder: no recursive V7.
    let pending = decode_effect(bytes.get(HEADER..pending_end).ok_or_else(invalid)?)?;
    let (plan, state, dispatch, metadata) = pending.into_parts();
    if !plan.is_reserved_observe() || state != EffectState::Planned || dispatch.is_some() || metadata.is_some() {
        return Err(invalid());
    }
    let reservation = ControllerExecutionObserveReservationV1::decode(
        plan.request().get(8..24).ok_or_else(invalid)?, plan.request()).map_err(|_| invalid())?;
    let receipt = EffectReceipt::new(bytes.get(pending_end..receipt_end).ok_or_else(invalid)?.to_vec())?;
    let completion = ObserveChildCompletionDataV1::decode(&reservation, receipt.as_bytes(),
        bytes.get(receipt_end..).ok_or_else(invalid)?).map_err(|_| invalid())?;
    Ok((EffectLedgerRecord::from_parts((plan, EffectState::Applied { attempt: 1, receipt }, None, None)), completion))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::effect_history::EffectPlan;
    use aos_sandbox_model::{ExecutionId, ObjectDigest, OperationId};

    fn pending() -> EffectLedgerRecord {
        let mut receipt = [7; 40];
        receipt[..8].copy_from_slice(b"AOSEXE01");
        let reservation = ControllerExecutionObserveReservationV1::new(
            ExecutionId::from_bytes([1; 16]), OperationId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]), [4; 32], &receipt).unwrap();
        EffectLedgerRecord::from_parts((EffectPlan::reserved_observe(&reservation), EffectState::Planned, None, None))
    }

    #[test]
    fn old_inert_bytes_remain_planned_and_an_executor_receipt_cannot_complete_them() {
        let pending = pending();
        let bytes = encode_effect(&pending).unwrap();
        assert_eq!(bytes[0], RESERVED_OBSERVE_EFFECT_VERSION);
        assert_eq!(decode_effect(&bytes).unwrap(), pending);

        let (plan, _, _, _) = pending.into_parts();
        let applied = EffectLedgerRecord::from_parts((plan, EffectState::Applied {
            attempt: 1, receipt: EffectReceipt::new(vec![9; 40]).unwrap(),
        }, None, None));
        assert!(encode_effect(&applied).is_err());
        let mut changed = bytes;
        changed[2] = 3;
        changed[4..8].copy_from_slice(&1_u32.to_le_bytes());
        assert!(decode_effect(&changed).is_err());
    }

    #[test]
    fn completed_wrapper_rejects_recursive_versions_unbounded_lengths_and_missing_signed_evidence() {
        let pending = encode_effect(&pending()).unwrap();
        let mut bytes = Vec::from([COMPLETED_OBSERVE_EFFECT_VERSION]);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(pending.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&pending);
        bytes.extend_from_slice(&[9; RECEIPT]);
        assert!(decode_effect(&bytes).is_err());

        let mut recursive = bytes.clone();
        recursive[HEADER] = COMPLETED_OBSERVE_EFFECT_VERSION;
        assert!(decode_effect(&recursive).is_err());
        for offset in [9, 13] {
            let mut oversized = bytes.clone();
            oversized[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(decode_effect(&oversized).is_err());
        }
        bytes.push(0);
        assert!(decode_effect(&bytes).is_err());
    }
}
