//! Prices the sole provisioning historical-link decoder graph before entry.
//!
//! This reads borrowed lengths only. The caller retains the actual Native
//! state/index and independently admits the returned representation under its
//! genuine original. The supplier creates no decoded model or authority.

use std::mem::size_of;

use aos_sandbox_core::{DecodeLimits, RecordNamespace};
use aos_sandbox_core::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;

use super::{PREFIX, PROVISIONING_RESOURCE_KEY_BYTES_V1, ProvisioningResourceRecordsV1, State};
use crate::domain_ledger::{
    effect_history::effect_decoding_receiving_bytes_v1,
    operation::OperationRecord,
    ownership_gate::{OwnershipGatePlanV1, OwnershipGateStatusV1},
    runtime_authority_history::RuntimeAuthorityPendingV1,
    transaction::JournalTransaction,
};

/// Bounds one complete sequential provisioning-link pass from captured bytes.
///
/// Each referenced row is bounded by this SAME captured extent. A parent
/// Effect remains live while its public request is validated again, so both
/// actual decoder entries receive the existing complete Effect graph supplier.
/// Its fixed variant closure includes every public, Controller, FUSE, Nix and
/// Q04 branch; a forged historical link cannot choose a cheaper decoder.
///
/// The pending assignment and gate remain live beside that parent/request.
/// Their existing assignment/publication suppliers include canonical model,
/// construction, reencoding and collection-growth planes. Gate-owned claim,
/// key ID and idempotency bytes are additionally bounded by the raw extent.
/// Two Copy Operation values and the actual lookup/companion stack carriers
/// are separate below. Parent sets are scanned sequentially, never retained
/// in a new map. Every namespace/index/native representation is paid outside
/// this BYTE-only term. Decoder limits and the actual cgroup remain backstops.
/// `None` reports checked arithmetic overflow.
#[must_use]
pub fn provisioning_links_decoding_receiving_bytes_v1(encoded: usize) -> Option<usize> {
    let (assignment, _) = CanonicalAssignmentDecodeCaptureV1::
        receiving_dynamic_footprint_v1(encoded, DecodeLimits::default())?;
    let pending = assignment
        .checked_add(CanonicalAssignmentDecodeCaptureV1::receiving_construction_bytes_v1()?)?
        .checked_add(encoded.checked_mul(3)?)?
        .checked_add(size_of::<RuntimeAuthorityPendingV1>().checked_mul(2)?)?;
    let gate = crate::publication::decoding_receiving_bytes_v1(encoded)?
        .checked_add(encoded.checked_mul(3)?)?
        .checked_add(size_of::<OwnershipGatePlanV1>().checked_mul(2)?)?
        .checked_add(size_of::<OwnershipGateStatusV1>().checked_mul(2)?)?;
    let parent_and_request = effect_decoding_receiving_bytes_v1(encoded)?.checked_mul(2)?;

    // record() and companion checks each hold at most one allocated lookup key.
    // The two planes cover its construction temporary and live destination.
    // All reference keys are no wider than the canonical companion key.
    let lookup = size_of::<(RecordNamespace, Vec<u8>)>()
        .checked_add(PROVISIONING_RESOURCE_KEY_BYTES_V1)?.checked_mul(2)?;
    let fixed = size_of::<OperationRecord>().checked_mul(2)?
        .checked_add(size_of::<ProvisioningResourceRecordsV1>().checked_mul(2)?)?
        .checked_add(super::PROVISIONING_RESOURCE_ROW_BYTES_V1.checked_mul(2)?)?
        .checked_add(size_of::<sha2::Sha256>().checked_mul(2)?)?
        .checked_add(size_of::<super::ProvisioningResourceLinkErrorV1>().checked_mul(2)?)?
        .checked_add(lookup)?;
    parent_and_request.checked_add(pending)?.checked_add(gate)?.checked_add(fixed)
}

/// Bounds the same pass over actual current and proposed borrowed rows.
///
/// A malformed recognized key also enters the bound. A removed or replaced
/// value retains its old extent, and every proposed value contributes before
/// application. No decoder runs while computing this complete upper bound.
/// With no provisioning family the validator cannot enter a foreign decoder,
/// so this returns zero additional bytes. It charges no field namespace fees.
/// `None` reports checked length or decoder-geometry overflow.
#[must_use]
pub fn provisioning_links_reached_receiving_bytes_v1(
    state: &State,
    transaction: Option<&JournalTransaction>,
) -> Option<usize> {
    let selected = state.keys().any(|(namespace, key)|
        *namespace == RecordNamespace::DesiredState && key.starts_with(PREFIX))
        || transaction.is_some_and(|transaction| transaction.records().iter().any(|record|
            record.namespace() == RecordNamespace::DesiredState
                && record.key().starts_with(PREFIX)));
    if !selected {
        return Some(0);
    }

    let mut encoded = 0usize;
    for ((_, key), value) in state {
        encoded = encoded.checked_add(key.len())?.checked_add(value.len())?;
    }
    if let Some(transaction) = transaction {
        for record in transaction.records() {
            encoded = encoded.checked_add(record.key().len())?
                .checked_add(record.value().map_or(0, <[u8]>::len))?;
        }
    }
    provisioning_links_decoding_receiving_bytes_v1(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::transaction::JournalRecord;

    #[test]
    fn proposed_recognized_rows_pay_foreign_decoders_before_application() {
        let state = State::new();
        let ordinary = JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, b"unrelated".to_vec(), vec![0; 8],
        )]).unwrap();
        let recognized = JournalTransaction::new([2; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, PREFIX.to_vec(), vec![0; 8],
        )]).unwrap();

        assert_eq!(provisioning_links_reached_receiving_bytes_v1(&state, Some(&ordinary)), Some(0));
        let reached = provisioning_links_reached_receiving_bytes_v1(&state, Some(&recognized)).unwrap();
        assert!(reached >= effect_decoding_receiving_bytes_v1(PREFIX.len() + 8).unwrap() * 2);
        assert_eq!(provisioning_links_reached_receiving_bytes_v1(&state, None), Some(0));
    }

    #[test]
    fn captured_extent_bound_grows_and_refuses_overflow() {
        let small = provisioning_links_decoding_receiving_bytes_v1(512).unwrap();
        let large = provisioning_links_decoding_receiving_bytes_v1(4096).unwrap();

        assert!(small < large);
        assert!(provisioning_links_decoding_receiving_bytes_v1(usize::MAX).is_none());
    }
}
