//! Compares the existing Controller resource-capacity selection as DATA only.

use aos_sandbox_protocol::domain_ledger::{
    capacity::GlobalCapacityReservationPurposeV1,
    capacity_family::capacity_record_has_legacy_purpose,
    transaction::JournalRecord,
};

use super::*;

/// Selects the existing purpose from every actual proposed or deleted capacity.
///
/// This supplies no capacity or native permission. A preceding matching record
/// cannot hide a later malformed or unknown family. Deleted values are read
/// from the same supplied historical map before canonical comparison.
///
/// # Errors
/// Preserves each canonical capacity family or record-decoding refusal.
pub fn consumer_capacity_is_selected_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<bool, JournalError> {
    transaction.records().iter().filter(|record| {
        record.namespace() == RecordNamespace::GlobalCapacityReservation
    }).try_fold(false, |found, record| {
        let stored;
        let capacity = if record.value().is_some() {
            record
        } else if let Some(value) = state.get(&(RecordNamespace::GlobalCapacityReservation, record.key().to_vec())) {
            stored = JournalRecord::put(
                RecordNamespace::GlobalCapacityReservation,
                record.key().to_vec(), value.to_vec(),
            );
            &stored
        } else {
            return Ok(found);
        };
        let selected = capacity_record_has_legacy_purpose(
            capacity, GlobalCapacityReservationPurposeV1::ControllerConsumerResource,
        )?;
        Ok(found || selected)
    })
}

/// Preserves the ordinary no-Controller-original branch without a native grant.
///
/// `allow_capacity_records` preserves only the former diagnostic scan frontier.
/// It cannot admit a selected Controller resource record or capacity. Actual
/// Controller admission still needs its separate protected original.
///
/// # Errors
/// Refuses selected resource/capacity writes and preserves capacity decode errors.
pub fn require_no_consumer_resource_transition_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    allow_capacity_records: bool,
) -> Result<(), JournalError> {
    let resources = transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::ControllerConsumerReadAttempt
    });
    if !resources && !allow_capacity_records {
        return Ok(());
    }
    let capacity = consumer_capacity_is_selected_v1(state, transaction)?;
    if resources || capacity {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_fast_path_and_selected_capacity_keep_the_original_decode_order() {
        let malformed = JournalRecord::put(
            RecordNamespace::GlobalCapacityReservation, b"capacity".to_vec(), vec![0],
        );
        let transaction = JournalTransaction::new([1; 16], vec![malformed.clone()]).unwrap();
        let state = BTreeMap::new();

        assert!(require_no_consumer_resource_transition_v1(&state, &transaction, false).is_ok());
        let expected = capacity_record_has_legacy_purpose(
            &malformed, GlobalCapacityReservationPurposeV1::ControllerConsumerResource,
        ).unwrap_err();
        let expected = JournalError::from(expected);
        let selected = require_no_consumer_resource_transition_v1(&state, &transaction, true).unwrap_err();

        assert_eq!(selected.to_string(), expected.to_string());
        let with_resource = JournalTransaction::new([2; 16], vec![
            JournalRecord::put(
                RecordNamespace::ControllerConsumerReadAttempt, b"resource".to_vec(), vec![0],
            ),
            malformed,
        ]).unwrap();
        assert_eq!(
            require_no_consumer_resource_transition_v1(&state, &with_resource, false)
                .unwrap_err().to_string(),
            expected.to_string(),
        );
    }
}
