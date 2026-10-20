//! Shares the existing complete outstanding-capacity pressure recipe.
//!
//! Deletion selectors are comparison DATA derived from a real role's already
//! checked private crossing. Selecting a branch here cannot authorize a native
//! mutation, recreate an original, settle a reservation or admit a role.

use std::collections::BTreeMap;
use aos_sandbox_core::RecordNamespace;
use aos_sandbox_journal::materialized::{self, RecordMutationRef};
use aos_sandbox_protocol::domain_ledger::capacity::reservation_key;
use aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError;
use aos_sandbox_protocol::domain_ledger::JournalTransactionDataError;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalRecord};

/// Selects an existing mechanical deletion comparison without role authority.
#[derive(Clone, Copy)]
pub enum CapacityDeletionSelectorDataV1 {
    /// Compares the exact retained identifier supplied by the private caller.
    Reservation(Option<[u8; 32]>),
    /// Decodes the identifier from the actual original materialized record.
    ExistingRecord,
}

/// Compares every promised record, byte and transaction floor against native DATA.
///
/// Real role wrappers independently enforce the closed namespace, currentness,
/// payer, deletion purpose and final native crossing around this shared recipe.
///
/// # Errors
/// Preserves malformed/duplicate/exhausted capacity and projected native count
/// refusals in the existing arithmetic and short-circuit order.
pub fn validate_reserved_capacity_data_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    prospective_materialized_bytes: usize,
    records: &[JournalRecord],
    deletion: CapacityDeletionSelectorDataV1,
    prospective_journal_bytes: u64,
    prospective_transactions: usize,
    limits: JournalLimits,
) -> Result<(), CapacityDataError> {
    let mut reservations =
        aos_sandbox_protocol::domain_ledger::capacity_family::family::accounting_reservations(
            state,
        )?;
    for record in records {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        match record.value() {
            Some(value) => {
                let decoded = aos_sandbox_protocol::domain_ledger::capacity_family::family::accounting_reservation(
                    record.key(), value,
                )?;
                if reservations
                    .insert(decoded.reservation_id, decoded)
                    .is_some()
                {
                    return Err(CapacityDataError::Transaction(
                        JournalTransactionDataError::DuplicateRecordKey,
                    ));
                }
            }
            None => {
                let identifier = match deletion {
                    CapacityDeletionSelectorDataV1::ExistingRecord => {
                        let value = state
                            .get(&(record.namespace(), record.key().to_vec()))
                            .ok_or(CapacityDataError::ProtectedBoundary)?;
                        aos_sandbox_protocol::domain_ledger::capacity_family::family::accounting_reservation(
                            record.key(), value,
                        )?.reservation_id
                    }
                    CapacityDeletionSelectorDataV1::Reservation(identifier) => {
                        identifier.ok_or(CapacityDataError::ProtectedBoundary)?
                    }
                };
                if record.key()
                    != reservation_key(identifier).as_slice()
                    || reservations.remove(&identifier).is_none()
                {
                    return Err(CapacityDataError::MalformedRecord(
                        "capacity settlement does not remove its exact reservation",
                    ));
                }
            }
        }
    }
    let (reserved_records, reserved_bytes, reserved_transactions) =
        reservations.values().try_fold(
            (0_usize, 0_u64, 0_usize),
            |(records, bytes, transactions), reservation| {
                Ok::<_, CapacityDataError>((
                    records
                        .checked_add(reservation.maximum_records)
                        .ok_or(CapacityDataError::LimitExceeded("reserved record count"))?,
                    bytes
                        .checked_add(reservation.maximum_bytes)
                        .ok_or(CapacityDataError::JournalTooLarge)?,
                    transactions
                        .checked_add(reservation.maximum_transactions)
                        .ok_or(CapacityDataError::LimitExceeded("reserved transaction count"))?,
                ))
            },
        )?;
    let projected_entries = materialized::projected_record_count(
        state, records.iter().map(RecordMutationRef::from),
    ).map_err(|cause| CapacityDataError::Transaction(JournalTransactionDataError::Frame(cause)))?;
    if prospective_materialized_bytes
        .checked_add(
            usize::try_from(reserved_bytes)
                .map_err(|_| CapacityDataError::LimitExceeded("reserved materialized bytes"))?,
        )
        .is_none_or(|bytes| bytes > limits.maximum_materialized_bytes)
        || projected_entries
            .checked_add(reserved_records)
            .is_none_or(|count| count > limits.maximum_materialized_records)
        || prospective_journal_bytes
            .checked_add(reserved_bytes)
            .is_none_or(|bytes| bytes > limits.maximum_journal_bytes)
        || prospective_transactions
            .checked_add(reserved_transactions)
            .is_none_or(|count| count > limits.maximum_transactions)
    {
        return Err(CapacityDataError::LimitExceeded(
            "outstanding global capacity reservations",
        ));
    }
    Ok(())
}
