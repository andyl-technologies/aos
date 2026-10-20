//! Shares complete legacy capacity record and settlement comparison DATA.
//!
//! Role-private methods keep their existing first-successor, Root, Controller,
//! original-payment and native append gates at their original frontiers. This
//! module neither claims a role nor constructs its accepted reservation type.

use aos_sandbox_core::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;
use aos_sandbox_protocol::domain_ledger::capacity::{
    GlobalCapacityReservationRequestV1, GlobalCapacityReservationRecoveryBindingV1,
    reservation_key, reservation_id, encode_reservation, decode_reservation,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::{
    CapacityDataError, validate_capacity_snapshot_data_v2,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::family::{
    CanonicalCapacityFamily, canonical_reservations,
};
use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalRecord, JournalTransaction, encoded_transaction_record_bytes,
};
use aos_sandbox_protocol::domain_ledger::JournalTransactionDataError;
use sha2::{Digest as _, Sha256};

/// Preserves the existing sole canonical capacity error DATA classifications.
pub use aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError
    as CapacityCustodyDataErrorV1;

/// Holds an unaccepted canonical reservation record for native preflight.
#[must_use]
pub struct PreparedCapacityRecordDataV1 {
    /// Original bounded request DATA.
    pub request: GlobalCapacityReservationRequestV1,
    /// Stable admission transaction coordinate.
    pub admission_transaction_id: [u8; 16],
    /// Derived deterministic record coordinate.
    pub reservation_id: [u8; 32],
    /// Exact canonical record which must join the admission transaction.
    pub record: JournalRecord,
}

/// Carries immutable retained record comparisons without settlement permission.
#[derive(Clone, Copy)]
pub struct RetainedCapacityRecordDataV1 {
    /// Original bounded request DATA.
    pub request: GlobalCapacityReservationRequestV1,
    /// Stable admission transaction coordinate.
    pub admission_transaction_id: [u8; 16],
    /// Canonical deterministic record coordinate.
    pub reservation_id: [u8; 32],
    /// Commitment to the complete existing canonical record bytes.
    pub record_digest: [u8; 32],
}

impl RetainedCapacityRecordDataV1 {
    /// Compares every field of the original bounded recovery recipe.
    #[must_use]
    pub fn matches_recovery_binding(
        &self,
        binding: &GlobalCapacityReservationRecoveryBindingV1,
    ) -> bool {
        self.request.purpose == binding.purpose
            && self.request.owner_namespace == binding.purpose.owner_namespace()
            && self.request.operation_id == binding.operation_id
            && self.request.artifact_digest == binding.artifact_digest
            && self.request.checkpoint_digest == binding.checkpoint_digest
            && self.request.chain_head_digest == binding.chain_head_digest
            && self.request.future_transactions == binding.future_transactions
            && self.request.terminal_records == binding.terminal_records
            && self.request.terminal_bytes == binding.terminal_bytes
            && self.request.poison_records == binding.poison_records
            && self.request.poison_bytes == binding.poison_bytes
    }
}

/// Borrows a decoded canonical record before the caller's actual purpose gate.
#[must_use]
pub struct DecodedCapacityRecordDataV1<'native> {
    /// Decoded request, without accepted role or settlement authority.
    pub request: GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    decoded_id: [u8; 32],
    expected_id: [u8; 32],
    value: &'native [u8],
}

impl DecodedCapacityRecordDataV1<'_> {
    /// Checks the original record provenance after the caller's purpose gate.
    ///
    /// # Errors
    /// Refuses either mismatched deterministic record identity.
    pub fn compare_provenance(self) -> Result<RetainedCapacityRecordDataV1, CapacityCustodyDataErrorV1> {
        if self.decoded_id != self.expected_id
            || reservation_id(&self.request, self.admission_transaction_id) != self.expected_id
        {
            return Err(CapacityDataError::MalformedRecord(
                "capacity reservation provenance is invalid",
            ).into());
        }
        Ok(RetainedCapacityRecordDataV1 {
            request: self.request,
            admission_transaction_id: self.admission_transaction_id,
            reservation_id: self.expected_id,
            record_digest: digest_bytes(self.value),
        })
    }
}

/// Builds the same canonical record after the role's request and purpose checks.
///
/// # Errors
/// Refuses a zero admission identity or an existing deterministic record key.
pub fn prepare_capacity_record_v1(
    view: HistoricalLedgerReadViewV1<'_>,
    request: GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
) -> Result<PreparedCapacityRecordDataV1, CapacityCustodyDataErrorV1> {
    if admission_transaction_id == [0; 16] {
        return Err(CapacityDataError::InvalidTransaction.into());
    }
    let reservation_id = reservation_id(&request, admission_transaction_id);
    let key = reservation_key(reservation_id);
    if view.materialized_state_v1()
        .contains_key(&(RecordNamespace::GlobalCapacityReservation, key.clone()))
    {
        return Err(CapacityDataError::Transaction(JournalTransactionDataError::DuplicateRecordKey).into());
    }
    let value = encode_reservation(&request, admission_transaction_id, reservation_id);
    Ok(PreparedCapacityRecordDataV1 {
        request,
        admission_transaction_id,
        reservation_id,
        record: JournalRecord::put(RecordNamespace::GlobalCapacityReservation, key, value),
    })
}

/// Decodes one actual retained record before the caller's closed purpose gate.
///
/// # Errors
/// Refuses malformed complete floor DATA or a nonlegacy selected record.
pub fn lookup_capacity_record_v1<'native>(
    view: HistoricalLedgerReadViewV1<'native>,
    expected_reservation_id: [u8; 32],
) -> Result<Option<DecodedCapacityRecordDataV1<'native>>, CapacityCustodyDataErrorV1> {
    validate_capacity_snapshot_data_v2(view.materialized_state_v1())?;
    let Some(value) = view.materialized_state_v1().get(&(
        RecordNamespace::GlobalCapacityReservation,
        reservation_key(expected_reservation_id),
    )) else {
        return Ok(None);
    };
    let (request, admission_transaction_id, decoded_id) =
        CanonicalCapacityFamily::decode(&reservation_key(expected_reservation_id), value)?
            .require_legacy()?;
    Ok(Some(DecodedCapacityRecordDataV1 {
        request,
        admission_transaction_id,
        decoded_id,
        expected_id: expected_reservation_id,
        value,
    }))
}

/// Selects the same unique immutable binding after the role's purpose gate.
///
/// # Errors
/// Refuses malformed floors, missing or ambiguous bindings, or missing bytes.
pub fn unique_capacity_record_v1(
    view: HistoricalLedgerReadViewV1<'_>,
    binding: &GlobalCapacityReservationRecoveryBindingV1,
) -> Result<RetainedCapacityRecordDataV1, CapacityCustodyDataErrorV1> {
    let families = canonical_reservations(view.materialized_state_v1())?;
    let mut matching = None;
    for family in families {
        let Some((request, admission_transaction_id, decoded_id)) = family.legacy() else {
            continue;
        };
        let value = view.materialized_state_v1()
            .get(&(
                RecordNamespace::GlobalCapacityReservation,
                reservation_key(decoded_id),
            ))
            .ok_or(CapacityDataError::MalformedRecord(
                "capacity reservation disappeared during selection",
            ))?;
        let reservation = RetainedCapacityRecordDataV1 {
            request,
            admission_transaction_id,
            reservation_id: decoded_id,
            record_digest: digest_bytes(value),
        };
        if !reservation.matches_recovery_binding(binding) {
            continue;
        }
        if matching.replace(reservation).is_some() {
            return Err(CapacityDataError::MalformedRecord(
                "capacity recovery binding is not unique",
            ).into());
        }
    }
    matching.ok_or_else(|| CapacityDataError::MalformedRecord(
        "capacity reservation is absent",
    ).into())
}

/// Keeps the original comparison allocation through the role's final gates.
///
/// It carries no success authority. Its retained borrowed Vec preserves the
/// old local cleanup frontier instead of dropping it before independent Root
/// or Controller settlement checks.
#[must_use]
pub struct CapacitySettlementComparisonDataV1<'transaction> {
    _reservation_records: Vec<&'transaction JournalRecord>,
}

/// Compares the same current record, deletion and full terminal byte bounds.
///
/// The role performs its first-successor/future-count checks before this call
/// and its real Controller/Root semantic gates afterwards, preserving order.
///
/// # Errors
/// Refuses absent/changed capacity, alternate deletion, or exhausted terminal
/// and poison envelopes. It does not settle or release the actual reservation.
pub fn compare_capacity_settlement_v1<'transaction>(
    view: HistoricalLedgerReadViewV1<'_>,
    reservation: RetainedCapacityRecordDataV1,
    transaction: &'transaction JournalTransaction,
) -> Result<CapacitySettlementComparisonDataV1<'transaction>, CapacityCustodyDataErrorV1> {
    let key = reservation_key(reservation.reservation_id);
    let current = view.materialized_state_v1()
        .get(&(RecordNamespace::GlobalCapacityReservation, key.clone()))
        .ok_or(CapacityDataError::MalformedRecord(
            "capacity reservation is absent",
        ))?;
    if digest_bytes(current) != reservation.record_digest
        || decode_reservation(current)?
            != (
                reservation.request,
                reservation.admission_transaction_id,
                reservation.reservation_id,
            )
    {
        return Err(CapacityDataError::MalformedRecord(
            "capacity reservation changed before settlement",
        ).into());
    }
    let reservation_records = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
        .collect::<Vec<_>>();
    if reservation_records
        != [&JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            key,
        )]
    {
        return Err(CapacityDataError::InvalidTransaction.into());
    }
    let encoded_bytes = encoded_transaction_record_bytes(transaction)?;
    let terminal_fits = transaction.records().len()
        <= usize::try_from(reservation.request.terminal_records)
            .map_err(|_| CapacityDataError::InvalidTransaction)?
        && encoded_bytes <= reservation.request.terminal_bytes;
    let poison_fits = transaction.records().len()
        <= usize::try_from(reservation.request.poison_records)
            .map_err(|_| CapacityDataError::InvalidTransaction)?
        && encoded_bytes <= reservation.request.poison_bytes;
    if !terminal_fits && !poison_fits {
        return Err(CapacityDataError::LimitExceeded(
            "capacity-reserved terminal transaction",
        ).into());
    }
    Ok(CapacitySettlementComparisonDataV1 { _reservation_records: reservation_records })
}

fn digest_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}
