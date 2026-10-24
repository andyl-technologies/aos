//! Shares canonical members and comparison recipes without effect authority.
//!
//! A decoded record and its phase remain DATA. Each real role privately owns
//! its complete snapshot/instance/currentness conjunction and accepted composite;
//! no constructor here recreates that conjunction or an effect permit.

use aos_sandbox_protocol::domain_ledger::{DomainLedgerDataError, JournalTransactionDataError};
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedDomainEnvelopeV1, ProtectedDomainKeyV1, ProtectedDomainSchemaV1,
    DomainPostcommitRecordDataV1, ProtectedRecordRoleV1, ProtectedReducerPhaseV1, decode_durable_member,
    reducer_phase, aggregate_semantic_phases, ENVELOPE_FIXED_BYTES, DURABLE_MEMBER_FIXED_BYTES,
};

/// Decodes the same ordered postcommit DATA after the real role's readback.
///
/// # Errors
/// Preserves member-count, value, namespace, canonical decoder and phase errors
/// in the original order. The caller privately supplies all actual role guards.
pub fn postcommit_records_v1<S: ProtectedDomainSchemaV1>(
    transaction: &JournalTransaction,
    roles: &[ProtectedRecordRoleV1],
    after: &[Vec<u8>],
    validator: &S::ReplayValidator,
) -> Result<Vec<DomainPostcommitRecordDataV1<S>>, DomainLedgerDataError> {
    if transaction.records().len() != roles.len()
        || transaction.records().len() != after.len()
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let mut records = Vec::new();
    for ((record, role), value) in transaction
        .records()
        .iter()
        .zip(roles)
        .zip(after)
    {
        if record.value() != Some(value.as_slice()) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let key = ProtectedDomainKeyV1::<S>::decode(record.key())?;
        if record.namespace() != S::namespace(key.kind()) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let durable = decode_durable_member::<S>(key, value, validator)?;
        let namespace = record.namespace();
        let role = *role;
        let phase = reducer_phase(durable.envelope())?;
        let (_, _, _, _, envelope, encoded) = durable.into_parts();
        let postcommit = DomainPostcommitRecordDataV1::from_comparison_parts(
            namespace, role, phase, ProtectedReducerPhaseV1::Observed, envelope, encoded,
        );
        records.push(postcommit);
    }
    let transaction_phase = aggregate_semantic_phases(
        &records
            .iter()
            .map(DomainPostcommitRecordDataV1::phase)
            .collect::<Vec<_>>(),
    );
    for record in &mut records {
        record.set_transaction_phase_comparison_v1(transaction_phase);
    }
    Ok(records)
}

/// Compares the same complete predecessor or successor image against native rows.
#[must_use]
pub fn values_match_v1(
    ledger: HistoricalLedgerReadViewV1<'_>,
    transaction: &JournalTransaction,
    before: &[Option<Vec<u8>>],
    successor: &[Vec<u8>],
    after: bool,
) -> bool {
    let records = transaction.records();
    if records.len() != before.len() || records.len() != successor.len() {
        return false;
    }
    records
        .iter()
        .zip(before.iter().zip(successor))
        .all(|(record, (before, after_value))| {
            let expected = if after {
                Some(after_value.as_slice())
            } else {
                before.as_deref()
            };
            ledger.get(record.namespace(), record.key()) == expected
        })
}

/// Derives the unchanged joined canonical byte recipe before planner copies.
///
/// # Errors
/// Refuses the original checked resident canonical payload byte overflow.
pub fn resident_plan_payload_bytes_v1<S: ProtectedDomainSchemaV1>(
    ledger: HistoricalLedgerReadViewV1<'_>,
    successors: &[ProtectedDomainEnvelopeV1<S>],
) -> Result<usize, JournalTransactionDataError> {
    successors.iter().try_fold(0_usize, |sum, successor| {
        let key = successor.key().as_bytes();
        let previous = ledger
            .get(S::namespace(successor.key().kind()), key)
            .map_or(0, <[u8]>::len);
        let bytes = resident_plan_member_payload_bytes_for_lengths_v1(
            successor.payload().len(), key.len(), successor.key().identity().len(), previous,
        )?;
        sum.checked_add(bytes)
            .ok_or(JournalTransactionDataError::LimitExceeded("resident canonical payload bytes"))
    })
}

/// Prices the sole canonical planner copy recipe from pre-encoder widths.
///
/// Widths are nonauthorizing DATA; the actual planner still decodes every
/// predecessor and validates the real ordered successor set before mutation.
///
/// # Errors
/// Returns the same checked resident canonical payload overflow.
pub fn resident_plan_member_payload_bytes_for_lengths_v1(
    payload_bytes: usize, key_bytes: usize, identity_bytes: usize, previous_bytes: usize,
) -> Result<usize, JournalTransactionDataError> {
    // Prepared: two new durable values + one old value + one key.
    // Postcommit: one encoded value + decoded payload + one key.
    payload_bytes.checked_add(ENVELOPE_FIXED_BYTES)
        .and_then(|bytes| bytes.checked_add(DURABLE_MEMBER_FIXED_BYTES))
        .and_then(|bytes| bytes.checked_mul(3))
        .and_then(|bytes| bytes.checked_add(previous_bytes))
        .and_then(|bytes| bytes.checked_add(payload_bytes))
        .and_then(|bytes| key_bytes.checked_mul(2).and_then(|keys| bytes.checked_add(keys)))
        .and_then(|bytes| bytes.checked_add(identity_bytes))
        .ok_or(JournalTransactionDataError::LimitExceeded("resident canonical payload bytes"))
}
