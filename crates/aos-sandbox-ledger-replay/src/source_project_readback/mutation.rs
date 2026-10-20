//! Compares the actual Source project-admission transition DATA.
//!
//! The canonical full-row decoder runs before every transition comparison.
//! These selectors accept no native original and create no reservation, grant,
//! retirement proof or currentness. Actual Source/Root/Controller owners retain
//! their independent native admission, signing, commit and final crossings.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_core::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::source_project_history::{
    SourceProjectAdmissionChallengeV1, SourceProjectAdmissionReservationV1,
    SourceProjectAdmissionSettlementV1, SourceProjectReservationCancellationV1,
    SourceProjectTerminalRetirementAckV1,
};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use std::collections::BTreeMap;

use super::{current_rows, CANCELLATION_KEY, KEY, RESERVATION_KEY,
            RETIREMENT_ACK_KEY, SETTLEMENT_KEY};

/// Selects a pure saved-row comparison, never a native append permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceProjectAdmissionTransition {
    /// Selects the ordinary deny-only comparison, without a native loan.
    None,
    /// Compares the next saved reservation and exact prior-row deletion.
    Reserve,
    /// Compares the exact saved reservation and challenge fields.
    Acquire,
    /// Compares a settlement with the saved challenge.
    Settle,
    /// Compares cancellation against the saved reservation.
    CancelReservation,
    /// Compares the exact saved terminal retirement association.
    AcknowledgeRetirement,
}

/// Compares the exact saved rows and proposed transition in their original order.
///
/// # Errors
/// Refuses malformed joined history, an outstanding ordinary reservation,
/// protected-key mutation, or any mismatched selected transition DATA.
pub fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: SourceProjectAdmissionTransition,
) -> Result<(), JournalError> {
    let rows = current_rows(state)?;
    let reservation = rows.reservation();
    let cancellation = rows.cancellation();
    let challenge = rows.challenge();
    let settlement = rows.settlement();
    let retirement_ack = rows.retirement_ack();
    let records = transaction.records();
    match transition {
        SourceProjectAdmissionTransition::None => {
            crate::ordinary_mutation::require_no_project_admission_mutation_v1(
                &rows, transaction,
            ).map_err(JournalError::from)?;
        }
        SourceProjectAdmissionTransition::Reserve => {
            let [record, rest @ ..] = records else {
                return Err(JournalError::ProtectedBoundary);
            };
            if record.namespace() != RecordNamespace::DesiredState
                || record.key() != RESERVATION_KEY
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let next = record
                .value()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(|bytes| {
                    SourceProjectAdmissionReservationV1::decode(bytes).map_err(JournalError::from)
                })?;
            match (reservation, challenge, settlement, rest) {
                (None, None, None, []) if next.issue() == 1 && retirement_ack.is_none() => {}
                (
                    Some(previous),
                    Some(_),
                    Some(_),
                    [delete_challenge, delete_settlement, delete_ack],
                ) if retirement_ack.is_some()
                    && next.issue()
                        == previous
                            .issue()
                            .checked_add(1)
                            .ok_or(JournalError::ProtectedBoundary)?
                    && delete_challenge.namespace() == RecordNamespace::DesiredState
                    && delete_challenge.key() == KEY
                    && delete_challenge.value().is_none()
                    && delete_settlement.namespace() == RecordNamespace::DesiredState
                    && delete_settlement.key() == SETTLEMENT_KEY
                    && delete_settlement.value().is_none()
                    && is_ack_delete(delete_ack) => {}
                (Some(previous), None, None, [delete_cancellation, delete_ack])
                    if cancellation.is_some()
                        && retirement_ack.is_some()
                        && next.issue()
                            == previous
                                .issue()
                                .checked_add(1)
                                .ok_or(JournalError::ProtectedBoundary)?
                        && delete_cancellation.namespace() == RecordNamespace::DesiredState
                        && delete_cancellation.key() == CANCELLATION_KEY
                        && delete_cancellation.value().is_none()
                        && is_ack_delete(delete_ack) => {}
                _ => return Err(JournalError::ProtectedBoundary),
            }
        }
        SourceProjectAdmissionTransition::Acquire => {
            let [record, rest @ ..] = records else {
                return Err(JournalError::ProtectedBoundary);
            };
            if record.namespace() != RecordNamespace::DesiredState || record.key() != KEY {
                return Err(JournalError::ProtectedBoundary);
            }
            let next = record
                .value()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(|bytes| {
                    SourceProjectAdmissionChallengeV1::decode(bytes).map_err(JournalError::from)
                })?;
            if !rest.is_empty()
                || challenge.is_some()
                || settlement.is_some()
                || cancellation.is_some()
                || retirement_ack.is_some()
                || !reservation.is_some_and(|reserved| {
                    next.issue() == reserved.issue()
                        && next.project() == reserved.project()
                        && next.names() == reserved.names()
                })
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        SourceProjectAdmissionTransition::Settle => {
            let [record] = records else {
                return Err(JournalError::ProtectedBoundary);
            };
            let row = record
                .value()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(|bytes| {
                    SourceProjectAdmissionSettlementV1::decode(bytes).map_err(JournalError::from)
                })?;
            if record.namespace() != RecordNamespace::DesiredState
                || record.key() != SETTLEMENT_KEY
                || settlement.is_some()
                || cancellation.is_some()
                || retirement_ack.is_some()
                || !challenge.is_some_and(|challenge| row.matches(challenge))
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        SourceProjectAdmissionTransition::CancelReservation => {
            let [record] = records else {
                return Err(JournalError::ProtectedBoundary);
            };
            let row = record
                .value()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(|bytes| {
                    SourceProjectReservationCancellationV1::decode(bytes)
                        .map_err(JournalError::from)
                })?;
            if record.namespace() != RecordNamespace::DesiredState
                || record.key() != CANCELLATION_KEY
                || challenge.is_some()
                || settlement.is_some()
                || cancellation.is_some()
                || retirement_ack.is_some()
                || !reservation.is_some_and(|reservation| {
                    row.issue() == reservation.issue()
                        && row.reservation() == reservation.record_digest()
                })
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        SourceProjectAdmissionTransition::AcknowledgeRetirement => {
            let [record] = records else {
                return Err(JournalError::ProtectedBoundary);
            };
            let row = record
                .value()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(|bytes| {
                    SourceProjectTerminalRetirementAckV1::decode(bytes).map_err(JournalError::from)
                })?;
            let rows = current_rows(state)?;
            let terminal = rows.terminal().ok_or(JournalError::ProtectedBoundary)?;
            if record.namespace() != RecordNamespace::DesiredState
                || record.key() != RETIREMENT_ACK_KEY
                || retirement_ack.is_some()
                || row.issue() != terminal.reservation().issue()
                || row.reservation() != terminal.reservation().record_digest()
                || row.source_terminal() != terminal.source_terminal_digest()
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
    }
    Ok(())
}

/// Refuses compaction while the actual saved reservation remains unretired.
///
/// # Errors
/// Refuses malformed full-row history or a reservation without its retirement ACK.
pub fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    let rows = current_rows(state)?;
    if rows.reservation().is_some() && rows.retirement_ack().is_none() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn is_ack_delete(record: &JournalRecord) -> bool {
    record.namespace() == RecordNamespace::DesiredState
        && record.key() == RETIREMENT_ACK_KEY
        && record.value().is_none()
}

