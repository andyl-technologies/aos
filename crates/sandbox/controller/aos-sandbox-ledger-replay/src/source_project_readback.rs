//! Shares the sole saved Source project-admission row lookup and join.
//!
//! Protocol owns all five row codecs. This module invokes them in the original
//! lookup order on borrowed historical state; it performs no IO, observes no
//! current owner and creates no admission, cancellation or retirement proof.

use std::collections::BTreeMap;
use aos_sandbox_model::{ObjectDigest, ProjectId, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_protocol::domain_ledger::source_project_history::SourceProjectAdmissionChallengeKindV1;
use aos_sandbox_protocol::domain_ledger::{ProtectedHistoryDataErrorV1,
    source_project_history::{SourceProjectAdmissionHistoryV1, SourceProjectAdmissionChallengeV1,
        SourceProjectAdmissionReservationV1, SourceProjectReservationCancellationV1,
        SourceProjectAdmissionSettlementV1, SourceProjectTerminalRetirementAckV1}};

/// Names the established saved key row.
pub const KEY: &[u8] = b"\0aos-source-project-admission-challenge-v1\0";
/// Names the established saved reservation key row.
pub const RESERVATION_KEY: &[u8] = b"\0aos-source-project-admission-reservation-v1\0";
/// Names the established saved cancellation key row.
pub const CANCELLATION_KEY: &[u8] = b"\0aos-source-project-reservation-cancellation-v1\0";
/// Names the established saved retirement ack key row.
pub const RETIREMENT_ACK_KEY: &[u8] = b"\0aos-source-project-terminal-retirement-ack-v1\0";
/// Names the established saved settlement key row.
pub const SETTLEMENT_KEY: &[u8] = b"\0aos-source-project-admission-settlement-v1\0";

/// Decodes only the actual saved reservation row.
///
/// # Errors
/// Refuses the original row framing, checksum or complete historical join.
pub fn current_reservation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<SourceProjectAdmissionReservationV1>, ProtectedHistoryDataErrorV1> {
    state
        .get(&(RecordNamespace::DesiredState, RESERVATION_KEY.to_vec()))
        .map(|bytes| SourceProjectAdmissionReservationV1::decode(bytes))
        .transpose()
}

/// Decodes only the actual saved cancellation row.
///
/// # Errors
/// Refuses the original row framing, checksum or complete historical join.
pub fn current_cancellation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<SourceProjectReservationCancellationV1>, ProtectedHistoryDataErrorV1> {
    state
        .get(&(RecordNamespace::DesiredState, CANCELLATION_KEY.to_vec()))
        .map(|bytes| {
            SourceProjectReservationCancellationV1::decode(bytes)
        })
        .transpose()
}

/// Decodes and rejoins the existing five-row project-admission history.
///
/// # Errors
/// Refuses the original row framing, checksum or complete historical join.
pub fn current_rows(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<SourceProjectAdmissionHistoryV1, ProtectedHistoryDataErrorV1> {
    let challenge = state
        .get(&(RecordNamespace::DesiredState, KEY.to_vec()))
        .map(|bytes| SourceProjectAdmissionChallengeV1::decode(bytes))
        .transpose()?;
    let settlement = state
        .get(&(RecordNamespace::DesiredState, SETTLEMENT_KEY.to_vec()))
        .map(|bytes| SourceProjectAdmissionSettlementV1::decode(bytes))
        .transpose()?;
    let reservation = current_reservation(state)?;
    let cancellation = current_cancellation(state)?;
    let retirement_ack = state
        .get(&(RecordNamespace::DesiredState, RETIREMENT_ACK_KEY.to_vec()))
        .map(|bytes| {
            SourceProjectTerminalRetirementAckV1::decode(bytes)
        })
        .transpose()?;
    let rows = SourceProjectAdmissionHistoryV1::from_historical_fields(
        reservation,
        cancellation,
        challenge,
        settlement,
        retirement_ack,
    );
    rows.require_joined()?;
    Ok(rows)
}

/// Compares the established project challenge fields as historical DATA only.
pub fn challenge_matches_current_v1(
    row: SourceProjectAdmissionChallengeV1,
    nonce: [u8; 16],
    cut: ObjectDigest,
    project: ProjectId,
    ancestry: ObjectDigest,
    stage: ObjectDigest,
    names: ProtectedJournalNamesV1,
) -> bool {
    row.kind() == SourceProjectAdmissionChallengeKindV1::Admission
        && row.nonce() == nonce
        && row.cut() == cut
        && row.project() == project
        && row.ancestry() == ancestry
        && row.stage() == stage
        && row.names() == names
}

mod mutation;
pub use mutation::{SourceProjectAdmissionTransition, require_no_mutation, require_no_compaction};
