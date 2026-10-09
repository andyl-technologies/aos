//! Bounded historical Root floor for one completely joined admission issue.
//!
//! The row is historical, not a current project-policy or Create receipt. A
//! decoder cannot authorize its append. The Root writer must separately join
//! the Controller's protected original-Effect acceptance with the Source-only
//! terminal readback before deleting the exact covered terminal artifacts.
//!
//! ```text
//! AOSQPF01 | version:u16=1 | terminal-kind:u8 | reserved[5]=0 | issue:u64 |
//! reservation:32 | challenge:32 or zero | Source-terminal:32 |
//! Root-terminal:32 | Controller-acceptance:32 | Source-pinned-key:32 |
//! original-operation:16 | original-sandbox:16 | project:16 |
//! original-source-commitment:32 | client-nonce:16 | Source-fixed-names[48] |
//! SHA-256(Root-history-floor-domain || preceding 360 bytes):32
//! ```

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    GlobalCapacityReservationRequestV1, Journal, JournalError, JournalTransaction,
    RecordNamespace,
};

use super::super::controller_project_terminal_readback::verify_controller_project_terminal_readback_v1;
use super::super::{
    PinnedControllerHoldSignerV1, PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackChallengeV1,
    verify_source_project_completed_terminal_readback_v1,
};
pub use aos_sandbox_protocol::domain_ledger::root_project_history::{
    RootProjectHistoryFloorV1, RootProjectHistoryTerminalKindV1,
};
pub(crate) use aos_sandbox_protocol::domain_ledger::root_project_history::ROOT_PROJECT_HISTORY_FLOOR_BYTES_V1;

use super::{
    PolicyDeploymentHeadErrorV1, RootProjectAdmissionOutcomeKindV1, RootProjectAdmissionOutcomeV1,
    RootProjectAdmissionStageV1, RootProjectReservationCancellationV1, STAGE_KEY, digest, intent,
    outcome_key, reservation_cancellation_key, zero_digest,
};

pub(super) const KEY: &[u8] = b"\0aos-policy-project-history-floor-v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-project-history-retirement-cut.v1\0";
#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;

/// Retires only the exact Root history accepted by both protected owners.
///
/// The two signed packets are untrusted input. Root reads its immutable role
/// pins independently, joins the actual retained terminal and reservation, and
/// atomically replaces covered history with one monotonically issued floor.
/// Current deployment/project expiry does not invalidate this historical cut.
///
/// # Errors
///
/// Rejects changed pins, original Create identity, owner evidence, fixed names,
/// issue, terminal class, missing suffix capacity, foreign orphan history, or
/// ambiguous durable append/readback. Below-floor and equal-but-changed cuts
/// fail closed; an exact lost-reply replay does not append another floor.
pub fn retire_fixed_root_project_history_v1(
    controller_packet: &[u8],
    source_packet: &[u8],
    controller_uid: u32,
) -> Result<RootProjectHistoryFloorV1, PolicyDeploymentHeadErrorV1> {
    let mut journal = super::open_fixed_root_project_journal()?;
    retire_root_project_history_with_journal(
        &mut journal,
        controller_packet,
        source_packet,
        controller_uid,
    )
}

pub(super) fn retire_root_project_history_with_journal(
    journal: &mut Journal,
    controller_packet: &[u8],
    source_packet: &[u8],
    controller_uid: u32,
) -> Result<RootProjectHistoryFloorV1, PolicyDeploymentHeadErrorV1> {
    let current = intent::current_intent(journal)?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let prior = authority
        .get(KEY)?
        .map(RootProjectHistoryFloorV1::from_record_bytes)
        .transpose()?;
    let controller_pin = authority
        .get(super::CONTROLLER_HOLD_PIN_KEY)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let source_pin = authority
        .get(super::SOURCE_HOLD_PIN_KEY)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let controller_signer = PinnedControllerHoldSignerV1::decode(controller_pin)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let source_signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let controller = verify_controller_project_terminal_readback_v1(
        controller_packet,
        &controller_signer,
        controller_uid,
    )
    .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let challenge =
        SourceHoldReadbackChallengeV1::new(controller.client_nonce, controller.root_terminal)
            .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)?;
    let source = verify_source_project_completed_terminal_readback_v1(
        source_packet,
        &source_signer,
        challenge,
    )
    .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let reservation = source.reservation();
    if controller.reservation != reservation.record_digest()
        || controller.issue != reservation.issue()
        || controller.project != reservation.project()
        || controller.names != source.names()
        || controller.client_nonce != reservation.client_nonce()
        || super::project_admission_client_nonce_v1(
            controller.operation,
            controller.source_commitment,
        ) != controller.client_nonce
        || controller.root_terminal != source.root_terminal_digest()
        || controller.challenge
            != source
                .challenge()
                .map(|row| row.record_digest())
                .unwrap_or_else(zero_digest)
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let floor = RootProjectHistoryFloorV1::from_historical_fields(
        controller.kind,
        reservation.issue(),
        reservation.record_digest(),
        controller.challenge,
        source.source_terminal_digest(),
        controller.root_terminal,
        controller.accepted_metadata,
        digest(source_pin),
        *controller.operation.as_bytes(),
        *controller.sandbox.as_bytes(),
        controller.project,
        controller.source_commitment,
        controller.client_nonce,
        source.names(),
    );
    RootProjectHistoryFloorV1::from_record_bytes(&floor.record_bytes())?;
    if let Some(prior) = prior {
        if prior.issue() >= floor.issue() {
            return if prior == floor {
                Ok(prior)
            } else {
                Err(PolicyDeploymentHeadErrorV1::StaleHead)
            };
        }
    }
    let current = current.ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    if !current.retains_history()
        || current.decision() != floor.root_terminal_digest()
        || current.source_reservation() != floor.reservation_digest()
        || current.client_nonce() != floor.client_nonce()
        || current.project() != floor.project()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let covered = match floor.kind() {
        RootProjectHistoryTerminalKindV1::CanceledReservation => {
            vec![reservation_cancellation_key(floor.reservation_digest())]
        }
        RootProjectHistoryTerminalKindV1::Committed | RootProjectHistoryTerminalKindV1::Aborted => {
            let stage = authority
                .get(STAGE_KEY)?
                .map(RootProjectAdmissionStageV1::from_record_bytes)
                .transpose()?
                .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
            vec![STAGE_KEY.to_vec(), outcome_key(stage.record_digest())]
        }
    };
    // No horizon exists for an unmatched historical orphan. A floor cannot
    // cover it by inference merely because a higher Source issue was signed.
    for (key, _) in authority.records()? {
        if (key.starts_with(super::OUTCOME_PREFIX)
            || key.starts_with(super::RESERVATION_CANCELLATION_PREFIX)
            || key == STAGE_KEY)
            && !covered.iter().any(|covered| covered.as_slice() == key)
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
    }
    drop(authority);
    intent::require_intent_capacity(journal, current)?;
    let reservation = journal.recover_global_capacity_reservation_v1(current.capacity_id())?;
    let mut records = vec![
        crate::journal::JournalRecord::put(
            RecordNamespace::DesiredState,
            KEY.to_vec(),
            floor.record_bytes().to_vec(),
        ),
        crate::journal::JournalRecord::delete(RecordNamespace::DesiredState, intent::KEY.to_vec()),
    ];
    records.extend(
        covered
            .into_iter()
            .map(|key| crate::journal::JournalRecord::delete(RecordNamespace::DesiredState, key)),
    );
    records.push(reservation.settlement_record());
    let transaction_digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(floor.record_bytes())
        .finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&transaction_digest[..16]);
    let transaction = JournalTransaction::new(id, records)?;
    let mut capacity = journal.claim_global_capacity_reservation_authority(
        crate::journal::GlobalCapacityReservationPurposeV1::RootProjectAdmission,
    )?;
    let preflight = capacity.preflight_reserved_terminal_v1(&reservation, &transaction)?;
    capacity.commit_reserved_terminal_v1(&preflight, reservation, &transaction)?;
    drop(capacity);
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(KEY)? != Some(floor.record_bytes().as_slice())
        || authority.get(intent::KEY)?.is_some()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(floor)
}

/// Replays only the exact bounded floor for a requested historical Source row.
///
/// # Errors
///
/// Rejects unsafe Root custody or malformed retained history. Another issue is
/// absent for this request, not authenticated absence of any Root outcome.
pub fn recover_fixed_root_project_history_floor_v1(
    reservation: crate::journal::SourceProjectAdmissionReservationV1,
) -> Result<Option<RootProjectHistoryFloorV1>, PolicyDeploymentHeadErrorV1> {
    let mut journal = super::open_fixed_root_project_journal()?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let floor = authority
        .get(KEY)?
        .map(RootProjectHistoryFloorV1::from_record_bytes)
        .transpose()?;
    let Some(floor) = floor else {
        return Ok(None);
    };
    if authority.get(super::SOURCE_HOLD_PIN_KEY)?.map(digest) != Some(floor.source_pin_digest()) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    if floor.issue() < reservation.issue() {
        return Ok(None);
    }
    if floor.issue() != reservation.issue()
        || floor.reservation_digest() != reservation.record_digest()
        || floor.project() != reservation.project()
        || floor.client_nonce() != reservation.client_nonce()
        || floor.names() != reservation.names()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(Some(floor))
}

/// Reports retained historical replay availability, not positive readiness.
///
/// # Errors
///
/// Rejects unsafe Root custody, malformed floor, or changed historical pin.
pub fn fixed_root_project_history_readback_available_v1()
-> Result<bool, PolicyDeploymentHeadErrorV1> {
    let mut journal = super::open_fixed_root_project_journal()?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let Some(floor) = authority
        .get(KEY)?
        .map(RootProjectHistoryFloorV1::from_record_bytes)
        .transpose()?
    else {
        return Ok(false);
    };
    if authority.get(super::SOURCE_HOLD_PIN_KEY)?.map(digest) != Some(floor.source_pin_digest()) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(true)
}

pub(super) fn require_successor_source_issue(
    authority: &crate::journal::ProtectedJournalAuthority<'_>,
    reservation: crate::journal::SourceProjectAdmissionReservationV1,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    match authority
        .get(KEY)?
        .map(RootProjectHistoryFloorV1::from_record_bytes)
        .transpose()?
    {
        Some(floor)
            if floor.issue().checked_add(1) == Some(reservation.issue())
                && authority.get(super::SOURCE_HOLD_PIN_KEY)?.map(digest)
                    == Some(floor.source_pin_digest()) =>
        {
            Ok(())
        }
        None if reservation.issue() == 1 => Ok(()),
        _ => Err(PolicyDeploymentHeadErrorV1::StaleHead),
    }
}

/// Checks only exact retirement geometry; authenticated joins precede this cut.
pub(crate) fn validate_capacity_settlement(
    journal: &Journal,
    transaction: &JournalTransaction,
    request: &GlobalCapacityReservationRequestV1,
    capacity: [u8; 32],
) -> Result<(), JournalError> {
    let check = || -> Result<(), PolicyDeploymentHeadErrorV1> {
        let Some(current) = intent::current_intent_readback(journal)? else {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        };
        if !current.retains_history() {
            // Legacy intents retain their original terminal API. They do not
            // gain a history floor merely by being decoded alongside V2.
            return Ok(());
        }
        if current.capacity_id() != capacity || current.capacity_request() != *request {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        if current.decision() == zero_digest() {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        let retained = journal.recover_global_capacity_reservation_v1(capacity)?;
        if retained.request() != *request {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        let records = transaction
            .records()
            .iter()
            .filter(|record| record.namespace() == RecordNamespace::DesiredState)
            .collect::<Vec<_>>();
        let [floor_record, delete_intent, deletion @ ..] = records.as_slice() else {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        };
        let floor = RootProjectHistoryFloorV1::from_record_bytes(
            floor_record
                .value()
                .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?,
        )?;
        if floor_record.key() != KEY
            || delete_intent.key() != intent::KEY
            || delete_intent.value().is_some()
            || floor.root_terminal_digest() != current.decision()
            || floor.reservation_digest() != current.source_reservation()
            || floor.project() != current.project()
            || floor.client_nonce() != current.client_nonce()
            || transaction.records().len() != records.len() + 1
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        match journal
            .get(RecordNamespace::DesiredState, KEY)
            .map(RootProjectHistoryFloorV1::from_record_bytes)
            .transpose()?
        {
            Some(prior)
                if prior.issue().checked_add(1) == Some(floor.issue())
                    && prior.source_pin_digest() == floor.source_pin_digest() => {}
            None if floor.issue() == 1 => {}
            _ => return Err(PolicyDeploymentHeadErrorV1::StaleHead),
        }
        if journal
            .get(RecordNamespace::DesiredState, super::SOURCE_HOLD_PIN_KEY)
            .map(digest)
            != Some(floor.source_pin_digest())
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        match (floor.kind(), deletion) {
            (RootProjectHistoryTerminalKindV1::CanceledReservation, [delete_marker]) => {
                let key = reservation_cancellation_key(floor.reservation_digest());
                let marker = journal
                    .get(RecordNamespace::DesiredState, &key)
                    .map(RootProjectReservationCancellationV1::from_record_bytes)
                    .transpose()?
                    .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
                if delete_marker.key() != key
                    || delete_marker.value().is_some()
                    || marker.record_digest() != floor.root_terminal_digest()
                {
                    return Err(PolicyDeploymentHeadErrorV1::StaleHead);
                }
            }
            (
                RootProjectHistoryTerminalKindV1::Committed
                | RootProjectHistoryTerminalKindV1::Aborted,
                [delete_stage, delete_outcome],
            ) => {
                let stage = journal
                    .get(RecordNamespace::DesiredState, STAGE_KEY)
                    .map(RootProjectAdmissionStageV1::from_record_bytes)
                    .transpose()?
                    .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
                let key = outcome_key(stage.record_digest());
                let outcome = journal
                    .get(RecordNamespace::DesiredState, &key)
                    .map(RootProjectAdmissionOutcomeV1::from_record_bytes)
                    .transpose()?
                    .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
                if delete_stage.key() != STAGE_KEY
                    || delete_stage.value().is_some()
                    || delete_outcome.key() != key
                    || delete_outcome.value().is_some()
                    || stage.source_reservation_digest() != floor.reservation_digest()
                    || outcome.record_digest() != floor.root_terminal_digest()
                    || outcome.source_row() != floor.challenge_digest()
                    || (outcome.kind() == RootProjectAdmissionOutcomeKindV1::Committed)
                        != (floor.kind() == RootProjectHistoryTerminalKindV1::Committed)
                    || (outcome.kind() == RootProjectAdmissionOutcomeKindV1::Committed
                        && (outcome.operation() != floor.operation()
                            || outcome.sandbox() != floor.sandbox()
                            || outcome.source_commitment() != floor.source_commitment()))
                {
                    return Err(PolicyDeploymentHeadErrorV1::StaleHead);
                }
            }
            _ => return Err(PolicyDeploymentHeadErrorV1::StaleHead),
        }
        Ok(())
    };
    check().map_err(|_| JournalError::AuthorityPreflightMismatch)
}
