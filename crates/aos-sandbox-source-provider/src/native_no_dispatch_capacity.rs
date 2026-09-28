//! Durable terminal headroom for both protected native reservation owners.
//!
//! Namespace 46 reserves one bounded five-record terminal append in the same
//! transaction that creates the proofless Applying row. Cold replay requires
//! one matching reservation for each such row and no orphan reservations.
//! The distinct dispatch owner retains a larger reservation across Requested,
//! Prepared and Active; it is not the no-dispatch owner's five-record budget.

use std::collections::BTreeSet;

use aos_sandbox::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1, JournalTransaction, ProtectedJournalAuthority,
    RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::ProviderLedgerError;
use crate::acquire::is_native_no_dispatch_acquisition;
use crate::format::{encode_acquisition, record_digest};
use crate::limits::MAXIMUM_ACQUIRE_COMPLETION_BYTES;
use crate::model::{
    AcquisitionRecordV1, AttemptRecordV1, HolderSessionHeadRecordV1, ProviderAcquisitionStateV1,
    ProviderAttemptStateV1, RecoveredProviderLedgerV1,
};
use crate::native_completion::is_native_dispatch_acquisition;
use crate::state::ProviderLedgerV1;
use crate::transaction::prepare_mutations_validated;

const PURPOSE: GlobalCapacityReservationPurposeV1 =
    GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal;
const TERMINAL_RECORDS: u32 = 5;
const TERMINAL_BYTES: u64 = MAXIMUM_ACQUIRE_COMPLETION_BYTES as u64;
const OWNER_DOMAIN: &[u8] = b"aos.sandbox.source-provider.native-capacity-owner.v1\0";
const DISPATCH_OWNER_DOMAIN: &[u8] =
    b"aos.sandbox.source-provider.native-dispatch-capacity-owner.v2\0";
const DISPATCH_TERMINAL_RECORDS: u32 = 7;
// Six namespace-41 owner rows and the exact namespace-46 deletion. Journal
// framing is 72 bytes per record plus Begin/Commit frames and 40 payload bytes.
// The shared carrier bound includes mandatory body-7 clock bytes. An older,
// smaller private dispatch floor fails exact recovery; it is never upgraded.
const DISPATCH_TERMINAL_BYTES: u64 =
    aos_sandbox_source_provider_ledger::ledger::format::MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2
        as u64
        + 7 + 72
        + 72 * (DISPATCH_TERMINAL_RECORDS as u64 + 2) + 40;

fn request(
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
    session: &HolderSessionHeadRecordV1,
    native: Option<&crate::ledger::native_completion::NativeAcquireCompletionRecordV2>,
) -> Result<GlobalCapacityReservationRequestV1, ProviderLedgerError> {
    let dispatch = is_native_dispatch_acquisition(acquisition);
    let phase_matches = if dispatch && native.is_some() {
        native.is_some_and(|record| {
            record.canonical_request.is_some()
                && record.validate_provider_graph(attempt, acquisition).is_ok()
        })
    } else {
        acquisition.state == ProviderAcquisitionStateV1::Applying
            && attempt.state == ProviderAttemptStateV1::Reserved
            && session.pending_attempt_digest == Some(attempt.attempt_digest)
    };
    if !phase_matches
        || (!is_native_no_dispatch_acquisition(acquisition) && !dispatch)
        || acquisition.current_attempt_digest != attempt.attempt_digest
        || acquisition.effect_attempt_digest != attempt.attempt_digest
        || session.session_binding != attempt.session_binding
        || acquisition.provider != attempt.provider
        || acquisition.holder != attempt.holder
        || session.provider != attempt.provider
        || session.holder != attempt.holder
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let mut owner = Sha256::new();
    owner.update(if dispatch {
        DISPATCH_OWNER_DOMAIN
    } else {
        OWNER_DOMAIN
    });
    owner.update(acquisition.provider.authority_id());
    owner.update(acquisition.holder.authority_id());
    owner.update(acquisition.acquisition_id.as_bytes());

    let owner_digest = match native {
        Some(record) if dispatch => {
            record
                .reservation_acquisition_digest
                .ok_or(ProviderLedgerError::Corrupt(
                    "native original capacity digest",
                ))?
        }
        _ => record_digest(&encode_acquisition(acquisition))?,
    };
    let (terminal_records, terminal_bytes) = if dispatch {
        (DISPATCH_TERMINAL_RECORDS, DISPATCH_TERMINAL_BYTES)
    } else {
        (TERMINAL_RECORDS, TERMINAL_BYTES)
    };
    Ok(GlobalCapacityReservationRequestV1 {
        purpose: PURPOSE,
        owner_namespace: RecordNamespace::SourceProviderAuthority,
        owner_id: owner.finalize().into(),
        owner_digest: *owner_digest.as_bytes(),
        operation_id: acquisition.effect_id,
        artifact_digest: *attempt.attempt_digest.as_bytes(),
        checkpoint_digest: *attempt.signed_request_digest.as_bytes(),
        chain_head_digest: *session.session_binding.as_bytes(),
        terminal_records,
        terminal_bytes,
        poison_records: terminal_records,
        poison_bytes: terminal_bytes,
    })
}

fn binding(
    request: GlobalCapacityReservationRequestV1,
) -> GlobalCapacityReservationRecoveryBindingV1 {
    GlobalCapacityReservationRecoveryBindingV1 {
        purpose: request.purpose,
        operation_id: request.operation_id,
        artifact_digest: request.artifact_digest,
        checkpoint_digest: request.checkpoint_digest,
        chain_head_digest: request.chain_head_digest,
        terminal_records: request.terminal_records,
        terminal_bytes: request.terminal_bytes,
        poison_records: request.poison_records,
        poison_bytes: request.poison_bytes,
    }
}

fn exact_reservation(
    journal: &ProtectedJournalAuthority<'_>,
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
    session: &HolderSessionHeadRecordV1,
    native: Option<&crate::ledger::native_completion::NativeAcquireCompletionRecordV2>,
) -> Result<aos_sandbox::GlobalCapacityReservationV1, ProviderLedgerError> {
    let expected = request(acquisition, attempt, session, native)?;
    let reservation = journal.recover_unique_global_capacity_reservation_v1(&binding(expected))?;
    if reservation.request() != expected {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(reservation)
}

fn validate_committed_graph(ledger: &mut ProviderLedgerV1<'_>) -> Result<(), ProviderLedgerError> {
    let result = crate::recovery::recover(&ledger.journal, &ledger.configuration)
        .and_then(|replay| validate_set(&ledger.journal, &replay));
    if let Err(error) = result {
        ledger.poison_runtime();
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_completion/capacity_tests.rs"]
mod native_capacity_tests;

/// Validates the exact union of both native owners and rejects orphan capacity.
pub(crate) fn validate_set(
    journal: &ProtectedJournalAuthority<'_>,
    recovered: &RecoveredProviderLedgerV1,
) -> Result<(), ProviderLedgerError> {
    let mut expected = BTreeSet::new();
    for acquisition in recovered.acquisitions.values().filter(|record| {
        (record.state == ProviderAcquisitionStateV1::Applying
            && is_native_no_dispatch_acquisition(record))
            || (is_native_dispatch_acquisition(record)
                && recovered.native_completions.get(&record.acquisition_id).is_none_or(|native| {
                    native.state != crate::ledger::native_completion::NativeAcquireCompletionStateV2::CleanupRequired
                }))
    }) {
        let attempt = recovered
            .attempts
            .values()
            .find(|record| record.attempt_digest == acquisition.current_attempt_digest)
            .ok_or(ProviderLedgerError::Corrupt("native capacity attempt"))?;
        let native = recovered.native_completions.get(&acquisition.acquisition_id);
        let session = match native {
            Some(native) => recovered.session_history.get(&(
                acquisition.provider.authority_id(),
                acquisition.holder.authority_id(),
                native.session_binding,
            )),
            None => recovered.sessions.get(&(
                acquisition.provider.authority_id(),
                acquisition.holder.authority_id(),
            )),
        }.ok_or(ProviderLedgerError::Corrupt("native capacity original session"))?;
        let reservation = exact_reservation(journal, acquisition, attempt, session, native)?;
        if !expected.insert(reservation.reservation_id()) {
            return Err(ProviderLedgerError::Equivocation);
        }
    }
    journal.validate_global_capacity_reservation_set_v1(&expected)?;
    Ok(())
}

/// Atomically commits a native Applying row and its one-use terminal headroom.
pub(crate) fn commit_reservation(
    ledger: &mut ProviderLedgerV1<'_>,
    purpose: &[u8],
    records: Vec<(Vec<u8>, Vec<u8>)>,
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
    session: &HolderSessionHeadRecordV1,
) -> Result<ObjectDigest, ProviderLedgerError> {
    let prepared = prepare_mutations_validated(
        ledger,
        purpose,
        records
            .into_iter()
            .map(|(key, value)| (key, Some(value)))
            .collect(),
        None,
    )?;
    let capacity = ledger.journal.prepare_global_capacity_reservation_v1(
        request(acquisition, attempt, session, None)?,
        *prepared.transaction.id(),
    )?;
    let mut combined = prepared.transaction.records().to_vec();
    combined.push(capacity.record().clone());
    let transaction = JournalTransaction::new(*prepared.transaction.id(), combined)?;
    let preflight = ledger
        .journal
        .preflight_global_capacity_reservation_v1(&capacity, &transaction)?;
    if let Err(error) =
        ledger
            .journal
            .commit_global_capacity_reservation_v1(&preflight, capacity, &transaction)
    {
        ledger.poison_runtime();
        return Err(error.into());
    }
    validate_committed_graph(ledger)?;
    Ok(prepared.digest)
}

/// Commits the exact terminal rows and capacity deletion as one protected cut.
pub(crate) fn commit_terminal(
    ledger: &mut ProviderLedgerV1<'_>,
    purpose: &[u8],
    records: Vec<(Vec<u8>, Vec<u8>)>,
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
    session: &HolderSessionHeadRecordV1,
) -> Result<(), ProviderLedgerError> {
    let native = ledger
        .recovered
        .native_completions
        .get(&acquisition.acquisition_id);
    let reservation = exact_reservation(&ledger.journal, acquisition, attempt, session, native)?;
    let prepared = prepare_mutations_validated(
        ledger,
        purpose,
        records
            .into_iter()
            .map(|(key, value)| (key, Some(value)))
            .collect(),
        None,
    )?;
    let mut combined = prepared.transaction.records().to_vec();
    combined.push(reservation.settlement_record());
    let transaction = JournalTransaction::new(*prepared.transaction.id(), combined)?;
    let preflight = ledger
        .journal
        .preflight_reserved_terminal_v1(&reservation, &transaction)?;
    if let Err(error) =
        ledger
            .journal
            .commit_reserved_terminal_v1(&preflight, reservation, &transaction)
    {
        ledger.poison_runtime();
        return Err(error.into());
    }
    validate_committed_graph(ledger)?;
    Ok(())
}
