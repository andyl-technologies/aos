//! Durable terminal headroom for both protected native reservation owners.
//!
//! Namespace 46 reserves one bounded five-record terminal append in the same
//! transaction that creates the proofless Applying row. Cold replay requires
//! one matching reservation for each such row and no orphan reservations.
//! The distinct dispatch owner retains a larger reservation across Requested,
//! Prepared and Active; it is not the no-dispatch owner's five-record budget.
//! A lease-bearing native Release adds its own four-record status-only suffix;
//! all three owners contribute to one exact complete reservation union.

use std::collections::BTreeSet;

use aos_sandbox::{
    GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1, JournalTransaction, ProtectedJournalAuthority,
    RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
#[cfg(test)]
use sha2::{Digest as _, Sha256};

use crate::ProviderLedgerError;
use crate::acquire::is_native_no_dispatch_acquisition;
use crate::model::{
    AcquisitionRecordV1, AttemptRecordV1, HolderSessionHeadRecordV1, ProviderAcquisitionStateV1,
    ProviderAttemptStateV1, RecoveredProviderLedgerV1,
};
use crate::native_completion::is_native_dispatch_acquisition;
use crate::state::ProviderLedgerV1;
use crate::transaction::prepare_mutations_validated;

// Preserve unchanged private test fixture names through the shared policy.
#[cfg(test)]
const PURPOSE: aos_sandbox::GlobalCapacityReservationPurposeV1 =
    aos_sandbox::GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal;
#[cfg(test)]
const TERMINAL_BYTES: u64 = aos_sandbox::journal::SOURCE_NATIVE_NO_DISPATCH_TERMINAL_BYTES_V1 as u64;
#[cfg(test)]
const DISPATCH_TERMINAL_RECORDS: u32 = aos_sandbox::journal::SOURCE_NATIVE_DISPATCH_TERMINAL_RECORDS_V1;
#[cfg(test)]
const DISPATCH_TERMINAL_BYTES: u64 = aos_sandbox::journal::SOURCE_NATIVE_DISPATCH_TERMINAL_BYTES_V1;

fn request(
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
    session: &HolderSessionHeadRecordV1,
    native: Option<&crate::ledger::native_completion::NativeAcquireCompletionRecordV2>,
) -> Result<GlobalCapacityReservationRequestV1, ProviderLedgerError> {
    let binding = aos_sandbox_source_provider_ledger::ledger::source_capacity::derive_native_acquire_ordinary_binding_v1(
        acquisition, attempt, session, native,
    )
    .map_err(|error| match error {
        crate::ledger::LedgerFormatErrorV1::Corrupt("native original capacity digest") => {
            ProviderLedgerError::Corrupt("native original capacity digest")
        }
        _ => ProviderLedgerError::Equivocation,
    })?;
    Ok(aos_sandbox::journal::source_native_ordinary_capacity_request_v1(&binding))
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
        future_transactions: request.future_transactions,
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
    let result = crate::recovery::recover_capacity_checked(&ledger.journal, &ledger.configuration);
    if let Err(error) = result {
        ledger.poison_runtime();
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_completion/capacity_tests.rs"]
mod native_capacity_tests;

#[cfg(test)]
#[path = "native_completion/graph_capacity_tests.rs"]
mod native_graph_capacity_tests;

/// Validates all exact native owner reservations and rejects orphan capacity.
pub(crate) fn validate_set(
    journal: &ProtectedJournalAuthority<'_>,
    recovered: &RecoveredProviderLedgerV1,
) -> Result<(), ProviderLedgerError> {
    let mut expected = BTreeSet::new();
    add_expected(
        recovered,
        recovered.acquisitions.values(),
        &mut expected,
        |request| {
            let reservation =
                journal.recover_unique_global_capacity_reservation_v1(&binding(request))?;
            if reservation.request() != request {
                return Err(ProviderLedgerError::Equivocation);
            }
            Ok(reservation.reservation_id())
        },
    )?;
    crate::native_release_capacity::add_expected(journal, recovered, &mut expected)?;
    journal.validate_global_capacity_reservation_set_v1(&expected)?;
    Ok(())
}

/// Accumulates unchanged legacy expectations without granting settlement custody.
pub(crate) fn add_expected<'record>(
    recovered: &RecoveredProviderLedgerV1,
    acquisitions: impl Iterator<Item = &'record AcquisitionRecordV1>,
    expected: &mut BTreeSet<[u8; 32]>,
    mut exact: impl FnMut(GlobalCapacityReservationRequestV1) -> Result<[u8; 32], ProviderLedgerError>,
) -> Result<(), ProviderLedgerError> {
    for acquisition in acquisitions {
        let needs_floor = if is_native_dispatch_acquisition(acquisition) {
            !dispatch_terminal_in_validated_graph(acquisition, recovered)?
        } else {
            acquisition.state == ProviderAcquisitionStateV1::Applying
                && is_native_no_dispatch_acquisition(acquisition)
        };
        if !needs_floor {
            continue;
        }
        let native = recovered
            .native_completions
            .get(&acquisition.acquisition_id);
        // Release/recovery can move the ordinary current attempt and session.
        // The dispatch floor ALWAYS retains its original Acquire provenance.
        let attempt_digest = native
            .filter(|_| is_native_dispatch_acquisition(acquisition))
            .map_or(acquisition.current_attempt_digest, |record| {
                record.attempt_digest
            });
        let attempt = recovered
            .attempts
            .values()
            .find(|record| record.attempt_digest == attempt_digest)
            .ok_or(ProviderLedgerError::Corrupt("native capacity attempt"))?;
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
        }
        .ok_or(ProviderLedgerError::Corrupt(
            "native capacity original session",
        ))?;
        let identifier = exact(request(acquisition, attempt, session, native)?)?;
        if !expected.insert(identifier) {
            return Err(ProviderLedgerError::Equivocation);
        }
    }
    Ok(())
}

// CleanupRequired is a local observation, not ordinary lease deauthorization.
// Only a canonical Released acquisition with its exact tombstone is terminal
// for this Provider floor. This does NOT prove Root/Storage custody absence or
// authorize Storage retirement; the native terminal caller remains unwired.
fn dispatch_terminal_in_validated_graph(
    acquisition: &AcquisitionRecordV1,
    recovered: &RecoveredProviderLedgerV1,
) -> Result<bool, ProviderLedgerError> {
    if acquisition.state != ProviderAcquisitionStateV1::Released {
        return Ok(false);
    }

    let native = recovered
        .native_completions
        .get(&acquisition.acquisition_id);
    let release = recovered
        .releases
        .get(&crate::model::ReleaseKeyV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            acquisition_id: acquisition.acquisition_id,
        });
    let attempt = recovered
        .attempts
        .values()
        .find(|attempt| attempt.attempt_digest == acquisition.current_attempt_digest);
    aos_sandbox_source_provider_ledger::ledger::source_capacity::legacy_dispatch_capacity_is_retired_v1(
        acquisition, native, release, attempt,
    )
    .map_err(crate::transaction::map_pure_ledger_error)
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
    commit_reservation_checked(
        ledger,
        purpose,
        records,
        acquisition,
        attempt,
        session,
        |_| Ok(()),
    )
}

/// Rechecks and retains original-owner custody after preflight, before append.
pub(crate) fn commit_reservation_checked(
    ledger: &mut ProviderLedgerV1<'_>,
    purpose: &[u8],
    records: Vec<(Vec<u8>, Vec<u8>)>,
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
    session: &HolderSessionHeadRecordV1,
    before_commit: impl FnOnce(&mut ProviderLedgerV1<'_>) -> Result<(), ProviderLedgerError>,
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
    before_commit(ledger)?;
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
