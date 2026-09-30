//! Separate native lease-bearing Release status suffix custody.
//!
//! Admission commits seven fence-owner rows and this suffix's capacity PUT.
//! A sealed descriptor-free status consumes only this four-record suffix.
//! The original native seven-record cleanup floor is retained throughout.
//! Neither reservation establishes physical absence or Storage retirement.

use std::collections::BTreeSet;

use aos_sandbox::{
    GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1, GlobalCapacityReservationV1, JournalTransaction,
    ProtectedJournalAuthority, RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::ledger::native_completion::release_fence::{
    NativeReleaseStatusCapacityBindingV1, native_release_status_capacity_binding_v1,
    native_release_status_is_completed_v1,
};

use crate::ProviderLedgerError;
use crate::model::{ProviderAcquisitionStateV1, ProviderAttemptStateV1, RecoveredProviderLedgerV1};
use crate::state::ProviderLedgerV1;

fn request(binding: NativeReleaseStatusCapacityBindingV1) -> GlobalCapacityReservationRequestV1 {
    aos_sandbox::journal::source_native_release_status_capacity_request_v1(binding)
}

pub(crate) fn binding(
    recovered: &RecoveredProviderLedgerV1,
    acquisition_id: ObjectDigest,
) -> Result<NativeReleaseStatusCapacityBindingV1, ProviderLedgerError> {
    let acquisition = recovered
        .acquisitions
        .values()
        .find(|row| row.acquisition_id == acquisition_id)
        .ok_or(ProviderLedgerError::Corrupt(
            "native Release capacity acquisition",
        ))?;
    let native =
        recovered
            .native_completions
            .get(&acquisition_id)
            .ok_or(ProviderLedgerError::Corrupt(
                "native Release capacity marker",
            ))?;
    let original = recovered
        .attempts
        .values()
        .find(|row| row.attempt_digest == native.attempt_digest)
        .ok_or(ProviderLedgerError::Corrupt(
            "native Release capacity original Acquire",
        ))?;
    let release = recovered
        .releases
        .values()
        .find(|row| row.acquisition_id == acquisition_id)
        .ok_or(ProviderLedgerError::Corrupt(
            "native Release capacity intent",
        ))?;
    let attempt = recovered
        .attempts
        .values()
        .find(|row| row.attempt_digest == release.attempt_digest)
        .ok_or(ProviderLedgerError::Corrupt(
            "native Release capacity current attempt",
        ))?;
    let session = recovered
        .session_history
        .get(&(
            attempt.provider.authority_id(),
            attempt.holder.authority_id(),
            attempt.session_binding,
        ))
        .ok_or(ProviderLedgerError::Corrupt(
            "native Release capacity request session",
        ))?;
    native_release_status_capacity_binding_v1(
        acquisition,
        native,
        original,
        release,
        attempt,
        session,
    )
    .map_err(crate::transaction::map_pure_ledger_error)
}

#[cfg(test)]
pub(crate) fn fixture_request(
    recovered: &RecoveredProviderLedgerV1,
    acquisition_id: ObjectDigest,
) -> Result<GlobalCapacityReservationRequestV1, ProviderLedgerError> {
    Ok(request(binding(recovered, acquisition_id)?))
}

/// Recovers only the exact still-Reserved native Release status suffix.
///
/// # Errors
///
/// Rejects completed/foreign lineage, missing capacity or any geometry mismatch.
pub(crate) fn exact_reservation(
    journal: &ProtectedJournalAuthority<'_>,
    recovered: &RecoveredProviderLedgerV1,
    acquisition_id: ObjectDigest,
) -> Result<GlobalCapacityReservationV1, ProviderLedgerError> {
    let release = recovered
        .releases
        .values()
        .find(|row| row.acquisition_id == acquisition_id)
        .ok_or(ProviderLedgerError::Unavailable)?;
    if !recovered.attempts.values().any(|row| {
        row.attempt_digest == release.attempt_digest
            && row.state == ProviderAttemptStateV1::Reserved
    }) {
        return Err(ProviderLedgerError::Unavailable);
    }
    let expected = request(binding(recovered, acquisition_id)?);
    let stable = GlobalCapacityReservationRecoveryBindingV1 {
        purpose: expected.purpose,
        operation_id: expected.operation_id,
        artifact_digest: expected.artifact_digest,
        checkpoint_digest: expected.checkpoint_digest,
        chain_head_digest: expected.chain_head_digest,
        future_transactions: expected.future_transactions,
        terminal_records: expected.terminal_records,
        terminal_bytes: expected.terminal_bytes,
        poison_records: expected.poison_records,
        poison_bytes: expected.poison_bytes,
    };
    let retained = journal.recover_unique_global_capacity_reservation_v1(&stable)?;
    if retained.request() != expected {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(retained)
}

/// Adds this owner's exact reservations to the single complete expected union.
///
/// Faulted retains its unresolved status obligation but restores no completion
/// eligibility. Completed status keeps exact historical lineage without a floor.
///
/// # Errors
///
/// Rejects missing/foreign provenance or capacity, and duplicate reservations.
pub(crate) fn add_expected(
    journal: &ProtectedJournalAuthority<'_>,
    recovered: &RecoveredProviderLedgerV1,
    expected: &mut BTreeSet<[u8; 32]>,
) -> Result<(), ProviderLedgerError> {
    add_expected_with(
        recovered,
        expected,
        |acquisition| binding(recovered, acquisition),
        |request| {
            let stable = GlobalCapacityReservationRecoveryBindingV1 {
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
            };
            let reservation = journal.recover_unique_global_capacity_reservation_v1(&stable)?;
            if reservation.request() != request {
                return Err(ProviderLedgerError::Equivocation);
            }
            Ok(reservation.reservation_id())
        },
    )
}

/// Reuses status disposition and expectation logic for the checked actual profile.
pub(crate) fn add_expected_with(
    recovered: &RecoveredProviderLedgerV1,
    expected: &mut BTreeSet<[u8; 32]>,
    mut association: impl FnMut(
        ObjectDigest,
    )
        -> Result<NativeReleaseStatusCapacityBindingV1, ProviderLedgerError>,
    mut exact: impl FnMut(GlobalCapacityReservationRequestV1) -> Result<[u8; 32], ProviderLedgerError>,
) -> Result<(), ProviderLedgerError> {
    for acquisition in recovered.acquisitions.values().filter(|row| {
        matches!(
            row.state,
            ProviderAcquisitionStateV1::Releasing | ProviderAcquisitionStateV1::Faulted
        ) && crate::native_completion::is_native_dispatch_acquisition(row)
            && recovered
                .releases
                .values()
                .any(|release| release.acquisition_id == row.acquisition_id)
    }) {
        let release = recovered
            .releases
            .values()
            .find(|row| row.acquisition_id == acquisition.acquisition_id)
            .ok_or(ProviderLedgerError::Corrupt("native Release status intent"))?;
        let attempt = recovered
            .attempts
            .values()
            .find(|row| row.attempt_digest == release.attempt_digest)
            .ok_or(ProviderLedgerError::Corrupt(
                "native Release status attempt",
            ))?;
        if attempt.state == ProviderAttemptStateV1::Reserved {
            let identifier = exact(request(association(acquisition.acquisition_id)?))?;
            if !expected.insert(identifier) {
                return Err(ProviderLedgerError::Equivocation);
            }
        } else if !native_release_status_is_completed_v1(attempt) {
            return Err(ProviderLedgerError::Corrupt(
                "native Release status suffix disposition",
            ));
        } else {
            // Consumed status capacity is absent, but exact native/lease/Root
            // request lineage must remain valid for authenticated recovery.
            association(acquisition.acquisition_id)?;
        }
    }
    Ok(())
}

/// Commits the exact seven-owner-row fence and separate suffix as eight records.
///
/// # Errors
///
/// Rejects an invalid full graph/transition, insufficient exact geometry or
/// headroom, failed durable append, or mismatched protected readback.
pub(crate) fn commit_admission(
    ledger: &mut ProviderLedgerV1<'_>,
    records: Vec<(Vec<u8>, Vec<u8>)>,
    acquisition_id: ObjectDigest,
) -> Result<ObjectDigest, ProviderLedgerError> {
    crate::native_no_dispatch_capacity::validate_set(&ledger.journal, &ledger.recovered)?;
    let prepared = crate::transaction::prepare_native_release_admission(
        ledger,
        records
            .into_iter()
            .map(|(key, value)| (key, Some(value)))
            .collect(),
    )?;
    let capacity = ledger.journal.prepare_global_capacity_reservation_v1(
        request(binding(&prepared.prospective_recovered, acquisition_id)?),
        *prepared.transaction.id(),
    )?;
    let mut rows = prepared.transaction.records().to_vec();
    rows.push(capacity.record().clone());
    let transaction = JournalTransaction::new(*prepared.transaction.id(), rows)?;
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
    ledger.recovered =
        match crate::recovery::recover_capacity_checked(&ledger.journal, &ledger.configuration) {
            Ok(recovered) => recovered,
            Err(error) => {
                ledger.poison_runtime();
                return Err(error);
            }
        };
    ledger.refresh_recovery_work();
    Ok(prepared.digest)
}
