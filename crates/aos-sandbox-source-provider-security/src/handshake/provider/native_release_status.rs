//! Exact protected native Release status suffix consumption, never retirement.

use aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1;
use aos_sandbox_source_provider_ledger::ledger::native_completion::release_fence::{
    NATIVE_RELEASE_STATUS_TERMINAL_BYTES_V1, NATIVE_RELEASE_STATUS_TERMINAL_RECORDS_V1,
    native_release_status_capacity_binding_v1,
};

use crate::SourceProviderSecurityError;

// The records come from current protected completion custody. Validate their
// full graph before the exact suffix join; no public raw-binding/reservation
// conversion to a sealed builder exists.
pub(super) fn exact_reservation(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    records: &[(Vec<u8>, Vec<u8>)],
    authorization: &super::super::ProviderOutcomeAuthorizationV1,
) -> Result<aos_sandbox::GlobalCapacityReservationV1, SourceProviderSecurityError> {
    aos_sandbox_source_provider_ledger::validate_prospective_records(
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let decoded = records
        .iter()
        .map(|(key, value)| {
            aos_sandbox_source_provider_ledger::ledger::format::decode_record(key, value)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let attempt = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::Attempt(row) if row.attempt_digest == authorization.attempt_digest => {
                Some(row)
            }
            _ => None,
        })
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    if attempt.state != aos_sandbox_source_provider_ledger::ProviderAttemptStateV1::Reserved {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let acquisition = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::Acquisition(row)
                if row.current_attempt_digest == attempt.attempt_digest =>
            {
                Some(row)
            }
            _ => None,
        })
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    if acquisition.state
        != aos_sandbox_source_provider_ledger::ProviderAcquisitionStateV1::Releasing
    {
        // Faulted retains the suffix but does not restore a poisoned runtime's
        // status completion or signing eligibility.
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let native = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::NativeCompletion(row)
                if row.acquisition_id == acquisition.acquisition_id =>
            {
                Some(row)
            }
            _ => None,
        })
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let original = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::Attempt(row) if row.attempt_digest == native.attempt_digest => {
                Some(row)
            }
            _ => None,
        })
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let release = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::Release(row) if row.acquisition_id == acquisition.acquisition_id => {
                Some(row)
            }
            _ => None,
        })
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let session = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::Session(row)
                if row.provider == attempt.provider && row.holder == attempt.holder =>
            {
                Some(row)
            }
            _ => None,
        })
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let binding = native_release_status_capacity_binding_v1(
        acquisition,
        native,
        original,
        release,
        attempt,
        session,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let expected = aos_sandbox::GlobalCapacityReservationRequestV1 {
        purpose: aos_sandbox::GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
        owner_namespace: aos_sandbox::RecordNamespace::SourceProviderAuthority,
        owner_id: binding.owner_id,
        owner_digest: *binding.owner_digest.as_bytes(),
        operation_id: binding.operation_id,
        artifact_digest: *binding.artifact_digest.as_bytes(),
        checkpoint_digest: *binding.checkpoint_digest.as_bytes(),
        chain_head_digest: *binding.chain_head_digest.as_bytes(),
        terminal_records: NATIVE_RELEASE_STATUS_TERMINAL_RECORDS_V1,
        terminal_bytes: NATIVE_RELEASE_STATUS_TERMINAL_BYTES_V1,
        poison_records: NATIVE_RELEASE_STATUS_TERMINAL_RECORDS_V1,
        poison_bytes: NATIVE_RELEASE_STATUS_TERMINAL_BYTES_V1,
        future_transactions: 1,
    };
    let retained = journal
        .recover_unique_global_capacity_reservation_v1(
            &aos_sandbox::GlobalCapacityReservationRecoveryBindingV1 {
                purpose: expected.purpose,
                operation_id: expected.operation_id,
                artifact_digest: expected.artifact_digest,
                checkpoint_digest: expected.checkpoint_digest,
                chain_head_digest: expected.chain_head_digest,
                terminal_records: expected.terminal_records,
                terminal_bytes: expected.terminal_bytes,
                poison_records: expected.poison_records,
                poison_bytes: expected.poison_bytes,
                future_transactions: expected.future_transactions,
            },
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    if retained.request() != expected {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(retained)
}

// Generic status builders must not complete a native Release while stranding
// its separate suffix. Only the exact reserved native facade may consume it.
pub(super) fn contains_native_release(
    records: &[(Vec<u8>, Vec<u8>)],
    attempt_digest: aos_sandbox_core::ObjectDigest,
) -> Result<bool, SourceProviderSecurityError> {
    for (key, value) in records {
        if let DecodedRecordV1::Acquisition(row) =
            aos_sandbox_source_provider_ledger::ledger::format::decode_record(key, value)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
            && row.current_attempt_digest == attempt_digest
        {
            let native_key = aos_sandbox_source_provider_ledger::ledger::native_completion::native_completion_key_v2(row.acquisition_id);
            return Ok(records.iter().any(|(key, _)| key == &native_key));
        }
    }
    Ok(false)
}
