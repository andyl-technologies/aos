//! Non-authorizing native export-fence joins over canonical owner records.
//!
//! A release fence leaves immutable Acquire, lease, request and acceptance
//! artifacts readable. Their retention is not permission to issue another
//! lease, reopen a root, or send an already prepared descriptor-bearing reply.
//! Callers still authenticate the complete protected graph and live custody.

use super::{NativeAcquireCompletionRecordV2, NativeAcquireCompletionStateV2};
use crate::ledger::LedgerFormatErrorV1;
use crate::ledger::model::{AcquisitionRecordV1, AttemptRecordV1, ProviderAcquisitionStateV1};

/// Rejects a native owner state that durably fences every future export.
///
/// Applying/Prepared may still be eligible for the original completion, while
/// Releasing, Released, Faulted and CleanupRequired cannot recreate export
/// permission. This pure join grants no effect, signing, reopen or FD custody
/// authority; non-native acquisitions retain their existing validation path.
///
/// # Errors
///
/// Rejects a foreign native row or a durable native export fence.
pub fn validate_native_export_open_v1(
    acquisition: &AcquisitionRecordV1,
    native: Option<&NativeAcquireCompletionRecordV2>,
) -> Result<(), LedgerFormatErrorV1> {
    if !has_native_origin(acquisition, native) {
        return Ok(());
    }
    if let Some(native) = native
        && (native.acquisition_id != acquisition.acquisition_id
            || native.provider_id != acquisition.provider.authority_id()
            || native.holder_id != acquisition.holder.authority_id()
            || native.attempt_digest != acquisition.effect_attempt_digest)
    {
        return Err(LedgerFormatErrorV1::Corrupt("native export origin join"));
    }
    if matches!(
        acquisition.state,
        ProviderAcquisitionStateV1::Releasing
            | ProviderAcquisitionStateV1::Released
            | ProviderAcquisitionStateV1::Faulted
    ) || native
        .is_some_and(|native| native.state == NativeAcquireCompletionStateV2::CleanupRequired)
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native export is durably fenced",
        ));
    }
    Ok(())
}

/// Checks native Complete-Acquire artifact eligibility independently of retention.
///
/// Historical signed artifacts remain decodable after a release fence. A
/// protected exporter must additionally join the exact original Acquire to
/// ordinary Active and native Active before any fresh or replay FD handoff.
/// This check alone supplies no protected currentness or descriptor authority.
///
/// # Errors
///
/// Rejects a durable fence, a missing or legacy native marker, another Acquire,
/// or a native acquisition that is no longer exactly Active.
pub fn validate_native_complete_export_v1(
    acquisition: &AcquisitionRecordV1,
    native: Option<&NativeAcquireCompletionRecordV2>,
    attempt: &AttemptRecordV1,
) -> Result<(), LedgerFormatErrorV1> {
    if !has_native_origin(acquisition, native) {
        return Ok(());
    }
    validate_native_export_open_v1(acquisition, native)?;
    let native = native.ok_or(LedgerFormatErrorV1::Corrupt("native export marker missing"))?;
    native.validate_provider_graph(attempt, acquisition)?;
    if acquisition.state != ProviderAcquisitionStateV1::Active
        || native.state != NativeAcquireCompletionStateV2::Active
        || native.canonical_request.is_none()
        || native.original_clock.is_none()
        || acquisition.lease_attempt_digest != Some(attempt.attempt_digest)
        || acquisition.source_root != Some(native.original_root)
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native Complete export lineage",
        ));
    }
    Ok(())
}

fn has_native_origin(
    acquisition: &AcquisitionRecordV1,
    native: Option<&NativeAcquireCompletionRecordV2>,
) -> bool {
    native.is_some()
        || acquisition.backend_id
            == crate::identity::acquire_native_dispatch_id_v2(
                acquisition.normalized_intent.digest(),
                acquisition.catalog_generation,
                acquisition.catalog_digest,
                acquisition.effect_attempt_digest,
            )
}
