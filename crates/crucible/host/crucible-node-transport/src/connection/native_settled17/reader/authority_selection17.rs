//! Selects only the small historical Authority during the actual Connection walk.
//!
//! The caller owns its retaining attempt before this method starts. Every later
//! Connection field still consumes its original rows and aliases, with target
//! reconstruction suspended. No source cursor is reset and no old host graph is
//! reconstructed as an indirect way to obtain this one historical registration.

use super::*;
use crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans;
use crate::protocol_snapshot::owned11::typed::Native17Build;

/// Prices exactly the selected Authority and validates all remaining fields.
///
/// The caller enters with target accounting enabled and its group caches bound
/// to this same Ledger. Successful return leaves accounting enabled. Refusal
/// poisons the original attempt and still attempts the matching private resume.
///
/// # Errors
/// Refuses malformed source fields, changed rows/aliases, unavailable selected
/// target demand or any remaining Connection invariant. No independent ledger
/// or new registration is created.
pub(crate) fn preflight_rooted_native17_connection_authority_data(
    roots: &NativeCurrentGraph17RootSpans<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<NativeConnection17GroupIds, ProviderError> {
    let mut fields = read_connection_header(roots.connection_data(), true)?;
    HistoricalAuthority17::preflight_data(fields.named("authority")?, ledger)?;
    let suspended = ledger.suspend_native17_targets_data()?;
    let remaining = read_connection_after_authority(fields, None, Some(roots), ledger, false);
    ledger.resume_native17_targets_data(suspended)?;
    let (owned, groups) = remaining?;
    if owned.is_some() {
        return Err(invalid());
    }
    Ok(groups)
}

/// Retains the selected Authority before any later Connection read can fail.
///
/// Every completed or partial selected child remains in the caller's concrete
/// Authority attempt. Remaining host caches are validation-only, using the same
/// source metadata and alias walk with no reset, detached proof or heap clone.
///
/// # Errors
/// Refuses repeated or failed attempts, selected backing refusal, malformed
/// source fields or any remaining Connection row/alias/invariant disagreement.
/// Successful return restores target accounting to the caller's entry state.
pub(crate) fn read_rooted_native17_connection_authority_into_data(
    roots: &NativeCurrentGraph17RootSpans<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    attempt: &mut <HistoricalAuthority17 as Native17Build>::Attempt,
) -> Result<NativeConnection17GroupIds, ProviderError> {
    let mut fields = read_connection_header(roots.connection_data(), true)?;
    HistoricalAuthority17::read_into_data(fields.named("authority")?, ledger, attempt)?;
    let suspended = ledger.suspend_native17_targets_data()?;
    let remaining = read_connection_after_authority(fields, None, Some(roots), ledger, false);
    ledger.resume_native17_targets_data(suspended)?;
    let (owned, groups) = remaining?;
    if owned.is_some() {
        return Err(invalid());
    }
    Ok(groups)
}
