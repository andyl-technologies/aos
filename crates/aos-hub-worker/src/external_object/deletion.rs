//! Versioned conditional-delete evidence without absence-based unknown settlement.
//!
//! A current HEAD is a pre-dispatch precondition check. Only an exact provider
//! DELETE acknowledgement closes a dispatched mutation; a later HEAD or timeout
//! never clears its permanent pending turn.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::external_object::{
    deletion::ExternalDeletePrecondition, ExternalObjectOutcome,
};

/// Checks metadata without turning HEAD into settlement of a pending DELETE.
///
/// # Errors
/// Returns an error when the retained version, ETag, length, or hash is invalid.
pub(super) fn condition_matches(
    expected: &ExternalDeletePrecondition,
    path: &str,
    size: Option<&str>,
    etag: Option<&str>,
    provider_version: Option<&str>,
) -> Result<bool> {
    expected.validate()?;
    let probe = aos_hub_core::storage_work::admitted_probe_path(path)
        && expected.bytes.parse::<u64>()? <= 4096;
    Ok(size == Some(expected.bytes.as_str())
        && provider_version == Some(expected.provider_version.as_str())
        && (probe || etag == Some(expected.etag.as_str())))
}

/// Classifies only the original provider DELETE response, without guessing.
///
/// # Errors
/// Returns an error for an ambiguous status, a different acknowledged version,
/// or a delete marker instead of the exact version deletion.
pub(super) fn acknowledgement(
    expected: &ExternalDeletePrecondition,
    status: u16,
    provider_version: Option<&str>,
    delete_marker: Option<&str>,
) -> Result<ExternalObjectOutcome> {
    expected.validate()?;
    match status {
        200 | 204 => {
            ensure!(
                provider_version == Some(expected.provider_version.as_str())
                    && delete_marker.is_none_or(|value| value == "false"),
                "provider did not acknowledge the exact version deletion"
            );
            Ok(ExternalObjectOutcome::DeleteAcknowledged {
                provider_version: expected.provider_version.clone(),
                etag: expected.etag.clone(),
            })
        }
        404 => Ok(ExternalObjectOutcome::DeleteAbsent),
        412 => Ok(ExternalObjectOutcome::DeletePreconditionFailed),
        _ => anyhow::bail!("conditional delete outcome remains unknown"),
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) mod runtime;

#[cfg(test)]
mod tests;
