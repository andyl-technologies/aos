//! Structural commitments of exact selected protected external profiles.
//!
//! This read-only computation checks the shared closed canonical profile. It
//! does not authenticate discovery, accept an artifact, query SQL or contact a
//! provider. Callers retain those independent original joins separately.
//!
//! ```text
//! input = DirectProtectedExternalProfile { profile, runtimeQualification }
//! output = {version: 1, profile_sha256, protected_profile_digest}
//! ```

use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::DirectProtectedExternalProfile;

use super::journal;

const MAX_PROFILE_BYTES: u64 = 256 * 1024;

/// Computes a shared commitment without granting authenticity or permission.
///
/// # Errors
/// Returns an error for excessive, malformed, unknown or noncanonical fields,
/// invalid shared profile facts, and file errors.
pub(super) fn project(path: &Path) -> Result<String> {
    let bytes = journal::read(path, MAX_PROFILE_BYTES, false)?;
    let profile: DirectProtectedExternalProfile = serde_json::from_slice(&bytes)?;
    ensure!(serde_json::to_vec(&profile)? == bytes,
        "protected external profile input is noncanonical");
    profile.validate()?;
    Ok(serde_json::to_string(&serde_json::json!({
        "version": 1,
        "profile_sha256": journal::digest(&bytes),
        "protected_profile_digest": profile.digest()?,
    }))?)
}

#[cfg(test)]
mod tests;
