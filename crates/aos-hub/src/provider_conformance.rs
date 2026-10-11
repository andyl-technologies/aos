//! Retained operator-side S3 provider experiments without runtime acceptance.
//!
//! This module executes a bounded multipart experiment against an explicitly
//! selected private staging prefix. Every mutation has a durable original
//! intent before dispatch. Unknown effects remain retained and cannot be
//! resumed, replayed or inferred settled from time or object absence.
//!
//! Reports contain closed observations and receipt commitments, never bearer
//! URLs or credentials. They establish neither private writer closure nor
//! Worker SDK compatibility; both require their independent review gates.

mod config;
mod copy_contract;
mod copy_capacity;
mod profile_digest;
mod journal;
mod model;
mod probe;
mod transport;
mod transport_failure;

#[cfg(test)]
mod tests;

use std::path::Path;

use anyhow::Result;

/// Runs one new, bounded operator-side provider experiment.
///
/// # Errors
/// Returns an error for invalid protected inputs, reused output/journal paths,
/// unsupported provider behavior, or an unknown retained effect. No error
/// triggers replay or cleanup of a provider mutation.
pub async fn run_provider_conformance(
    config_file: &Path,
    journal_directory: &Path,
    output: &Path,
) -> Result<String> {
    let loaded = config::load(config_file)?;
    probe::run(loaded, journal_directory, output).await
}

/// Reads the retained experiment state without contacting the provider.
///
/// # Errors
/// Returns an error for an invalid, oversized or inaccessible private journal.
pub fn provider_conformance_status(journal_directory: &Path) -> Result<String> {
    journal::status(journal_directory)
}

/// Projects complete retained versionless observations into copy transport facts.
///
/// This read-only command contacts no provider and installs no acceptance,
/// credential, cohort or runtime permission. Its input remains independently
/// selected evidence rather than an authenticated provider attestation.
///
/// # Errors
/// Refuses changed source/executable or report/journal correlation, missing,
/// partial, unknown or incompatible phases, and insecure or existing output.
pub fn export_provider_copy_contract(
    report_file: &Path,
    journal_directory: &Path,
    output: &Path,
) -> Result<String> {
    copy_contract::project(report_file, journal_directory, output)
}

/// Computes a structural protected-profile digest without authentication or effects.
///
/// The caller retains independently authenticated discovery and accepted
/// artifact originals. This projection supplies neither of those authorities.
///
/// # Errors
/// Returns an error for excessive, malformed, noncanonical or invalid shared
/// profile facts, and file errors.
pub fn export_provider_profile_digest(profile_file: &Path) -> Result<String> {
    profile_digest::project(profile_file)
}

/// Projects explicit Copy configuration ceilings beneath verified runtime capacity.
///
/// The closed declaration supplies administrative ceilings, not measured peaks.
/// Existing artifact verification supplies actual capacity and protected profiles.
/// This read-only projection creates no provider or cohort permission.
///
/// # Errors
/// Refuses invalid signature, audience, expiry, reviewer, declared profile or
/// bounds; oversized or insecure inputs; and an existing or inaccessible output.
pub fn export_provider_copy_capacity(
    artifact_file: &Path,
    reviewer_public_key_file: &Path,
    declaration_file: &Path,
    output: &Path,
) -> Result<String> {
    copy_capacity::project(artifact_file, reviewer_public_key_file, declaration_file, output)
}
