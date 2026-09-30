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
