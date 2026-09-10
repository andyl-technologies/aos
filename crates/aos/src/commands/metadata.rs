//! The `aos metadata` subcommand for cross-cloud host configuration.
//!
//! The command model and implementation live in [`aos_package::metadata`] so
//! the repository CLI and compact on-host runtime expose identical semantics.

use anyhow::Result;
use aos_package::metadata::MetadataCommand;

/// Dispatches a parsed metadata command to the shared production agent.
///
/// # Errors
///
/// Returns an error when acquisition, authorization, restricted evaluation,
/// binding verification, or durable state publication fails.
pub async fn run(command: &MetadataCommand) -> Result<()> {
    aos_package::metadata::run_command(command).await
}
