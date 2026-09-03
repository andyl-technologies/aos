//! Maintainer-side coordination for canonical AOS releases.
//!
//! Effectful filesystem, Nix, signer, Git, and Hub adapters live below this
//! module. The `aos-release` crate remains the sole semantic contract.

mod build;
mod capture;
mod plan;
mod signer;
mod stage;
mod status;
mod verify;

use anyhow::Result;
use aos_core::nix::NixRunner;
use aos_core::output::Printer;

use crate::cli::ReleaseCommand;

/// Runs one canonical release operation.
///
/// # Errors
///
/// Returns an error when planning, capture, or release verification fails.
pub fn run(command: &ReleaseCommand, nix: &NixRunner, printer: &Printer) -> Result<()> {
    match command {
        ReleaseCommand::Plan(args) => plan::run(args, nix, printer),
        ReleaseCommand::Build(args) => build::run(args, nix, printer),
        ReleaseCommand::Status(args) => status::run(args, printer),
        ReleaseCommand::Signer { .. } => {
            anyhow::bail!("release signer command must use the asynchronous offline dispatcher")
        }
        ReleaseCommand::Stage(_) => {
            anyhow::bail!("release stage command must use the asynchronous dispatcher")
        }
        ReleaseCommand::Verify(args) => verify::run(args, printer),
    }
}

/// Stages one finalized release without constructing a Nix environment.
///
/// # Errors
///
/// Returns an error when local verification, Hub publication, public read-back,
/// or durable receipt persistence fails.
pub async fn stage_offline(args: &crate::cli::ReleaseStageArgs, printer: &Printer) -> Result<()> {
    stage::run(args, printer).await
}

/// Invokes an external signer without constructing a Nix environment.
///
/// # Errors
///
/// Returns an error when signer invocation, response verification, or output
/// persistence fails.
pub async fn signer_offline(
    command: &crate::cli::ReleaseSignerCommand,
    printer: &Printer,
) -> Result<()> {
    signer::run(command, printer).await
}

/// Runs offline verification without constructing a Nix environment.
///
/// # Errors
///
/// Returns an error when the release bundle or trust inputs are invalid.
pub fn verify_offline(args: &crate::cli::ReleaseVerifyArgs, printer: &Printer) -> Result<()> {
    verify::run(args, printer)
}

/// Reconciles local journal state without constructing a Nix environment.
///
/// # Errors
///
/// Returns an error when the journal cannot be captured or is invalid.
pub fn status_offline(args: &crate::cli::ReleaseStatusArgs, printer: &Printer) -> Result<()> {
    status::run(args, printer)
}
