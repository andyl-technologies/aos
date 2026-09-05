//! Maintainer-side coordination for canonical AOS releases.
//!
//! Effectful filesystem, Nix, signer, Git, and Hub adapters live below this
//! module. The `aos-release` crate remains the sole semantic contract.

mod bootstrap;
mod build;
mod capture;
mod channel;
mod compose_surface;
mod contract;
mod finalize;
mod finalize_cache;
mod finalize_image;
mod finalize_registry;
mod hub_transition;
mod plan;
mod promote;
mod qualification_run;
mod qualify;
mod signer;
mod stage;
mod status;
mod timestamp;
mod tuf;
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
        ReleaseCommand::Contract(args) => contract::run(args, nix, printer),
        ReleaseCommand::Plan(args) => plan::run(args, nix, printer),
        ReleaseCommand::Build(args) => build::run(args, nix, printer),
        ReleaseCommand::Status(args) => status::run(args, printer),
        ReleaseCommand::FinalizeImage(_) => {
            anyhow::bail!("release image finalization must use the asynchronous dispatcher")
        }
        ReleaseCommand::FinalizeRegistry(_) => {
            anyhow::bail!("release registry finalization must use the asynchronous dispatcher")
        }
        ReleaseCommand::Finalize(_) => {
            anyhow::bail!("release bundle finalization must use the asynchronous dispatcher")
        }
        ReleaseCommand::FinalizeCache(_) => {
            anyhow::bail!("release cache finalization must use the asynchronous dispatcher")
        }
        ReleaseCommand::Timestamp { .. } => {
            anyhow::bail!("release timestamp command must use the asynchronous offline dispatcher")
        }
        ReleaseCommand::Tuf(_) => {
            anyhow::bail!("release TUF command must use the asynchronous offline dispatcher")
        }
        ReleaseCommand::ComposeSurface(_) => {
            anyhow::bail!("release surface composition must use the offline dispatcher")
        }
        ReleaseCommand::Signer { .. } => {
            anyhow::bail!("release signer command must use the asynchronous offline dispatcher")
        }
        ReleaseCommand::Stage(_) => {
            anyhow::bail!("release stage command must use the asynchronous dispatcher")
        }
        ReleaseCommand::Qualify(_) => {
            anyhow::bail!("release qualify command must use the asynchronous dispatcher")
        }
        ReleaseCommand::QualifyRun(_) => {
            anyhow::bail!("release qualify-run command must use the asynchronous dispatcher")
        }
        ReleaseCommand::Promote(_) => {
            anyhow::bail!("release promote command must use the asynchronous dispatcher")
        }
        ReleaseCommand::Bootstrap(_) => {
            anyhow::bail!("release bootstrap command must use the asynchronous dispatcher")
        }
        ReleaseCommand::Channel { .. } => {
            anyhow::bail!("release channel command must use the asynchronous dispatcher")
        }
        ReleaseCommand::Verify(args) => verify::run(args, printer),
    }
}

/// Renews a timestamp over an already-authorized immutable snapshot.
///
/// # Errors
///
/// Returns an error for trust, rollback, signer, freshness, or output failure.
pub async fn timestamp_offline(
    command: &crate::cli::ReleaseTimestampCommand,
    printer: &Printer,
) -> Result<()> {
    timestamp::run(command, printer).await
}

/// Constructs immutable role-separated TUF metadata for a finalized bundle.
///
/// # Errors
///
/// Returns an error for plan, bundle, root, role-policy, signer, expiry,
/// predecessor, or atomic-output failure.
pub async fn tuf_offline(args: &crate::cli::ReleaseTufArgs, printer: &Printer) -> Result<()> {
    tuf::run(args, printer).await
}

/// Composes one verified immutable registry and TUF publication surface.
///
/// # Errors
///
/// Returns an error for bundle, root, metadata, freshness, source-tree, or
/// atomic-output validation failure.
pub fn compose_surface_offline(
    args: &crate::cli::ReleaseComposeSurfaceArgs,
    printer: &Printer,
) -> Result<()> {
    compose_surface::run(args, printer)
}

/// Finalizes one public Linux image assembly through configured signers.
///
/// # Errors
///
/// Returns an error when plan/assembly binding, tool identity, signing,
/// reconstruction, or durable final output sealing fails.
pub async fn finalize_image(
    args: &crate::cli::ReleaseFinalizeImageArgs,
    nix: &NixRunner,
    printer: &Printer,
) -> Result<()> {
    finalize_image::run(args, nix, printer).await
}

/// Authors and signs one complete isolated canonical registry transaction.
///
/// # Errors
///
/// Returns an error for plan/build/transaction drift, untrusted provider
/// output, incomplete authoring, surface mismatch, or non-atomic persistence.
pub async fn finalize_registry(
    args: &crate::cli::ReleaseFinalizeRegistryArgs,
    printer: &Printer,
) -> Result<()> {
    finalize_registry::run(args, printer).await
}

/// Closes and threshold-signs one exact release bundle.
///
/// # Errors
///
/// Returns an error for plan, manifest, payload, journal, signer, verification,
/// or atomic-output failure.
pub async fn finalize(args: &crate::cli::ReleaseFinalizeArgs, printer: &Printer) -> Result<()> {
    finalize::run(args, printer).await
}

/// Generates and externally signs one complete static Nix cache.
///
/// # Errors
///
/// Returns an error for plan/build/registry drift, NAR generation, signer
/// binding, narinfo verification, or atomic-output failure.
pub async fn finalize_cache(
    args: &crate::cli::ReleaseFinalizeCacheArgs,
    printer: &Printer,
) -> Result<()> {
    finalize_cache::run(args, printer).await
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

/// Admits signed qualification evidence for an exact staged release.
///
/// # Errors
///
/// Returns an error when any trust input, receipt binding, journal transition,
/// Hub response, or durable evidence write fails.
pub async fn qualify_offline(
    args: &crate::cli::ReleaseQualifyArgs,
    printer: &Printer,
) -> Result<()> {
    qualify::run(args, printer).await
}

/// Executes all planned qualification gates on native platform adapters.
///
/// # Errors
///
/// Returns an error for trust drift, incomplete executor configuration,
/// failed native gates, authority signing failure, or non-atomic persistence.
pub async fn qualification_run_offline(
    args: &crate::cli::ReleaseQualifyRunArgs,
    printer: &Printer,
) -> Result<()> {
    qualification_run::run(args, printer).await
}

/// Promotes one exact qualified release into the isolated production Hub.
///
/// # Errors
///
/// Returns an error when trust, continuity, upload, public read-back, Hub
/// admission, signed receipt, or durable evidence persistence fails.
pub async fn promote_offline(
    args: &crate::cli::ReleasePromoteArgs,
    printer: &Printer,
) -> Result<()> {
    promote::run(args, printer).await
}

/// Installs an explicitly approved first registry base in one empty Hub.
///
/// # Errors
///
/// Returns an error for trust, plan, deployment, nonempty destination,
/// publication, public read-back, or durable evidence failure.
pub async fn bootstrap_offline(
    args: &crate::cli::ReleaseBootstrapArgs,
    printer: &Printer,
) -> Result<()> {
    bootstrap::run(args, printer).await
}

/// Advances one planned production release channel range.
///
/// # Errors
///
/// Returns an error when trust, plan intent, generation continuity, public
/// projection, signed receipt, or durable evidence persistence fails.
pub async fn channel_offline(
    command: &crate::cli::ReleaseChannelCommand,
    printer: &Printer,
) -> Result<()> {
    channel::run(command, printer).await
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
