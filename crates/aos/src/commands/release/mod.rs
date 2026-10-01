//! Maintainer-side coordination for canonical AOS releases.
//!
//! Effectful filesystem, Nix, signer, Git, Hub, and static-origin adapters
//! live below this module; the `aos-release` crate remains the sole semantic
//! contract. The [`porcelain`](self) (`aos maintain release new / advance / publish / status /
//! explain / review / fitness`) drives a release from the maintainer
//! configuration and a work directory by calling the leaf commands' `run`
//! functions in process. `aos maintain release step ...` exposes each operation as a
//! leaf command:
//!
//! - planning and build: [`plan`](self) freezes a plan, `build`, `assemble`,
//!   `finalize-*`, and `prepare-registry` produce and sign the bundle;
//! - publication: `publish` places the bundle on one destination's surface
//!   through [`surface`](self), `qualify-run` executes and signs a
//!   destination's qualification phase, and `channel advance|complete` roll
//!   the destination's channel out ring by ring;
//! - metadata: `tuf`, `timestamp`, `compose-surface`, and `record`;
//! - inspection: `contract`, `status`, `verify`, and `qualification cases`.
//!
//! Commands that evaluate Nix run through [`run_with_nix`]; the rest through
//! [`run_offline`] so they never construct a Nix environment.

mod access;
mod artifact_profiles;
mod assemble;
mod bootstrap;
mod build;
mod capture;
mod channel;
mod compose_surface;
mod config;
mod contract;
mod finalize;
mod finalize_cache;
mod finalize_image;
mod finalize_registry;
mod fitness_gate;
mod journal;
mod plan;
mod porcelain;
mod publish;
mod qualification_executor;
mod qualification_objects;
mod qualification_run;
mod qualification_transition;
mod record;
mod registry_entries;
mod signer;
mod status;
mod surface;
mod timestamp;
mod tooling;
mod tuf;
mod verify;

use anyhow::Result;
use aos_core::nix::NixRunner;
use aos_core::output::Printer;

use crate::cli::{ReleaseCommand, ReleaseStepCommand};

/// Returns whether a release command evaluates Nix.
#[must_use]
pub fn requires_nix(command: &ReleaseCommand) -> bool {
    match command {
        ReleaseCommand::Step { command } => matches!(
            command,
            ReleaseStepCommand::Contract(_)
                | ReleaseStepCommand::Plan(_)
                | ReleaseStepCommand::Build(_)
                | ReleaseStepCommand::Assemble(_)
                | ReleaseStepCommand::FinalizeImage(_)
        ),
        // `new` exports the contract and plans; `advance` builds, finalizes
        // images, and assembles through Nix.
        ReleaseCommand::New(_) | ReleaseCommand::Advance(_) => true,
        ReleaseCommand::Publish(_)
        | ReleaseCommand::Status(_)
        | ReleaseCommand::Explain(_)
        | ReleaseCommand::Review(_)
        | ReleaseCommand::Fitness { .. } => false,
    }
}

/// Runs a release command that needs no Nix environment.
///
/// # Errors
///
/// Returns an error when the command's verification, signing, publication,
/// or durable output fails, or when the command requires Nix.
pub async fn run_offline(command: &ReleaseCommand, printer: &Printer) -> Result<()> {
    let ReleaseCommand::Step { command } = command else {
        return porcelain::run_offline(command, printer).await;
    };
    match command {
        ReleaseStepCommand::Qualification { command } => {
            qualification_executor::run(command, printer).await
        }
        ReleaseStepCommand::Status(args) => status::run(args, printer),
        ReleaseStepCommand::Verify(args) => verify::run(args, printer),
        ReleaseStepCommand::Record(args) => record::run(args, printer),
        ReleaseStepCommand::Signer { command } => signer::run(command, printer).await,
        ReleaseStepCommand::PrepareRegistry(args) => {
            finalize_registry::prepare(args, printer).await
        }
        ReleaseStepCommand::FinalizeRegistry(args) => {
            finalize_registry::finalize(args, printer).await
        }
        ReleaseStepCommand::Finalize(args) => finalize::run(args, printer).await,
        ReleaseStepCommand::FinalizeCache(args) => finalize_cache::run(args, printer).await,
        ReleaseStepCommand::Timestamp { command } => timestamp::run(command, printer).await,
        ReleaseStepCommand::Tuf(args) => tuf::run(args, printer).await,
        ReleaseStepCommand::ComposeSurface(args) => compose_surface::run(args, printer),
        ReleaseStepCommand::Publish(args) => publish::run(args, printer).await,
        ReleaseStepCommand::QualifyRun(args) => qualification_run::run(args, printer).await,
        ReleaseStepCommand::Bootstrap(args) => bootstrap::run(args, printer).await,
        ReleaseStepCommand::Channel { command } => channel::run(command, printer).await,
        ReleaseStepCommand::Contract(_)
        | ReleaseStepCommand::Plan(_)
        | ReleaseStepCommand::Build(_)
        | ReleaseStepCommand::Assemble(_)
        | ReleaseStepCommand::FinalizeImage(_) => {
            anyhow::bail!("this release step evaluates Nix and must use the Nix dispatcher")
        }
    }
}

/// Runs a release command, constructing Nix evaluations where needed.
///
/// # Errors
///
/// Returns an error when planning, build, assembly, image finalization, or
/// any offline operation fails.
pub async fn run_with_nix(
    command: &ReleaseCommand,
    nix: &NixRunner,
    printer: &Printer,
) -> Result<()> {
    let ReleaseCommand::Step { command: step } = command else {
        return porcelain::run_with_nix(command, nix, printer).await;
    };
    match step {
        ReleaseStepCommand::Contract(args) => contract::run(args, nix, printer),
        ReleaseStepCommand::Plan(args) => plan::run(args, nix, printer),
        ReleaseStepCommand::Build(args) => build::run(args, nix, printer),
        ReleaseStepCommand::Assemble(args) => assemble::run(args, nix, printer),
        ReleaseStepCommand::FinalizeImage(args) => finalize_image::run(args, nix, printer).await,
        _ => run_offline(command, printer).await,
    }
}
