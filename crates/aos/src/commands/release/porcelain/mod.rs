//! Maintainer porcelain: `aos maintain release new / advance / status / explain /
//! review / fitness`.
//!
//! The porcelain operates one release from the maintainer configuration
//! ([`MaintainerConfig`]) and a work directory ([`workdir`]). It never spawns
//! `aos`: every effect is a leaf command's `run` function called in process
//! with an Args struct constructed from the configuration and the work
//! directory, so the step commands and the porcelain share one fail-closed
//! implementation.
//!
//! - [`new`] derives the plan request from the configuration and live
//!   registry state and freezes the plan;
//! - [`advance`] observes the journal and work directory, asks [`planner`]
//!   for the next step, runs it through [`steps`], and repeats until the
//!   destination completes or a person must act (`Waiting: ...`);
//! - [`status`] and [`explain`] render the same observations read-only;
//! - [`review`] signs the pending qualification review or completion
//!   approval with the `[reviewer]` key;
//! - [`fitness`] records and inspects maintainer-wide fitness attestations.
//!
//! [`observe`] gathers planner facts, [`keys`] renders configured keys as
//! leaf trust inputs, [`evidence`] signs release-evidence envelopes through
//! the configured external signer, and [`surface_metadata`] prepares the TUF
//! metadata, release record, and timestamp a surface's first publication
//! carries.

mod advance;
mod evidence;
mod explain;
mod fitness;
mod keys;
mod new;
mod observe;
mod planner;
mod review;
mod status;
mod steps;
mod surface_metadata;
mod workdir;

#[cfg(test)]
mod testing;

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::manifest::ManifestEnvelopeV1;
use aos_release::plan::{ReleasePlan, ReleasePlanRequest};

use super::capture;
use super::config::MaintainerConfig;
use crate::cli::{ReleaseCommand, ReleaseFitnessCommand};
use workdir::{ReleaseIndex, WorkDir};

/// Runs a porcelain command that needs no Nix environment.
///
/// # Errors
/// Returns an error when the command fails, or when it requires Nix.
pub(super) async fn run_offline(command: &ReleaseCommand, printer: &Printer) -> Result<()> {
    match command {
        ReleaseCommand::Publish(args) => advance::publish(args, printer).await,
        ReleaseCommand::Status(args) => status::run(args, printer),
        ReleaseCommand::Explain(args) => explain::run(args, printer),
        ReleaseCommand::Review(args) => review::run(args, printer).await,
        ReleaseCommand::Fitness { command } => match command {
            ReleaseFitnessCommand::Run(args) => fitness::run(args, printer).await,
            ReleaseFitnessCommand::Status(args) => fitness::status(args, printer),
        },
        ReleaseCommand::New(_) | ReleaseCommand::Advance(_) => {
            bail!("this release command evaluates Nix and must use the Nix dispatcher")
        }
        ReleaseCommand::Step { .. } => bail!("release steps are not porcelain commands"),
    }
}

/// Runs a porcelain command that evaluates Nix.
///
/// # Errors
/// Returns an error when the command fails.
pub(super) async fn run_with_nix(
    command: &ReleaseCommand,
    nix: &NixRunner,
    printer: &Printer,
) -> Result<()> {
    match command {
        ReleaseCommand::New(args) => new::run(args, nix, printer).await,
        ReleaseCommand::Advance(args) => advance::run(args, nix, printer).await,
        _ => run_offline(command, printer).await,
    }
}

/// One release opened from the maintainer configuration and its work directory.
struct Session {
    /// Path of the configuration actually read.
    config_path: PathBuf,
    /// Parsed maintainer configuration.
    config: MaintainerConfig,
    /// The release's work directory.
    work: WorkDir,
    /// The work directory's index.
    index: ReleaseIndex,
    /// Exact frozen plan bytes.
    plan_bytes: Vec<u8>,
    /// Parsed frozen plan.
    plan: ReleasePlan,
    /// Whether the request planned a registry's first release, whose base
    /// `step bootstrap` must install on each surface before publication.
    first_release: bool,
}

impl Session {
    /// Opens the configured release selected by `work`.
    ///
    /// # Errors
    /// Returns an error when the configuration or work directory cannot be
    /// read, the plan is invalid, or the configuration, index, and plan name
    /// different registries or releases.
    fn open(config: Option<&Path>, work: Option<&Path>) -> Result<Self> {
        let (config_path, config) = MaintainerConfig::load(config)?;
        let work = WorkDir::select(&config, work)?;
        let index = work.read_index()?;
        let plan_bytes = capture::control_file(&work.plan(), "release plan")
            .with_context(|| format!("{} has no frozen plan", work.root().display()))?;
        canonical::require_canonical(&plan_bytes, "release plan")?;
        let plan: ReleasePlan = canonical::from_slice(&plan_bytes, "release plan")?;
        plan.validate()?;
        if plan.registry != config.registry || index.registry != config.registry {
            bail!(
                "work directory {} belongs to registry {}, not the configured {}",
                work.root().display(),
                plan.registry,
                config.registry
            );
        }
        if plan.release_id != index.release_id || plan.version != index.version {
            bail!("release.toml and plan.json name different releases");
        }
        let first_release = planned_first_release(&work, &plan)?;
        Ok(Self {
            config_path,
            config,
            work,
            index,
            plan_bytes,
            plan,
            first_release,
        })
    }

    /// Returns the signed manifest payload once the bundle is finalized.
    ///
    /// # Errors
    /// Returns an error for an unreadable or malformed manifest envelope.
    fn manifest(&self) -> Result<Option<ManifestEnvelopeV1>> {
        let path = self.work.bundle().join("release-manifest.json");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = capture::control_file(&path, "release manifest")?;
        Ok(Some(canonical::from_slice(&bytes, "release manifest")?))
    }

    /// Resolves the planned destination named on the command line.
    ///
    /// # Errors
    /// Returns an error for a destination the plan does not contain.
    fn destination(&self, name: &str) -> Result<&aos_release::plan::PlannedDestination> {
        self.plan.destination(name).with_context(|| {
            let planned: Vec<&str> = self
                .plan
                .destinations
                .iter()
                .map(|destination| destination.name.as_str())
                .collect();
            format!("planned destinations: {}", planned.join(", "))
        })
    }
}

/// Reads whether the release's request planned a registry's first release.
///
/// `new` writes the request before it freezes the plan, so a work directory
/// without one, or with a request for another release or base, is refused
/// rather than treated as an ordinary release.
///
/// # Errors
/// Returns an error for a missing or malformed request, or one that names a
/// different release or registry base than the plan.
fn planned_first_release(work: &WorkDir, plan: &ReleasePlan) -> Result<bool> {
    let bytes = capture::control_file(&work.request(), "plan request")
        .with_context(|| format!("{} has no derived request", work.root().display()))?;
    let request: ReleasePlanRequest = canonical::from_slice(&bytes, "plan request")?;
    if request.release_id != plan.release_id
        || request.registry != plan.registry
        || request.registry_base_commit != plan.registry_base_commit
    {
        bail!("request.json and plan.json name different releases or registry bases");
    }
    Ok(request.first_release)
}

/// Prints the single `Waiting:` instruction of a human step.
pub(super) fn print_waiting(printer: &Printer, instruction: &str) {
    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.porcelain-result/v1",
        "waiting": instruction,
    })) {
        return;
    }
    println!("Waiting: {instruction}");
}
