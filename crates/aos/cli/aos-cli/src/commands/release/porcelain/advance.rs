//! `aos maintain release advance --to <destination>`: drive a release forward.
//!
//! The driver is a loop over [`observe`] and [`planner::next`]: observe the
//! journal and work directory, compute the next step, run it in process, and
//! repeat until the destination completes, `--ring N` stops the rollout, or
//! a person must act. A human step prints exactly one `Waiting:` line and
//! exits zero; rerunning resumes where the work directory left off because
//! every step is recognized by its durable output and journal state.
//!
//! `--override DIR` re-freezes the plan with signed profile-override
//! envelopes while nothing has been built (the superseded plan stays in the
//! work directory as `plan.superseded-<n>.json`).

use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context as _, Result, bail, ensure};
use aos_cli_ui::output::Printer;
use aos_nix::NixRunner;
use aos_release_format::plan::SurfaceRole;
use aos_release_format::signing::SignerRole;

use super::super::tooling::ToolingEnvironment;
use super::super::{capture, plan};
use super::planner::{self, Next, Options, Step};
use super::steps::Driver;
use super::workdir::{self, Phase, WorkDir, digest_string};
use super::{Session, keys, observe, print_waiting};
use crate::cli::{ReleaseAdvanceArgs, ReleaseDestinationArgs, ReleasePlanArgs};

/// Upper bound on steps one invocation runs; each step changes durable state.
const MAX_STEPS: usize = 512;

/// Drives the selected release toward `--to`.
///
/// # Errors
/// Returns the failing step's leaf error prefixed with the step name, or an
/// error for an invalid destination, ring, override, or work directory.
pub(super) async fn run(
    args: &ReleaseAdvanceArgs,
    nix: &NixRunner,
    printer: &Printer,
) -> Result<()> {
    // Every automated step runs from the installed tooling closure; a
    // development build may inspect a release but never drive one.
    ToolingEnvironment::require()?;
    let mut session = Session::open(args.config.as_deref(), args.work.as_deref())?;
    let destination = session.destination(&args.to)?.clone();
    if let Some(ring) = args.ring
        && (ring == 0 || usize::from(ring) > destination.rings.len())
    {
        bail!(
            "{} has rings 1..={}; --ring {ring} is outside the plan",
            destination.name,
            destination.rings.len()
        );
    }
    if args.stop_after_upload {
        let prior_state = session
            .work
            .latest_journal(&session.plan)?
            .and_then(|(_, journal)| journal.summary.state_of(&destination.name));
        require_unpublished_upload_target(prior_state, &destination.name)?;
    }

    warn_on_config_drift(&session, printer)?;
    if let Some(directory) = &args.override_dir {
        refreeze_with_override(&session, directory, nix, printer)?;
        session = Session::open(args.config.as_deref(), args.work.as_deref())?;
    }

    let driver = Driver {
        session: &session,
        nix: Some(nix),
        printer,
    };
    let mut previous: Option<Step> = None;
    for _ in 0..MAX_STEPS {
        let observation = observe::release(&session)?;
        if let Some((path, _)) = &observation.journal {
            session.work.record_latest_journal(path)?;
        }
        let facts = observe::destination(&session, &observation, &destination)?;
        let options = Options {
            accept_transaction: args.accept_transaction,
            ring_limit: args.ring,
            now: SystemTime::now(),
        };
        match planner::next(&observation.release, &facts, &options)? {
            Next::Run(Step::Publish) if args.stop_after_upload => {
                super::steps::publish_destination(
                    &session,
                    &destination,
                    &observation,
                    true,
                    args.stage_revision,
                    printer,
                )
                .await?;
                printer.success(&format!(
                    "{} is fully uploaded and unreleased; run aos maintain release publish --to {} --work {}",
                    destination.name,
                    destination.name,
                    session.work.root().display()
                ));
                return Ok(());
            }
            Next::Run(step) => {
                let label = step.describe(&destination.name);
                if previous.as_ref() == Some(&step) {
                    bail!(
                        "{label} completed without changing the release state; inspect the work directory"
                    );
                }
                printer.info(&format!("Running {label}"));
                driver
                    .execute(&step, &destination, &observation)
                    .await
                    .with_context(|| failure_context(&session, &destination.name, &step, &label))?;
                previous = Some(step);
            }
            Next::Wait(instruction) => {
                print_waiting(printer, &instruction);
                return Ok(());
            }
            Next::Done(message) => {
                printer.success(&message);
                return Ok(());
            }
        }
    }
    bail!("advance ran {MAX_STEPS} steps without reaching a stopping point")
}

/// Names the failed step and, for a failed admission, how to recollect.
///
/// A collected report can expire before it is admitted (rollout reports
/// must be reviewed promptly); the driver never discards it on its own.
fn failure_context(session: &Session, destination: &str, step: &Step, label: &str) -> String {
    match step {
        Step::Admit(phase) => {
            let directory = session.work.phase(destination, *phase);
            format!(
                "{label} failed; if the collected report expired, move {} aside (for example \
                 to {}.retired-<n>) and rerun advance to recollect it",
                session.work.relative(&directory),
                phase.directory_name()
            )
        }
        Step::Publish
            if session
                .plan
                .destination(destination)
                .is_ok_and(|planned| planned.surface == SurfaceRole::Production) =>
        {
            let directory = session.work.phase(destination, Phase::Staging);
            format!(
                "{label} failed; if its staging qualification expired, move {} aside and rerun \
                 advance to recollect it",
                session.work.relative(&directory)
            )
        }
        Step::Tuf => format!(
            "{label} failed; if the surface published other TUF metadata since, rerun advance \
             to observe it again"
        ),
        Step::RefreshTimestamp | Step::ComposeSurface | Step::PublishTimestamp => {
            let attempt = session.work.timestamp_attempt(destination);
            format!(
                "{label} failed; if the surface's timestamp moved or the signed timestamp \
                 expired, move {} aside (for example to timestamp.retired-<n>) and rerun \
                 advance to sign its successor",
                session.work.relative(&attempt)
            )
        }
        _ => format!("{label} failed"),
    }
}

/// Warns when the configuration differs from the one `new` froze the plan from.
///
/// Credentials and executors may legitimately change during a release, so
/// this is advisory; everything the plan binds is rechecked by the leaves.
fn warn_on_config_drift(session: &Session, printer: &Printer) -> Result<()> {
    let bytes = capture::control_file(&session.config_path, "maintainer configuration")?;
    if digest_string(&bytes) != session.index.config_digest {
        printer.warning(&format!(
            "maintainer configuration {} differs from the one this release was planned with",
            session.config_path.display()
        ));
    }
    Ok(())
}

/// Re-freezes the plan with the signed overrides in `directory`.
///
/// Accepted only before the build: the build journal binds the plan digest,
/// so a later plan change would orphan every output.
fn refreeze_with_override(
    session: &Session,
    directory: &Path,
    nix: &NixRunner,
    printer: &Printer,
) -> Result<()> {
    let work = &session.work;
    if work.build().exists() {
        bail!("--override is accepted only before the release is built; start a new release");
    }
    if !session.plan.profile_overrides.is_empty() {
        printer.info("The frozen plan already carries its profile override; nothing to re-freeze");
        return Ok(());
    }
    let superseded = superseded_path(work)?;
    workdir::rename_noreplace(&work.plan(), &superseded)?;
    let result = plan::run(
        &ReleasePlanArgs {
            request: work.request(),
            contributor_authorization: work.contributor_authorization(),
            predecessor_manifest: super::new::predecessor_manifest(&session.config),
            overrides: vec![directory.to_path_buf()],
            override_keys: keys::role_specs(&session.config, SignerRole::ReleaseEvidence)?,
            output: work.plan(),
        },
        nix,
        printer,
    );
    if let Err(error) = result {
        // Restore the frozen plan: the override was not accepted.
        if !work.plan().exists() {
            workdir::rename_noreplace(&superseded, &work.plan())?;
        }
        return Err(error.context("re-freezing the plan with the profile override"));
    }
    printer.success(&format!(
        "Re-froze the plan with the profile override; the previous plan is {}",
        work.relative(&superseded)
    ));
    Ok(())
}

/// Returns the first free `plan.superseded-<n>.json` path.
fn superseded_path(work: &WorkDir) -> Result<std::path::PathBuf> {
    (1..=u32::MAX)
        .map(|attempt| work.join(format!("plan.superseded-{attempt}.json")))
        .find(|candidate| !candidate.exists())
        .context("no free superseded-plan name")
}

/// Publishes an uploaded destination after checking every current admission again.
///
/// # Errors
///
/// Returns an error for missing candidate evidence, failed publication or timestamp
/// verification, or a planner state requiring preparation before publication.
pub(super) async fn publish(args: &ReleaseDestinationArgs, printer: &Printer) -> Result<()> {
    let session = Session::open(args.config.as_deref(), args.work.as_deref())?;
    let destination = session.destination(&args.to)?.clone();
    if !session
        .work
        .staged_upload_record(&destination.name)
        .is_file()
    {
        bail!(
            "{} has no completed immutable upload; run aos maintain release advance --to {} --stop-after-upload",
            destination.name,
            destination.name
        );
    }
    if let Some(expected) = args.stage_revision {
        let stage: aos_registry_surface::staging::StageRecord =
            serde_json::from_slice(&capture::control_file(
                &session
                    .work
                    .staged_upload(&destination.name)
                    .join("stage.json"),
                "candidate stage record",
            )?)?;
        stage.revision.validate()?;
        ensure!(
            expected == stage.revision.revision,
            "candidate revision changed: selected {expected}, current {}",
            stage.revision.revision
        );
    }

    let driver = Driver {
        session: &session,
        nix: None,
        printer,
    };
    let mut previous: Option<Step> = None;
    for _ in 0..MAX_STEPS {
        let observation = observe::release(&session)?;
        if let Some((path, _)) = &observation.journal {
            session.work.record_latest_journal(path)?;
        }
        let facts = observe::destination(&session, &observation, &destination)?;
        if facts.state.is_some()
            && facts
                .surface_metadata
                .as_ref()
                .is_none_or(|metadata| metadata.timestamp_published)
        {
            publication_complete(&destination.name, printer);
            return Ok(());
        }
        let options = Options {
            accept_transaction: false,
            ring_limit: None,
            now: SystemTime::now(),
        };
        match planner::next(&observation.release, &facts, &options)? {
            Next::Run(step) if publication_step(&step) => {
                if previous.as_ref() == Some(&step) {
                    bail!(
                        "{} completed without changing the publication state",
                        step.describe(&destination.name)
                    );
                }
                if step == Step::Publish {
                    super::steps::publish_destination(
                        &session,
                        &destination,
                        &observation,
                        false,
                        args.stage_revision,
                        printer,
                    )
                    .await?;
                } else {
                    driver.execute(&step, &destination, &observation).await?;
                }
                previous = Some(step);
            }
            Next::Run(_) if facts.state.is_some() => {
                publication_complete(&destination.name, printer);
                return Ok(());
            }
            Next::Run(step) => bail!(
                "{} must complete before publication; run aos maintain release advance --to {} --stop-after-upload",
                step.describe(&destination.name),
                destination.name
            ),
            Next::Wait(instruction) => bail!("publication is blocked: {instruction}"),
            Next::Done(message) => {
                printer.success(&message);
                return Ok(());
            }
        }
    }
    bail!("publication ran {MAX_STEPS} steps without reaching a stopping point")
}

fn publication_complete(destination: &str, printer: &Printer) {
    printer.success(&format!(
        "{destination} publication is complete; run aos maintain release advance --to {destination} to continue rollout"
    ));
}

/// Limits explicit publication to release visibility and its discovery metadata.
pub(super) fn publication_step(step: &Step) -> bool {
    matches!(
        step,
        Step::Publish
            | Step::PublishTimestamp
            | Step::RefreshTimestamp
            | Step::RetireTimestamp
            | Step::ComposeSurface
    )
}

/// Rejects upload-only continuation once a destination is publicly released.
fn require_unpublished_upload_target(
    state: Option<aos_release::state::ReleaseState>,
    destination: &str,
) -> Result<()> {
    if state.is_some() {
        bail!(
            "{destination} is already published; --stop-after-upload cannot continue its rollout"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_release::state::ReleaseState;

    #[test]
    fn upload_only_resumption_rejects_every_published_distribution_state() {
        assert!(require_unpublished_upload_target(None, "staging/edge").is_ok());
        for state in [
            ReleaseState::Published,
            ReleaseState::Rolling,
            ReleaseState::Complete,
        ] {
            let error = require_unpublished_upload_target(Some(state), "staging/edge")
                .expect_err("upload-only command must stop before rollout effects");
            assert!(error.to_string().contains("already published"));
        }
    }
}
