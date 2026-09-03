//! Local foreground package-maintenance controller and process-boundary renderer.

mod discovery;
mod evidence;
mod git;
mod inventory;
mod materialize;
mod mutation;
mod state;
mod validation;
mod worktree;

use std::collections::BTreeMap;
use std::io::Write as _;

use anyhow::{Context as _, Result};
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_maintain::MAINTENANCE_CLI_V1;
use aos_maintain::inventory::Classification;
use aos_maintain::presentation::{
    CommandCompletion, CommandData, CommandDisposition, Diagnostic, DiagnosticSeverity,
    EffectClass, MaintainCommandResult, NextAction, PrimaryValue, PullRequestDraft,
    escape_terminal,
};
use serde::Serialize;

use crate::cli::{Cli, ColorChoice, MaintainArgs, MaintainCommand, ProgressChoice};

/// Dispatches one recognized maintenance command to a typed completion.
///
/// All expected operational errors become diagnostics in the returned result,
/// so the process boundary emits exactly one completion in human or machine
/// form instead of mixing incremental JSON fragments with an error object.
///
/// # Errors
///
/// Returns an error only when constructing an internally inconsistent command
/// result, which indicates a controller bug rather than an update outcome.
pub async fn run(cli: &Cli, args: &MaintainArgs) -> Result<CommandCompletion> {
    if let Some(problem) = option_conflict(cli, args) {
        return completion(
            command_name(args),
            CommandDisposition::InvalidInvocation,
            CommandData::default(),
            vec![diagnostic(
                "maintain.invalid-output-mode",
                DiagnosticSeverity::Error,
                &problem,
            )],
            Vec::new(),
            Vec::new(),
        );
    }

    match &args.command {
        None => cached_completion("home", args, None),
        Some(MaintainCommand::Inventory(command)) => {
            let evaluated = NixRunner::new(cli.verbose, cli.quiet)
                .and_then(|nix| inventory::evaluate(&nix, command.target.as_deref()))
                .and_then(|envelope| {
                    let store =
                        state::StateStore::open_for_envelope(args.state_dir.as_deref(), &envelope)?;
                    store.write_inventory(&envelope)?;
                    Ok(envelope)
                });
            match evaluated {
                Ok(envelope) => {
                    let mut values = BTreeMap::new();
                    values.insert(
                        "unitCount".to_string(),
                        envelope.inventory.units.len().to_string(),
                    );
                    values.insert(
                        "repositoryState".to_string(),
                        if envelope.content.permits_write_plan() {
                            "clean"
                        } else {
                            "dirty"
                        }
                        .to_string(),
                    );
                    let digest = envelope.inventory_digest.to_string();
                    completion(
                        "inventory",
                        CommandDisposition::Success,
                        CommandData {
                            values,
                            inventory: Some(envelope),
                            discovery: None,
                            plan: None,
                            run: None,
                            runs: Vec::new(),
                            patch: None,
                            evidence: None,
                            pull_request: None,
                        },
                        Vec::new(),
                        vec![PrimaryValue {
                            name: "inventoryDigest".to_string(),
                            value: digest,
                        }],
                        Vec::new(),
                    )
                }
                Err(error) => completion(
                    "inventory",
                    CommandDisposition::OperationFailed,
                    CommandData::default(),
                    vec![diagnostic(
                        "maintain.inventory-evaluation-failed",
                        DiagnosticSeverity::Error,
                        &format!("{error:#}"),
                    )],
                    Vec::new(),
                    vec![NextAction {
                        label: "Inspect the repository and retry".to_string(),
                        argv: vec![
                            "aos".to_string(),
                            "maintain".to_string(),
                            "inventory".to_string(),
                            "--check".to_string(),
                        ],
                        reason: "inventory evaluation did not reach a verified boundary"
                            .to_string(),
                        prerequisites: vec!["resolve the reported diagnostic".to_string()],
                        effect_class: EffectClass::ReadOnly,
                        bound_context: None,
                    }],
                ),
            }
        }
        Some(MaintainCommand::Scan(command)) => {
            let evaluated = NixRunner::new(cli.verbose, cli.quiet)
                .and_then(|nix| inventory::evaluate(&nix, command.target.as_deref()));
            let envelope = match evaluated {
                Ok(envelope) => envelope,
                Err(error) => {
                    return completion(
                        "scan",
                        CommandDisposition::InfrastructureUnavailable,
                        CommandData::default(),
                        vec![diagnostic(
                            "maintain.inventory-evaluation-failed",
                            DiagnosticSeverity::Error,
                            &format!("{error:#}"),
                        )],
                        Vec::new(),
                        Vec::new(),
                    );
                }
            };
            let store = state::StateStore::open_for_envelope(args.state_dir.as_deref(), &envelope)?;
            store.write_inventory(&envelope)?;
            match discovery::scan(&envelope, &store, command.offline).await {
                Ok(outcome) => {
                    let digest = store.write_discovery(&outcome.snapshot)?;
                    scan_completion(envelope, outcome, digest)
                }
                Err(error) => completion(
                    "scan",
                    CommandDisposition::InfrastructureUnavailable,
                    CommandData::default(),
                    vec![diagnostic(
                        "maintain.scan-failed",
                        DiagnosticSeverity::Error,
                        &format!("{error:#}"),
                    )],
                    Vec::new(),
                    Vec::new(),
                ),
            }
        }
        Some(MaintainCommand::Report(command)) => cached_completion("report", args, Some(command)),
        Some(MaintainCommand::Status(command)) => status_command(args, command),
        Some(MaintainCommand::Plan(command)) => plan_command(args, command),
        Some(MaintainCommand::Run(command)) => run_command(cli, args, command).await,
        Some(MaintainCommand::Resume(command)) => resume_command(cli, args, command).await,
        Some(MaintainCommand::Inspect(command)) => inspect_command(args, command),
        Some(MaintainCommand::Diff(command)) => diff_command(args, command),
        Some(MaintainCommand::Abandon(command)) => abandon_command(args, command),
        Some(MaintainCommand::Clean(command)) => clean_command(args, command),
        Some(MaintainCommand::Accept(command)) => accept_command(args, command),
        Some(MaintainCommand::Commit(command)) => commit_command(args, command),
        Some(MaintainCommand::Test(command)) => test_command(args, command),
        Some(MaintainCommand::Evidence(command)) => evidence_command(args, command),
        Some(MaintainCommand::PreparePr(command)) => prepare_pr_command(args, command),
    }
}

fn accept_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainAcceptArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    if run.state == aos_maintain::workflow::RunState::CandidateAccepted {
        return run_view_completion("accept", &store, run, None);
    }
    if run.state != aos_maintain::workflow::RunState::QuickGated {
        return run_view_completion(
            "accept",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "Only an exact quick-gated candidate can be accepted",
            )),
        );
    }
    let digest = git::candidate_digest(&store, &run)?;
    let digest_text = digest.to_string();
    if command.confirm.as_deref() != Some(digest_text.as_str()) {
        let mut completion = run_view_completion(
            "accept",
            &store,
            run.clone(),
            Some((
                CommandDisposition::ActionRequired,
                "Review the candidate diff and confirm its exact patch digest",
            )),
        )?;
        completion.result.next_actions = vec![NextAction {
            label: "Accept this exact candidate".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "accept".to_string(),
                run.run_id.to_string(),
                "--confirm".to_string(),
                digest.to_string(),
            ],
            reason: "acceptance binds the reviewed patch and does not create a commit".to_string(),
            prerequisites: vec!["review `aos maintain diff` output".to_string()],
            effect_class: EffectClass::HumanDecision,
            bound_context: Some(digest.to_string()),
        }];
        return CommandCompletion::new(completion.result);
    }
    run.accepted_candidate = Some(digest);
    run.updated_at_unix = state::now_unix()?;
    store.write_run(&run)?;
    store.transition(
        &mut run,
        aos_maintain::workflow::RunState::CandidateAccepted,
        aos_maintain::workflow::ActorClass::Maintainer,
        state::now_unix()?,
    )?;
    run_view_completion("accept", &store, run, None)
}

fn commit_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainCommitArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    if run.state == aos_maintain::workflow::RunState::Committed {
        return run_view_completion("commit", &store, run, None);
    }
    if run.state != aos_maintain::workflow::RunState::CandidateAccepted {
        return run_view_completion(
            "commit",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "The exact candidate must be accepted before commit",
            )),
        );
    }
    if command.confirm.as_deref() != Some(run.run_id.as_str()) {
        let mut completion = run_view_completion(
            "commit",
            &store,
            run.clone(),
            Some((
                CommandDisposition::ActionRequired,
                "Review the commit effect and repeat the run ID with --confirm",
            )),
        )?;
        completion.result.next_actions = vec![NextAction {
            label: "Commit with maintainer Git identity".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "commit".to_string(),
                run.run_id.to_string(),
                "--confirm".to_string(),
                run.run_id.to_string(),
            ],
            reason: "Git hooks are disabled; configured identity and signing policy are retained"
                .to_string(),
            prerequisites: vec!["accepted exact candidate".to_string()],
            effect_class: EffectClass::HumanDecision,
            bound_context: run.accepted_candidate.map(|digest| digest.to_string()),
        }];
        return CommandCompletion::new(completion.result);
    }
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    match git::commit_candidate(&store, &plan, &mut run) {
        Ok(commit) => {
            let mut completion = run_view_completion("commit", &store, run, None)?;
            completion.result.primary_values.push(PrimaryValue {
                name: "candidateCommit".to_string(),
                value: commit.value,
            });
            CommandCompletion::new(completion.result)
        }
        Err(error) => stopped_run_completion(
            "commit",
            CommandDisposition::ActionRequired,
            store
                .read_inventory()?
                .ok_or_else(|| anyhow::anyhow!("run inventory is unavailable"))?,
            plan,
            run,
            "maintain.commit-blocked",
            &format!("{error:#}"),
        ),
    }
}

fn test_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainTestArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    let final_phase = if command.quick {
        false
    } else {
        command.final_gate
    };
    let results = if final_phase {
        validation::final_gates(&store, &plan, &mut run)
    } else {
        validation::quick(&store, &plan, &mut run)
    };
    match results {
        Ok(results) if results.all_succeeded() => run_view_completion("test", &store, run, None),
        Ok(_) => run_view_completion(
            "test",
            &store,
            run,
            Some((
                CommandDisposition::OperationFailed,
                "One or more planned gates failed",
            )),
        ),
        Err(error) => run_view_completion(
            "test",
            &store,
            run,
            Some((CommandDisposition::ActionRequired, &format!("{error:#}"))),
        ),
    }
}

fn evidence_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainRunIdentityArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    let (evidence, digest) = match evidence::generate(&store, &plan, &mut run) {
        Ok(result) => result,
        Err(error) => {
            return run_view_completion(
                "evidence",
                &store,
                run,
                Some((CommandDisposition::ActionRequired, &format!("{error:#}"))),
            );
        }
    };
    let mut completion = run_view_completion("evidence", &store, run, None)?;
    completion.result.data.evidence = Some(evidence);
    completion.result.primary_values.push(PrimaryValue {
        name: "evidenceDigest".to_string(),
        value: digest.to_string(),
    });
    CommandCompletion::new(completion.result)
}

fn prepare_pr_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainRunIdentityArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let run = resolve_run(&store, &command.run)?;
    if run.state != aos_maintain::workflow::RunState::ReadyForPr {
        return run_view_completion(
            "prepare-pr",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "Final local evidence must be complete before PR preparation",
            )),
        );
    }
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    let evidence = store
        .read_evidence(run.run_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run evidence is unavailable"))?;
    let evidence_digest = run
        .evidence_digest
        .ok_or_else(|| anyhow::anyhow!("run evidence digest is unavailable"))?;
    let head = run
        .candidate_commit
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("candidate commit is unavailable"))?;
    let title = format!(
        "pkg: update {} to {}",
        plan.unit_id, plan.target_package_version
    );
    let body = format!(
        "## Package update\n\n- Unit: `{}`\n- Change: `{}` -> `{}`\n- Risk: `{}`\n- Sources: {} resolved and hashed\n- Quick gates: {}/{} passed\n- Final gates: {}/{} passed\n- Candidate commit: `{}`\n- Local evidence: `{}`\n\n## Review\n\n- [ ] Review the package and source changes\n- [ ] Confirm required package-owner or specialist review\n- [ ] Confirm remote contributor authorization and protected checks\n",
        plan.unit_id,
        plan.current_package_version,
        plan.target_package_version,
        risk_name(plan.risk),
        evidence.materialization.sources.len(),
        evidence.quick_gates.results.len(),
        evidence.quick_gates.results.len(),
        evidence.final_gates.results.len(),
        evidence.final_gates.results.len(),
        head.value,
        evidence_digest,
    );
    let mut completion = run_view_completion("prepare-pr", &store, run.clone(), None)?;
    completion.result.data.pull_request = Some(PullRequestDraft {
        branch: run.branch,
        base_branch: "master".to_string(),
        title,
        body,
        head: head.value.clone(),
        evidence_digest,
    });
    CommandCompletion::new(completion.result)
}

fn status_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainStatusArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    if let Some(query) = &command.run {
        let run = resolve_run(&store, query)?;
        return run_view_completion("status", &store, run, None);
    }
    let mut runs = store.list_runs()?;
    if command.active {
        runs.retain(|run| !run.state.is_terminal());
    }
    let mut values = BTreeMap::new();
    values.insert("runCount".to_string(), runs.len().to_string());
    values.insert(
        "activeRunCount".to_string(),
        runs.iter()
            .filter(|run| !run.state.is_terminal())
            .count()
            .to_string(),
    );
    completion(
        "status",
        CommandDisposition::Success,
        CommandData {
            values,
            runs,
            ..CommandData::default()
        },
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

async fn resume_command(
    cli: &Cli,
    args: &MaintainArgs,
    command: &crate::cli::MaintainResumeArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let run = resolve_run(&store, &command.run)?;
    if run.state.is_terminal() {
        return run_view_completion(
            "resume",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "Terminal runs cannot be resumed",
            )),
        );
    }
    let mut completion = run_command(
        cli,
        args,
        &crate::cli::MaintainRunArgs {
            unit: None,
            plan: Some(run.plan_id.to_string()),
            until: command.until,
            worktree: Some(std::path::PathBuf::from(run.worktree)),
        },
    )
    .await?;
    completion.result.command = "resume".to_string();
    CommandCompletion::new(completion.result)
}

fn inspect_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainInspectArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    if let Some(plan_id) = &command.plan {
        let Some(plan) = store.read_plan(plan_id)? else {
            return missing_object("inspect", "immutable plan");
        };
        return completion(
            "inspect",
            CommandDisposition::Success,
            CommandData {
                plan: Some(plan),
                ..CommandData::default()
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
    }
    let query = command
        .run
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("inspect requires a run or plan"))?;
    let run = resolve_run(&store, query)?;
    run_view_completion("inspect", &store, run, None)
}

fn diff_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainRunIdentityArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let run = resolve_run(&store, &command.run)?;
    let Some(bytes) = store.read_patch(run.run_id.as_str())? else {
        return run_view_completion(
            "diff",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "This run has no retained candidate patch yet",
            )),
        );
    };
    let patch = String::from_utf8(bytes).context("retained patch is not UTF-8")?;
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    completion(
        "diff",
        CommandDisposition::Success,
        CommandData {
            plan: Some(plan),
            run: Some(run),
            patch: Some(patch),
            ..CommandData::default()
        },
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

fn abandon_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainRunIdentityArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    if !run.state.is_terminal() {
        store.transition(
            &mut run,
            aos_maintain::workflow::RunState::Abandoned,
            aos_maintain::workflow::ActorClass::Maintainer,
            state::now_unix()?,
        )?;
    }
    run_view_completion("abandon", &store, run, None)
}

fn clean_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainCleanArgs,
) -> Result<CommandCompletion> {
    let (store, coordinates) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    if run.worktree_cleaned {
        return run_view_completion("clean", &store, run, None);
    }
    if !run.state.is_terminal()
        && !matches!(
            run.state,
            aos_maintain::workflow::RunState::ReadyForPr
                | aos_maintain::workflow::RunState::PrPublished
                | aos_maintain::workflow::RunState::AwaitingRemoteAuthorization
                | aos_maintain::workflow::RunState::MergeEligibleObserved
                | aos_maintain::workflow::RunState::MergedObserved
        )
    {
        return run_view_completion(
            "clean",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "Only completed or abandoned runs can be cleaned",
            )),
        );
    }
    if command.confirm.as_deref() != Some(run.run_id.as_str()) {
        let mut result = run_view_completion(
            "clean",
            &store,
            run.clone(),
            Some((
                CommandDisposition::ActionRequired,
                "Review the exact target and repeat its run ID with --confirm",
            )),
        )?;
        result.result.next_actions = vec![NextAction {
            label: "Remove the clean managed worktree".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "clean".to_string(),
                run.run_id.to_string(),
                "--confirm".to_string(),
                run.run_id.to_string(),
            ],
            reason: "cleanup retains the branch and durable evidence".to_string(),
            prerequisites: vec!["clean managed worktree".to_string()],
            effect_class: EffectClass::HumanDecision,
            bound_context: Some(run.plan_digest.to_string()),
        }];
        return CommandCompletion::new(result.result);
    }
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(&run.worktree)
        .args(["status", "--porcelain=v2", "-z"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .context("checking cleanup worktree")?;
    if !status.status.success() || !status.stdout.is_empty() {
        return run_view_completion(
            "clean",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "The managed worktree has uncommitted changes and was not removed",
            )),
        );
    }
    let removed = std::process::Command::new("git")
        .arg("-C")
        .arg(coordinates.root)
        .args(["worktree", "remove"])
        .arg(&run.worktree)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()
        .context("removing managed maintenance worktree")?;
    if !removed.success() {
        anyhow::bail!("Git refused to remove the managed worktree");
    }
    run.worktree_cleaned = true;
    run.updated_at_unix = state::now_unix()?;
    store.write_run(&run)?;
    run_view_completion("clean", &store, run, None)
}

fn cached_completion(
    command: &str,
    args: &MaintainArgs,
    report: Option<&crate::cli::MaintainReportArgs>,
) -> Result<CommandCompletion> {
    use aos_maintain::workflow::DiscoveryDecision;

    let directory = std::env::current_dir().context("resolving current directory")?;
    let coordinates = inventory::repository_coordinates(&directory)?;
    let store = state::StateStore::open(args.state_dir.as_deref(), &coordinates)?;
    let Some(inventory) = store.read_inventory()? else {
        return completion(
            command,
            CommandDisposition::ActionRequired,
            CommandData::default(),
            vec![diagnostic(
                "maintain.inventory-not-cached",
                DiagnosticSeverity::Warning,
                "No cached maintenance inventory is available for this clone",
            )],
            Vec::new(),
            vec![NextAction {
                label: "Evaluate the maintenance inventory".to_string(),
                argv: vec![
                    "aos".to_string(),
                    "maintain".to_string(),
                    "inventory".to_string(),
                    "--check".to_string(),
                ],
                reason: "cached views never evaluate Nix implicitly".to_string(),
                prerequisites: Vec::new(),
                effect_class: EffectClass::ReadOnly,
                bound_context: None,
            }],
        );
    };
    let mut discovery = store.read_discovery()?;
    let inventory_digest = aos_contract::Sha256Digest::of_canonical(
        aos_maintain::MAINTENANCE_INVENTORY_ENVELOPE_V1,
        &inventory,
    )?;
    if discovery
        .as_ref()
        .is_some_and(|snapshot| snapshot.inventory_envelope_digest != inventory_digest)
    {
        discovery = None;
    }
    if let Some(snapshot) = &mut discovery {
        let now = state::now_unix()?;
        if now < snapshot.evaluated_at_unix
            || now.saturating_sub(snapshot.evaluated_at_unix) > 24 * 60 * 60
        {
            for unit in &mut snapshot.units {
                unit.decision = DiscoveryDecision::Unknown;
                for component in &mut unit.components {
                    component.decision = DiscoveryDecision::Unknown;
                    component.selected = None;
                }
            }
        }
        if let Some(report) = report {
            snapshot.units.retain(|unit| {
                let family_matches = report.family.as_ref().is_none_or(|family| {
                    inventory.inventory.units.iter().any(|candidate| {
                        candidate.unit_id.as_str() == unit.unit_id
                            && candidate.family.as_str() == family
                    })
                });
                let state_matches = if report.outdated {
                    unit.decision == DiscoveryDecision::UpdateAvailable
                } else if report.unknown {
                    unit.decision == DiscoveryDecision::Unknown
                } else {
                    true
                };
                family_matches && state_matches
            });
        }
    }

    let mut values = BTreeMap::new();
    values.insert(
        "repositoryState".to_string(),
        if inventory.content.permits_write_plan() {
            "clean"
        } else {
            "dirty"
        }
        .to_string(),
    );
    values.insert("stateRoot".to_string(), store.root().display().to_string());
    values.insert(
        "unitCount".to_string(),
        discovery
            .as_ref()
            .map_or(0, |snapshot| snapshot.units.len())
            .to_string(),
    );
    let mut diagnostics = Vec::new();
    let mut actions = Vec::new();
    if discovery.is_none() {
        diagnostics.push(diagnostic(
            "maintain.discovery-not-cached",
            DiagnosticSeverity::Warning,
            "No matching discovery snapshot is cached",
        ));
        actions.push(NextAction {
            label: "Refresh upstream evidence".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "scan".to_string(),
            ],
            reason: "reports require repository-bound upstream evidence".to_string(),
            prerequisites: Vec::new(),
            effect_class: EffectClass::ReadOnly,
            bound_context: Some(inventory_digest.to_string()),
        });
    }
    completion(
        command,
        CommandDisposition::Success,
        CommandData {
            values,
            inventory: Some(inventory),
            discovery,
            plan: None,
            run: None,
            runs: Vec::new(),
            patch: None,
            evidence: None,
            pull_request: None,
        },
        diagnostics,
        Vec::new(),
        actions,
    )
}

fn scan_completion(
    envelope: aos_maintain::envelope::InventoryEnvelopeV1,
    outcome: discovery::ScanOutcome,
    digest: aos_contract::Sha256Digest,
) -> Result<CommandCompletion> {
    use aos_maintain::workflow::DiscoveryDecision;

    let mut counts = BTreeMap::from([
        ("current".to_string(), 0_u64),
        ("quarantined".to_string(), 0),
        ("unknown".to_string(), 0),
        ("updateAvailable".to_string(), 0),
    ]);
    for unit in &outcome.snapshot.units {
        let key = match unit.decision {
            DiscoveryDecision::Current => "current",
            DiscoveryDecision::UpdateAvailable => "updateAvailable",
            DiscoveryDecision::Unknown => "unknown",
            DiscoveryDecision::Quarantined => "quarantined",
        };
        if let Some(count) = counts.get_mut(key) {
            *count += 1;
        }
    }
    let disposition = if counts["quarantined"] > 0 {
        CommandDisposition::Quarantined
    } else if counts["unknown"] > 0 {
        CommandDisposition::UpstreamUnknown
    } else if counts["updateAvailable"] == 0 {
        CommandDisposition::NoChange
    } else {
        CommandDisposition::Success
    };
    let values = counts
        .into_iter()
        .map(|(key, value)| (key, value.to_string()))
        .chain([(
            "repositoryState".to_string(),
            if envelope.content.permits_write_plan() {
                "clean"
            } else {
                "dirty"
            }
            .to_string(),
        )])
        .collect();
    let diagnostics = outcome
        .warnings
        .iter()
        .map(|warning| {
            diagnostic(
                "maintain.advisory-unavailable",
                DiagnosticSeverity::Warning,
                warning,
            )
        })
        .collect();
    completion(
        "scan",
        disposition,
        CommandData {
            values,
            inventory: Some(envelope),
            discovery: Some(outcome.snapshot),
            plan: None,
            run: None,
            runs: Vec::new(),
            patch: None,
            evidence: None,
            pull_request: None,
        },
        diagnostics,
        vec![PrimaryValue {
            name: "discoverySnapshotDigest".to_string(),
            value: digest.to_string(),
        }],
        Vec::new(),
    )
}

fn plan_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainPlanArgs,
) -> Result<CommandCompletion> {
    use aos_maintain::identity::UnitId;
    use aos_maintain::workflow::DiscoveryDecision;

    let directory = std::env::current_dir().context("resolving current directory")?;
    let coordinates = inventory::repository_coordinates(&directory)?;
    let store = state::StateStore::open(args.state_dir.as_deref(), &coordinates)?;
    let Some(envelope) = store.read_inventory()? else {
        return missing_plan_input("inventory", CommandDisposition::ActionRequired);
    };
    if !envelope.content.permits_write_plan() {
        return completion(
            "plan",
            CommandDisposition::Stale,
            CommandData::default(),
            vec![diagnostic(
                "maintain.plan-dirty-base",
                DiagnosticSeverity::Error,
                "Write plans require an inventory evaluated from a clean committed tree",
            )],
            Vec::new(),
            vec![NextAction {
                label: "Refresh inventory from a clean tree".to_string(),
                argv: vec![
                    "aos".to_string(),
                    "maintain".to_string(),
                    "inventory".to_string(),
                    "--check".to_string(),
                ],
                reason: "dirty source can be inspected but cannot become a write-plan base"
                    .to_string(),
                prerequisites: vec!["clean Git worktree".to_string()],
                effect_class: EffectClass::ReadOnly,
                bound_context: None,
            }],
        );
    }
    let Some(mut snapshot) = store.read_discovery()? else {
        return missing_plan_input("discovery", CommandDisposition::UpstreamUnknown);
    };
    let unit_id = match UnitId::parse(&command.unit) {
        Ok(unit_id) => unit_id,
        Err(error) => {
            return completion(
                "plan",
                CommandDisposition::InvalidInvocation,
                CommandData::default(),
                vec![diagnostic(
                    "maintain.invalid-unit",
                    DiagnosticSeverity::Error,
                    &error.to_string(),
                )],
                Vec::new(),
                Vec::new(),
            );
        }
    };
    let now = state::now_unix()?;
    if let Some(target) = &command.target {
        if let Err(error) = select_explicit_target(&envelope, &mut snapshot, &unit_id, target, now)
        {
            return completion(
                "plan",
                CommandDisposition::InvalidInvocation,
                CommandData::default(),
                vec![diagnostic(
                    "maintain.invalid-target",
                    DiagnosticSeverity::Error,
                    &error.to_string(),
                )],
                Vec::new(),
                Vec::new(),
            );
        }
    }
    let Some(discovered) = snapshot
        .units
        .iter()
        .find(|unit| unit.unit_id == unit_id.as_str())
    else {
        return missing_plan_input("unit discovery", CommandDisposition::UpstreamUnknown);
    };
    match discovered.decision {
        DiscoveryDecision::Current => {
            return completion(
                "plan",
                CommandDisposition::NoChange,
                CommandData::default(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
        }
        DiscoveryDecision::Unknown => {
            return missing_plan_input(
                "complete upstream evidence",
                CommandDisposition::UpstreamUnknown,
            );
        }
        DiscoveryDecision::Quarantined => {
            return missing_plan_input(
                "unconflicted upstream evidence",
                CommandDisposition::Quarantined,
            );
        }
        DiscoveryDecision::UpdateAvailable => {}
    }
    let plan = match aos_maintain::plan::create_plan(&envelope, &snapshot, &unit_id, now) {
        Ok(plan) => plan,
        Err(error) => {
            return completion(
                "plan",
                CommandDisposition::Stale,
                CommandData::default(),
                vec![diagnostic(
                    "maintain.plan-stale-input",
                    DiagnosticSeverity::Error,
                    &error.to_string(),
                )],
                Vec::new(),
                Vec::new(),
            );
        }
    };
    let digest = store.write_plan(&plan)?;
    completion(
        "plan",
        CommandDisposition::Success,
        CommandData {
            values: BTreeMap::new(),
            inventory: Some(envelope),
            discovery: Some(snapshot),
            plan: Some(plan.clone()),
            run: None,
            runs: Vec::new(),
            patch: None,
            evidence: None,
            pull_request: None,
        },
        Vec::new(),
        vec![PrimaryValue {
            name: "planId".to_string(),
            value: plan.plan_id.to_string(),
        }],
        vec![NextAction {
            label: "Create the isolated update worktree".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "run".to_string(),
                "--plan".to_string(),
                plan.plan_id.to_string(),
                "--until".to_string(),
                "worktree-ready".to_string(),
            ],
            reason: "the immutable plan is ready for local execution".to_string(),
            prerequisites: Vec::new(),
            effect_class: EffectClass::LocalMutation,
            bound_context: Some(digest.to_string()),
        }],
    )
}

async fn run_command(
    cli: &Cli,
    args: &MaintainArgs,
    command: &crate::cli::MaintainRunArgs,
) -> Result<CommandCompletion> {
    use aos_contract::Sha256Digest;
    use aos_maintain::presentation::MaintainCommandResult;

    let directory = std::env::current_dir().context("resolving current directory")?;
    let coordinates = inventory::repository_coordinates(&directory)?;
    let store = state::StateStore::open(args.state_dir.as_deref(), &coordinates)?;
    let plan = if let Some(plan_id) = &command.plan {
        match store.read_plan(plan_id)? {
            Some(plan) => plan,
            None => {
                return completion(
                    "run",
                    CommandDisposition::InvalidInvocation,
                    CommandData::default(),
                    vec![diagnostic(
                        "maintain.plan-not-found",
                        DiagnosticSeverity::Error,
                        "The requested immutable plan does not exist in this clone's state",
                    )],
                    Vec::new(),
                    Vec::new(),
                );
            }
        }
    } else {
        let unit = command
            .unit
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("run requires a unit or plan"))?;
        let planned = plan_command(
            args,
            &crate::cli::MaintainPlanArgs {
                unit: unit.clone(),
                target: None,
            },
        )?;
        let Some(plan) = planned.result.data.plan.clone() else {
            let mut result = planned.result;
            result.command = "run".to_string();
            return CommandCompletion::new(result);
        };
        plan
    };

    let now = state::now_unix()?;
    let plan_has_run = store
        .list_runs()?
        .iter()
        .any(|run| run.plan_id == plan.plan_id);
    if now >= plan.expires_at_unix && !plan_has_run {
        return completion(
            "run",
            CommandDisposition::Stale,
            CommandData::default(),
            vec![diagnostic(
                "maintain.plan-expired",
                DiagnosticSeverity::Error,
                "The immutable plan expired before execution began",
            )],
            Vec::new(),
            vec![NextAction {
                label: "Create a fresh plan".to_string(),
                argv: vec![
                    "aos".to_string(),
                    "maintain".to_string(),
                    "plan".to_string(),
                    plan.unit_id.to_string(),
                ],
                reason: "execution cannot extend or reinterpret an expired plan".to_string(),
                prerequisites: vec!["fresh discovery evidence".to_string()],
                effect_class: EffectClass::ReadOnly,
                bound_context: Some(plan.plan_id.to_string()),
            }],
        );
    }
    let Some(envelope) = store.read_inventory()? else {
        return missing_plan_input("inventory", CommandDisposition::Stale);
    };
    let envelope_digest =
        Sha256Digest::of_canonical(aos_maintain::MAINTENANCE_INVENTORY_ENVELOPE_V1, &envelope)?;
    if envelope_digest != plan.inventory_envelope_digest || envelope.controller != plan.controller {
        return completion(
            "run",
            CommandDisposition::Stale,
            CommandData::default(),
            vec![diagnostic(
                "maintain.plan-controller-mismatch",
                DiagnosticSeverity::Error,
                "Cached inventory or controller identity no longer matches the immutable plan",
            )],
            Vec::new(),
            Vec::new(),
        );
    }
    let mut run = match worktree::ensure(
        &store,
        &coordinates.root,
        &plan,
        command.worktree.as_deref(),
    ) {
        Ok(run) => run,
        Err(error) => {
            return completion(
                "run",
                CommandDisposition::ActionRequired,
                CommandData::default(),
                vec![diagnostic(
                    "maintain.worktree-reconciliation-required",
                    DiagnosticSeverity::Error,
                    &format!("{error:#}"),
                )],
                Vec::new(),
                Vec::new(),
            );
        }
    };

    let mut values = BTreeMap::from([
        ("branch".to_string(), run.branch.clone()),
        ("worktree".to_string(), run.worktree.clone()),
        ("repositoryState".to_string(), "clean".to_string()),
    ]);
    if command.until != crate::cli::MaintainRunUntil::WorktreeReady {
        let materialization =
            match materialize::execute(&store, &plan, &mut run, cli.verbose, cli.quiet).await {
                Ok(record) => record,
                Err(error) => {
                    return stopped_run_completion(
                        "run",
                        CommandDisposition::ActionRequired,
                        envelope,
                        plan,
                        run,
                        "maintain.materialization-blocked",
                        &format!("{error:#}"),
                    );
                }
            };
        values.insert(
            "patchDigest".to_string(),
            materialization.patch_digest.to_string(),
        );
        values.insert(
            "downloadBytes".to_string(),
            materialization
                .sources
                .iter()
                .map(|source| source.bytes)
                .sum::<u64>()
                .to_string(),
        );
    }
    if command.until == crate::cli::MaintainRunUntil::QuickGated {
        let gates = match validation::quick(&store, &plan, &mut run) {
            Ok(gates) => gates,
            Err(error) => {
                return stopped_run_completion(
                    "run",
                    CommandDisposition::ActionRequired,
                    envelope,
                    plan,
                    run,
                    "maintain.quick-gates-blocked",
                    &format!("{error:#}"),
                );
            }
        };
        let passed = gates
            .results
            .iter()
            .filter(|result| result.outcome == aos_maintain::workflow::GateOutcome::Success)
            .count();
        values.insert("gatesPassed".to_string(), passed.to_string());
        values.insert("gatesTotal".to_string(), gates.results.len().to_string());
        if !gates.all_succeeded() {
            return stopped_run_completion(
                "run",
                CommandDisposition::OperationFailed,
                envelope,
                plan,
                run,
                "maintain.quick-gate-failed",
                "One or more planned quick gates failed; retained logs are available for inspection",
            );
        }
    }

    let plan_digest = Sha256Digest::of_canonical(aos_maintain::PACKAGE_UPDATE_PLAN_V1, &plan)?;
    let result = MaintainCommandResult {
        schema_version: MAINTENANCE_CLI_V1.to_string(),
        command: "run".to_string(),
        disposition: CommandDisposition::Success,
        exit_code: CommandDisposition::Success.exit_code(),
        run_id: Some(run.run_id.clone()),
        data: CommandData {
            values,
            inventory: Some(envelope),
            discovery: None,
            plan: Some(plan),
            run: Some(run.clone()),
            runs: Vec::new(),
            patch: None,
            evidence: None,
            pull_request: None,
        },
        primary_values: vec![PrimaryValue {
            name: "runId".to_string(),
            value: run.run_id.to_string(),
        }],
        diagnostics: Vec::new(),
        next_actions: vec![NextAction {
            label: "Inspect the isolated update worktree".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "status".to_string(),
                run.run_id.to_string(),
            ],
            reason: format!(
                "the run reached {} at the requested {:?} boundary",
                run_state_name(run.state),
                command.until
            ),
            prerequisites: Vec::new(),
            effect_class: EffectClass::ReadOnly,
            bound_context: Some(plan_digest.to_string()),
        }],
    };
    CommandCompletion::new(result)
}

fn stopped_run_completion(
    command: &str,
    disposition: CommandDisposition,
    envelope: aos_maintain::envelope::InventoryEnvelopeV1,
    plan: aos_maintain::plan::PackageUpdatePlanV1,
    run: aos_maintain::run::PackageUpdateRunV1,
    code: &str,
    summary: &str,
) -> Result<CommandCompletion> {
    CommandCompletion::new(MaintainCommandResult {
        schema_version: MAINTENANCE_CLI_V1.to_string(),
        command: command.to_string(),
        disposition,
        exit_code: disposition.exit_code(),
        run_id: Some(run.run_id.clone()),
        data: CommandData {
            values: BTreeMap::from([
                ("branch".to_string(), run.branch.clone()),
                ("worktree".to_string(), run.worktree.clone()),
            ]),
            inventory: Some(envelope),
            discovery: None,
            plan: Some(plan),
            run: Some(run.clone()),
            runs: Vec::new(),
            patch: None,
            evidence: None,
            pull_request: None,
        },
        primary_values: vec![PrimaryValue {
            name: "runId".to_string(),
            value: run.run_id.to_string(),
        }],
        diagnostics: vec![diagnostic(code, DiagnosticSeverity::Error, summary)],
        next_actions: vec![NextAction {
            label: "Inspect the stopped run".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "status".to_string(),
                run.run_id.to_string(),
            ],
            reason: "durable state identifies the last verified boundary".to_string(),
            prerequisites: Vec::new(),
            effect_class: EffectClass::ReadOnly,
            bound_context: Some(run.plan_digest.to_string()),
        }],
    })
}

fn current_store(
    args: &MaintainArgs,
) -> Result<(state::StateStore, inventory::RepositoryCoordinates)> {
    let directory = std::env::current_dir().context("resolving current directory")?;
    let coordinates = inventory::repository_coordinates(&directory)?;
    let store = state::StateStore::open(args.state_dir.as_deref(), &coordinates)?;
    Ok((store, coordinates))
}

fn resolve_run(
    store: &state::StateStore,
    query: &str,
) -> Result<aos_maintain::run::PackageUpdateRunV1> {
    if let Some(run) = store.read_run(query)? {
        return Ok(run);
    }
    let matches = store
        .list_runs()?
        .into_iter()
        .filter(|run| run.run_id.as_str().starts_with(query))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [run] => Ok(run.clone()),
        [] => anyhow::bail!("no local maintenance run matches {query}"),
        _ => anyhow::bail!("maintenance run prefix {query} is ambiguous"),
    }
}

fn run_view_completion(
    command: &str,
    store: &state::StateStore,
    run: aos_maintain::run::PackageUpdateRunV1,
    stopped: Option<(CommandDisposition, &str)>,
) -> Result<CommandCompletion> {
    let events = store.read_journal(run.run_id.as_str())?;
    let state = aos_maintain::workflow::verify_journal(&events)?;
    if state != run.state {
        anyhow::bail!("run projection disagrees with its verified journal");
    }
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    let mut values = BTreeMap::from([
        ("branch".to_string(), run.branch.clone()),
        ("worktree".to_string(), run.worktree.clone()),
        ("journalEvents".to_string(), events.len().to_string()),
    ]);
    if let Some(gates) = store.read_gate_results(run.run_id.as_str(), "quick")? {
        values.insert("gatesTotal".to_string(), gates.results.len().to_string());
        values.insert(
            "gatesPassed".to_string(),
            gates
                .results
                .iter()
                .filter(|result| result.outcome == aos_maintain::workflow::GateOutcome::Success)
                .count()
                .to_string(),
        );
    }
    let evidence = store.read_evidence(run.run_id.as_str())?;
    let (disposition, diagnostics) = stopped.map_or(
        (CommandDisposition::Success, Vec::new()),
        |(disposition, summary)| {
            (
                disposition,
                vec![diagnostic(
                    "maintain.run-stopped",
                    DiagnosticSeverity::Error,
                    summary,
                )],
            )
        },
    );
    CommandCompletion::new(MaintainCommandResult {
        schema_version: MAINTENANCE_CLI_V1.to_string(),
        command: command.to_string(),
        disposition,
        exit_code: disposition.exit_code(),
        run_id: Some(run.run_id.clone()),
        data: CommandData {
            values,
            plan: Some(plan),
            run: Some(run.clone()),
            evidence,
            ..CommandData::default()
        },
        primary_values: vec![PrimaryValue {
            name: "runId".to_string(),
            value: run.run_id.to_string(),
        }],
        diagnostics,
        next_actions: next_actions_for_run(&run),
    })
}

fn next_actions_for_run(run: &aos_maintain::run::PackageUpdateRunV1) -> Vec<NextAction> {
    use aos_maintain::workflow::RunState;

    let (label, tail, reason, effect_class) = match run.state {
        RunState::WorktreeReady => (
            "Materialize the planned update",
            vec!["resume", run.run_id.as_str(), "--until", "materialized"],
            "download, hash, and apply only the immutable source intents",
            EffectClass::LocalMutation,
        ),
        RunState::PolicyValid => (
            "Run the planned quick gates",
            vec!["test", run.run_id.as_str(), "--quick"],
            "validate the exact retained candidate patch",
            EffectClass::LocalMutation,
        ),
        RunState::QuickGated => (
            "Review and accept the candidate",
            vec!["accept", run.run_id.as_str()],
            "acceptance requires the exact displayed patch digest",
            EffectClass::HumanDecision,
        ),
        RunState::CandidateAccepted => (
            "Review and commit the candidate",
            vec!["commit", run.run_id.as_str()],
            "commit creation requires a second operation-specific confirmation",
            EffectClass::HumanDecision,
        ),
        RunState::Committed => (
            "Run the complete final gate plan",
            vec!["test", run.run_id.as_str(), "--final"],
            "final results bind the exact candidate commit",
            EffectClass::LocalMutation,
        ),
        RunState::FinalGated => (
            "Generate the final local evidence",
            vec!["evidence", run.run_id.as_str()],
            "the dossier cross-checks the plan, journal, patch, commit, and gates",
            EffectClass::LocalMutation,
        ),
        RunState::ReadyForPr => (
            "Prepare the pull request offline",
            vec!["prepare-pr", run.run_id.as_str()],
            "review title, body, branch, head, and evidence before publication",
            EffectClass::ReadOnly,
        ),
        _ => return Vec::new(),
    };
    let mut argv = vec!["aos".to_string(), "maintain".to_string()];
    argv.extend(tail.into_iter().map(str::to_string));
    vec![NextAction {
        label: label.to_string(),
        argv,
        reason: reason.to_string(),
        prerequisites: Vec::new(),
        effect_class,
        bound_context: Some(run.plan_digest.to_string()),
    }]
}

fn missing_object(command: &str, label: &str) -> Result<CommandCompletion> {
    completion(
        command,
        CommandDisposition::InvalidInvocation,
        CommandData::default(),
        vec![diagnostic(
            "maintain.object-not-found",
            DiagnosticSeverity::Error,
            &format!("The requested {label} does not exist in this clone's state"),
        )],
        Vec::new(),
        Vec::new(),
    )
}

fn missing_plan_input(label: &str, disposition: CommandDisposition) -> Result<CommandCompletion> {
    completion(
        "plan",
        disposition,
        CommandData::default(),
        vec![diagnostic(
            "maintain.plan-input-unavailable",
            DiagnosticSeverity::Error,
            &format!("Required {label} is unavailable"),
        )],
        Vec::new(),
        Vec::new(),
    )
}

fn select_explicit_target(
    envelope: &aos_maintain::envelope::InventoryEnvelopeV1,
    snapshot: &mut aos_maintain::discovery::DiscoverySnapshotV1,
    unit_id: &aos_maintain::identity::UnitId,
    target: &str,
    now_unix: u64,
) -> Result<()> {
    use aos_maintain::workflow::DiscoveryDecision;

    let unit = envelope
        .inventory
        .units
        .iter()
        .find(|unit| &unit.unit_id == unit_id)
        .ok_or_else(|| anyhow::anyhow!("unknown update unit {unit_id}"))?;
    if unit.components.len() != 1 {
        anyhow::bail!("--target is valid only for one-component update units");
    }
    let (component_id, _) = unit
        .components
        .first_key_value()
        .ok_or_else(|| anyhow::anyhow!("update unit has no components"))?;
    let key = format!("{unit_id}/{component_id}/primary");
    let observation = snapshot
        .observations
        .get(&key)
        .ok_or_else(|| anyhow::anyhow!("primary observation is unavailable"))?;
    let matches = observation
        .candidates
        .iter()
        .filter(|candidate| candidate.raw_id == target || candidate.raw_version == target)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        anyhow::bail!("explicit target must match exactly one observed candidate");
    }
    let matched = matches
        .first()
        .ok_or_else(|| anyhow::anyhow!("explicit target disappeared during selection"))?;
    let mut exact_observation = observation.clone();
    exact_observation
        .candidates
        .retain(|candidate| candidate.raw_id == matched.raw_id);
    let selected = aos_maintain::discovery::select_unit(
        unit,
        &BTreeMap::from([(component_id.to_string(), exact_observation)]),
        now_unix,
        24 * 60 * 60,
    )?;
    if selected.decision != DiscoveryDecision::UpdateAvailable {
        anyhow::bail!("explicit target is not selectable under current unit policy");
    }
    let discovery = snapshot
        .units
        .iter_mut()
        .find(|unit| unit.unit_id == unit_id.as_str())
        .ok_or_else(|| anyhow::anyhow!("unit discovery is unavailable"))?;
    *discovery = selected;
    Ok(())
}

/// Renders exactly one typed completion at the process boundary.
///
/// # Errors
///
/// Returns an error when JSON serialization or writing the selected output
/// stream fails.
pub fn render(
    cli: &Cli,
    args: &MaintainArgs,
    completion: &CommandCompletion,
    printer: &Printer,
) -> Result<()> {
    if cli.json {
        write_json(&completion.result)?;
        return Ok(());
    }
    if args.jsonl {
        write_json(&StreamEnvelope {
            schema_version: "aos.maintain.stream/v1",
            stream_sequence: 1,
            event_type: "result",
            result: &completion.result,
        })?;
        return Ok(());
    }

    render_human(&completion.result, args.screen_reader, printer);
    Ok(())
}

fn completion(
    command: &str,
    disposition: CommandDisposition,
    data: CommandData,
    diagnostics: Vec<Diagnostic>,
    primary_values: Vec<PrimaryValue>,
    next_actions: Vec<NextAction>,
) -> Result<CommandCompletion> {
    CommandCompletion::new(MaintainCommandResult {
        schema_version: MAINTENANCE_CLI_V1.to_string(),
        command: command.to_string(),
        disposition,
        exit_code: disposition.exit_code(),
        run_id: None,
        data,
        primary_values,
        diagnostics,
        next_actions,
    })
}

fn diagnostic(code: &str, severity: DiagnosticSeverity, summary: &str) -> Diagnostic {
    Diagnostic {
        code: code.to_string(),
        severity,
        summary: summary.to_string(),
        detail: None,
        span: None,
        remediation: None,
    }
}

fn command_name(args: &MaintainArgs) -> &'static str {
    match &args.command {
        None => "home",
        Some(MaintainCommand::Inventory(_)) => "inventory",
        Some(MaintainCommand::Scan(_)) => "scan",
        Some(MaintainCommand::Report(_)) => "report",
        Some(MaintainCommand::Status(_)) => "status",
        Some(MaintainCommand::Plan(_)) => "plan",
        Some(MaintainCommand::Run(_)) => "run",
        Some(MaintainCommand::Resume(_)) => "resume",
        Some(MaintainCommand::Inspect(_)) => "inspect",
        Some(MaintainCommand::Diff(_)) => "diff",
        Some(MaintainCommand::Abandon(_)) => "abandon",
        Some(MaintainCommand::Clean(_)) => "clean",
        Some(MaintainCommand::Accept(_)) => "accept",
        Some(MaintainCommand::Commit(_)) => "commit",
        Some(MaintainCommand::Test(_)) => "test",
        Some(MaintainCommand::Evidence(_)) => "evidence",
        Some(MaintainCommand::PreparePr(_)) => "prepare-pr",
    }
}

fn option_conflict(cli: &Cli, args: &MaintainArgs) -> Option<String> {
    if cli.json && args.jsonl {
        return Some("--json cannot be combined with --jsonl".to_string());
    }
    if let Some(MaintainCommand::Report(report)) = &args.command
        && report.outdated
        && report.unknown
    {
        return Some("--outdated cannot be combined with --unknown".to_string());
    }
    if let Some(MaintainCommand::Status(status)) = &args.command
        && status.run.is_some()
        && status.active
    {
        return Some("RUN cannot be combined with --active".to_string());
    }
    let machine = cli.json || args.jsonl;
    if machine && !matches!(cli.progress, ProgressChoice::Auto | ProgressChoice::Off) {
        return Some("machine output requires --progress auto or --progress off".to_string());
    }
    if args.screen_reader && cli.progress == ProgressChoice::Tty {
        return Some("--screen-reader cannot be combined with --progress tty".to_string());
    }
    if args.screen_reader && cli.color == ColorChoice::Always {
        return Some("--screen-reader cannot be combined with --color always".to_string());
    }
    if std::env::var("TERM").is_ok_and(|term| term == "dumb") && cli.progress == ProgressChoice::Tty
    {
        return Some("TERM=dumb cannot be combined with --progress tty".to_string());
    }
    None
}

fn render_human(result: &MaintainCommandResult, screen_reader: bool, printer: &Printer) {
    let title = if screen_reader {
        "AOS package maintenance"
    } else {
        "AOS Package Maintenance"
    };
    printer.header(title);
    printer.kv("Command", &result.command);
    printer.kv("Disposition", disposition_name(result.disposition));

    if let Some(envelope) = &result.data.inventory {
        let repository_state = result
            .data
            .values
            .get("repositoryState")
            .map(String::as_str)
            .unwrap_or("unknown");
        printer.kv("Repository", repository_state);
        printer.kv("Inventory", &envelope.inventory_digest.to_string());
        let unit_count = result
            .data
            .values
            .get("unitCount")
            .cloned()
            .unwrap_or_else(|| envelope.inventory.units.len().to_string());
        printer.kv("Units", &unit_count);
        if result.command == "inventory" {
            printer.plain("");
            for unit in &envelope.inventory.units {
                let current = unit
                    .package
                    .as_ref()
                    .map(|package| package.current_version.as_str())
                    .unwrap_or("local");
                printer.plain(&format!(
                    "{}  current={}  stream={}  classification={}",
                    escape_terminal(unit.unit_id.as_str(), 256),
                    escape_terminal(current, 256),
                    escape_terminal(&unit.stream, 256),
                    classification_name(unit.classification),
                ));
            }
        }
    }

    if let Some(snapshot) = &result.data.discovery {
        printer.plain("");
        printer.header("Discovery");
        for unit in &snapshot.units {
            let candidate = unit
                .components
                .iter()
                .find_map(|component| component.selected.as_ref())
                .map(|version| version.comparison_version.as_str())
                .unwrap_or("-");
            printer.plain(&format!(
                "{}  candidate={}  discovery={}",
                escape_terminal(&unit.unit_id, 256),
                escape_terminal(candidate, 256),
                discovery_name(unit.decision),
            ));
        }
    }

    if let Some(plan) = &result.data.plan {
        printer.plain("");
        printer.header("Plan");
        printer.kv("ID", plan.plan_id.as_str());
        printer.kv(
            "Change",
            &format!(
                "{} -> {}",
                escape_terminal(&plan.current_package_version, 256),
                escape_terminal(&plan.target_package_version, 256)
            ),
        );
        let owner = plan
            .semantic_mutations
            .first()
            .map(|mutation| mutation.owner.as_str())
            .unwrap_or("unknown");
        printer.kv("Owner", &escape_terminal(owner, 4096));
        printer.kv("Fields", &plan.semantic_mutations.len().to_string());
        printer.kv("Sources", &plan.sources.len().to_string());
        printer.kv("Quick gates", &plan.quick_gates.len().to_string());
        printer.kv("Final gates", &plan.final_gates.len().to_string());
        printer.kv("Risk", risk_name(plan.risk));
    }

    if let Some(run) = &result.data.run {
        printer.plain("");
        printer.header("Run");
        printer.kv("ID", run.run_id.as_str());
        printer.kv("State", run_state_name(run.state));
        printer.kv("Branch", &escape_terminal(&run.branch, 256));
        printer.kv("Worktree", &escape_terminal(&run.worktree, 4096));
    }

    if !result.data.runs.is_empty() {
        printer.plain("");
        printer.header("Runs");
        for run in &result.data.runs {
            printer.plain(&format!(
                "{}  state={}  branch={}",
                escape_terminal(run.run_id.as_str(), 256),
                run_state_name(run.state),
                escape_terminal(&run.branch, 256),
            ));
        }
    }

    if let Some(patch) = &result.data.patch {
        printer.plain("");
        printer.header("Patch");
        printer.plain(&escape_multiline(patch, 32 * 1024 * 1024));
    }

    if let Some(evidence) = &result.data.evidence {
        printer.plain("");
        printer.header("Evidence");
        printer.kv("Candidate", &evidence.candidate_commit.value);
        printer.kv("Patch", &evidence.patch_digest.to_string());
        printer.kv(
            "Quick gates",
            &format!("{} passed", evidence.quick_gates.results.len()),
        );
        printer.kv(
            "Final gates",
            &format!("{} passed", evidence.final_gates.results.len()),
        );
    }

    if let Some(draft) = &result.data.pull_request {
        printer.plain("");
        printer.header("Pull request draft");
        printer.kv("Branch", &escape_terminal(&draft.branch, 256));
        printer.kv("Base", &escape_terminal(&draft.base_branch, 256));
        printer.kv("Head", &draft.head);
        printer.kv("Title", &escape_terminal(&draft.title, 256));
        printer.plain("");
        printer.plain(&escape_multiline(&draft.body, 64 * 1024));
    }

    for diagnostic in &result.diagnostics {
        let message = format!(
            "{}: {}",
            diagnostic.code,
            escape_terminal(&diagnostic.summary, 4096)
        );
        match diagnostic.severity {
            DiagnosticSeverity::Warning => printer.warning(&message),
            DiagnosticSeverity::Error => printer.error(&message),
        }
    }
    if !result.next_actions.is_empty() {
        printer.plain("");
        printer.header("Next actions");
        for (index, action) in result.next_actions.iter().enumerate() {
            printer.plain(&format!(
                "{}. {}",
                index + 1,
                action
                    .argv
                    .iter()
                    .map(|argument| shell_display(argument))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
            printer.plain(&format!("   {}", escape_terminal(&action.reason, 1024)));
        }
    }
}

fn disposition_name(disposition: CommandDisposition) -> &'static str {
    match disposition {
        CommandDisposition::Success => "success",
        CommandDisposition::OperationFailed => "operation-failed",
        CommandDisposition::InvalidInvocation => "invalid-invocation",
        CommandDisposition::InfrastructureUnavailable => "infrastructure-unavailable",
        CommandDisposition::NoChange => "no-change",
        CommandDisposition::ActionRequired => "action-required",
        CommandDisposition::UpstreamUnknown => "upstream-unknown",
        CommandDisposition::Quarantined => "quarantined",
        CommandDisposition::Stale => "stale",
        CommandDisposition::Interrupted => "interrupted",
    }
}

fn run_state_name(state: aos_maintain::workflow::RunState) -> &'static str {
    use aos_maintain::workflow::RunState;

    match state {
        RunState::Observed => "observed",
        RunState::Selected => "selected",
        RunState::Planned => "planned",
        RunState::WorktreeReady => "worktree-ready",
        RunState::Materializing => "materializing",
        RunState::PolicyValid => "policy-valid",
        RunState::QuickGated => "quick-gated",
        RunState::Repairing => "repairing",
        RunState::CandidateAccepted => "candidate-accepted",
        RunState::Committed => "committed",
        RunState::FinalGated => "final-gated",
        RunState::ReadyForPr => "ready-for-pr",
        RunState::PrPublished => "pr-published",
        RunState::AwaitingRemoteAuthorization => "awaiting-remote-authorization",
        RunState::MergeEligibleObserved => "merge-eligible-observed",
        RunState::MergedObserved => "merged-observed",
        RunState::ReleaseHandoff => "release-handoff",
        RunState::NoChange => "no-change",
        RunState::Superseded => "superseded",
        RunState::BlockedHuman => "blocked-human",
        RunState::Quarantined => "quarantined",
        RunState::Rejected => "rejected",
        RunState::Abandoned => "abandoned",
        RunState::Failed => "failed",
    }
}

fn classification_name(classification: Classification) -> &'static str {
    match classification {
        Classification::Automatic => "automatic",
        Classification::Assisted => "assisted",
        Classification::Manual => "manual",
        Classification::Frozen => "frozen",
        Classification::Generated => "generated",
        Classification::Alias => "alias",
        Classification::Local => "local",
    }
}

fn discovery_name(decision: aos_maintain::workflow::DiscoveryDecision) -> &'static str {
    use aos_maintain::workflow::DiscoveryDecision;

    match decision {
        DiscoveryDecision::Current => "current",
        DiscoveryDecision::UpdateAvailable => "update-available",
        DiscoveryDecision::Unknown => "unknown",
        DiscoveryDecision::Quarantined => "quarantined",
    }
}

fn risk_name(risk: aos_maintain::inventory::RiskLevel) -> &'static str {
    use aos_maintain::inventory::RiskLevel;

    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Normal => "normal",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

fn shell_display(argument: &str) -> String {
    let escaped = escape_terminal(argument, 4096);
    if escaped.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
    }) {
        escaped
    } else {
        format!("'{}'", escaped.replace('\'', "'\\''"))
    }
}

fn escape_multiline(value: &str, maximum: usize) -> String {
    let mut output = String::new();
    for (index, line) in value.split('\n').enumerate() {
        if index > 0 {
            output.push('\n');
        }
        if output.len() >= maximum {
            break;
        }
        output.push_str(&escape_terminal(line, maximum.saturating_sub(output.len())));
    }
    output
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::Commands;

    #[tokio::test]
    async fn accepts_both_machine_formats_for_typed_invocation_diagnostics() {
        let cli = Cli::try_parse_from(["aos", "maintain", "--json", "--jsonl"])
            .expect("recognized maintenance invocations must reach typed diagnostics");
        let Commands::Maintain(args) = &cli.command else {
            panic!("expected maintain command");
        };
        let completion = run(&cli, args)
            .await
            .expect("output-mode conflict should produce a valid completion");

        assert_eq!(
            completion.result.disposition,
            CommandDisposition::InvalidInvocation
        );
        assert_eq!(completion.exit_code(), 2);
    }
}

fn write_json<T>(value: &T) -> Result<()>
where
    T: Serialize,
{
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, value).context("serializing maintenance output")?;
    lock.write_all(b"\n")?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamEnvelope<'a> {
    schema_version: &'static str,
    stream_sequence: u64,
    #[serde(rename = "type")]
    event_type: &'static str,
    result: &'a MaintainCommandResult,
}
