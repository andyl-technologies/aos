//! Local foreground package-maintenance controller and process-boundary renderer.

mod confinement;
mod discovery;
mod evidence;
mod git;
mod inventory;
mod materialize;
mod mutation;
mod remote;
mod repair;
mod state;
mod tui;
mod validation;
mod worktree;

use std::collections::BTreeMap;
use std::io::Write as _;

use anyhow::{Context as _, Result};
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_maintain::identity::OperationId;
use aos_maintain::inventory::Classification;
use aos_maintain::presentation::{
    CommandCompletion, CommandData, CommandDisposition, Diagnostic, DiagnosticSeverity,
    EffectClass, GateLogView, MaintainCommandResult, NextAction, PrimaryValue, PullRequestDraft,
    escape_terminal,
};
use aos_maintain::workflow::{DiscoveryDecision, ProgressEvent, TaskStatus};
use aos_maintain::{MAINTENANCE_CLI_V1, MAINTENANCE_PROGRESS_EVENT_V1};
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
pub async fn run(cli: &Cli, args: &MaintainArgs, printer: &Printer) -> Result<CommandCompletion> {
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

    if args.jsonl {
        let event = ProgressEvent {
            schema: MAINTENANCE_PROGRESS_EVENT_V1.to_string(),
            stream_sequence: 1,
            operation: OperationId::parse(command_name(args))?,
            run_id: None,
            status: TaskStatus::Running,
            message: activity_label(args)
                .unwrap_or("Resolving local maintenance state")
                .to_string(),
            completed: None,
            total: None,
            elapsed_ms: 0,
        };
        event.validate()?;
        write_json(&ProgressStreamEnvelope {
            schema_version: "aos.maintain.stream/v1",
            stream_sequence: 1,
            event_type: "progress",
            event: &event,
        })?;
    }

    let _activity = activity_label(args).map(|label| printer.activity(label));

    match &args.command {
        None => cached_completion("home", args, None),
        Some(MaintainCommand::Inventory(command)) => {
            let evaluated = NixRunner::new(cli.verbose, cli.quiet).and_then(|nix| {
                let envelope = inventory::evaluate(&nix, command.target.as_deref())?;
                let audited = if command.check {
                    inventory::audit_fixed_outputs(&nix, &envelope, command.target.as_deref())?
                } else {
                    0
                };
                let store =
                    state::StateStore::open_for_envelope(args.state_dir.as_deref(), &envelope)?;
                store.write_inventory(&envelope)?;
                Ok((envelope, audited))
            });
            match evaluated {
                Ok((envelope, audited)) => {
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
                    if command.check {
                        values.insert("fixedOutputsAudited".to_string(), audited.to_string());
                        values.insert("inventoryCheck".to_string(), "true".to_string());
                    }
                    let digest = envelope.inventory_digest.to_string();
                    completion(
                        "inventory",
                        CommandDisposition::Success,
                        CommandData {
                            values,
                            inventory: Some(envelope),
                            ..CommandData::default()
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
            match discovery::scan(&envelope, &store, command.offline, &command.token_env).await {
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
        Some(MaintainCommand::Ui(command)) => ui_command(args, command).await,
        Some(MaintainCommand::Plan(command)) => plan_command(args, command),
        Some(MaintainCommand::Run(command)) => run_command(cli, args, command, printer).await,
        Some(MaintainCommand::Resume(command)) => resume_command(cli, args, command, printer).await,
        Some(MaintainCommand::Inspect(command)) => inspect_command(args, command),
        Some(MaintainCommand::Diff(command)) => diff_command(args, command),
        Some(MaintainCommand::Abandon(command)) => abandon_command(args, command),
        Some(MaintainCommand::Clean(command)) => clean_command(args, command),
        Some(MaintainCommand::Accept(command)) => accept_command(args, command),
        Some(MaintainCommand::Commit(command)) => commit_command(args, command),
        Some(MaintainCommand::Test(command)) => test_command(args, command, printer),
        Some(MaintainCommand::Repair(command)) => repair_command(cli, args, command, printer).await,
        Some(MaintainCommand::Evidence(command)) => evidence_command(args, command),
        Some(MaintainCommand::PreparePr(command)) => prepare_pr_command(args, command),
        Some(MaintainCommand::PublishPr(command)) => publish_pr_command(args, command).await,
        Some(MaintainCommand::ObservePr(command)) => observe_pr_command(args, command).await,
        Some(MaintainCommand::Handoff(command)) => handoff_command(args, command),
    }
}

fn accept_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainAcceptArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    require_frozen_controller(&plan)?;
    let _operation_lease = store.acquire_operation_lease(plan.plan_id.as_str())?;
    if command.adopt_worktree {
        return adopt_worktree(args, &store, run, command.confirm.as_deref());
    }
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

fn adopt_worktree(
    _args: &MaintainArgs,
    store: &state::StateStore,
    mut run: aos_maintain::run::PackageUpdateRunV1,
    confirmation: Option<&str>,
) -> Result<CommandCompletion> {
    use aos_maintain::run::{AttemptOrigin, RepairAttemptV1};
    use aos_maintain::workflow::{ActorClass, RunState};

    if run.state != RunState::QuickGated {
        return run_view_completion(
            "accept",
            store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "Worktree adoption requires a previously quick-gated candidate",
            )),
        );
    }
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    require_frozen_controller(&plan)?;
    let (patch, changed_paths) =
        materialize::adopt_candidate(std::path::Path::new(&run.worktree), &plan, 0, false)?;
    let retained = store
        .read_patch(run.run_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run has no retained candidate"))?;
    if patch == retained {
        return run_view_completion(
            "accept",
            store,
            run,
            Some((
                CommandDisposition::NoChange,
                "The worktree has no edits to adopt",
            )),
        );
    }
    let candidate_digest =
        aos_contract::Sha256Digest::separated("aos.package-update-patch/v1", &patch);
    let candidate_digest_text = candidate_digest.to_string();
    if confirmation != Some(candidate_digest_text.as_str()) {
        let mut completion = run_view_completion(
            "accept",
            store,
            run.clone(),
            Some((
                CommandDisposition::ActionRequired,
                "Review the changed worktree and confirm its exact candidate digest",
            )),
        )?;
        completion.result.next_actions = vec![NextAction {
            label: "Adopt these maintainer edits".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "accept".to_string(),
                run.run_id.to_string(),
                "--adopt-worktree".to_string(),
                "--confirm".to_string(),
                candidate_digest.to_string(),
            ],
            reason: "adoption creates a new human attempt and invalidates prior gates".to_string(),
            prerequisites: vec!["review `aos maintain diff --patch` output".to_string()],
            effect_class: EffectClass::HumanDecision,
            bound_context: Some(candidate_digest.to_string()),
        }];
        return CommandCompletion::new(completion.result);
    }
    let attempt = run
        .attempt
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("candidate attempt counter overflow"))?;
    let record = RepairAttemptV1 {
        schema: aos_maintain::PACKAGE_UPDATE_REPAIR_ATTEMPT_V1.to_string(),
        run_id: run.run_id.clone(),
        plan_id: run.plan_id.clone(),
        attempt,
        parent_attempt: run.attempt,
        origin: AttemptOrigin::Maintainer,
        task_digest: None,
        result_digest: None,
        proposal_digest: candidate_digest,
        candidate_digest,
        changed_paths,
        completed_at_unix: state::now_unix()?,
    };
    record.validate()?;
    store.write_repair_attempt(&run, &record, &patch)?;
    store.transition(
        &mut run,
        RunState::Repairing,
        ActorClass::Maintainer,
        state::now_unix()?,
    )?;
    run.attempt = attempt;
    run.accepted_candidate = None;
    run.candidate_commit = None;
    run.evidence_digest = None;
    run.updated_at_unix = state::now_unix()?;
    store.write_run(&run)?;
    store.transition(
        &mut run,
        RunState::PolicyValid,
        ActorClass::Maintainer,
        state::now_unix()?,
    )?;
    let mut completion = run_view_completion("accept", store, run, None)?;
    completion.result.data.repair_attempt = Some(record);
    CommandCompletion::new(completion.result)
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
    require_frozen_controller(&plan)?;
    let _operation_lease = store.acquire_operation_lease(plan.plan_id.as_str())?;
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
    printer: &Printer,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    require_frozen_controller(&plan)?;
    let _operation_lease = store.acquire_operation_lease(plan.plan_id.as_str())?;
    let final_phase = if command.quick {
        false
    } else {
        command.final_gate
    };
    let results = if final_phase {
        validation::final_gates(&store, &plan, &mut run, printer)
    } else {
        validation::quick(&store, &plan, &mut run, printer)
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

async fn repair_command(
    cli: &Cli,
    args: &MaintainArgs,
    command: &crate::cli::MaintainRepairArgs,
    printer: &Printer,
) -> Result<CommandCompletion> {
    use crate::cli::MaintainAgentMode;
    use aos_maintain::agent::AgentResultDisposition;
    use aos_maintain::workflow::{ActorClass, RunState};

    let (store, _) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    require_frozen_controller(&plan)?;
    let _operation_lease = store.acquire_operation_lease(plan.plan_id.as_str())?;

    if let Some(confirmation) = command.confirm.as_deref() {
        let Some(proposal) = repair::pending(&store, &run)? else {
            return run_view_completion(
                "repair",
                &store,
                run,
                Some((
                    CommandDisposition::ActionRequired,
                    "No retained repair proposal is awaiting confirmation",
                )),
            );
        };
        let attempt = match repair::accept(
            &store,
            &plan,
            &mut run,
            &proposal,
            confirmation,
            cli.verbose,
            cli.quiet,
        ) {
            Ok(attempt) => attempt,
            Err(error) => {
                return run_view_completion(
                    "repair",
                    &store,
                    run,
                    Some((CommandDisposition::ActionRequired, &format!("{error:#}"))),
                );
            }
        };
        let gates = validation::quick(&store, &plan, &mut run, printer);
        let failure = match gates {
            Ok(results) if results.all_succeeded() => None,
            Ok(_) => Some((
                CommandDisposition::OperationFailed,
                "The repaired candidate still fails one or more quick gates".to_string(),
            )),
            Err(error) => Some((
                CommandDisposition::ActionRequired,
                format!("The repaired candidate could not complete quick validation: {error:#}"),
            )),
        };
        let mut completion = run_view_completion(
            "repair",
            &store,
            run,
            failure
                .as_ref()
                .map(|(disposition, message)| (*disposition, message.as_str())),
        )?;
        completion.result.primary_values.push(PrimaryValue {
            name: "attempt".to_string(),
            value: attempt.attempt.to_string(),
        });
        completion.result.primary_values.push(PrimaryValue {
            name: "candidateDigest".to_string(),
            value: attempt.candidate_digest.to_string(),
        });
        completion.result.data.agent_task = Some(proposal.task);
        completion.result.data.agent_result = Some(proposal.result);
        completion.result.data.repair_attempt = Some(attempt);
        return CommandCompletion::new(completion.result);
    }

    let proposal = if let Some(proposal) = repair::pending(&store, &run)? {
        proposal
    } else if command.agent == MaintainAgentMode::None {
        let mut completion = run_view_completion(
            "repair",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "Agent repair is disabled; inspect the failed gate and repair the retained worktree manually",
            )),
        )?;
        completion.result.next_actions = vec![NextAction {
            label: "Inspect the current run and failed gate".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "inspect".to_string(),
                command.run.clone(),
            ],
            reason: "--agent none never invokes an adapter or changes the candidate".to_string(),
            prerequisites: vec!["resolve the reported package failure".to_string()],
            effect_class: EffectClass::ReadOnly,
            bound_context: Some(plan.plan_id.to_string()),
        }];
        return CommandCompletion::new(completion.result);
    } else {
        let adapter = command
            .adapter
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--agent local requires --adapter PATH"))?;
        match repair::propose(&store, &plan, &run, adapter).await {
            Ok(proposal) => proposal,
            Err(error) => {
                return run_view_completion(
                    "repair",
                    &store,
                    run,
                    Some((CommandDisposition::ActionRequired, &format!("{error:#}"))),
                );
            }
        }
    };

    if run.state == RunState::PolicyValid {
        store.transition(
            &mut run,
            RunState::Repairing,
            ActorClass::Controller,
            state::now_unix()?,
        )?;
    }
    let disposition = match proposal.result.disposition {
        AgentResultDisposition::ProposedPatch
        | AgentResultDisposition::ScopeRequired
        | AgentResultDisposition::MaintainerQuestion => CommandDisposition::ActionRequired,
        AgentResultDisposition::NoProposal => CommandDisposition::OperationFailed,
    };
    let mut completion = run_view_completion(
        "repair",
        &store,
        run.clone(),
        Some((disposition, proposal.result.explanation.as_str())),
    )?;
    let task_digest = aos_contract::Sha256Digest::of_canonical(
        aos_maintain::PACKAGE_UPDATE_AGENT_TASK_V1,
        &proposal.task,
    )?;
    completion.result.data.values.insert(
        "agentResult".to_string(),
        agent_result_disposition_name(proposal.result.disposition).to_string(),
    );
    completion
        .result
        .data
        .values
        .insert("taskDigest".to_string(), task_digest.to_string());
    completion.result.data.patch = proposal.result.patch.clone();
    completion.result.data.agent_task = Some(proposal.task.clone());
    completion.result.data.agent_result = Some(proposal.result.clone());
    if let Some(digest) = proposal.proposal_digest {
        completion.result.primary_values.push(PrimaryValue {
            name: "proposalDigest".to_string(),
            value: digest.to_string(),
        });
        completion.result.next_actions = vec![NextAction {
            label: "Apply this exact repair proposal".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "repair".to_string(),
                run.run_id.to_string(),
                "--confirm".to_string(),
                digest.to_string(),
            ],
            reason: "the adapter is terminated; confirmation enters the trusted mutation gateway"
                .to_string(),
            prerequisites: vec!["review the complete retained patch".to_string()],
            effect_class: EffectClass::HumanDecision,
            bound_context: Some(digest.to_string()),
        }];
    }
    CommandCompletion::new(completion.result)
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
    require_frozen_controller(&plan)?;
    let _operation_lease = store.acquire_operation_lease(plan.plan_id.as_str())?;
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
    let (store, coordinates) = current_store(args)?;
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
    let draft = pull_request_draft(&store, &coordinates, &run)?;
    let mut completion = run_view_completion("prepare-pr", &store, run.clone(), None)?;
    completion.result.data.pull_request = Some(draft);
    CommandCompletion::new(completion.result)
}

fn pull_request_draft(
    store: &state::StateStore,
    coordinates: &inventory::RepositoryCoordinates,
    run: &aos_maintain::run::PackageUpdateRunV1,
) -> Result<PullRequestDraft> {
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
    let base_branch = remote::default_branch(coordinates)?;
    let changes = plan
        .units
        .iter()
        .map(|unit| {
            format!(
                "- `{}`: `{}` -> `{}`",
                unit.unit_id, unit.current_package_version, unit.target_package_version
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let title = if let Ok(unit) = plan.single_unit() {
        format!(
            "pkg: update {} to {}",
            unit.unit_id, unit.target_package_version
        )
    } else {
        format!(
            "pkg: update {} cohort",
            plan.cohort
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("campaign has no cohort identity"))?
        )
    };
    let body = format!(
        "## Package update\n\n{changes}\n\n- Units: {}\n- Components: {}\n- Risk: `{}`\n- Sources: {} resolved and hashed\n- Deterministic attempts: 1\n- Accepted repair attempts: {}\n- Quick gates: {}/{} passed\n- Final gates: {}/{} passed\n- Candidate commit: `{}`\n- Local evidence: `{}`\n\n## Review\n\n- [ ] Review the package and source changes\n- [ ] Confirm required package-owner or specialist review\n- [ ] Confirm remote contributor authorization and protected checks\n",
        plan.units.len(),
        plan.units
            .iter()
            .map(|unit| unit.component_targets.len())
            .sum::<usize>(),
        risk_name(plan.risk),
        evidence.materialization.sources.len(),
        run.attempt,
        evidence.quick_gates.results.len(),
        evidence.quick_gates.results.len(),
        evidence.final_gates.results.len(),
        evidence.final_gates.results.len(),
        head.value,
        evidence_digest,
    );
    Ok(PullRequestDraft {
        branch: run.branch.clone(),
        base_branch,
        title,
        body,
        head: head.value.clone(),
        evidence_digest,
    })
}

fn parse_expected_remote_head(
    run: &aos_maintain::run::PackageUpdateRunV1,
    value: &str,
) -> Result<Option<String>> {
    if value == "absent" {
        return Ok(None);
    }
    let object = aos_maintain::envelope::GitObjectId {
        algorithm: run.base_commit.algorithm,
        value: value.to_string(),
    };
    object.validate()?;
    Ok(Some(object.value))
}

async fn publish_pr_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainPublishPrArgs,
) -> Result<CommandCompletion> {
    let (store, coordinates) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    require_frozen_controller(&plan)?;
    let _operation_lease = store.acquire_operation_lease(plan.plan_id.as_str())?;
    if !matches!(
        run.state,
        aos_maintain::workflow::RunState::ReadyForPr
            | aos_maintain::workflow::RunState::PrPublished
            | aos_maintain::workflow::RunState::AwaitingRemoteAuthorization
    ) {
        return run_view_completion(
            "publish-pr",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "Only a final-evidenced candidate may be published",
            )),
        );
    }
    let draft = pull_request_draft(&store, &coordinates, &run)?;
    if let Some(publication) = store.read_publication(run.run_id.as_str())? {
        if publication.head.value != draft.head
            || publication.branch != draft.branch
            || publication.base_branch != draft.base_branch
            || publication.evidence_digest != draft.evidence_digest
        {
            anyhow::bail!("retained publication disagrees with the current exact candidate");
        }
        advance_published_state(&store, &mut run)?;
        let mut completion = run_view_completion("publish-pr", &store, run, None)?;
        completion.result.data.pull_request = Some(draft);
        completion.result.data.publication = Some(publication.clone());
        completion.result.primary_values.push(PrimaryValue {
            name: "pullRequestUrl".to_string(),
            value: publication.pull_request_url,
        });
        return CommandCompletion::new(completion.result);
    }
    let expected = parse_expected_remote_head(&run, &command.expected_remote_head)?;
    let request_digest = remote::publication_request_digest(
        &coordinates,
        &run,
        &draft,
        expected.as_deref(),
        &command.token_env,
    )?;
    if command.confirm.as_deref() != Some(request_digest.to_string().as_str()) {
        let mut completion = run_view_completion(
            "publish-pr",
            &store,
            run.clone(),
            Some((
                CommandDisposition::ActionRequired,
                "Review and confirm the exact remote branch and pull-request effect",
            )),
        )?;
        completion.result.data.pull_request = Some(draft);
        completion.result.primary_values.push(PrimaryValue {
            name: "publicationRequestDigest".to_string(),
            value: request_digest.to_string(),
        });
        completion.result.next_actions = vec![NextAction {
            label: "Publish this exact branch and pull request".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "publish-pr".to_string(),
                run.run_id.to_string(),
                "--expected-remote-head".to_string(),
                command.expected_remote_head.clone(),
                "--token-env".to_string(),
                command.token_env.clone(),
                "--confirm".to_string(),
                request_digest.to_string(),
            ],
            reason: "the confirmation binds the remote, ref, expected prior head, candidate, evidence, and PR text".to_string(),
            prerequisites: vec![
                format!("load the GitHub API credential into {}", command.token_env),
                "ensure configured Git push authentication is available".to_string(),
            ],
            effect_class: EffectClass::RemoteMutation,
            bound_context: Some(request_digest.to_string()),
        }];
        return CommandCompletion::new(completion.result);
    }

    let publication = match remote::publish(
        &coordinates,
        &run,
        &draft,
        expected.as_deref(),
        &command.token_env,
    )
    .await
    {
        Ok(publication) => publication,
        Err(error) => {
            return run_view_completion(
                "publish-pr",
                &store,
                run,
                Some((CommandDisposition::OperationFailed, &format!("{error:#}"))),
            );
        }
    };
    if store.read_publication(run.run_id.as_str())?.is_none() {
        store.write_publication(&publication)?;
    }
    advance_published_state(&store, &mut run)?;
    let mut completion = run_view_completion("publish-pr", &store, run, None)?;
    completion.result.data.pull_request = Some(draft);
    completion.result.data.publication = Some(publication.clone());
    completion.result.primary_values.push(PrimaryValue {
        name: "pullRequestUrl".to_string(),
        value: publication.pull_request_url,
    });
    CommandCompletion::new(completion.result)
}

fn advance_published_state(
    store: &state::StateStore,
    run: &mut aos_maintain::run::PackageUpdateRunV1,
) -> Result<()> {
    if run.state == aos_maintain::workflow::RunState::ReadyForPr {
        store.transition(
            run,
            aos_maintain::workflow::RunState::PrPublished,
            aos_maintain::workflow::ActorClass::Maintainer,
            state::now_unix()?,
        )?;
    }
    if run.state == aos_maintain::workflow::RunState::PrPublished {
        store.transition(
            run,
            aos_maintain::workflow::RunState::AwaitingRemoteAuthorization,
            aos_maintain::workflow::ActorClass::Controller,
            state::now_unix()?,
        )?;
    }
    Ok(())
}

async fn observe_pr_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainObservePrArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    require_frozen_controller(&plan)?;
    let _operation_lease = store.acquire_operation_lease(plan.plan_id.as_str())?;
    if !matches!(
        run.state,
        aos_maintain::workflow::RunState::AwaitingRemoteAuthorization
            | aos_maintain::workflow::RunState::MergeEligibleObserved
            | aos_maintain::workflow::RunState::MergedObserved
            | aos_maintain::workflow::RunState::ReleaseHandoff
    ) {
        return run_view_completion(
            "observe-pr",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "Publish the exact candidate before observing remote authorization",
            )),
        );
    }
    let publication = store
        .read_publication(run.run_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run publication is unavailable"))?;
    let observation = match remote::observe(
        &publication,
        &command.authorization_check,
        &command.token_env,
    )
    .await
    {
        Ok(observation) => observation,
        Err(error) => {
            return run_view_completion(
                "observe-pr",
                &store,
                run,
                Some((CommandDisposition::OperationFailed, &format!("{error:#}"))),
            );
        }
    };
    store.write_remote_observation(&observation)?;
    if run.state == aos_maintain::workflow::RunState::AwaitingRemoteAuthorization
        && observation.is_qualified_merge()
    {
        store.transition(
            &mut run,
            aos_maintain::workflow::RunState::MergedObserved,
            aos_maintain::workflow::ActorClass::RemoteObservation,
            state::now_unix()?,
        )?;
    } else if run.state == aos_maintain::workflow::RunState::AwaitingRemoteAuthorization
        && observation.is_merge_eligible()
    {
        store.transition(
            &mut run,
            aos_maintain::workflow::RunState::MergeEligibleObserved,
            aos_maintain::workflow::ActorClass::RemoteObservation,
            state::now_unix()?,
        )?;
    }
    if run.state == aos_maintain::workflow::RunState::MergeEligibleObserved && observation.merged {
        store.transition(
            &mut run,
            aos_maintain::workflow::RunState::MergedObserved,
            aos_maintain::workflow::ActorClass::RemoteObservation,
            state::now_unix()?,
        )?;
    }
    let disposition = if observation.is_merge_eligible() || observation.is_qualified_merge() {
        None
    } else {
        Some((
            CommandDisposition::ActionRequired,
            "The exact head is still waiting for authorization, successful checks, and approval",
        ))
    };
    let mut completion = run_view_completion("observe-pr", &store, run, disposition)?;
    completion.result.data.publication = Some(publication);
    completion.result.data.remote_observation = Some(observation);
    CommandCompletion::new(completion.result)
}

fn handoff_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainHandoffArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let mut run = resolve_run(&store, &command.run)?;
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    require_frozen_controller(&plan)?;
    let _operation_lease = store.acquire_operation_lease(plan.plan_id.as_str())?;
    if run.state == aos_maintain::workflow::RunState::ReleaseHandoff {
        return run_view_completion("handoff", &store, run, None);
    }
    if run.state != aos_maintain::workflow::RunState::MergedObserved {
        return run_view_completion(
            "handoff",
            &store,
            run,
            Some((
                CommandDisposition::ActionRequired,
                "A protected exact merge must be observed before release handoff",
            )),
        );
    }
    let observation = store
        .read_remote_observation(run.run_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("merged run has no remote observation"))?;
    let merge_commit = observation
        .merge_commit
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("merged observation has no merge commit"))?
        .value
        .clone();
    if command.confirm.as_deref() != Some(merge_commit.as_str()) {
        let mut completion = run_view_completion(
            "handoff",
            &store,
            run.clone(),
            Some((
                CommandDisposition::ActionRequired,
                "Confirm the exact observed protected merge commit for release handoff",
            )),
        )?;
        completion.result.data.remote_observation = Some(observation);
        completion.result.next_actions = vec![NextAction {
            label: "Record release identity handoff".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "handoff".to_string(),
                run.run_id.to_string(),
                "--confirm".to_string(),
                merge_commit.clone(),
            ],
            reason: "this records identity for the independent release workflow; it does not publish artifacts".to_string(),
            prerequisites: vec!["review the exact protected merge identity".to_string()],
            effect_class: EffectClass::HumanDecision,
            bound_context: Some(merge_commit),
        }];
        return CommandCompletion::new(completion.result);
    }
    store.transition(
        &mut run,
        aos_maintain::workflow::RunState::ReleaseHandoff,
        aos_maintain::workflow::ActorClass::Maintainer,
        state::now_unix()?,
    )?;
    run_view_completion("handoff", &store, run, None)
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

async fn ui_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainUiArgs,
) -> Result<CommandCompletion> {
    let (store, _) = current_store(args)?;
    let runs = store.list_runs()?;
    let selected = command
        .run
        .as_deref()
        .map(|query| resolve_run(&store, query).map(|run| run.run_id))
        .transpose()?;
    let discovery = store.read_discovery()?;
    tui::run(runs.clone(), discovery, selected.as_ref()).await?;
    completion(
        "ui",
        CommandDisposition::Success,
        CommandData {
            values: BTreeMap::from([("interactiveRendered".to_string(), "true".to_string())]),
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
    printer: &Printer,
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
            campaign: None,
            plan: Some(run.plan_id.to_string()),
            until: command.until,
            worktree: Some(std::path::PathBuf::from(run.worktree)),
        },
        printer,
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
    let mut gate_results = Vec::new();
    for phase in ["quick", "final"] {
        if let Some(results) = store.read_gate_results(run.run_id.as_str(), phase)? {
            gate_results.push(results);
        }
    }
    let selected_log = command.log.as_ref().or(command.log_file.as_ref());
    let gate_log = if let Some(gate_id) = selected_log {
        let phase = gate_results
            .iter()
            .rev()
            .find(|results| {
                results
                    .results
                    .iter()
                    .any(|result| result.gate_id == *gate_id)
            })
            .map(|results| results.phase.as_str())
            .ok_or_else(|| anyhow::anyhow!("selected gate has no retained execution"))?;
        if command.log_file.is_some() {
            store.read_gate_log(run.run_id.as_str(), phase, gate_id)?;
            let path = store.gate_log_path(run.run_id.as_str(), phase, gate_id)?;
            Some(GateLogView {
                phase: phase.to_string(),
                gate_id: gate_id.clone(),
                path: Some(
                    path.to_str()
                        .ok_or_else(|| anyhow::anyhow!("retained gate-log path is not UTF-8"))?
                        .to_string(),
                ),
                contents: None,
            })
        } else {
            let bytes = store.read_gate_log(run.run_id.as_str(), phase, gate_id)?;
            Some(GateLogView {
                phase: phase.to_string(),
                gate_id: gate_id.clone(),
                path: None,
                contents: Some(String::from_utf8_lossy(&bytes).into_owned()),
            })
        }
    } else {
        None
    };
    if command.failure {
        gate_results.retain(|results| {
            results
                .results
                .iter()
                .any(|result| result.outcome != aos_maintain::workflow::GateOutcome::Success)
        });
    }
    let mut completion = run_view_completion("inspect", &store, run, None)?;
    completion.result.data.gate_results = gate_results;
    completion.result.data.gate_log = gate_log;
    if let Some(log) = &completion.result.data.gate_log
        && let Some(path) = &log.path
    {
        completion.result.primary_values = vec![PrimaryValue {
            name: "gateLogPath".to_string(),
            value: path.clone(),
        }];
    }
    if command.failure {
        completion
            .result
            .data
            .values
            .insert("inspectionFocus".to_string(), "failure".to_string());
    }
    CommandCompletion::new(completion.result)
}

fn diff_command(
    args: &MaintainArgs,
    command: &crate::cli::MaintainDiffArgs,
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
    let current = materialize::worktree_patch(std::path::Path::new(&run.worktree))?;
    let (bytes, source) = if current.is_empty() || current == bytes {
        (bytes, "retained")
    } else {
        (current, "worktree")
    };
    let patch_digest = aos_contract::Sha256Digest::separated("aos.package-update-patch/v1", &bytes);
    let patch = String::from_utf8(bytes).context("candidate patch is not UTF-8")?;
    let plan = store
        .read_plan(run.plan_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run plan is unavailable"))?;
    completion(
        "diff",
        CommandDisposition::Success,
        CommandData {
            values: BTreeMap::from([
                ("patchDigest".to_string(), patch_digest.to_string()),
                ("patchSource".to_string(), source.to_string()),
            ]),
            plan: Some(plan),
            run: Some(run),
            patch: (!command.semantic).then_some(patch),
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
    let _operation_lease = store.acquire_operation_lease(run.plan_id.as_str())?;
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
    let _operation_lease = store.acquire_operation_lease(run.plan_id.as_str())?;
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
        snapshot.units.retain(|unit| {
            let declared = inventory
                .inventory
                .units
                .iter()
                .find(|candidate| candidate.unit_id.as_str() == unit.unit_id);
            let family_matches = report
                .and_then(|selection| selection.family.as_ref())
                .is_none_or(|family| {
                    declared.is_some_and(|candidate| candidate.family.as_str() == family)
                });
            let required = declared.is_some_and(|candidate| {
                matches!(
                    candidate.classification,
                    Classification::Automatic | Classification::Assisted
                )
            });
            let state_matches = match report {
                Some(selection) if selection.outdated => {
                    unit.decision == DiscoveryDecision::UpdateAvailable
                }
                Some(selection) if selection.unknown => unit.decision == DiscoveryDecision::Unknown,
                Some(_) => true,
                None => {
                    matches!(
                        unit.decision,
                        DiscoveryDecision::UpdateAvailable | DiscoveryDecision::Quarantined
                    ) || (required && unit.decision == DiscoveryDecision::Unknown)
                }
            };
            family_matches && state_matches
        });
        let retained = snapshot
            .units
            .iter()
            .map(|unit| format!("{}/", unit.unit_id))
            .collect::<Vec<_>>();
        snapshot
            .observations
            .retain(|key, _| retained.iter().any(|prefix| key.starts_with(prefix)));
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
    values.insert("inventoryDigest".to_string(), inventory_digest.to_string());
    values.insert(
        "unitCount".to_string(),
        discovery
            .as_ref()
            .map_or(0, |snapshot| snapshot.units.len())
            .to_string(),
    );
    if let Some(snapshot) = &discovery {
        for (name, decision) in [
            ("current", DiscoveryDecision::Current),
            ("updateAvailable", DiscoveryDecision::UpdateAvailable),
            ("unknown", DiscoveryDecision::Unknown),
            ("quarantined", DiscoveryDecision::Quarantined),
        ] {
            values.insert(
                name.to_string(),
                snapshot
                    .units
                    .iter()
                    .filter(|unit| unit.decision == decision)
                    .count()
                    .to_string(),
            );
        }
    }
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
            inventory: (command == "inventory").then_some(inventory),
            discovery,
            ..CommandData::default()
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
    let required = outcome
        .snapshot
        .units
        .iter()
        .filter(|unit| {
            envelope.inventory.units.iter().any(|candidate| {
                candidate.unit_id.as_str() == unit.unit_id
                    && matches!(
                        candidate.classification,
                        Classification::Automatic | Classification::Assisted
                    )
            })
        })
        .fold((0_u64, 0_u64), |(unknown, quarantined), unit| {
            match unit.decision {
                DiscoveryDecision::Unknown => (unknown + 1, quarantined),
                DiscoveryDecision::Quarantined => (unknown, quarantined + 1),
                DiscoveryDecision::Current | DiscoveryDecision::UpdateAvailable => {
                    (unknown, quarantined)
                }
            }
        });
    let disposition = if required.1 > 0 {
        CommandDisposition::Quarantined
    } else if required.0 > 0 {
        CommandDisposition::UpstreamUnknown
    } else if counts["updateAvailable"] == 0 {
        CommandDisposition::NoChange
    } else {
        CommandDisposition::Success
    };
    let values = counts
        .into_iter()
        .map(|(key, value)| (key, value.to_string()))
        .chain([
            ("requiredUnknown".to_string(), required.0.to_string()),
            ("requiredQuarantined".to_string(), required.1.to_string()),
            (
                "repositoryState".to_string(),
                if envelope.content.permits_write_plan() {
                    "clean"
                } else {
                    "dirty"
                }
                .to_string(),
            ),
        ])
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
            ..CommandData::default()
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
    let cohort = match command
        .campaign
        .as_ref()
        .map(|value| aos_maintain::identity::CohortId::parse(value))
        .transpose()
    {
        Ok(cohort) => cohort,
        Err(error) => return invalid_plan_selection("maintain.invalid-campaign", &error),
    };
    let unit_id = match command.unit.as_ref().map(UnitId::parse).transpose() {
        Ok(unit) => unit,
        Err(error) => return invalid_plan_selection("maintain.invalid-unit", &error),
    };
    let unit_ids = if let Some(cohort) = &cohort {
        let units = envelope
            .inventory
            .units
            .iter()
            .filter(|unit| unit.cohort.as_ref() == Some(cohort))
            .map(|unit| unit.unit_id.clone())
            .collect::<Vec<_>>();
        if units.len() < 2 {
            return invalid_plan_selection(
                "maintain.invalid-campaign",
                &anyhow::anyhow!("campaign cohort is absent or does not contain multiple units"),
            );
        }
        units
    } else {
        vec![
            unit_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("plan requires a unit or campaign"))?,
        ]
    };
    let now = state::now_unix()?;
    if let Some(target) = &command.target {
        if let Err(error) = select_explicit_target(
            &envelope,
            &mut snapshot,
            unit_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("target requires a unit"))?,
            target,
            now,
        ) {
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
    if !command.component.is_empty() {
        let selections = match parse_component_selections(&command.component) {
            Ok(selections) => selections,
            Err(error) => {
                return completion(
                    "plan",
                    CommandDisposition::InvalidInvocation,
                    CommandData::default(),
                    vec![diagnostic(
                        "maintain.invalid-component-target",
                        DiagnosticSeverity::Error,
                        &error.to_string(),
                    )],
                    Vec::new(),
                    Vec::new(),
                );
            }
        };
        if let Err(error) = select_explicit_components(
            &envelope,
            &mut snapshot,
            unit_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("components require a unit"))?,
            &selections,
            now,
        ) {
            return completion(
                "plan",
                CommandDisposition::InvalidInvocation,
                CommandData::default(),
                vec![diagnostic(
                    "maintain.invalid-component-target",
                    DiagnosticSeverity::Error,
                    &error.to_string(),
                )],
                Vec::new(),
                Vec::new(),
            );
        }
    }
    for selected in &unit_ids {
        let Some(discovered) = snapshot
            .units
            .iter()
            .find(|unit| unit.unit_id == selected.as_str())
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
    }
    let mut plan = match aos_maintain::plan::create_campaign_plan(
        &envelope,
        &snapshot,
        cohort.as_ref(),
        &unit_ids,
        now,
    ) {
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
    let digest = if let Some(existing) = store.read_plan(plan.plan_id.as_str())? {
        plan.created_at_unix = existing.created_at_unix;
        if plan != existing {
            anyhow::bail!("existing immutable plan disagrees with its deterministic identity");
        }
        aos_contract::Sha256Digest::of_canonical(aos_maintain::PACKAGE_UPDATE_PLAN_V1, &existing)?
    } else {
        store.write_plan(&plan)?
    };
    completion(
        "plan",
        CommandDisposition::Success,
        CommandData {
            values: BTreeMap::from([("repositoryState".to_string(), "clean".to_string())]),
            plan: Some(plan.clone()),
            ..CommandData::default()
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
    printer: &Printer,
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
        let planned = plan_command(
            args,
            &crate::cli::MaintainPlanArgs {
                unit: command.unit.clone(),
                campaign: command.campaign.clone(),
                target: None,
                component: Vec::new(),
            },
        )?;
        let Some(plan) = planned.result.data.plan.clone() else {
            let mut result = planned.result;
            result.command = "run".to_string();
            return CommandCompletion::new(result);
        };
        plan
    };
    let _operation_lease = store.acquire_operation_lease(plan.plan_id.as_str())?;

    let now = state::now_unix()?;
    let plan_has_run = store
        .list_runs()?
        .iter()
        .any(|run| run.plan_id == plan.plan_id);
    if now >= plan.expires_at_unix && !plan_has_run {
        let mut argv = vec![
            "aos".to_string(),
            "maintain".to_string(),
            "plan".to_string(),
        ];
        if let Some(cohort) = &plan.cohort {
            argv.extend(["--campaign".to_string(), cohort.to_string()]);
        } else if let Ok(unit) = plan.single_unit() {
            argv.push(unit.unit_id.to_string());
        }
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
                argv,
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
    if envelope_digest != plan.inventory_envelope_digest
        || envelope.controller != plan.controller
        || inventory::controller_identity()? != plan.controller
    {
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
            match materialize::execute(&store, &plan, &mut run, cli.verbose, cli.quiet, printer)
                .await
            {
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
        let gates = match validation::quick(&store, &plan, &mut run, printer) {
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
            plan: Some(plan),
            run: Some(run.clone()),
            ..CommandData::default()
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
    _envelope: aos_maintain::envelope::InventoryEnvelopeV1,
    plan: aos_maintain::plan::PackageUpdatePlanV1,
    run: aos_maintain::run::PackageUpdateRunV1,
    code: &str,
    summary: &str,
) -> Result<CommandCompletion> {
    let inspect_failure = code == "maintain.quick-gate-failed";
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
            plan: Some(plan),
            run: Some(run.clone()),
            ..CommandData::default()
        },
        primary_values: vec![PrimaryValue {
            name: "runId".to_string(),
            value: run.run_id.to_string(),
        }],
        diagnostics: vec![diagnostic(code, DiagnosticSeverity::Error, summary)],
        next_actions: vec![NextAction {
            label: if inspect_failure {
                "Inspect failed gates"
            } else {
                "Inspect the stopped run"
            }
            .to_string(),
            argv: if inspect_failure {
                vec![
                    "aos".to_string(),
                    "maintain".to_string(),
                    "inspect".to_string(),
                    run.run_id.to_string(),
                    "--failure".to_string(),
                ]
            } else {
                vec![
                    "aos".to_string(),
                    "maintain".to_string(),
                    "status".to_string(),
                    run.run_id.to_string(),
                ]
            },
            reason: if inspect_failure {
                "retained results identify each failed gate and its bounded log"
            } else {
                "durable state identifies the last verified boundary"
            }
            .to_string(),
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

fn require_frozen_controller(plan: &aos_maintain::plan::PackageUpdatePlanV1) -> Result<()> {
    if inventory::controller_identity()? != plan.controller {
        anyhow::bail!(
            "the running AOS executable does not match the immutable plan's frozen controller"
        );
    }
    Ok(())
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
        values.insert(
            "patchDigest".to_string(),
            gates.candidate_digest.to_string(),
        );
    }
    let evidence = store.read_evidence(run.run_id.as_str())?;
    let publication = store.read_publication(run.run_id.as_str())?;
    let remote_observation = store.read_remote_observation(run.run_id.as_str())?;
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
            publication,
            remote_observation,
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
        RunState::Repairing => (
            "Inspect the retained repair proposal",
            vec!["repair", run.run_id.as_str()],
            "a retained adapter result requires a maintainer decision",
            EffectClass::ReadOnly,
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
        RunState::MergedObserved => (
            "Record release identity handoff",
            vec!["handoff", run.run_id.as_str()],
            "confirm the protected merge identity for independent release consumption",
            EffectClass::HumanDecision,
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

fn invalid_plan_selection(code: &str, error: &anyhow::Error) -> Result<CommandCompletion> {
    completion(
        "plan",
        CommandDisposition::InvalidInvocation,
        CommandData::default(),
        vec![diagnostic(
            code,
            DiagnosticSeverity::Error,
            &error.to_string(),
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
    select_explicit_components(
        envelope,
        snapshot,
        unit_id,
        &BTreeMap::from([(component_id.to_string(), target.to_string())]),
        now_unix,
    )
}

fn parse_component_selections(values: &[String]) -> Result<BTreeMap<String, String>> {
    let mut output = BTreeMap::new();
    for value in values {
        let (name, identity) = value
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("component target must use NAME=IDENTITY"))?;
        if name.is_empty()
            || identity.is_empty()
            || output
                .insert(name.to_string(), identity.to_string())
                .is_some()
        {
            anyhow::bail!("component targets must be non-empty and unique");
        }
    }
    Ok(output)
}

fn select_explicit_components(
    envelope: &aos_maintain::envelope::InventoryEnvelopeV1,
    snapshot: &mut aos_maintain::discovery::DiscoverySnapshotV1,
    unit_id: &aos_maintain::identity::UnitId,
    selections: &BTreeMap<String, String>,
    now_unix: u64,
) -> Result<()> {
    use aos_maintain::workflow::DiscoveryDecision;

    let unit = envelope
        .inventory
        .units
        .iter()
        .find(|unit| &unit.unit_id == unit_id)
        .ok_or_else(|| anyhow::anyhow!("unknown update unit {unit_id}"))?;
    let expected = unit
        .components
        .keys()
        .map(ToString::to_string)
        .collect::<std::collections::BTreeSet<_>>();
    if selections
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        anyhow::bail!("--component must select every component in the update unit");
    }
    let mut observations = BTreeMap::new();
    for (component, target) in selections {
        let key = format!("{unit_id}/{component}/primary");
        let observation = snapshot
            .observations
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("primary observation for {component} is unavailable"))?;
        let matches = observation
            .candidates
            .iter()
            .filter(|candidate| candidate.raw_id == *target || candidate.raw_version == *target)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            anyhow::bail!("component {component} target must match exactly one observed candidate");
        }
        let matched = matches
            .first()
            .ok_or_else(|| anyhow::anyhow!("component target disappeared during selection"))?;
        let mut exact = observation.clone();
        exact
            .candidates
            .retain(|candidate| candidate.raw_id == matched.raw_id);
        observations.insert(component.clone(), exact);
    }
    let selected =
        aos_maintain::discovery::select_unit(unit, &observations, now_unix, 24 * 60 * 60)?;
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
    if completion
        .result
        .data
        .values
        .get("interactiveRendered")
        .is_some_and(|value| value == "true")
    {
        return Ok(());
    }
    if matches!(args.command, Some(MaintainCommand::Diff(ref command)) if command.patch)
        && let Some(patch) = completion.result.data.patch.as_deref()
    {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(patch.as_bytes())?;
        return Ok(());
    }
    if cli.json {
        write_json(&completion.result)?;
        return Ok(());
    }
    if args.jsonl {
        write_json(&StreamEnvelope {
            schema_version: "aos.maintain.stream/v1",
            stream_sequence: 2,
            event_type: "result",
            result: &completion.result,
        })?;
        return Ok(());
    }

    render_human(&completion.result, args.screen_reader, printer);
    let mut stdout = std::io::stdout().lock();
    for value in &completion.result.primary_values {
        writeln!(stdout, "{}", value.value)?;
    }
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
        Some(MaintainCommand::Ui(_)) => "ui",
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
        Some(MaintainCommand::Repair(_)) => "repair",
        Some(MaintainCommand::Evidence(_)) => "evidence",
        Some(MaintainCommand::PreparePr(_)) => "prepare-pr",
        Some(MaintainCommand::PublishPr(_)) => "publish-pr",
        Some(MaintainCommand::ObservePr(_)) => "observe-pr",
        Some(MaintainCommand::Handoff(_)) => "handoff",
    }
}

fn activity_label(args: &MaintainArgs) -> Option<&'static str> {
    match args.command.as_ref()? {
        MaintainCommand::Inventory(_) => Some("Evaluating package maintenance inventory"),
        MaintainCommand::Scan(_) => Some("Checking direct upstreams and advisory evidence"),
        MaintainCommand::Run(_) | MaintainCommand::Resume(_) => {
            Some("Advancing the isolated package update")
        }
        MaintainCommand::Test(_) => Some("Running the immutable package gate plan"),
        MaintainCommand::Repair(_) => Some("Running the confined repair workflow"),
        MaintainCommand::PublishPr(_) => Some("Publishing the exact candidate branch and PR"),
        MaintainCommand::ObservePr(_) => Some("Refreshing exact-head pull-request evidence"),
        MaintainCommand::Ui(_)
        | MaintainCommand::Report(_)
        | MaintainCommand::Status(_)
        | MaintainCommand::Plan(_)
        | MaintainCommand::Inspect(_)
        | MaintainCommand::Diff(_)
        | MaintainCommand::Abandon(_)
        | MaintainCommand::Clean(_)
        | MaintainCommand::Accept(_)
        | MaintainCommand::Commit(_)
        | MaintainCommand::Evidence(_)
        | MaintainCommand::PreparePr(_)
        | MaintainCommand::Handoff(_) => None,
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
    if machine
        && matches!(
            args.command,
            Some(MaintainCommand::Diff(ref command)) if command.patch
        )
    {
        return Some("--patch cannot be combined with JSON or JSONL output".to_string());
    }
    if matches!(args.command, Some(MaintainCommand::Ui(_))) {
        use std::io::IsTerminal as _;

        if machine || args.screen_reader {
            return Some("maintain ui requires human terminal output".to_string());
        }
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Some("maintain ui requires interactive stdin and stdout terminals".to_string());
        }
    }
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
    match result.disposition {
        CommandDisposition::Success | CommandDisposition::NoChange => {
            printer.success(if screen_reader {
                "Complete"
            } else {
                "✓ Complete"
            });
        }
        CommandDisposition::ActionRequired
        | CommandDisposition::UpstreamUnknown
        | CommandDisposition::Stale => {
            printer.warning(if screen_reader {
                "Maintainer action required"
            } else {
                "◆ Maintainer action required"
            });
        }
        _ => {}
    }

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
        let unit_label = match result.command.as_str() {
            "plan" | "run" => "Inventory units",
            "report" => "Matching units",
            _ => "Units",
        };
        printer.kv(unit_label, &unit_count);
        if let Some(audited) = result.data.values.get("fixedOutputsAudited") {
            printer.kv("Fixed outputs", &format!("{audited} associations verified"));
        }
        if result.command == "inventory"
            && result.data.values.get("inventoryCheck").map(String::as_str) != Some("true")
        {
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
        if let (Some(updates), Some(unknown), Some(quarantined)) = (
            result.data.values.get("updateAvailable"),
            result.data.values.get("unknown"),
            result.data.values.get("quarantined"),
        ) {
            printer.kv(
                "Summary",
                &format!("{updates} available, {unknown} unknown, {quarantined} quarantined"),
            );
        }
        if let (Some(unknown), Some(quarantined)) = (
            result.data.values.get("requiredUnknown"),
            result.data.values.get("requiredQuarantined"),
        ) {
            printer.kv(
                "Required",
                &format!("{unknown} unknown, {quarantined} quarantined"),
            );
        }
        let visible = snapshot.units.iter().filter(|unit| {
            if result.command != "scan" {
                return true;
            }
            if matches!(
                unit.decision,
                DiscoveryDecision::UpdateAvailable | DiscoveryDecision::Quarantined
            ) {
                return true;
            }
            unit.decision == DiscoveryDecision::Unknown
                && result.data.inventory.as_ref().is_some_and(|inventory| {
                    inventory.inventory.units.iter().any(|candidate| {
                        candidate.unit_id.as_str() == unit.unit_id
                            && matches!(
                                candidate.classification,
                                Classification::Automatic | Classification::Assisted
                            )
                    })
                })
        });
        for unit in visible {
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
        if let Some(cohort) = &plan.cohort {
            printer.kv("Campaign", cohort.as_str());
        }
        for unit in &plan.units {
            printer.plain(&format!(
                "{}  {} -> {}",
                unit.unit_id,
                escape_terminal(&unit.current_package_version, 256),
                escape_terminal(&unit.target_package_version, 256)
            ));
        }
        printer.kv("Units", &plan.units.len().to_string());
        printer.kv(
            "Fields",
            &plan
                .units
                .iter()
                .map(|unit| unit.semantic_mutations.len())
                .sum::<usize>()
                .to_string(),
        );
        printer.kv(
            "Sources",
            &plan
                .units
                .iter()
                .map(|unit| unit.sources.len())
                .sum::<usize>()
                .to_string(),
        );
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
        if let Some(digest) = result.data.values.get("patchDigest") {
            printer.kv("Patch", digest);
        }
    }

    if result.command == "diff"
        && let Some(plan) = &result.data.plan
    {
        printer.plain("");
        printer.header("Semantic changes");
        for unit in &plan.units {
            printer.plain(&format!(
                "{}  {} -> {}",
                escape_terminal(unit.unit_id.as_str(), 256),
                escape_terminal(&unit.current_package_version, 256),
                escape_terminal(&unit.target_package_version, 256),
            ));
            for (component, target) in &unit.component_targets {
                printer.plain(&format!(
                    "  component {}  target {}",
                    escape_terminal(component.as_str(), 256),
                    escape_terminal(&target.upstream_id, 512),
                ));
            }
            for mutation in &unit.semantic_mutations {
                printer.plain(&format!(
                    "  {}:{}  {} -> {}",
                    escape_terminal(&mutation.owner, 4096),
                    escape_terminal(&mutation.field_path.join("."), 4096),
                    escape_terminal(&mutation.expected, 4096),
                    escape_terminal(&mutation.replacement, 4096),
                ));
            }
            for source in &unit.sources {
                printer.plain(&format!(
                    "  source {}/{}  resolve {}",
                    escape_terminal(source.component.as_str(), 256),
                    escape_terminal(source.slot.as_str(), 256),
                    escape_terminal(&source.upstream_id, 512),
                ));
            }
            for artifact in &unit.artifacts {
                printer.plain(&format!(
                    "  artifact {}  regenerate with {}",
                    escape_terminal(artifact.slot.as_str(), 256),
                    artifact_materializer_name(&artifact.materializer),
                ));
            }
        }
    }

    if !result.data.gate_results.is_empty() {
        printer.plain("");
        printer.header("Gates");
        for gates in &result.data.gate_results {
            let passed = gates
                .results
                .iter()
                .filter(|gate| gate.outcome == aos_maintain::workflow::GateOutcome::Success)
                .count();
            printer.plain(&format!(
                "{}  {passed}/{} passed",
                gates.phase,
                gates.results.len()
            ));
            for gate in gates
                .results
                .iter()
                .filter(|gate| gate.outcome != aos_maintain::workflow::GateOutcome::Success)
            {
                printer.plain(&format!(
                    "  {}  outcome={}  exit={}",
                    escape_terminal(&gate.gate_id, 256),
                    gate_outcome_name(gate.outcome),
                    gate.exit_code
                        .map_or_else(|| "signal".to_string(), |code| code.to_string())
                ));
            }
        }
    } else if result.command == "inspect"
        && result
            .data
            .values
            .get("inspectionFocus")
            .map(String::as_str)
            == Some("failure")
    {
        printer.plain("");
        printer.success("No retained gate failures");
    }

    if let Some(log) = &result.data.gate_log {
        printer.plain("");
        printer.header("Gate log");
        printer.kv("Gate", &escape_terminal(&log.gate_id, 256));
        printer.kv("Phase", &log.phase);
        if let Some(path) = &log.path {
            printer.plain(&escape_terminal(path, 8192));
        }
        if let Some(contents) = &log.contents {
            printer.plain(&escape_multiline(contents, 8 * 1024 * 1024));
        }
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

    if let (Some(task), Some(agent_result)) = (&result.data.agent_task, &result.data.agent_result) {
        printer.plain("");
        printer.header("Repair proposal");
        printer.kv("Attempt", &task.attempt.to_string());
        printer.kv(
            "Failure",
            task.failure.gate_id.as_deref().unwrap_or("package repair"),
        );
        printer.kv(
            "Result",
            agent_result_disposition_name(agent_result.disposition),
        );
        printer.kv(
            "Writable scope",
            &task
                .writable_paths
                .iter()
                .map(|path| escape_terminal(path, 4096))
                .collect::<Vec<_>>()
                .join(", "),
        );
        if !agent_result.scope_requests.is_empty() {
            for request in &agent_result.scope_requests {
                printer.plain(&format!(
                    "scope requested: {} ({})",
                    escape_terminal(&request.path, 4096),
                    escape_terminal(&request.reason, 4096),
                ));
            }
        }
    }

    if let Some(attempt) = &result.data.repair_attempt {
        printer.plain("");
        printer.header("Accepted repair");
        printer.kv("Attempt", &attempt.attempt.to_string());
        printer.kv("Candidate", &attempt.candidate_digest.to_string());
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

    if let Some(publication) = &result.data.publication {
        printer.plain("");
        printer.header("Published pull request");
        printer.kv("URL", &publication.pull_request_url);
        printer.kv("Remote", &publication.remote);
        printer.kv("Branch", &publication.branch);
        printer.kv("Base", &publication.base_branch);
        printer.kv("Head", &publication.head.value);
    }

    if let Some(observation) = &result.data.remote_observation {
        printer.plain("");
        printer.header("Remote observation");
        printer.kv("Head", &observation.head.value);
        printer.kv(
            "Authorization",
            if observation.authorization_succeeded {
                "passed"
            } else {
                "pending or failed"
            },
        );
        printer.kv(
            "Checks",
            &format!(
                "{} observed; {}",
                observation.checks.len(),
                if observation.checks_succeeded {
                    "passed"
                } else {
                    "pending or failed"
                }
            ),
        );
        printer.kv("Approvals", &observation.approvals.to_string());
        printer.kv(
            "Changes requested",
            &observation.changes_requested.to_string(),
        );
        printer.kv(
            "Mergeability",
            if observation.is_merge_eligible() {
                "eligible"
            } else {
                "not yet proven"
            },
        );
        if let Some(commit) = &observation.merge_commit {
            printer.kv("Protected merge", &commit.value);
        }
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

fn agent_result_disposition_name(
    disposition: aos_maintain::agent::AgentResultDisposition,
) -> &'static str {
    use aos_maintain::agent::AgentResultDisposition;

    match disposition {
        AgentResultDisposition::ProposedPatch => "proposed-patch",
        AgentResultDisposition::ScopeRequired => "scope-required",
        AgentResultDisposition::MaintainerQuestion => "maintainer-question",
        AgentResultDisposition::NoProposal => "no-proposal",
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

fn gate_outcome_name(outcome: aos_maintain::workflow::GateOutcome) -> &'static str {
    match outcome {
        aos_maintain::workflow::GateOutcome::Success => "success",
        aos_maintain::workflow::GateOutcome::Failure => "failure",
        aos_maintain::workflow::GateOutcome::ActionRequired => "action-required",
        aos_maintain::workflow::GateOutcome::Cancelled => "cancelled",
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

fn artifact_materializer_name(
    materializer: &aos_maintain::inventory::ArtifactMaterializer,
) -> &'static str {
    use aos_maintain::inventory::ArtifactMaterializer;

    match materializer {
        ArtifactMaterializer::CargoDeps { .. } => "cargo-deps",
        ArtifactMaterializer::CargoVendor { .. } => "cargo-vendor",
        ArtifactMaterializer::GoModules { .. } => "go-modules",
        ArtifactMaterializer::NpmDeps { .. } => "npm-deps",
        ArtifactMaterializer::BazelDeps { .. } => "bazel-deps",
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
        let printer = Printer::new(0, false, true);
        let completion = run(&cli, args, &printer)
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressStreamEnvelope<'a> {
    schema_version: &'static str,
    stream_sequence: u64,
    #[serde(rename = "type")]
    event_type: &'static str,
    event: &'a ProgressEvent,
}
