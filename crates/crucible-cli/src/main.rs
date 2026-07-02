//! `crucible` is the CLI entry point for the Crucible control plane.
//!
//! Spec index: RFC-0010 files 23.
//!
//! This L4 binary crate will remain a thin client over `crucible-api` and
//! `crucible-session` as specified by RFC-0010 file 23.
//!
//! Module map: the binary root owns argument dispatch only; future command
//! modules will remain transport clients over the session and API crates.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand, ValueEnum};
use crucible::DagStore;
use crucible_session::SessionCommand;

const REPRODUCTION_ARTIFACT_SCHEMA: &str = "crucible.reproduction-artifact.v1";
const REPRODUCTION_ARTIFACT_MEDIA_TYPE: &str = "application/vnd.crucible.reproduction+text";
const CONTENT_ADDRESS_PREFIX: &str = "crucible-hash:";

#[derive(Parser, Debug, PartialEq, Eq)]
#[command(
    name = "crucible",
    version,
    about = "Run and inspect Crucible simulations.",
    disable_help_subcommand = true
)]
struct Cli {
    /// Set root entropy.
    #[arg(long, env = "CRUCIBLE_SEED", value_name = "u64|hex", global = true)]
    seed: Option<String>,
    /// Select local backend.
    #[arg(long, value_enum, default_value_t = Backend::Auto, global = true)]
    backend: Backend,
    /// Use remote daemon.
    #[arg(long, value_name = "addr", global = true)]
    daemon: Option<String>,
    /// Use patched QEMU binary.
    #[arg(long, value_name = "path", global = true)]
    qemu: Option<PathBuf>,
    /// Use Crucible QEMU plugin.
    #[arg(long, value_name = "path", global = true)]
    plugin: Option<PathBuf>,
    /// Use content-addressed store root.
    #[arg(long, value_name = "path", global = true)]
    store: Option<PathBuf>,
    /// Select output format.
    #[arg(
        long,
        value_enum,
        value_name = "jsonl|json|table|markdown",
        default_value_t = OutputFormat::Jsonl,
        global = true
    )]
    format: OutputFormat,
    /// Write event log stream.
    #[arg(long, value_name = "path", global = true)]
    trace: Option<PathBuf>,
    /// Write failure artifacts here.
    #[arg(
        long,
        value_name = "path",
        default_value = "./.crucible",
        global = true
    )]
    artifact_dir: PathBuf,
    /// Increase log verbosity.
    #[arg(short = 'v', long, action = ArgAction::Count, global = true)]
    verbose: u8,
    /// Suppress non-essential output.
    #[arg(short = 'q', long, action = ArgAction::SetTrue, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum Backend {
    /// Discover the best local backend.
    #[default]
    Auto,
    /// Use patched QEMU locally.
    Qemu,
    /// Use the in-process test double.
    Double,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Emit newline-delimited JSON.
    #[default]
    Jsonl,
    /// Emit one JSON document.
    Json,
    /// Emit a human-readable table.
    Table,
    /// Emit Markdown.
    Markdown,
}

impl OutputFormat {
    fn triage_report_format(self) -> crucible::FailureClusterReportFormat {
        match self {
            Self::Jsonl => crucible::FailureClusterReportFormat::JsonLines,
            Self::Json => crucible::FailureClusterReportFormat::Json,
            Self::Table => crucible::FailureClusterReportFormat::Table,
            Self::Markdown => crucible::FailureClusterReportFormat::Markdown,
        }
    }
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum Commands {
    /// Run a scenario to completion.
    Run(RunArgs),
    /// Prove deterministic replay.
    Verify(VerifyArgs),
    /// Run selected built-in gates.
    Selftest(SelftestArgs),
    /// Run to a savepoint.
    Save(SaveArgs),
    /// Resume from a checkpoint.
    Resume(ResumeArgs),
    /// Fork from a savepoint.
    Fork(ForkArgs),
    /// Replay a reproduction artifact.
    Replay(ReplayArgs),
    /// Drive state-space search.
    Search(SearchArgs),
    /// Drive coverage-guided fuzzing.
    Fuzz(FuzzArgs),
    /// Cluster, dedup, and minimize discovered failures.
    Triage(TriageArgs),
    /// Open the time-travel debugger.
    Debug(DebugArgs),
    /// Run the API daemon.
    Serve(ServeArgs),
    /// Generate shell completions.
    Completions(CompletionsArgs),
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct RunArgs {
    /// Emit a mock failure artifact for gate testing.
    #[arg(long, hide = true, action = ArgAction::SetTrue)]
    emit_mock_failure_artifact: bool,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct VerifyArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct SelftestArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct SaveArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ResumeArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ForkArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ReplayArgs {
    /// Read this reproduction artifact.
    #[arg(value_name = "ARTIFACT")]
    artifact: PathBuf,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct SearchArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct FuzzArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct TriageArgs {
    /// Read this findings ledger.
    #[arg(value_name = "FINDINGS")]
    findings: String,
    /// Select the failure-signature policy.
    #[arg(
        long,
        value_enum,
        value_name = "coarse|default|fine|exact",
        default_value_t = TriagePolicyArg::Default
    )]
    policy: TriagePolicyArg,
    /// Select representative minimization mode.
    #[arg(
        long,
        value_enum,
        value_name = "none|representative|all",
        default_value_t = TriageMinimizeArg::Representative
    )]
    minimize: TriageMinimizeArg,
    /// Write per-cluster reports here.
    #[arg(long, value_name = "dir")]
    report: Option<PathBuf>,
    /// Recompute signatures and fail if discovery-time bytes drift.
    #[arg(long, action = ArgAction::SetTrue)]
    recompute_signatures: bool,
    /// Diff against another content-addressed triage result.
    #[arg(long, value_name = "other-triage-result")]
    compare: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum TriagePolicyArg {
    /// Coarse failure-signature grouping.
    Coarse,
    /// Default failure-signature grouping.
    #[default]
    Default,
    /// Fine failure-signature grouping.
    Fine,
    /// Exact failure-signature grouping.
    Exact,
}

impl TriagePolicyArg {
    fn policy(self) -> crucible::SignaturePolicy {
        match self {
            Self::Coarse => crucible::SignaturePolicy::coarse(),
            Self::Default => crucible::SignaturePolicy::default_policy(),
            Self::Fine => crucible::SignaturePolicy::fine(),
            Self::Exact => crucible::SignaturePolicy::exact(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum TriageMinimizeArg {
    /// Skip minimization and report representatives unchanged.
    None,
    /// Minimize the content-address-least representative per cluster.
    #[default]
    Representative,
    /// Minimize every finding in every cluster.
    All,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
#[command(group(
    ArgGroup::new("debug_coordinate")
        .args(["at", "at_event", "at_failure", "at_checkpoint"])
        .multiple(false)
))]
struct DebugArgs {
    /// Attach to this artifact or savepoint.
    #[arg(value_name = "ARTIFACT|SAVEPOINT", conflicts_with = "session")]
    target: Option<String>,
    /// Attach to a running session.
    #[arg(long, value_name = "ADDR")]
    session: Option<String>,
    /// Open at a virtual-time or node-icount coordinate.
    #[arg(long, value_name = "COORD")]
    at: Option<String>,
    /// Open at this event-log sequence.
    #[arg(long, value_name = "SEQ")]
    at_event: Option<u64>,
    /// Open at the recorded failure point.
    #[arg(long, action = ArgAction::SetTrue)]
    at_failure: bool,
    /// Open at this checkpoint content address.
    #[arg(long, value_name = "HASH")]
    at_checkpoint: Option<String>,
    /// Attach this node's gdbstub.
    #[arg(long, value_name = "ID")]
    node: Option<String>,
    /// Listen for gdb-protocol clients here.
    #[arg(long, value_name = "ADDR")]
    gdb_listen: Option<String>,
    /// Keep the canonical run read-only.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "allow_mutate")]
    read_only: bool,
    /// Fork a non-canonical branch for mutation.
    #[arg(long, action = ArgAction::SetTrue)]
    allow_mutate: bool,
    /// Bound reverse-step replay distance.
    #[arg(long, value_name = "N")]
    checkpoint_stride: Option<u64>,
    #[command(subcommand)]
    verb: Option<DebugVerbArgs>,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum DebugVerbArgs {
    /// Open the mediated gdbstub channel.
    AttachGdb,
    /// Move to another debug coordinate.
    Goto {
        /// Coordinate accepted by --at.
        coord: String,
    },
    /// Step backward by one deterministic grain.
    ReverseStep {
        /// Reverse-step grain.
        #[arg(value_enum)]
        grain: DebugStepGrainArg,
    },
    /// Continue backward to a matching condition.
    ReverseContinue {
        /// Condition expression.
        condition: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum DebugStepGrainArg {
    /// Instruction-scale coordinate.
    Instruction,
    /// Scheduler quantum.
    Quantum,
    /// Event-log entry.
    Event,
    /// Assertion-state transition.
    Assertion,
    /// Timer event.
    Timer,
}

impl DebugStepGrainArg {
    fn reverse_grain(self) -> crucible::DebugReverseStepGrain {
        match self {
            Self::Instruction => crucible::DebugReverseStepGrain::Instruction,
            Self::Quantum => crucible::DebugReverseStepGrain::Quantum,
            Self::Event => crucible::DebugReverseStepGrain::Event,
            Self::Assertion => crucible::DebugReverseStepGrain::Assertion,
            Self::Timer => crucible::DebugReverseStepGrain::Timer,
        }
    }
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ServeArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct CompletionsArgs {}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => handle_cli_parse_error(error),
    };
    if let Err(error) = dispatch(&cli) {
        eprintln!("crucible: {error}");
        std::process::exit(error.exit_code());
    }
}

fn handle_cli_parse_error(error: clap::Error) -> ! {
    let exit_code = cli_parse_error_exit_code(&error);
    if let Err(print_error) = error.print() {
        eprintln!("crucible: {print_error}");
        std::process::exit(CliError::Io(print_error).exit_code());
    }
    std::process::exit(exit_code);
}

fn cli_parse_error_exit_code(error: &clap::Error) -> i32 {
    match error.kind() {
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => 0,
        _ => CliError::Usage(error.to_string()).exit_code(),
    }
}

fn dispatch(cli: &Cli) -> Result<(), CliError> {
    match &cli.command {
        Commands::Replay(args) => {
            let report = replay_reproduction_artifact(cli, args)?;
            if !cli.quiet {
                println!(
                    "crucible: replay artifact {} ({}) seed={} scenario={} digest={}",
                    report.path.display(),
                    REPRODUCTION_ARTIFACT_MEDIA_TYPE,
                    report.seed,
                    report.scenario_digest,
                    report.digest
                );
            }
            Ok(())
        }
        Commands::Run(args) => {
            if args.emit_mock_failure_artifact {
                let artifact = mock_failure_reproduction_artifact_bytes(cli)?;
                let report = write_failure_reproduction_artifact(cli, &artifact, "mock failure")?;
                if !cli.quiet {
                    println!(
                        "crucible: wrote reproduction artifact {} ({}) digest={}",
                        report.path.display(),
                        REPRODUCTION_ARTIFACT_MEDIA_TYPE,
                        report.digest
                    );
                    println!("crucible: reproduce with:\n    {}", report.replay_command);
                    println!(
                        "crucible: debug at the failure with:\n    {}",
                        report.debug_command
                    );
                }
            }
            Ok(())
        }
        Commands::Selftest(_) => {
            let report = run_selftest(cli)?;
            if !cli.quiet {
                for verified in report.verified {
                    println!(
                        "crucible: selftest {} PASS runs={}",
                        verified.scenario_name, verified.runs
                    );
                }
            }
            Ok(())
        }
        Commands::Verify(_)
        | Commands::Save(_)
        | Commands::Resume(_)
        | Commands::Fork(_)
        | Commands::Search(_)
        | Commands::Fuzz(_)
        | Commands::Serve(_)
        | Commands::Completions(_) => Ok(()),
        Commands::Triage(args) => {
            let report = run_triage_invocation(cli, args)?;
            if !cli.quiet {
                println!(
                    "crucible: triage findings={} findings_count={} ledger={} ledger_cache_hit={} policy={} minimize={} clusters={} report={} format={} store={} result={} cache_hit={} compare={}",
                    report.plan.findings.label(),
                    report.ledger.artifact_count(),
                    format_content_hash_ref(report.stored_ledger.key),
                    report.stored_ledger.cache_hit,
                    report.plan.policy_label(),
                    report.plan.minimize_label(),
                    report.result.clustering.cluster_count(),
                    report.report_path.display(),
                    report.plan.format_label(),
                    report.plan.store_root.display(),
                    format_content_hash_ref(report.stored_result.key),
                    report.stored_result.cache_hit,
                    report
                        .compare
                        .as_ref()
                        .map(|diff| diff.status_label())
                        .unwrap_or("none")
                );
                if let Some(diff) = &report.compare {
                    println!("{}", diff.content_diff());
                }
            }
            Ok(())
        }
        Commands::Debug(args) => {
            let plan = plan_debug_invocation(cli, args)?;
            if !cli.quiet {
                println!(
                    "crucible: debug target={} coordinate={} mode={} listen={} verb={}",
                    plan.target.label(),
                    plan.coordinate.label(),
                    plan.mode_label(),
                    plan.gdb_listen,
                    plan.verb.label()
                );
            }
            Ok(())
        }
    }
}

fn run_selftest(_cli: &Cli) -> Result<SelftestReport, CliError> {
    let corpus = crucible::built_in_example_corpus().map_err(CliError::Selftest)?;
    let mut verified = Vec::with_capacity(corpus.len());
    for fixture in corpus {
        verified
            .push(crucible::verify_example_scenario_runs(&fixture, 5).map_err(CliError::Selftest)?);
    }
    Ok(SelftestReport { verified })
}

fn replay_reproduction_artifact(
    cli: &Cli,
    args: &ReplayArgs,
) -> Result<ReplayArtifactReport, CliError> {
    let bytes = fs::read(&args.artifact)?;
    let artifact = validate_replayable_reproduction_artifact(cli, &bytes)?;
    Ok(ReplayArtifactReport {
        path: args.artifact.clone(),
        digest: content_address_bytes(&bytes),
        seed: artifact.seed,
        scenario_digest: artifact.scenario.digest,
    })
}

fn write_failure_reproduction_artifact(
    cli: &Cli,
    artifact_bytes: &[u8],
    failure_slug: &str,
) -> Result<FailureArtifactReport, CliError> {
    validate_replayable_reproduction_artifact(cli, artifact_bytes)?;
    let digest = content_address_bytes(artifact_bytes);
    fs::create_dir_all(&cli.artifact_dir)?;
    let file_name = format!(
        "repro-{}-{}.crucible",
        sanitize_slug(failure_slug),
        short_digest(&digest)
    );
    let path = cli.artifact_dir.join(file_name);
    fs::write(&path, artifact_bytes)?;
    let replay_command = format!("crucible replay {}", path.display());
    let debug_command =
        crucible::DebugFailureFooterCommand::new(path.display().to_string()).debug_command;

    Ok(FailureArtifactReport {
        path,
        digest,
        replay_command,
        debug_command,
    })
}

fn plan_triage_invocation(cli: &Cli, args: &TriageArgs) -> Result<TriageInvocationPlan, CliError> {
    if cli.daemon.is_some() {
        return Err(CliError::Backend(
            "triage is an offline DagStore operation and must not use --daemon".to_string(),
        ));
    }
    if args.findings.is_empty() {
        return Err(usage_error("triage requires a non-empty FINDINGS argument"));
    }

    let findings = parse_triage_findings_source(&args.findings);
    let compare = args
        .compare
        .as_deref()
        .map(parse_triage_compare_target)
        .transpose()?;
    let report_dir = args
        .report
        .clone()
        .unwrap_or_else(|| cli.artifact_dir.clone());
    let store_root = cli
        .store
        .clone()
        .unwrap_or_else(|| cli.artifact_dir.join("store"));
    let mut pipeline = vec![TriagePipelineStep::LoadFindingsLedger];
    if args.recompute_signatures {
        pipeline.push(TriagePipelineStep::RecomputeSignatureSelfCheck);
    }
    pipeline.push(TriagePipelineStep::Cluster);
    pipeline.push(match args.minimize {
        TriageMinimizeArg::None => TriagePipelineStep::SkipMinimization,
        TriageMinimizeArg::Representative => TriagePipelineStep::MinimizeRepresentative,
        TriageMinimizeArg::All => TriagePipelineStep::MinimizeAll,
    });
    pipeline.push(TriagePipelineStep::EmitReports);
    pipeline.push(TriagePipelineStep::StoreTriageResult);
    if compare.is_some() {
        pipeline.push(TriagePipelineStep::CompareContentDiff);
    }

    let plan = TriageInvocationPlan {
        findings,
        policy: args.policy.policy(),
        minimize: args.minimize,
        report_dir,
        format: cli.format.triage_report_format(),
        recompute_signatures: args.recompute_signatures,
        compare,
        store_root,
        pipeline,
        failure_exit_code: CliError::Triage(
            "triage self-check or signature-preserving minimization failed".to_string(),
        )
        .exit_code(),
        thin_driver: true,
        owns_run_state: false,
        offline: true,
        scheduler_started: false,
    };
    if !plan.proves_t_tri_7() {
        return Err(CliError::Backend(
            "triage planner does not satisfy the RFC-0010 thin-driver contract".to_string(),
        ));
    }
    Ok(plan)
}

fn run_triage_invocation(cli: &Cli, args: &TriageArgs) -> Result<TriageRunReport, CliError> {
    let plan = plan_triage_invocation(cli, args)?;
    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    let ledger = load_triage_findings_ledger(&store, &plan.findings)?;
    let stored_ledger = ledger.store(&store).map_err(CliError::Store)?;
    if ledger.artifact_count() != 0 {
        return Err(CliError::Artifact(format!(
            "triage findings ledger contains {} artifact(s), but discovery-time signature evidence is not available in this ledger format",
            ledger.artifact_count()
        )));
    }

    let findings = Vec::<crucible::FailureClusterFinding>::new();
    let clustering = crucible::FailureClusteringResult::from_findings(plan.policy, findings)
        .map_err(|_| {
            CliError::Triage("triage clustering failed for the findings ledger".to_string())
        })?;
    let minimization = crucible::FailureSignaturePreservingMinimizationResult {
        policy: plan.policy,
        runs: Vec::new(),
    };
    let report_set = crucible::FailureClusterReportSet::from_reports(plan.policy, Vec::new())
        .map_err(|_| CliError::Triage("triage report set assembly failed".to_string()))?;
    let signature_self_check = if plan.recompute_signatures {
        crucible::FailureTriageSignatureSelfCheck::from_signature_pairs(Vec::<
            crucible::FailureTriageSignatureSelfCheckInput,
        >::new())
    } else {
        crucible::FailureTriageSignatureSelfCheck::skipped()
    };
    let result = crucible::FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering,
        minimization,
        report_set,
        signature_self_check,
    )
    .map_err(|_| CliError::Triage("triage result validation failed".to_string()))?;
    let report_path = write_triage_report(&plan, &result.report_set)?;
    let compare = plan
        .compare
        .as_ref()
        .map(|target| compare_triage_result(&store, &result, target))
        .transpose()?;
    let stored_result = result.store(&store).map_err(CliError::Store)?;

    Ok(TriageRunReport {
        plan,
        ledger,
        stored_ledger,
        result,
        stored_result,
        report_path,
        compare,
    })
}

fn load_triage_findings_ledger(
    store: &crucible::LocalDagStore,
    source: &TriageFindingsSource,
) -> Result<crucible::FailureFindingsLedger, CliError> {
    match source {
        TriageFindingsSource::StoredLedger(hash) => {
            let bytes = store.get(hash).map_err(CliError::Store)?;
            parse_failure_findings_ledger_bytes(&bytes)
        }
        TriageFindingsSource::Path(path) if path.is_dir() => {
            let mut entries = fs::read_dir(path)?
                .collect::<Result<Vec<_>, io::Error>>()?
                .into_iter()
                .filter_map(|entry| {
                    entry
                        .file_type()
                        .ok()
                        .filter(|kind| kind.is_file())
                        .map(|_| entry.path())
                })
                .collect::<Vec<_>>();
            entries.sort();
            let mut artifacts = Vec::with_capacity(entries.len());
            for entry in entries {
                let bytes = fs::read(&entry)?;
                artifacts.push(store.put(&bytes).map_err(CliError::Store)?);
            }
            Ok(crucible::FailureFindingsLedger::from_artifacts(artifacts))
        }
        TriageFindingsSource::Path(path) => {
            let bytes = fs::read(path)?;
            parse_failure_findings_ledger_bytes(&bytes).or_else(|_| {
                store
                    .put(&bytes)
                    .map(|hash| crucible::FailureFindingsLedger::from_artifacts([hash]))
                    .map_err(CliError::Store)
            })
        }
    }
}

fn parse_failure_findings_ledger_bytes(
    bytes: &[u8],
) -> Result<crucible::FailureFindingsLedger, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| artifact_error(format!("findings ledger is not UTF-8: {error}")))?;
    if text.lines().next() != Some("crucible.failure-triage.findings-ledger.v1") {
        return Err(artifact_error(
            "unsupported findings ledger artifact schema",
        ));
    }
    let mut artifacts = Vec::new();
    for line in text.lines() {
        if let Some(hex) = line.strip_prefix("artifact.") {
            let Some((_, value)) = hex.split_once('=') else {
                return Err(artifact_error("malformed findings ledger artifact line"));
            };
            artifacts.push(parse_hex_content_hash("findings ledger artifact", value)?);
        }
    }
    Ok(crucible::FailureFindingsLedger::from_artifacts(artifacts))
}

fn write_triage_report(
    plan: &TriageInvocationPlan,
    report_set: &crucible::FailureClusterReportSet,
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&plan.report_dir)?;
    let path = plan.report_dir.join(format!(
        "triage-report.{}",
        triage_report_extension(plan.format)
    ));
    fs::write(&path, report_set.render(plan.format))?;
    Ok(path)
}

fn compare_triage_result(
    store: &crucible::LocalDagStore,
    result: &crucible::FailureTriageResult,
    target: &TriageCompareTarget,
) -> Result<TriageSummaryDiff, CliError> {
    let baseline = match target {
        TriageCompareTarget::StoredResult(hash) => {
            let bytes = store.get(hash).map_err(CliError::Store)?;
            TriageResultSummary::from_artifact_bytes(&bytes)?
        }
        TriageCompareTarget::Path(path) => {
            let bytes = fs::read(path)?;
            TriageResultSummary::from_artifact_bytes(&bytes)?
        }
    };
    Ok(TriageResultSummary::from_result(result).diff_from(&baseline))
}

fn triage_report_extension(format: crucible::FailureClusterReportFormat) -> &'static str {
    match format {
        crucible::FailureClusterReportFormat::JsonLines => "jsonl",
        crucible::FailureClusterReportFormat::Json => "json",
        crucible::FailureClusterReportFormat::Table => "txt",
        crucible::FailureClusterReportFormat::Markdown => "md",
    }
}

fn parse_hex_content_hash(
    field: &'static str,
    hex: &str,
) -> Result<crucible::ContentHash, CliError> {
    let reference = format!("blake3:{hex}");
    crucible::ContentAddressedBlobRef::parse(field, &reference)
        .map(crucible::ContentAddressedBlobRef::hash)
        .map_err(|error| artifact_error(format!("invalid {field}: {error}")))
}

fn format_content_hash_ref(hash: crucible::ContentHash) -> String {
    crucible::ContentAddressedBlobRef::from_hash(hash).to_uri()
}

fn parse_triage_findings_source(value: &str) -> TriageFindingsSource {
    if let Ok(reference) = crucible::ContentAddressedBlobRef::parse("findings", value) {
        TriageFindingsSource::StoredLedger(reference.hash())
    } else {
        TriageFindingsSource::Path(PathBuf::from(value))
    }
}

fn parse_triage_compare_target(value: &str) -> Result<TriageCompareTarget, CliError> {
    if value.is_empty() {
        return Err(usage_error("--compare must not be empty"));
    }
    if let Ok(reference) = crucible::ContentAddressedBlobRef::parse("triage compare", value) {
        Ok(TriageCompareTarget::StoredResult(reference.hash()))
    } else {
        Ok(TriageCompareTarget::Path(PathBuf::from(value)))
    }
}

fn plan_debug_invocation(cli: &Cli, args: &DebugArgs) -> Result<DebugInvocationPlan, CliError> {
    if cli.backend == Backend::Double {
        return Err(CliError::Backend(
            "selected backend `double` does not implement open_gdbstub".to_string(),
        ));
    }

    let target = debug_target(args)?;
    let coordinate = debug_coordinate(args, &target)?;
    let checkpoint_stride = args
        .checkpoint_stride
        .map(validate_debug_checkpoint_stride)
        .transpose()?;
    if args.node.as_deref().is_some_and(str::is_empty) {
        return Err(usage_error("--node must not be empty"));
    }
    let gdb_listen = args
        .gdb_listen
        .clone()
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    crucible::DebugGdbEndpoint::new("gdb_listen", gdb_listen.clone())
        .map_err(|error| usage_error(format!("invalid --gdb-listen: {error}")))?;

    let verb = debug_verb(args)?;
    let read_only = args.read_only || !args.allow_mutate;
    let mut session_commands = vec![SessionCommand::query_snapshot(), SessionCommand::Snapshot];
    let mut engine_operations = vec![
        DebugEngineOperation::ResolveTarget,
        DebugEngineOperation::Instantiate,
        DebugEngineOperation::AttachGdbProxy,
        DebugEngineOperation::OpenGdbstub,
        DebugEngineOperation::Goto,
        DebugEngineOperation::RestoreNearestCheckpointReplay,
        DebugEngineOperation::ReadOnlyInspection,
        DebugEngineOperation::NoSymbolServer,
        DebugEngineOperation::MultiVcpuThreadEnumeration,
        DebugEngineOperation::DisableRawGdbSingleStep,
    ];

    match &verb {
        DebugInteractiveVerbPlan::AttachGdb => {
            engine_operations.push(DebugEngineOperation::AttachGdbProxy);
        }
        DebugInteractiveVerbPlan::Goto(_) => {
            engine_operations.push(DebugEngineOperation::Goto);
        }
        DebugInteractiveVerbPlan::ReverseStep { .. } => {
            session_commands.push(SessionCommand::query_snapshot());
            engine_operations.push(DebugEngineOperation::ReverseStep);
            engine_operations.push(DebugEngineOperation::RestoreNearestCheckpointReplay);
        }
        DebugInteractiveVerbPlan::ReverseContinue { .. } => {
            session_commands.push(SessionCommand::query_snapshot());
            engine_operations.push(DebugEngineOperation::ReverseContinue);
        }
    }

    if args.allow_mutate {
        session_commands.push(SessionCommand::fork_current());
        engine_operations.push(DebugEngineOperation::NonCanonicalBranchFork);
    }
    if checkpoint_stride.is_some() {
        engine_operations.push(DebugEngineOperation::CheckpointCadence);
    }

    let plan = DebugInvocationPlan {
        target,
        coordinate,
        node: args.node.clone(),
        gdb_listen,
        read_only,
        allow_mutate: args.allow_mutate,
        checkpoint_stride,
        verb,
        session_commands,
        engine_operations,
        surface_contract: crucible::DebugCliSurfaceContract::rfc0010(),
        owns_debug_state: false,
        raw_gdb_single_step_allowed: false,
        non_canonical_branch_label: args
            .allow_mutate
            .then(|| "NON-CANONICAL debug branch".to_string()),
    };
    if !plan.proves_t_dbg_8() {
        return Err(CliError::Backend(
            "debug planner does not satisfy the RFC-0010 debug surface contract".to_string(),
        ));
    }
    Ok(plan)
}

fn debug_target(args: &DebugArgs) -> Result<DebugPlanTarget, CliError> {
    match (&args.target, &args.session) {
        (Some(_), Some(_)) => Err(usage_error(
            "debug accepts either ARTIFACT|SAVEPOINT or --session, not both",
        )),
        (None, None) => Err(usage_error(
            "debug requires ARTIFACT|SAVEPOINT or --session",
        )),
        (None, Some(session)) => Ok(DebugPlanTarget::Session(session.clone())),
        (Some(target), None) => {
            if let Ok(reference) = crucible::ContentAddressedBlobRef::parse("debug target", target)
            {
                Ok(DebugPlanTarget::Savepoint(reference.hash()))
            } else {
                Ok(DebugPlanTarget::Artifact(PathBuf::from(target)))
            }
        }
    }
}

fn debug_coordinate(
    args: &DebugArgs,
    target: &DebugPlanTarget,
) -> Result<DebugPlanCoordinate, CliError> {
    if let Some(at) = &args.at {
        return parse_debug_at_coordinate(at).map(DebugPlanCoordinate::At);
    }
    if let Some(sequence) = args.at_event {
        return Ok(DebugPlanCoordinate::AtEvent(sequence));
    }
    if args.at_failure {
        return Ok(DebugPlanCoordinate::AtFailure);
    }
    if let Some(checkpoint) = &args.at_checkpoint {
        return crucible::ContentAddressedBlobRef::parse("at-checkpoint", checkpoint)
            .map(|reference| DebugPlanCoordinate::AtCheckpoint(reference.hash()))
            .map_err(|error| usage_error(format!("invalid --at-checkpoint: {error}")));
    }
    Ok(match target {
        DebugPlanTarget::Artifact(_) => DebugPlanCoordinate::AtFailure,
        DebugPlanTarget::Savepoint(hash) => DebugPlanCoordinate::AtCheckpoint(*hash),
        DebugPlanTarget::Session(_) => DebugPlanCoordinate::Current,
    })
}

fn parse_debug_at_coordinate(value: &str) -> Result<crucible::DebugCoordinate, CliError> {
    if let Some(ticks) = value.strip_prefix("vtime:") {
        return parse_virtual_time(ticks);
    }
    if let Some(node_icount) = value.strip_prefix("icount:") {
        return parse_node_icount(node_icount);
    }
    if value.contains(':') {
        return parse_node_icount(value);
    }
    parse_virtual_time(value)
}

fn parse_virtual_time(value: &str) -> Result<crucible::DebugCoordinate, CliError> {
    let ticks = parse_u64_value("--at", value)?;
    Ok(crucible::DebugCoordinate::virtual_time(
        crucible::VirtualTime { ticks },
    ))
}

fn parse_node_icount(value: &str) -> Result<crucible::DebugCoordinate, CliError> {
    let Some((node, retired)) = value.split_once(':') else {
        return Err(usage_error(
            "--at node-icount coordinates must be `icount:<node>:<retired>`",
        ));
    };
    if node.is_empty() {
        return Err(usage_error("--at node-icount coordinate has an empty node"));
    }
    let retired = parse_u64_value("--at", retired)?;
    Ok(crucible::DebugCoordinate::node_icount(
        crucible::NodeId {
            name: node.to_string(),
        },
        crucible::Icount { retired },
    ))
}

fn parse_u64_value(field: &'static str, value: &str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|_| {
        usage_error(format!(
            "{field} must be an unsigned integer value, got `{value}`"
        ))
    })
}

fn validate_debug_checkpoint_stride(stride: u64) -> Result<u64, CliError> {
    let Ok(every) = usize::try_from(stride) else {
        return Err(usage_error(
            "--checkpoint-stride is too large for this platform",
        ));
    };
    if crucible::DebugCheckpointStride::new(every).is_none() {
        return Err(usage_error("--checkpoint-stride must be non-zero"));
    }
    Ok(stride)
}

fn debug_verb(args: &DebugArgs) -> Result<DebugInteractiveVerbPlan, CliError> {
    match &args.verb {
        None | Some(DebugVerbArgs::AttachGdb) => Ok(DebugInteractiveVerbPlan::AttachGdb),
        Some(DebugVerbArgs::Goto { coord }) => {
            parse_debug_at_coordinate(coord).map(DebugInteractiveVerbPlan::Goto)
        }
        Some(DebugVerbArgs::ReverseStep { grain }) => Ok(DebugInteractiveVerbPlan::ReverseStep {
            grain: grain.reverse_grain(),
        }),
        Some(DebugVerbArgs::ReverseContinue { condition }) => {
            Ok(DebugInteractiveVerbPlan::ReverseContinue {
                condition: condition.clone(),
            })
        }
    }
}

fn short_digest(digest: &str) -> &str {
    digest
        .strip_prefix(CONTENT_ADDRESS_PREFIX)
        .and_then(|hex| hex.get(..12))
        .unwrap_or("unknown")
}

fn sanitize_slug(slug: &str) -> String {
    let mut sanitized = slug
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while sanitized.contains("--") {
        sanitized = sanitized.replace("--", "-");
    }
    sanitized = sanitized.trim_matches('-').to_string();
    if sanitized.is_empty() {
        String::from("failure")
    } else {
        sanitized
    }
}

#[derive(Debug)]
struct CliReproductionArtifact {
    seed: u64,
    identity: CliIdentity,
    scenario: CliComponent,
    components: Vec<CliComponent>,
    payloads: Vec<CliPayload>,
    schedule_digest: String,
    decisions: Vec<CliDecision>,
    fingerprints: Vec<CliFingerprint>,
    sampling: CliSamplingConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CliIdentity {
    engine_version: String,
    engine_abi: String,
    artifact_abi: String,
    qemu_build_id: String,
    plugin_abi: String,
}

fn validate_replayable_reproduction_artifact(
    cli: &Cli,
    bytes: &[u8],
) -> Result<CliReproductionArtifact, CliError> {
    let artifact = decode_reproduction_artifact(bytes)?;
    verify_replay_identity(&artifact.identity, &expected_replay_identity(cli)?)?;
    Ok(artifact)
}

fn verify_replay_identity(actual: &CliIdentity, expected: &CliIdentity) -> Result<(), CliError> {
    if actual != expected {
        return Err(CliError::Identity(format!(
            "reproduction build identity mismatch: expected engine `{}` ABI `{}` artifact ABI `{}` QEMU `{}` plugin `{}`, got engine `{}` ABI `{}` artifact ABI `{}` QEMU `{}` plugin `{}`",
            expected.engine_version,
            expected.engine_abi,
            expected.artifact_abi,
            expected.qemu_build_id,
            expected.plugin_abi,
            actual.engine_version,
            actual.engine_abi,
            actual.artifact_abi,
            actual.qemu_build_id,
            actual.plugin_abi
        )));
    }
    Ok(())
}

fn expected_replay_identity(cli: &Cli) -> Result<CliIdentity, CliError> {
    let qemu_build_id = match &cli.qemu {
        Some(path) => content_address_file(path)?,
        None => content_address_bytes(b"mock-backend-source-v1"),
    };
    let plugin_abi = match &cli.plugin {
        Some(path) => format!("content-addressed-plugin:{}", content_address_file(path)?),
        None => String::from("simdouble-mock-plugin-abi"),
    };
    Ok(CliIdentity {
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        engine_abi: String::from("crucible-harness-e2e-v1"),
        artifact_abi: REPRODUCTION_ARTIFACT_SCHEMA.to_string(),
        qemu_build_id,
        plugin_abi,
    })
}

#[derive(Clone, Debug)]
struct CliComponent {
    kind: String,
    name: String,
    digest: String,
    store_uri: String,
    media_type: String,
    size_bytes: u64,
}

#[derive(Debug)]
struct CliPayload {
    digest: String,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct CliDecision {
    sequence: u64,
    virtual_time_ticks: u64,
    node: String,
    kind: String,
    payload_digest: String,
}

#[derive(Debug)]
struct CliFingerprint {
    index: u64,
    digest: String,
}

#[derive(Debug)]
struct CliSamplingConfig {
    fine: String,
    coarse: String,
    regions: Vec<String>,
}

fn decode_reproduction_artifact(bytes: &[u8]) -> Result<CliReproductionArtifact, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| artifact_error(format!("artifact is not UTF-8: {error}")))?;
    let mut schema_version = None;
    let mut seed = None;
    let mut identity = None;
    let mut scenario = None;
    let mut components = Vec::new();
    let mut payloads = Vec::new();
    let mut schedule_digest = None;
    let mut schedule_len = None;
    let mut decisions = Vec::new();
    let mut fingerprints = Vec::new();
    let mut sampling = None;

    for (line_index, line_text) in text.lines().enumerate() {
        let fields = parse_artifact_fields(line_text)?;
        let Some(tag) = fields.first().map(String::as_str) else {
            continue;
        };
        match tag {
            "schema" => {
                require_field_count(line_index, tag, &fields, 2)?;
                set_once(&mut schema_version, line_index, tag, fields[1].clone())?;
            }
            "seed" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_u64(line_index, tag, &fields[1])?;
                set_once(&mut seed, line_index, tag, parsed)?;
            }
            "identity" => {
                require_field_count(line_index, tag, &fields, 6)?;
                validate_required_field("identity.engine_version", &fields[1])?;
                validate_required_field("identity.engine_abi", &fields[2])?;
                if fields[3] != REPRODUCTION_ARTIFACT_SCHEMA {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "artifact ABI does not match supported schema",
                    ));
                }
                validate_digest("identity.qemu_build_id", &fields[4])?;
                validate_required_field("identity.plugin_abi", &fields[5])?;
                set_once(
                    &mut identity,
                    line_index,
                    tag,
                    CliIdentity {
                        engine_version: fields[1].clone(),
                        engine_abi: fields[2].clone(),
                        artifact_abi: fields[3].clone(),
                        qemu_build_id: fields[4].clone(),
                        plugin_abi: fields[5].clone(),
                    },
                )?;
            }
            "scenario" => {
                let parsed = parse_component(line_index, tag, &fields)?;
                if parsed.kind != "scenario_def" {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "scenario component kind must be scenario_def",
                    ));
                }
                set_once(&mut scenario, line_index, tag, parsed)?;
            }
            "component" => {
                components.push(parse_component(line_index, tag, &fields)?);
            }
            "payload" => {
                require_field_count(line_index, tag, &fields, 3)?;
                let payload = CliPayload {
                    digest: fields[1].clone(),
                    bytes: parse_hex_bytes(line_index, tag, &fields[2])?,
                };
                validate_digest("payload.digest", &payload.digest)?;
                let actual = content_address_bytes(&payload.bytes);
                if payload.digest != actual {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "payload digest does not match bytes",
                    ));
                }
                payloads.push(payload);
            }
            "schedule" => {
                require_field_count(line_index, tag, &fields, 3)?;
                validate_digest("schedule.digest", &fields[1])?;
                let parsed_len = parse_usize(line_index, tag, &fields[2])?;
                set_once(&mut schedule_digest, line_index, tag, fields[1].clone())?;
                set_once(&mut schedule_len, line_index, tag, parsed_len)?;
            }
            "decision" => {
                require_field_count(line_index, tag, &fields, 6)?;
                let decision = CliDecision {
                    sequence: parse_u64(line_index, tag, &fields[1])?,
                    virtual_time_ticks: parse_u64(line_index, tag, &fields[2])?,
                    node: fields[3].clone(),
                    kind: fields[4].clone(),
                    payload_digest: fields[5].clone(),
                };
                validate_required_field("decision.node", &decision.node)?;
                validate_required_field("decision.kind", &decision.kind)?;
                validate_digest("decision.payload_digest", &decision.payload_digest)?;
                decisions.push(decision);
            }
            "fingerprint" => {
                require_field_count(line_index, tag, &fields, 3)?;
                let index = parse_u64(line_index, tag, &fields[1])?;
                validate_digest("fingerprint.digest", &fields[2])?;
                fingerprints.push(CliFingerprint {
                    index,
                    digest: fields[2].clone(),
                });
            }
            "sampling" => {
                if fields.len() < 4 {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "expected at least 4 fields",
                    ));
                }
                validate_required_field("sampling.fine", &fields[1])?;
                validate_required_field("sampling.coarse", &fields[2])?;
                let region_count = parse_usize(line_index, tag, &fields[3])?;
                if region_count == 0 {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "sampling must name at least one region",
                    ));
                }
                if fields.len() != region_count + 4 {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "region count does not match fields",
                    ));
                }
                for region in &fields[4..] {
                    validate_required_field("sampling.region", region)?;
                }
                set_once(
                    &mut sampling,
                    line_index,
                    tag,
                    CliSamplingConfig {
                        fine: fields[1].clone(),
                        coarse: fields[2].clone(),
                        regions: fields[4..].to_vec(),
                    },
                )?;
            }
            _ => return Err(artifact_line_error(line_index, tag, "unknown line tag")),
        }
    }

    let schema_version = schema_version.ok_or_else(|| missing_line("schema"))?;
    if schema_version != REPRODUCTION_ARTIFACT_SCHEMA {
        return Err(artifact_error(format!(
            "unsupported reproduction artifact schema `{schema_version}`"
        )));
    }
    let identity = identity.ok_or_else(|| missing_line("identity"))?;
    let scenario = scenario.ok_or_else(|| missing_line("scenario"))?;
    let schedule_digest = schedule_digest.ok_or_else(|| missing_line("schedule"))?;
    let schedule_len = schedule_len.ok_or_else(|| missing_line("schedule"))?;
    if schedule_len != decisions.len() {
        return Err(artifact_error(format!(
            "schedule declared {schedule_len} decisions but encoded {}",
            decisions.len()
        )));
    }
    validate_schedule(&decisions, &schedule_digest)?;
    if !components.iter().any(|component| {
        component.kind == "scenario_def"
            && component.digest == scenario.digest
            && component.store_uri == scenario.store_uri
    }) {
        return Err(artifact_error(format!(
            "scenario component `{}` is missing from artifact component references",
            scenario.digest
        )));
    }
    for payload in &payloads {
        if !components
            .iter()
            .any(|component| component.digest == payload.digest)
            && scenario.digest != payload.digest
        {
            return Err(artifact_error(format!(
                "component payload `{}` is missing from artifact component references",
                payload.digest
            )));
        }
    }
    let sampling = sampling.ok_or_else(|| missing_line("sampling"))?;

    let artifact = CliReproductionArtifact {
        seed: seed.ok_or_else(|| missing_line("seed"))?,
        identity,
        scenario,
        components,
        payloads,
        schedule_digest,
        decisions,
        fingerprints,
        sampling,
    };
    if canonical_artifact_text(&artifact) != text {
        return Err(artifact_error("non-canonical artifact encoding"));
    }

    Ok(artifact)
}

fn parse_component(
    line_index: usize,
    tag: &str,
    fields: &[String],
) -> Result<CliComponent, CliError> {
    require_field_count(line_index, tag, fields, 7)?;
    let component = CliComponent {
        kind: fields[1].clone(),
        name: fields[2].clone(),
        digest: fields[3].clone(),
        store_uri: fields[4].clone(),
        media_type: fields[5].clone(),
        size_bytes: parse_u64(line_index, tag, &fields[6])?,
    };
    validate_required_field("component.name", &component.name)?;
    validate_required_field("component.media_type", &component.media_type)?;
    validate_digest("component.digest", &component.digest)?;
    if component.store_uri != format!("cas:{}", component.digest) {
        return Err(artifact_line_error(
            line_index,
            tag,
            "component store URI does not match digest",
        ));
    }
    Ok(component)
}

fn validate_schedule(decisions: &[CliDecision], digest: &str) -> Result<(), CliError> {
    if decisions.is_empty() {
        return Err(artifact_error("reproduction schedule is empty"));
    }
    for (expected, decision) in decisions.iter().enumerate() {
        if decision.sequence != expected as u64 {
            return Err(artifact_error(format!(
                "schedule decision sequence out of order: expected {expected}, got {}",
                decision.sequence
            )));
        }
    }
    let expected = schedule_digest(decisions);
    if digest != expected {
        return Err(artifact_error(format!(
            "schedule digest mismatch: expected {expected}, got {digest}"
        )));
    }
    Ok(())
}

fn canonical_artifact_text(artifact: &CliReproductionArtifact) -> String {
    let mut text = String::new();
    artifact_line(&mut text, &["schema", REPRODUCTION_ARTIFACT_SCHEMA]);
    artifact_line(&mut text, &["seed", &artifact.seed.to_string()]);
    artifact_line(
        &mut text,
        &[
            "identity",
            &artifact.identity.engine_version,
            &artifact.identity.engine_abi,
            &artifact.identity.artifact_abi,
            &artifact.identity.qemu_build_id,
            &artifact.identity.plugin_abi,
        ],
    );
    artifact_component_line(&mut text, "scenario", &artifact.scenario);
    for component in &artifact.components {
        artifact_component_line(&mut text, "component", component);
    }
    for payload in &artifact.payloads {
        artifact_line(
            &mut text,
            &["payload", &payload.digest, &hex_bytes(&payload.bytes)],
        );
    }
    artifact_line(
        &mut text,
        &[
            "schedule",
            &artifact.schedule_digest,
            &artifact.decisions.len().to_string(),
        ],
    );
    for decision in &artifact.decisions {
        artifact_line(
            &mut text,
            &[
                "decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.node,
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    for fingerprint in &artifact.fingerprints {
        artifact_line(
            &mut text,
            &[
                "fingerprint",
                &fingerprint.index.to_string(),
                &fingerprint.digest,
            ],
        );
    }
    let mut sampling_fields = vec![
        String::from("sampling"),
        artifact.sampling.fine.clone(),
        artifact.sampling.coarse.clone(),
        artifact.sampling.regions.len().to_string(),
    ];
    sampling_fields.extend(artifact.sampling.regions.iter().cloned());
    artifact_line(
        &mut text,
        &sampling_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    text
}

fn artifact_component_line(text: &mut String, tag: &str, component: &CliComponent) {
    artifact_line(
        text,
        &[
            tag,
            &component.kind,
            &component.name,
            &component.digest,
            &component.store_uri,
            &component.media_type,
            &component.size_bytes.to_string(),
        ],
    );
}

fn mock_failure_reproduction_artifact_bytes(cli: &Cli) -> Result<Vec<u8>, CliError> {
    let seed = 0xe2e0_0010_u64;
    let scenario_material = b"scenario\tmock-failure\nnode\tnode-a\tserver\n";
    let scenario_digest = content_address_bytes(scenario_material);
    let identity = expected_replay_identity(cli)?;
    let payload_digest = content_address_bytes(b"mock-failure-decision");
    let fingerprint_digest = content_address_bytes(b"mock-failure-fingerprint");
    let decisions = vec![CliDecision {
        sequence: 0,
        virtual_time_ticks: 1,
        node: String::from("node-a"),
        kind: String::from("property_observation"),
        payload_digest,
    }];
    let schedule_digest = schedule_digest(&decisions);
    let scenario_size = scenario_material.len().to_string();
    let seed_text = seed.to_string();
    let schedule_len = decisions.len().to_string();
    let store_uri = format!("cas:{scenario_digest}");
    let mut text = String::new();

    artifact_line(&mut text, &["schema", REPRODUCTION_ARTIFACT_SCHEMA]);
    artifact_line(&mut text, &["seed", &seed_text]);
    artifact_line(
        &mut text,
        &[
            "identity",
            &identity.engine_version,
            &identity.engine_abi,
            &identity.artifact_abi,
            &identity.qemu_build_id,
            &identity.plugin_abi,
        ],
    );
    artifact_line(
        &mut text,
        &[
            "scenario",
            "scenario_def",
            "mock-failure.scn",
            &scenario_digest,
            &store_uri,
            "application/vnd.crucible.mock-scenario+text",
            &scenario_size,
        ],
    );
    artifact_line(
        &mut text,
        &[
            "component",
            "scenario_def",
            "mock-failure.scn",
            &scenario_digest,
            &store_uri,
            "application/vnd.crucible.mock-scenario+text",
            &scenario_size,
        ],
    );
    artifact_line(
        &mut text,
        &["payload", &scenario_digest, &hex_bytes(scenario_material)],
    );
    artifact_line(&mut text, &["schedule", &schedule_digest, &schedule_len]);
    for decision in &decisions {
        artifact_line(
            &mut text,
            &[
                "decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.node,
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    artifact_line(&mut text, &["fingerprint", "1", &fingerprint_digest]);
    artifact_line(
        &mut text,
        &[
            "sampling",
            "every-decision",
            "final",
            "1",
            "canonical-log-tail",
        ],
    );

    let bytes = text.into_bytes();
    validate_replayable_reproduction_artifact(cli, &bytes)?;
    Ok(bytes)
}

fn schedule_digest(decisions: &[CliDecision]) -> String {
    let mut material = String::new();
    for decision in decisions {
        artifact_line(
            &mut material,
            &[
                "decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.node,
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    content_address_bytes(material.as_bytes())
}

fn content_address_bytes(bytes: &[u8]) -> String {
    format!(
        "{}{}",
        CONTENT_ADDRESS_PREFIX,
        hex_bytes(&stable_digest(bytes))
    )
}

fn content_address_file(path: &Path) -> Result<String, CliError> {
    Ok(content_address_bytes(&fs::read(path)?))
}

fn stable_digest(material: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for lane in 0..4 {
        let mut state = 0xcbf2_9ce4_8422_2325u64 ^ lane;
        for byte in b"crucible.reproduction.hash.v1"
            .iter()
            .copied()
            .chain([0xff])
            .chain(material.iter().copied())
        {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
            state ^= state.rotate_left(17);
        }
        output[lane as usize * 8..lane as usize * 8 + 8].copy_from_slice(&state.to_be_bytes());
    }
    output
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn artifact_line(text: &mut String, fields: &[&str]) {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            text.push('\t');
        }
        text.push_str(&escape_artifact_field(field));
    }
    text.push('\n');
}

fn escape_artifact_field(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        match byte {
            b'%' => escaped.push_str("%25"),
            b'\t' => escaped.push_str("%09"),
            b'\n' => escaped.push_str("%0A"),
            b'\r' => escaped.push_str("%0D"),
            _ => escaped.push(char::from(byte)),
        }
    }
    escaped
}

fn parse_artifact_fields(line_text: &str) -> Result<Vec<String>, CliError> {
    line_text.split('\t').map(unescape_artifact_field).collect()
}

fn unescape_artifact_field(value: &str) -> Result<String, CliError> {
    let bytes = value.as_bytes();
    let mut output = String::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            output.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(artifact_error(format!("truncated escape in `{value}`")));
        }
        let escape = &value[index + 1..index + 3];
        match escape {
            "25" => output.push('%'),
            "09" => output.push('\t'),
            "0A" => output.push('\n'),
            "0D" => output.push('\r'),
            _ => {
                return Err(artifact_error(format!(
                    "unknown escape %{escape} in `{value}`"
                )));
            }
        }
        index += 3;
    }
    Ok(output)
}

fn require_field_count(
    line_index: usize,
    tag: &str,
    fields: &[String],
    expected: usize,
) -> Result<(), CliError> {
    if fields.len() == expected {
        return Ok(());
    }
    Err(artifact_line_error(
        line_index,
        tag,
        &format!("expected {expected} fields, got {}", fields.len()),
    ))
}

fn set_once<T>(
    slot: &mut Option<T>,
    line_index: usize,
    tag: &str,
    value: T,
) -> Result<(), CliError> {
    if slot.is_some() {
        return Err(artifact_line_error(
            line_index,
            tag,
            "duplicate singleton line",
        ));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_u64(line_index: usize, tag: &str, value: &str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|error| {
        artifact_line_error(line_index, tag, &format!("invalid u64 `{value}`: {error}"))
    })
}

fn parse_usize(line_index: usize, tag: &str, value: &str) -> Result<usize, CliError> {
    value.parse::<usize>().map_err(|error| {
        artifact_line_error(
            line_index,
            tag,
            &format!("invalid usize `{value}`: {error}"),
        )
    })
}

fn parse_hex_bytes(line_index: usize, tag: &str, value: &str) -> Result<Vec<u8>, CliError> {
    if value.len() % 2 != 0 {
        return Err(artifact_line_error(
            line_index,
            tag,
            "hex payload has odd length",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks(2) {
        let high = hex_nibble(chunk[0])
            .ok_or_else(|| artifact_line_error(line_index, tag, "hex payload is malformed"))?;
        let low = hex_nibble(chunk[1])
            .ok_or_else(|| artifact_line_error(line_index, tag, "hex payload is malformed"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_required_field(field: &'static str, value: &str) -> Result<(), CliError> {
    if value.is_empty() {
        return Err(artifact_error(format!("required field `{field}` is empty")));
    }
    Ok(())
}

fn validate_digest(field: &'static str, digest: &str) -> Result<(), CliError> {
    let Some(hex) = digest.strip_prefix(CONTENT_ADDRESS_PREFIX) else {
        return Err(artifact_error(format!(
            "field `{field}` is not a content address: `{digest}`"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(artifact_error(format!(
            "field `{field}` is not a content address: `{digest}`"
        )));
    }
    Ok(())
}

fn artifact_line_error(line_index: usize, tag: &str, reason: &str) -> CliError {
    artifact_error(format!("line {} `{tag}`: {reason}", line_index + 1))
}

fn missing_line(tag: &str) -> CliError {
    artifact_error(format!("missing `{tag}` line"))
}

fn artifact_error(reason: impl Into<String>) -> CliError {
    CliError::Artifact(reason.into())
}

#[derive(Debug)]
struct ReplayArtifactReport {
    path: PathBuf,
    digest: String,
    seed: u64,
    scenario_digest: String,
}

#[derive(Debug)]
struct FailureArtifactReport {
    path: PathBuf,
    digest: String,
    replay_command: String,
    debug_command: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TriageRunReport {
    plan: TriageInvocationPlan,
    ledger: crucible::FailureFindingsLedger,
    stored_ledger: crucible::FailureTriageStoredArtifact,
    result: crucible::FailureTriageResult,
    stored_result: crucible::FailureTriageStoredArtifact,
    report_path: PathBuf,
    compare: Option<TriageSummaryDiff>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TriageInvocationPlan {
    findings: TriageFindingsSource,
    policy: crucible::SignaturePolicy,
    minimize: TriageMinimizeArg,
    report_dir: PathBuf,
    format: crucible::FailureClusterReportFormat,
    recompute_signatures: bool,
    compare: Option<TriageCompareTarget>,
    store_root: PathBuf,
    pipeline: Vec<TriagePipelineStep>,
    failure_exit_code: i32,
    thin_driver: bool,
    owns_run_state: bool,
    offline: bool,
    scheduler_started: bool,
}

impl TriageInvocationPlan {
    fn policy_label(&self) -> &'static str {
        match self.policy.level() {
            crucible::SignaturePolicyLevel::Coarse => "coarse",
            crucible::SignaturePolicyLevel::Default => "default",
            crucible::SignaturePolicyLevel::Fine => "fine",
            crucible::SignaturePolicyLevel::Exact => "exact",
        }
    }

    fn minimize_label(&self) -> &'static str {
        match self.minimize {
            TriageMinimizeArg::None => "none",
            TriageMinimizeArg::Representative => "representative",
            TriageMinimizeArg::All => "all",
        }
    }

    fn format_label(&self) -> &'static str {
        match self.format {
            crucible::FailureClusterReportFormat::JsonLines => "jsonl",
            crucible::FailureClusterReportFormat::Json => "json",
            crucible::FailureClusterReportFormat::Table => "table",
            crucible::FailureClusterReportFormat::Markdown => "markdown",
        }
    }

    fn proves_t_tri_7(&self) -> bool {
        self.thin_driver
            && !self.owns_run_state
            && self.offline
            && !self.scheduler_started
            && self
                .pipeline
                .contains(&TriagePipelineStep::LoadFindingsLedger)
            && self.pipeline.contains(&TriagePipelineStep::Cluster)
            && self.pipeline.contains(&TriagePipelineStep::EmitReports)
            && self
                .pipeline
                .contains(&TriagePipelineStep::StoreTriageResult)
            && self.failure_exit_code == 1
            && match self.minimize {
                TriageMinimizeArg::None => self
                    .pipeline
                    .contains(&TriagePipelineStep::SkipMinimization),
                TriageMinimizeArg::Representative => self
                    .pipeline
                    .contains(&TriagePipelineStep::MinimizeRepresentative),
                TriageMinimizeArg::All => self.pipeline.contains(&TriagePipelineStep::MinimizeAll),
            }
            && (!self.recompute_signatures
                || self
                    .pipeline
                    .contains(&TriagePipelineStep::RecomputeSignatureSelfCheck))
            && (self.compare.is_none()
                || self
                    .pipeline
                    .contains(&TriagePipelineStep::CompareContentDiff))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TriageFindingsSource {
    Path(PathBuf),
    StoredLedger(crucible::ContentHash),
}

impl TriageFindingsSource {
    fn label(&self) -> &'static str {
        match self {
            Self::Path(_) => "path",
            Self::StoredLedger(_) => "dag-store",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TriageCompareTarget {
    Path(PathBuf),
    StoredResult(crucible::ContentHash),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TriagePipelineStep {
    LoadFindingsLedger,
    RecomputeSignatureSelfCheck,
    Cluster,
    SkipMinimization,
    MinimizeRepresentative,
    MinimizeAll,
    EmitReports,
    StoreTriageResult,
    CompareContentDiff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TriageResultSummary {
    result: crucible::ContentHash,
    report_hashes: BTreeMap<crucible::ContentHash, crucible::ContentHash>,
}

impl TriageResultSummary {
    fn from_result(result: &crucible::FailureTriageResult) -> Self {
        Self {
            result: result.content_hash(),
            report_hashes: result
                .report_set
                .reports
                .iter()
                .map(|report| (report.cluster_id, report.content_hash()))
                .collect(),
        }
    }

    fn from_artifact_bytes(bytes: &[u8]) -> Result<Self, CliError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|error| artifact_error(format!("triage result is not UTF-8: {error}")))?;
        if text.lines().next() != Some("crucible.failure-triage.result.v1") {
            return Err(artifact_error("unsupported triage result artifact schema"));
        }
        let mut by_index =
            BTreeMap::<usize, (Option<crucible::ContentHash>, Option<crucible::ContentHash>)>::new(
            );
        for line in text.lines() {
            let Some(rest) = line.strip_prefix("report.") else {
                continue;
            };
            let Some((index, field_value)) = rest.split_once('.') else {
                return Err(artifact_error("malformed triage result report line"));
            };
            let index = index
                .parse::<usize>()
                .map_err(|_| artifact_error("malformed triage result report index"))?;
            let Some((field, value)) = field_value.split_once('=') else {
                return Err(artifact_error("malformed triage result report field"));
            };
            let entry = by_index.entry(index).or_insert((None, None));
            match field {
                "cluster_id" => {
                    entry.0 = Some(parse_hex_content_hash("triage result cluster id", value)?);
                }
                "content_hash" => {
                    entry.1 = Some(parse_hex_content_hash("triage result report hash", value)?);
                }
                "minimal_representative" => {}
                _ => {}
            }
        }
        let mut report_hashes = BTreeMap::new();
        for (index, (cluster_id, report_hash)) in by_index {
            let cluster_id = cluster_id.ok_or_else(|| {
                artifact_error(format!(
                    "triage result report {index} is missing cluster_id"
                ))
            })?;
            let report_hash = report_hash.ok_or_else(|| {
                artifact_error(format!(
                    "triage result report {index} is missing content_hash"
                ))
            })?;
            report_hashes.insert(cluster_id, report_hash);
        }
        Ok(Self {
            result: crucible::ContentHash::from_bytes(bytes),
            report_hashes,
        })
    }

    fn diff_from(&self, baseline: &Self) -> TriageSummaryDiff {
        let all_clusters = self
            .report_hashes
            .keys()
            .chain(baseline.report_hashes.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = Vec::new();
        for cluster in all_clusters {
            match (
                baseline.report_hashes.get(&cluster),
                self.report_hashes.get(&cluster),
            ) {
                (None, Some(_)) => added.push(cluster),
                (Some(_), None) => removed.push(cluster),
                (Some(left), Some(right)) if left == right => unchanged.push(cluster),
                (Some(left), Some(right)) => changed.push(TriageSummaryChangedCluster {
                    cluster,
                    baseline_report: *left,
                    candidate_report: *right,
                }),
                (None, None) => {}
            }
        }
        TriageSummaryDiff {
            baseline: baseline.result,
            candidate: self.result,
            added,
            removed,
            changed,
            unchanged,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TriageSummaryChangedCluster {
    cluster: crucible::ContentHash,
    baseline_report: crucible::ContentHash,
    candidate_report: crucible::ContentHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TriageSummaryDiff {
    baseline: crucible::ContentHash,
    candidate: crucible::ContentHash,
    added: Vec<crucible::ContentHash>,
    removed: Vec<crucible::ContentHash>,
    changed: Vec<TriageSummaryChangedCluster>,
    unchanged: Vec<crucible::ContentHash>,
}

impl TriageSummaryDiff {
    fn status_label(&self) -> &'static str {
        if self.baseline == self.candidate
            && self.added.is_empty()
            && self.removed.is_empty()
            && self.changed.is_empty()
        {
            "unchanged"
        } else {
            "changed"
        }
    }

    fn content_diff(&self) -> String {
        let mut lines = vec![
            format!("baseline\t{}", format_content_hash_ref(self.baseline)),
            format!("candidate\t{}", format_content_hash_ref(self.candidate)),
        ];
        for cluster in &self.added {
            lines.push(format!("added\t{}", format_content_hash_ref(*cluster)));
        }
        for cluster in &self.removed {
            lines.push(format!("removed\t{}", format_content_hash_ref(*cluster)));
        }
        for changed in &self.changed {
            lines.push(format!(
                "changed\t{}\t{}\t{}",
                format_content_hash_ref(changed.cluster),
                format_content_hash_ref(changed.baseline_report),
                format_content_hash_ref(changed.candidate_report)
            ));
        }
        for cluster in &self.unchanged {
            lines.push(format!("unchanged\t{}", format_content_hash_ref(*cluster)));
        }
        lines.join("\n")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DebugInvocationPlan {
    target: DebugPlanTarget,
    coordinate: DebugPlanCoordinate,
    node: Option<String>,
    gdb_listen: String,
    read_only: bool,
    allow_mutate: bool,
    checkpoint_stride: Option<u64>,
    verb: DebugInteractiveVerbPlan,
    session_commands: Vec<SessionCommand>,
    engine_operations: Vec<DebugEngineOperation>,
    surface_contract: crucible::DebugCliSurfaceContract,
    owns_debug_state: bool,
    raw_gdb_single_step_allowed: bool,
    non_canonical_branch_label: Option<String>,
}

impl DebugInvocationPlan {
    fn mode_label(&self) -> &'static str {
        if self.allow_mutate {
            "allow-mutate"
        } else {
            "read-only"
        }
    }

    fn proves_read_only_default(&self) -> bool {
        !self.allow_mutate
            && self.read_only
            && self.non_canonical_branch_label.is_none()
            && !self
                .engine_operations
                .contains(&DebugEngineOperation::NonCanonicalBranchFork)
    }

    fn proves_thin_wrapper(&self) -> bool {
        !self.owns_debug_state
            && self.surface_contract.delegates_to_session_commands
            && self.surface_contract.delegates_to_gdbstub_proxy
            && self
                .engine_operations
                .contains(&DebugEngineOperation::ResolveTarget)
            && self
                .engine_operations
                .contains(&DebugEngineOperation::AttachGdbProxy)
            && self
                .engine_operations
                .contains(&DebugEngineOperation::OpenGdbstub)
            && self.engine_operations.contains(&DebugEngineOperation::Goto)
            && self
                .engine_operations
                .contains(&DebugEngineOperation::RestoreNearestCheckpointReplay)
            && self.session_commands.iter().all(|command| {
                matches!(
                    command,
                    SessionCommand::Query { .. }
                        | SessionCommand::Snapshot
                        | SessionCommand::Fork { .. }
                )
            })
    }

    fn proves_read_mutate_boundary(&self) -> bool {
        if self.allow_mutate {
            !self.read_only
                && self.non_canonical_branch_label.as_deref() == Some("NON-CANONICAL debug branch")
                && self
                    .session_commands
                    .contains(&SessionCommand::fork_current())
                && self
                    .engine_operations
                    .contains(&DebugEngineOperation::NonCanonicalBranchFork)
        } else {
            self.proves_read_only_default()
        }
    }

    fn proves_t_dbg_8(&self) -> bool {
        self.surface_contract.proves_t_dbg_8()
            && self.proves_thin_wrapper()
            && self.proves_read_mutate_boundary()
            && !self.raw_gdb_single_step_allowed
            && self
                .engine_operations
                .contains(&DebugEngineOperation::DisableRawGdbSingleStep)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DebugPlanTarget {
    Artifact(PathBuf),
    Savepoint(crucible::ContentHash),
    Session(String),
}

impl DebugPlanTarget {
    fn label(&self) -> &'static str {
        match self {
            Self::Artifact(_) => "artifact",
            Self::Savepoint(_) => "savepoint",
            Self::Session(_) => "session",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DebugPlanCoordinate {
    Current,
    At(crucible::DebugCoordinate),
    AtEvent(u64),
    AtFailure,
    AtCheckpoint(crucible::ContentHash),
}

impl DebugPlanCoordinate {
    fn label(&self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::At(_) => "at",
            Self::AtEvent(_) => "at-event",
            Self::AtFailure => "at-failure",
            Self::AtCheckpoint(_) => "at-checkpoint",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DebugInteractiveVerbPlan {
    AttachGdb,
    Goto(crucible::DebugCoordinate),
    ReverseStep {
        grain: crucible::DebugReverseStepGrain,
    },
    ReverseContinue {
        condition: String,
    },
}

impl DebugInteractiveVerbPlan {
    fn label(&self) -> &'static str {
        match self {
            Self::AttachGdb => "attach-gdb",
            Self::Goto(_) => "goto",
            Self::ReverseStep { .. } => "reverse-step",
            Self::ReverseContinue { .. } => "reverse-continue",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum DebugEngineOperation {
    ResolveTarget,
    Instantiate,
    AttachGdbProxy,
    OpenGdbstub,
    Goto,
    RestoreNearestCheckpointReplay,
    ReverseStep,
    ReverseContinue,
    ReadOnlyInspection,
    NonCanonicalBranchFork,
    CheckpointCadence,
    NoSymbolServer,
    MultiVcpuThreadEnumeration,
    DisableRawGdbSingleStep,
}

#[derive(Debug)]
struct SelftestReport {
    verified: Vec<crucible::ExampleScenarioVerifyReport>,
}

#[derive(Debug)]
enum CliError {
    Io(io::Error),
    Store(crucible::DagStoreError),
    Artifact(String),
    Usage(String),
    Backend(String),
    Identity(String),
    Triage(String),
    Selftest(crucible::ExampleCorpusError),
}

impl CliError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) => 5,
            Self::Store(_) => 5,
            Self::Artifact(_) => 5,
            Self::Usage(_) => 64,
            Self::Backend(_) => 4,
            Self::Identity(_) => 3,
            Self::Triage(_) => 1,
            Self::Selftest(_) => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Artifact(error) => write!(formatter, "{error}"),
            Self::Usage(error) => write!(formatter, "{error}"),
            Self::Backend(error) => write!(formatter, "{error}"),
            Self::Identity(error) => write!(formatter, "{error}"),
            Self::Triage(error) => write!(formatter, "{error}"),
            Self::Selftest(error) => write!(formatter, "selftest failed: {error}"),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Artifact(_) => None,
            Self::Usage(_) => None,
            Self::Backend(_) => None,
            Self::Identity(_) => None,
            Self::Triage(_) => None,
            Self::Selftest(error) => Some(error),
        }
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn usage_error(reason: impl Into<String>) -> CliError {
    CliError::Usage(reason.into())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use clap::CommandFactory;
    use crucible_harness::reproduction::{ReproductionArtifact, mock_e2e_reproduction_artifact};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn cli_skeleton_exposes_closed_subcommand_set() {
        let mut names = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_string())
            .collect::<Vec<_>>();
        names.sort();

        assert_eq!(
            names,
            [
                "completions",
                "debug",
                "fork",
                "fuzz",
                "replay",
                "resume",
                "run",
                "save",
                "search",
                "selftest",
                "serve",
                "triage",
                "verify",
            ]
        );
    }

    #[test]
    fn cli_skeleton_parses_global_flag_block() {
        let cli = Cli::parse_from([
            "crucible",
            "--seed",
            "0x10",
            "--backend",
            "double",
            "--daemon",
            "127.0.0.1:9000",
            "--qemu",
            "/nix/store/qemu/bin/qemu-system-x86_64",
            "--plugin",
            "/nix/store/plugin/lib/crucible-qemu-plugin.so",
            "--store",
            ".crucible-store",
            "--format",
            "json",
            "--trace",
            "trace.jsonl",
            "--artifact-dir",
            "artifacts",
            "-vv",
            "--quiet",
            "run",
        ]);

        assert_eq!(cli.seed.as_deref(), Some("0x10"));
        assert_eq!(cli.backend, Backend::Double);
        assert_eq!(cli.daemon.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(
            cli.qemu.as_ref().and_then(|path| path.to_str()),
            Some("/nix/store/qemu/bin/qemu-system-x86_64")
        );
        assert_eq!(
            cli.plugin.as_ref().and_then(|path| path.to_str()),
            Some("/nix/store/plugin/lib/crucible-qemu-plugin.so")
        );
        assert_eq!(
            cli.store.as_ref().and_then(|path| path.to_str()),
            Some(".crucible-store")
        );
        assert_eq!(cli.format, OutputFormat::Json);
        assert_eq!(
            cli.trace.as_ref().and_then(|path| path.to_str()),
            Some("trace.jsonl")
        );
        assert_eq!(cli.artifact_dir.to_str(), Some("artifacts"));
        assert_eq!(cli.verbose, 2);
        assert!(cli.quiet);
        assert!(matches!(
            cli.command,
            Commands::Run(RunArgs {
                emit_mock_failure_artifact: false
            })
        ));
    }

    #[test]
    fn cli_skeleton_rejects_unknown_subcommands() {
        let error = match Cli::try_parse_from(["crucible", "invented"]) {
            Ok(_) => panic!("invented subcommand must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn cli_triage_help_surface_lists_required_flags_and_exit_code_contract() {
        let mut command = Cli::command();
        let top_help = command.render_long_help().to_string();
        assert!(top_help.contains("triage"));
        assert!(top_help.contains("Cluster, dedup, and minimize discovered failures"));
        assert!(top_help.contains("--format <jsonl|json|table|markdown>"));

        let triage_help = command
            .find_subcommand_mut("triage")
            .expect("triage subcommand must be registered")
            .render_long_help()
            .to_string();
        for needle in [
            "<FINDINGS>",
            "--policy <coarse|default|fine|exact>",
            "--minimize <none|representative|all>",
            "--report <dir>",
            "--recompute-signatures",
            "--compare <other-triage-result>",
            "--format <jsonl|json|table|markdown>",
            "Select output format",
        ] {
            assert!(
                triage_help.contains(needle),
                "triage help is missing `{needle}`:\n{triage_help}"
            );
        }

        assert_eq!(
            CliError::Triage("signature self-check mismatch".to_string()).exit_code(),
            1
        );
        assert_eq!(
            CliError::Backend("triage discovery/config failure".to_string()).exit_code(),
            4
        );
        assert_eq!(
            CliError::Artifact("malformed findings ledger".to_string()).exit_code(),
            5
        );
        assert_eq!(
            CliError::Usage("triage usage error".to_string()).exit_code(),
            64
        );

        let missing_findings = Cli::try_parse_from(["crucible", "triage"])
            .expect_err("missing triage findings must be a parse error");
        assert_eq!(cli_parse_error_exit_code(&missing_findings), 64);

        let invalid_policy =
            Cli::try_parse_from(["crucible", "triage", "findings", "--policy", "wide"])
                .expect_err("invalid triage policy must be a parse error");
        assert_eq!(cli_parse_error_exit_code(&invalid_policy), 64);

        let help = Cli::try_parse_from(["crucible", "triage", "--help"])
            .expect_err("help must render through Clap's display path");
        assert_eq!(cli_parse_error_exit_code(&help), 0);
    }

    #[test]
    fn cli_triage_surface_parses_full_t_tri_7_flags_and_pipeline() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let findings = temp.path().join("findings");
        let store = temp.path().join("store");
        let reports = temp.path().join("triage-reports");
        fs::create_dir_all(&findings)?;
        let baseline_cli = Cli::parse_from([
            "crucible",
            "--store",
            store.to_str().unwrap_or("."),
            "--artifact-dir",
            temp.path().join("artifacts").to_str().unwrap_or("."),
            "triage",
            findings.to_str().unwrap_or("."),
            "--report",
            reports.to_str().unwrap_or("."),
            "--format",
            "markdown",
            "--recompute-signatures",
        ]);
        let Commands::Triage(baseline_args) = &baseline_cli.command else {
            panic!("expected triage command");
        };
        let baseline = run_triage_invocation(&baseline_cli, baseline_args)?;
        assert_eq!(baseline.ledger.artifact_count(), 0);
        assert!(baseline.report_path.exists());
        assert_eq!(baseline.stored_result.key, baseline.result.content_hash());
        let prior = format_content_hash_ref(baseline.stored_result.key);

        let cli = Cli::parse_from([
            "crucible",
            "--store",
            store.to_str().unwrap_or("."),
            "--artifact-dir",
            temp.path().join("artifacts").to_str().unwrap_or("."),
            "triage",
            findings.to_str().unwrap_or("."),
            "--policy",
            "fine",
            "--minimize",
            "representative",
            "--report",
            reports.to_str().unwrap_or("."),
            "--format",
            "markdown",
            "--recompute-signatures",
            "--compare",
            &prior,
        ]);
        let Commands::Triage(args) = &cli.command else {
            panic!("expected triage command");
        };

        assert_eq!(args.findings, findings.to_string_lossy());
        assert_eq!(args.policy, TriagePolicyArg::Fine);
        assert_eq!(args.minimize, TriageMinimizeArg::Representative);
        assert_eq!(args.report.as_deref(), Some(reports.as_path()));
        assert_eq!(cli.format, OutputFormat::Markdown);
        assert!(args.recompute_signatures);
        assert_eq!(args.compare.as_deref(), Some(prior.as_str()));

        let plan = plan_triage_invocation(&cli, args)?;

        assert!(matches!(plan.findings, TriageFindingsSource::Path(_)));
        assert_eq!(plan.policy.level(), crucible::SignaturePolicyLevel::Fine);
        assert_eq!(plan.minimize, TriageMinimizeArg::Representative);
        assert_eq!(plan.report_dir, reports);
        assert_eq!(plan.format, crucible::FailureClusterReportFormat::Markdown);
        assert!(matches!(
            plan.compare,
            Some(TriageCompareTarget::StoredResult(_))
        ));
        assert_eq!(plan.failure_exit_code, 1);
        assert_eq!(plan.store_root, store);
        assert_eq!(
            plan.pipeline,
            vec![
                TriagePipelineStep::LoadFindingsLedger,
                TriagePipelineStep::RecomputeSignatureSelfCheck,
                TriagePipelineStep::Cluster,
                TriagePipelineStep::MinimizeRepresentative,
                TriagePipelineStep::EmitReports,
                TriagePipelineStep::StoreTriageResult,
                TriagePipelineStep::CompareContentDiff,
            ]
        );
        assert!(plan.proves_t_tri_7());
        let report = run_triage_invocation(&cli, args)?;
        assert!(report.stored_ledger.cache_hit);
        assert!(report.compare.as_ref().is_some_and(|diff| {
            diff.status_label() == "changed" && diff.content_diff().contains("baseline\t")
        }));
        dispatch(&cli)?;

        Ok(())
    }

    #[test]
    fn cli_triage_is_offline_and_uses_uniform_failure_exit_code() {
        let cli = Cli::parse_from([
            "crucible",
            "--daemon",
            "127.0.0.1:9000",
            "triage",
            "findings-ledger",
        ]);
        let Commands::Triage(args) = &cli.command else {
            panic!("expected triage command");
        };
        let error = match plan_triage_invocation(&cli, args) {
            Ok(_) => panic!("triage must not use a live daemon"),
            Err(error) => error,
        };

        assert!(matches!(error, CliError::Backend(_)));
        assert_eq!(error.exit_code(), 4);
        assert!(error.to_string().contains("offline"));

        let self_check_failure = CliError::Triage(
            "--recompute-signatures found a discovery-time signature mismatch".to_string(),
        );
        assert_eq!(self_check_failure.exit_code(), 1);
    }

    #[test]
    fn cli_selftest_runs_builtin_example_corpus() -> Result<(), Box<dyn Error>> {
        let cli = Cli::parse_from(["crucible", "--quiet", "selftest"]);
        let report = run_selftest(&cli)?;

        let scenario_names = report
            .verified
            .iter()
            .map(|verified| verified.scenario_name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(report.verified.len(), 3);
        assert!(scenario_names.contains(&"happy-path.scn"));
        assert!(scenario_names.contains(&"partition-recovery.scn"));
        assert!(scenario_names.contains(&"crash-restart.scn"));
        assert!(report.verified.iter().all(|verified| verified.runs == 5));
        dispatch(&cli)?;

        Ok(())
    }

    #[test]
    fn cli_replay_validates_reproduction_artifact() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("case.crucible");
        let artifact = mock_e2e_reproduction_artifact()?;
        fs::write(&path, artifact.encode()?)?;

        let cli = Cli::parse_from(["crucible", "run"]);
        let report = replay_reproduction_artifact(
            &cli,
            &ReplayArgs {
                artifact: path.clone(),
            },
        )?;

        assert_eq!(report.path, path);
        assert_eq!(report.seed, artifact.seed);
        assert_eq!(report.scenario_digest, artifact.scenario.digest);
        assert_eq!(report.digest, artifact.digest()?);

        Ok(())
    }

    #[test]
    fn cli_replay_rejects_build_identity_mismatch_with_identity_exit() -> Result<(), Box<dyn Error>>
    {
        let temp = TempDir::new()?;
        let path = temp.path().join("identity-drift.crucible");
        let mut artifact = mock_e2e_reproduction_artifact()?;
        artifact.build_identity.qemu_build_id = content_address_bytes(b"different-qemu-build");
        fs::write(&path, artifact.encode()?)?;

        let cli = Cli::parse_from(["crucible", "run"]);
        let error = match replay_reproduction_artifact(&cli, &ReplayArgs { artifact: path }) {
            Ok(_) => panic!("replay must reject artifacts from a different QEMU identity"),
            Err(error) => error,
        };

        assert!(matches!(error, CliError::Identity(_)));
        assert_eq!(error.exit_code(), 3);
        assert!(error.to_string().contains("QEMU"));

        Ok(())
    }

    #[test]
    fn cli_replay_rejects_selected_qemu_file_identity_mismatch_with_identity_exit()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let artifact_path = temp.path().join("case.crucible");
        let qemu_path = temp.path().join("qemu-system-x86_64");
        fs::write(&qemu_path, b"different-local-qemu-binary")?;
        let artifact = mock_e2e_reproduction_artifact()?;
        fs::write(&artifact_path, artifact.encode()?)?;
        let cli = Cli::parse_from([
            "crucible",
            "--qemu",
            qemu_path.to_str().unwrap_or("."),
            "run",
        ]);

        let error = match replay_reproduction_artifact(
            &cli,
            &ReplayArgs {
                artifact: artifact_path,
            },
        ) {
            Ok(_) => panic!("replay must reject the selected QEMU identity mismatch"),
            Err(error) => error,
        };

        assert!(matches!(error, CliError::Identity(_)));
        assert_eq!(error.exit_code(), 3);
        assert!(error.to_string().contains("QEMU"));

        Ok(())
    }

    #[test]
    fn cli_failure_artifact_writer_emits_replay_and_debug_commands() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let artifact_dir = temp.path().join("artifact dir with spaces");
        let cli = Cli::parse_from([
            "crucible",
            "--artifact-dir",
            artifact_dir.to_str().unwrap_or("."),
            "run",
        ]);
        let artifact = mock_e2e_reproduction_artifact()?;
        let artifact_bytes = artifact.encode()?;

        let report =
            write_failure_reproduction_artifact(&cli, &artifact_bytes, "Property Violation")?;

        assert!(report.path.starts_with(temp.path()));
        assert!(report.path.exists());
        assert!(report.replay_command.starts_with("crucible replay "));
        assert!(report.debug_command.ends_with(" --at-failure"));
        assert!(report.debug_command.contains("artifact dir with spaces"));
        assert!(report.debug_command.contains('\''));
        assert!(report.path.to_string_lossy().contains("property-violation"));
        let debug_cli = Cli::parse_from([
            "crucible",
            "debug",
            report.path.to_str().unwrap_or("."),
            "--at-failure",
            "--gdb-listen",
            "127.0.0.1:9000",
        ]);
        assert!(matches!(
            debug_cli.command,
            Commands::Debug(DebugArgs {
                target: Some(_),
                at_failure: true,
                gdb_listen: Some(_),
                ..
            })
        ));
        assert_eq!(
            ReproductionArtifact::decode(&fs::read(&report.path)?)?,
            artifact
        );
        replay_reproduction_artifact(
            &cli,
            &ReplayArgs {
                artifact: report.path.clone(),
            },
        )?;
        assert_eq!(report.digest, artifact.digest()?);

        Ok(())
    }

    #[test]
    fn cli_debug_surface_parses_full_t_dbg_8_flags_and_verbs() -> Result<(), Box<dyn Error>> {
        let cli = Cli::parse_from([
            "crucible",
            "debug",
            "case.crucible",
            "--at",
            "icount:guest-a:102",
            "--node",
            "guest-a",
            "--gdb-listen",
            "127.0.0.1:9000",
            "--checkpoint-stride",
            "4",
            "reverse-step",
            "event",
        ]);
        let Commands::Debug(args) = &cli.command else {
            panic!("expected debug command");
        };

        assert_eq!(args.target.as_deref(), Some("case.crucible"));
        assert_eq!(args.at.as_deref(), Some("icount:guest-a:102"));
        assert_eq!(args.node.as_deref(), Some("guest-a"));
        assert_eq!(args.gdb_listen.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(args.checkpoint_stride, Some(4));
        assert!(matches!(
            &args.verb,
            Some(DebugVerbArgs::ReverseStep {
                grain: DebugStepGrainArg::Event
            })
        ));

        let plan = plan_debug_invocation(&cli, args)?;

        assert!(matches!(&plan.target, DebugPlanTarget::Artifact(_)));
        assert!(matches!(
            &plan.coordinate,
            DebugPlanCoordinate::At(crucible::DebugCoordinate::NodeIcount {
                node,
                icount
            }) if node.name == "guest-a" && icount.retired == 102
        ));
        assert_eq!(plan.node.as_deref(), Some("guest-a"));
        assert!(plan.read_only);
        assert!(!plan.allow_mutate);
        assert_eq!(plan.checkpoint_stride, Some(4));
        assert!(
            plan.session_commands
                .iter()
                .all(SessionCommand::is_read_only),
            "reverse-step grains are realized by the debug reverse-step/goto path, not unsupported session step modes"
        );
        assert!(
            plan.engine_operations
                .contains(&DebugEngineOperation::ReverseStep)
        );
        assert!(
            plan.engine_operations
                .contains(&DebugEngineOperation::RestoreNearestCheckpointReplay)
        );
        assert!(
            plan.engine_operations
                .contains(&DebugEngineOperation::CheckpointCadence)
        );
        assert!(plan.proves_t_dbg_8());

        Ok(())
    }

    #[test]
    fn cli_debug_surface_supports_session_checkpoint_and_allow_mutate() -> Result<(), Box<dyn Error>>
    {
        let checkpoint = "blake3:0000000000000000000000000000000000000000000000000000000000000000";
        let cli = Cli::parse_from([
            "crucible",
            "debug",
            "--session",
            "127.0.0.1:7000",
            "--at-checkpoint",
            checkpoint,
            "--allow-mutate",
            "goto",
            "vtime:7",
        ]);
        let Commands::Debug(args) = &cli.command else {
            panic!("expected debug command");
        };

        let plan = plan_debug_invocation(&cli, args)?;

        assert!(matches!(&plan.target, DebugPlanTarget::Session(_)));
        assert!(matches!(
            &plan.coordinate,
            DebugPlanCoordinate::AtCheckpoint(_)
        ));
        assert!(matches!(
            &plan.verb,
            DebugInteractiveVerbPlan::Goto(crucible::DebugCoordinate::VirtualTime(
                crucible::VirtualTime { ticks: 7 }
            ))
        ));
        assert!(plan.allow_mutate);
        assert!(!plan.read_only);
        assert_eq!(
            plan.non_canonical_branch_label.as_deref(),
            Some("NON-CANONICAL debug branch")
        );
        assert!(
            plan.session_commands
                .contains(&SessionCommand::fork_current())
        );
        assert!(
            plan.engine_operations
                .contains(&DebugEngineOperation::NonCanonicalBranchFork)
        );
        assert!(plan.proves_t_dbg_8());

        Ok(())
    }

    #[test]
    fn cli_debug_surface_rejects_conflicts_and_backend_without_gdbstub() {
        assert!(
            Cli::try_parse_from([
                "crucible",
                "debug",
                "case.crucible",
                "--read-only",
                "--allow-mutate",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "crucible",
                "debug",
                "case.crucible",
                "--at-event",
                "1",
                "--at-failure",
            ])
            .is_err()
        );

        let cli = Cli::parse_from(["crucible", "--backend", "double", "debug", "case.crucible"]);
        let Commands::Debug(args) = &cli.command else {
            panic!("expected debug command");
        };
        let error = match plan_debug_invocation(&cli, args) {
            Ok(_) => panic!("double backend must not advertise a gdbstub debug surface"),
            Err(error) => error,
        };

        assert!(matches!(error, CliError::Backend(_)));
        assert_eq!(error.exit_code(), 4);
        assert!(error.to_string().contains("open_gdbstub"));

        let cli = Cli::parse_from([
            "crucible",
            "debug",
            "case.crucible",
            "--checkpoint-stride",
            "0",
        ]);
        let Commands::Debug(args) = &cli.command else {
            panic!("expected debug command");
        };
        let error = match plan_debug_invocation(&cli, args) {
            Ok(_) => panic!("zero checkpoint stride must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);
        assert!(error.to_string().contains("non-zero"));

        let cli = Cli::parse_from(["crucible", "debug", "case.crucible", "--node", ""]);
        let Commands::Debug(args) = &cli.command else {
            panic!("expected debug command");
        };
        let error = match plan_debug_invocation(&cli, args) {
            Ok(_) => panic!("empty debug node must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);
        assert!(error.to_string().contains("--node"));
    }

    #[test]
    fn cli_debug_surface_defaults_coordinate_by_target_kind() -> Result<(), Box<dyn Error>> {
        let artifact_cli = Cli::parse_from(["crucible", "debug", "case.crucible"]);
        let Commands::Debug(args) = &artifact_cli.command else {
            panic!("expected debug command");
        };
        let artifact_plan = plan_debug_invocation(&artifact_cli, args)?;
        assert!(matches!(
            artifact_plan.coordinate,
            DebugPlanCoordinate::AtFailure
        ));

        let savepoint = "blake3:1111111111111111111111111111111111111111111111111111111111111111";
        let savepoint_cli = Cli::parse_from(["crucible", "debug", savepoint]);
        let Commands::Debug(args) = &savepoint_cli.command else {
            panic!("expected debug command");
        };
        let savepoint_plan = plan_debug_invocation(&savepoint_cli, args)?;
        assert!(matches!(
            savepoint_plan.coordinate,
            DebugPlanCoordinate::AtCheckpoint(_)
        ));

        let session_cli = Cli::parse_from(["crucible", "debug", "--session", "127.0.0.1:7000"]);
        let Commands::Debug(args) = &session_cli.command else {
            panic!("expected debug command");
        };
        let session_plan = plan_debug_invocation(&session_cli, args)?;
        assert!(matches!(
            session_plan.coordinate,
            DebugPlanCoordinate::Current
        ));

        Ok(())
    }

    #[test]
    fn cli_replay_rejects_duplicate_singleton_lines() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("duplicate.crucible");
        let artifact = mock_e2e_reproduction_artifact()?;
        let mut encoded = String::from_utf8(artifact.encode()?)?;
        encoded.push_str("seed\t9\n");
        fs::write(&path, encoded)?;

        let cli = Cli::parse_from(["crucible", "run"]);
        let error = match replay_reproduction_artifact(&cli, &ReplayArgs { artifact: path }) {
            Ok(_) => panic!("duplicate singleton line must fail CLI replay validation"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("duplicate singleton line"));

        Ok(())
    }

    #[test]
    fn cli_mock_failure_artifact_is_harness_decodable() -> Result<(), Box<dyn Error>> {
        let cli = Cli::parse_from(["crucible", "run"]);
        let bytes = mock_failure_reproduction_artifact_bytes(&cli)?;
        let artifact = ReproductionArtifact::decode(&bytes)?;

        assert_eq!(artifact.seed, 0xe2e0_0010);
        assert_eq!(artifact.schema_version, REPRODUCTION_ARTIFACT_SCHEMA);

        Ok(())
    }
}
