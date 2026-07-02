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
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{ArgAction, ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use crucible::DagStore;
use crucible_api::{
    AttachRequest, CommandResultStatus, ControlClient, CreateSessionRequest,
    InProcessLifecycleClient, LifecycleControlPlane, QuiescentLifecycleLoop, RpcControlClient,
    RpcEndpoint, serve_lifecycle_http2,
};
use crucible_session::{
    CommandReply, LiveStateKind, OutcomeKind, QueryKind, QueryResult, SessionCommand,
    SessionCommandKind,
};

const REPRODUCTION_ARTIFACT_SCHEMA: &str = "crucible.reproduction-artifact.v1";
const REPRODUCTION_ARTIFACT_MEDIA_TYPE: &str = "application/vnd.crucible.reproduction+text";
const CONTENT_ADDRESS_PREFIX: &str = "crucible-hash:";
const CRUCIBLE_SEED_ENV: &str = "CRUCIBLE_SEED";
const CRUCIBLE_QEMU_ENV: &str = "CRUCIBLE_QEMU";
const CRUCIBLE_PLUGIN_ENV: &str = "CRUCIBLE_PLUGIN";
const CRUCIBLE_AOS_QEMU_ENV: &str = "CRUCIBLE_AOS_QEMU";
const CRUCIBLE_AOS_PLUGIN_ENV: &str = "CRUCIBLE_AOS_PLUGIN";
const CRUCIBLE_QEMU_PLUGIN_ABI_PREFIX: &str = "crucible-shmem-abi-v";
const OS_ENTROPY_DEVICE: &str = "/dev/urandom";
const DEFAULT_SELFTEST_RUNS: usize = 5;
const BUILT_IN_CORPUS_SELFTEST_GATES: &[&str] = &["gate:replay-oracle"];

#[derive(Parser, Debug, PartialEq, Eq)]
#[command(
    name = "crucible",
    version,
    about = "Run and inspect Crucible simulations.",
    disable_help_subcommand = true
)]
struct Cli {
    /// Set root entropy.
    #[arg(long, value_name = "u64|hex", global = true)]
    seed: Option<String>,
    /// Select local backend.
    #[arg(
        long,
        value_enum,
        value_name = "auto|qemu|double",
        default_value_t = Backend::Auto,
        global = true
    )]
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
    /// Scenario file or content hash.
    #[arg(value_name = "SCENARIO")]
    scenario: Option<String>,
    /// Stop at this terminal condition.
    #[arg(
        long,
        value_enum,
        value_name = "quiescence|virtual-time|property|stopped",
        default_value_t = RunUntilArg::Quiescence
    )]
    until: RunUntilArg,
    /// Stop past this virtual time.
    #[arg(long, value_name = "dur")]
    max_virtual_time: Option<String>,
    /// Stop past this many scheduler quanta.
    #[arg(long, value_name = "n")]
    max_quanta: Option<u64>,
    /// Pause at genesis for control commands.
    #[arg(long, action = ArgAction::SetTrue)]
    interactive: bool,
    /// Savepoint policy at outcome.
    #[arg(
        long,
        value_enum,
        value_name = "fail|always|never",
        default_value_t = RunSaveOnArg::Never
    )]
    save_on: RunSaveOnArg,
    /// Stream live status.
    #[arg(long, action = ArgAction::SetTrue)]
    watch: bool,
    /// Emit a mock failure artifact for gate testing.
    #[arg(long, hide = true, action = ArgAction::SetTrue)]
    emit_mock_failure_artifact: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum RunUntilArg {
    /// Stop at scheduler quiescence.
    #[default]
    Quiescence,
    /// Stop at a virtual-time budget.
    VirtualTime,
    /// Stop at a property verdict.
    Property,
    /// Stop only on an explicit stopped state.
    Stopped,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum RunSaveOnArg {
    /// Save only on failure.
    Fail,
    /// Always save at outcome.
    Always,
    /// Do not save at outcome.
    #[default]
    Never,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct VerifyArgs {
    /// Scenario file or content hash.
    #[arg(value_name = "SCENARIO")]
    scenario: Option<String>,
    /// Number of independent reductions to compare.
    #[arg(long, value_name = "n", default_value_t = 2)]
    runs: usize,
    /// Run under hostile host-condition profiles.
    #[arg(long, action = ArgAction::SetTrue)]
    adversarial: bool,
    /// Localize the first divergence.
    #[arg(long, action = ArgAction::SetTrue)]
    bisect: bool,
    /// Compare two existing reproduction artifacts.
    #[arg(long, value_names = ["A", "B"], num_args = 2)]
    compare: Vec<PathBuf>,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct SelftestArgs {
    /// Run this double-backed gate subset.
    #[arg(long, value_name = "list")]
    gates: Option<String>,
}

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

#[derive(Args, Debug, PartialEq, Eq)]
struct ServeArgs {
    /// Bind daemon listener.
    #[arg(long, value_name = "addr", default_value = "127.0.0.1:9000")]
    listen: String,
}

#[derive(Args, Debug, PartialEq, Eq)]
struct CompletionsArgs {
    /// Select completion shell.
    #[arg(value_enum)]
    shell: Shell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum CliSubcommand {
    Run,
    Verify,
    Selftest,
    Save,
    Resume,
    Fork,
    Replay,
    Search,
    Fuzz,
    Triage,
    Debug,
    Serve,
    Completions,
}

impl CliSubcommand {
    fn from_command(command: &Commands) -> Self {
        match command {
            Commands::Run(_) => Self::Run,
            Commands::Verify(_) => Self::Verify,
            Commands::Selftest(_) => Self::Selftest,
            Commands::Save(_) => Self::Save,
            Commands::Resume(_) => Self::Resume,
            Commands::Fork(_) => Self::Fork,
            Commands::Replay(_) => Self::Replay,
            Commands::Search(_) => Self::Search,
            Commands::Fuzz(_) => Self::Fuzz,
            Commands::Triage(_) => Self::Triage,
            Commands::Debug(_) => Self::Debug,
            Commands::Serve(_) => Self::Serve,
            Commands::Completions(_) => Self::Completions,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum CliApiCall {
    Hello,
    ListScenarios,
    CreateSession,
    ListSessions,
    DestroySession,
    ControlAttach,
    ControlSend,
    WatchAttach,
    SendCommand,
    GetReproduction,
}

impl CliApiCall {
    const ALL: &'static [Self] = &[
        Self::Hello,
        Self::ListScenarios,
        Self::CreateSession,
        Self::ListSessions,
        Self::DestroySession,
        Self::ControlAttach,
        Self::ControlSend,
        Self::WatchAttach,
        Self::SendCommand,
        Self::GetReproduction,
    ];

    const fn control_client_method(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::ListScenarios => "list_scenarios",
            Self::CreateSession => "create_session",
            Self::ListSessions => "list_sessions",
            Self::DestroySession => "destroy_session",
            Self::ControlAttach => "control_attach",
            Self::ControlSend => "control_send",
            Self::WatchAttach => "watch_attach",
            Self::SendCommand => "send_command",
            Self::GetReproduction => "get_reproduction",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum CliDelegatedDriver {
    SessionControlPlane,
    ControlApi,
    HarnessGateCatalog,
    ReplayOracle,
    ExplorationEngine,
    TriageEngine,
    TimeTravelDebugger,
    DaemonHost,
    ShellCompletionGenerator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum CliStateReferenceKind {
    LocalSessionHandle,
    DaemonConnection,
    ContentAddressedStore,
    ReproductionArtifact,
    SavepointHandle,
    FindingsLedger,
    DebugCoordinate,
}

impl CliStateReferenceKind {
    const fn is_non_canonical_reference(self) -> bool {
        matches!(
            self,
            Self::LocalSessionHandle
                | Self::DaemonConnection
                | Self::ContentAddressedStore
                | Self::ReproductionArtifact
                | Self::SavepointHandle
                | Self::FindingsLedger
                | Self::DebugCoordinate
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CliThinWrapperPlan {
    subcommand: CliSubcommand,
    session_commands: Vec<SessionCommandKind>,
    api_calls: Vec<CliApiCall>,
    delegated_drivers: Vec<CliDelegatedDriver>,
    state_references: Vec<CliStateReferenceKind>,
    thin_wrapper: bool,
    owns_canonical_run_state: bool,
    implements_scheduler: bool,
    implements_checkpoint_materialization: bool,
    implements_fork_logic: bool,
    extra_control_capabilities: Vec<&'static str>,
}

impl CliThinWrapperPlan {
    fn proves_t_cli_2(&self) -> bool {
        self.thin_wrapper
            && !self.owns_canonical_run_state
            && !self.implements_scheduler
            && !self.implements_checkpoint_materialization
            && !self.implements_fork_logic
            && self.extra_control_capabilities.is_empty()
            && !self.delegated_drivers.is_empty()
            && self
                .state_references
                .iter()
                .copied()
                .all(CliStateReferenceKind::is_non_canonical_reference)
            && self
                .session_commands
                .iter()
                .all(|command| SessionCommandKind::ALL.contains(command))
            && self.api_calls.iter().all(|call| {
                CliApiCall::ALL.contains(call) && !call.control_client_method().is_empty()
            })
            && self.has_valid_decomposition()
    }

    fn has_valid_decomposition(&self) -> bool {
        !self.session_commands.is_empty()
            || !self.api_calls.is_empty()
            || matches!(
                self.subcommand,
                CliSubcommand::Triage | CliSubcommand::Completions
            )
    }
}

fn plan_cli_invocation(cli: &Cli) -> CliThinWrapperPlan {
    let subcommand = CliSubcommand::from_command(&cli.command);
    let mut plan = match &cli.command {
        Commands::Run(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: vec![
                SessionCommandKind::Start,
                SessionCommandKind::Continue,
                SessionCommandKind::Query,
                SessionCommandKind::Stop,
            ],
            api_calls: vec![
                CliApiCall::Hello,
                CliApiCall::CreateSession,
                CliApiCall::WatchAttach,
                CliApiCall::SendCommand,
                CliApiCall::GetReproduction,
            ],
            delegated_drivers: vec![CliDelegatedDriver::SessionControlPlane],
            state_references: vec![CliStateReferenceKind::LocalSessionHandle],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Verify(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: vec![
                SessionCommandKind::Start,
                SessionCommandKind::Continue,
                SessionCommandKind::Snapshot,
                SessionCommandKind::Query,
            ],
            api_calls: vec![CliApiCall::Hello, CliApiCall::CreateSession],
            delegated_drivers: vec![
                CliDelegatedDriver::SessionControlPlane,
                CliDelegatedDriver::ReplayOracle,
            ],
            state_references: vec![
                CliStateReferenceKind::ContentAddressedStore,
                CliStateReferenceKind::ReproductionArtifact,
            ],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Selftest(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: vec![
                SessionCommandKind::Start,
                SessionCommandKind::Continue,
                SessionCommandKind::Query,
            ],
            api_calls: Vec::new(),
            delegated_drivers: vec![CliDelegatedDriver::HarnessGateCatalog],
            state_references: vec![CliStateReferenceKind::ContentAddressedStore],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Save(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: vec![
                SessionCommandKind::Start,
                SessionCommandKind::StepDuration,
                SessionCommandKind::CreateSavepoint,
                SessionCommandKind::Query,
            ],
            api_calls: vec![
                CliApiCall::Hello,
                CliApiCall::CreateSession,
                CliApiCall::SendCommand,
            ],
            delegated_drivers: vec![
                CliDelegatedDriver::SessionControlPlane,
                CliDelegatedDriver::ReplayOracle,
            ],
            state_references: vec![
                CliStateReferenceKind::LocalSessionHandle,
                CliStateReferenceKind::ContentAddressedStore,
                CliStateReferenceKind::SavepointHandle,
            ],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Resume(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: vec![
                SessionCommandKind::Start,
                SessionCommandKind::Continue,
                SessionCommandKind::Query,
            ],
            api_calls: vec![
                CliApiCall::Hello,
                CliApiCall::CreateSession,
                CliApiCall::SendCommand,
            ],
            delegated_drivers: vec![CliDelegatedDriver::SessionControlPlane],
            state_references: vec![
                CliStateReferenceKind::SavepointHandle,
                CliStateReferenceKind::ContentAddressedStore,
            ],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Fork(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: vec![
                SessionCommandKind::Fork,
                SessionCommandKind::Continue,
                SessionCommandKind::Query,
            ],
            api_calls: vec![
                CliApiCall::Hello,
                CliApiCall::CreateSession,
                CliApiCall::SendCommand,
            ],
            delegated_drivers: vec![CliDelegatedDriver::SessionControlPlane],
            state_references: vec![
                CliStateReferenceKind::SavepointHandle,
                CliStateReferenceKind::ContentAddressedStore,
            ],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Replay(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: vec![
                SessionCommandKind::Start,
                SessionCommandKind::Continue,
                SessionCommandKind::Snapshot,
            ],
            api_calls: Vec::new(),
            delegated_drivers: vec![
                CliDelegatedDriver::SessionControlPlane,
                CliDelegatedDriver::ReplayOracle,
            ],
            state_references: vec![
                CliStateReferenceKind::ReproductionArtifact,
                CliStateReferenceKind::ContentAddressedStore,
            ],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Search(_) | Commands::Fuzz(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: vec![
                SessionCommandKind::Start,
                SessionCommandKind::Continue,
                SessionCommandKind::Fork,
                SessionCommandKind::Query,
            ],
            api_calls: vec![
                CliApiCall::Hello,
                CliApiCall::CreateSession,
                CliApiCall::SendCommand,
            ],
            delegated_drivers: vec![
                CliDelegatedDriver::ExplorationEngine,
                CliDelegatedDriver::ReplayOracle,
            ],
            state_references: vec![
                CliStateReferenceKind::LocalSessionHandle,
                CliStateReferenceKind::ContentAddressedStore,
                CliStateReferenceKind::ReproductionArtifact,
            ],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Triage(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: Vec::new(),
            api_calls: Vec::new(),
            delegated_drivers: vec![CliDelegatedDriver::TriageEngine],
            state_references: vec![
                CliStateReferenceKind::FindingsLedger,
                CliStateReferenceKind::ContentAddressedStore,
                CliStateReferenceKind::ReproductionArtifact,
            ],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Debug(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: vec![
                SessionCommandKind::Query,
                SessionCommandKind::Snapshot,
                SessionCommandKind::AttachGdb,
                SessionCommandKind::DebugGoto,
                SessionCommandKind::DebugReverseStep,
                SessionCommandKind::DebugReverseContinue,
                SessionCommandKind::DebugForkNonCanonical,
            ],
            api_calls: vec![
                CliApiCall::Hello,
                CliApiCall::ListSessions,
                CliApiCall::SendCommand,
            ],
            delegated_drivers: vec![
                CliDelegatedDriver::SessionControlPlane,
                CliDelegatedDriver::TimeTravelDebugger,
            ],
            state_references: vec![
                CliStateReferenceKind::ReproductionArtifact,
                CliStateReferenceKind::SavepointHandle,
                CliStateReferenceKind::DaemonConnection,
                CliStateReferenceKind::DebugCoordinate,
            ],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Serve(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: vec![
                SessionCommandKind::Start,
                SessionCommandKind::Continue,
                SessionCommandKind::Stop,
                SessionCommandKind::Query,
            ],
            api_calls: CliApiCall::ALL.to_vec(),
            delegated_drivers: vec![
                CliDelegatedDriver::DaemonHost,
                CliDelegatedDriver::ControlApi,
            ],
            state_references: vec![
                CliStateReferenceKind::DaemonConnection,
                CliStateReferenceKind::LocalSessionHandle,
            ],
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
        Commands::Completions(_) => CliThinWrapperPlan {
            subcommand,
            session_commands: Vec::new(),
            api_calls: Vec::new(),
            delegated_drivers: vec![CliDelegatedDriver::ShellCompletionGenerator],
            state_references: Vec::new(),
            thin_wrapper: true,
            owns_canonical_run_state: false,
            implements_scheduler: false,
            implements_checkpoint_materialization: false,
            implements_fork_logic: false,
            extra_control_capabilities: Vec::new(),
        },
    };

    if cli.daemon.is_some() && subcommand_uses_backend_selection(&cli.command) {
        plan.delegated_drivers.push(CliDelegatedDriver::ControlApi);
        plan.state_references
            .push(CliStateReferenceKind::DaemonConnection);
    }

    plan
}

trait CliOperationRecorder {
    fn record_session_command(&mut self, command: SessionCommandKind);

    fn record_api_call(&mut self, call: CliApiCall);

    fn record_driver(&mut self, driver: CliDelegatedDriver);

    fn record_state_reference(&mut self, reference: CliStateReferenceKind);
}

#[derive(Default)]
struct NullOperationRecorder;

impl CliOperationRecorder for NullOperationRecorder {
    fn record_session_command(&mut self, _command: SessionCommandKind) {}

    fn record_api_call(&mut self, _call: CliApiCall) {}

    fn record_driver(&mut self, _driver: CliDelegatedDriver) {}

    fn record_state_reference(&mut self, _reference: CliStateReferenceKind) {}
}

fn execute_cli_dispatch_plan(
    plan: &CliThinWrapperPlan,
    recorder: &mut impl CliOperationRecorder,
) -> Result<(), CliError> {
    if !plan.proves_t_cli_2() {
        return Err(CliError::Backend(
            "CLI invocation violates the RFC-0010 thin-wrapper contract".to_string(),
        ));
    }

    for command in &plan.session_commands {
        recorder.record_session_command(*command);
    }
    for call in &plan.api_calls {
        recorder.record_api_call(*call);
    }
    for driver in &plan.delegated_drivers {
        recorder.record_driver(*driver);
    }
    for reference in &plan.state_references {
        recorder.record_state_reference(*reference);
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeterminismErgonomicsPlan {
    subcommand: CliSubcommand,
    seed: ResolvedSeed,
    seed_printed_at_run_start: bool,
    generated_seed_drawn_before_run: bool,
    generated_seed_is_identity_only: bool,
    failure_artifact_rule: FailureArtifactRule,
    trace_formats: Vec<OutputFormat>,
    jsonl_streams_entries: bool,
    format_changes_only_rendering: bool,
    no_wall_clock_feeds_canonical_state: bool,
}

impl DeterminismErgonomicsPlan {
    fn proves_t_cli_4(&self) -> bool {
        self.seed_printed_at_run_start
            && self.failure_artifact_rule.self_contained_artifact
            && self.failure_artifact_rule.replay_command_copy_pasteable
            && self.failure_artifact_rule.debug_command_copy_pasteable
            && self.trace_formats
                == vec![OutputFormat::Jsonl, OutputFormat::Json, OutputFormat::Table]
            && self.jsonl_streams_entries
            && self.format_changes_only_rendering
            && self.no_wall_clock_feeds_canonical_state
            && match self.seed.source {
                SeedSource::Flag | SeedSource::Environment => {
                    !self.generated_seed_drawn_before_run && self.seed.value_source_pinned
                }
                SeedSource::Generated => {
                    self.generated_seed_drawn_before_run
                        && self.generated_seed_is_identity_only
                        && self.seed.value_source_pinned
                }
            }
    }

    fn seed_announcement(&self) -> String {
        self.seed.announcement()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedSeed {
    value: u64,
    source: SeedSource,
    value_source_pinned: bool,
}

impl ResolvedSeed {
    fn announcement(&self) -> String {
        match self.source {
            SeedSource::Flag => {
                format!("crucible: seed = {} (--seed)", format_seed(self.value))
            }
            SeedSource::Environment => {
                format!(
                    "crucible: seed = {} ({CRUCIBLE_SEED_ENV})",
                    format_seed(self.value)
                )
            }
            SeedSource::Generated => {
                format!(
                    "crucible: seed not set; generated seed = {} (set {CRUCIBLE_SEED_ENV} to pin)",
                    format_seed(self.value)
                )
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SeedSource {
    Flag,
    Environment,
    Generated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FailureArtifactRule {
    self_contained_artifact: bool,
    replay_command_copy_pasteable: bool,
    debug_command_copy_pasteable: bool,
}

const RUN_INTERACTIVE_ACK_QUANTA_BOUND: u64 = crucible_api::STREAMING_COMMAND_MAX_ACTOR_YIELDS;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunInvocationPlan {
    scenario: RunScenarioRef,
    request_seed: Option<crucible::Seed>,
    terminal_condition: RunTerminalCondition,
    max_virtual_time: Option<String>,
    max_virtual_time_ticks: Option<u64>,
    max_quanta: Option<u64>,
    execution_mode: RunExecutionMode,
    save_policy: RunSavePolicy,
    watch_streams_live_status: bool,
    startup_commands: Vec<SessionCommandKind>,
    initial_control_commands: Vec<SessionCommandKind>,
    accepted_interactive_commands: Vec<SessionCommandKind>,
    observer_profile: VerifyHostProfile,
    collect_execution_fingerprints: bool,
    bounded_ack_quanta: u64,
    outcome_exit_codes: Vec<(BackendCommandStatus, i32)>,
    invalid_scenario_exit_code: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RunScenarioRef {
    File {
        path: PathBuf,
        form: crucible::ScenarioDefForm,
        scenario: crucible::ScenarioDef,
    },
    Stored {
        reference: crucible::ContentHash,
        form: crucible::ScenarioDefForm,
        scenario: crucible::ScenarioDef,
    },
}

impl RunScenarioRef {
    #[cfg(test)]
    fn label(&self) -> String {
        match self {
            Self::File { path, .. } => path.display().to_string(),
            Self::Stored { reference, .. } => format_content_hash_ref(*reference),
        }
    }

    fn scenario_id(&self) -> crucible::ContentHash {
        match self {
            Self::File { scenario, .. } | Self::Stored { scenario, .. } => scenario.id(),
        }
    }

    fn scenario_def(&self) -> &crucible::ScenarioDef {
        match self {
            Self::File { scenario, .. } | Self::Stored { scenario, .. } => scenario,
        }
    }

    fn scenario_form(&self) -> &crucible::ScenarioDefForm {
        match self {
            Self::File { form, .. } | Self::Stored { form, .. } => form,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifyInvocationPlan {
    mode: VerifyMode,
    requested_runs: usize,
    reductions: Vec<VerifyReductionPlan>,
    compare_canonical_logs: bool,
    compare_fingerprint_streams: bool,
    pairwise_byte_identity: bool,
    bisection_on_divergence: bool,
    print_bisection_state_dump: bool,
    writes_side_artifacts_on_divergence: bool,
    applies_hostile_condition_matrix: bool,
    outcome_exit_codes: Vec<(BackendCommandStatus, i32)>,
}

impl VerifyInvocationPlan {
    fn scenario(&self) -> Option<&RunScenarioRef> {
        match &self.mode {
            VerifyMode::RunScenario { scenario } => Some(scenario),
            VerifyMode::CompareArtifacts { .. } => None,
        }
    }

    fn surface_shape_is_consistent(&self) -> bool {
        let expected_reductions = match &self.mode {
            VerifyMode::RunScenario { .. } => {
                self.requested_runs
                    .saturating_mul(if self.applies_hostile_condition_matrix {
                        VERIFY_HOSTILE_PROFILES.len()
                    } else {
                        1
                    })
            }
            VerifyMode::CompareArtifacts { .. } => 2,
        };
        self.requested_runs > 0
            && self.reductions.len() == expected_reductions
            && self.compare_canonical_logs
            && self.compare_fingerprint_streams
            && self.pairwise_byte_identity
            && self.writes_side_artifacts_on_divergence
            && (!self.applies_hostile_condition_matrix
                || self
                    .reductions
                    .iter()
                    .any(|reduction| reduction.host_profile != VERIFY_BASELINE_PROFILE))
            && self
                .outcome_exit_codes
                .contains(&(BackendCommandStatus::Passed, 0))
            && self
                .outcome_exit_codes
                .contains(&(BackendCommandStatus::Failed, 1))
            && self
                .outcome_exit_codes
                .contains(&(BackendCommandStatus::Crashed, 3))
            && self
                .outcome_exit_codes
                .contains(&(BackendCommandStatus::Timeout, 2))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum VerifyMode {
    RunScenario { scenario: RunScenarioRef },
    CompareArtifacts { left: PathBuf, right: PathBuf },
}

impl VerifyMode {
    fn label(&self) -> &'static str {
        match self {
            Self::RunScenario { .. } => "run-scenario",
            Self::CompareArtifacts { .. } => "compare-artifacts",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifyReductionPlan {
    index: usize,
    run_index: usize,
    host_profile: VerifyHostProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VerifyHostProfile {
    label: &'static str,
    poll_order: VerifyPollOrder,
    event_timeout_ms: u64,
    state_timeout_ms: u64,
    pre_poll_yields: u8,
    post_poll_yields: u8,
}

impl VerifyHostProfile {
    const fn label(self) -> &'static str {
        self.label
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerifyPollOrder {
    EventThenState,
    StateThenEvent,
}

const VERIFY_BASELINE_PROFILE: VerifyHostProfile = VerifyHostProfile {
    label: "baseline",
    poll_order: VerifyPollOrder::EventThenState,
    event_timeout_ms: 1,
    state_timeout_ms: 10,
    pre_poll_yields: 0,
    post_poll_yields: 1,
};
const VERIFY_HOSTILE_PROFILES: &[VerifyHostProfile] = &[
    VerifyHostProfile {
        label: "randomized-host-scheduler",
        poll_order: VerifyPollOrder::StateThenEvent,
        event_timeout_ms: 1,
        state_timeout_ms: 10,
        pre_poll_yields: 2,
        post_poll_yields: 3,
    },
    VerifyHostProfile {
        label: "wall-clock-jitter",
        poll_order: VerifyPollOrder::EventThenState,
        event_timeout_ms: 3,
        state_timeout_ms: 7,
        pre_poll_yields: 1,
        post_poll_yields: 2,
    },
    VerifyHostProfile {
        label: "varied-core-count",
        poll_order: VerifyPollOrder::StateThenEvent,
        event_timeout_ms: 2,
        state_timeout_ms: 5,
        pre_poll_yields: 3,
        post_poll_yields: 1,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RunTerminalCondition {
    Quiescence,
    VirtualTime,
    Property,
    Stopped,
}

impl RunTerminalCondition {
    fn from_arg(arg: RunUntilArg) -> Self {
        match arg {
            RunUntilArg::Quiescence => Self::Quiescence,
            RunUntilArg::VirtualTime => Self::VirtualTime,
            RunUntilArg::Property => Self::Property,
            RunUntilArg::Stopped => Self::Stopped,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RunExecutionMode {
    ToCompletion,
    Interactive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RunSavePolicy {
    OnFail,
    Always,
    Never,
}

impl RunSavePolicy {
    fn from_arg(arg: RunSaveOnArg) -> Self {
        match arg {
            RunSaveOnArg::Fail => Self::OnFail,
            RunSaveOnArg::Always => Self::Always,
            RunSaveOnArg::Never => Self::Never,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SimBackendLifecycleLoop {
    backend: crucible::SimBackend,
    quanta: u64,
    event_log_events: u64,
}

#[cfg(test)]
impl SimBackendLifecycleLoop {
    fn diagnostic_entry(
        &self,
        frontier: crucible::VirtualTime,
    ) -> crucible::SchedulerEventLogEntry {
        let mut details = BTreeMap::new();
        details.insert(
            String::from("quantum"),
            crucible::EventAttributeValue::U64(self.quanta),
        );
        crucible::SchedulerEventLogEntry::diagnostic(
            self.event_log_events,
            frontier,
            crucible::EventDiagnosticPayload::new(
                "crucible.cli.sim-backend-lifecycle",
                crucible::EventLevel::Info,
                details,
            ),
        )
    }
}

#[cfg(test)]
impl crucible::QuantumLoop for SimBackendLifecycleLoop {
    fn drive_quantum(
        &mut self,
        request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let frontier = crucible::VirtualTime { ticks: self.quanta };
        crucible::SimulationBackend::step_to(&mut self.backend, frontier)?;
        let event_log_entries = vec![self.diagnostic_entry(frontier)];
        self.event_log_events = self
            .event_log_events
            .saturating_add(event_log_entries.len() as u64);
        Ok(crucible::QuantumOutcome {
            configuration: request.configuration,
            frontier,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::new(
                Default::default(),
                0,
                self.event_log_events,
            ),
            scheduler_quiescence: Some(crucible::SchedulerQuiescence::default()),
        })
    }

    fn sample_fingerprint(
        &mut self,
        node: crucible::NodeId,
    ) -> Result<crucible::FingerprintSample, crucible::SchedulerError> {
        crucible::SimulationBackend::fingerprint(&mut self.backend, node).map_err(Into::into)
    }

    fn shutdown(&mut self) -> Result<(), crucible::SchedulerError> {
        crucible::SimulationBackend::shutdown(&mut self.backend).map_err(Into::into)
    }
}

fn plan_run_invocation(args: &RunArgs, store_root: &Path) -> Result<RunInvocationPlan, CliError> {
    let scenario = resolve_run_scenario(args.scenario.as_deref(), store_root)?;
    if args.max_quanta == Some(0) {
        return Err(usage_error("--max-quanta must be greater than zero"));
    }
    if let Some(duration) = &args.max_virtual_time {
        if parse_run_duration_budget_ticks(duration).is_none() {
            return Err(usage_error(
                "--max-virtual-time must be a non-empty duration like 10ms, 5s, or 100ticks",
            ));
        }
    }
    let terminal_condition = RunTerminalCondition::from_arg(args.until);
    if terminal_condition == RunTerminalCondition::VirtualTime && args.max_virtual_time.is_none() {
        return Err(usage_error(
            "--until virtual-time requires --max-virtual-time",
        ));
    }
    let execution_mode = if args.interactive {
        RunExecutionMode::Interactive
    } else {
        RunExecutionMode::ToCompletion
    };
    let startup_commands = match execution_mode {
        RunExecutionMode::ToCompletion => {
            vec![SessionCommandKind::Start, SessionCommandKind::Continue]
        }
        RunExecutionMode::Interactive => vec![SessionCommandKind::Start],
    };
    let initial_control_commands = vec![SessionCommandKind::Query];
    let accepted_interactive_commands = if args.interactive {
        run_interactive_session_command_set()
    } else {
        Vec::new()
    };

    Ok(RunInvocationPlan {
        scenario,
        request_seed: None,
        terminal_condition,
        max_virtual_time: args.max_virtual_time.clone(),
        max_virtual_time_ticks: args
            .max_virtual_time
            .as_deref()
            .and_then(parse_run_duration_budget_ticks),
        max_quanta: args.max_quanta,
        execution_mode,
        save_policy: RunSavePolicy::from_arg(args.save_on),
        watch_streams_live_status: args.watch,
        startup_commands,
        initial_control_commands,
        accepted_interactive_commands,
        observer_profile: VERIFY_BASELINE_PROFILE,
        collect_execution_fingerprints: false,
        bounded_ack_quanta: RUN_INTERACTIVE_ACK_QUANTA_BOUND,
        outcome_exit_codes: vec![
            (
                BackendCommandStatus::Passed,
                CliError::Outcome(BackendCommandStatus::Passed).exit_code(),
            ),
            (
                BackendCommandStatus::Failed,
                CliError::Outcome(BackendCommandStatus::Failed).exit_code(),
            ),
            (
                BackendCommandStatus::Timeout,
                CliError::Outcome(BackendCommandStatus::Timeout).exit_code(),
            ),
            (
                BackendCommandStatus::Crashed,
                CliError::Outcome(BackendCommandStatus::Crashed).exit_code(),
            ),
        ],
        invalid_scenario_exit_code: CliError::InvalidScenario(String::new()).exit_code(),
    })
}

fn plan_verify_invocation(
    args: &VerifyArgs,
    store_root: &Path,
) -> Result<VerifyInvocationPlan, CliError> {
    if args.compare.len() != 0 && args.compare.len() != 2 {
        return Err(usage_error("--compare requires exactly two artifacts"));
    }
    let mode = if args.compare.is_empty() {
        if args.runs < 2 {
            return Err(usage_error(
                "--runs must be at least 2 for fresh verify reductions",
            ));
        }
        VerifyMode::RunScenario {
            scenario: resolve_command_scenario("verify", args.scenario.as_deref(), store_root)?,
        }
    } else {
        if args.scenario.is_some() {
            return Err(usage_error(
                "verify accepts either SCENARIO or --compare A B, not both",
            ));
        }
        if args.adversarial {
            return Err(usage_error(
                "--adversarial applies only to fresh verify reductions, not --compare",
            ));
        }
        if args.runs != 2 {
            return Err(usage_error(
                "--runs is ignored by --compare; omit it or use --runs 2",
            ));
        }
        VerifyMode::CompareArtifacts {
            left: args.compare[0].clone(),
            right: args.compare[1].clone(),
        }
    };
    let reductions = verify_reduction_plans(args.runs, args.adversarial, &mode);
    let plan = VerifyInvocationPlan {
        mode,
        requested_runs: args.runs,
        reductions,
        compare_canonical_logs: true,
        compare_fingerprint_streams: true,
        pairwise_byte_identity: true,
        bisection_on_divergence: true,
        print_bisection_state_dump: args.bisect,
        writes_side_artifacts_on_divergence: true,
        applies_hostile_condition_matrix: args.adversarial,
        outcome_exit_codes: vec![
            (
                BackendCommandStatus::Passed,
                CliError::Outcome(BackendCommandStatus::Passed).exit_code(),
            ),
            (
                BackendCommandStatus::Failed,
                CliError::Outcome(BackendCommandStatus::Failed).exit_code(),
            ),
            (
                BackendCommandStatus::Timeout,
                CliError::Outcome(BackendCommandStatus::Timeout).exit_code(),
            ),
            (
                BackendCommandStatus::Crashed,
                CliError::Outcome(BackendCommandStatus::Crashed).exit_code(),
            ),
        ],
    };
    if !plan.surface_shape_is_consistent() {
        return Err(CliError::Backend(
            "verify planner is internally inconsistent".to_string(),
        ));
    }
    Ok(plan)
}

fn verify_reduction_plans(
    runs: usize,
    adversarial: bool,
    mode: &VerifyMode,
) -> Vec<VerifyReductionPlan> {
    if matches!(mode, VerifyMode::CompareArtifacts { .. }) {
        return vec![
            VerifyReductionPlan {
                index: 0,
                run_index: 0,
                host_profile: VERIFY_BASELINE_PROFILE,
            },
            VerifyReductionPlan {
                index: 1,
                run_index: 1,
                host_profile: VERIFY_BASELINE_PROFILE,
            },
        ];
    }
    let profiles = if adversarial {
        VERIFY_HOSTILE_PROFILES
    } else {
        &[VERIFY_BASELINE_PROFILE]
    };
    let mut reductions = Vec::with_capacity(runs.saturating_mul(profiles.len()));
    for run_index in 0..runs {
        for host_profile in profiles {
            reductions.push(VerifyReductionPlan {
                index: reductions.len(),
                run_index,
                host_profile: *host_profile,
            });
        }
    }
    reductions
}

fn resolve_run_scenario(
    scenario: Option<&str>,
    store_root: &Path,
) -> Result<RunScenarioRef, CliError> {
    resolve_command_scenario("run", scenario, store_root)
}

fn resolve_command_scenario(
    command: &'static str,
    scenario: Option<&str>,
    store_root: &Path,
) -> Result<RunScenarioRef, CliError> {
    let Some(raw) = scenario else {
        return Err(usage_error(format!(
            "{command} requires a SCENARIO argument"
        )));
    };
    let value = raw.trim();
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(invalid_scenario(
            "scenario reference must not be empty or multiline",
        ));
    }

    if value.starts_with(CONTENT_ADDRESS_PREFIX) {
        return Err(invalid_scenario(format!(
            "scenario content hash `{value}` is not a DAG-store `blake3:<hash>` reference",
        )));
    }
    if value.starts_with("blake3:") {
        let reference =
            crucible::ContentAddressedBlobRef::parse("scenario", value).map_err(|error| {
                invalid_scenario(format!(
                    "scenario content hash `{value}` is malformed: {error}"
                ))
            })?;
        let store = crucible::LocalDagStore::new(store_root.to_path_buf());
        let bytes = store.get(&reference.hash()).map_err(|error| {
            invalid_scenario(format!(
                "scenario content hash `{value}` could not be loaded from {}: {error}",
                store.root().display()
            ))
        })?;
        let form = parse_run_scenario_bytes(value, &bytes)?;
        let scenario = form.scenario_def();
        return Ok(RunScenarioRef::Stored {
            reference: reference.hash(),
            form,
            scenario,
        });
    }

    let path = Path::new(value);
    if !path.exists() {
        return Err(invalid_scenario(format!(
            "scenario `{value}` does not exist"
        )));
    }
    if !path.is_file() {
        return Err(invalid_scenario(format!(
            "scenario `{value}` is not a regular file"
        )));
    }
    let bytes = fs::read(path).map_err(|error| {
        invalid_scenario(format!("scenario `{value}` could not be read: {error}"))
    })?;
    let form = parse_run_scenario_bytes(value, &bytes)?;
    let scenario = form.scenario_def();
    Ok(RunScenarioRef::File {
        path: path.to_path_buf(),
        form,
        scenario,
    })
}

fn parse_run_scenario_bytes(
    label: &str,
    bytes: &[u8],
) -> Result<crucible::ScenarioDefForm, CliError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        invalid_scenario(format!(
            "scenario `{label}` is not UTF-8 canonical TOML: {error}"
        ))
    })?;
    crucible::ScenarioDefForm::from_canonical_toml(text).map_err(|error| {
        invalid_scenario(format!(
            "scenario `{label}` failed canonical TOML build/validation: {error}"
        ))
    })
}

fn reseed_run_scenario_ref(
    scenario: &RunScenarioRef,
    seed: crucible::Seed,
) -> Result<RunScenarioRef, CliError> {
    let form = scenario.scenario_form();
    let seeded_form = crucible::ScenarioDefForm::from_components_with_app_random_draw_cap(
        form.world(),
        form.plan(),
        form.properties(),
        seed,
        form.app_random_draw_cap(),
    )
    .map_err(|error| {
        backend_error(format!(
            "verify could not rematerialize scenario for seed {}: {error}",
            seed.to_hex()
        ))
    })?;
    let seeded_scenario = seeded_form.scenario_def();
    Ok(match scenario {
        RunScenarioRef::File { path, .. } => RunScenarioRef::File {
            path: path.clone(),
            form: seeded_form,
            scenario: seeded_scenario,
        },
        RunScenarioRef::Stored { reference, .. } => RunScenarioRef::Stored {
            reference: *reference,
            form: seeded_form,
            scenario: seeded_scenario,
        },
    })
}

fn parse_run_duration_budget_ticks(duration: &str) -> Option<u64> {
    let trimmed = duration.trim();
    if trimmed.is_empty() {
        return None;
    }
    let digit_len = trimmed.bytes().take_while(u8::is_ascii_digit).count();
    if digit_len == 0 {
        return None;
    }
    let value = trimmed[..digit_len].parse::<u64>().ok()?;
    if value == 0 {
        return None;
    }
    let suffix = &trimmed[digit_len..];
    let multiplier = match suffix {
        "" | "tick" | "ticks" => 1,
        "ns" => 1,
        "us" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        _ => return None,
    };
    value.checked_mul(multiplier)
}

fn run_interactive_session_command_set() -> Vec<SessionCommandKind> {
    vec![
        SessionCommandKind::Continue,
        SessionCommandKind::Pause,
        SessionCommandKind::StepQuantum,
        SessionCommandKind::StepEvent,
        SessionCommandKind::StepAssertion,
        SessionCommandKind::StepTimer,
        SessionCommandKind::StepDuration,
        SessionCommandKind::Inject,
        SessionCommandKind::InjectFault,
        SessionCommandKind::HealFault,
        SessionCommandKind::CreateSavepoint,
        SessionCommandKind::Fork,
        SessionCommandKind::Query,
        SessionCommandKind::Stop,
    ]
}

trait SeedEnvironment {
    fn variable(&self, name: &'static str) -> Option<String>;
}

#[derive(Default)]
struct ProcessSeedEnvironment;

impl SeedEnvironment for ProcessSeedEnvironment {
    fn variable(&self, name: &'static str) -> Option<String> {
        std::env::var(name).ok()
    }
}

trait SeedEntropySource {
    fn generated_seed(&mut self) -> Result<u64, CliError>;
}

#[derive(Default)]
struct OsSeedEntropySource;

impl SeedEntropySource for OsSeedEntropySource {
    fn generated_seed(&mut self) -> Result<u64, CliError> {
        let mut bytes = [0u8; 8];
        let mut device = fs::File::open(OS_ENTROPY_DEVICE).map_err(|error| {
            CliError::Backend(format!(
                "could not open OS entropy source before run identity creation: {error}"
            ))
        })?;
        device.read_exact(&mut bytes).map_err(|error| {
            CliError::Backend(format!(
                "could not read OS entropy source before run identity creation: {error}"
            ))
        })?;
        Ok(u64::from_le_bytes(bytes))
    }
}

trait DeterminismErgonomicsRecorder {
    fn record_seed_resolution(&mut self, seed: &ResolvedSeed);

    fn record_trace_format(&mut self, format: OutputFormat);

    fn record_failure_artifact_rule(&mut self, rule: &FailureArtifactRule);
}

#[derive(Default)]
struct NullDeterminismErgonomicsRecorder;

impl DeterminismErgonomicsRecorder for NullDeterminismErgonomicsRecorder {
    fn record_seed_resolution(&mut self, _seed: &ResolvedSeed) {}

    fn record_trace_format(&mut self, _format: OutputFormat) {}

    fn record_failure_artifact_rule(&mut self, _rule: &FailureArtifactRule) {}
}

fn plan_determinism_ergonomics(
    cli: &Cli,
    environment: &impl SeedEnvironment,
    entropy: &mut impl SeedEntropySource,
) -> Result<Option<DeterminismErgonomicsPlan>, CliError> {
    validate_canonical_trace_format(cli)?;
    if !subcommand_uses_seed_resolution(&cli.command) {
        return Ok(None);
    }
    let seed = resolve_seed(cli, environment, entropy)?;
    let generated = seed.source == SeedSource::Generated;
    Ok(Some(DeterminismErgonomicsPlan {
        subcommand: CliSubcommand::from_command(&cli.command),
        seed,
        seed_printed_at_run_start: true,
        generated_seed_drawn_before_run: generated,
        generated_seed_is_identity_only: generated,
        failure_artifact_rule: FailureArtifactRule {
            self_contained_artifact: true,
            replay_command_copy_pasteable: true,
            debug_command_copy_pasteable: true,
        },
        trace_formats: vec![OutputFormat::Jsonl, OutputFormat::Json, OutputFormat::Table],
        jsonl_streams_entries: true,
        format_changes_only_rendering: true,
        no_wall_clock_feeds_canonical_state: true,
    }))
}

fn execute_determinism_ergonomics_plan(
    plan: &DeterminismErgonomicsPlan,
    recorder: &mut impl DeterminismErgonomicsRecorder,
) -> Result<(), CliError> {
    if !plan.proves_t_cli_4() {
        return Err(CliError::Backend(
            "CLI determinism ergonomics violate the RFC-0010 seed/artifact/trace contract"
                .to_string(),
        ));
    }
    let rendered = render_canonical_trace_format_proof()?;
    if !rendered.iter().all(|entry| {
        entry.entry_count == 1
            && entry.canonical_digest == rendered[0].canonical_digest
            && (entry.format != OutputFormat::Jsonl || entry.jsonl_streams_entries)
            && !entry.bytes.is_empty()
    }) {
        return Err(CliError::Backend(
            "canonical event-log renderers do not preserve the same entry stream".to_string(),
        ));
    }
    if !BackendCommandStatus::non_passing_variants()
        .iter()
        .all(|status| status.is_non_passing() && status.failure_slug() != "passed")
    {
        return Err(CliError::Backend(
            "non-passing outcomes are not all artifact-producing statuses".to_string(),
        ));
    }
    if !canonical_state_wall_clock_guard() {
        return Err(CliError::Backend(
            "canonical state paths expose host wall-clock APIs".to_string(),
        ));
    }
    recorder.record_seed_resolution(&plan.seed);
    for format in &plan.trace_formats {
        recorder.record_trace_format(*format);
    }
    recorder.record_failure_artifact_rule(&plan.failure_artifact_rule);
    Ok(())
}

fn subcommand_uses_seed_resolution(command: &Commands) -> bool {
    seed_resolution_mode(command) == SeedResolutionMode::FreshRunIdentity
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SeedResolutionMode {
    FreshRunIdentity,
    ArtifactOrSavepointOwned,
    NotApplicable,
}

fn seed_resolution_mode(command: &Commands) -> SeedResolutionMode {
    matches!(
        command,
        Commands::Run(_)
            | Commands::Verify(_)
            | Commands::Save(_)
            | Commands::Fork(_)
            | Commands::Search(_)
            | Commands::Fuzz(_)
    )
    .then_some(SeedResolutionMode::FreshRunIdentity)
    .unwrap_or_else(|| match command {
        Commands::Resume(_) | Commands::Replay(_) => SeedResolutionMode::ArtifactOrSavepointOwned,
        Commands::Selftest(_)
        | Commands::Triage(_)
        | Commands::Debug(_)
        | Commands::Serve(_)
        | Commands::Completions(_) => SeedResolutionMode::NotApplicable,
        Commands::Run(_)
        | Commands::Verify(_)
        | Commands::Save(_)
        | Commands::Fork(_)
        | Commands::Search(_)
        | Commands::Fuzz(_) => SeedResolutionMode::FreshRunIdentity,
    })
}

fn validate_canonical_trace_format(cli: &Cli) -> Result<(), CliError> {
    if cli.format == OutputFormat::Markdown && subcommand_uses_canonical_event_trace(&cli.command) {
        return Err(usage_error(
            "--format markdown is reserved for triage reports, not canonical event-log traces",
        ));
    }
    Ok(())
}

fn subcommand_uses_canonical_event_trace(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Run(_)
            | Commands::Verify(_)
            | Commands::Save(_)
            | Commands::Resume(_)
            | Commands::Fork(_)
            | Commands::Replay(_)
            | Commands::Search(_)
            | Commands::Fuzz(_)
            | Commands::Selftest(_)
    )
}

fn resolve_seed(
    cli: &Cli,
    environment: &impl SeedEnvironment,
    entropy: &mut impl SeedEntropySource,
) -> Result<ResolvedSeed, CliError> {
    if let Some(seed) = &cli.seed {
        return Ok(ResolvedSeed {
            value: parse_seed_value("--seed", seed)?,
            source: SeedSource::Flag,
            value_source_pinned: true,
        });
    }
    if let Some(seed) = environment.variable(CRUCIBLE_SEED_ENV) {
        return Ok(ResolvedSeed {
            value: parse_seed_value(CRUCIBLE_SEED_ENV, &seed)?,
            source: SeedSource::Environment,
            value_source_pinned: true,
        });
    }
    Ok(ResolvedSeed {
        value: entropy.generated_seed()?,
        source: SeedSource::Generated,
        value_source_pinned: true,
    })
}

fn parse_seed_value(field: &'static str, value: &str) -> Result<u64, CliError> {
    if value.is_empty() {
        return Err(usage_error(format!("{field} must not be empty")));
    }
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    };
    parsed.map_err(|_| usage_error(format!("{field} must be a u64 decimal or hex value")))
}

fn format_seed(seed: u64) -> String {
    format!("0x{seed:016x}")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalLogEntry {
    sequence: u64,
    virtual_time_ticks: u64,
    node: String,
    kind: String,
    summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RenderedCanonicalLog {
    format: OutputFormat,
    bytes: Vec<u8>,
    entry_count: usize,
    canonical_digest: String,
    jsonl_streams_entries: bool,
}

fn render_canonical_event_log(
    format: OutputFormat,
    entries: &[CanonicalLogEntry],
) -> Result<RenderedCanonicalLog, CliError> {
    if format == OutputFormat::Markdown {
        return Err(usage_error(
            "--format markdown is reserved for triage reports, not canonical event-log traces",
        ));
    }
    let canonical_digest = canonical_log_digest(entries);
    let (bytes, jsonl_streams_entries) = match format {
        OutputFormat::Jsonl => (jsonl_for_canonical_log_entries(entries).into_bytes(), true),
        OutputFormat::Json => (
            format!(
                "[{}]",
                entries
                    .iter()
                    .map(json_for_canonical_log_entry)
                    .collect::<Vec<_>>()
                    .join(",")
            )
            .into_bytes(),
            false,
        ),
        OutputFormat::Table => (table_for_canonical_log_entries(entries).into_bytes(), false),
        OutputFormat::Markdown => unreachable!("markdown rejected above"),
    };
    Ok(RenderedCanonicalLog {
        format,
        bytes,
        entry_count: entries.len(),
        canonical_digest,
        jsonl_streams_entries,
    })
}

fn jsonl_for_canonical_log_entries(entries: &[CanonicalLogEntry]) -> String {
    let mut text = String::new();
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            text.push('\n');
        }
        text.push_str(&json_for_canonical_log_entry(entry));
    }
    text
}

fn canonical_log_digest(entries: &[CanonicalLogEntry]) -> String {
    let mut material = String::new();
    for entry in entries {
        artifact_line(
            &mut material,
            &[
                &entry.sequence.to_string(),
                &entry.virtual_time_ticks.to_string(),
                &entry.node,
                &entry.kind,
                &entry.summary,
            ],
        );
    }
    content_address_bytes(material.as_bytes())
}

fn json_for_canonical_log_entry(entry: &CanonicalLogEntry) -> String {
    format!(
        "{{\"seq\":{},\"virtual_time\":{},\"node\":\"{}\",\"kind\":\"{}\",\"summary\":\"{}\"}}",
        entry.sequence,
        entry.virtual_time_ticks,
        json_escape(&entry.node),
        json_escape(&entry.kind),
        json_escape(&entry.summary)
    )
}

fn table_for_canonical_log_entries(entries: &[CanonicalLogEntry]) -> String {
    let mut lines = vec![String::from("seq\tvirtual_time\tnode\tkind\tsummary")];
    for entry in entries {
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}",
            entry.sequence, entry.virtual_time_ticks, entry.node, entry.kind, entry.summary
        ));
    }
    lines.join("\n")
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
}

fn render_canonical_trace_format_proof() -> Result<Vec<RenderedCanonicalLog>, CliError> {
    let entries = [CanonicalLogEntry {
        sequence: 0,
        virtual_time_ticks: 0,
        node: String::from("proof-node"),
        kind: String::from("proof"),
        summary: String::from("same canonical entry stream"),
    }];
    [OutputFormat::Jsonl, OutputFormat::Json, OutputFormat::Table]
        .into_iter()
        .map(|format| render_canonical_event_log(format, &entries))
        .collect()
}

fn canonical_state_wall_clock_guard() -> bool {
    let sources = [
        ("crucible-cli", include_str!("main.rs")),
        (
            "crucible-model",
            include_str!("../../crucible/src/model.rs"),
        ),
        (
            "crucible-session",
            include_str!("../../crucible-session/src/lib.rs"),
        ),
    ];
    let forbidden = [
        ["System", "Time"].concat(),
        ["Ins", "tant::now"].concat(),
        ["std::", "ti", "me::", "Ins", "tant"].concat(),
        ["UNIX", "_EPOCH"].concat(),
    ];
    sources.iter().all(|(_, source)| {
        forbidden
            .iter()
            .all(|needle| !source.contains(needle.as_str()))
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FailureReproductionFooter {
    artifact_path: PathBuf,
    replay_command: String,
    debug_command: String,
    self_contained_artifact: bool,
}

fn failure_reproduction_footer(path: PathBuf) -> FailureReproductionFooter {
    let artifact = path.display().to_string();
    FailureReproductionFooter {
        replay_command: format!(
            "crucible replay {}",
            shell_quote_command_argument(&artifact)
        ),
        debug_command: crucible::DebugFailureFooterCommand::new(artifact).debug_command,
        artifact_path: path,
        self_contained_artifact: true,
    }
}

fn shell_quote_command_argument(value: &str) -> String {
    if !value.is_empty() && value.bytes().all(is_shell_safe_unquoted_byte) {
        return value.to_owned();
    }

    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn is_shell_safe_unquoted_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'@'
            | b'%'
            | b'_'
            | b'+'
            | b'='
            | b':'
            | b','
            | b'.'
            | b'/'
            | b'-'
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendSelectionPlan {
    subcommand: CliSubcommand,
    target: BackendExecutionTarget,
    requested_backend: Backend,
    resolved_backend: Option<ResolvedLocalBackend>,
    reason: BackendSelectionReason,
    daemon: Option<String>,
    remote_uses_control_api: bool,
    local_uses_simulation_backend: bool,
    local_remote_equivalence_contract: bool,
}

impl BackendSelectionPlan {
    fn proves_t_cli_3(&self) -> bool {
        self.local_remote_equivalence_contract
            && match self.target {
                BackendExecutionTarget::RemoteDaemon => {
                    self.daemon
                        .as_deref()
                        .is_some_and(|daemon| !daemon.is_empty())
                        && self.resolved_backend.is_none()
                        && self.remote_uses_control_api
                        && !self.local_uses_simulation_backend
                        && self.reason == BackendSelectionReason::RemoteDaemon
                }
                BackendExecutionTarget::Local => {
                    self.daemon.is_none()
                        && self.resolved_backend.is_some()
                        && !self.remote_uses_control_api
                        && self.local_uses_simulation_backend
                        && match (self.requested_backend, &self.resolved_backend, self.reason) {
                            (
                                Backend::Auto,
                                Some(ResolvedLocalBackend::Qemu { qemu, plugin, .. }),
                                BackendSelectionReason::AutoQemuArtifactsSupplied,
                            ) => !qemu.as_os_str().is_empty() && !plugin.as_os_str().is_empty(),
                            (
                                Backend::Auto,
                                Some(ResolvedLocalBackend::Double),
                                BackendSelectionReason::AutoFallbackDouble,
                            )
                            | (
                                Backend::Double,
                                Some(ResolvedLocalBackend::Double),
                                BackendSelectionReason::ExplicitDouble,
                            ) => true,
                            (
                                Backend::Qemu,
                                Some(ResolvedLocalBackend::Qemu { qemu, plugin, .. }),
                                BackendSelectionReason::ExplicitQemu,
                            ) => !qemu.as_os_str().is_empty() && !plugin.as_os_str().is_empty(),
                            _ => false,
                        }
                }
            }
    }

    fn proves_t_cli_5(&self) -> bool {
        match (&self.target, &self.resolved_backend, self.requested_backend) {
            (BackendExecutionTarget::RemoteDaemon, None, _) => true,
            (BackendExecutionTarget::Local, Some(ResolvedLocalBackend::Double), Backend::Auto)
            | (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Double),
                Backend::Double,
            ) => true,
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Qemu {
                    qemu,
                    plugin,
                    qemu_build_id,
                    plugin_abi,
                    qemu_source,
                    plugin_source,
                }),
                Backend::Auto | Backend::Qemu,
            ) => {
                let required_plugin_abi = required_qemu_plugin_abi();
                !qemu.as_os_str().is_empty()
                    && !plugin.as_os_str().is_empty()
                    && is_content_address(qemu_build_id)
                    && plugin_abi == &required_plugin_abi
                    && qemu_source.is_hermetic()
                    && plugin_source.is_hermetic()
            }
            _ => false,
        }
    }

    fn should_announce(&self, quiet: bool) -> bool {
        !quiet
            && matches!(
                self.reason,
                BackendSelectionReason::AutoFallbackDouble
                    | BackendSelectionReason::AutoQemuArtifactsSupplied
            )
    }

    fn announcement(&self) -> String {
        match (&self.target, &self.resolved_backend, self.reason) {
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Qemu { .. }),
                BackendSelectionReason::AutoQemuArtifactsSupplied,
            ) => String::from(
                "crucible: backend = qemu (--backend auto; patched QEMU and plugin discovered)",
            ),
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Double),
                BackendSelectionReason::AutoFallbackDouble,
            ) => String::from(
                "crucible: backend = double (--backend auto; patched QEMU/plugin not discoverable)",
            ),
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Double),
                BackendSelectionReason::ExplicitDouble,
            ) => String::from("crucible: backend = double (explicit --backend double)"),
            (
                BackendExecutionTarget::Local,
                Some(ResolvedLocalBackend::Qemu { .. }),
                BackendSelectionReason::ExplicitQemu,
            ) => String::from(
                "crucible: backend = qemu (explicit --backend qemu with hermetic QEMU/plugin discovery)",
            ),
            (BackendExecutionTarget::RemoteDaemon, None, BackendSelectionReason::RemoteDaemon) => {
                format!(
                    "crucible: backend = daemon (remote API {}; daemon backend fidelity applies)",
                    self.daemon.as_deref().unwrap_or("<unset>")
                )
            }
            _ => String::from("crucible: backend selection is invalid"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BackendExecutionTarget {
    Local,
    RemoteDaemon,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ResolvedLocalBackend {
    Qemu {
        qemu: PathBuf,
        plugin: PathBuf,
        qemu_build_id: String,
        plugin_abi: String,
        qemu_source: QemuDiscoverySource,
        plugin_source: QemuDiscoverySource,
    },
    Double,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum QemuDiscoverySource {
    Flag,
    Environment,
    AosPackageSet,
}

impl QemuDiscoverySource {
    const fn is_hermetic(self) -> bool {
        matches!(self, Self::Flag | Self::Environment | Self::AosPackageSet)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QemuDiscoveryCandidate {
    path: PathBuf,
    source: QemuDiscoverySource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QemuArtifactIdentity {
    qemu_build_id: String,
    plugin_abi: String,
}

#[derive(Debug)]
struct QemuBuildMarker {
    raw_build_id: String,
    artifact_build_id: String,
}

#[derive(Debug)]
struct PluginBuildMarker {
    plugin_abi: String,
    qemu_build_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BackendSelectionReason {
    RemoteDaemon,
    ExplicitDouble,
    ExplicitQemu,
    AutoQemuArtifactsSupplied,
    AutoFallbackDouble,
}

trait BackendRouteRecorder {
    fn record_remote_daemon(&mut self, daemon: &str);

    fn record_local_backend(&mut self, backend: &ResolvedLocalBackend);

    fn record_backend_announcement(&mut self, message: &str);
}

#[derive(Default)]
struct NullBackendRouteRecorder;

impl BackendRouteRecorder for NullBackendRouteRecorder {
    fn record_remote_daemon(&mut self, _daemon: &str) {}

    fn record_local_backend(&mut self, _backend: &ResolvedLocalBackend) {}

    fn record_backend_announcement(&mut self, _message: &str) {}
}

#[cfg(not(test))]
fn plan_backend_selection(cli: &Cli) -> Result<Option<BackendSelectionPlan>, CliError> {
    plan_backend_selection_with_discovery(
        cli,
        &ProcessQemuDiscoveryEnvironment,
        &CompileTimeAosQemuPackageSet,
    )
}

#[cfg(test)]
fn plan_backend_selection(cli: &Cli) -> Result<Option<BackendSelectionPlan>, CliError> {
    plan_backend_selection_with_discovery(
        cli,
        &ProcessQemuDiscoveryEnvironment,
        &NoAosQemuPackageSet,
    )
}

fn plan_backend_selection_with_discovery(
    cli: &Cli,
    environment: &impl QemuDiscoveryEnvironment,
    package_set: &impl AosQemuPackageSet,
) -> Result<Option<BackendSelectionPlan>, CliError> {
    if !subcommand_uses_backend_selection(&cli.command) {
        return Ok(None);
    }
    let subcommand = CliSubcommand::from_command(&cli.command);
    if matches!(cli.command, Commands::Serve(_)) && cli.daemon.is_some() {
        return Err(usage_error(
            "serve hosts the daemon and cannot itself use --daemon",
        ));
    }

    if let Some(daemon) = &cli.daemon {
        if daemon.is_empty() {
            return Err(usage_error("--daemon must not be empty"));
        }
        return Ok(Some(BackendSelectionPlan {
            subcommand,
            target: BackendExecutionTarget::RemoteDaemon,
            requested_backend: cli.backend,
            resolved_backend: None,
            reason: BackendSelectionReason::RemoteDaemon,
            daemon: Some(daemon.clone()),
            remote_uses_control_api: true,
            local_uses_simulation_backend: false,
            local_remote_equivalence_contract: true,
        }));
    }

    let (resolved_backend, reason) = match cli.backend {
        Backend::Double => (
            ResolvedLocalBackend::Double,
            BackendSelectionReason::ExplicitDouble,
        ),
        Backend::Qemu => (
            require_qemu_artifacts(cli, environment, package_set)?,
            BackendSelectionReason::ExplicitQemu,
        ),
        Backend::Auto => match discover_qemu_artifacts(cli, environment, package_set)? {
            Some(artifacts) => (artifacts, BackendSelectionReason::AutoQemuArtifactsSupplied),
            None => (
                ResolvedLocalBackend::Double,
                BackendSelectionReason::AutoFallbackDouble,
            ),
        },
    };

    Ok(Some(BackendSelectionPlan {
        subcommand,
        target: BackendExecutionTarget::Local,
        requested_backend: cli.backend,
        resolved_backend: Some(resolved_backend),
        reason,
        daemon: None,
        remote_uses_control_api: false,
        local_uses_simulation_backend: true,
        local_remote_equivalence_contract: true,
    }))
}

trait QemuDiscoveryEnvironment {
    fn variable(&self, name: &'static str) -> Option<String>;
}

#[derive(Default)]
struct ProcessQemuDiscoveryEnvironment;

impl QemuDiscoveryEnvironment for ProcessQemuDiscoveryEnvironment {
    fn variable(&self, name: &'static str) -> Option<String> {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    }
}

trait AosQemuPackageSet {
    fn qemu_path(&self) -> Option<PathBuf>;

    fn plugin_path(&self) -> Option<PathBuf>;
}

#[derive(Default)]
struct CompileTimeAosQemuPackageSet;

impl AosQemuPackageSet for CompileTimeAosQemuPackageSet {
    fn qemu_path(&self) -> Option<PathBuf> {
        option_env!("CRUCIBLE_AOS_QEMU").map(PathBuf::from)
    }

    fn plugin_path(&self) -> Option<PathBuf> {
        option_env!("CRUCIBLE_AOS_PLUGIN").map(PathBuf::from)
    }
}

#[cfg(test)]
#[derive(Default)]
struct NoAosQemuPackageSet;

#[cfg(test)]
impl AosQemuPackageSet for NoAosQemuPackageSet {
    fn qemu_path(&self) -> Option<PathBuf> {
        None
    }

    fn plugin_path(&self) -> Option<PathBuf> {
        None
    }
}

fn require_qemu_artifacts(
    cli: &Cli,
    environment: &impl QemuDiscoveryEnvironment,
    package_set: &impl AosQemuPackageSet,
) -> Result<ResolvedLocalBackend, CliError> {
    discover_qemu_artifacts(cli, environment, package_set)?.ok_or_else(|| {
        qemu_backend_config_error(format!(
            "--backend qemu could not discover both patched QEMU and plugin; {}",
            qemu_discovery_order_help()
        ))
    })
}

fn discover_qemu_artifacts(
    cli: &Cli,
    environment: &impl QemuDiscoveryEnvironment,
    package_set: &impl AosQemuPackageSet,
) -> Result<Option<ResolvedLocalBackend>, CliError> {
    let qemu = select_qemu_candidate(
        cli.qemu.as_ref(),
        environment.variable(CRUCIBLE_QEMU_ENV),
        package_set.qemu_path(),
    );
    let plugin = select_plugin_candidate(
        cli.plugin.as_ref(),
        environment.variable(CRUCIBLE_PLUGIN_ENV),
        package_set.plugin_path(),
    );
    let (Some(qemu), Some(plugin)) = (qemu, plugin) else {
        return Ok(None);
    };
    let identity = validate_qemu_artifacts(&qemu.path, &plugin.path)?;
    Ok(Some(ResolvedLocalBackend::Qemu {
        qemu: qemu.path,
        plugin: plugin.path,
        qemu_build_id: identity.qemu_build_id,
        plugin_abi: identity.plugin_abi,
        qemu_source: qemu.source,
        plugin_source: plugin.source,
    }))
}

fn select_qemu_candidate(
    flag: Option<&PathBuf>,
    environment: Option<String>,
    package_set: Option<PathBuf>,
) -> Option<QemuDiscoveryCandidate> {
    select_qemu_discovery_candidate(flag, environment, package_set)
}

fn select_plugin_candidate(
    flag: Option<&PathBuf>,
    environment: Option<String>,
    package_set: Option<PathBuf>,
) -> Option<QemuDiscoveryCandidate> {
    select_qemu_discovery_candidate(flag, environment, package_set)
}

fn select_qemu_discovery_candidate(
    flag: Option<&PathBuf>,
    environment: Option<String>,
    package_set: Option<PathBuf>,
) -> Option<QemuDiscoveryCandidate> {
    if let Some(path) = flag {
        return Some(QemuDiscoveryCandidate {
            path: path.clone(),
            source: QemuDiscoverySource::Flag,
        });
    }
    if let Some(value) = environment.filter(|value| !value.trim().is_empty()) {
        return Some(QemuDiscoveryCandidate {
            path: PathBuf::from(value),
            source: QemuDiscoverySource::Environment,
        });
    }
    package_set.map(|path| QemuDiscoveryCandidate {
        path,
        source: QemuDiscoverySource::AosPackageSet,
    })
}

fn validate_qemu_artifacts(qemu: &Path, plugin: &Path) -> Result<QemuArtifactIdentity, CliError> {
    validate_readable_file_artifact("patched QEMU", qemu)?;
    validate_readable_file_artifact("plugin", plugin)?;
    let qemu_marker = read_qemu_build_marker(qemu)?;
    let plugin_marker = read_plugin_build_marker(plugin)?;
    let required_plugin_abi = required_qemu_plugin_abi();
    if plugin_marker.plugin_abi != required_plugin_abi {
        return Err(qemu_backend_config_error(format!(
            "plugin `{}` advertises ABI `{}` but this CLI requires `{}`; {}",
            plugin.display(),
            plugin_marker.plugin_abi,
            required_plugin_abi,
            qemu_discovery_order_help()
        )));
    }
    if plugin_marker.qemu_build_id != qemu_marker.raw_build_id {
        return Err(qemu_backend_config_error(format!(
            "plugin `{}` was built for QEMU identity `{}` but patched QEMU `{}` advertises `{}`; {}",
            plugin.display(),
            plugin_marker.qemu_build_id,
            qemu.display(),
            qemu_marker.raw_build_id,
            qemu_discovery_order_help()
        )));
    }
    Ok(QemuArtifactIdentity {
        qemu_build_id: qemu_marker.artifact_build_id,
        plugin_abi: plugin_marker.plugin_abi,
    })
}

fn validate_readable_file_artifact(label: &'static str, path: &Path) -> Result<(), CliError> {
    if !path.is_file() {
        return Err(qemu_backend_config_error(format!(
            "--backend qemu cannot read {label} artifact `{}`: not a regular file; {}",
            path.display(),
            qemu_discovery_order_help()
        )));
    }
    fs::File::open(path).map_err(|error| {
        qemu_backend_config_error(format!(
            "--backend qemu cannot read {label} artifact `{}`: {error}; {}",
            path.display(),
            qemu_discovery_order_help()
        ))
    })?;
    Ok(())
}

fn qemu_backend_config_error(reason: impl Into<String>) -> CliError {
    CliError::Backend(reason.into())
}

fn required_qemu_plugin_abi() -> String {
    format!(
        "{CRUCIBLE_QEMU_PLUGIN_ABI_PREFIX}{}",
        crucible_shmem::ABI_VERSION
    )
}

fn qemu_discovery_order_help() -> String {
    format!(
        "discovery order is --qemu/--plugin, {CRUCIBLE_QEMU_ENV}/{CRUCIBLE_PLUGIN_ENV}, then AOS package-set hints {CRUCIBLE_AOS_QEMU_ENV}/{CRUCIBLE_AOS_PLUGIN_ENV}; host $PATH QEMU is never used; supply a matched qemu-crucible/crucible-qemu-plugin pair or use --backend double"
    )
}

fn read_qemu_build_marker(qemu: &Path) -> Result<QemuBuildMarker, CliError> {
    let marker = existing_metadata_path(qemu_build_marker_paths(qemu)).ok_or_else(|| {
        qemu_backend_config_error(format!(
            "patched QEMU `{}` is missing its sim-capability marker `share/aos/crucible/qemu-build-identity.env`; {}",
            qemu.display(),
            qemu_discovery_order_help()
        ))
    })?;
    let fields = read_key_value_metadata(&marker)?;
    let patches_applied =
        required_metadata_field(&fields, "qemu_crucible_patches_applied", &marker)?;
    if patches_applied != "true" {
        return Err(qemu_backend_config_error(format!(
            "QEMU `{}` is not the patched Crucible build (qemu_crucible_patches_applied={patches_applied}); {}",
            qemu.display(),
            qemu_discovery_order_help()
        )));
    }
    let plugins_enabled = required_metadata_field(&fields, "qemu_plugins_enabled", &marker)?;
    if plugins_enabled != "true" {
        return Err(qemu_backend_config_error(format!(
            "QEMU `{}` was built without plugin support (qemu_plugins_enabled={plugins_enabled}); {}",
            qemu.display(),
            qemu_discovery_order_help()
        )));
    }
    let raw_build_id = required_metadata_field(&fields, "qemu_build_id", &marker)?;
    if raw_build_id.is_empty() {
        return Err(qemu_backend_config_error(format!(
            "QEMU marker `{}` has an empty qemu_build_id; {}",
            marker.display(),
            qemu_discovery_order_help()
        )));
    }
    let artifact_build_id = if is_content_address(&raw_build_id) {
        raw_build_id.clone()
    } else {
        content_address_bytes(raw_build_id.as_bytes())
    };
    Ok(QemuBuildMarker {
        raw_build_id,
        artifact_build_id,
    })
}

fn read_plugin_build_marker(plugin: &Path) -> Result<PluginBuildMarker, CliError> {
    let marker = existing_metadata_path(plugin_build_marker_paths(plugin)).ok_or_else(|| {
        qemu_backend_config_error(format!(
            "plugin `{}` is missing `nix-support/crucible-qemu-plugin-build-info`; {}",
            plugin.display(),
            qemu_discovery_order_help()
        ))
    })?;
    let fields = read_key_value_metadata(&marker)?;
    let plugin_abi = required_metadata_field(&fields, "plugin_abi", &marker)?;
    let qemu_build_id = required_metadata_field(&fields, "qemu_build_id", &marker)?;
    if plugin_abi.is_empty() || qemu_build_id.is_empty() {
        return Err(qemu_backend_config_error(format!(
            "plugin marker `{}` must contain non-empty plugin_abi and qemu_build_id; {}",
            marker.display(),
            qemu_discovery_order_help()
        )));
    }
    Ok(PluginBuildMarker {
        plugin_abi,
        qemu_build_id,
    })
}

fn qemu_build_marker_paths(qemu: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(parent) = qemu.parent() {
        if parent.file_name().and_then(|name| name.to_str()) == Some("bin") {
            if let Some(root) = parent.parent() {
                paths.push(root.join("share/aos/crucible/qemu-build-identity.env"));
            }
        }
        paths.push(parent.join("qemu-build-identity.env"));
    }
    paths
}

fn plugin_build_marker_paths(plugin: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(parent) = plugin.parent() {
        if parent.file_name().and_then(|name| name.to_str()) == Some("lib") {
            if let Some(root) = parent.parent() {
                paths.push(root.join("nix-support/crucible-qemu-plugin-build-info"));
            }
        }
        paths.push(parent.join("crucible-qemu-plugin-build-info"));
    }
    paths
}

fn existing_metadata_path(paths: Vec<PathBuf>) -> Option<PathBuf> {
    paths.into_iter().find(|path| path.is_file())
}

fn read_key_value_metadata(path: &Path) -> Result<BTreeMap<String, String>, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        qemu_backend_config_error(format!(
            "cannot read metadata marker `{}`: {error}",
            path.display()
        ))
    })?;
    let mut fields = BTreeMap::new();
    for (line_index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(qemu_backend_config_error(format!(
                "metadata marker `{}` line {} is not key=value",
                path.display(),
                line_index + 1
            )));
        };
        fields.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(fields)
}

fn required_metadata_field(
    fields: &BTreeMap<String, String>,
    key: &'static str,
    marker: &Path,
) -> Result<String, CliError> {
    fields.get(key).cloned().ok_or_else(|| {
        qemu_backend_config_error(format!(
            "metadata marker `{}` is missing `{key}`; {}",
            marker.display(),
            qemu_discovery_order_help()
        ))
    })
}

fn subcommand_uses_backend_selection(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Run(_)
            | Commands::Verify(_)
            | Commands::Save(_)
            | Commands::Resume(_)
            | Commands::Fork(_)
            | Commands::Replay(_)
            | Commands::Search(_)
            | Commands::Fuzz(_)
            | Commands::Serve(_)
    )
}

fn execute_backend_selection_plan(
    plan: &BackendSelectionPlan,
    quiet: bool,
    recorder: &mut impl BackendRouteRecorder,
) -> Result<(), CliError> {
    if !plan.proves_t_cli_3() {
        return Err(CliError::Backend(
            "CLI backend selection violates the RFC-0010 local/remote split".to_string(),
        ));
    }
    if !plan.proves_t_cli_5() {
        return Err(CliError::Backend(
            "CLI QEMU discovery violates the RFC-0010 hermetic discovery contract".to_string(),
        ));
    }

    match (&plan.target, &plan.resolved_backend, &plan.daemon) {
        (BackendExecutionTarget::RemoteDaemon, None, Some(daemon)) => {
            recorder.record_remote_daemon(daemon);
        }
        (BackendExecutionTarget::Local, Some(backend), None) => {
            recorder.record_local_backend(backend);
        }
        _ => {
            return Err(CliError::Backend(
                "CLI backend selection is internally inconsistent".to_string(),
            ));
        }
    }
    if plan.should_announce(quiet) {
        recorder.record_backend_announcement(&plan.announcement());
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendCommandOutcome {
    subcommand: CliSubcommand,
    status: BackendCommandStatus,
    exit_code: i32,
    stdout: Vec<String>,
    stderr: Vec<String>,
    canonical_log: Vec<CanonicalLogEntry>,
    canonical_log_digest: String,
    artifact_digest: String,
    reproduction_artifact: Option<Vec<u8>>,
    side_reproduction_artifacts: Vec<(String, Vec<u8>)>,
}

impl BackendCommandOutcome {
    #[cfg(test)]
    fn normalized(&self) -> BackendCommandOutcomeProjection {
        BackendCommandOutcomeProjection {
            subcommand: self.subcommand,
            status: self.status,
            exit_code: self.exit_code,
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            canonical_log_digest: self.canonical_log_digest.clone(),
            artifact_digest: self.artifact_digest.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BackendCommandStatus {
    Passed,
    Failed,
    Crashed,
    Timeout,
}

impl BackendCommandStatus {
    fn exit_code(self) -> i32 {
        CliError::Outcome(self).exit_code()
    }

    fn non_passing_variants() -> [Self; 3] {
        [Self::Failed, Self::Crashed, Self::Timeout]
    }

    fn is_non_passing(self) -> bool {
        !matches!(self, Self::Passed)
    }

    fn failure_slug(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Crashed => "crashed",
            Self::Timeout => "timeout",
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendCommandOutcomeProjection {
    subcommand: CliSubcommand,
    status: BackendCommandStatus,
    exit_code: i32,
    stdout: Vec<String>,
    stderr: Vec<String>,
    canonical_log_digest: String,
    artifact_digest: String,
}

trait BackendCommandRunner {
    fn run_local(
        &mut self,
        backend: &ResolvedLocalBackend,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        run_plan: Option<&RunInvocationPlan>,
        verify_plan: Option<&VerifyInvocationPlan>,
    ) -> Result<BackendCommandOutcome, CliError>;

    fn run_remote(
        &mut self,
        daemon: &str,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        run_plan: Option<&RunInvocationPlan>,
        verify_plan: Option<&VerifyInvocationPlan>,
    ) -> Result<BackendCommandOutcome, CliError>;
}

#[derive(Default)]
struct NullBackendCommandRunner;

impl BackendCommandRunner for NullBackendCommandRunner {
    fn run_local(
        &mut self,
        backend: &ResolvedLocalBackend,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        run_plan: Option<&RunInvocationPlan>,
        verify_plan: Option<&VerifyInvocationPlan>,
    ) -> Result<BackendCommandOutcome, CliError> {
        if let Some(verify_plan) = verify_plan {
            return match (&verify_plan.mode, backend) {
                (VerifyMode::CompareArtifacts { .. }, _) => {
                    let report = verify_compare_artifacts(verify_plan, Some(backend))?;
                    finish_verify_workflow_outcome(
                        thin_plan,
                        backend_plan,
                        ergonomics_plan,
                        verify_plan,
                        report,
                    )
                }
                (VerifyMode::RunScenario { .. }, ResolvedLocalBackend::Double) => {
                    run_local_double_verify_workflow(
                        thin_plan,
                        backend_plan,
                        ergonomics_plan,
                        verify_plan,
                    )
                }
                (VerifyMode::RunScenario { .. }, ResolvedLocalBackend::Qemu { .. }) => {
                    Err(backend_error(
                        "verify with local QEMU requires an RFC-0010 execution-fingerprint runner; shared-memory quantum fingerprints are not sufficient",
                    ))
                }
            };
        }
        if matches!(backend, ResolvedLocalBackend::Double) {
            if let Some(run_plan) = run_plan {
                return run_local_double_workflow(
                    thin_plan,
                    backend_plan,
                    ergonomics_plan,
                    run_plan,
                );
            }
        }
        Ok(backend_command_outcome(
            thin_plan,
            backend_plan,
            ergonomics_plan,
        ))
    }

    fn run_remote(
        &mut self,
        daemon: &str,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        run_plan: Option<&RunInvocationPlan>,
        verify_plan: Option<&VerifyInvocationPlan>,
    ) -> Result<BackendCommandOutcome, CliError> {
        if let Some(run_plan) = run_plan {
            return run_remote_workflow(daemon, thin_plan, backend_plan, ergonomics_plan, run_plan);
        }
        if let Some(verify_plan) = verify_plan {
            return run_remote_verify_workflow(
                daemon,
                thin_plan,
                backend_plan,
                ergonomics_plan,
                verify_plan,
            );
        }
        Ok(backend_command_outcome(
            thin_plan,
            backend_plan,
            ergonomics_plan,
        ))
    }
}

fn execute_backend_routed_command(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: Option<&RunInvocationPlan>,
    verify_plan: Option<&VerifyInvocationPlan>,
    runner: &mut impl BackendCommandRunner,
) -> Result<BackendCommandOutcome, CliError> {
    if !thin_plan.proves_t_cli_2() || !backend_plan.proves_t_cli_3() {
        return Err(CliError::Backend(
            "CLI command route violates the RFC-0010 backend split".to_string(),
        ));
    }
    if thin_plan.subcommand != backend_plan.subcommand {
        return Err(CliError::Backend(
            "CLI backend route does not match the command dispatch plan".to_string(),
        ));
    }

    match (
        &backend_plan.target,
        &backend_plan.resolved_backend,
        &backend_plan.daemon,
    ) {
        (BackendExecutionTarget::Local, Some(backend), None) => runner.run_local(
            backend,
            thin_plan,
            backend_plan,
            ergonomics_plan,
            run_plan,
            verify_plan,
        ),
        (BackendExecutionTarget::RemoteDaemon, None, Some(daemon)) => runner.run_remote(
            daemon,
            thin_plan,
            backend_plan,
            ergonomics_plan,
            run_plan,
            verify_plan,
        ),
        _ => Err(CliError::Backend(
            "CLI backend route is internally inconsistent".to_string(),
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunWorkflowReport {
    status: BackendCommandStatus,
    created_state: String,
    final_state: String,
    outcome: Option<OutcomeKind>,
    terminal_savepoint: Option<crucible::ContentHash>,
    final_frontier_ticks: u64,
    final_quanta: u64,
    budget_timed_out: bool,
    state_updates: Vec<String>,
    streamed_events: Vec<String>,
    streamed_event_frames: Vec<Vec<u8>>,
    execution_fingerprints: Vec<crucible::FingerprintSample>,
    acknowledged_commands: Vec<SessionCommandKind>,
    watch_statuses: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifyWorkflowReport {
    witnesses: Vec<VerifyRunWitness>,
    divergence: Option<VerifyDivergenceReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifyRunWitness {
    reduction: VerifyReductionPlan,
    canonical_log: Vec<CanonicalLogEntry>,
    canonical_log_bytes: Vec<u8>,
    fingerprint_samples: Vec<VerifyFingerprintSample>,
    fingerprint_stream: Vec<u8>,
    state_dump: String,
    artifact: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifyFingerprintSample {
    index: u64,
    instruction: u64,
    node: String,
    digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifyDivergenceReport {
    left: usize,
    right: usize,
    mismatch: VerifyMismatchKind,
    first_different_decision: Option<usize>,
    first_different_fingerprint_sample: Option<usize>,
    first_different_instruction: u64,
    node: Option<String>,
    first_different_byte: usize,
    left_state_digest: String,
    right_state_digest: String,
    left_state_dump: String,
    right_state_dump: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerifyMismatchKind {
    CanonicalLog,
    FingerprintStream,
    CanonicalLogAndFingerprintStream,
}

impl VerifyMismatchKind {
    fn label(self) -> &'static str {
        match self {
            Self::CanonicalLog => "canonical-log",
            Self::FingerprintStream => "fingerprint-stream",
            Self::CanonicalLogAndFingerprintStream => "canonical-log+fingerprint-stream",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunObservation {
    final_state: String,
    outcome: Option<OutcomeKind>,
    terminal_savepoint: Option<crucible::ContentHash>,
    frontier_ticks: u64,
    quanta: u64,
    budget_timed_out: bool,
    watch_statuses: Vec<String>,
}

fn run_local_double_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = if matches!(run_plan.execution_mode, RunExecutionMode::Interactive) {
        runtime.block_on(run_local_double_workflow_stdin_async(
            run_plan,
            ergonomics_plan,
        ))?
    } else {
        runtime.block_on(run_local_double_workflow_async(
            run_plan,
            ergonomics_plan,
            &[],
        ))?
    };
    finish_run_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, run_plan, report)
}

fn run_local_double_verify_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = LifecycleControlPlane::new(
        "crucible-cli-double",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    );
    let client = InProcessLifecycleClient::new(control_plane);
    let report = runtime.block_on(run_control_client_verify_workflow_async(
        &client,
        verify_plan,
        backend_plan.resolved_backend.as_ref(),
        ergonomics_plan,
    ))?;
    finish_verify_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        verify_plan,
        report,
    )
}

fn run_remote_workflow(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = RpcControlClient::new(RpcEndpoint::http2(daemon_rpc_endpoint(daemon)))
        .map_err(control_client_error)?;
    let report = if matches!(run_plan.execution_mode, RunExecutionMode::Interactive) {
        runtime.block_on(run_control_client_workflow_stdin_async(&client, run_plan))?
    } else {
        runtime.block_on(run_control_client_workflow_async(&client, run_plan, &[]))?
    };
    finish_run_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, run_plan, report)
}

fn run_remote_verify_workflow(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = match &verify_plan.mode {
        VerifyMode::RunScenario { .. } => {
            let client = RpcControlClient::new(RpcEndpoint::http2(daemon_rpc_endpoint(daemon)))
                .map_err(control_client_error)?;
            runtime.block_on(run_control_client_verify_workflow_async(
                &client,
                verify_plan,
                backend_plan.resolved_backend.as_ref(),
                ergonomics_plan,
            ))?
        }
        VerifyMode::CompareArtifacts { .. } => {
            verify_compare_artifacts(verify_plan, backend_plan.resolved_backend.as_ref())?
        }
    };
    finish_verify_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        verify_plan,
        report,
    )
}

fn daemon_rpc_endpoint(daemon: &str) -> String {
    if daemon.contains("://") {
        daemon.to_string()
    } else {
        format!("http://{daemon}")
    }
}

fn finish_run_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
    report: RunWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    outcome.status = report.status;
    outcome.exit_code = report.status.exit_code();
    if outcome.status.is_non_passing() {
        let artifact_seed = ergonomics_plan.map(|plan| plan.seed.value).unwrap_or(0);
        let artifact = mock_failure_reproduction_artifact_bytes_for_backend(
            artifact_seed,
            backend_plan.resolved_backend.as_ref(),
        )?;
        outcome.artifact_digest = content_address_bytes(&artifact);
        outcome.reproduction_artifact = Some(artifact);
    }
    outcome.stdout.push(format!(
        "run-session\tcreated={}\tfinal={}\toutcome={}\tsavepoint={}\tfrontier_ticks={}\tquanta={}\tevents={}\tacks={}",
        report.created_state,
        report.final_state,
        terminal_outcome_label(report.outcome),
        report
            .terminal_savepoint
            .map(format_content_hash_ref)
            .unwrap_or_else(|| String::from("none")),
        report.final_frontier_ticks,
        report.final_quanta,
        report.streamed_events.len(),
        report.acknowledged_commands.len()
    ));
    for status in &report.watch_statuses {
        outcome.stdout.push(format!("run-watch\t{status}"));
    }
    append_local_double_run_entries(&mut outcome, run_plan, &report);
    if let Some(savepoint) = run_terminal_savepoint_for_policy(run_plan, &report)? {
        let savepoint = format_content_hash_ref(savepoint);
        outcome.stdout.push(format!(
            "run-savepoint\tpolicy={}\tcheckpoint={}\tfinal={}\toutcome={}",
            run_save_policy_label(run_plan.save_policy),
            savepoint,
            report.final_state,
            terminal_outcome_label(report.outcome)
        ));
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("session"),
            kind: String::from("run_savepoint"),
            summary: format!(
                "policy={} checkpoint={} outcome={}",
                run_save_policy_label(run_plan.save_policy),
                savepoint,
                terminal_outcome_label(report.outcome)
            ),
        });
        outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    }
    Ok(outcome)
}

fn finish_verify_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
    report: VerifyWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    outcome.stdout.push(format!(
        "verify-plan\tmode={}\truns={}\treductions={}\tadversarial={}\tbisect={}",
        verify_plan.mode.label(),
        verify_plan.requested_runs,
        report.witnesses.len(),
        verify_plan.applies_hostile_condition_matrix,
        verify_plan.bisection_on_divergence
    ));
    for witness in &report.witnesses {
        let canonical_log_digest = content_address_bytes(&witness.canonical_log_bytes);
        let fingerprint_digest = content_address_bytes(&witness.fingerprint_stream);
        outcome.stdout.push(format!(
            "verify-run\tindex={}\trun={}\tprofile={}\tcanonical_log={}\tfingerprint={}\tsamples={}",
            witness.reduction.index,
            witness.reduction.run_index,
            witness.reduction.host_profile.label(),
            canonical_log_digest,
            fingerprint_digest,
            witness.fingerprint_samples.len()
        ));
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("verify"),
            kind: String::from("independent_reduction"),
            summary: format!(
                "index={} run={} profile={} canonical_log={} fingerprint={} samples={}",
                witness.reduction.index,
                witness.reduction.run_index,
                witness.reduction.host_profile.label(),
                canonical_log_digest,
                fingerprint_digest,
                witness.fingerprint_samples.len()
            ),
        });
    }
    if let Some(divergence) = report.divergence {
        outcome.status = BackendCommandStatus::Failed;
        outcome.exit_code = outcome.status.exit_code();
        outcome.stdout.push(format!(
            "verify-divergence\tleft={}\tright={}\tmismatch={}\tfirst_decision={}\tfirst_fingerprint_sample={}\tfirst_instruction={}\tnode={}\tbyte={}",
            divergence.left,
            divergence.right,
            divergence.mismatch.label(),
            divergence
                .first_different_decision
                .map(|decision| decision.to_string())
                .unwrap_or_else(|| String::from("unknown")),
            divergence
                .first_different_fingerprint_sample
                .map(|sample| sample.to_string())
                .unwrap_or_else(|| String::from("unknown")),
            divergence.first_different_instruction,
            divergence.node.as_deref().unwrap_or("unknown"),
            divergence.first_different_byte
        ));
        if verify_plan.print_bisection_state_dump {
            outcome.stdout.push(format!(
                "verify-bisect-state\tleft_state={}\tright_state={}\tleft_dump={}\tright_dump={}",
                divergence.left_state_digest,
                divergence.right_state_digest,
                divergence.left_state_dump,
                divergence.right_state_dump
            ));
        }
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: divergence
                .node
                .clone()
                .unwrap_or_else(|| String::from("verify")),
            kind: String::from("verify_divergence_bisection"),
            summary: format!(
                "left={} right={} mismatch={} first_instruction={} byte={}",
                divergence.left,
                divergence.right,
                divergence.mismatch.label(),
                divergence.first_different_instruction,
                divergence.first_different_byte
            ),
        });
        let left = report
            .witnesses
            .get(divergence.left)
            .ok_or_else(|| backend_error("verify divergence left side is out of range"))?;
        let right = report
            .witnesses
            .get(divergence.right)
            .ok_or_else(|| backend_error("verify divergence right side is out of range"))?;
        outcome.side_reproduction_artifacts = vec![
            (String::from("left"), left.artifact.clone()),
            (String::from("right"), right.artifact.clone()),
        ];
        let mut artifact_material = Vec::new();
        artifact_material.extend_from_slice(&left.artifact);
        artifact_material.extend_from_slice(&right.artifact);
        outcome.artifact_digest = content_address_bytes(&artifact_material);
    } else {
        outcome.stdout.push(format!(
            "verify-result\tstatus=passed\treductions={}\tcanonical_log={}\tfingerprint={}",
            report.witnesses.len(),
            report
                .witnesses
                .first()
                .map(|witness| content_address_bytes(&witness.canonical_log_bytes))
                .unwrap_or_else(|| content_address_bytes(b"verify-empty-log")),
            report
                .witnesses
                .first()
                .map(|witness| content_address_bytes(&witness.fingerprint_stream))
                .unwrap_or_else(|| content_address_bytes(b"verify-empty-fingerprint"))
        ));
    }
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    Ok(outcome)
}

async fn run_control_client_verify_workflow_async<C>(
    client: &C,
    verify_plan: &VerifyInvocationPlan,
    backend: Option<&ResolvedLocalBackend>,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Result<VerifyWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    let Some(scenario) = verify_plan.scenario() else {
        return Err(backend_error(
            "verify compare mode must not enter the live control-client workflow",
        ));
    };
    let mut witnesses = Vec::with_capacity(verify_plan.reductions.len());
    let request_seed = ergonomics_plan
        .map(|plan| crucible::Seed::from_u64(plan.seed.value))
        .unwrap_or_else(|| scenario.scenario_def().seed());
    let seeded_scenario = reseed_run_scenario_ref(scenario, request_seed)?;
    for reduction in &verify_plan.reductions {
        let run_plan =
            verify_run_invocation_plan(seeded_scenario.clone(), request_seed, reduction.clone());
        let report = run_control_client_workflow_async(client, &run_plan, &[]).await?;
        if report.status.is_non_passing() {
            return Err(CliError::Outcome(report.status));
        }
        witnesses.push(verify_witness_from_run_report(
            reduction.clone(),
            &run_plan,
            &report,
            backend,
            ergonomics_plan,
        )?);
    }
    let divergence = compare_verify_witnesses(&witnesses);
    Ok(VerifyWorkflowReport {
        witnesses,
        divergence,
    })
}

fn verify_compare_artifacts(
    verify_plan: &VerifyInvocationPlan,
    backend: Option<&ResolvedLocalBackend>,
) -> Result<VerifyWorkflowReport, CliError> {
    let VerifyMode::CompareArtifacts { left, right } = &verify_plan.mode else {
        return Err(backend_error(
            "verify run mode must use the live control-client workflow",
        ));
    };
    let left_bytes = fs::read(left)?;
    let right_bytes = fs::read(right)?;
    let left_artifact = decode_reproduction_artifact(&left_bytes)?;
    let right_artifact = decode_reproduction_artifact(&right_bytes)?;
    let expected_identity = expected_replay_identity_for_backend(backend);
    verify_replay_identity(&left_artifact.identity, &expected_identity)?;
    verify_replay_identity(&right_artifact.identity, &expected_identity)?;
    verify_compare_artifact_inputs_match(&left_artifact, &right_artifact)?;
    let witnesses = vec![
        verify_witness_from_artifact(verify_plan.reductions[0].clone(), left_artifact, left_bytes)?,
        verify_witness_from_artifact(
            verify_plan.reductions[1].clone(),
            right_artifact,
            right_bytes,
        )?,
    ];
    let divergence = compare_verify_witnesses(&witnesses);
    Ok(VerifyWorkflowReport {
        witnesses,
        divergence,
    })
}

fn verify_compare_artifact_inputs_match(
    left: &CliReproductionArtifact,
    right: &CliReproductionArtifact,
) -> Result<(), CliError> {
    if left.seed != right.seed {
        return Err(artifact_error(format!(
            "verify --compare requires matching seeds, got left={} right={}",
            left.seed, right.seed
        )));
    }
    if left.scenario.digest != right.scenario.digest {
        return Err(artifact_error(format!(
            "verify --compare requires matching scenario digests, got left={} right={}",
            left.scenario.digest, right.scenario.digest
        )));
    }
    if left.scenario.media_type != right.scenario.media_type {
        return Err(artifact_error(format!(
            "verify --compare requires matching scenario media types, got left={} right={}",
            left.scenario.media_type, right.scenario.media_type
        )));
    }
    Ok(())
}

fn verify_run_invocation_plan(
    scenario: RunScenarioRef,
    request_seed: crucible::Seed,
    reduction: VerifyReductionPlan,
) -> RunInvocationPlan {
    RunInvocationPlan {
        scenario,
        request_seed: Some(request_seed),
        terminal_condition: RunTerminalCondition::Quiescence,
        max_virtual_time: None,
        max_virtual_time_ticks: None,
        max_quanta: None,
        execution_mode: RunExecutionMode::ToCompletion,
        save_policy: RunSavePolicy::Never,
        watch_streams_live_status: false,
        startup_commands: vec![
            SessionCommandKind::Start,
            SessionCommandKind::StepQuantum,
            SessionCommandKind::Continue,
        ],
        initial_control_commands: vec![SessionCommandKind::Query, SessionCommandKind::Query],
        accepted_interactive_commands: Vec::new(),
        observer_profile: reduction.host_profile,
        collect_execution_fingerprints: true,
        bounded_ack_quanta: RUN_INTERACTIVE_ACK_QUANTA_BOUND,
        outcome_exit_codes: vec![
            (
                BackendCommandStatus::Passed,
                CliError::Outcome(BackendCommandStatus::Passed).exit_code(),
            ),
            (
                BackendCommandStatus::Failed,
                CliError::Outcome(BackendCommandStatus::Failed).exit_code(),
            ),
            (
                BackendCommandStatus::Timeout,
                CliError::Outcome(BackendCommandStatus::Timeout).exit_code(),
            ),
            (
                BackendCommandStatus::Crashed,
                CliError::Outcome(BackendCommandStatus::Crashed).exit_code(),
            ),
        ],
        invalid_scenario_exit_code: CliError::InvalidScenario(String::new()).exit_code(),
    }
}

fn verify_witness_from_run_report(
    reduction: VerifyReductionPlan,
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
    backend: Option<&ResolvedLocalBackend>,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Result<VerifyRunWitness, CliError> {
    let canonical_log = canonical_run_log_entries(run_plan, report);
    let canonical_log_bytes =
        canonical_verify_log_stream_bytes(&canonical_log, &report.streamed_event_frames);
    let fingerprint_samples = verify_fingerprint_samples(report)?;
    let fingerprint_stream = verify_fingerprint_stream_bytes(&fingerprint_samples);
    let request_seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    let seed = ergonomics_plan
        .map(|plan| plan.seed.value)
        .unwrap_or_else(|| seed_to_u64(request_seed));
    let state_dump = verify_state_dump(run_plan, report);
    let artifact = verify_reproduction_artifact_bytes(
        seed,
        backend,
        run_plan.scenario.scenario_def(),
        &canonical_log,
        &fingerprint_samples,
    )?;
    Ok(VerifyRunWitness {
        reduction,
        canonical_log,
        canonical_log_bytes,
        fingerprint_samples,
        fingerprint_stream,
        state_dump,
        artifact,
    })
}

fn verify_witness_from_artifact(
    reduction: VerifyReductionPlan,
    artifact: CliReproductionArtifact,
    bytes: Vec<u8>,
) -> Result<VerifyRunWitness, CliError> {
    let canonical_log = canonical_log_entries_from_artifact(&artifact)?;
    let canonical_log_bytes = canonical_log_entry_bytes(&canonical_log);
    let fingerprint_samples = artifact_fingerprint_samples(&artifact);
    let fingerprint_stream = verify_fingerprint_stream_bytes(&fingerprint_samples);
    let state_dump = artifact_state_dump(&artifact);
    Ok(VerifyRunWitness {
        reduction,
        canonical_log,
        canonical_log_bytes,
        fingerprint_samples,
        fingerprint_stream,
        state_dump,
        artifact: bytes,
    })
}

fn canonical_run_log_entries(
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
) -> Vec<CanonicalLogEntry> {
    let mut outcome = BackendCommandOutcome {
        subcommand: CliSubcommand::Run,
        status: BackendCommandStatus::Passed,
        exit_code: 0,
        stdout: Vec::new(),
        stderr: Vec::new(),
        canonical_log: Vec::new(),
        canonical_log_digest: content_address_bytes(b"empty"),
        artifact_digest: content_address_bytes(b"empty"),
        reproduction_artifact: None,
        side_reproduction_artifacts: Vec::new(),
    };
    append_local_double_run_entries(&mut outcome, run_plan, report);
    outcome.canonical_log
}

fn canonical_log_entry_bytes(entries: &[CanonicalLogEntry]) -> Vec<u8> {
    jsonl_for_canonical_log_entries(entries).into_bytes()
}

fn canonical_verify_log_stream_bytes(
    entries: &[CanonicalLogEntry],
    event_frames: &[Vec<u8>],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"crucible.verify.canonical-log-stream.v1\n");
    bytes.extend_from_slice(&canonical_log_entry_bytes(entries));
    bytes.extend_from_slice(b"\ncrucible.verify.api-event-frames.v1\n");
    for frame in event_frames {
        bytes.extend_from_slice(frame);
        if !frame.ends_with(b"\n") {
            bytes.push(b'\n');
        }
    }
    bytes
}

fn canonical_streaming_event_frame_bytes(frame: &crucible_api::StreamingEventFrame) -> Vec<u8> {
    let mut output = String::from("crucible.rpc/event-frame\n");
    push_canonical_wire_line(&mut output, "generation", &frame.generation.to_string());
    push_canonical_wire_line(
        &mut output,
        "cursor",
        &frame.cursor.next_sequence.to_string(),
    );
    push_canonical_wire_line(
        &mut output,
        "next-cursor",
        &frame.next_cursor.next_sequence.to_string(),
    );
    push_canonical_wire_line(&mut output, "sequence", &frame.event.sequence.to_string());
    push_canonical_wire_line(
        &mut output,
        "virtual-time-ticks",
        &frame.event.at.virtual_time_ticks.to_string(),
    );
    push_canonical_wire_line(
        &mut output,
        "icount-retired",
        &frame.event.at.icount_retired.to_string(),
    );
    push_canonical_wire_line(
        &mut output,
        "icount-node",
        &optional_string_canonical_wire(frame.event.at.icount_node.as_deref()),
    );
    push_canonical_wire_line(
        &mut output,
        "source",
        &event_source_canonical_wire(&frame.event.source),
    );
    push_canonical_wire_line(
        &mut output,
        "level",
        event_level_canonical_wire(frame.event.level),
    );
    push_canonical_wire_line(
        &mut output,
        "observational",
        if frame.event.observational {
            "true"
        } else {
            "false"
        },
    );
    push_canonical_wire_line(&mut output, "kind", &frame.event.payload.kind);
    for (name, value) in &frame.event.payload.attributes {
        push_canonical_wire_line(
            &mut output,
            "attribute",
            &format!(
                "{}|{}",
                hex_bytes(name.as_bytes()),
                attribute_canonical_wire(value)
            ),
        );
    }
    output.into_bytes()
}

fn optional_string_canonical_wire(value: Option<&str>) -> String {
    value
        .map(|value| hex_bytes(value.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

fn event_source_canonical_wire(source: &crucible_api::OpenSetEventSource) -> String {
    match source {
        crucible_api::OpenSetEventSource::Scenario { event } => {
            format!("scenario|{}", hex_bytes(event.as_bytes()))
        }
        crucible_api::OpenSetEventSource::Engine => String::from("engine"),
        crucible_api::OpenSetEventSource::Node { node } => {
            format!("node|{}", hex_bytes(node.as_bytes()))
        }
        crucible_api::OpenSetEventSource::Guest { node } => {
            format!("guest|{}", hex_bytes(node.as_bytes()))
        }
        crucible_api::OpenSetEventSource::Command { command_id } => {
            format!("command|{command_id}")
        }
    }
}

fn event_level_canonical_wire(level: crucible::EventLevel) -> &'static str {
    match level {
        crucible::EventLevel::Trace => "trace",
        crucible::EventLevel::Debug => "debug",
        crucible::EventLevel::Info => "info",
        crucible::EventLevel::Warn => "warn",
        crucible::EventLevel::Error => "error",
    }
}

fn attribute_canonical_wire(value: &crucible_api::OpenSetAttributeValue) -> String {
    match value {
        crucible_api::OpenSetAttributeValue::Bool(value) => {
            format!("bool|{}", if *value { "true" } else { "false" })
        }
        crucible_api::OpenSetAttributeValue::Int(value) => format!("int|{value}"),
        crucible_api::OpenSetAttributeValue::Uint(value) => format!("uint|{value}"),
        crucible_api::OpenSetAttributeValue::Uint128(value) => format!("uint128|{value}"),
        crucible_api::OpenSetAttributeValue::Float64Bits(value) => {
            format!("float64bits|{value}")
        }
        crucible_api::OpenSetAttributeValue::String(value) => {
            format!("string|{}", hex_bytes(value.as_bytes()))
        }
        crucible_api::OpenSetAttributeValue::Bytes(value) => format!("bytes|{}", hex_bytes(value)),
    }
}

fn push_canonical_wire_line(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push('=');
    output.push_str(value);
    output.push('\n');
}

fn verify_fingerprint_samples(
    report: &RunWorkflowReport,
) -> Result<Vec<VerifyFingerprintSample>, CliError> {
    if report.execution_fingerprints.is_empty() {
        return Err(backend_error(
            "verify did not collect any backend execution fingerprint samples",
        ));
    }
    let mut samples = Vec::new();
    for (index, sample) in report.execution_fingerprints.iter().enumerate() {
        let index = u64::try_from(index).unwrap_or(u64::MAX);
        samples.push(VerifyFingerprintSample {
            index,
            instruction: sample.at.ticks,
            node: sample.node.name.clone(),
            digest: format!(
                "{}{}",
                CONTENT_ADDRESS_PREFIX,
                sample.fingerprint.hash.to_hex()
            ),
        });
    }
    Ok(samples)
}

fn verify_fingerprint_stream_bytes(samples: &[VerifyFingerprintSample]) -> Vec<u8> {
    let mut text = String::from("crucible.verify.execution-fingerprint-stream.v1\n");
    for sample in samples {
        artifact_line(
            &mut text,
            &[
                "sample",
                &sample.index.to_string(),
                &sample.instruction.to_string(),
                &sample.node,
                &sample.digest,
            ],
        );
    }
    text.into_bytes()
}

fn verify_state_dump(run_plan: &RunInvocationPlan, report: &RunWorkflowReport) -> String {
    let seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    format!(
        "scenario={} seed={} final_state={} outcome={} frontier_ticks={} quanta={} savepoint={} events={} frames={}",
        run_plan.scenario.scenario_id().to_hex(),
        seed.to_hex(),
        report.final_state,
        terminal_outcome_label(report.outcome),
        report.final_frontier_ticks,
        report.final_quanta,
        report
            .terminal_savepoint
            .map(format_content_hash_ref)
            .unwrap_or_else(|| String::from("none")),
        report.streamed_events.len(),
        report.streamed_event_frames.len()
    )
}

fn canonical_log_entries_from_artifact(
    artifact: &CliReproductionArtifact,
) -> Result<Vec<CanonicalLogEntry>, CliError> {
    if artifact.decisions.is_empty() {
        return Err(artifact_error(
            "verify comparison artifact contains no canonical decisions",
        ));
    }
    Ok(artifact
        .decisions
        .iter()
        .map(|decision| CanonicalLogEntry {
            sequence: decision.sequence,
            virtual_time_ticks: decision.virtual_time_ticks,
            node: decision.node.clone(),
            kind: decision.kind.clone(),
            summary: decision.payload_digest.clone(),
        })
        .collect())
}

fn artifact_fingerprint_samples(
    artifact: &CliReproductionArtifact,
) -> Vec<VerifyFingerprintSample> {
    artifact
        .fingerprints
        .iter()
        .map(|fingerprint| VerifyFingerprintSample {
            index: fingerprint.index,
            instruction: fingerprint.index,
            node: String::from("artifact"),
            digest: fingerprint.digest.clone(),
        })
        .collect()
}

fn artifact_state_dump(artifact: &CliReproductionArtifact) -> String {
    format!(
        "scenario={} seed={} decisions={} fingerprints={} schedule={}",
        artifact.scenario.digest,
        artifact.seed,
        artifact.decisions.len(),
        artifact.fingerprints.len(),
        artifact.schedule_digest
    )
}

fn compare_verify_witnesses(witnesses: &[VerifyRunWitness]) -> Option<VerifyDivergenceReport> {
    for left_index in 0..witnesses.len() {
        for right_index in left_index + 1..witnesses.len() {
            let left = &witnesses[left_index];
            let right = &witnesses[right_index];
            let canonical_log_differs = left.canonical_log_bytes != right.canonical_log_bytes;
            let fingerprint_differs = left.fingerprint_stream != right.fingerprint_stream;
            if canonical_log_differs || fingerprint_differs {
                let mismatch = match (canonical_log_differs, fingerprint_differs) {
                    (true, true) => VerifyMismatchKind::CanonicalLogAndFingerprintStream,
                    (true, false) => VerifyMismatchKind::CanonicalLog,
                    (false, true) => VerifyMismatchKind::FingerprintStream,
                    (false, false) => unreachable!("guarded by difference check"),
                };
                return Some(localize_verify_divergence(
                    left_index,
                    right_index,
                    mismatch,
                    left,
                    right,
                ));
            }
        }
    }
    None
}

fn localize_verify_divergence(
    left_index: usize,
    right_index: usize,
    mismatch: VerifyMismatchKind,
    left: &VerifyRunWitness,
    right: &VerifyRunWitness,
) -> VerifyDivergenceReport {
    let first_different_decision =
        first_different_canonical_entry(&left.canonical_log, &right.canonical_log);
    let first_different_sample =
        first_different_fingerprint_sample(&left.fingerprint_samples, &right.fingerprint_samples);
    let entry = first_different_decision.and_then(|index| {
        left.canonical_log
            .get(index)
            .or_else(|| right.canonical_log.get(index))
    });
    let sample = first_different_sample.and_then(|index| {
        left.fingerprint_samples
            .get(index)
            .or_else(|| right.fingerprint_samples.get(index))
    });
    let first_different_byte = bisect_first_different_byte(
        bytes_for_mismatch(mismatch, left),
        bytes_for_mismatch(mismatch, right),
    );
    VerifyDivergenceReport {
        left: left_index,
        right: right_index,
        mismatch,
        first_different_decision,
        first_different_fingerprint_sample: first_different_sample,
        first_different_instruction: entry
            .map(|entry| entry.virtual_time_ticks)
            .or_else(|| sample.map(|sample| sample.instruction))
            .unwrap_or(first_different_byte as u64),
        node: entry
            .map(|entry| entry.node.clone())
            .or_else(|| sample.map(|sample| sample.node.clone())),
        first_different_byte,
        left_state_digest: content_address_bytes(&left.artifact),
        right_state_digest: content_address_bytes(&right.artifact),
        left_state_dump: left.state_dump.clone(),
        right_state_dump: right.state_dump.clone(),
    }
}

fn bytes_for_mismatch(mismatch: VerifyMismatchKind, witness: &VerifyRunWitness) -> &[u8] {
    match mismatch {
        VerifyMismatchKind::CanonicalLog | VerifyMismatchKind::CanonicalLogAndFingerprintStream => {
            &witness.canonical_log_bytes
        }
        VerifyMismatchKind::FingerprintStream => &witness.fingerprint_stream,
    }
}

fn first_different_canonical_entry(
    left: &[CanonicalLogEntry],
    right: &[CanonicalLogEntry],
) -> Option<usize> {
    for (index, (left_entry, right_entry)) in left.iter().zip(right.iter()).enumerate() {
        if json_for_canonical_log_entry(left_entry) != json_for_canonical_log_entry(right_entry) {
            return Some(index);
        }
    }
    (left.len() != right.len()).then_some(left.len().min(right.len()))
}

fn first_different_fingerprint_sample(
    left: &[VerifyFingerprintSample],
    right: &[VerifyFingerprintSample],
) -> Option<usize> {
    for (index, (left_sample, right_sample)) in left.iter().zip(right.iter()).enumerate() {
        if left_sample != right_sample {
            return Some(index);
        }
    }
    (left.len() != right.len()).then_some(left.len().min(right.len()))
}

fn bisect_first_different_byte(left: &[u8], right: &[u8]) -> usize {
    let max_len = left.len().max(right.len());
    if max_len == 0 || left == right {
        return 0;
    }
    let mut low = 0usize;
    let mut high = max_len;
    while low < high {
        let midpoint = low + ((high - low) / 2);
        if prefixes_match(left, right, midpoint.saturating_add(1)) {
            low = midpoint.saturating_add(1);
        } else {
            high = midpoint;
        }
    }
    low
}

fn prefixes_match(left: &[u8], right: &[u8], len: usize) -> bool {
    left.get(..len) == right.get(..len)
}

fn verify_reproduction_artifact_bytes(
    seed: u64,
    backend: Option<&ResolvedLocalBackend>,
    scenario: &crucible::ScenarioDef,
    canonical_log: &[CanonicalLogEntry],
    fingerprint_samples: &[VerifyFingerprintSample],
) -> Result<Vec<u8>, CliError> {
    let scenario_bytes = scenario_identity_bytes(scenario);
    let scenario_digest = content_address_bytes(&scenario_bytes);
    let store_uri = format!("cas:{scenario_digest}");
    let identity = expected_replay_identity_for_backend(backend);
    let decisions = canonical_log
        .iter()
        .map(|entry| CliDecision {
            sequence: entry.sequence,
            virtual_time_ticks: entry.virtual_time_ticks,
            node: entry.node.clone(),
            kind: entry.kind.clone(),
            payload_digest: content_address_bytes(entry.summary.as_bytes()),
        })
        .collect::<Vec<_>>();
    let schedule_digest = schedule_digest(&decisions);
    let mut text = String::new();

    artifact_line(&mut text, &["schema", REPRODUCTION_ARTIFACT_SCHEMA]);
    artifact_line(&mut text, &["seed", &seed.to_string()]);
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
            "verify.scn",
            &scenario_digest,
            &store_uri,
            "application/vnd.crucible.scenario+text",
            &scenario_bytes.len().to_string(),
        ],
    );
    artifact_line(
        &mut text,
        &[
            "component",
            "scenario_def",
            "verify.scn",
            &scenario_digest,
            &store_uri,
            "application/vnd.crucible.scenario+text",
            &scenario_bytes.len().to_string(),
        ],
    );
    artifact_line(
        &mut text,
        &["payload", &scenario_digest, &hex_bytes(&scenario_bytes)],
    );
    artifact_line(
        &mut text,
        &["schedule", &schedule_digest, &decisions.len().to_string()],
    );
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
    for sample in fingerprint_samples {
        artifact_line(
            &mut text,
            &["fingerprint", &sample.index.to_string(), &sample.digest],
        );
    }
    artifact_line(
        &mut text,
        &[
            "sampling",
            "every-fingerprint-sample",
            "final",
            "1",
            "execution-fingerprint-stream",
        ],
    );

    let bytes = text.into_bytes();
    let artifact = decode_reproduction_artifact(&bytes)?;
    verify_replay_identity(&artifact.identity, &identity)?;
    Ok(bytes)
}

fn seed_to_u64(seed: crucible::Seed) -> u64 {
    let bytes = seed.bytes();
    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(low)
}

fn scenario_identity_bytes(scenario: &crucible::ScenarioDef) -> Vec<u8> {
    format!(
        "scenario_id={}\nseed={}\napp_random_draw_cap={}\n",
        scenario.id().to_hex(),
        scenario.seed().to_hex(),
        scenario.app_random_draw_cap()
    )
    .into_bytes()
}

async fn run_local_double_workflow_async(
    run_plan: &RunInvocationPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    interactive_commands: &[SessionCommandKind],
) -> Result<RunWorkflowReport, CliError> {
    let control_plane = LifecycleControlPlane::new(
        "crucible-cli-double",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    );
    let client = InProcessLifecycleClient::new(control_plane);
    run_control_client_workflow_async(&client, run_plan, interactive_commands).await
}

async fn run_local_double_workflow_stdin_async(
    run_plan: &RunInvocationPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Result<RunWorkflowReport, CliError> {
    let control_plane = LifecycleControlPlane::new(
        "crucible-cli-double",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    );
    let client = InProcessLifecycleClient::new(control_plane);
    run_control_client_workflow_stdin_async(&client, run_plan).await
}

fn run_serve_invocation(cli: &Cli, args: &ServeArgs) -> Result<(), CliError> {
    if cli.daemon.is_some() {
        return Err(usage_error(
            "serve hosts the daemon and cannot itself use --daemon",
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(&args.listen).await?;
        let address = listener.local_addr()?;
        if !cli.quiet {
            println!("crucible: serving API daemon at http://{address}");
        }
        let control_plane = LifecycleControlPlane::new(
            "crucible-cli-daemon",
            Vec::new(),
            |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
        );
        serve_lifecycle_http2(listener, control_plane).await?;
        Ok(())
    })
}

async fn run_control_client_workflow_async<C>(
    client: &C,
    run_plan: &RunInvocationPlan,
    interactive_commands: &[SessionCommandKind],
) -> Result<RunWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    run_control_client_workflow_with_interactive_driver(
        client,
        run_plan,
        InteractiveCommandDriver::Preparsed(interactive_commands),
    )
    .await
}

fn run_save_policy_label(policy: RunSavePolicy) -> &'static str {
    match policy {
        RunSavePolicy::OnFail => "fail",
        RunSavePolicy::Always => "always",
        RunSavePolicy::Never => "never",
    }
}

fn run_terminal_savepoint_for_policy(
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
) -> Result<Option<crucible::ContentHash>, CliError> {
    let should_save = match run_plan.save_policy {
        RunSavePolicy::Always => true,
        RunSavePolicy::OnFail => report.status.is_non_passing(),
        RunSavePolicy::Never => false,
    };
    if !should_save {
        return Ok(None);
    }
    report.terminal_savepoint.map(Some).ok_or_else(|| {
        backend_error(format!(
            "run save policy `{}` required an outcome savepoint, but the session did not materialize one",
            run_save_policy_label(run_plan.save_policy)
        ))
    })
}

async fn run_control_client_workflow_stdin_async<C>(
    client: &C,
    run_plan: &RunInvocationPlan,
) -> Result<RunWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    run_control_client_workflow_with_interactive_driver(
        client,
        run_plan,
        InteractiveCommandDriver::Stdin,
    )
    .await
}

enum InteractiveCommandDriver<'a> {
    Preparsed(&'a [SessionCommandKind]),
    Stdin,
}

async fn run_control_client_workflow_with_interactive_driver<C>(
    client: &C,
    run_plan: &RunInvocationPlan,
    interactive_driver: InteractiveCommandDriver<'_>,
) -> Result<RunWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    let seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    let request = CreateSessionRequest::inline(run_plan.scenario.scenario_def().clone(), seed)
        .with_start_paused(true);
    let created = client
        .create_session(request)
        .await
        .map_err(control_client_error)?;
    let mut control = client
        .control_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_client_name("crucible-cli-run"),
        )
        .await
        .map_err(control_client_error)?;

    let mut acknowledged_commands = Vec::new();
    let mut execution_fingerprints = Vec::new();
    let mut command_id = 1;
    acknowledge_stream_command(
        &control,
        &mut command_id,
        SessionCommandKind::Query,
        &mut acknowledged_commands,
    )
    .await?;
    if run_plan.collect_execution_fingerprints {
        query_execution_fingerprint(
            &control,
            &mut command_id,
            run_plan,
            &mut acknowledged_commands,
            &mut execution_fingerprints,
        )
        .await?;
        acknowledge_stream_command(
            &control,
            &mut command_id,
            SessionCommandKind::StepQuantum,
            &mut acknowledged_commands,
        )
        .await?;
        query_execution_fingerprint(
            &control,
            &mut command_id,
            run_plan,
            &mut acknowledged_commands,
            &mut execution_fingerprints,
        )
        .await?;
    }

    match run_plan.execution_mode {
        RunExecutionMode::ToCompletion => {
            acknowledge_stream_command(
                &control,
                &mut command_id,
                SessionCommandKind::Continue,
                &mut acknowledged_commands,
            )
            .await?;
        }
        RunExecutionMode::Interactive => match interactive_driver {
            InteractiveCommandDriver::Preparsed(commands) => {
                for command in commands {
                    acknowledge_stream_command(
                        &control,
                        &mut command_id,
                        *command,
                        &mut acknowledged_commands,
                    )
                    .await?;
                }
            }
            InteractiveCommandDriver::Stdin => {
                drive_interactive_stdin_commands(
                    &control,
                    &mut command_id,
                    &mut acknowledged_commands,
                )
                .await?;
            }
        },
    }

    let mut state_updates = Vec::new();
    let mut streamed_events = Vec::new();
    let mut streamed_event_frames = Vec::new();
    let observation = observe_run_final_state(
        client,
        &mut control,
        run_plan,
        created.session,
        &mut command_id,
        &mut acknowledged_commands,
        &mut state_updates,
        &mut streamed_events,
        &mut streamed_event_frames,
    )
    .await?;
    if state_updates.last() != Some(&observation.final_state) {
        state_updates.push(observation.final_state.clone());
    }
    let status = run_status_from_observation(run_plan, &observation);

    Ok(RunWorkflowReport {
        status,
        created_state: format!("{:?}", created.state).to_ascii_lowercase(),
        final_state: observation.final_state,
        outcome: observation.outcome,
        terminal_savepoint: observation.terminal_savepoint,
        final_frontier_ticks: observation.frontier_ticks,
        final_quanta: observation.quanta,
        budget_timed_out: observation.budget_timed_out,
        state_updates,
        streamed_events,
        streamed_event_frames,
        execution_fingerprints,
        acknowledged_commands,
        watch_statuses: observation.watch_statuses,
    })
}

async fn drive_interactive_stdin_commands(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<(), CliError> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    drive_interactive_command_reader(
        control,
        command_id,
        acknowledged_commands,
        stdin.lock(),
        &mut stdout,
    )
    .await
}

async fn drive_interactive_command_reader<R, W>(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    reader: R,
    writer: &mut W,
) -> Result<(), CliError>
where
    R: BufRead,
    W: Write,
{
    for line in reader.lines() {
        let line = line?;
        let Some(command) = parse_interactive_session_command_line(&line)? else {
            continue;
        };
        acknowledge_stream_command(control, command_id, command, acknowledged_commands).await?;
        writeln!(
            writer,
            "interactive-ack\tcommand={}\tstatus=accepted",
            session_command_name(command)
        )?;
        writer.flush()?;
    }
    Ok(())
}

async fn acknowledge_stream_command(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    command: SessionCommandKind,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<(), CliError> {
    let model_command = cli_stream_command(command)?;
    let response = control
        .send_command(*command_id, model_command)
        .await
        .map_err(control_client_error)?;
    *command_id = command_id.saturating_add(1);
    match response.result.status {
        CommandResultStatus::Accepted => {
            acknowledged_commands.push(command);
            Ok(())
        }
        CommandResultStatus::Rejected { reason } => Err(backend_error(format!(
            "session command `{}` was rejected: {reason:?}",
            session_command_name(command)
        ))),
    }
}

fn cli_stream_command(command: SessionCommandKind) -> Result<SessionCommand, CliError> {
    if command == SessionCommandKind::Query {
        return Ok(SessionCommand::Query {
            kind: QueryKind::State,
            reply: CommandReply::discard(),
        });
    }
    command.representative_command().ok_or_else(|| {
        backend_error(format!(
            "session command `{}` is not supported",
            session_command_name(command)
        ))
    })
}

async fn observe_run_final_state<C>(
    client: &C,
    control: &mut crucible_api::ClientControlStream,
    run_plan: &RunInvocationPlan,
    session_ref: crucible_api::SessionRef,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
    streamed_events: &mut Vec<String>,
    streamed_event_frames: &mut Vec<Vec<u8>>,
) -> Result<RunObservation, CliError>
where
    C: ControlClient + Sync,
{
    let max_yields = run_plan
        .max_quanta
        .unwrap_or(RUN_INTERACTIVE_ACK_QUANTA_BOUND);
    let mut last_frontier_ticks = 0;
    let mut last_quanta = 0;
    let mut last_session = None;
    let mut watch_statuses = Vec::new();
    for _ in 0..max_yields {
        for _ in 0..run_plan.observer_profile.pre_poll_yields {
            tokio::task::yield_now().await;
        }
        match run_plan.observer_profile.poll_order {
            VerifyPollOrder::EventThenState => {
                if observe_next_event(
                    control,
                    run_plan.observer_profile.event_timeout_ms,
                    streamed_events,
                    streamed_event_frames,
                )
                .await?
                {
                    break;
                }
                if observe_next_state_update(
                    control,
                    run_plan.observer_profile.state_timeout_ms,
                    state_updates,
                )
                .await?
                {
                    break;
                }
            }
            VerifyPollOrder::StateThenEvent => {
                if observe_next_state_update(
                    control,
                    run_plan.observer_profile.state_timeout_ms,
                    state_updates,
                )
                .await?
                {
                    break;
                }
                if observe_next_event(
                    control,
                    run_plan.observer_profile.event_timeout_ms,
                    streamed_events,
                    streamed_event_frames,
                )
                .await?
                {
                    break;
                }
            }
        }
        let sessions = client.list_sessions().await.map_err(control_client_error)?;
        let Some(session) = sessions
            .sessions
            .iter()
            .find(|summary| summary.session == session_ref)
        else {
            return Ok(RunObservation {
                final_state: terminal_final_state(run_plan, None),
                outcome: None,
                terminal_savepoint: None,
                frontier_ticks: last_frontier_ticks,
                quanta: last_quanta,
                budget_timed_out: false,
                watch_statuses,
            });
        };
        let state = format!("{:?}", session.state).to_ascii_lowercase();
        last_session = Some(session.clone());
        last_frontier_ticks = session.frontier.ticks;
        last_quanta = session.quanta_stepped;
        if run_plan.watch_streams_live_status {
            watch_statuses.push(run_watch_status(session));
        }
        let virtual_time_timed_out = run_plan
            .max_virtual_time_ticks
            .is_some_and(|budget| session.frontier.ticks >= budget);
        let quantum_timed_out = run_plan
            .max_quanta
            .is_some_and(|budget| session.quanta_stepped >= budget && state != "stopped");
        if virtual_time_timed_out {
            return stop_budget_timed_out_session(
                client,
                control,
                command_id,
                acknowledged_commands,
                String::from("virtual-time"),
                session.clone(),
                watch_statuses,
                run_plan.watch_streams_live_status,
            )
            .await;
        }
        if quantum_timed_out {
            return stop_budget_timed_out_session(
                client,
                control,
                command_id,
                acknowledged_commands,
                String::from("timeout"),
                session.clone(),
                watch_statuses,
                run_plan.watch_streams_live_status,
            )
            .await;
        }
        if state == "stopped" {
            return Ok(RunObservation {
                final_state: terminal_final_state(run_plan, session.outcome),
                outcome: session.outcome,
                terminal_savepoint: session.terminal_savepoint,
                frontier_ticks: session.frontier.ticks,
                quanta: session.quanta_stepped,
                budget_timed_out: false,
                watch_statuses,
            });
        }
        for _ in 0..run_plan.observer_profile.post_poll_yields {
            tokio::task::yield_now().await;
        }
    }
    if let Some(session) = last_session {
        return stop_budget_timed_out_session(
            client,
            control,
            command_id,
            acknowledged_commands,
            String::from("timeout"),
            session,
            watch_statuses,
            run_plan.watch_streams_live_status,
        )
        .await;
    }
    Ok(RunObservation {
        final_state: String::from("timeout"),
        outcome: Some(OutcomeKind::Timeout),
        terminal_savepoint: None,
        frontier_ticks: last_frontier_ticks,
        quanta: last_quanta,
        budget_timed_out: true,
        watch_statuses,
    })
}

async fn query_execution_fingerprint(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    run_plan: &RunInvocationPlan,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    execution_fingerprints: &mut Vec<crucible::FingerprintSample>,
) -> Result<(), CliError> {
    let Some(node) = run_plan
        .scenario
        .scenario_form()
        .world()
        .nodes()
        .first()
        .map(|node| node.id.clone())
    else {
        return Err(backend_error(
            "verify requires at least one scenario node for execution fingerprint sampling",
        ));
    };
    let response = control
        .send_command(
            *command_id,
            SessionCommand::Query {
                kind: QueryKind::ExecutionFingerprint { node: node.clone() },
                reply: CommandReply::discard(),
            },
        )
        .await
        .map_err(control_client_error)?;
    *command_id = command_id.saturating_add(1);
    match response.result.status {
        CommandResultStatus::Accepted => {
            acknowledged_commands.push(SessionCommandKind::Query);
        }
        CommandResultStatus::Rejected { reason } => {
            return Err(backend_error(format!(
                "execution fingerprint query for node `{}` was rejected: {reason:?}",
                node.name
            )));
        }
    }
    match response.query_result {
        Some(QueryResult::ExecutionFingerprint(sample)) => {
            execution_fingerprints.push(sample);
            Ok(())
        }
        Some(other) => Err(backend_error(format!(
            "execution fingerprint query for node `{}` returned unexpected payload: {other:?}",
            node.name
        ))),
        None => Err(backend_error(format!(
            "execution fingerprint query for node `{}` returned no payload",
            node.name
        ))),
    }
}

async fn observe_next_event(
    control: &mut crucible_api::ClientControlStream,
    timeout_ms: u64,
    streamed_events: &mut Vec<String>,
    streamed_event_frames: &mut Vec<Vec<u8>>,
) -> Result<bool, CliError> {
    match tokio::time::timeout(Duration::from_millis(timeout_ms), control.recv_event()).await {
        Ok(Ok(Some(frame))) => {
            streamed_event_frames.push(canonical_streaming_event_frame_bytes(&frame));
            streamed_events.push(frame.event.payload.kind);
            Ok(false)
        }
        Ok(Ok(None)) => Ok(true),
        Ok(Err(error)) => Err(control_client_error(error)),
        Err(_) => Ok(false),
    }
}

async fn observe_next_state_update(
    control: &mut crucible_api::ClientControlStream,
    timeout_ms: u64,
    state_updates: &mut Vec<String>,
) -> Result<bool, CliError> {
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        control.recv_state_update(),
    )
    .await
    {
        Ok(Ok(Some(frame))) => {
            state_updates.push(format!("{:?}", frame.update.state).to_ascii_lowercase());
            Ok(false)
        }
        Ok(Ok(None)) => Ok(true),
        Ok(Err(error)) => Err(control_client_error(error)),
        Err(_) => Ok(false),
    }
}

async fn stop_budget_timed_out_session<C>(
    client: &C,
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    final_state: String,
    initial: crucible_api::SessionSummary,
    mut watch_statuses: Vec<String>,
    watch_streams_live_status: bool,
) -> Result<RunObservation, CliError>
where
    C: ControlClient + Sync,
{
    let stopped = if initial.state == LiveStateKind::Stopped {
        initial
    } else {
        acknowledge_stream_command(
            control,
            command_id,
            SessionCommandKind::Stop,
            acknowledged_commands,
        )
        .await?;
        let mut stopped = initial;
        for _ in 0..RUN_INTERACTIVE_ACK_QUANTA_BOUND {
            let sessions = client.list_sessions().await.map_err(control_client_error)?;
            let Some(session) = sessions
                .sessions
                .iter()
                .find(|summary| summary.session == stopped.session)
            else {
                break;
            };
            stopped = session.clone();
            if watch_streams_live_status {
                watch_statuses.push(run_watch_status(session));
            }
            if session.state == LiveStateKind::Stopped {
                break;
            }
            tokio::task::yield_now().await;
        }
        stopped
    };

    Ok(RunObservation {
        final_state,
        outcome: Some(OutcomeKind::Timeout),
        terminal_savepoint: stopped.terminal_savepoint,
        frontier_ticks: stopped.frontier.ticks,
        quanta: stopped.quanta_stepped,
        budget_timed_out: true,
        watch_statuses,
    })
}

fn run_watch_status(session: &crucible_api::SessionSummary) -> String {
    format!(
        "state={}\tfrontier_ticks={}\tquanta={}\toutcome={}\tsavepoint={}",
        format!("{:?}", session.state).to_ascii_lowercase(),
        session.frontier.ticks,
        session.quanta_stepped,
        terminal_outcome_label(session.outcome),
        session
            .terminal_savepoint
            .map(format_content_hash_ref)
            .unwrap_or_else(|| String::from("none"))
    )
}

fn terminal_final_state(run_plan: &RunInvocationPlan, outcome: Option<OutcomeKind>) -> String {
    match run_plan.terminal_condition {
        RunTerminalCondition::Quiescence => match outcome {
            Some(OutcomeKind::Passed) => String::from("quiescent"),
            _ => terminal_outcome_label(outcome).to_string(),
        },
        RunTerminalCondition::VirtualTime => match outcome {
            Some(OutcomeKind::Passed) => String::from("stopped-before-virtual-time"),
            _ => terminal_outcome_label(outcome).to_string(),
        },
        RunTerminalCondition::Stopped => match outcome {
            Some(OutcomeKind::Passed) => String::from("stopped-passed"),
            _ => terminal_outcome_label(outcome).to_string(),
        },
        RunTerminalCondition::Property => match outcome {
            Some(OutcomeKind::Failed) => String::from("property-failed"),
            Some(OutcomeKind::Passed) | None => String::from("property-missing"),
            _ => terminal_outcome_label(outcome).to_string(),
        },
    }
}

fn terminal_outcome_label(outcome: Option<OutcomeKind>) -> &'static str {
    match outcome {
        Some(OutcomeKind::Passed) => "passed",
        Some(OutcomeKind::Failed) => "failed",
        Some(OutcomeKind::Timeout) => "timeout",
        Some(OutcomeKind::Crashed) => "crashed",
        Some(OutcomeKind::Stopped) => "stopped",
        None => "unknown",
    }
}

fn run_status_from_observation(
    run_plan: &RunInvocationPlan,
    observation: &RunObservation,
) -> BackendCommandStatus {
    if observation.budget_timed_out {
        return BackendCommandStatus::Timeout;
    }
    if run_plan.terminal_condition == RunTerminalCondition::Property
        && matches!(observation.outcome, Some(OutcomeKind::Passed) | None)
    {
        return BackendCommandStatus::Failed;
    }
    status_from_outcome(observation.outcome)
}

fn status_from_outcome(outcome: Option<OutcomeKind>) -> BackendCommandStatus {
    match outcome {
        Some(OutcomeKind::Passed | OutcomeKind::Stopped) => BackendCommandStatus::Passed,
        Some(OutcomeKind::Failed) => BackendCommandStatus::Failed,
        Some(OutcomeKind::Timeout) | None => BackendCommandStatus::Timeout,
        Some(OutcomeKind::Crashed) => BackendCommandStatus::Crashed,
    }
}

#[cfg(test)]
fn parse_interactive_session_commands(input: &str) -> Result<Vec<SessionCommandKind>, CliError> {
    input
        .lines()
        .filter_map(|line| parse_interactive_session_command_line(line).transpose())
        .collect()
}

fn parse_interactive_session_command_line(
    line: &str,
) -> Result<Option<SessionCommandKind>, CliError> {
    let command = line.split('#').next().unwrap_or("").trim();
    if command.is_empty() {
        Ok(None)
    } else {
        parse_interactive_session_command(command).map(Some)
    }
}

fn parse_interactive_session_command(command: &str) -> Result<SessionCommandKind, CliError> {
    match command {
        "continue" => Ok(SessionCommandKind::Continue),
        "pause" => Ok(SessionCommandKind::Pause),
        "step" | "step-quantum" => Ok(SessionCommandKind::StepQuantum),
        "step-event" => Ok(SessionCommandKind::StepEvent),
        "step-assertion" => Ok(SessionCommandKind::StepAssertion),
        "step-timer" => Ok(SessionCommandKind::StepTimer),
        "step-duration" => Ok(SessionCommandKind::StepDuration),
        "inject" => Ok(SessionCommandKind::Inject),
        "inject-fault" => Ok(SessionCommandKind::InjectFault),
        "heal" | "heal-fault" => Ok(SessionCommandKind::HealFault),
        "save" | "create-savepoint" => Ok(SessionCommandKind::CreateSavepoint),
        "fork" => Ok(SessionCommandKind::Fork),
        "query" => Ok(SessionCommandKind::Query),
        "stop" => Ok(SessionCommandKind::Stop),
        _ => Err(usage_error(format!(
            "unknown interactive session command `{command}`"
        ))),
    }
}

fn append_local_double_run_entries(
    outcome: &mut BackendCommandOutcome,
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
) {
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("scenario"),
        kind: String::from("run_scenario"),
        summary: format!("id={}", run_plan.scenario.scenario_id().to_hex()),
    });
    let request_seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("session"),
        kind: String::from("run_seed"),
        summary: request_seed.to_hex(),
    });
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("session"),
        kind: String::from("run_terminal_condition"),
        summary: format!("{:?}", run_plan.terminal_condition),
    });
    for state in &report.state_updates {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("session"),
            kind: String::from("run_state_update"),
            summary: state.clone(),
        });
    }
    for event in &report.streamed_events {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("event-log"),
            kind: String::from("run_stream_event"),
            summary: event.clone(),
        });
    }
    for command in &report.acknowledged_commands {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("control"),
            kind: String::from("interactive_ack"),
            summary: session_command_name(*command).to_string(),
        });
    }
    for status in &report.watch_statuses {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("session"),
            kind: String::from("run_watch_status"),
            summary: status.clone(),
        });
    }
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
}

fn session_command_name(command: SessionCommandKind) -> &'static str {
    match command {
        SessionCommandKind::Start => "start",
        SessionCommandKind::Continue => "continue",
        SessionCommandKind::Pause => "pause",
        SessionCommandKind::StepQuantum => "step-quantum",
        SessionCommandKind::StepEvent => "step-event",
        SessionCommandKind::StepAssertion => "step-assertion",
        SessionCommandKind::StepTimer => "step-timer",
        SessionCommandKind::StepDuration => "step-duration",
        SessionCommandKind::Inject => "inject",
        SessionCommandKind::InjectFault => "inject-fault",
        SessionCommandKind::HealFault => "heal-fault",
        SessionCommandKind::SetBreakpoint => "set-breakpoint",
        SessionCommandKind::RemoveBreakpoint => "remove-breakpoint",
        SessionCommandKind::CreateSavepoint => "create-savepoint",
        SessionCommandKind::Fork => "fork",
        SessionCommandKind::Query => "query",
        SessionCommandKind::Stop => "stop",
        SessionCommandKind::Snapshot => "snapshot",
        SessionCommandKind::AttachGdb => "attach-gdb",
        SessionCommandKind::DebugGoto => "debug-goto",
        SessionCommandKind::DebugReverseStep => "debug-reverse-step",
        SessionCommandKind::DebugReverseContinue => "debug-reverse-continue",
        SessionCommandKind::DebugForkNonCanonical => "debug-fork-non-canonical",
    }
}

fn control_client_error(error: crucible_api::ControlClientError) -> CliError {
    backend_error(format!("control API error: {error}"))
}

fn backend_command_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> BackendCommandOutcome {
    let canonical_log = backend_canonical_log_entries(thin_plan, backend_plan, ergonomics_plan);
    let canonical_log_digest = canonical_log_digest(&canonical_log);
    let artifact_digest = content_address_bytes(
        format!(
            "artifact\n{:?}\n{}\nseed={}\n",
            thin_plan.subcommand,
            canonical_log_digest,
            ergonomics_plan
                .map(|plan| format_seed(plan.seed.value))
                .unwrap_or_else(|| String::from("artifact-or-savepoint-owned"))
        )
        .as_bytes(),
    );

    BackendCommandOutcome {
        subcommand: backend_plan.subcommand,
        status: BackendCommandStatus::Passed,
        exit_code: 0,
        stdout: vec![format!(
            "outcome\t{:?}\t{}",
            thin_plan.subcommand, canonical_log_digest
        )],
        stderr: Vec::new(),
        canonical_log,
        canonical_log_digest,
        artifact_digest,
        reproduction_artifact: None,
        side_reproduction_artifacts: Vec::new(),
    }
}

fn backend_canonical_log_entries(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Vec<CanonicalLogEntry> {
    let mut entries = Vec::new();
    let seed_summary = ergonomics_plan
        .map(|plan| {
            format!(
                "seed={} source={:?}",
                format_seed(plan.seed.value),
                plan.seed.source
            )
        })
        .unwrap_or_else(|| String::from("seed=artifact-or-savepoint-owned"));
    entries.push(CanonicalLogEntry {
        sequence: entries.len() as u64,
        virtual_time_ticks: 0,
        node: String::from("cli"),
        kind: String::from("run_identity"),
        summary: seed_summary,
    });
    entries.push(CanonicalLogEntry {
        sequence: entries.len() as u64,
        virtual_time_ticks: 0,
        node: String::from("cli"),
        kind: String::from("backend_fidelity"),
        summary: format!("{:?}", backend_plan.requested_backend),
    });
    for command in &thin_plan.session_commands {
        entries.push(CanonicalLogEntry {
            sequence: entries.len() as u64,
            virtual_time_ticks: entries.len() as u64,
            node: String::from("session"),
            kind: String::from("session_command"),
            summary: format!("{command:?}"),
        });
    }
    for call in &thin_plan.api_calls {
        entries.push(CanonicalLogEntry {
            sequence: entries.len() as u64,
            virtual_time_ticks: entries.len() as u64,
            node: String::from("api"),
            kind: String::from("api_call"),
            summary: call.control_client_method().to_string(),
        });
    }
    entries
}

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
    let thin_plan = plan_cli_invocation(cli);
    execute_cli_dispatch_plan(&thin_plan, &mut NullOperationRecorder)?;
    let mut seed_entropy = OsSeedEntropySource;
    let ergonomics_plan =
        plan_determinism_ergonomics(cli, &ProcessSeedEnvironment, &mut seed_entropy)?;
    let run_store_root = default_run_store_root(cli);
    let run_plan = match &cli.command {
        Commands::Run(args) => Some(plan_run_invocation(args, &run_store_root)?),
        _ => None,
    };
    let verify_plan = match &cli.command {
        Commands::Verify(args) => Some(plan_verify_invocation(args, &run_store_root)?),
        _ => None,
    };
    if let Some(plan) = &ergonomics_plan {
        execute_determinism_ergonomics_plan(plan, &mut NullDeterminismErgonomicsRecorder)?;
        if !cli.quiet {
            println!("{}", plan.seed_announcement());
        }
    }
    if let Commands::Serve(args) = &cli.command {
        return run_serve_invocation(cli, args);
    }
    if let Some(backend_plan) = plan_backend_selection(cli)? {
        execute_backend_selection_plan(&backend_plan, cli.quiet, &mut NullBackendRouteRecorder)?;
        let mut outcome = execute_backend_routed_command(
            &thin_plan,
            &backend_plan,
            ergonomics_plan.as_ref(),
            run_plan.as_ref(),
            verify_plan.as_ref(),
            &mut NullBackendCommandRunner,
        )?;
        if matches!(
            &cli.command,
            Commands::Run(RunArgs {
                emit_mock_failure_artifact: true,
                ..
            })
        ) {
            mark_mock_failure_outcome(cli, &backend_plan, &mut outcome, ergonomics_plan.as_ref())?;
        }
        if backend_plan.should_announce(cli.quiet) {
            println!("{}", backend_plan.announcement());
        }
        emit_backend_command_output(cli, &outcome)?;
        if outcome.status.is_non_passing() {
            return Err(CliError::Outcome(outcome.status));
        }
    }

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
        Commands::Run(_) => Ok(()),
        Commands::Selftest(args) => {
            let report = run_selftest(cli, args)?;
            if !cli.quiet {
                for gate in &report.gates {
                    println!(
                        "crucible: selftest gate={} status={} corpus={} runs-per-entry={}",
                        gate.name,
                        gate.status.label(),
                        gate.corpus_entries,
                        gate.runs_per_entry
                    );
                }
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
        | Commands::Serve(_) => Ok(()),
        Commands::Completions(args) => {
            write_completions(args.shell, &mut io::stdout());
            Ok(())
        }
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

fn default_run_store_root(cli: &Cli) -> PathBuf {
    cli.store
        .clone()
        .unwrap_or_else(|| cli.artifact_dir.join("store"))
}

fn plan_selftest_gates(args: &SelftestArgs) -> Result<Vec<String>, CliError> {
    let requested = match args.gates.as_deref() {
        Some(raw) => raw.split(',').map(str::trim).collect::<Vec<_>>(),
        None => BUILT_IN_CORPUS_SELFTEST_GATES.iter().copied().collect(),
    };
    if requested.is_empty() || requested.iter().any(|gate| gate.is_empty()) {
        return Err(usage_error(
            "--gates must name one or more comma-separated canonical gates",
        ));
    }

    let mut seen = BTreeSet::new();
    for gate in &requested {
        if !seen.insert(*gate) {
            return Err(usage_error(format!(
                "duplicate selftest gate `{gate}` in --gates"
            )));
        }
        if crucible_harness::find_gate(gate).is_none() {
            return Err(usage_error(format!(
                "unknown selftest gate `{gate}`; use canonical gate names from RFC-0010 file 24"
            )));
        }
        if !BUILT_IN_CORPUS_SELFTEST_GATES.contains(gate) {
            return Err(usage_error(format!(
                "selftest gate `{gate}` is not implemented by the built-in corpus runner yet; real-QEMU and extended gate runners remain tracked by T-CLI-8"
            )));
        }
    }

    Ok(requested.into_iter().map(ToOwned::to_owned).collect())
}

fn run_selftest(_cli: &Cli, args: &SelftestArgs) -> Result<SelftestReport, CliError> {
    let selected_gates = plan_selftest_gates(args)?;
    let corpus = crucible::built_in_example_corpus().map_err(CliError::Selftest)?;
    let mut verified = Vec::with_capacity(corpus.len());
    for fixture in corpus {
        verified.push(
            crucible::verify_example_scenario_runs(&fixture, DEFAULT_SELFTEST_RUNS)
                .map_err(CliError::Selftest)?,
        );
    }
    let gates = selected_gates
        .into_iter()
        .map(|gate| SelftestGateReport {
            name: gate,
            status: SelftestGateStatus::Passed,
            corpus_entries: verified.len(),
            runs_per_entry: DEFAULT_SELFTEST_RUNS,
        })
        .collect();
    Ok(SelftestReport { gates, verified })
}

fn write_completions<W: Write>(shell: Shell, writer: &mut W) {
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    clap_complete::generate(shell, &mut command, name, writer);
}

fn mark_mock_failure_outcome(
    _cli: &Cli,
    backend_plan: &BackendSelectionPlan,
    outcome: &mut BackendCommandOutcome,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Result<(), CliError> {
    let Some(plan) = ergonomics_plan else {
        return Err(CliError::Backend(
            "run requires a resolved seed before emitting a reproduction artifact".to_string(),
        ));
    };
    let artifact = mock_failure_reproduction_artifact_bytes_for_backend(
        plan.seed.value,
        backend_plan.resolved_backend.as_ref(),
    )?;
    outcome.status = BackendCommandStatus::Failed;
    outcome.exit_code = 1;
    outcome.stderr.push(String::from(
        "crucible: mock non-passing outcome requested for gate testing",
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("session"),
        kind: String::from("outcome"),
        summary: String::from("Failed"),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    outcome.artifact_digest = content_address_bytes(&artifact);
    outcome.reproduction_artifact = Some(artifact);
    Ok(())
}

fn emit_backend_command_output(cli: &Cli, outcome: &BackendCommandOutcome) -> Result<(), CliError> {
    let _trace = emit_canonical_trace(
        cli.format,
        &outcome.canonical_log,
        cli.trace.as_deref(),
        !cli.quiet,
    )?;
    if !cli.quiet {
        for line in &outcome.stdout {
            println!("{line}");
        }
    }
    if outcome.status.is_non_passing() {
        if !outcome.side_reproduction_artifacts.is_empty() {
            for (label, artifact) in &outcome.side_reproduction_artifacts {
                let slug = format!("{}-{label}", outcome.status.failure_slug());
                let report = write_failure_reproduction_artifact(cli, artifact, &slug)?;
                if !cli.quiet {
                    println!(
                        "crucible: wrote reproduction artifact side={} {} ({}) digest={}",
                        label,
                        report.path.display(),
                        REPRODUCTION_ARTIFACT_MEDIA_TYPE,
                        report.digest
                    );
                    println!(
                        "crucible: reproduce side {} with:\n    {}",
                        label, report.footer.replay_command
                    );
                    println!(
                        "crucible: debug side {} at the failure with:\n    {}",
                        label, report.footer.debug_command
                    );
                }
            }
            return Ok(());
        }
        let Some(artifact) = &outcome.reproduction_artifact else {
            return Err(CliError::Artifact(format!(
                "{:?} outcome did not provide a reproduction artifact",
                outcome.status
            )));
        };
        let report =
            write_failure_reproduction_artifact(cli, artifact, outcome.status.failure_slug())?;
        if !cli.quiet {
            println!(
                "crucible: wrote reproduction artifact {} ({}) digest={}",
                report.path.display(),
                REPRODUCTION_ARTIFACT_MEDIA_TYPE,
                report.digest
            );
            println!(
                "crucible: reproduce with:\n    {}",
                report.footer.replay_command
            );
            println!(
                "crucible: debug at the failure with:\n    {}",
                report.footer.debug_command
            );
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TraceRenderReport {
    format: OutputFormat,
    path: Option<PathBuf>,
    bytes: Vec<u8>,
    entry_count: usize,
    streamed_entries: usize,
    canonical_digest: String,
}

fn emit_canonical_trace(
    format: OutputFormat,
    entries: &[CanonicalLogEntry],
    trace_path: Option<&Path>,
    stdout: bool,
) -> Result<TraceRenderReport, CliError> {
    if format == OutputFormat::Markdown {
        return Err(usage_error(
            "--format markdown is reserved for triage reports, not canonical event-log traces",
        ));
    }

    let mut bytes = Vec::new();
    let mut streamed_entries = 0usize;
    match format {
        OutputFormat::Jsonl => {
            let mut trace_file = trace_path.map(fs::File::create).transpose()?;
            for entry in entries {
                let line = json_for_canonical_log_entry(entry);
                if stdout {
                    println!("{line}");
                }
                if let Some(file) = trace_file.as_mut() {
                    writeln!(file, "{line}")?;
                }
                writeln!(&mut bytes, "{line}")?;
                streamed_entries += 1;
            }
        }
        OutputFormat::Json | OutputFormat::Table => {
            let rendered = render_canonical_event_log(format, entries)?;
            if stdout {
                println!("{}", String::from_utf8_lossy(&rendered.bytes));
            }
            if let Some(path) = trace_path {
                fs::write(path, &rendered.bytes)?;
            }
            bytes = rendered.bytes;
        }
        OutputFormat::Markdown => unreachable!("markdown rejected above"),
    }

    Ok(TraceRenderReport {
        format,
        path: trace_path.map(Path::to_path_buf),
        bytes,
        entry_count: entries.len(),
        streamed_entries,
        canonical_digest: canonical_log_digest(entries),
    })
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
    let footer = failure_reproduction_footer(path.clone());

    Ok(FailureArtifactReport {
        path,
        digest,
        footer,
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
    let backend_plan = plan_backend_selection(cli)?;
    let resolved_backend = backend_plan
        .as_ref()
        .and_then(|plan| plan.resolved_backend.as_ref());
    Ok(expected_replay_identity_for_backend(resolved_backend))
}

fn expected_replay_identity_for_backend(backend: Option<&ResolvedLocalBackend>) -> CliIdentity {
    let (qemu_build_id, plugin_abi) = match backend {
        Some(ResolvedLocalBackend::Qemu {
            qemu_build_id,
            plugin_abi,
            ..
        }) => (qemu_build_id.clone(), plugin_abi.clone()),
        Some(ResolvedLocalBackend::Double) | None => (
            content_address_bytes(b"mock-backend-source-v1"),
            String::from("simdouble-mock-plugin-abi"),
        ),
    };
    CliIdentity {
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        engine_abi: String::from("crucible-harness-e2e-v1"),
        artifact_abi: REPRODUCTION_ARTIFACT_SCHEMA.to_string(),
        qemu_build_id,
        plugin_abi,
    }
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

#[cfg(test)]
fn mock_failure_reproduction_artifact_bytes(cli: &Cli, seed: u64) -> Result<Vec<u8>, CliError> {
    let backend_plan = plan_backend_selection(cli)?;
    let resolved_backend = backend_plan
        .as_ref()
        .and_then(|plan| plan.resolved_backend.as_ref());
    mock_failure_reproduction_artifact_bytes_for_backend(seed, resolved_backend)
}

fn mock_failure_reproduction_artifact_bytes_for_backend(
    seed: u64,
    backend: Option<&ResolvedLocalBackend>,
) -> Result<Vec<u8>, CliError> {
    let scenario_material = b"scenario\tmock-failure\nnode\tnode-a\tserver\n";
    let scenario_digest = content_address_bytes(scenario_material);
    let identity = expected_replay_identity_for_backend(backend);
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
    let artifact = decode_reproduction_artifact(&bytes)?;
    verify_replay_identity(&artifact.identity, &identity)?;
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

fn is_content_address(digest: &str) -> bool {
    digest
        .strip_prefix(CONTENT_ADDRESS_PREFIX)
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
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
    if !is_content_address(digest) {
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

fn invalid_scenario(reason: impl Into<String>) -> CliError {
    CliError::InvalidScenario(reason.into())
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
    footer: FailureReproductionFooter,
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
    gates: Vec<SelftestGateReport>,
    verified: Vec<crucible::ExampleScenarioVerifyReport>,
}

#[derive(Debug)]
struct SelftestGateReport {
    name: String,
    status: SelftestGateStatus,
    corpus_entries: usize,
    runs_per_entry: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelftestGateStatus {
    Passed,
}

impl SelftestGateStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Passed => "PASS",
        }
    }
}

#[derive(Debug)]
enum CliError {
    Io(io::Error),
    Store(crucible::DagStoreError),
    Artifact(String),
    Usage(String),
    Backend(String),
    Identity(String),
    Outcome(BackendCommandStatus),
    InvalidScenario(String),
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
            Self::Outcome(BackendCommandStatus::Passed) => 0,
            Self::Outcome(BackendCommandStatus::Failed) => 1,
            Self::Outcome(BackendCommandStatus::Timeout) => 2,
            Self::Outcome(BackendCommandStatus::Crashed) => 3,
            Self::InvalidScenario(_) => 5,
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
            Self::Outcome(status) => write!(formatter, "run ended with {status:?}"),
            Self::InvalidScenario(error) => write!(formatter, "{error}"),
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
            Self::Outcome(_) => None,
            Self::InvalidScenario(_) => None,
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

fn backend_error(reason: impl Into<String>) -> CliError {
    CliError::Backend(reason.into())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use clap::CommandFactory;
    use crucible_harness::reproduction::{ReproductionArtifact, mock_e2e_reproduction_artifact};
    use tempfile::TempDir;

    use super::*;

    #[derive(Default)]
    struct RecordingOperationRecorder {
        session_commands: Vec<SessionCommandKind>,
        api_calls: Vec<CliApiCall>,
        drivers: Vec<CliDelegatedDriver>,
        state_references: Vec<CliStateReferenceKind>,
    }

    impl CliOperationRecorder for RecordingOperationRecorder {
        fn record_session_command(&mut self, command: SessionCommandKind) {
            self.session_commands.push(command);
        }

        fn record_api_call(&mut self, call: CliApiCall) {
            self.api_calls.push(call);
        }

        fn record_driver(&mut self, driver: CliDelegatedDriver) {
            self.drivers.push(driver);
        }

        fn record_state_reference(&mut self, reference: CliStateReferenceKind) {
            self.state_references.push(reference);
        }
    }

    #[derive(Default)]
    struct RecordingBackendRouteRecorder {
        remote_daemons: Vec<String>,
        local_backends: Vec<ResolvedLocalBackend>,
        announcements: Vec<String>,
    }

    impl BackendRouteRecorder for RecordingBackendRouteRecorder {
        fn record_remote_daemon(&mut self, daemon: &str) {
            self.remote_daemons.push(daemon.to_string());
        }

        fn record_local_backend(&mut self, backend: &ResolvedLocalBackend) {
            self.local_backends.push(backend.clone());
        }

        fn record_backend_announcement(&mut self, message: &str) {
            self.announcements.push(message.to_string());
        }
    }

    #[derive(Default)]
    struct RecordingBackendCommandRunner {
        local_runs: Vec<ResolvedLocalBackend>,
        remote_runs: Vec<String>,
        outcomes: Vec<BackendCommandOutcome>,
    }

    impl BackendCommandRunner for RecordingBackendCommandRunner {
        fn run_local(
            &mut self,
            backend: &ResolvedLocalBackend,
            thin_plan: &CliThinWrapperPlan,
            backend_plan: &BackendSelectionPlan,
            ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
            _run_plan: Option<&RunInvocationPlan>,
            _verify_plan: Option<&VerifyInvocationPlan>,
        ) -> Result<BackendCommandOutcome, CliError> {
            self.local_runs.push(backend.clone());
            let outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
            self.outcomes.push(outcome.clone());
            Ok(outcome)
        }

        fn run_remote(
            &mut self,
            daemon: &str,
            thin_plan: &CliThinWrapperPlan,
            backend_plan: &BackendSelectionPlan,
            ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
            _run_plan: Option<&RunInvocationPlan>,
            _verify_plan: Option<&VerifyInvocationPlan>,
        ) -> Result<BackendCommandOutcome, CliError> {
            self.remote_runs.push(daemon.to_string());
            let outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
            self.outcomes.push(outcome.clone());
            Ok(outcome)
        }
    }

    #[derive(Default)]
    struct RecordingDeterminismErgonomicsRecorder {
        seeds: Vec<ResolvedSeed>,
        formats: Vec<OutputFormat>,
        failure_rules: Vec<FailureArtifactRule>,
    }

    impl DeterminismErgonomicsRecorder for RecordingDeterminismErgonomicsRecorder {
        fn record_seed_resolution(&mut self, seed: &ResolvedSeed) {
            self.seeds.push(seed.clone());
        }

        fn record_trace_format(&mut self, format: OutputFormat) {
            self.formats.push(format);
        }

        fn record_failure_artifact_rule(&mut self, rule: &FailureArtifactRule) {
            self.failure_rules.push(rule.clone());
        }
    }

    fn write_valid_run_scenario(temp: &TempDir) -> Result<PathBuf, Box<dyn Error>> {
        let fixture = crucible::happy_path_scenario()?;
        let path = temp.path().join("scenario.toml");
        fs::write(&path, fixture.scenario.to_canonical_toml()?)?;
        Ok(path)
    }

    fn spawn_production_lifecycle_server() -> Result<String, Box<dyn Error>> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => return,
            };
            runtime.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(_) => return,
                };
                let control_plane = LifecycleControlPlane::new(
                    "crucible-cli-test-daemon",
                    Vec::new(),
                    |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
                );
                let _server = serve_lifecycle_http2(listener, control_plane).await;
            });
        });
        Ok(address.to_string())
    }

    #[derive(Default)]
    struct FakeSeedEnvironment {
        seed: Option<String>,
    }

    impl SeedEnvironment for FakeSeedEnvironment {
        fn variable(&self, name: &'static str) -> Option<String> {
            if name == CRUCIBLE_SEED_ENV {
                self.seed.clone()
            } else {
                None
            }
        }
    }

    struct FakeSeedEntropySource {
        next: u64,
        draws: usize,
    }

    impl FakeSeedEntropySource {
        fn new(next: u64) -> Self {
            Self { next, draws: 0 }
        }
    }

    impl SeedEntropySource for FakeSeedEntropySource {
        fn generated_seed(&mut self) -> Result<u64, CliError> {
            self.draws += 1;
            Ok(self.next)
        }
    }

    #[derive(Default)]
    struct FakeQemuDiscoveryEnvironment {
        qemu: Option<String>,
        plugin: Option<String>,
    }

    impl QemuDiscoveryEnvironment for FakeQemuDiscoveryEnvironment {
        fn variable(&self, name: &'static str) -> Option<String> {
            match name {
                CRUCIBLE_QEMU_ENV => self.qemu.clone(),
                CRUCIBLE_PLUGIN_ENV => self.plugin.clone(),
                _ => None,
            }
        }
    }

    #[derive(Default)]
    struct FakeAosQemuPackageSet {
        qemu: Option<PathBuf>,
        plugin: Option<PathBuf>,
    }

    impl AosQemuPackageSet for FakeAosQemuPackageSet {
        fn qemu_path(&self) -> Option<PathBuf> {
            self.qemu.clone()
        }

        fn plugin_path(&self) -> Option<PathBuf> {
            self.plugin.clone()
        }
    }

    fn canonical_trace_entries() -> Vec<CanonicalLogEntry> {
        vec![
            CanonicalLogEntry {
                sequence: 0,
                virtual_time_ticks: 10,
                node: String::from("node-a"),
                kind: String::from("decision"),
                summary: String::from("deliver packet"),
            },
            CanonicalLogEntry {
                sequence: 1,
                virtual_time_ticks: 12,
                node: String::from("node-b"),
                kind: String::from("assertion"),
                summary: String::from("property ok"),
            },
        ]
    }

    fn verify_compare_artifacts_with_paths(
        left: &Path,
        right_bytes: &[u8],
        _cli: &Cli,
    ) -> Result<CliError, Box<dyn Error>> {
        let temp = TempDir::new()?;
        let right = temp.path().join("right.crucible");
        fs::write(&right, right_bytes)?;
        let compare_cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("verify"),
            String::from("--compare"),
            left.display().to_string(),
            right.display().to_string(),
        ]);
        let Commands::Verify(args) = &compare_cli.command else {
            panic!("expected verify command");
        };
        let verify_plan = plan_verify_invocation(args, temp.path())?;
        let error = execute_backend_routed_command(
            &plan_cli_invocation(&compare_cli),
            &plan_backend_selection(&compare_cli)?
                .expect("verify should require backend selection"),
            None,
            None,
            Some(&verify_plan),
            &mut NullBackendCommandRunner,
        )
        .expect_err("mismatched compare artifacts should fail");
        Ok(error)
    }

    fn temp_qemu_artifacts(temp: &TempDir) -> Result<(String, String), Box<dyn Error>> {
        qemu_artifacts_in_dir(
            temp.path(),
            "test-qemu-build-v1",
            &required_qemu_plugin_abi(),
        )
    }

    fn qemu_artifacts_in_dir(
        dir: &Path,
        qemu_build_id: &str,
        plugin_abi: &str,
    ) -> Result<(String, String), Box<dyn Error>> {
        fs::create_dir_all(dir)?;
        let qemu = dir.join("qemu-system-x86_64");
        let plugin = dir.join("crucible-qemu-plugin.so");
        fs::write(&qemu, b"patched-qemu")?;
        fs::write(&plugin, b"plugin")?;
        write_qemu_artifact_markers(dir, qemu_build_id, plugin_abi)?;
        Ok((
            qemu.to_string_lossy().into_owned(),
            plugin.to_string_lossy().into_owned(),
        ))
    }

    fn write_qemu_artifact_markers(
        dir: &Path,
        qemu_build_id: &str,
        plugin_abi: &str,
    ) -> Result<(), Box<dyn Error>> {
        fs::write(
            dir.join("qemu-build-identity.env"),
            format!(
                "qemu_plugins_enabled=true\nqemu_crucible_patches_applied=true\nqemu_build_id={qemu_build_id}\n"
            ),
        )?;
        fs::write(
            dir.join("crucible-qemu-plugin-build-info"),
            format!(
                "package=crucible-qemu-plugin\nqemu_package=qemu-crucible\nqemu_build_id={qemu_build_id}\nplugin_abi={plugin_abi}\n"
            ),
        )?;
        Ok(())
    }

    fn backend_routed_subcommand_cases() -> Vec<(CliSubcommand, Vec<&'static str>)> {
        vec![
            (CliSubcommand::Run, vec!["run"]),
            (CliSubcommand::Verify, vec!["verify"]),
            (CliSubcommand::Save, vec!["save"]),
            (CliSubcommand::Resume, vec!["resume"]),
            (CliSubcommand::Fork, vec!["fork"]),
            (CliSubcommand::Replay, vec!["replay", "case.crucible"]),
            (CliSubcommand::Search, vec!["search"]),
            (CliSubcommand::Fuzz, vec!["fuzz"]),
            (CliSubcommand::Serve, vec!["serve"]),
        ]
    }

    fn cli_from_owned(args: Vec<String>) -> Cli {
        Cli::parse_from(args)
    }

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
                emit_mock_failure_artifact: false,
                ..
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
    fn cli_completions_generates_shell_script() -> Result<(), Box<dyn Error>> {
        let cli = Cli::parse_from(["crucible", "completions", "bash"]);
        let Commands::Completions(args) = cli.command else {
            panic!("expected completions command");
        };
        assert_eq!(args.shell, Shell::Bash);

        let mut script = Vec::new();
        write_completions(args.shell, &mut script);
        let script = String::from_utf8(script)?;

        assert!(script.contains("crucible"));
        assert!(script.contains("verify"));
        assert!(script.contains("completions"));

        Ok(())
    }

    #[test]
    fn cli_completions_requires_shell_argument() {
        let error = match Cli::try_parse_from(["crucible", "completions"]) {
            Ok(_) => panic!("completions without shell must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn cli_completions_ignores_global_daemon_for_thin_wrapper_metadata()
    -> Result<(), Box<dyn Error>> {
        let cli = Cli::parse_from([
            "crucible",
            "--daemon",
            "127.0.0.1:9000",
            "completions",
            "bash",
        ]);
        let plan = plan_cli_invocation(&cli);

        assert_eq!(
            plan.delegated_drivers,
            vec![CliDelegatedDriver::ShellCompletionGenerator]
        );
        assert!(plan.state_references.is_empty());
        assert!(plan_backend_selection(&cli)?.is_none());

        Ok(())
    }

    #[test]
    fn cli_help_and_version_surface_matches_rfc_copy() {
        let mut command = Cli::command();
        let top_help = command.render_long_help().to_string();
        for needle in [
            "Run and inspect Crucible simulations.",
            "run",
            "verify",
            "selftest",
            "save",
            "resume",
            "fork",
            "replay",
            "search",
            "fuzz",
            "serve",
            "completions",
            "--seed <u64|hex>",
            "--backend <auto|qemu|double>",
            "--daemon <addr>",
            "--qemu <path>",
            "--plugin <path>",
            "--store <path>",
            "--format <jsonl|json|table|markdown>",
            "--trace <path>",
            "--artifact-dir <path>",
            "--quiet",
        ] {
            assert!(
                top_help.contains(needle),
                "top-level help is missing `{needle}`:\n{top_help}"
            );
        }

        let version = Cli::command().render_version().to_string();
        assert!(
            version.contains(env!("CARGO_PKG_VERSION")),
            "version output must contain the crate version: {version}"
        );
        let version_exit = Cli::try_parse_from(["crucible", "--version"])
            .expect_err("--version must render through Clap's display path");
        assert_eq!(cli_parse_error_exit_code(&version_exit), 0);

        for (name, needles) in [
            (
                "run",
                &[
                    "SCENARIO",
                    "--until <quiescence|virtual-time|property|stopped>",
                    "--max-virtual-time <dur>",
                    "--max-quanta <n>",
                    "--interactive",
                    "--save-on <fail|always|never>",
                    "--watch",
                ][..],
            ),
            (
                "verify",
                &[
                    "SCENARIO",
                    "--runs <n>",
                    "--adversarial",
                    "--bisect",
                    "--compare <A> <B>",
                ],
            ),
            ("selftest", &["--gates <list>"]),
            ("replay", &["ARTIFACT"]),
            ("serve", &["--listen <addr>", "--store <path>"]),
        ] {
            let help = command
                .find_subcommand_mut(name)
                .unwrap_or_else(|| panic!("{name} subcommand must be registered"))
                .render_long_help()
                .to_string();
            for needle in needles {
                assert!(
                    help.contains(needle),
                    "{name} help is missing `{needle}`:\n{help}"
                );
            }
        }
    }

    #[test]
    fn cli_help_surface_rejects_unimplemented_future_flags() {
        for argv in [
            vec!["crucible", "selftest", "--with-qemu"],
            vec![
                "crucible",
                "replay",
                "case.crucible",
                "--check",
                "log.jsonl",
            ],
            vec!["crucible", "serve", "--read-only"],
        ] {
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "future flag must stay rejected until command behavior implements it"
            );
        }

        let serve = Cli::parse_from(["crucible", "serve", "--listen", "127.0.0.1:9001"]);
        let Commands::Serve(args) = serve.command else {
            panic!("expected serve command");
        };
        assert_eq!(args.listen, "127.0.0.1:9001");
    }

    #[test]
    fn cli_thin_wrapper_maps_every_subcommand_to_session_api_or_declared_driver() {
        let cases = [
            (
                CliSubcommand::Run,
                vec!["crucible", "--daemon", "127.0.0.1:9000", "run"],
            ),
            (CliSubcommand::Verify, vec!["crucible", "verify"]),
            (CliSubcommand::Selftest, vec!["crucible", "selftest"]),
            (CliSubcommand::Save, vec!["crucible", "save"]),
            (CliSubcommand::Resume, vec!["crucible", "resume"]),
            (CliSubcommand::Fork, vec!["crucible", "fork"]),
            (
                CliSubcommand::Replay,
                vec!["crucible", "replay", "case.crucible"],
            ),
            (CliSubcommand::Search, vec!["crucible", "search"]),
            (CliSubcommand::Fuzz, vec!["crucible", "fuzz"]),
            (
                CliSubcommand::Triage,
                vec!["crucible", "triage", "findings"],
            ),
            (
                CliSubcommand::Debug,
                vec!["crucible", "debug", "case.crucible"],
            ),
            (CliSubcommand::Serve, vec!["crucible", "serve"]),
            (
                CliSubcommand::Completions,
                vec!["crucible", "completions", "bash"],
            ),
        ];
        let mut observed = BTreeSet::new();

        for (expected, argv) in cases {
            let cli = Cli::parse_from(argv);
            let plan = plan_cli_invocation(&cli);
            observed.insert(plan.subcommand);

            assert_eq!(plan.subcommand, expected);
            assert!(
                plan.proves_t_cli_2(),
                "{expected:?} must satisfy the thin-wrapper contract: {plan:?}"
            );
            assert!(!plan.owns_canonical_run_state);
            assert!(!plan.implements_scheduler);
            assert!(!plan.implements_checkpoint_materialization);
            assert!(!plan.implements_fork_logic);
            assert!(plan.extra_control_capabilities.is_empty());
            assert!(
                plan.session_commands
                    .iter()
                    .all(|command| SessionCommandKind::ALL.contains(command))
            );
            assert!(
                plan.api_calls
                    .iter()
                    .all(|call| CliApiCall::ALL.contains(call)
                        && !call.control_client_method().is_empty())
            );

            let mut recorder = RecordingOperationRecorder::default();
            execute_cli_dispatch_plan(&plan, &mut recorder)
                .expect("thin-wrapper dispatch plan should execute");
            assert_eq!(recorder.session_commands, plan.session_commands);
            assert_eq!(recorder.api_calls, plan.api_calls);
            assert_eq!(recorder.drivers, plan.delegated_drivers);
            assert_eq!(recorder.state_references, plan.state_references);
        }

        assert_eq!(observed.len(), 13);
        assert!(observed.contains(&CliSubcommand::Run));
        assert!(observed.contains(&CliSubcommand::Completions));
    }

    #[test]
    fn cli_thin_wrapper_emits_only_control_client_methods_and_session_command_kinds() {
        let cli = Cli::parse_from(["crucible", "--daemon", "127.0.0.1:9000", "run"]);
        let plan = plan_cli_invocation(&cli);
        let mut recorder = RecordingOperationRecorder::default();

        execute_cli_dispatch_plan(&plan, &mut recorder)
            .expect("remote run should emit a valid thin-wrapper plan");

        assert!(recorder.drivers.contains(&CliDelegatedDriver::ControlApi));
        assert!(
            recorder
                .state_references
                .contains(&CliStateReferenceKind::DaemonConnection)
        );
        assert!(
            recorder
                .session_commands
                .iter()
                .all(|command| SessionCommandKind::ALL.contains(command))
        );
        assert_eq!(
            recorder
                .api_calls
                .iter()
                .map(|call| call.control_client_method())
                .collect::<Vec<_>>(),
            [
                "hello",
                "create_session",
                "watch_attach",
                "send_command",
                "get_reproduction",
            ]
        );
    }

    #[test]
    fn cli_thin_wrapper_rejects_canonical_state_or_extra_control_capabilities() {
        let cli = Cli::parse_from(["crucible", "run"]);
        let base = plan_cli_invocation(&cli);
        assert!(base.proves_t_cli_2());

        let mut owns_state = base.clone();
        owns_state.owns_canonical_run_state = true;
        assert!(!owns_state.proves_t_cli_2());

        let mut schedules = base.clone();
        schedules.implements_scheduler = true;
        assert!(!schedules.proves_t_cli_2());

        let mut materializes = base.clone();
        materializes.implements_checkpoint_materialization = true;
        assert!(!materializes.proves_t_cli_2());

        let mut forks = base.clone();
        forks.implements_fork_logic = true;
        assert!(!forks.proves_t_cli_2());

        let mut extra_control = base;
        extra_control
            .extra_control_capabilities
            .push("invented-control-capability");
        assert!(!extra_control.proves_t_cli_2());
        let mut recorder = RecordingOperationRecorder::default();
        let error = match execute_cli_dispatch_plan(&extra_control, &mut recorder) {
            Ok(_) => panic!("invented control capabilities must not dispatch"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Backend(_)));
        assert!(recorder.session_commands.is_empty());
        assert!(recorder.api_calls.is_empty());
    }

    #[test]
    fn cli_backend_selection_auto_announces_qemu_or_double_resolution() -> Result<(), Box<dyn Error>>
    {
        let temp = TempDir::new()?;
        let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
        let double_cli = Cli::parse_from(["crucible", "run"]);
        let double_plan =
            plan_backend_selection(&double_cli)?.expect("run should require backend selection");
        assert_eq!(double_plan.target, BackendExecutionTarget::Local);
        assert_eq!(
            double_plan.resolved_backend,
            Some(ResolvedLocalBackend::Double)
        );
        assert_eq!(
            double_plan.reason,
            BackendSelectionReason::AutoFallbackDouble
        );
        assert!(double_plan.should_announce(false));
        assert!(double_plan.announcement().contains("backend = double"));
        assert!(double_plan.proves_t_cli_3());
        let mut recorder = RecordingBackendRouteRecorder::default();
        execute_backend_selection_plan(&double_plan, false, &mut recorder)?;
        assert_eq!(recorder.local_backends, vec![ResolvedLocalBackend::Double]);
        assert_eq!(recorder.announcements, vec![double_plan.announcement()]);

        let qemu_cli = Cli::parse_from(["crucible", "--qemu", &qemu, "--plugin", &plugin, "run"]);
        let qemu_plan =
            plan_backend_selection(&qemu_cli)?.expect("run should require backend selection");
        assert!(matches!(
            qemu_plan.resolved_backend,
            Some(ResolvedLocalBackend::Qemu { .. })
        ));
        assert_eq!(
            qemu_plan.reason,
            BackendSelectionReason::AutoQemuArtifactsSupplied
        );
        assert!(qemu_plan.announcement().contains("backend = qemu"));
        assert!(qemu_plan.proves_t_cli_3());

        Ok(())
    }

    #[test]
    fn cli_backend_selection_honors_explicit_backend_and_qemu_failure_exit()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
        let double_cli = Cli::parse_from([
            "crucible",
            "--backend",
            "double",
            "--qemu",
            &qemu,
            "--plugin",
            &plugin,
            "run",
        ]);
        let double_plan =
            plan_backend_selection(&double_cli)?.expect("run should require backend selection");
        assert_eq!(double_plan.requested_backend, Backend::Double);
        assert_eq!(
            double_plan.resolved_backend,
            Some(ResolvedLocalBackend::Double)
        );
        assert_eq!(double_plan.reason, BackendSelectionReason::ExplicitDouble);
        assert!(!double_plan.should_announce(false));
        assert!(double_plan.proves_t_cli_3());

        let missing_qemu = Cli::parse_from(["crucible", "--backend", "qemu", "run"]);
        let error = match plan_backend_selection(&missing_qemu) {
            Ok(_) => panic!("explicit qemu without artifacts must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Backend(_)));
        assert_eq!(error.exit_code(), 4);
        assert!(error.to_string().contains("--qemu"));
        assert!(error.to_string().contains("--plugin"));

        let missing_files = Cli::parse_from([
            "crucible",
            "--backend",
            "qemu",
            "--qemu",
            temp.path()
                .join("missing-qemu")
                .to_str()
                .unwrap_or("missing-qemu"),
            "--plugin",
            &plugin,
            "run",
        ]);
        let error = match plan_backend_selection(&missing_files) {
            Ok(_) => panic!("explicit qemu with an unusable artifact must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Backend(_)));
        assert_eq!(error.exit_code(), 4);
        assert!(error.to_string().contains("cannot read patched QEMU"));

        let directory_artifact = Cli::parse_from([
            "crucible",
            "--backend",
            "qemu",
            "--qemu",
            temp.path().to_str().unwrap_or("."),
            "--plugin",
            &plugin,
            "run",
        ]);
        let error = match plan_backend_selection(&directory_artifact) {
            Ok(_) => panic!("explicit qemu with a directory artifact must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Backend(_)));
        assert_eq!(error.exit_code(), 4);
        assert!(error.to_string().contains("not a regular file"));

        let auto_with_unusable_artifact = Cli::parse_from([
            "crucible",
            "--qemu",
            temp.path().to_str().unwrap_or("."),
            "--plugin",
            &plugin,
            "run",
        ]);
        let error = match plan_backend_selection(&auto_with_unusable_artifact) {
            Ok(_) => panic!("auto with a complete but invalid QEMU candidate pair must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Backend(_)));
        assert_eq!(error.exit_code(), 4);
        assert!(error.to_string().contains("not a regular file"));

        let qemu_cli = Cli::parse_from([
            "crucible",
            "--backend",
            "qemu",
            "--qemu",
            &qemu,
            "--plugin",
            &plugin,
            "run",
        ]);
        let qemu_plan =
            plan_backend_selection(&qemu_cli)?.expect("run should require backend selection");
        assert_eq!(qemu_plan.reason, BackendSelectionReason::ExplicitQemu);
        assert!(matches!(
            qemu_plan.resolved_backend,
            Some(ResolvedLocalBackend::Qemu { .. })
        ));
        assert!(qemu_plan.proves_t_cli_3());

        Ok(())
    }

    #[test]
    fn cli_hermetic_qemu_discovery_prefers_flags_then_env_then_aos_package_set()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let plugin_abi = required_qemu_plugin_abi();
        let (flag_qemu, flag_plugin) =
            qemu_artifacts_in_dir(&temp.path().join("flag"), "flag-qemu-build", &plugin_abi)?;
        let (env_qemu, env_plugin) =
            qemu_artifacts_in_dir(&temp.path().join("env"), "env-qemu-build", &plugin_abi)?;
        let (aos_qemu, aos_plugin) =
            qemu_artifacts_in_dir(&temp.path().join("aos"), "aos-qemu-build", &plugin_abi)?;
        let env = FakeQemuDiscoveryEnvironment {
            qemu: Some(env_qemu.clone()),
            plugin: Some(env_plugin.clone()),
        };
        let package_set = FakeAosQemuPackageSet {
            qemu: Some(PathBuf::from(&aos_qemu)),
            plugin: Some(PathBuf::from(&aos_plugin)),
        };

        let flag_cli = Cli::parse_from([
            "crucible",
            "--qemu",
            &flag_qemu,
            "--plugin",
            &flag_plugin,
            "run",
        ]);
        let flag_plan = plan_backend_selection_with_discovery(&flag_cli, &env, &package_set)?
            .expect("run should require backend selection");
        let Some(ResolvedLocalBackend::Qemu {
            qemu,
            plugin,
            qemu_source,
            plugin_source,
            ..
        }) = &flag_plan.resolved_backend
        else {
            panic!("flags should resolve QEMU");
        };
        assert_eq!(qemu, &PathBuf::from(&flag_qemu));
        assert_eq!(plugin, &PathBuf::from(&flag_plugin));
        assert_eq!(*qemu_source, QemuDiscoverySource::Flag);
        assert_eq!(*plugin_source, QemuDiscoverySource::Flag);
        assert!(flag_plan.proves_t_cli_5());

        let env_cli = Cli::parse_from(["crucible", "--backend", "qemu", "run"]);
        let env_plan = plan_backend_selection_with_discovery(&env_cli, &env, &package_set)?
            .expect("run should require backend selection");
        let Some(ResolvedLocalBackend::Qemu {
            qemu,
            plugin,
            qemu_source,
            plugin_source,
            ..
        }) = &env_plan.resolved_backend
        else {
            panic!("environment should resolve QEMU");
        };
        assert_eq!(qemu, &PathBuf::from(&env_qemu));
        assert_eq!(plugin, &PathBuf::from(&env_plugin));
        assert_eq!(*qemu_source, QemuDiscoverySource::Environment);
        assert_eq!(*plugin_source, QemuDiscoverySource::Environment);
        assert!(env_plan.proves_t_cli_5());

        let empty_env = FakeQemuDiscoveryEnvironment::default();
        let aos_cli = Cli::parse_from(["crucible", "run"]);
        let aos_plan = plan_backend_selection_with_discovery(&aos_cli, &empty_env, &package_set)?
            .expect("run should require backend selection");
        let Some(ResolvedLocalBackend::Qemu {
            qemu,
            plugin,
            qemu_source,
            plugin_source,
            ..
        }) = &aos_plan.resolved_backend
        else {
            panic!("AOS package set should resolve QEMU");
        };
        assert_eq!(qemu, &PathBuf::from(&aos_qemu));
        assert_eq!(plugin, &PathBuf::from(&aos_plugin));
        assert_eq!(*qemu_source, QemuDiscoverySource::AosPackageSet);
        assert_eq!(*plugin_source, QemuDiscoverySource::AosPackageSet);
        assert_eq!(
            aos_plan.reason,
            BackendSelectionReason::AutoQemuArtifactsSupplied
        );
        assert!(aos_plan.proves_t_cli_5());

        Ok(())
    }

    #[test]
    fn cli_hermetic_qemu_discovery_uses_compile_time_aos_package_hints()
    -> Result<(), Box<dyn Error>> {
        let (Some(qemu_hint), Some(plugin_hint)) = (
            option_env!("CRUCIBLE_AOS_QEMU"),
            option_env!("CRUCIBLE_AOS_PLUGIN"),
        ) else {
            return Ok(());
        };
        let cli = Cli::parse_from(["crucible", "run"]);
        let plan = plan_backend_selection_with_discovery(
            &cli,
            &FakeQemuDiscoveryEnvironment::default(),
            &CompileTimeAosQemuPackageSet,
        )?
        .expect("run should require backend selection");
        let Some(ResolvedLocalBackend::Qemu {
            qemu,
            plugin,
            qemu_source,
            plugin_source,
            ..
        }) = &plan.resolved_backend
        else {
            panic!("compile-time AOS hints should resolve QEMU");
        };

        assert_eq!(qemu, &PathBuf::from(qemu_hint));
        assert_eq!(plugin, &PathBuf::from(plugin_hint));
        assert_eq!(*qemu_source, QemuDiscoverySource::AosPackageSet);
        assert_eq!(*plugin_source, QemuDiscoverySource::AosPackageSet);
        assert_eq!(
            plan.reason,
            BackendSelectionReason::AutoQemuArtifactsSupplied
        );
        assert!(plan.proves_t_cli_5());

        Ok(())
    }

    #[test]
    fn cli_hermetic_qemu_discovery_fails_absent_or_mismatched_artifacts_with_exit_4()
    -> Result<(), Box<dyn Error>> {
        let missing_cli = Cli::parse_from(["crucible", "--backend", "qemu", "run"]);
        let error = match plan_backend_selection_with_discovery(
            &missing_cli,
            &FakeQemuDiscoveryEnvironment::default(),
            &FakeAosQemuPackageSet::default(),
        ) {
            Ok(_) => panic!("explicit qemu without hermetic sources must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Backend(_)));
        assert_eq!(error.exit_code(), 4);
        assert!(error.to_string().contains(CRUCIBLE_QEMU_ENV));
        assert!(error.to_string().contains("host $PATH QEMU is never used"));

        let temp = TempDir::new()?;
        let plugin_abi = required_qemu_plugin_abi();
        let (qemu, plugin) =
            qemu_artifacts_in_dir(&temp.path().join("mismatch"), "qemu-build-a", &plugin_abi)?;
        fs::write(
            temp.path()
                .join("mismatch")
                .join("crucible-qemu-plugin-build-info"),
            format!(
                "package=crucible-qemu-plugin\nqemu_build_id=qemu-build-b\nplugin_abi={plugin_abi}\n"
            ),
        )?;
        let mismatch_cli = Cli::parse_from([
            "crucible",
            "--backend",
            "qemu",
            "--qemu",
            &qemu,
            "--plugin",
            &plugin,
            "run",
        ]);
        let error = match plan_backend_selection_with_discovery(
            &mismatch_cli,
            &FakeQemuDiscoveryEnvironment::default(),
            &FakeAosQemuPackageSet::default(),
        ) {
            Ok(_) => panic!("mismatched plugin must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Backend(_)));
        assert_eq!(error.exit_code(), 4);
        assert!(error.to_string().contains("built for QEMU identity"));

        Ok(())
    }

    #[test]
    fn cli_hermetic_qemu_discovery_pins_identity_into_failure_artifacts()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let plugin_abi = required_qemu_plugin_abi();
        let (qemu, plugin) =
            qemu_artifacts_in_dir(temp.path(), "artifact-qemu-build", &plugin_abi)?;
        let cli = Cli::parse_from([
            "crucible",
            "--backend",
            "qemu",
            "--qemu",
            &qemu,
            "--plugin",
            &plugin,
            "run",
        ]);
        let backend_plan = plan_backend_selection_with_discovery(
            &cli,
            &FakeQemuDiscoveryEnvironment::default(),
            &FakeAosQemuPackageSet::default(),
        )?
        .expect("run should require backend selection");
        let bytes = mock_failure_reproduction_artifact_bytes_for_backend(
            0x0010_0005,
            backend_plan.resolved_backend.as_ref(),
        )?;
        let artifact = decode_reproduction_artifact(&bytes)?;

        assert_eq!(
            artifact.identity.qemu_build_id,
            content_address_bytes(b"artifact-qemu-build")
        );
        assert_eq!(artifact.identity.plugin_abi, plugin_abi);
        assert!(backend_plan.proves_t_cli_5());

        Ok(())
    }

    #[test]
    fn cli_run_workflow_plans_start_continue_stream_and_budgets() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("run"),
            scenario.display().to_string(),
            String::from("--watch"),
            String::from("--max-quanta"),
            String::from("7"),
            String::from("--save-on"),
            String::from("fail"),
        ]);
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        let plan = plan_run_invocation(args, temp.path())?;

        assert_eq!(plan.scenario.label(), scenario.display().to_string());
        assert!(matches!(plan.scenario, RunScenarioRef::File { .. }));
        assert_eq!(plan.execution_mode, RunExecutionMode::ToCompletion);
        assert_eq!(plan.save_policy, RunSavePolicy::OnFail);
        assert_eq!(plan.max_quanta, Some(7));
        assert!(plan.watch_streams_live_status);
        assert_eq!(
            plan.startup_commands,
            vec![SessionCommandKind::Start, SessionCommandKind::Continue]
        );
        assert_eq!(
            plan.initial_control_commands,
            vec![SessionCommandKind::Query]
        );
        assert!(plan.accepted_interactive_commands.is_empty());

        Ok(())
    }

    #[test]
    fn cli_run_workflow_supports_virtual_time_budget() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("run"),
            scenario.display().to_string(),
            String::from("--until"),
            String::from("virtual-time"),
            String::from("--max-virtual-time"),
            String::from("10ms"),
        ]);
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        let plan = plan_run_invocation(args, temp.path())?;

        assert_eq!(plan.terminal_condition, RunTerminalCondition::VirtualTime);
        assert_eq!(plan.max_virtual_time.as_deref(), Some("10ms"));
        assert_eq!(plan.max_virtual_time_ticks, Some(10_000_000));
        assert_eq!(
            plan.startup_commands,
            vec![SessionCommandKind::Start, SessionCommandKind::Continue]
        );

        Ok(())
    }

    #[test]
    fn cli_run_workflow_interactive_pauses_at_genesis_and_accepts_session_commands()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("run"),
            scenario.display().to_string(),
            String::from("--interactive"),
            String::from("--until"),
            String::from("stopped"),
        ]);
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        let plan = plan_run_invocation(args, temp.path())?;

        assert_eq!(plan.execution_mode, RunExecutionMode::Interactive);
        assert_eq!(plan.startup_commands, vec![SessionCommandKind::Start]);
        assert_eq!(
            plan.initial_control_commands,
            vec![SessionCommandKind::Query]
        );
        assert!(
            plan.accepted_interactive_commands
                .contains(&SessionCommandKind::Continue)
        );
        assert!(
            plan.accepted_interactive_commands
                .contains(&SessionCommandKind::Pause)
        );
        assert!(
            plan.accepted_interactive_commands
                .contains(&SessionCommandKind::StepQuantum)
        );
        assert!(
            plan.accepted_interactive_commands
                .contains(&SessionCommandKind::InjectFault)
        );
        assert!(
            plan.accepted_interactive_commands
                .contains(&SessionCommandKind::HealFault)
        );
        assert!(
            plan.accepted_interactive_commands
                .contains(&SessionCommandKind::CreateSavepoint)
        );
        assert!(
            plan.accepted_interactive_commands
                .contains(&SessionCommandKind::Fork)
        );
        assert!(plan.bounded_ack_quanta <= RUN_INTERACTIVE_ACK_QUANTA_BOUND);
        assert_eq!(
            plan.accepted_interactive_commands,
            run_interactive_session_command_set()
        );

        Ok(())
    }

    #[test]
    fn cli_run_workflow_rejects_bad_scenarios_and_invalid_budgets() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let error = match plan_run_invocation(
            &RunArgs {
                scenario: Some(String::from("bad\nscenario")),
                ..RunArgs::default()
            },
            temp.path(),
        ) {
            Ok(_) => panic!("multiline scenario reference must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::InvalidScenario(_)));
        assert_eq!(error.exit_code(), 5);

        let error = match plan_run_invocation(
            &RunArgs {
                scenario: Some(temp.path().to_string_lossy().into_owned()),
                ..RunArgs::default()
            },
            temp.path(),
        ) {
            Ok(_) => panic!("directory scenario reference must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::InvalidScenario(_)));
        assert_eq!(error.exit_code(), 5);

        let error = match plan_run_invocation(
            &RunArgs {
                scenario: Some(temp.path().join("missing.toml").display().to_string()),
                ..RunArgs::default()
            },
            temp.path(),
        ) {
            Ok(_) => panic!("missing scenario file must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::InvalidScenario(_)));
        assert_eq!(error.exit_code(), 5);

        let malformed = temp.path().join("malformed.toml");
        fs::write(&malformed, "not = \"a scenario\"")?;
        let error = match plan_run_invocation(
            &RunArgs {
                scenario: Some(malformed.display().to_string()),
                ..RunArgs::default()
            },
            temp.path(),
        ) {
            Ok(_) => panic!("malformed scenario TOML must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::InvalidScenario(_)));
        assert_eq!(error.exit_code(), 5);

        let error = match plan_run_invocation(
            &RunArgs {
                ..RunArgs::default()
            },
            temp.path(),
        ) {
            Ok(_) => panic!("missing scenario argument must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);

        let scenario = write_valid_run_scenario(&temp)?;
        let scenario_ref = scenario.display().to_string();
        let error = match plan_run_invocation(
            &RunArgs {
                scenario: Some(scenario_ref.clone()),
                max_virtual_time: Some(String::from("soon")),
                ..RunArgs::default()
            },
            temp.path(),
        ) {
            Ok(_) => panic!("malformed virtual-time budget must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);

        let error = match plan_run_invocation(
            &RunArgs {
                scenario: Some(scenario_ref.clone()),
                max_virtual_time: Some(String::from("0ticks")),
                ..RunArgs::default()
            },
            temp.path(),
        ) {
            Ok(_) => panic!("zero virtual-time budget must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);

        let error = match plan_run_invocation(
            &RunArgs {
                scenario: Some(scenario_ref.clone()),
                max_quanta: Some(0),
                ..RunArgs::default()
            },
            temp.path(),
        ) {
            Ok(_) => panic!("zero max quanta must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);

        let error = match plan_run_invocation(
            &RunArgs {
                scenario: Some(scenario_ref),
                until: RunUntilArg::VirtualTime,
                ..RunArgs::default()
            },
            temp.path(),
        ) {
            Ok(_) => panic!("virtual-time terminal condition requires a budget"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);

        Ok(())
    }

    #[test]
    fn cli_run_workflow_uses_uniform_outcome_exit_code_mapping() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let scenario_bytes = fs::read(&scenario)?;
        let store = crucible::LocalDagStore::new(temp.path().join("store"));
        let key = store.put(&scenario_bytes)?;
        let reference = format_content_hash_ref(key);
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("run"),
            reference.clone(),
        ]);
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        let plan = plan_run_invocation(args, store.root())?;

        assert_eq!(plan.scenario.label(), reference);
        assert!(matches!(plan.scenario, RunScenarioRef::Stored { .. }));
        assert_eq!(
            plan.outcome_exit_codes,
            vec![
                (BackendCommandStatus::Passed, 0),
                (BackendCommandStatus::Failed, 1),
                (BackendCommandStatus::Timeout, 2),
                (BackendCommandStatus::Crashed, 3),
            ]
        );
        assert_eq!(plan.invalid_scenario_exit_code, 5);

        Ok(())
    }

    #[test]
    fn cli_run_workflow_executes_local_double_session_and_timeout_budget()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let pass_cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("--seed"),
            String::from("1"),
            String::from("run"),
            scenario.display().to_string(),
            String::from("--watch"),
        ]);
        let Commands::Run(pass_args) = &pass_cli.command else {
            panic!("expected run command");
        };
        let pass_run = plan_run_invocation(pass_args, temp.path())?;
        let pass_seed = plan_determinism_ergonomics(
            &pass_cli,
            &FakeSeedEnvironment::default(),
            &mut FakeSeedEntropySource::new(0),
        )?
        .expect("run should resolve a seed");
        let pass_outcome = execute_backend_routed_command(
            &plan_cli_invocation(&pass_cli),
            &plan_backend_selection(&pass_cli)?.expect("run should require backend selection"),
            Some(&pass_seed),
            Some(&pass_run),
            None,
            &mut NullBackendCommandRunner,
        )?;

        assert_eq!(pass_outcome.status, BackendCommandStatus::Passed);
        assert_eq!(pass_outcome.exit_code, 0);
        assert!(
            pass_outcome
                .canonical_log
                .iter()
                .any(|entry| entry.kind == "run_scenario")
        );
        assert!(
            pass_outcome
                .canonical_log
                .iter()
                .any(|entry| entry.kind == "run_state_update" && entry.summary == "quiescent")
        );
        assert!(
            pass_outcome
                .canonical_log
                .iter()
                .any(|entry| entry.kind == "run_stream_event"
                    && entry.summary == "crucible.event.diagnostic")
        );
        assert!(
            pass_outcome
                .stdout
                .iter()
                .any(|line| line.starts_with("run-watch\t"))
        );
        assert!(
            pass_outcome
                .canonical_log
                .iter()
                .any(|entry| entry.kind == "run_watch_status")
        );

        let timeout_cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("--seed"),
            String::from("2"),
            String::from("run"),
            scenario.display().to_string(),
            String::from("--until"),
            String::from("virtual-time"),
            String::from("--max-virtual-time"),
            String::from("1ticks"),
            String::from("--save-on"),
            String::from("fail"),
        ]);
        let Commands::Run(timeout_args) = &timeout_cli.command else {
            panic!("expected run command");
        };
        let timeout_run = plan_run_invocation(timeout_args, temp.path())?;
        let timeout_seed = plan_determinism_ergonomics(
            &timeout_cli,
            &FakeSeedEnvironment::default(),
            &mut FakeSeedEntropySource::new(0),
        )?
        .expect("run should resolve a seed");
        let timeout_outcome = execute_backend_routed_command(
            &plan_cli_invocation(&timeout_cli),
            &plan_backend_selection(&timeout_cli)?.expect("run should require backend selection"),
            Some(&timeout_seed),
            Some(&timeout_run),
            None,
            &mut NullBackendCommandRunner,
        )?;

        assert_eq!(timeout_outcome.status, BackendCommandStatus::Timeout);
        assert_eq!(timeout_outcome.exit_code, 2);
        assert!(timeout_outcome.reproduction_artifact.is_some());
        assert!(
            timeout_outcome
                .stdout
                .iter()
                .any(|line| line.starts_with("run-savepoint\tpolicy=fail\tcheckpoint=blake3:"))
        );

        let property_cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("--seed"),
            String::from("4"),
            String::from("run"),
            scenario.display().to_string(),
            String::from("--until"),
            String::from("property"),
            String::from("--save-on"),
            String::from("fail"),
        ]);
        let Commands::Run(property_args) = &property_cli.command else {
            panic!("expected run command");
        };
        let property_run = plan_run_invocation(property_args, temp.path())?;
        let property_seed = plan_determinism_ergonomics(
            &property_cli,
            &FakeSeedEnvironment::default(),
            &mut FakeSeedEntropySource::new(0),
        )?
        .expect("run should resolve a seed");
        let property_outcome = execute_backend_routed_command(
            &plan_cli_invocation(&property_cli),
            &plan_backend_selection(&property_cli)?.expect("run should require backend selection"),
            Some(&property_seed),
            Some(&property_run),
            None,
            &mut NullBackendCommandRunner,
        )?;

        assert_eq!(property_outcome.status, BackendCommandStatus::Failed);
        assert_eq!(property_outcome.exit_code, 1);
        assert!(property_outcome.reproduction_artifact.is_some());
        assert!(property_outcome.stdout.iter().any(|line| {
            line.starts_with("run-session\t") && line.contains("final=property-missing")
        }));
        assert!(
            property_outcome
                .stdout
                .iter()
                .any(|line| line.starts_with("run-savepoint\tpolicy=fail\tcheckpoint=blake3:"))
        );

        let dispatch_artifacts = temp.path().join("dispatch-timeout-artifacts");
        let dispatch_cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--quiet"),
            String::from("--backend"),
            String::from("double"),
            String::from("--seed"),
            String::from("3"),
            String::from("--artifact-dir"),
            dispatch_artifacts.display().to_string(),
            String::from("run"),
            scenario.display().to_string(),
            String::from("--until"),
            String::from("virtual-time"),
            String::from("--max-virtual-time"),
            String::from("1ticks"),
        ]);
        let error = match dispatch(&dispatch_cli) {
            Ok(_) => panic!("timeout dispatch must propagate outcome exit code"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CliError::Outcome(BackendCommandStatus::Timeout)
        ));
        assert_eq!(error.exit_code(), 2);
        assert_eq!(
            fs::read_dir(&dispatch_artifacts)?
                .collect::<Result<Vec<_>, _>>()?
                .len(),
            1
        );

        Ok(())
    }

    #[test]
    fn cli_run_workflow_executes_remote_daemon_session_against_production_server()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let daemon = spawn_production_lifecycle_server()?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--daemon"),
            daemon,
            String::from("--seed"),
            String::from("7"),
            String::from("run"),
            scenario.display().to_string(),
        ]);
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        let run_plan = plan_run_invocation(args, temp.path())?;
        let ergonomics_plan = plan_determinism_ergonomics(
            &cli,
            &FakeSeedEnvironment::default(),
            &mut FakeSeedEntropySource::new(0),
        )?
        .expect("run should resolve a seed");
        let backend_plan = plan_backend_selection(&cli)?.expect("remote run should route daemon");
        assert_eq!(backend_plan.target, BackendExecutionTarget::RemoteDaemon);

        let outcome = execute_backend_routed_command(
            &plan_cli_invocation(&cli),
            &backend_plan,
            Some(&ergonomics_plan),
            Some(&run_plan),
            None,
            &mut NullBackendCommandRunner,
        )?;

        assert_eq!(outcome.status, BackendCommandStatus::Passed);
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.iter().any(|line| {
            line.starts_with("run-session\t")
                && line.contains("created=paused")
                && line.contains("final=quiescent")
                && !line.contains("events=0")
        }));
        assert!(
            outcome
                .canonical_log
                .iter()
                .any(|entry| entry.kind == "run_stream_event"
                    && entry.summary == "crucible.event.diagnostic")
        );

        Ok(())
    }

    #[test]
    fn cli_run_workflow_parses_interactive_session_commands() -> Result<(), Box<dyn Error>> {
        let commands = parse_interactive_session_commands(
            "\n# comment\nquery\nstep\ninject-fault\nheal\nsave\nfork\nstop\n",
        )?;

        assert_eq!(
            commands,
            vec![
                SessionCommandKind::Query,
                SessionCommandKind::StepQuantum,
                SessionCommandKind::InjectFault,
                SessionCommandKind::HealFault,
                SessionCommandKind::CreateSavepoint,
                SessionCommandKind::Fork,
                SessionCommandKind::Stop,
            ]
        );

        let error = match parse_interactive_session_commands("invented\n") {
            Ok(_) => panic!("unknown interactive command must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);

        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cli_run_workflow_acknowledges_interactive_reader_commands()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("--seed"),
            String::from("5"),
            String::from("run"),
            scenario.display().to_string(),
            String::from("--interactive"),
        ]);
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        let run_plan = plan_run_invocation(args, temp.path())?;
        let control_plane = LifecycleControlPlane::new(
            "crucible-cli-reader-test",
            Vec::new(),
            |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
        );
        let client = InProcessLifecycleClient::new(control_plane);
        let request = CreateSessionRequest::inline(
            run_plan.scenario.scenario_def().clone(),
            run_plan.scenario.scenario_def().seed(),
        )
        .with_start_paused(true);
        let created = client.create_session(request).await?;
        let control = client
            .control_attach(
                AttachRequest::new(created.session)
                    .with_expected_epoch(created.session.epoch)
                    .with_client_name("crucible-cli-reader-test"),
            )
            .await?;

        let mut command_id = 1;
        let mut acknowledged = Vec::new();
        let mut output = Vec::new();
        drive_interactive_command_reader(
            &control,
            &mut command_id,
            &mut acknowledged,
            io::Cursor::new("query\n# ignored\n\n"),
            &mut output,
        )
        .await?;

        assert_eq!(acknowledged, vec![SessionCommandKind::Query]);
        assert_eq!(command_id, 2);
        assert_eq!(
            String::from_utf8(output)?,
            "interactive-ack\tcommand=query\tstatus=accepted\n"
        );

        Ok(())
    }

    #[test]
    fn cli_backend_selection_covers_every_backend_routed_subcommand() -> Result<(), Box<dyn Error>>
    {
        let temp = TempDir::new()?;
        let (qemu, plugin) = temp_qemu_artifacts(&temp)?;

        for (subcommand, tail) in backend_routed_subcommand_cases() {
            let mut auto_args = vec![String::from("crucible")];
            auto_args.extend(tail.iter().map(|arg| (*arg).to_string()));
            let auto_cli = cli_from_owned(auto_args);
            let auto_plan =
                plan_backend_selection(&auto_cli)?.expect("subcommand should be backend-routed");
            assert_eq!(auto_plan.subcommand, subcommand);
            assert_eq!(
                auto_plan.resolved_backend,
                Some(ResolvedLocalBackend::Double)
            );
            assert!(auto_plan.proves_t_cli_3());

            let mut double_args = vec![
                String::from("crucible"),
                String::from("--backend"),
                String::from("double"),
            ];
            double_args.extend(tail.iter().map(|arg| (*arg).to_string()));
            let double_cli = cli_from_owned(double_args);
            let double_plan =
                plan_backend_selection(&double_cli)?.expect("subcommand should be backend-routed");
            assert_eq!(double_plan.subcommand, subcommand);
            assert_eq!(double_plan.reason, BackendSelectionReason::ExplicitDouble);
            assert_eq!(
                double_plan.resolved_backend,
                Some(ResolvedLocalBackend::Double)
            );
            assert!(double_plan.proves_t_cli_3());

            let mut qemu_args = vec![
                String::from("crucible"),
                String::from("--backend"),
                String::from("qemu"),
                String::from("--qemu"),
                qemu.clone(),
                String::from("--plugin"),
                plugin.clone(),
            ];
            qemu_args.extend(tail.iter().map(|arg| (*arg).to_string()));
            let qemu_cli = cli_from_owned(qemu_args);
            let qemu_plan =
                plan_backend_selection(&qemu_cli)?.expect("subcommand should be backend-routed");
            assert_eq!(qemu_plan.subcommand, subcommand);
            assert_eq!(qemu_plan.reason, BackendSelectionReason::ExplicitQemu);
            assert!(matches!(
                qemu_plan.resolved_backend,
                Some(ResolvedLocalBackend::Qemu { .. })
            ));
            assert!(qemu_plan.proves_t_cli_3());

            if subcommand == CliSubcommand::Serve {
                let mut daemon_args = vec![
                    String::from("crucible"),
                    String::from("--daemon"),
                    String::from("127.0.0.1:9000"),
                ];
                daemon_args.extend(tail.iter().map(|arg| (*arg).to_string()));
                let serve_daemon = cli_from_owned(daemon_args);
                assert!(matches!(
                    plan_backend_selection(&serve_daemon),
                    Err(CliError::Usage(_))
                ));
                continue;
            }

            let mut daemon_args = vec![
                String::from("crucible"),
                String::from("--daemon"),
                String::from("127.0.0.1:9000"),
            ];
            daemon_args.extend(tail.iter().map(|arg| (*arg).to_string()));
            let daemon_cli = cli_from_owned(daemon_args);
            let daemon_plan =
                plan_backend_selection(&daemon_cli)?.expect("subcommand should be backend-routed");
            assert_eq!(daemon_plan.subcommand, subcommand);
            assert_eq!(daemon_plan.target, BackendExecutionTarget::RemoteDaemon);
            assert_eq!(daemon_plan.resolved_backend, None);
            assert!(daemon_plan.remote_uses_control_api);
            assert!(daemon_plan.proves_t_cli_3());
        }

        for argv in [
            vec!["crucible", "selftest"],
            vec!["crucible", "triage", "findings"],
            vec!["crucible", "debug", "case.crucible"],
            vec!["crucible", "completions", "bash"],
        ] {
            let cli = Cli::parse_from(argv);
            assert!(
                plan_backend_selection(&cli)?.is_none(),
                "non backend-routed subcommand should not select a backend"
            );
        }

        Ok(())
    }

    #[test]
    fn cli_verify_workflow_plans_runs_adversarial_matrix_and_bisection()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("verify"),
            scenario.display().to_string(),
            String::from("--runs"),
            String::from("3"),
            String::from("--adversarial"),
            String::from("--bisect"),
        ]);
        let Commands::Verify(args) = &cli.command else {
            panic!("expected verify command");
        };

        let plan = plan_verify_invocation(args, temp.path())?;

        assert!(matches!(plan.mode, VerifyMode::RunScenario { .. }));
        assert_eq!(plan.requested_runs, 3);
        assert_eq!(plan.reductions.len(), 3 * VERIFY_HOSTILE_PROFILES.len());
        assert!(plan.applies_hostile_condition_matrix);
        assert!(plan.bisection_on_divergence);
        assert!(plan.print_bisection_state_dump);
        assert!(plan.compare_canonical_logs);
        assert!(plan.compare_fingerprint_streams);
        assert!(plan.pairwise_byte_identity);
        assert!(plan.writes_side_artifacts_on_divergence);
        assert!(plan.surface_shape_is_consistent());

        Ok(())
    }

    #[test]
    fn cli_verify_workflow_rejects_single_fresh_reduction() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("verify"),
            scenario.display().to_string(),
            String::from("--runs"),
            String::from("1"),
        ]);
        let Commands::Verify(args) = &cli.command else {
            panic!("expected verify command");
        };

        let error = plan_verify_invocation(args, temp.path())
            .expect_err("fresh verify with one reduction cannot prove determinism");
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);
        assert!(
            error
                .to_string()
                .contains("--runs must be at least 2 for fresh verify reductions")
        );

        Ok(())
    }

    #[test]
    fn cli_verify_sim_backend_loop_fingerprints_backend_state_after_quantum()
    -> Result<(), Box<dyn Error>> {
        let mut loop_impl = SimBackendLifecycleLoop::default();
        let node = crucible::NodeId {
            name: String::from("node-a"),
        };
        let before = crucible::QuantumLoop::sample_fingerprint(&mut loop_impl, node.clone())?;
        let configuration =
            crucible::Configuration::genesis(crucible::ScenarioDef::from_canonical_material(
                "crucible.cli.verify.test",
                "sim-backend-loop",
            ));

        crucible::QuantumLoop::drive_quantum(
            &mut loop_impl,
            crucible::QuantumRequest {
                configuration,
                control: Vec::new(),
            },
        )?;
        let after = crucible::QuantumLoop::sample_fingerprint(&mut loop_impl, node)?;

        assert_eq!(before.at.ticks, 0);
        assert_eq!(after.at.ticks, 1);
        assert_ne!(before.fingerprint, after.fingerprint);

        Ok(())
    }

    #[test]
    fn cli_verify_workflow_collects_post_step_backend_fingerprint() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("--seed"),
            String::from("11"),
            String::from("verify"),
            scenario.display().to_string(),
            String::from("--runs"),
            String::from("2"),
        ]);
        let Commands::Verify(args) = &cli.command else {
            panic!("expected verify command");
        };
        let verify_plan = plan_verify_invocation(args, temp.path())?;
        let seed_plan = plan_determinism_ergonomics(
            &cli,
            &FakeSeedEnvironment::default(),
            &mut FakeSeedEntropySource::new(0),
        )?
        .expect("verify should resolve a seed");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let control_plane = LifecycleControlPlane::new(
            "crucible-cli-double-test",
            Vec::new(),
            |_scenario: &crucible::ScenarioDef, _seed| SimBackendLifecycleLoop::default(),
        );
        let client = InProcessLifecycleClient::new(control_plane);
        let report = runtime.block_on(run_control_client_verify_workflow_async(
            &client,
            &verify_plan,
            Some(&ResolvedLocalBackend::Double),
            Some(&seed_plan),
        ))?;
        assert_eq!(report.witnesses.len(), 2);
        let witness = report
            .witnesses
            .first()
            .ok_or_else(|| io::Error::other("missing verify witness"))?;

        assert!(witness.fingerprint_samples.len() >= 2);
        assert_eq!(witness.fingerprint_samples[0].instruction, 0);
        assert!(
            witness
                .fingerprint_samples
                .iter()
                .any(|sample| sample.instruction > 0)
        );
        assert!(
            witness
                .canonical_log
                .iter()
                .any(|entry| entry.kind == "interactive_ack" && entry.summary == "step-quantum")
        );

        Ok(())
    }

    #[test]
    fn cli_verify_workflow_runs_fresh_local_double_reductions() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("--seed"),
            String::from("11"),
            String::from("verify"),
            scenario.display().to_string(),
            String::from("--runs"),
            String::from("2"),
        ]);
        let Commands::Verify(args) = &cli.command else {
            panic!("expected verify command");
        };
        let verify_plan = plan_verify_invocation(args, temp.path())?;
        let seed_plan = plan_determinism_ergonomics(
            &cli,
            &FakeSeedEnvironment::default(),
            &mut FakeSeedEntropySource::new(0),
        )?
        .expect("verify should resolve a seed");
        let outcome = execute_backend_routed_command(
            &plan_cli_invocation(&cli),
            &plan_backend_selection(&cli)?.expect("verify should require backend selection"),
            Some(&seed_plan),
            None,
            Some(&verify_plan),
            &mut NullBackendCommandRunner,
        )
        .expect("fresh local double verify should run independent reductions");

        assert_eq!(outcome.status, BackendCommandStatus::Passed);
        assert_eq!(outcome.exit_code, 0);
        assert!(
            outcome
                .stdout
                .iter()
                .any(|line| line.contains("verify-plan\tmode=run-scenario\truns=2"))
        );
        assert_eq!(
            outcome
                .stdout
                .iter()
                .filter(|line| line.starts_with("verify-run\t"))
                .count(),
            2
        );
        assert!(
            outcome
                .stdout
                .iter()
                .filter(|line| line.starts_with("verify-run\t"))
                .all(|line| line.contains("\tfingerprint=") && line.contains("\tsamples=2"))
        );
        assert!(
            outcome
                .stdout
                .iter()
                .any(|line| line.contains("verify-result\tstatus=passed"))
        );

        Ok(())
    }

    #[test]
    fn cli_verify_workflow_localizes_divergence_and_writes_side_artifacts()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario_path = write_valid_run_scenario(&temp)?;
        let scenario =
            match resolve_run_scenario(Some(&scenario_path.display().to_string()), temp.path())? {
                RunScenarioRef::File { scenario, .. } | RunScenarioRef::Stored { scenario, .. } => {
                    scenario
                }
            };
        let entries = canonical_trace_entries();
        let first_samples = vec![VerifyFingerprintSample {
            index: 0,
            instruction: 0,
            node: String::from("session"),
            digest: content_address_bytes(b"first-verify-fingerprint-sample"),
        }];
        let first = verify_reproduction_artifact_bytes(
            12,
            Some(&ResolvedLocalBackend::Double),
            &scenario,
            &entries,
            &first_samples,
        )?;
        let mut diverged_entries = entries.clone();
        diverged_entries[1].summary.push_str(" diverged");
        let second_samples = vec![VerifyFingerprintSample {
            index: 0,
            instruction: 0,
            node: String::from("session"),
            digest: content_address_bytes(b"second-verify-fingerprint-sample"),
        }];
        let second = verify_reproduction_artifact_bytes(
            12,
            Some(&ResolvedLocalBackend::Double),
            &scenario,
            &diverged_entries,
            &second_samples,
        )?;
        let left = temp.path().join("left.crucible");
        let right = temp.path().join("right.crucible");
        fs::write(&left, first)?;
        fs::write(&right, second)?;
        let artifact_dir = temp.path().join("verify-artifacts");
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--quiet"),
            String::from("--backend"),
            String::from("double"),
            String::from("--seed"),
            String::from("12"),
            String::from("--artifact-dir"),
            artifact_dir.display().to_string(),
            String::from("verify"),
            String::from("--compare"),
            left.display().to_string(),
            right.display().to_string(),
            String::from("--bisect"),
        ]);
        let Commands::Verify(args) = &cli.command else {
            panic!("expected verify command");
        };
        let verify_plan = plan_verify_invocation(args, temp.path())?;
        let seed_plan = plan_determinism_ergonomics(
            &cli,
            &FakeSeedEnvironment::default(),
            &mut FakeSeedEntropySource::new(0),
        )?
        .expect("verify should resolve a seed");

        let outcome = execute_backend_routed_command(
            &plan_cli_invocation(&cli),
            &plan_backend_selection(&cli)?.expect("verify should require backend selection"),
            Some(&seed_plan),
            None,
            Some(&verify_plan),
            &mut NullBackendCommandRunner,
        )?;

        assert_eq!(outcome.status, BackendCommandStatus::Failed);
        assert_eq!(outcome.exit_code, 1);
        assert_eq!(outcome.side_reproduction_artifacts.len(), 2);
        assert!(
            outcome
                .stdout
                .iter()
                .any(|line| line.starts_with("verify-divergence\t"))
        );
        assert!(
            outcome
                .stdout
                .iter()
                .any(|line| line.starts_with("verify-bisect-state\t"))
        );
        assert!(
            outcome
                .canonical_log
                .iter()
                .any(|entry| entry.kind == "verify_divergence_bisection")
        );

        emit_backend_command_output(&cli, &outcome)?;
        let artifacts = fs::read_dir(&artifact_dir)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(artifacts.len(), 2);
        for entry in artifacts {
            let artifact = ReproductionArtifact::decode(&fs::read(entry.path())?)?;
            assert_eq!(artifact.seed, 12);
        }

        Ok(())
    }

    #[test]
    fn cli_verify_workflow_compares_existing_reproduction_artifacts() -> Result<(), Box<dyn Error>>
    {
        let temp = TempDir::new()?;
        let scenario_path = write_valid_run_scenario(&temp)?;
        let scenario =
            match resolve_run_scenario(Some(&scenario_path.display().to_string()), temp.path())? {
                RunScenarioRef::File { scenario, .. } | RunScenarioRef::Stored { scenario, .. } => {
                    scenario
                }
            };
        let mut entries = canonical_trace_entries();
        let first_samples = vec![VerifyFingerprintSample {
            index: 0,
            instruction: 0,
            node: String::from("session"),
            digest: content_address_bytes(b"first-compare-fingerprint-sample"),
        }];
        let first = verify_reproduction_artifact_bytes(
            21,
            Some(&ResolvedLocalBackend::Double),
            &scenario,
            &entries,
            &first_samples,
        )?;
        entries[1].summary.push_str(" diverged");
        let second_samples = vec![VerifyFingerprintSample {
            index: 0,
            instruction: 0,
            node: String::from("session"),
            digest: content_address_bytes(b"second-compare-fingerprint-sample"),
        }];
        let second = verify_reproduction_artifact_bytes(
            21,
            Some(&ResolvedLocalBackend::Double),
            &scenario,
            &entries,
            &second_samples,
        )?;
        let left = temp.path().join("left.crucible");
        let right = temp.path().join("right.crucible");
        fs::write(&left, first)?;
        fs::write(&right, second)?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("verify"),
            String::from("--compare"),
            left.display().to_string(),
            right.display().to_string(),
        ]);
        let Commands::Verify(args) = &cli.command else {
            panic!("expected verify command");
        };
        let verify_plan = plan_verify_invocation(args, temp.path())?;

        let outcome = execute_backend_routed_command(
            &plan_cli_invocation(&cli),
            &plan_backend_selection(&cli)?.expect("verify should require backend selection"),
            None,
            None,
            Some(&verify_plan),
            &mut NullBackendCommandRunner,
        )?;

        assert!(matches!(
            verify_plan.mode,
            VerifyMode::CompareArtifacts { .. }
        ));
        assert_eq!(outcome.status, BackendCommandStatus::Failed);
        assert_eq!(outcome.side_reproduction_artifacts.len(), 2);
        assert!(
            outcome
                .stdout
                .iter()
                .any(|line| line.contains("mismatch=canonical-log+fingerprint-stream"))
        );

        let different_seed = verify_reproduction_artifact_bytes(
            22,
            Some(&ResolvedLocalBackend::Double),
            &scenario,
            &entries,
            &second_samples,
        )?;
        let seed_mismatch = verify_compare_artifacts_with_paths(&left, &different_seed, &cli)?;
        assert!(matches!(
            seed_mismatch,
            CliError::Artifact(message) if message.contains("matching seeds")
        ));

        let different_scenario = crucible::ScenarioDef::from_canonical_material_with_seed(
            "cli-verify-test-scenario",
            "different scenario",
            scenario.seed(),
        );
        let scenario_mismatch_artifact = verify_reproduction_artifact_bytes(
            21,
            Some(&ResolvedLocalBackend::Double),
            &different_scenario,
            &entries,
            &second_samples,
        )?;
        let scenario_mismatch =
            verify_compare_artifacts_with_paths(&left, &scenario_mismatch_artifact, &cli)?;
        assert!(matches!(
            scenario_mismatch,
            CliError::Artifact(message) if message.contains("matching scenario digests")
        ));

        Ok(())
    }

    #[test]
    fn cli_verify_workflow_runs_fresh_remote_daemon_reductions() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let daemon = spawn_production_lifecycle_server()?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--daemon"),
            daemon,
            String::from("--seed"),
            String::from("13"),
            String::from("verify"),
            scenario.display().to_string(),
            String::from("--runs"),
            String::from("2"),
        ]);
        let Commands::Verify(args) = &cli.command else {
            panic!("expected verify command");
        };
        let verify_plan = plan_verify_invocation(args, temp.path())?;
        let seed_plan = plan_determinism_ergonomics(
            &cli,
            &FakeSeedEnvironment::default(),
            &mut FakeSeedEntropySource::new(0),
        )?
        .expect("verify should resolve a seed");
        let backend_plan =
            plan_backend_selection(&cli)?.expect("remote verify should route daemon");
        assert_eq!(backend_plan.target, BackendExecutionTarget::RemoteDaemon);

        let outcome = execute_backend_routed_command(
            &plan_cli_invocation(&cli),
            &backend_plan,
            Some(&seed_plan),
            None,
            Some(&verify_plan),
            &mut NullBackendCommandRunner,
        )
        .expect("fresh remote daemon verify should run independent reductions");

        assert_eq!(outcome.status, BackendCommandStatus::Passed);
        assert_eq!(outcome.exit_code, 0);
        assert!(
            outcome
                .stdout
                .iter()
                .any(|line| line.contains("verify-plan\tmode=run-scenario\truns=2"))
        );
        assert_eq!(
            outcome
                .stdout
                .iter()
                .filter(|line| line.starts_with("verify-run\t"))
                .count(),
            2
        );
        assert!(
            outcome
                .stdout
                .iter()
                .filter(|line| line.starts_with("verify-run\t"))
                .all(|line| line.contains("\tfingerprint=") && line.contains("\tsamples=2"))
        );
        assert!(
            outcome
                .stdout
                .iter()
                .any(|line| line.contains("verify-result\tstatus=passed"))
        );

        Ok(())
    }

    #[test]
    fn cli_verify_workflow_rejects_local_qemu_without_rfc_fingerprint_runner()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let scenario = write_valid_run_scenario(&temp)?;
        let (qemu, plugin) = temp_qemu_artifacts(&temp)?;
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("qemu"),
            String::from("--qemu"),
            qemu,
            String::from("--plugin"),
            plugin,
            String::from("verify"),
            scenario.display().to_string(),
            String::from("--runs"),
            String::from("2"),
        ]);
        let Commands::Verify(args) = &cli.command else {
            panic!("expected verify command");
        };
        let verify_plan = plan_verify_invocation(args, temp.path())?;
        let backend_plan =
            plan_backend_selection(&cli)?.expect("qemu verify should require backend selection");

        let error = execute_backend_routed_command(
            &plan_cli_invocation(&cli),
            &backend_plan,
            None,
            None,
            Some(&verify_plan),
            &mut NullBackendCommandRunner,
        )
        .expect_err("local qemu verify must not fall through to a generic pass");

        assert!(matches!(error, CliError::Backend(_)));
        assert!(error.to_string().contains("execution-fingerprint runner"));

        Ok(())
    }

    #[test]
    fn cli_backend_selection_routes_daemon_over_api_without_local_backend()
    -> Result<(), Box<dyn Error>> {
        let cli = Cli::parse_from([
            "crucible",
            "--daemon",
            "127.0.0.1:9000",
            "--backend",
            "qemu",
            "run",
        ]);
        let backend_plan =
            plan_backend_selection(&cli)?.expect("run should require backend selection");
        assert_eq!(backend_plan.target, BackendExecutionTarget::RemoteDaemon);
        assert_eq!(backend_plan.daemon.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(backend_plan.resolved_backend, None);
        assert!(backend_plan.remote_uses_control_api);
        assert!(!backend_plan.local_uses_simulation_backend);
        assert!(backend_plan.proves_t_cli_3());

        let thin_plan = plan_cli_invocation(&cli);
        assert!(
            thin_plan
                .delegated_drivers
                .contains(&CliDelegatedDriver::ControlApi)
        );
        assert!(
            thin_plan
                .state_references
                .contains(&CliStateReferenceKind::DaemonConnection)
        );
        let mut recorder = RecordingBackendRouteRecorder::default();
        execute_backend_selection_plan(&backend_plan, false, &mut recorder)?;
        assert_eq!(
            recorder.remote_daemons,
            vec![String::from("127.0.0.1:9000")]
        );
        assert!(recorder.local_backends.is_empty());
        let mut runner = RecordingBackendCommandRunner::default();
        let outcome = execute_backend_routed_command(
            &thin_plan,
            &backend_plan,
            None,
            None,
            None,
            &mut runner,
        )?;
        assert_eq!(runner.remote_runs, vec![String::from("127.0.0.1:9000")]);
        assert!(runner.local_runs.is_empty());
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stderr.is_empty());

        Ok(())
    }

    #[test]
    fn cli_backend_selection_local_and_remote_have_equivalent_canonical_outcome()
    -> Result<(), Box<dyn Error>> {
        let local_cli = Cli::parse_from(["crucible", "--backend", "double", "run"]);
        let remote_cli = Cli::parse_from([
            "crucible",
            "--backend",
            "double",
            "--daemon",
            "127.0.0.1:9000",
            "run",
        ]);
        let local_thin = plan_cli_invocation(&local_cli);
        let remote_thin = plan_cli_invocation(&remote_cli);
        let local_backend =
            plan_backend_selection(&local_cli)?.expect("run should require backend selection");
        let remote_backend =
            plan_backend_selection(&remote_cli)?.expect("run should require backend selection");
        let mut local_runner = RecordingBackendCommandRunner::default();
        let mut remote_runner = RecordingBackendCommandRunner::default();
        let local_outcome = execute_backend_routed_command(
            &local_thin,
            &local_backend,
            None,
            None,
            None,
            &mut local_runner,
        )?;
        let remote_outcome = execute_backend_routed_command(
            &remote_thin,
            &remote_backend,
            None,
            None,
            None,
            &mut remote_runner,
        )?;

        assert!(local_backend.proves_t_cli_3());
        assert!(remote_backend.proves_t_cli_3());
        assert_eq!(local_runner.local_runs, vec![ResolvedLocalBackend::Double]);
        assert!(local_runner.remote_runs.is_empty());
        assert_eq!(
            remote_runner.remote_runs,
            vec![String::from("127.0.0.1:9000")]
        );
        assert!(remote_runner.local_runs.is_empty());
        assert_eq!(
            local_outcome.normalized(),
            remote_outcome.normalized(),
            "daemon routing must preserve the canonical session/API outcome projection",
        );
        assert_eq!(local_outcome.exit_code, 0);
        assert_eq!(remote_outcome.exit_code, 0);
        assert_eq!(local_outcome.stdout, remote_outcome.stdout);
        assert_eq!(local_outcome.stderr, remote_outcome.stderr);

        Ok(())
    }

    #[test]
    fn cli_backend_selection_rejects_daemon_on_serve() {
        let cli = Cli::parse_from(["crucible", "--daemon", "127.0.0.1:9000", "serve"]);
        let error = match plan_backend_selection(&cli) {
            Ok(_) => panic!("serve is the daemon host and must reject --daemon"),
            Err(error) => error,
        };

        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);
        assert!(error.to_string().contains("serve"));
    }

    #[test]
    fn cli_determinism_ergonomics_resolves_seed_by_flag_env_or_generated()
    -> Result<(), Box<dyn Error>> {
        let mut entropy = FakeSeedEntropySource::new(0xfeed_face_cafe_beef);
        let flag_cli = Cli::parse_from(["crucible", "--seed", "0x2a", "run"]);
        let flag_plan = plan_determinism_ergonomics(
            &flag_cli,
            &FakeSeedEnvironment {
                seed: Some(String::from("99")),
            },
            &mut entropy,
        )?
        .expect("run should resolve a seed");

        assert_eq!(flag_plan.seed.value, 42);
        assert_eq!(flag_plan.seed.source, SeedSource::Flag);
        assert_eq!(entropy.draws, 0);
        assert!(flag_plan.seed_announcement().contains("--seed"));
        assert!(flag_plan.proves_t_cli_4());

        let env_cli = Cli::parse_from(["crucible", "run"]);
        let env_plan = plan_determinism_ergonomics(
            &env_cli,
            &FakeSeedEnvironment {
                seed: Some(String::from("0X10")),
            },
            &mut entropy,
        )?
        .expect("run should resolve a seed");

        assert_eq!(env_plan.seed.value, 16);
        assert_eq!(env_plan.seed.source, SeedSource::Environment);
        assert_eq!(entropy.draws, 0);
        assert!(env_plan.seed_announcement().contains(CRUCIBLE_SEED_ENV));
        assert!(env_plan.proves_t_cli_4());

        let generated_cli = Cli::parse_from(["crucible", "run"]);
        let generated_plan = plan_determinism_ergonomics(
            &generated_cli,
            &FakeSeedEnvironment::default(),
            &mut entropy,
        )?
        .expect("run should resolve a seed");

        assert_eq!(generated_plan.seed.value, 0xfeed_face_cafe_beef);
        assert_eq!(generated_plan.seed.source, SeedSource::Generated);
        assert_eq!(entropy.draws, 1);
        assert!(generated_plan.generated_seed_drawn_before_run);
        assert!(generated_plan.generated_seed_is_identity_only);
        assert!(
            generated_plan
                .seed_announcement()
                .contains("generated seed = 0xfeedfacecafebeef")
        );
        assert!(generated_plan.proves_t_cli_4());

        let mut recorder = RecordingDeterminismErgonomicsRecorder::default();
        execute_determinism_ergonomics_plan(&generated_plan, &mut recorder)?;
        assert_eq!(recorder.seeds, vec![generated_plan.seed.clone()]);
        assert_eq!(
            recorder.formats,
            vec![OutputFormat::Jsonl, OutputFormat::Json, OutputFormat::Table]
        );
        assert_eq!(
            recorder.failure_rules,
            vec![generated_plan.failure_artifact_rule.clone()]
        );

        Ok(())
    }

    #[test]
    fn cli_determinism_ergonomics_rejects_invalid_seed_and_markdown_trace_format()
    -> Result<(), Box<dyn Error>> {
        let mut entropy = FakeSeedEntropySource::new(7);
        let bad_seed = Cli::parse_from(["crucible", "--seed", "not-a-seed", "run"]);
        let error = match plan_determinism_ergonomics(
            &bad_seed,
            &FakeSeedEnvironment::default(),
            &mut entropy,
        ) {
            Ok(_) => panic!("invalid seed must be rejected before dispatch"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);
        assert!(error.to_string().contains("--seed"));

        let markdown_trace = Cli::parse_from(["crucible", "--format", "markdown", "run"]);
        let error = match plan_determinism_ergonomics(
            &markdown_trace,
            &FakeSeedEnvironment::default(),
            &mut entropy,
        ) {
            Ok(_) => panic!("markdown must not render canonical event-log traces"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);
        assert!(error.to_string().contains("triage reports"));

        let triage = Cli::parse_from(["crucible", "--format", "markdown", "triage", "findings"]);
        assert!(
            plan_determinism_ergonomics(&triage, &FakeSeedEnvironment::default(), &mut entropy)?
                .is_none()
        );
        assert_eq!(
            seed_resolution_mode(&Cli::parse_from(["crucible", "replay", "case.crucible"]).command),
            SeedResolutionMode::ArtifactOrSavepointOwned
        );
        assert_eq!(
            seed_resolution_mode(&Cli::parse_from(["crucible", "resume"]).command),
            SeedResolutionMode::ArtifactOrSavepointOwned
        );
        let draws_before = entropy.draws;
        assert!(
            plan_determinism_ergonomics(
                &Cli::parse_from(["crucible", "replay", "case.crucible"]),
                &FakeSeedEnvironment::default(),
                &mut entropy,
            )?
            .is_none()
        );
        assert_eq!(entropy.draws, draws_before);

        Ok(())
    }

    #[test]
    fn cli_determinism_ergonomics_renders_three_formats_over_same_canonical_log()
    -> Result<(), Box<dyn Error>> {
        let entries = canonical_trace_entries();
        let jsonl = render_canonical_event_log(OutputFormat::Jsonl, &entries)?;
        let json = render_canonical_event_log(OutputFormat::Json, &entries)?;
        let table = render_canonical_event_log(OutputFormat::Table, &entries)?;

        assert_eq!(jsonl.entry_count, entries.len());
        assert_eq!(json.entry_count, entries.len());
        assert_eq!(table.entry_count, entries.len());
        assert_eq!(jsonl.canonical_digest, json.canonical_digest);
        assert_eq!(json.canonical_digest, table.canonical_digest);
        assert!(jsonl.jsonl_streams_entries);
        assert!(!json.jsonl_streams_entries);
        assert!(!table.jsonl_streams_entries);
        assert_eq!(
            String::from_utf8(jsonl.bytes.clone())?.lines().count(),
            entries.len()
        );
        assert!(String::from_utf8(json.bytes)?.starts_with('['));
        assert!(String::from_utf8(table.bytes)?.starts_with("seq\tvirtual_time"));

        let error = match render_canonical_event_log(OutputFormat::Markdown, &entries) {
            Ok(_) => panic!("markdown is not a canonical event-log trace format"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));

        Ok(())
    }

    #[test]
    fn cli_determinism_ergonomics_threads_seed_into_backend_outcome() -> Result<(), Box<dyn Error>>
    {
        let local_cli = Cli::parse_from(["crucible", "--backend", "double", "--seed", "1", "run"]);
        let remote_cli = Cli::parse_from([
            "crucible",
            "--backend",
            "double",
            "--daemon",
            "127.0.0.1:9000",
            "--seed",
            "1",
            "run",
        ]);
        let different_seed_cli =
            Cli::parse_from(["crucible", "--backend", "double", "--seed", "2", "run"]);
        let mut entropy = FakeSeedEntropySource::new(99);
        let seed_one =
            plan_determinism_ergonomics(&local_cli, &FakeSeedEnvironment::default(), &mut entropy)?
                .expect("run should resolve a seed");
        let remote_seed_one = plan_determinism_ergonomics(
            &remote_cli,
            &FakeSeedEnvironment::default(),
            &mut entropy,
        )?
        .expect("remote run should resolve a seed");
        let seed_two = plan_determinism_ergonomics(
            &different_seed_cli,
            &FakeSeedEnvironment::default(),
            &mut entropy,
        )?
        .expect("run should resolve a seed");

        let local_thin = plan_cli_invocation(&local_cli);
        let remote_thin = plan_cli_invocation(&remote_cli);
        let different_seed_thin = plan_cli_invocation(&different_seed_cli);
        let local_backend =
            plan_backend_selection(&local_cli)?.expect("run should require backend selection");
        let remote_backend =
            plan_backend_selection(&remote_cli)?.expect("run should require backend selection");
        let different_seed_backend = plan_backend_selection(&different_seed_cli)?
            .expect("run should require backend selection");
        let mut local_runner = RecordingBackendCommandRunner::default();
        let mut remote_runner = RecordingBackendCommandRunner::default();
        let mut different_seed_runner = RecordingBackendCommandRunner::default();

        let local = execute_backend_routed_command(
            &local_thin,
            &local_backend,
            Some(&seed_one),
            None,
            None,
            &mut local_runner,
        )?;
        let remote = execute_backend_routed_command(
            &remote_thin,
            &remote_backend,
            Some(&remote_seed_one),
            None,
            None,
            &mut remote_runner,
        )?;
        let different_seed = execute_backend_routed_command(
            &different_seed_thin,
            &different_seed_backend,
            Some(&seed_two),
            None,
            None,
            &mut different_seed_runner,
        )?;

        assert_eq!(local.normalized(), remote.normalized());
        assert_ne!(
            local.canonical_log_digest,
            different_seed.canonical_log_digest
        );
        assert_ne!(local.artifact_digest, different_seed.artifact_digest);
        assert!(
            local
                .canonical_log
                .iter()
                .any(|entry| entry.kind == "run_identity"
                    && entry.summary.contains("0x0000000000000001"))
        );

        Ok(())
    }

    #[test]
    fn cli_determinism_ergonomics_failure_artifact_carries_resolved_seed_and_footer()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let artifact_dir = temp.path().join("artifacts");
        let cli = Cli::parse_from([
            "crucible",
            "--seed",
            "0x1234",
            "--artifact-dir",
            artifact_dir.to_str().unwrap_or("."),
            "run",
        ]);
        let mut entropy = FakeSeedEntropySource::new(9);
        let plan =
            plan_determinism_ergonomics(&cli, &FakeSeedEnvironment::default(), &mut entropy)?
                .expect("run should resolve a seed");
        let artifact_bytes = mock_failure_reproduction_artifact_bytes(&cli, plan.seed.value)?;
        let artifact = ReproductionArtifact::decode(&artifact_bytes)?;
        let report =
            write_failure_reproduction_artifact(&cli, &artifact_bytes, "Property Violation")?;

        assert_eq!(artifact.seed, 0x1234);
        assert_eq!(report.footer.artifact_path, report.path);
        assert!(report.footer.self_contained_artifact);
        assert!(report.footer.replay_command.starts_with("crucible replay "));
        assert!(report.footer.debug_command.ends_with(" --at-failure"));
        replay_reproduction_artifact(
            &cli,
            &ReplayArgs {
                artifact: report.path.clone(),
            },
        )?;

        Ok(())
    }

    #[test]
    fn cli_determinism_ergonomics_emits_trace_and_failure_artifact_from_outcome()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let artifact_dir = temp.path().join("artifact dir with spaces");
        let trace = temp.path().join("trace.jsonl");
        let cli = Cli::parse_from([
            "crucible",
            "--seed",
            "0x55",
            "--artifact-dir",
            artifact_dir.to_str().unwrap_or("."),
            "--trace",
            trace.to_str().unwrap_or("."),
            "run",
        ]);
        let mut entropy = FakeSeedEntropySource::new(1);
        let plan =
            plan_determinism_ergonomics(&cli, &FakeSeedEnvironment::default(), &mut entropy)?
                .expect("run should resolve a seed");
        let thin = plan_cli_invocation(&cli);
        let backend = plan_backend_selection(&cli)?.expect("run should require backend selection");
        let mut runner = RecordingBackendCommandRunner::default();
        let mut outcome =
            execute_backend_routed_command(&thin, &backend, Some(&plan), None, None, &mut runner)?;
        mark_mock_failure_outcome(&cli, &backend, &mut outcome, Some(&plan))?;

        emit_backend_command_output(&cli, &outcome)?;

        let trace_text = fs::read_to_string(&trace)?;
        assert_eq!(trace_text.lines().count(), outcome.canonical_log.len());
        let artifact_entries = fs::read_dir(&artifact_dir)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(artifact_entries.len(), 1);
        let artifact_path = artifact_entries[0].path();
        let artifact = ReproductionArtifact::decode(&fs::read(&artifact_path)?)?;
        assert_eq!(artifact.seed, 0x55);
        let footer = failure_reproduction_footer(artifact_path);
        assert!(footer.replay_command.contains('\''));
        assert!(footer.debug_command.contains('\''));
        assert!(footer.replay_command.starts_with("crucible replay "));
        assert!(footer.debug_command.ends_with(" --at-failure"));
        assert_eq!(
            CliError::Outcome(BackendCommandStatus::Failed).exit_code(),
            1
        );
        assert_eq!(
            CliError::Outcome(BackendCommandStatus::Timeout).exit_code(),
            2
        );
        assert_eq!(
            CliError::Outcome(BackendCommandStatus::Crashed).exit_code(),
            3
        );

        let dispatch_artifacts = temp.path().join("dispatch-artifacts");
        let scenario = write_valid_run_scenario(&temp)?;
        let dispatch_cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--quiet"),
            String::from("--seed"),
            String::from("0x55"),
            String::from("--artifact-dir"),
            dispatch_artifacts.display().to_string(),
            String::from("run"),
            scenario.display().to_string(),
            String::from("--emit-mock-failure-artifact"),
        ]);
        let error = match dispatch(&dispatch_cli) {
            Ok(_) => panic!("non-passing dispatch must propagate the outcome exit code"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CliError::Outcome(BackendCommandStatus::Failed)
        ));
        assert_eq!(error.exit_code(), 1);
        assert_eq!(
            fs::read_dir(&dispatch_artifacts)?
                .collect::<Result<Vec<_>, _>>()?
                .len(),
            1
        );

        Ok(())
    }

    #[test]
    fn cli_determinism_ergonomics_keeps_wall_clock_out_of_canonical_paths() {
        assert!(canonical_state_wall_clock_guard());
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
        let Commands::Selftest(args) = &cli.command else {
            panic!("expected selftest command");
        };
        let report = run_selftest(&cli, args)?;

        let scenario_names = report
            .verified
            .iter()
            .map(|verified| verified.scenario_name.as_str())
            .collect::<Vec<_>>();
        let gate_names = report
            .gates
            .iter()
            .map(|gate| gate.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(report.verified.len(), 3);
        assert!(scenario_names.contains(&"happy-path.scn"));
        assert!(scenario_names.contains(&"partition-recovery.scn"));
        assert!(scenario_names.contains(&"crash-restart.scn"));
        assert!(report.verified.iter().all(|verified| verified.runs == 5));
        assert_eq!(gate_names, BUILT_IN_CORPUS_SELFTEST_GATES);
        assert!(report.gates.iter().all(|gate| {
            gate.status == SelftestGateStatus::Passed
                && gate.corpus_entries == 3
                && gate.runs_per_entry == DEFAULT_SELFTEST_RUNS
        }));
        dispatch(&cli)?;

        let selected = Cli::parse_from([
            "crucible",
            "--quiet",
            "selftest",
            "--gates",
            "gate:replay-oracle",
        ]);
        let Commands::Selftest(args) = &selected.command else {
            panic!("expected selftest command");
        };
        let selected_report = run_selftest(&selected, args)?;
        assert_eq!(
            selected_report
                .gates
                .iter()
                .map(|gate| gate.name.as_str())
                .collect::<Vec<_>>(),
            ["gate:replay-oracle"]
        );
        dispatch(&selected)?;

        let unknown = Cli::parse_from(["crucible", "selftest", "--gates", "gate:not-real"]);
        let Commands::Selftest(args) = &unknown.command else {
            panic!("expected selftest command");
        };
        let error = match run_selftest(&unknown, args) {
            Ok(_) => panic!("unknown selftest gate must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);

        let empty = Cli::parse_from(["crucible", "selftest", "--gates", "gate:replay-oracle,"]);
        let Commands::Selftest(args) = &empty.command else {
            panic!("expected selftest command");
        };
        let error = match run_selftest(&empty, args) {
            Ok(_) => panic!("empty selftest gate component must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);

        let duplicate = Cli::parse_from([
            "crucible",
            "selftest",
            "--gates",
            "gate:replay-oracle,gate:replay-oracle",
        ]);
        let Commands::Selftest(args) = &duplicate.command else {
            panic!("expected selftest command");
        };
        let error = match run_selftest(&duplicate, args) {
            Ok(_) => panic!("duplicate selftest gate must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);

        let unsupported = Cli::parse_from(["crucible", "selftest", "--gates", "gate:qemu-inert"]);
        let Commands::Selftest(args) = &unsupported.command else {
            panic!("expected selftest command");
        };
        let error = match run_selftest(&unsupported, args) {
            Ok(_) => panic!("real-QEMU selftest gate must not be silently accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);

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
        let plugin_abi = required_qemu_plugin_abi();
        let (qemu, plugin) =
            qemu_artifacts_in_dir(temp.path(), "different-local-qemu-build", &plugin_abi)?;
        let artifact = mock_e2e_reproduction_artifact()?;
        fs::write(&artifact_path, artifact.encode()?)?;
        let cli = Cli::parse_from([
            "crucible",
            "--backend",
            "qemu",
            "--qemu",
            &qemu,
            "--plugin",
            &plugin,
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
        assert!(report.footer.replay_command.starts_with("crucible replay "));
        assert!(report.footer.debug_command.ends_with(" --at-failure"));
        assert!(
            report
                .footer
                .debug_command
                .contains("artifact dir with spaces")
        );
        assert!(report.footer.debug_command.contains('\''));
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
        let bytes = mock_failure_reproduction_artifact_bytes(&cli, 0xe2e0_0010)?;
        let artifact = ReproductionArtifact::decode(&bytes)?;

        assert_eq!(artifact.seed, 0xe2e0_0010);
        assert_eq!(artifact.schema_version, REPRODUCTION_ARTIFACT_SCHEMA);

        Ok(())
    }
}
