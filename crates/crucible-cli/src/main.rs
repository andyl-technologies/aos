//! `crucible` is the CLI entry point for the Crucible control plane.
//! Spec index: RFC-0010 files 23.
//! This L4 binary crate will remain a thin client over `crucible-api` and `crucible-session` as specified by RFC-0010 file 23.
//!
//! Module map: the binary root owns argument dispatch only; future command modules will remain transport clients over the session and API crates.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

#[macro_use]
#[cfg(any(test, feature = "test-double"))]
mod quantum_loop_method;

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::error::Error;
use std::fmt;
use std::fs;
use std::future::Future;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
#[cfg(any(test, feature = "test-double"))]
use std::sync::Arc;
use std::time::Duration;

use clap::{ArgAction, ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use crucible_api::{
    AttachRequest, CONTROL_PROTOCOL_VERSION, CommandResultStatus, ControlClient,
    CreateSessionRequest, DebugAuthorizationPolicy, DestroySessionRequest,
    InProcessLifecycleClient, LifecycleControlPlane, LifecycleServerMode, QuiescentLifecycleLoop,
    RPC_PROTOCOL_BUILD, RPC_PROTOCOL_MAJOR, RPC_PROTOCOL_MINOR, RPC_PROTOCOL_PATCH,
    ResumeSessionRequest, RpcControlClient, RpcEndpoint, RpcMutualTlsConfig, SendRequest,
    SessionRef, mutual_tls_acceptor_from_pem, serve_lifecycle_http2_mtls_with_mode_until_shutdown,
    serve_lifecycle_http2_with_debug_policy_until_shutdown,
};
use crucible_session::engine as crucible_model;
#[cfg(test)]
use crucible_session::engine::QuantumLoop as EngineLoop;
use crucible_session::validation::{
    ValidationDag, ValidationDagStoreError, recorded_checkpoint_for_configuration,
    validation_dag_with_baked_genesis,
};
use crucible_session::{
    BreakpointDisposition, BreakpointId, BreakpointSpec, CommandReply, DebugCapability, DebugRole,
    EngineSnapshot, LiveStateKind, OutcomeKind, QueryKind, QueryResult, SessionCommand,
    SessionCommandKind, StepMode,
    engine::{
        self as crucible, Checkpoint, CheckpointKind, ChoiceTag, DagStore, FindingDiscoveryPath,
        FindingReproductionArtifact, MaterializationPolicy, MaterializationTrigger, MemoryDagStore,
        OverrideDecision, RecordedAssertionLog, Schedule, SchedulingPoint, SearchDiscoveredFailure,
        SearchRetainedLogAssertionEvidence, SimDuration, VirtualTime,
    },
};
#[cfg(test)]
use crucible_session::{BreakpointFiring, EngineState, Outcome};
#[cfg(any(test, feature = "test-double"))]
mod test_double_imports;
use serde::Deserialize;
#[cfg(any(test, feature = "test-double"))]
use test_double_imports::*;
#[cfg(any(test, feature = "test-double"))]
use tokio::sync::{mpsc, oneshot};

const REPRODUCTION_ARTIFACT_SCHEMA: &str = "crucible.reproduction-artifact.v3";
const REPRODUCTION_ARTIFACT_MEDIA_TYPE: &str = "application/vnd.crucible.reproduction+text";
const MODEL_REPRODUCTION_ARTIFACT_MEDIA_TYPE: &str =
    "application/vnd.crucible.model-reproduction+binary";
const MODEL_REPLAY_STATE_MEDIA_TYPE: &str = "application/vnd.crucible.model-replay-state+text";
const LIVE_QEMU_REPLAY_CONTRACT_MEDIA_TYPE: &str =
    "application/vnd.crucible.live-qemu-replay-contract.v2+text";
const LIVE_QEMU_EVENT_STREAM_MEDIA_TYPE: &str =
    "application/vnd.crucible.live-qemu-event-stream.v1+bytes";
const LIVE_QEMU_FINGERPRINT_STREAM_MEDIA_TYPE: &str =
    "application/vnd.crucible.live-qemu-fingerprint-stream.v1+bytes";
const REPLAY_SCHEDULE_PREFIX_PROOF_SCHEMA: &str = "crucible.replay.schedule-prefix-proof.v1";
const SEARCH_SCHEDULE_NAMED_TRUTHS_SCHEMA: &str = "crucible.search-schedule-named-truths.v1";
const SEARCH_SCHEDULE_NAMED_TRUTHS_MEDIA_TYPE: &str =
    "application/vnd.crucible.search-schedule-named-truths+toml";
const SEARCH_RETAINED_EVIDENCE_SCHEMA: &str = "crucible.search-retained-evidence.v1";
const SEARCH_RETAINED_EVIDENCE_MEDIA_TYPE: &str =
    "application/vnd.crucible.search-retained-evidence+toml";
const SAVEPOINT_HANDLE_SCHEMA: &str = "crucible.savepoint-handle.v3";
const SAVEPOINT_HANDLE_SCHEMA_V2: &str = "crucible.savepoint-handle.v2";
const FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V1: &str = "crucible.failure-triage.findings-ledger.v1";
const FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V2: &str = "crucible.failure-triage.findings-ledger.v2";
const FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V3: &str = "crucible.failure-triage.findings-ledger.v3";
const RECORDED_DECISION_PAYLOAD_MEDIA_TYPE: &str =
    "application/vnd.crucible.recorded-decision-payload+text";
const CONTENT_ADDRESS_PREFIX: &str = "crucible-hash:";
const CRUCIBLE_SEED_ENV: &str = "CRUCIBLE_SEED";
const CRUCIBLE_QEMU_ENV: &str = "CRUCIBLE_QEMU";
const CRUCIBLE_PLUGIN_ENV: &str = "CRUCIBLE_PLUGIN";
const CRUCIBLE_AOS_QEMU_ENV: &str = "CRUCIBLE_AOS_QEMU";
const CRUCIBLE_AOS_PLUGIN_ENV: &str = "CRUCIBLE_AOS_PLUGIN";
const CRUCIBLE_QEMU_PLUGIN_ABI_PREFIX: &str = "crucible-shmem-abi-v";
const OS_ENTROPY_DEVICE: &str = "/dev/urandom";
const DEFAULT_SELFTEST_RUNS: usize = 5;
#[cfg(any(test, feature = "test-double"))]
const BACKEND_VALUE_NAME: &str = "auto|qemu|double";
#[cfg(not(any(test, feature = "test-double")))]
const BACKEND_VALUE_NAME: &str = "auto|qemu";
#[cfg(test)]
const SAVE_DOUBLE_ASSERTION_VIOLATION: &str = "no-split-brain";
#[cfg(test)]
const SAVE_DOUBLE_GUEST_MARKER: &str = "compaction-started";
#[cfg(any(test, feature = "test-double"))]
const SAVE_GUEST_MARKER_CMDLINE_PREFIX: &str = "crucible-guest-marker=";
const REAL_QEMU_SELFTEST_GATES: &[&str] = &[
    "gate:single-vm-fingerprint",
    "gate:any-guest",
    "gate:qemu-inert",
];
const CANONICAL_GATE_NAMES: &[&str] = &[
    "gate:harness-lint",
    "gate:license-boundary",
    "gate:layer0-determinism",
    "gate:single-vm-fingerprint",
    "gate:layer1-injection",
    "gate:content-address",
    "gate:replay-oracle",
    "gate:divergence-bisect",
    "gate:scheduler-liveness",
    "gate:control-responsive",
    "gate:any-guest",
    "gate:qemu-inert",
    "gate:abi-conformance",
    "gate:patch-microtests",
    "gate:adversarial-determinism",
    "gate:e2e-determinism",
    "gate:basic-block-coverage",
    "gate:perf-bench",
    "gate:fleet-equivalence",
    "gate:campaign-continuity",
];

#[derive(Parser, Debug, PartialEq, Eq)]
#[command(
    name = "crucible",
    version,
    about = "Run and inspect Crucible simulations.",
    disable_help_subcommand = true
)]
struct Cli {
    /// Root entropy (06 §5.3). Overrides CRUCIBLE_SEED.
    #[arg(long, value_name = "u64|hex", global = true)]
    seed: Option<String>,
    /// Local backend (20 §10). Default: auto.
    #[arg(
        long,
        value_enum,
        value_name = BACKEND_VALUE_NAME,
        default_value_t = Backend::Auto,
        global = true
    )]
    backend: Backend,
    /// Talk to a daemon (21) instead of running in-process.
    #[arg(long, value_name = "addr", global = true)]
    daemon: Option<String>,
    /// CA certificate used to authenticate an HTTPS daemon.
    #[arg(long, value_name = "path", global = true, requires = "daemon")]
    daemon_ca: Option<PathBuf>,
    /// Client certificate chain presented to an HTTPS daemon.
    #[arg(long, value_name = "path", global = true, requires = "daemon")]
    daemon_cert: Option<PathBuf>,
    /// Client private key presented to an HTTPS daemon.
    #[arg(long, value_name = "path", global = true, requires = "daemon")]
    daemon_key: Option<PathBuf>,
    /// Permit an unauthenticated daemon endpoint on a trusted network.
    #[arg(long, action = ArgAction::SetTrue, global = true, requires = "daemon")]
    trusted_unauthenticated_daemon: bool,
    /// Patched QEMU system binary (26). Else discovered.
    #[arg(long, value_name = "path", global = true)]
    qemu: Option<PathBuf>,
    /// crucible-qemu-plugin cdylib (12, 26). Else discovered.
    #[arg(long, value_name = "path", global = true)]
    plugin: Option<PathBuf>,
    /// Content-addressed store root (06, 07). Else default.
    #[arg(long, value_name = "path", global = true)]
    store: Option<PathBuf>,
    /// Trace/report render format. Default: table on a terminal, otherwise jsonl.
    #[arg(
        long,
        value_enum,
        value_name = "jsonl|json|table|markdown",
        global = true
    )]
    format: Option<OutputFormat>,
    /// Write the event-log stream here. Default: stdout.
    #[arg(long, value_name = "path", global = true)]
    trace: Option<PathBuf>,
    /// Where failure artifacts are written. Default: ./.crucible.
    #[arg(
        long,
        value_name = "path",
        default_value = "./.crucible",
        global = true
    )]
    artifact_dir: PathBuf,
    /// Increase log verbosity (repeatable: -vv).
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
    #[cfg(any(test, feature = "test-double"))]
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
    fn is_machine_readable(self) -> bool {
        matches!(self, Self::Jsonl | Self::Json)
    }

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
    /// Run a scenario to completion (local or via a daemon).
    Run(RunArgs),
    /// Prove determinism: run N times, diff fingerprints + causal logs.
    Verify(VerifyArgs),
    /// Run the packaged determinism gates.
    Selftest(SelftestArgs),
    /// Run to a savepoint and export it as a resumable checkpoint.
    Save(SaveArgs),
    /// Resume a run from a checkpoint or savepoint.
    Resume(ResumeArgs),
    /// Fork a run from a savepoint with a new seed or decision override.
    Fork(ForkArgs),
    /// Replay a reproduction artifact, bit-identically.
    Replay(ReplayArgs),
    /// Drive state-space search over the schedule space (22).
    Search(SearchArgs),
    /// Coverage-guided fuzzing over a scenario family (22).
    Fuzz(FuzzArgs),
    /// Cluster, dedup, and minimize discovered failures.
    Triage(TriageArgs),
    /// Open the time-travel debugger.
    Debug(DebugArgs),
    /// Run the daemon hosting the API (21).
    Serve(ServeArgs),
    /// Generate shell completions.
    Completions(CompletionsArgs),
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct RunArgs {
    /// Scenario file (the canonical TOML form, 06 §6.1) or its content hash.
    #[arg(value_name = "SCENARIO", required = true)]
    scenario: Option<String>,
    /// Terminal condition. Default: quiescence.
    #[arg(
        long,
        value_enum,
        value_name = "quiescence|virtual-time|property|stopped",
        default_value_t = RunUntilArg::Quiescence
    )]
    until: RunUntilArg,
    /// Stop with Timeout past this virtual time (20 §2).
    #[arg(long, value_name = "dur", required_if_eq("until", "virtual-time"))]
    max_virtual_time: Option<String>,
    /// Stop with Timeout at this scheduler-quantum boundary.
    #[arg(long, value_name = "n")]
    max_quanta: Option<u64>,
    /// Pause at genesis and drive the session interactively.
    #[arg(long, action = ArgAction::SetTrue)]
    interactive: bool,
    /// Materialize a savepoint at the outcome. Default: never.
    #[arg(
        long,
        value_enum,
        value_name = "fail|always|never",
        default_value_t = RunSaveOnArg::Never
    )]
    save_on: RunSaveOnArg,
    /// Stream the live status line (20 §9) alongside the trace.
    #[arg(long, action = ArgAction::SetTrue)]
    watch: bool,
    /// Emit a mock failure artifact for gate testing.
    #[cfg(any(test, feature = "test-double"))]
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
#[command(group(
    ArgGroup::new("verify_input")
        .args(["scenario", "compare"])
        .required(true)
        .multiple(false)
))]
struct VerifyArgs {
    /// Scenario file (the canonical TOML form, 06 §6.1) or its content hash.
    #[arg(value_name = "SCENARIO")]
    scenario: Option<String>,
    /// Number of runs to compare. Default: 2.
    #[arg(long, value_name = "n", default_value_t = 2)]
    runs: usize,
    /// Run under the hostile host-condition matrix (24 §7).
    #[arg(long, action = ArgAction::SetTrue)]
    adversarial: bool,
    /// On divergence, run divergence-bisection (24 §5) and print the report.
    #[arg(long, action = ArgAction::SetTrue)]
    bisect: bool,
    /// Diff two existing reproduction artifacts instead of running.
    #[arg(long, value_names = ["a", "b"], num_args = 2)]
    compare: Vec<PathBuf>,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct SelftestArgs {
    /// Gate subset to run.
    #[arg(long, value_name = "list")]
    gates: Option<String>,
    /// Execute the QEMU-backed gates.
    #[cfg_attr(not(any(test, feature = "test-double")), arg(hide = true))]
    #[arg(long, action = ArgAction::SetTrue)]
    with_qemu: bool,
    /// Test-only manifest of built-in fixture names.
    #[cfg(any(test, feature = "test-double"))]
    #[arg(long, value_name = "path")]
    corpus: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SaveAtArg {
    /// Stop at a virtual-time coordinate.
    VirtualTime,
    /// Stop at scheduler quiescence.
    Quiescence,
    /// Stop at a property verdict.
    Property,
    /// Stop at a named guest marker.
    Marker,
}

impl SaveAtArg {
    fn label(self) -> &'static str {
        match self {
            Self::VirtualTime => "virtual-time",
            Self::Quiescence => "quiescence",
            Self::Property => "property",
            Self::Marker => "marker",
        }
    }
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct SaveArgs {
    /// Scenario file (the canonical TOML form, 06 §6.1) or its content hash.
    #[arg(value_name = "SCENARIO", required = true)]
    scenario: Option<String>,
    /// Where to stop and save. Required.
    #[arg(
        long,
        value_enum,
        value_name = "virtual-time|quiescence|property|marker",
        required = true
    )]
    at: Option<SaveAtArg>,
    /// Human label for the savepoint (07).
    #[arg(long, value_name = "name")]
    label: Option<String>,
    /// Coordinate for --at virtual-time.
    #[arg(long, value_name = "dur", required_if_eq("at", "virtual-time"))]
    max_virtual_time: Option<String>,
    /// Assertion selector for --at property.
    #[arg(long, value_name = "assertion", required_if_eq("at", "property"))]
    property: Option<String>,
    /// Guest marker selector for --at marker.
    #[arg(long, value_name = "name", required_if_eq("at", "marker"))]
    marker: Option<String>,
    /// Write the exported savepoint handle here. Default: --artifact-dir.
    #[arg(long, value_name = "path")]
    out: Option<PathBuf>,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ResumeArgs {
    /// A savepoint handle / checkpoint content hash (07).
    #[arg(value_name = "SAVEPOINT", required = true)]
    savepoint: Option<String>,
    /// Terminal condition, as in `run` (§6).
    #[arg(
        long,
        value_enum,
        value_name = "quiescence|virtual-time|property|stopped",
        default_value_t = RunUntilArg::Quiescence
    )]
    until: RunUntilArg,
    /// Stop with Timeout past this virtual time (20 §2).
    #[arg(long, value_name = "dur", required_if_eq("until", "virtual-time"))]
    max_virtual_time: Option<String>,
    /// Drive the resumed session interactively (as in `run`).
    #[arg(long, action = ArgAction::SetTrue)]
    interactive: bool,
    /// Stream the live status line (20 §9).
    #[arg(long, action = ArgAction::SetTrue)]
    watch: bool,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ForkArgs {
    /// The fork point: a savepoint handle / checkpoint hash (07).
    #[arg(value_name = "SAVEPOINT", required = true)]
    savepoint: Option<String>,
    /// Override a decision at/after the fork point (05 §3). Repeatable.
    #[arg(
        long = "override",
        value_name = "decision=value",
        action = ArgAction::Append,
        conflicts_with = "seed"
    )]
    overrides: Vec<String>,
    /// Terminal condition, as in `run` (§6).
    #[arg(
        long,
        value_enum,
        value_name = "quiescence|virtual-time|property|stopped",
        default_value_t = RunUntilArg::Quiescence
    )]
    until: RunUntilArg,
    /// Stop with Timeout past this virtual time (20 §2).
    #[arg(long, value_name = "dur", required_if_eq("until", "virtual-time"))]
    max_virtual_time: Option<String>,
    /// Label the forked branch.
    #[arg(long, value_name = "name")]
    label: Option<String>,
    /// Drive the forked session interactively.
    #[arg(long, action = ArgAction::SetTrue)]
    interactive: bool,
    /// Stream the live status line (20 §9).
    #[arg(long, action = ArgAction::SetTrue)]
    watch: bool,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ReplayArgs {
    /// A reproduction artifact (06 §7.1) or its content hash.
    #[arg(value_name = "ARTIFACT")]
    artifact: PathBuf,
    /// Assert the replayed canonical log is byte-identical to this one.
    #[arg(long, value_name = "original-log")]
    check: Option<PathBuf>,
    /// Validate a target savepoint handle or checkpoint hash.
    #[arg(long, value_name = "savepoint")]
    to: Option<String>,
    /// Bisect this artifact against another (24 §5).
    #[arg(long, value_name = "other-artifact")]
    bisect: Option<PathBuf>,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct SearchArgs {
    /// Scenario file (the canonical TOML form, 06 §6.1) or its content hash.
    #[arg(value_name = "SCENARIO", required = true)]
    scenario: Option<String>,
    /// Frontier expansion strategy (22).
    #[arg(
        long,
        value_enum,
        value_name = "bfs|dfs|guided",
        default_value_t = SearchStrategyArg::Bfs
    )]
    strategy: SearchStrategyArg,
    /// Decision-depth bound.
    #[arg(long, value_name = "n")]
    max_depth: Option<u64>,
    /// Budget on materialized states.
    #[arg(long, value_name = "n", default_value_t = 1)]
    max_states: u64,
    /// Stop at the first finding, or collect findings within the search bound.
    #[arg(long, value_enum, value_name = "stop|collect")]
    on_violation: Option<SearchOnViolationArg>,
    /// Write the signed findings ledger to this path.
    #[arg(long, value_name = "path")]
    findings_out: Option<PathBuf>,
    /// Load schedule-named assertion truth data.
    #[arg(long, value_name = "path")]
    schedule_named_truths: Option<PathBuf>,
    /// Load backend-retained assertion evidence.
    #[arg(long, value_name = "path", hide = true)]
    retained_evidence: Option<PathBuf>,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
#[command(group(
    ArgGroup::new("fuzz_family")
        .args(["family", "family_flag"])
        .required(true)
        .multiple(false)
))]
struct FuzzArgs {
    /// A ScenarioFamily (06 §7) to sample.
    #[arg(value_name = "FAMILY")]
    family: Option<String>,
    /// A ScenarioFamily (06 §7) to sample.
    #[arg(long = "family", value_name = "path|hash")]
    family_flag: Option<String>,
    /// Number of family instances to run.
    #[arg(long, value_name = "n", default_value_t = 1)]
    runs: u64,
    /// Coverage signal guiding sampling (22).
    #[arg(
        long,
        value_enum,
        value_name = "basic-block",
        default_value_t = FuzzCoverageArg::BasicBlock
    )]
    coverage: FuzzCoverageArg,
    /// Seed/regression corpus directory.
    #[arg(long, value_name = "path")]
    corpus: Option<PathBuf>,
    /// Stop at the first finding, or collect findings within the run bound.
    #[arg(long, value_enum, value_name = "stop|collect")]
    on_violation: Option<SearchOnViolationArg>,
    /// Write the signed findings ledger to this path.
    #[arg(long, value_name = "path")]
    findings_out: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum SearchStrategyArg {
    /// Breadth-first frontier expansion.
    #[default]
    Bfs,
    /// Depth-first frontier expansion.
    Dfs,
    /// Coverage-guided frontier expansion.
    Guided,
}

impl SearchStrategyArg {
    fn engine_strategy(self) -> crucible::SearchStrategy {
        match self {
            Self::Bfs => crucible::SearchStrategy::BreadthFirst,
            Self::Dfs => crucible::SearchStrategy::DepthFirst,
            Self::Guided => crucible::SearchStrategy::CoverageGuided,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Bfs => "bfs",
            Self::Dfs => "dfs",
            Self::Guided => "guided",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum SearchOnViolationArg {
    /// Stop at the first counterexample.
    #[default]
    Stop,
    /// Collect counterexamples within the budget.
    Collect,
}

impl SearchOnViolationArg {
    fn label(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Collect => "collect",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum FuzzCoverageArg {
    /// Use black-box basic-block coverage feedback.
    #[default]
    BasicBlock,
}

impl FuzzCoverageArg {
    fn label(self) -> &'static str {
        match self {
            Self::BasicBlock => "basic-block",
        }
    }
}

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
    /// Minimize the selected representative for every cluster.
    All,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
#[command(group(
    ArgGroup::new("debug_coordinate")
        .args(["at", "at_event", "at_failure", "at_checkpoint"])
        .multiple(false)
), group(
    ArgGroup::new("debug_target")
        .args(["target", "session"])
        .required(true)
        .multiple(false)
))]
struct DebugArgs {
    /// Attach to this artifact or savepoint.
    #[arg(value_name = "ARTIFACT|SAVEPOINT", conflicts_with = "session")]
    target: Option<String>,
    /// Attach to a running daemon session by id:epoch:64-lowercase-hex-seed.
    #[arg(long, value_name = "SESSION")]
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
    /// Authorize an explicit non-canonical debug fork.
    #[arg(long, action = ArgAction::SetTrue)]
    allow_mutate: bool,
    /// Bound reverse-step replay distance.
    #[arg(long, value_name = "N")]
    checkpoint_stride: Option<u64>,
    /// Record the non-canonical guest channel to a new transcript file.
    #[arg(long, value_name = "PATH")]
    record_transcript: Option<PathBuf>,
    /// Fail when the guest agent produces no response for this duration.
    #[arg(long, value_name = "dur")]
    guest_idle_timeout: Option<String>,
    #[command(subcommand)]
    verb: Option<DebugVerbArgs>,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum DebugVerbArgs {
    /// Open the mediated gdbstub channel.
    AttachGdb,
    /// Explicitly fork a non-canonical whole-world debug branch.
    ForkDebug,
    /// Move to another debug coordinate.
    Goto {
        /// Virtual-time, event-log, or node-icount coordinate.
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
    /// Execute an argv-based command through the guest debug agent.
    Exec {
        /// Program and arguments, without shell parsing.
        #[arg(required = true, trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// Open an interactive command on a guest PTY.
    Pty {
        /// Initial terminal columns.
        #[arg(long, default_value_t = 80)]
        columns: u16,
        /// Initial terminal rows.
        #[arg(long, default_value_t = 24)]
        rows: u16,
        /// Program and arguments, without shell parsing.
        #[arg(required = true, trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// Bridge stdin/stdout to the guest agent's configured SSH server.
    Ssh,
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
    /// Address to bind the API (21) on. Required.
    #[arg(long, value_name = "addr", required = true)]
    listen: String,
    /// Concurrency cap on live sessions.
    #[arg(long, value_name = "n")]
    max_sessions: Option<usize>,
    /// Host sessions with the packaged production QEMU lifecycle.
    #[arg(long, action = ArgAction::SetTrue)]
    production_qemu: bool,
    /// Cap production-QEMU RUNs at this deterministic icount interval.
    #[arg(long, value_name = "icount")]
    qemu_rendezvous_icount: Option<u64>,
    /// Accept only read-only API calls (query/watch); no mutate.
    #[arg(long, action = ArgAction::SetTrue)]
    read_only: bool,
    /// Server certificate chain for authenticated remote access.
    #[arg(long, value_name = "path")]
    tls_cert: Option<PathBuf>,
    /// Server private key for authenticated remote access.
    #[arg(long, value_name = "path")]
    tls_key: Option<PathBuf>,
    /// CA certificate used to authenticate remote clients.
    #[arg(long, value_name = "path")]
    client_ca: Option<PathBuf>,
    /// Permit cleartext access on this explicitly trusted bind address.
    #[arg(long, action = ArgAction::SetTrue)]
    trusted_unauthenticated_bind: bool,
    /// Map a client certificate fingerprint to debugger capabilities.
    #[arg(long, value_name = "sha256=capability,...")]
    debug_role: Vec<String>,
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

    fn label(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Verify => "verify",
            Self::Selftest => "selftest",
            Self::Save => "save",
            Self::Resume => "resume",
            Self::Fork => "fork",
            Self::Replay => "replay",
            Self::Search => "search",
            Self::Fuzz => "fuzz",
            Self::Triage => "triage",
            Self::Debug => "debug",
            Self::Serve => "serve",
            Self::Completions => "completions",
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
                SessionCommandKind::StepQuantum,
                SessionCommandKind::StepDuration,
                SessionCommandKind::SetBreakpoint,
                SessionCommandKind::CreateSavepoint,
                SessionCommandKind::Stop,
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
                SessionCommandKind::StepQuantum,
                SessionCommandKind::StepDuration,
                SessionCommandKind::Continue,
                SessionCommandKind::Stop,
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

#[path = "cli/artifact.rs"]
mod cli_artifact;
#[path = "cli/backend.rs"]
mod cli_backend;
#[path = "cli/control.rs"]
mod cli_control;
#[path = "cli/dispatch.rs"]
mod cli_dispatch;
#[path = "cli/exploration.rs"]
mod cli_exploration;
#[path = "cli/planning.rs"]
mod cli_planning;
#[path = "cli/replay.rs"]
mod cli_replay;
#[path = "cli/report.rs"]
mod cli_report;
#[path = "cli/resume_fork.rs"]
mod cli_resume_fork;
#[path = "cli/run_save.rs"]
mod cli_run_save;
#[path = "cli/triage_debug.rs"]
mod cli_triage_debug;
#[path = "cli/verify_serve.rs"]
mod cli_verify_serve;

use cli_artifact::*;
use cli_backend::*;
use cli_control::*;
use cli_dispatch::*;
use cli_exploration::*;
use cli_planning::*;
use cli_replay::*;
use cli_report::*;
use cli_resume_fork::*;
use cli_run_save::*;
use cli_triage_debug::*;
use cli_verify_serve::*;

mod null_operation_recorder;
use null_operation_recorder::*;
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
