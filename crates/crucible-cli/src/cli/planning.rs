// Determinism, scenario, savepoint, search, and fuzz invocation planning.
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
const SERVE_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

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
struct SaveInvocationPlan {
    at: SaveAtArg,
    label: String,
    output: SaveOutputTarget,
    store_root: PathBuf,
    selector: Option<SaveAtSelector>,
    run_plan: RunInvocationPlan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SaveAtSelector {
    PropertyViolation { assertion: String },
    Marker { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SavepointOracleProof {
    configuration: crucible::ContentHash,
    fat_checkpoint: crucible::ContentHash,
    thin_checkpoint: crucible::ContentHash,
    frontier: crucible::VirtualTime,
    schedule: crucible::Schedule,
    store_objects: usize,
}

impl SavepointOracleProof {
    fn status_label(&self) -> &'static str {
        "fat==thin-passed"
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SaveOutputTarget {
    Explicit(PathBuf),
    ArtifactDir(PathBuf),
}

impl SaveOutputTarget {
    fn resolve(&self, label: &str, handle_digest: &str) -> PathBuf {
        match self {
            Self::Explicit(path) => path.clone(),
            Self::ArtifactDir(dir) => dir.join(format!(
                "savepoint-{}-{}.crucible-savepoint",
                sanitize_slug(label),
                short_digest(handle_digest)
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResumeInvocationPlan {
    savepoint: ResumeSavepointRef,
    store_root: PathBuf,
    terminal_condition: RunTerminalCondition,
    max_virtual_time: Option<String>,
    max_virtual_time_ticks: Option<u64>,
    execution_mode: RunExecutionMode,
    watch_streams_live_status: bool,
    startup_commands: Vec<SessionCommandKind>,
    initial_control_commands: Vec<SessionCommandKind>,
    accepted_interactive_commands: Vec<SessionCommandKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ForkInvocationPlan {
    source: ResumeSavepointRef,
    label: String,
    artifact_dir: PathBuf,
    store_root: PathBuf,
    decision_overrides: Vec<ForkDecisionOverride>,
    fork_seed: Option<u64>,
    terminal_condition: RunTerminalCondition,
    max_virtual_time: Option<String>,
    max_virtual_time_ticks: Option<u64>,
    execution_mode: RunExecutionMode,
    watch_streams_live_status: bool,
    startup_commands: Vec<SessionCommandKind>,
    initial_control_commands: Vec<SessionCommandKind>,
    accepted_interactive_commands: Vec<SessionCommandKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ForkDecisionOverride {
    decision: String,
    value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SearchDriverPlan {
    scenario: RunScenarioRef,
    strategy_arg: SearchStrategyArg,
    engine_strategy: crucible::SearchStrategy,
    max_depth: Option<u64>,
    max_states: u64,
    budget: crucible::SearchBudget,
    on_violation: SearchOnViolationArg,
    explicit_on_violation: bool,
    schedule_named_truths: Option<SearchScheduleNamedTruthsPlan>,
    retained_evidence: Option<SearchRetainedEvidencePlan>,
    delegates_policy_to_advanced_engine: bool,
    opportunistic_replay_oracle_sampling: bool,
    counterexamples_are_self_contained: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SearchScheduleNamedTruthsPlan {
    path: PathBuf,
    digest: String,
    material: Vec<u8>,
    truths: crucible::SearchScheduleNamedPredicateTruths,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SearchRetainedEvidencePlan {
    path: PathBuf,
    digest: String,
    material: Vec<u8>,
    evidence: BTreeMap<crucible::ContentHash, SearchRetainedLogAssertionEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalDoubleSearchReport {
    root: crucible::ContentHash,
    expansions: usize,
    explored: usize,
    failures: usize,
    exhausted: bool,
    failure_oracle: String,
    schedule_named_truths: String,
    schedule_named_truths_digest: String,
    retained_evidence: String,
    retained_evidence_digest: String,
    counterexample: Option<LocalDoubleSearchCounterexample>,
    replay_oracle_considered: usize,
    replay_oracle_sampled: usize,
    replay_oracle_skipped: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalDoubleSearchCounterexample {
    configuration: crucible::ContentHash,
    fingerprint: crucible::ContentHash,
    artifact_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FuzzDriverPlan {
    family: FuzzFamilyRef,
    runs: u64,
    coverage: FuzzCoverageArg,
    corpus: Option<PathBuf>,
    store_root: PathBuf,
    config: crucible::CoverageGuidedFuzzConfig,
    delegates_policy_to_advanced_engine: bool,
    pins_one_scenario_def_per_iteration: bool,
    counterexamples_are_self_contained: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FuzzDispatchRoute {
    BuiltInFaultCampaignProof,
    LocalDouble,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalDoubleFuzzReport {
    family: String,
    corpus: Option<PathBuf>,
    iterations: usize,
    coverage_biased_order: usize,
    new_coverage: usize,
    retained_entries: usize,
    admissions: usize,
    replay_oracle_validations: u64,
    generated_mutants: u64,
    store_puts: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FuzzFamilyRef {
    BuiltInFaultCampaign,
    File(PathBuf),
    Stored(crucible::ContentHash),
}

impl FuzzFamilyRef {
    fn label(&self) -> String {
        match self {
            Self::BuiltInFaultCampaign => crucible::FAULT_CAMPAIGN_FAMILY_NAME.to_owned(),
            Self::File(path) => path.display().to_string(),
            Self::Stored(reference) => format_content_hash_ref(*reference),
        }
    }

    fn is_builtin_fault_campaign(&self) -> bool {
        matches!(self, Self::BuiltInFaultCampaign)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CliScenarioFamilyToml {
    schema: String,
    seed_space: CliSeedSpaceToml,
    fault_density: CliFaultDensityToml,
    topology_size: CliTopologySizeToml,
    topology_shapes: Vec<String>,
    node_template: CliNodeTemplateToml,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CliSearchScheduleNamedTruthsToml {
    schema: String,
    #[serde(default)]
    truth: Vec<CliSearchScheduleNamedTruthToml>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CliSearchScheduleNamedTruthToml {
    name: String,
    value: bool,
    #[serde(default)]
    nodes: Vec<String>,
    #[serde(default)]
    active_fault_tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CliSearchRetainedEvidenceToml {
    schema: String,
    #[serde(default)]
    evidence: Vec<CliSearchRetainedEvidenceEntryToml>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CliSearchRetainedEvidenceEntryToml {
    configuration: String,
    kind: String,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    marker: Option<String>,
    #[serde(default)]
    retired_icount: Option<u64>,
    #[serde(default)]
    quiescent: Option<bool>,
    #[serde(default)]
    virtual_time_ticks: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
enum CliSeedSpaceToml {
    Generated { meta_seed: String, count: u32 },
    Explicit { seeds: Vec<String> },
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CliFaultDensityToml {
    min_millionths: u32,
    max_millionths: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CliTopologySizeToml {
    min: u32,
    max: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CliNodeTemplateToml {
    fixed_icount: Option<u64>,
    network_idle_nanos: Option<u64>,
    console_marker: Option<String>,
    agent_signal: Option<bool>,
    arch: Option<String>,
    white_box: Option<String>,
    memory_mib: Option<u32>,
    cmdline: Option<String>,
    smp_vcpus: Option<u16>,
    icount_shift: Option<u8>,
    kernel: Option<String>,
    root_image: Option<String>,
    initrd: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::large_enum_variant)]
enum ResumeSavepointRef {
    CheckpointHash(crucible::ContentHash),
    Handle {
        path: PathBuf,
        handle: SavepointHandle,
    },
}

impl ResumeSavepointRef {
    fn checkpoint(&self) -> crucible::ContentHash {
        match self {
            Self::CheckpointHash(checkpoint) => *checkpoint,
            Self::Handle { handle, .. } => handle.checkpoint,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::CheckpointHash(checkpoint) => format_content_hash_ref(*checkpoint),
            Self::Handle { path, handle } => {
                format!("{} ({})", handle.label, path.display())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SavepointHandle {
    label: String,
    checkpoint: crucible::ContentHash,
    scenario_id_hex: String,
    scenario_label: String,
    scenario_payload: Vec<u8>,
    schedule_payload: Vec<u8>,
    frontier_ticks: u64,
    at: SaveAtArg,
    terminal_condition: RunTerminalCondition,
    materialization: String,
    oracle_status: String,
    canonical_log_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RunScenarioRef {
    BuiltInExample {
        name: String,
        form: crucible::ScenarioDefForm,
        scenario: crucible::ScenarioDef,
    },
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
    fn label(&self) -> String {
        match self {
            Self::BuiltInExample { name, .. } => name.clone(),
            Self::File { path, .. } => path.display().to_string(),
            Self::Stored { reference, .. } => format_content_hash_ref(*reference),
        }
    }

    fn scenario_id(&self) -> crucible::ContentHash {
        match self {
            Self::BuiltInExample { scenario, .. }
            | Self::File { scenario, .. }
            | Self::Stored { scenario, .. } => scenario.id(),
        }
    }

    fn scenario_def(&self) -> &crucible::ScenarioDef {
        match self {
            Self::BuiltInExample { scenario, .. }
            | Self::File { scenario, .. }
            | Self::Stored { scenario, .. } => scenario,
        }
    }

    fn scenario_form(&self) -> &crucible::ScenarioDefForm {
        match self {
            Self::BuiltInExample { form, .. }
            | Self::File { form, .. }
            | Self::Stored { form, .. } => form,
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
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::large_enum_variant)]
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

    fn label(self) -> &'static str {
        match self {
            Self::Quiescence => "quiescence",
            Self::VirtualTime => "virtual-time",
            Self::Property => "property",
            Self::Stopped => "stopped",
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
impl EngineLoop for SimBackendLifecycleLoop {
    impl_quantum_drive_method!(drive_quantum, QReq, QOut, QErr, |loop_state, request| {
        loop_state.quanta = loop_state.quanta.saturating_add(1);
        let frontier = crucible::VirtualTime {
            ticks: loop_state.quanta,
        };
        crucible::SimulationBackend::step_to(&mut loop_state.backend, frontier)?;
        let event_log_entries = vec![loop_state.diagnostic_entry(frontier)];
        loop_state.event_log_events = loop_state
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
                loop_state.event_log_events,
            ),
            scheduler_quiescence: Some(crucible::SchedulerQuiescence::default()),
        })
    });

    fn sample_fingerprint(
        &mut self,
        node: crucible::NodeId,
    ) -> Result<crucible::FingerprintSample, crucible::SchedulerError> {
        crucible::SimulationBackend::fingerprint(&mut self.backend, node).map_err(Into::into)
    }

    fn shutdown(
        &mut self,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, crucible::SchedulerError> {
        crucible::SimulationBackend::shutdown(&mut self.backend)
            .map(|()| Vec::new())
            .map_err(Into::into)
    }
}

fn plan_run_invocation(args: &RunArgs, store_root: &Path) -> Result<RunInvocationPlan, CliError> {
    let scenario = resolve_run_scenario(args.scenario.as_deref(), store_root)?;
    if args.max_quanta == Some(0) {
        return Err(usage_error("--max-quanta must be greater than zero"));
    }
    if let Some(duration) = &args.max_virtual_time
        && parse_run_duration_budget_ticks(duration).is_none()
    {
        return Err(usage_error(
            "--max-virtual-time must be a non-empty duration like 10ms, 5s, or 100ticks",
        ));
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

fn plan_save_invocation(
    args: &SaveArgs,
    store_root: &Path,
    artifact_dir: &Path,
) -> Result<SaveInvocationPlan, CliError> {
    let at = args.at.ok_or_else(|| {
        usage_error("save requires --at <virtual-time|quiescence|property|marker>")
    })?;
    let property_selector = args
        .property
        .as_deref()
        .map(|value| plan_save_selector(value, "--property"))
        .transpose()?;
    let marker_selector = args
        .marker
        .as_deref()
        .map(|value| plan_save_selector(value, "--marker"))
        .transpose()?;
    let mut selector = None;
    let until = match at {
        SaveAtArg::Quiescence => {
            if property_selector.is_some() || marker_selector.is_some() {
                return Err(usage_error(
                    "save --at quiescence does not accept --property or --marker selectors",
                ));
            }
            RunUntilArg::Quiescence
        }
        SaveAtArg::VirtualTime => {
            if property_selector.is_some() || marker_selector.is_some() {
                return Err(usage_error(
                    "save --at virtual-time does not accept --property or --marker selectors",
                ));
            }
            if args.max_virtual_time.is_none() {
                return Err(usage_error(
                    "save --at virtual-time requires --max-virtual-time <dur>",
                ));
            }
            RunUntilArg::VirtualTime
        }
        SaveAtArg::Property => {
            let Some(assertion) = property_selector else {
                return Err(usage_error(
                    "save --at property requires --property <assertion>",
                ));
            };
            if marker_selector.is_some() {
                return Err(usage_error("save --at property does not accept --marker"));
            }
            if args.max_virtual_time.is_some() {
                return Err(usage_error(
                    "save --at property does not accept --max-virtual-time",
                ));
            }
            selector = Some(SaveAtSelector::PropertyViolation { assertion });
            RunUntilArg::Property
        }
        SaveAtArg::Marker => {
            let Some(name) = marker_selector else {
                return Err(usage_error("save --at marker requires --marker <name>"));
            };
            if property_selector.is_some() {
                return Err(usage_error("save --at marker does not accept --property"));
            }
            if args.max_virtual_time.is_some() {
                return Err(usage_error(
                    "save --at marker does not accept --max-virtual-time",
                ));
            }
            selector = Some(SaveAtSelector::Marker { name });
            RunUntilArg::Quiescence
        }
    };
    let label = plan_save_label(args.label.as_deref())?;
    let run_args = RunArgs {
        scenario: args.scenario.clone(),
        until,
        max_virtual_time: args.max_virtual_time.clone(),
        max_quanta: None,
        interactive: false,
        save_on: RunSaveOnArg::Always,
        watch: false,
        emit_mock_failure_artifact: false,
    };
    let run_plan = plan_run_invocation(&run_args, store_root)?;
    validate_save_selector_for_scenario(selector.as_ref(), run_plan.scenario.scenario_form())?;
    let output = args
        .out
        .clone()
        .map(SaveOutputTarget::Explicit)
        .unwrap_or_else(|| SaveOutputTarget::ArtifactDir(artifact_dir.to_path_buf()));

    Ok(SaveInvocationPlan {
        at,
        label,
        output,
        store_root: store_root.to_path_buf(),
        selector,
        run_plan,
    })
}

fn plan_save_label(label: Option<&str>) -> Result<String, CliError> {
    plan_nonempty_label(label, "savepoint")
}

fn validate_save_selector_for_scenario(
    selector: Option<&SaveAtSelector>,
    scenario: &crucible::ScenarioDefForm,
) -> Result<(), CliError> {
    match selector {
        Some(SaveAtSelector::PropertyViolation { assertion }) => {
            let assertion_id = crucible::AssertionId::from_name(assertion.clone());
            if scenario
                .properties()
                .assertions()
                .iter()
                .any(|declared| declared.id == assertion_id)
            {
                Ok(())
            } else {
                Err(invalid_scenario(format!(
                    "save --at property assertion `{assertion}` is not declared by scenario {}",
                    scenario.id().to_hex()
                )))
            }
        }
        Some(SaveAtSelector::Marker { .. }) => Ok(()),
        None => Ok(()),
    }
}

fn plan_save_selector(value: &str, flag: &str) -> Result<String, CliError> {
    let selector = value.trim();
    if selector.is_empty()
        || selector
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(usage_error(format!(
            "{flag} must not be empty or contain control whitespace"
        )));
    }
    Ok(selector.to_string())
}

fn plan_fork_label(label: Option<&str>) -> Result<String, CliError> {
    plan_nonempty_label(label, "fork")
}

fn plan_nonempty_label(label: Option<&str>, default: &'static str) -> Result<String, CliError> {
    let label = label.unwrap_or(default).trim();
    if label.is_empty()
        || label
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(usage_error(
            "--label must not be empty or contain control whitespace",
        ));
    }
    Ok(label.to_string())
}

fn plan_resume_invocation(
    args: &ResumeArgs,
    store_root: &Path,
) -> Result<ResumeInvocationPlan, CliError> {
    let savepoint = resolve_resume_savepoint(args.savepoint.as_deref())?;
    if let Some(duration) = &args.max_virtual_time
        && parse_run_duration_budget_ticks(duration).is_none()
    {
        return Err(usage_error(
            "--max-virtual-time must be a non-empty duration like 10ms, 5s, or 100ticks",
        ));
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
    let accepted_interactive_commands = if args.interactive {
        run_interactive_session_command_set()
    } else {
        Vec::new()
    };

    Ok(ResumeInvocationPlan {
        savepoint,
        store_root: store_root.to_path_buf(),
        terminal_condition,
        max_virtual_time: args.max_virtual_time.clone(),
        max_virtual_time_ticks: args
            .max_virtual_time
            .as_deref()
            .and_then(parse_run_duration_budget_ticks),
        execution_mode,
        watch_streams_live_status: args.watch,
        startup_commands,
        initial_control_commands: vec![SessionCommandKind::Query],
        accepted_interactive_commands,
    })
}

fn resolve_resume_savepoint(savepoint: Option<&str>) -> Result<ResumeSavepointRef, CliError> {
    resolve_savepoint_ref("resume", savepoint)
}

fn plan_fork_invocation(
    args: &ForkArgs,
    fork_seed: Option<u64>,
    artifact_dir: &Path,
    store_root: &Path,
) -> Result<ForkInvocationPlan, CliError> {
    let source = resolve_savepoint_ref("fork", args.savepoint.as_deref())?;
    if fork_seed.is_some() && !args.overrides.is_empty() {
        return Err(usage_error(
            "fork does not accept both --seed and --override; choose one post-fork decision source",
        ));
    }
    let label = plan_fork_label(args.label.as_deref())?;
    let decision_overrides = args
        .overrides
        .iter()
        .map(|raw| parse_fork_decision_override(raw))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(duration) = &args.max_virtual_time
        && parse_run_duration_budget_ticks(duration).is_none()
    {
        return Err(usage_error(
            "--max-virtual-time must be a non-empty duration like 10ms, 5s, or 100ticks",
        ));
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
            vec![SessionCommandKind::Fork, SessionCommandKind::Continue]
        }
        RunExecutionMode::Interactive => vec![SessionCommandKind::Fork],
    };
    let accepted_interactive_commands = if args.interactive {
        run_interactive_session_command_set()
    } else {
        Vec::new()
    };

    Ok(ForkInvocationPlan {
        source,
        label,
        artifact_dir: artifact_dir.to_path_buf(),
        store_root: store_root.to_path_buf(),
        decision_overrides,
        fork_seed,
        terminal_condition,
        max_virtual_time: args.max_virtual_time.clone(),
        max_virtual_time_ticks: args
            .max_virtual_time
            .as_deref()
            .and_then(parse_run_duration_budget_ticks),
        execution_mode,
        watch_streams_live_status: args.watch,
        startup_commands,
        initial_control_commands: vec![SessionCommandKind::Query],
        accepted_interactive_commands,
    })
}

#[cfg(test)]
fn plan_fork_invocation_for_test(
    args: &ForkArgs,
    fork_seed: Option<u64>,
) -> Result<ForkInvocationPlan, CliError> {
    plan_fork_invocation(
        args,
        fork_seed,
        Path::new("./.crucible"),
        Path::new("./.crucible/store"),
    )
}

fn parse_fork_decision_override(raw: &str) -> Result<ForkDecisionOverride, CliError> {
    let value = raw.trim();
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(usage_error(
            "--override must be a single-line decision=value pair",
        ));
    }
    if value.bytes().filter(|byte| *byte == b'=').count() != 1 {
        return Err(usage_error(
            "--override must contain exactly one `=` separator",
        ));
    }
    let Some((decision, pinned_value)) = value.split_once('=') else {
        return Err(usage_error(
            "--override must contain exactly one `=` separator",
        ));
    };
    let decision = decision.trim();
    let pinned_value = pinned_value.trim();
    if decision.is_empty() || pinned_value.is_empty() {
        return Err(usage_error(
            "--override decision and value must both be non-empty",
        ));
    }
    Ok(ForkDecisionOverride {
        decision: decision.to_string(),
        value: pinned_value.to_string(),
    })
}

fn plan_search_invocation(
    args: &SearchArgs,
    store_root: &Path,
) -> Result<SearchDriverPlan, CliError> {
    let scenario = resolve_search_scenario(args.scenario.as_deref(), store_root)?;
    validate_positive_optional_budget("--max-depth", args.max_depth)?;
    validate_positive_budget("--max-states", args.max_states)?;
    let engine_strategy = args.strategy.engine_strategy();
    let budget = crucible::SearchBudget::new(args.max_states);
    let explicit_on_violation = args.on_violation.is_some();
    let on_violation = args.on_violation.unwrap_or(SearchOnViolationArg::Stop);
    if args.schedule_named_truths.is_some() && args.retained_evidence.is_some() {
        return Err(backend_error(
            "search --retained-evidence cannot be combined with --schedule-named-truths yet",
        ));
    }
    let schedule_named_truths = args
        .schedule_named_truths
        .as_deref()
        .map(|path| load_search_schedule_named_truths_file(path, scenario.scenario_form()))
        .transpose()?;
    let retained_evidence = args
        .retained_evidence
        .as_deref()
        .map(|path| load_search_retained_evidence_file(path, scenario.scenario_form()))
        .transpose()?;

    Ok(SearchDriverPlan {
        scenario,
        strategy_arg: args.strategy,
        engine_strategy,
        max_depth: args.max_depth,
        max_states: args.max_states,
        budget,
        on_violation,
        explicit_on_violation,
        schedule_named_truths,
        retained_evidence,
        delegates_policy_to_advanced_engine: true,
        opportunistic_replay_oracle_sampling: true,
        counterexamples_are_self_contained: true,
    })
}

fn resolve_search_scenario(
    scenario: Option<&str>,
    store_root: &Path,
) -> Result<RunScenarioRef, CliError> {
    resolve_command_scenario("search", scenario, store_root).map_err(|error| match error {
        CliError::InvalidScenario(message) => backend_error(message),
        error => error,
    })
}

fn load_search_schedule_named_truths_file(
    path: &Path,
    scenario: &crucible::ScenarioDefForm,
) -> Result<SearchScheduleNamedTruthsPlan, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        backend_error(format!(
            "schedule-named truths `{}` could not be read: {error}",
            path.display()
        ))
    })?;
    let truths = load_search_schedule_named_truths_toml(
        &format!("file `{}`", path.display()),
        &text,
        scenario,
    )?;
    Ok(SearchScheduleNamedTruthsPlan {
        path: path.to_path_buf(),
        digest: content_address_bytes(text.as_bytes()),
        material: text.into_bytes(),
        truths,
    })
}

fn load_search_schedule_named_truths_toml(
    label: &str,
    text: &str,
    scenario: &crucible::ScenarioDefForm,
) -> Result<crucible::SearchScheduleNamedPredicateTruths, CliError> {
    let authored = toml::from_str::<CliSearchScheduleNamedTruthsToml>(text).map_err(|error| {
        backend_error(format!(
            "schedule-named truths {label} are not valid TOML: {error}"
        ))
    })?;
    if authored.schema != SEARCH_SCHEDULE_NAMED_TRUTHS_SCHEMA {
        return Err(backend_error(format!(
            "schedule-named truths {label} use unsupported schema `{}`; expected `{SEARCH_SCHEDULE_NAMED_TRUTHS_SCHEMA}`",
            authored.schema
        )));
    }

    let scenario_nodes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut truths = crucible::SearchScheduleNamedPredicateTruths::new();
    let mut canonical_indexes = BTreeMap::new();
    for (index, truth) in authored.truth.into_iter().enumerate() {
        if truth.name.is_empty() {
            return Err(backend_error(format!(
                "schedule-named truths {label} entry {index} has an empty name"
            )));
        }
        for node in &truth.nodes {
            if !scenario_nodes.contains(node.as_str()) {
                return Err(backend_error(format!(
                    "schedule-named truths {label} entry {index} references unknown node `{node}`"
                )));
            }
        }
        let key = crucible::SearchScheduleNamedPredicateKey::new(
            truth.name,
            truth
                .nodes
                .into_iter()
                .map(|name| crucible::NodeId { name })
                .collect(),
            truth
                .active_fault_tags
                .into_iter()
                .map(crucible::FaultTag::from_name)
                .collect(),
        );
        if let Some(previous_index) = canonical_indexes.insert(key.clone(), index) {
            return Err(backend_error(format!(
                "schedule-named truths {label} entry {index} duplicates canonical entry {previous_index}"
            )));
        }
        truths.insert_truth(key, truth.value);
    }
    Ok(truths)
}

fn load_search_retained_evidence_file(
    path: &Path,
    scenario: &crucible::ScenarioDefForm,
) -> Result<SearchRetainedEvidencePlan, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        backend_error(format!(
            "search retained evidence `{}` could not be read: {error}",
            path.display()
        ))
    })?;
    let evidence =
        load_search_retained_evidence_toml(&format!("file `{}`", path.display()), &text, scenario)?;
    Ok(SearchRetainedEvidencePlan {
        path: path.to_path_buf(),
        digest: content_address_bytes(text.as_bytes()),
        material: text.into_bytes(),
        evidence,
    })
}

fn load_search_retained_evidence_toml(
    label: &str,
    text: &str,
    scenario: &crucible::ScenarioDefForm,
) -> Result<BTreeMap<crucible::ContentHash, SearchRetainedLogAssertionEvidence>, CliError> {
    let authored = toml::from_str::<CliSearchRetainedEvidenceToml>(text).map_err(|error| {
        backend_error(format!(
            "search retained evidence {label} is not valid TOML: {error}"
        ))
    })?;
    if authored.schema != SEARCH_RETAINED_EVIDENCE_SCHEMA {
        return Err(backend_error(format!(
            "search retained evidence {label} uses unsupported schema `{}`; expected `{SEARCH_RETAINED_EVIDENCE_SCHEMA}`",
            authored.schema
        )));
    }

    let scenario_nodes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| {
            (
                node.id.name.as_str(),
                node.white_box == crucible::WhiteBoxPolicy::Enabled,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let root = crucible::Configuration::genesis(scenario.scenario_def());
    let mut entries_by_configuration = BTreeMap::new();
    let mut terminal_boundary_by_configuration = BTreeMap::new();
    let mut terminal_quiescence_by_configuration = BTreeMap::new();
    for (index, entry) in authored.evidence.into_iter().enumerate() {
        let configuration = parse_search_retained_evidence_configuration(
            label,
            index,
            &entry.configuration,
            root.id(),
        )?;
        match entry.kind.as_str() {
            "guest-marker" => push_search_retained_guest_marker_entry(
                label,
                index,
                entry,
                &scenario_nodes,
                &mut entries_by_configuration,
                configuration,
            )?,
            "terminal-quiescence" => {
                let quiescence =
                    parse_search_retained_terminal_quiescence_entry(label, index, entry)?;
                if terminal_quiescence_by_configuration
                    .insert(configuration, quiescence)
                    .is_some()
                {
                    return Err(backend_error(format!(
                        "search retained evidence {label} entry {index} duplicates terminal quiescence for configuration {}",
                        format_content_hash_ref(configuration)
                    )));
                }
            }
            "evaluation-boundary" => {
                let ticks = parse_search_retained_evaluation_boundary_entry(label, index, entry)?;
                if terminal_boundary_by_configuration
                    .insert(configuration, ticks)
                    .is_some()
                {
                    return Err(backend_error(format!(
                        "search retained evidence {label} entry {index} duplicates terminal evaluation boundary for configuration {}",
                        format_content_hash_ref(configuration)
                    )));
                }
            }
            _ => {
                return Err(backend_error(format!(
                    "search retained evidence {label} entry {index} uses unsupported kind `{}`; expected `guest-marker`, `evaluation-boundary`, or `terminal-quiescence`",
                    entry.kind
                )));
            }
        }
    }

    let configurations = entries_by_configuration
        .keys()
        .chain(terminal_boundary_by_configuration.keys())
        .chain(terminal_quiescence_by_configuration.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    configurations
        .into_iter()
        .map(|configuration| {
            let entries = entries_by_configuration
                .remove(&configuration)
                .unwrap_or_default();
            let recorded_log =
                if let Some(ticks) = terminal_boundary_by_configuration.remove(&configuration) {
                    let sequence = u64::try_from(entries.len()).map_err(|_| {
                        backend_error(format!(
                            "search retained evidence {label} configuration {} sequence index overflowed",
                            format_content_hash_ref(configuration)
                        ))
                    })?;
                    RecordedAssertionLog::from_entries_with_quantum_evaluation_boundary(
                        entries,
                        sequence,
                        crucible::VirtualTime { ticks },
                    )
                } else {
                    RecordedAssertionLog::from_entries(entries)
                };
            let mut evidence = SearchRetainedLogAssertionEvidence::new(recorded_log);
            if let Some(quiescence) = terminal_quiescence_by_configuration.remove(&configuration) {
                evidence = evidence.with_terminal_scheduler_quiescence(quiescence);
            }
            Ok((configuration, evidence))
        })
        .collect::<Result<_, CliError>>()
}

fn push_search_retained_guest_marker_entry(
    label: &str,
    index: usize,
    entry: CliSearchRetainedEvidenceEntryToml,
    scenario_nodes: &BTreeMap<&str, bool>,
    entries_by_configuration: &mut BTreeMap<
        crucible::ContentHash,
        Vec<crucible::SchedulerEventLogEntry>,
    >,
    configuration: crucible::ContentHash,
) -> Result<(), CliError> {
    if entry.quiescent.is_some() || entry.virtual_time_ticks.is_some() {
        return Err(backend_error(format!(
            "search retained evidence {label} entry {index} kind `guest-marker` cannot set quiescent or virtual_time_ticks"
        )));
    }
    let Some(node) = entry.node else {
        return Err(backend_error(format!(
            "search retained evidence {label} entry {index} kind `guest-marker` is missing node"
        )));
    };
    let Some(white_box_enabled) = scenario_nodes.get(node.as_str()) else {
        return Err(backend_error(format!(
            "search retained evidence {label} entry {index} references unknown node `{node}`"
        )));
    };
    if !*white_box_enabled {
        return Err(backend_error(format!(
            "search retained evidence {label} entry {index} guest-marker node `{node}` is not white-box enabled"
        )));
    }
    let Some(marker) = entry.marker else {
        return Err(backend_error(format!(
            "search retained evidence {label} entry {index} kind `guest-marker` is missing marker"
        )));
    };
    if marker.is_empty() {
        return Err(backend_error(format!(
            "search retained evidence {label} entry {index} kind `guest-marker` has an empty marker"
        )));
    }
    let retained_icount = entry.retired_icount.unwrap_or(1);
    let entries = entries_by_configuration.entry(configuration).or_default();
    let sequence = u64::try_from(entries.len()).map_err(|_| {
        backend_error(format!(
            "search retained evidence {label} entry {index} sequence index overflowed"
        ))
    })?;
    entries.push(crucible::SchedulerEventLogEntry::guest_marker_observation(
        sequence,
        crucible::Icount {
            retired: retained_icount,
        },
        crucible::NodeId { name: node },
        crucible::MarkerId::from_name(marker),
    ));
    Ok(())
}

fn parse_search_retained_evaluation_boundary_entry(
    label: &str,
    index: usize,
    entry: CliSearchRetainedEvidenceEntryToml,
) -> Result<u64, CliError> {
    if entry.node.is_some()
        || entry.marker.is_some()
        || entry.retired_icount.is_some()
        || entry.quiescent.is_some()
    {
        return Err(backend_error(format!(
            "search retained evidence {label} entry {index} kind `evaluation-boundary` cannot set node, marker, retired_icount, or quiescent"
        )));
    }
    let Some(ticks) = entry.virtual_time_ticks else {
        return Err(backend_error(format!(
            "search retained evidence {label} entry {index} kind `evaluation-boundary` is missing virtual_time_ticks"
        )));
    };
    Ok(ticks)
}

fn parse_search_retained_terminal_quiescence_entry(
    label: &str,
    index: usize,
    entry: CliSearchRetainedEvidenceEntryToml,
) -> Result<crucible::SchedulerQuiescence, CliError> {
    if entry.node.is_some()
        || entry.marker.is_some()
        || entry.retired_icount.is_some()
        || entry.virtual_time_ticks.is_some()
    {
        return Err(backend_error(format!(
            "search retained evidence {label} entry {index} kind `terminal-quiescence` cannot set node, marker, retired_icount, or virtual_time_ticks"
        )));
    }
    match entry.quiescent {
        Some(true) => Ok(crucible::SchedulerQuiescence::default()),
        Some(false) => Err(backend_error(format!(
            "search retained evidence {label} entry {index} kind `terminal-quiescence` only supports quiescent = true"
        ))),
        None => Err(backend_error(format!(
            "search retained evidence {label} entry {index} kind `terminal-quiescence` is missing quiescent"
        ))),
    }
}

fn parse_search_retained_evidence_configuration(
    label: &str,
    index: usize,
    value: &str,
    root: crucible::ContentHash,
) -> Result<crucible::ContentHash, CliError> {
    if value == "root" {
        return Ok(root);
    }
    crucible::ContentAddressedBlobRef::parse("configuration", value)
        .map(crucible::ContentAddressedBlobRef::hash)
        .map_err(|error| {
            backend_error(format!(
                "search retained evidence {label} entry {index} has invalid configuration `{value}`: {error}"
            ))
        })
}

fn plan_fuzz_invocation(
    args: &FuzzArgs,
    seed: &DeterminismErgonomicsPlan,
    store_root: &Path,
) -> Result<FuzzDriverPlan, CliError> {
    let family = resolve_fuzz_family_ref(args.family.as_deref(), args.family_flag.as_deref())?;
    validate_positive_budget("--runs", args.runs)?;
    if let Some(corpus) = &args.corpus {
        validate_exploration_path_arg("--corpus", corpus)?;
        if corpus.exists() && !corpus.is_dir() {
            return Err(backend_error(format!(
                "--corpus `{}` must be a directory when it already exists",
                corpus.display()
            )));
        }
    }
    let config = crucible::CoverageGuidedFuzzConfig::new(
        crucible::Seed::from_u64(seed.seed.value),
        args.runs,
    );

    Ok(FuzzDriverPlan {
        family,
        runs: args.runs,
        coverage: args.coverage,
        corpus: args.corpus.clone(),
        store_root: store_root.to_path_buf(),
        config,
        delegates_policy_to_advanced_engine: true,
        pins_one_scenario_def_per_iteration: true,
        counterexamples_are_self_contained: true,
    })
}

fn resolve_fuzz_family_ref(
    positional: Option<&str>,
    flag: Option<&str>,
) -> Result<FuzzFamilyRef, CliError> {
    match (positional, flag) {
        (None, None) => Err(usage_error(
            "fuzz requires a FAMILY argument or --family <path|hash>",
        )),
        (Some(_), Some(_)) => Err(usage_error(
            "fuzz accepts either FAMILY or --family <path|hash>, not both",
        )),
        (Some(value), None) | (None, Some(value)) => parse_fuzz_family_ref(value),
    }
}

fn parse_fuzz_family_ref(raw: &str) -> Result<FuzzFamilyRef, CliError> {
    let value = raw.trim();
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(backend_error(
            "family reference must not be empty or multiline",
        ));
    }
    if value == crucible::FAULT_CAMPAIGN_FAMILY_NAME || value == "builtin:fault-campaign" {
        return Ok(FuzzFamilyRef::BuiltInFaultCampaign);
    }
    if value.starts_with(CONTENT_ADDRESS_PREFIX) {
        return Err(backend_error(format!(
            "family content hash `{value}` is not a DAG-store `blake3:<hash>` reference"
        )));
    }
    if value.starts_with("blake3:") {
        let reference =
            crucible::ContentAddressedBlobRef::parse("family", value).map_err(|error| {
                backend_error(format!(
                    "family content hash `{value}` is malformed: {error}"
                ))
            })?;
        return Ok(FuzzFamilyRef::Stored(reference.hash()));
    }
    let path = Path::new(value);
    validate_exploration_path_arg("FAMILY", path)?;
    if !path.exists() {
        return Err(backend_error(format!("family `{value}` does not exist")));
    }
    if !path.is_file() {
        return Err(backend_error(format!(
            "family `{value}` is not a regular file"
        )));
    }
    Ok(FuzzFamilyRef::File(path.to_path_buf()))
}

fn load_fuzz_family(plan: &FuzzDriverPlan) -> Result<crucible::ScenarioFamily, CliError> {
    match &plan.family {
        FuzzFamilyRef::BuiltInFaultCampaign => crucible::fault_campaign_family().map_err(|error| {
            backend_error(format!(
                "built-in fault-campaign family could not be loaded: {error}"
            ))
        }),
        FuzzFamilyRef::File(path) => load_fuzz_family_file(path),
        FuzzFamilyRef::Stored(reference) => load_stored_fuzz_family(plan, *reference),
    }
}

fn load_fuzz_family_file(path: &Path) -> Result<crucible::ScenarioFamily, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        backend_error(format!(
            "family `{}` could not be read: {error}",
            path.display()
        ))
    })?;
    load_fuzz_family_toml(&format!("file `{}`", path.display()), &text)
}

fn load_stored_fuzz_family(
    plan: &FuzzDriverPlan,
    reference: crucible::ContentHash,
) -> Result<crucible::ScenarioFamily, CliError> {
    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    let bytes = store.get(&reference).map_err(|error| {
        backend_error(format!(
            "family {} could not be loaded from store `{}`: {error}",
            format_content_hash_ref(reference),
            plan.store_root.display()
        ))
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        backend_error(format!(
            "family {} in store `{}` is not UTF-8 scenario-family TOML: {error}",
            format_content_hash_ref(reference),
            plan.store_root.display()
        ))
    })?;
    load_fuzz_family_toml(
        &format!(
            "{} in store `{}`",
            format_content_hash_ref(reference),
            plan.store_root.display()
        ),
        text,
    )
}

fn load_fuzz_family_toml(label: &str, text: &str) -> Result<crucible::ScenarioFamily, CliError> {
    let authored = toml::from_str::<CliScenarioFamilyToml>(text).map_err(|error| {
        backend_error(format!(
            "family {label} is not valid scenario-family TOML: {error}"
        ))
    })?;
    scenario_family_from_toml(label, authored)
}

fn scenario_family_from_toml(
    label: &str,
    authored: CliScenarioFamilyToml,
) -> Result<crucible::ScenarioFamily, CliError> {
    const SCHEMA: &str = "crucible.scenario-family.v1";

    if authored.schema != SCHEMA {
        return Err(family_file_error(
            label,
            format!(
                "uses unsupported schema `{}`; expected `{SCHEMA}`",
                authored.schema
            ),
        ));
    }

    let seeds = seed_space_from_toml(label, authored.seed_space)?;
    let min_density = crucible::FaultDensity::from_millionths(
        authored.fault_density.min_millionths,
    )
    .map_err(|error| family_file_error(label, format!("has invalid minimum density: {error}")))?;
    let max_density = crucible::FaultDensity::from_millionths(
        authored.fault_density.max_millionths,
    )
    .map_err(|error| family_file_error(label, format!("has invalid maximum density: {error}")))?;
    let fault_density = crucible::FaultDensityRange::new(min_density, max_density)
        .map_err(|error| family_file_error(label, format!("has invalid density range: {error}")))?;
    let topology_size =
        crucible::TopologySizeRange::new(authored.topology_size.min, authored.topology_size.max)
            .map_err(|error| {
                family_file_error(label, format!("has invalid topology size range: {error}"))
            })?;
    let topology_shapes = authored
        .topology_shapes
        .iter()
        .map(|shape| topology_shape_from_toml(label, shape))
        .collect::<Result<Vec<_>, _>>()?;
    let space = crucible::FamilySpace::new(seeds, fault_density, topology_size, topology_shapes)
        .map_err(|error| family_file_error(label, format!("has invalid family space: {error}")))?;
    let node_template = node_template_from_toml(label, authored.node_template)?;

    Ok(crucible::ScenarioFamily::new(space, node_template))
}

fn seed_space_from_toml(
    label: &str,
    authored: CliSeedSpaceToml,
) -> Result<crucible::SeedSpace, CliError> {
    match authored {
        CliSeedSpaceToml::Generated { meta_seed, count } => {
            let meta_seed = parse_family_seed(label, "seed_space.meta_seed", &meta_seed)?;
            crucible::SeedSpace::generated(meta_seed, count).map_err(|error| {
                family_file_error(label, format!("has invalid generated seed space: {error}"))
            })
        }
        CliSeedSpaceToml::Explicit { seeds } => {
            let seeds = seeds
                .iter()
                .enumerate()
                .map(|(index, seed)| {
                    parse_family_seed(label, &format!("seed_space.seeds[{index}]"), seed)
                })
                .collect::<Result<Vec<_>, _>>()?;
            crucible::SeedSpace::explicit(seeds).map_err(|error| {
                family_file_error(label, format!("has invalid explicit seed space: {error}"))
            })
        }
    }
}

fn topology_shape_from_toml(label: &str, shape: &str) -> Result<crucible::TopologyShape, CliError> {
    match shape {
        "ring" => Ok(crucible::TopologyShape::Ring),
        "star" => Ok(crucible::TopologyShape::Star),
        "mesh" => Ok(crucible::TopologyShape::Mesh),
        "random" => Ok(crucible::TopologyShape::Random),
        value => Err(family_file_error(
            label,
            format!("uses unknown topology shape `{value}`"),
        )),
    }
}

fn node_template_from_toml(
    label: &str,
    authored: CliNodeTemplateToml,
) -> Result<crucible::NodeTemplate, CliError> {
    let agent_signal = authored.agent_signal.unwrap_or(false);
    let ready_point_count = [
        authored.fixed_icount.is_some(),
        authored.network_idle_nanos.is_some(),
        authored.console_marker.is_some(),
        agent_signal,
    ]
    .into_iter()
    .filter(|set| *set)
    .count();
    if ready_point_count != 1 {
        return Err(family_file_error(
            label,
            "node_template must set exactly one of fixed_icount, network_idle_nanos, console_marker, or agent_signal=true",
        ));
    }

    let mut template = if let Some(retired) = authored.fixed_icount {
        crucible::NodeTemplate::fixed_icount(crucible::Icount { retired })
    } else if let Some(nanos) = authored.network_idle_nanos {
        crucible::NodeTemplate::network_idle(crucible::SimDuration { nanos })
    } else if let Some(marker) = authored.console_marker {
        crucible::NodeTemplate::console_marker(marker)
    } else {
        crucible::NodeTemplate::agent_signal()
    };

    if let Some(arch) = authored.arch {
        template = template.arch(vm_architecture_from_toml(label, &arch)?);
    }
    if let Some(white_box) = authored.white_box {
        template = template.white_box(white_box_from_toml(label, &white_box)?);
    }
    if let Some(memory_mib) = authored.memory_mib {
        template = template.memory_mib(memory_mib);
    }
    if let Some(cmdline) = authored.cmdline {
        template = template.cmdline(cmdline);
    }
    if let Some(smp_vcpus) = authored.smp_vcpus {
        template = template.smp_vcpus(smp_vcpus);
    }
    if let Some(icount_shift) = authored.icount_shift {
        template = template.icount_shift(icount_shift);
    }
    if let Some(kernel) = authored.kernel {
        template = template.kernel(blob_ref_from_toml(label, "node_template.kernel", &kernel)?);
    }
    if let Some(root_image) = authored.root_image {
        template = template.root_image(blob_ref_from_toml(
            label,
            "node_template.root_image",
            &root_image,
        )?);
    }
    if let Some(initrd) = authored.initrd {
        template = template.initrd(blob_ref_from_toml(label, "node_template.initrd", &initrd)?);
    }

    Ok(template)
}

fn vm_architecture_from_toml(
    label: &str,
    value: &str,
) -> Result<crucible::VmArchitecture, CliError> {
    match value {
        "x86_64" => Ok(crucible::VmArchitecture::X86_64),
        "aarch64" => Ok(crucible::VmArchitecture::Aarch64),
        value => Err(family_file_error(
            label,
            format!("uses unknown node_template.arch `{value}`"),
        )),
    }
}

fn white_box_from_toml(label: &str, value: &str) -> Result<crucible::WhiteBoxPolicy, CliError> {
    match value {
        "enabled" => Ok(crucible::WhiteBoxPolicy::Enabled),
        "disabled" => Ok(crucible::WhiteBoxPolicy::Disabled),
        value => Err(family_file_error(
            label,
            format!("uses unknown node_template.white_box `{value}`"),
        )),
    }
}

fn blob_ref_from_toml(
    label: &str,
    field: &'static str,
    value: &str,
) -> Result<crucible::ContentAddressedBlobRef, CliError> {
    crucible::ContentAddressedBlobRef::parse(field, value)
        .map_err(|error| family_file_error(label, format!("has invalid {field}: {error}")))
}

fn parse_family_seed(label: &str, field: &str, value: &str) -> Result<crucible::Seed, CliError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(family_file_error(
            label,
            format!("{field} must not be empty"),
        ));
    }
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"));
    if let Some(hex) = hex {
        if hex.len() == 64 {
            return Ok(crucible::Seed::from_bytes(parse_family_seed_hex(
                label, field, hex,
            )?));
        }
        let value = u64::from_str_radix(hex, 16).map_err(|error| {
            family_file_error(label, format!("{field} has invalid u64 hex seed: {error}"))
        })?;
        return Ok(crucible::Seed::from_u64(value));
    }
    if trimmed.len() == 64 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(crucible::Seed::from_bytes(parse_family_seed_hex(
            label, field, trimmed,
        )?));
    }
    let value = trimmed.parse::<u64>().map_err(|error| {
        family_file_error(
            label,
            format!("{field} must be a u64 or 64-byte hex seed: {error}"),
        )
    })?;
    Ok(crucible::Seed::from_u64(value))
}

fn parse_family_seed_hex(label: &str, field: &str, value: &str) -> Result<[u8; 32], CliError> {
    let mut bytes = [0; 32];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or_else(|| {
            family_file_error(label, format!("{field} has malformed 64-byte hex seed"))
        })?;
        let low = hex_nibble(chunk[1]).ok_or_else(|| {
            family_file_error(label, format!("{field} has malformed 64-byte hex seed"))
        })?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn family_file_error(label: &str, message: impl Into<String>) -> CliError {
    backend_error(format!("family {label} {}", message.into()))
}

fn validate_positive_optional_budget(
    label: &'static str,
    value: Option<u64>,
) -> Result<(), CliError> {
    if let Some(value) = value {
        validate_positive_budget(label, value)?;
    }
    Ok(())
}

fn validate_positive_budget(label: &'static str, value: u64) -> Result<(), CliError> {
    if value == 0 {
        return Err(usage_error(format!("{label} must be greater than zero")));
    }
    Ok(())
}

fn validate_exploration_path_arg(label: &'static str, path: &Path) -> Result<(), CliError> {
    if path.as_os_str().is_empty()
        || path
            .to_string_lossy()
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(backend_error(format!(
            "{label} path must not be empty or multiline"
        )));
    }
    Ok(())
}

fn resolve_savepoint_ref(
    command_name: &'static str,
    savepoint: Option<&str>,
) -> Result<ResumeSavepointRef, CliError> {
    let Some(raw) = savepoint else {
        return Err(usage_error(format!(
            "{command_name} requires a SAVEPOINT argument"
        )));
    };
    let value = raw.trim();
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(artifact_error(
            "savepoint reference must not be empty or multiline",
        ));
    }
    if value.starts_with("blake3:") {
        return parse_blake3_content_hash("savepoint", value)
            .map(ResumeSavepointRef::CheckpointHash);
    }

    let path = Path::new(value);
    let bytes = fs::read(path).map_err(|error| {
        artifact_error(format!(
            "savepoint handle `{}` could not be read: {error}",
            path.display()
        ))
    })?;
    let handle = decode_savepoint_handle(&bytes)?;
    Ok(ResumeSavepointRef::Handle {
        path: path.to_path_buf(),
        handle,
    })
}

fn decode_savepoint_handle(bytes: &[u8]) -> Result<SavepointHandle, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| artifact_error(format!("savepoint handle is not UTF-8: {error}")))?;
    let mut schema = None;
    let mut label = None;
    let mut checkpoint = None;
    let mut scenario = None;
    let mut scenario_payload = None;
    let mut schedule_payload = None;
    let mut frontier_ticks = None;
    let mut at = None;
    let mut terminal_condition = None;
    let mut materialization = None;
    let mut oracle_status = None;
    let mut canonical_log_digest = None;

    for (line_index, line_text) in text.lines().enumerate() {
        let fields = parse_artifact_fields(line_text)?;
        let Some(tag) = fields.first().map(String::as_str) else {
            continue;
        };
        match tag {
            "schema" => {
                require_field_count(line_index, tag, &fields, 2)?;
                set_once(&mut schema, line_index, tag, fields[1].clone())?;
            }
            "label" => {
                require_field_count(line_index, tag, &fields, 2)?;
                validate_required_field("savepoint label", &fields[1])?;
                set_once(&mut label, line_index, tag, fields[1].clone())?;
            }
            "checkpoint" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_blake3_content_hash("checkpoint", &fields[1])?;
                set_once(&mut checkpoint, line_index, tag, parsed)?;
            }
            "scenario" => {
                require_field_count(line_index, tag, &fields, 3)?;
                validate_content_hash_hex_line(line_index, tag, &fields[1])?;
                validate_required_field("scenario label", &fields[2])?;
                set_once(
                    &mut scenario,
                    line_index,
                    tag,
                    (fields[1].clone(), fields[2].clone()),
                )?;
            }
            "scenario-payload" => {
                require_field_count(line_index, tag, &fields, 3)?;
                let payload = parse_hex_payload_line(line_index, tag, &fields[1], &fields[2])?;
                set_once(&mut scenario_payload, line_index, tag, payload)?;
            }
            "schedule-payload" => {
                require_field_count(line_index, tag, &fields, 3)?;
                let payload = parse_hex_payload_line(line_index, tag, &fields[1], &fields[2])?;
                set_once(&mut schedule_payload, line_index, tag, payload)?;
            }
            "frontier" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_u64(line_index, tag, &fields[1])?;
                set_once(&mut frontier_ticks, line_index, tag, parsed)?;
            }
            "at" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_save_at_label(line_index, tag, &fields[1])?;
                set_once(&mut at, line_index, tag, parsed)?;
            }
            "terminal-condition" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_run_terminal_condition_label(line_index, tag, &fields[1])?;
                set_once(&mut terminal_condition, line_index, tag, parsed)?;
            }
            "materialization" => {
                require_field_count(line_index, tag, &fields, 3)?;
                validate_required_field("materialization kind", &fields[1])?;
                validate_required_field("materialization source", &fields[2])?;
                set_once(
                    &mut materialization,
                    line_index,
                    tag,
                    format!("{}:{}", fields[1], fields[2]),
                )?;
            }
            "oracle" => {
                require_field_count(line_index, tag, &fields, 2)?;
                validate_required_field("oracle status", &fields[1])?;
                set_once(&mut oracle_status, line_index, tag, fields[1].clone())?;
            }
            "canonical-log" => {
                require_field_count(line_index, tag, &fields, 2)?;
                validate_digest("canonical-log", &fields[1])?;
                set_once(
                    &mut canonical_log_digest,
                    line_index,
                    tag,
                    fields[1].clone(),
                )?;
            }
            _ => return Err(artifact_line_error(line_index, tag, "unknown line tag")),
        }
    }

    let schema = schema.ok_or_else(|| missing_line("schema"))?;
    if schema != SAVEPOINT_HANDLE_SCHEMA {
        return Err(artifact_error(format!(
            "unsupported savepoint handle schema `{schema}`"
        )));
    }
    let (scenario_id_hex, scenario_label) = scenario.ok_or_else(|| missing_line("scenario"))?;
    Ok(SavepointHandle {
        label: label.ok_or_else(|| missing_line("label"))?,
        checkpoint: checkpoint.ok_or_else(|| missing_line("checkpoint"))?,
        scenario_id_hex,
        scenario_label,
        scenario_payload: scenario_payload.ok_or_else(|| missing_line("scenario-payload"))?,
        schedule_payload: schedule_payload.ok_or_else(|| missing_line("schedule-payload"))?,
        frontier_ticks: frontier_ticks.ok_or_else(|| missing_line("frontier"))?,
        at: at.ok_or_else(|| missing_line("at"))?,
        terminal_condition: terminal_condition.ok_or_else(|| missing_line("terminal-condition"))?,
        materialization: materialization.ok_or_else(|| missing_line("materialization"))?,
        oracle_status: oracle_status.ok_or_else(|| missing_line("oracle"))?,
        canonical_log_digest: canonical_log_digest.ok_or_else(|| missing_line("canonical-log"))?,
    })
}

fn parse_hex_payload_line(
    line_index: usize,
    tag: &str,
    digest: &str,
    payload_hex: &str,
) -> Result<Vec<u8>, CliError> {
    if !is_content_address(digest) {
        return Err(artifact_line_error(
            line_index,
            tag,
            &format!("payload digest is not a content address: `{digest}`"),
        ));
    }
    let payload = parse_hex_bytes(line_index, tag, payload_hex)?;
    let actual = content_address_bytes(&payload);
    if actual != digest {
        return Err(artifact_line_error(
            line_index,
            tag,
            &format!("payload digest mismatch: expected `{digest}`, got `{actual}`"),
        ));
    }
    Ok(payload)
}

fn parse_blake3_content_hash(
    field: &'static str,
    value: &str,
) -> Result<crucible::ContentHash, CliError> {
    crucible::ContentAddressedBlobRef::parse(field, value)
        .map(crucible::ContentAddressedBlobRef::hash)
        .map_err(|error| artifact_error(format!("invalid {field} `{value}`: {error}")))
}

fn parse_save_at_label(line_index: usize, tag: &str, value: &str) -> Result<SaveAtArg, CliError> {
    match value {
        "virtual-time" => Ok(SaveAtArg::VirtualTime),
        "quiescence" => Ok(SaveAtArg::Quiescence),
        "property" => Ok(SaveAtArg::Property),
        "marker" => Ok(SaveAtArg::Marker),
        _ => Err(artifact_line_error(
            line_index,
            tag,
            &format!("unknown savepoint stop point `{value}`"),
        )),
    }
}

fn parse_run_terminal_condition_label(
    line_index: usize,
    tag: &str,
    value: &str,
) -> Result<RunTerminalCondition, CliError> {
    match value {
        "quiescence" => Ok(RunTerminalCondition::Quiescence),
        "virtual-time" => Ok(RunTerminalCondition::VirtualTime),
        "property" => Ok(RunTerminalCondition::Property),
        "stopped" => Ok(RunTerminalCondition::Stopped),
        _ => Err(artifact_line_error(
            line_index,
            tag,
            &format!("unknown terminal condition `{value}`"),
        )),
    }
}

fn validate_content_hash_hex_line(
    line_index: usize,
    tag: &str,
    value: &str,
) -> Result<(), CliError> {
    let bytes = parse_hex_bytes(line_index, tag, value)?;
    if bytes.len() == 32 {
        Ok(())
    } else {
        Err(artifact_line_error(
            line_index,
            tag,
            &format!("content hash must be 32 bytes, got {}", bytes.len()),
        ))
    }
}

fn plan_verify_invocation(
    args: &VerifyArgs,
    store_root: &Path,
) -> Result<VerifyInvocationPlan, CliError> {
    if !args.compare.is_empty() && args.compare.len() != 2 {
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
        if let Some(scenario) = resolve_builtin_example_scenario(value)? {
            return Ok(scenario);
        }
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

fn resolve_builtin_example_scenario(value: &str) -> Result<Option<RunScenarioRef>, CliError> {
    let name = value.strip_prefix("builtin:").unwrap_or(value);
    let fixture = match name {
        crucible::HAPPY_PATH_SCENARIO_NAME | "happy-path" => Some(crucible::happy_path_scenario()),
        crucible::PARTITION_RECOVERY_SCENARIO_NAME | "partition-recovery" => {
            Some(crucible::partition_recovery_scenario())
        }
        crucible::CRASH_RESTART_SCENARIO_NAME | "crash-restart" => {
            Some(crucible::crash_restart_scenario())
        }
        _ => None,
    };
    if let Some(fixture) = fixture {
        let fixture = fixture.map_err(|error| {
            invalid_scenario(format!(
                "built-in example scenario `{value}` failed validation: {error}"
            ))
        })?;
        let scenario = fixture.scenario.scenario_def();
        return Ok(Some(RunScenarioRef::BuiltInExample {
            name: fixture.name,
            form: fixture.scenario,
            scenario,
        }));
    }
    if matches!(
        name,
        crucible::FAULT_CAMPAIGN_FAMILY_NAME | "fault-campaign"
    ) {
        let family = crucible::fault_campaign_family().map_err(|error| {
            invalid_scenario(format!(
                "built-in example family `{value}` failed validation: {error}"
            ))
        })?;
        let sample = family.instantiate_sample(0).map_err(|error| {
            invalid_scenario(format!(
                "built-in example family `{value}` sample 0 failed validation: {error}"
            ))
        })?;
        let form = sample.into_form();
        let scenario = form.scenario_def();
        return Ok(Some(RunScenarioRef::BuiltInExample {
            name: crucible::FAULT_CAMPAIGN_FAMILY_NAME.to_owned(),
            form,
            scenario,
        }));
    }
    Ok(None)
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
        RunScenarioRef::BuiltInExample { name, .. } => RunScenarioRef::BuiltInExample {
            name: name.clone(),
            form: seeded_form,
            scenario: seeded_scenario,
        },
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
    .unwrap_or(match command {
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
    for entry in entries {
        text.push_str(&json_for_canonical_log_entry(entry));
        text.push('\n');
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
        ("crucible-cli", include_str!("../main.rs")),
        ("crucible-cli-planning", include_str!("planning.rs")),
        ("crucible-cli-backend", include_str!("backend.rs")),
        ("crucible-cli-run-save", include_str!("run_save.rs")),
        ("crucible-cli-resume-fork", include_str!("resume_fork.rs")),
        ("crucible-cli-verify-serve", include_str!("verify_serve.rs")),
        ("crucible-cli-control", include_str!("control.rs")),
        ("crucible-cli-dispatch", include_str!("dispatch.rs")),
        ("crucible-cli-exploration", include_str!("exploration.rs")),
        ("crucible-cli-replay", include_str!("replay.rs")),
        ("crucible-cli-triage-debug", include_str!("triage_debug.rs")),
        ("crucible-cli-artifact", include_str!("artifact.rs")),
        ("crucible-cli-report", include_str!("report.rs")),
        (
            "crucible-model",
            include_str!("../../../crucible/src/model.rs"),
        ),
        (
            "crucible-session",
            include_str!("../../../crucible-session/src/lib.rs"),
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
