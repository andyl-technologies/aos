//! Command invocation plans for run, save, search, fuzz, and replay workflows.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeterminismErgonomicsPlan {
    pub(crate) subcommand: CliSubcommand,
    pub(crate) seed: ResolvedSeed,
    pub(crate) seed_printed_at_run_start: bool,
    pub(crate) generated_seed_drawn_before_run: bool,
    pub(crate) generated_seed_is_identity_only: bool,
    pub(crate) failure_artifact_rule: FailureArtifactRule,
    pub(crate) trace_formats: Vec<OutputFormat>,
    pub(crate) jsonl_streams_entries: bool,
    pub(crate) format_changes_only_rendering: bool,
    pub(crate) no_wall_clock_feeds_canonical_state: bool,
}

impl DeterminismErgonomicsPlan {
    pub(crate) fn proves_t_cli_4(&self) -> bool {
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

    pub(crate) fn seed_announcement(&self) -> String {
        self.seed.announcement()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedSeed {
    pub(crate) value: u64,
    pub(crate) source: SeedSource,
    pub(crate) value_source_pinned: bool,
}

impl ResolvedSeed {
    pub(crate) fn announcement(&self) -> String {
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
pub(crate) enum SeedSource {
    Flag,
    Environment,
    Generated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FailureArtifactRule {
    pub(crate) self_contained_artifact: bool,
    pub(crate) replay_command_copy_pasteable: bool,
    pub(crate) debug_command_copy_pasteable: bool,
}

pub(crate) const RUN_INTERACTIVE_ACK_QUANTA_BOUND: u64 =
    crucible_api::STREAMING_COMMAND_MAX_ACTOR_YIELDS;
pub(crate) const SERVE_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunInvocationPlan {
    pub(crate) scenario: RunScenarioRef,
    pub(crate) save_store_root: Option<PathBuf>,
    pub(crate) request_seed: Option<crucible::Seed>,
    pub(crate) terminal_condition: RunTerminalCondition,
    pub(crate) max_virtual_time: Option<String>,
    pub(crate) max_virtual_time_ticks: Option<u64>,
    pub(crate) max_quanta: Option<u64>,
    pub(crate) execution_mode: RunExecutionMode,
    pub(crate) save_policy: RunSavePolicy,
    pub(crate) watch_streams_live_status: bool,
    pub(crate) startup_commands: Vec<SessionCommandKind>,
    pub(crate) initial_control_commands: Vec<SessionCommandKind>,
    pub(crate) accepted_interactive_commands: Vec<SessionCommandKind>,
    pub(crate) observer_profile: VerifyHostProfile,
    pub(crate) collect_execution_fingerprints: bool,
    pub(crate) bounded_ack_quanta: u64,
    pub(crate) outcome_exit_codes: Vec<(BackendCommandStatus, i32)>,
    pub(crate) invalid_scenario_exit_code: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SaveInvocationPlan {
    pub(crate) at: SaveAtArg,
    pub(crate) label: String,
    pub(crate) output: SaveOutputTarget,
    pub(crate) store_root: PathBuf,
    pub(crate) selector: Option<SaveAtSelector>,
    pub(crate) run_plan: RunInvocationPlan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SaveAtSelector {
    PropertyViolation { assertion: String },
    Marker { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SavepointOracleProof {
    pub(crate) configuration: crucible::ContentHash,
    pub(crate) fat_checkpoint: crucible::ContentHash,
    pub(crate) thin_checkpoint: crucible::ContentHash,
    pub(crate) frontier: crucible::VirtualTime,
    pub(crate) schedule: crucible::Schedule,
    pub(crate) store_objects: usize,
}

impl SavepointOracleProof {
    pub(crate) fn status_label(&self) -> &'static str {
        "fat==thin-passed"
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SaveOutputTarget {
    Explicit(PathBuf),
    ArtifactDir(PathBuf),
}

impl SaveOutputTarget {
    pub(crate) fn resolve(&self, label: &str, handle_digest: &str) -> PathBuf {
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
pub(crate) struct ResumeInvocationPlan {
    pub(crate) savepoint: ResumeSavepointRef,
    pub(crate) store_root: PathBuf,
    pub(crate) terminal_condition: RunTerminalCondition,
    pub(crate) max_virtual_time: Option<String>,
    pub(crate) max_virtual_time_ticks: Option<u64>,
    pub(crate) execution_mode: RunExecutionMode,
    pub(crate) watch_streams_live_status: bool,
    pub(crate) startup_commands: Vec<SessionCommandKind>,
    pub(crate) initial_control_commands: Vec<SessionCommandKind>,
    pub(crate) accepted_interactive_commands: Vec<SessionCommandKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForkInvocationPlan {
    pub(crate) source: ResumeSavepointRef,
    pub(crate) label: String,
    pub(crate) artifact_dir: PathBuf,
    pub(crate) store_root: PathBuf,
    pub(crate) decision_overrides: Vec<ForkDecisionOverride>,
    pub(crate) fork_seed: Option<u64>,
    pub(crate) terminal_condition: RunTerminalCondition,
    pub(crate) max_virtual_time: Option<String>,
    pub(crate) max_virtual_time_ticks: Option<u64>,
    pub(crate) execution_mode: RunExecutionMode,
    pub(crate) watch_streams_live_status: bool,
    pub(crate) startup_commands: Vec<SessionCommandKind>,
    pub(crate) initial_control_commands: Vec<SessionCommandKind>,
    pub(crate) accepted_interactive_commands: Vec<SessionCommandKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForkDecisionOverride {
    pub(crate) decision: String,
    pub(crate) value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SearchDriverPlan {
    pub(crate) scenario: RunScenarioRef,
    pub(crate) strategy_arg: SearchStrategyArg,
    pub(crate) engine_strategy: crucible::SearchStrategy,
    pub(crate) max_depth: Option<u64>,
    pub(crate) max_states: u64,
    pub(crate) budget: crucible::SearchBudget,
    pub(crate) on_violation: SearchOnViolationArg,
    pub(crate) explicit_on_violation: bool,
    pub(crate) store_root: PathBuf,
    pub(crate) artifact_dir: PathBuf,
    pub(crate) findings_out: Option<PathBuf>,
    pub(crate) schedule_named_truths: Option<SearchScheduleNamedTruthsPlan>,
    pub(crate) retained_evidence: Option<SearchRetainedEvidencePlan>,
    pub(crate) delegates_policy_to_advanced_engine: bool,
    pub(crate) opportunistic_replay_oracle_sampling: bool,
    pub(crate) counterexamples_are_self_contained: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SearchScheduleNamedTruthsPlan {
    pub(crate) path: PathBuf,
    pub(crate) digest: String,
    pub(crate) material: Vec<u8>,
    pub(crate) truths: crucible::SearchScheduleNamedPredicateTruths,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SearchRetainedEvidencePlan {
    pub(crate) path: PathBuf,
    pub(crate) digest: String,
    pub(crate) material: Vec<u8>,
    pub(crate) evidence: BTreeMap<crucible::ContentHash, SearchRetainedLogAssertionEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalDoubleSearchReport {
    pub(crate) root: crucible::ContentHash,
    pub(crate) expansions: usize,
    pub(crate) explored: usize,
    pub(crate) failures: usize,
    pub(crate) property_findings: usize,
    pub(crate) timeout_findings: usize,
    pub(crate) exhausted: bool,
    pub(crate) failure_oracle: String,
    pub(crate) schedule_named_truths: String,
    pub(crate) schedule_named_truths_digest: String,
    pub(crate) retained_evidence: String,
    pub(crate) retained_evidence_digest: String,
    pub(crate) counterexample: Option<LocalDoubleSearchCounterexample>,
    pub(crate) replay_oracle_considered: usize,
    pub(crate) replay_oracle_sampled: usize,
    pub(crate) replay_oracle_skipped: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalDoubleSearchCounterexample {
    pub(crate) configuration: crucible::ContentHash,
    pub(crate) fingerprint: crucible::ContentHash,
    pub(crate) artifact_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FuzzDriverPlan {
    pub(crate) family: FuzzFamilyRef,
    pub(crate) runs: u64,
    pub(crate) coverage: FuzzCoverageArg,
    pub(crate) corpus: Option<PathBuf>,
    pub(crate) store_root: PathBuf,
    pub(crate) artifact_dir: PathBuf,
    pub(crate) findings_out: Option<PathBuf>,
    pub(crate) on_violation: SearchOnViolationArg,
    pub(crate) config: crucible::CoverageGuidedFuzzConfig,
    pub(crate) delegates_policy_to_advanced_engine: bool,
    pub(crate) pins_one_scenario_def_per_iteration: bool,
    pub(crate) counterexamples_are_self_contained: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FuzzDispatchRoute {
    BuiltInFaultCampaignProof,
    #[cfg(any(test, feature = "test-double"))]
    LocalDouble,
    LocalPackagedBackend,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalDoubleFuzzReport {
    pub(crate) family: String,
    pub(crate) corpus: Option<PathBuf>,
    pub(crate) iterations: usize,
    pub(crate) coverage_biased_order: usize,
    pub(crate) new_coverage: usize,
    pub(crate) retained_entries: usize,
    pub(crate) admissions: usize,
    pub(crate) replay_oracle_validations: u64,
    pub(crate) generated_mutants: u64,
    pub(crate) store_puts: u64,
    pub(crate) property_findings: usize,
    pub(crate) timeout_findings: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FuzzFamilyRef {
    BuiltInFaultCampaign,
    File(PathBuf),
    Stored(crucible::ContentHash),
}

impl FuzzFamilyRef {
    pub(crate) fn label(&self) -> String {
        match self {
            Self::BuiltInFaultCampaign => crucible::FAULT_CAMPAIGN_FAMILY_NAME.to_owned(),
            Self::File(path) => path.display().to_string(),
            Self::Stored(reference) => format_content_hash_ref(*reference),
        }
    }

    pub(crate) fn is_builtin_fault_campaign(&self) -> bool {
        matches!(self, Self::BuiltInFaultCampaign)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CliScenarioFamilyToml {
    pub(crate) schema: String,
    pub(crate) seed_space: CliSeedSpaceToml,
    pub(crate) topology_size: CliTopologySizeToml,
    pub(crate) topology_shapes: Vec<String>,
    pub(crate) node_template: CliNodeTemplateToml,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CliSearchScheduleNamedTruthsToml {
    pub(crate) schema: String,
    #[serde(default)]
    pub(crate) truth: Vec<CliSearchScheduleNamedTruthToml>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CliSearchScheduleNamedTruthToml {
    pub(crate) name: String,
    pub(crate) value: bool,
    #[serde(default)]
    pub(crate) nodes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CliSearchRetainedEvidenceToml {
    pub(crate) schema: String,
    #[serde(default)]
    pub(crate) evidence: Vec<CliSearchRetainedEvidenceEntryToml>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CliSearchRetainedEvidenceEntryToml {
    pub(crate) configuration: String,
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) node: Option<String>,
    #[serde(default)]
    pub(crate) marker: Option<String>,
    #[serde(default)]
    pub(crate) retired_icount: Option<u64>,
    #[serde(default)]
    pub(crate) quiescent: Option<bool>,
    #[serde(default)]
    pub(crate) virtual_time_ticks: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
pub(crate) enum CliSeedSpaceToml {
    Generated { meta_seed: String, count: u32 },
    Explicit { seeds: Vec<String> },
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CliTopologySizeToml {
    pub(crate) min: u32,
    pub(crate) max: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CliNodeTemplateToml {
    pub(crate) fixed_icount: Option<u64>,
    pub(crate) network_idle_nanos: Option<u64>,
    pub(crate) console_marker: Option<String>,
    pub(crate) agent_signal: Option<bool>,
    pub(crate) arch: Option<String>,
    pub(crate) white_box: Option<String>,
    pub(crate) memory_mib: Option<u32>,
    pub(crate) cmdline: Option<String>,
    pub(crate) smp_vcpus: Option<u16>,
    pub(crate) icount_shift: Option<u8>,
    pub(crate) kernel: Option<String>,
    pub(crate) root_image: Option<String>,
    pub(crate) initrd: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ResumeSavepointRef {
    CheckpointHash(crucible::ContentHash),
    Handle {
        path: PathBuf,
        handle: SavepointHandle,
    },
}

impl ResumeSavepointRef {
    pub(crate) fn checkpoint(&self) -> crucible::ContentHash {
        match self {
            Self::CheckpointHash(checkpoint) => *checkpoint,
            Self::Handle { handle, .. } => handle.checkpoint,
        }
    }

    pub(crate) fn label(&self) -> String {
        match self {
            Self::CheckpointHash(checkpoint) => format_content_hash_ref(*checkpoint),
            Self::Handle { path, handle } => {
                format!("{} ({})", handle.label, path.display())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SavepointHandle {
    pub(crate) label: String,
    pub(crate) checkpoint: crucible::ContentHash,
    pub(crate) scenario_id_hex: String,
    pub(crate) scenario_label: String,
    pub(crate) scenario_payload: Vec<u8>,
    pub(crate) schedule_payload: Vec<u8>,
    pub(crate) frontier_ticks: u64,
    pub(crate) at: SaveAtArg,
    pub(crate) selector: Option<SaveAtSelector>,
    pub(crate) boundary_proof: Option<SavepointBoundaryProof>,
    pub(crate) boundary_predicate: Option<crucible::Predicate>,
    pub(crate) terminal_condition: RunTerminalCondition,
    pub(crate) materialization: String,
    pub(crate) oracle_status: String,
    pub(crate) canonical_log_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SavepointBoundaryProof {
    Coordinate {
        frontier_ticks: u64,
        quanta: u64,
    },
    Breakpoint {
        breakpoint_id: BreakpointId,
        frontier_ticks: u64,
        quanta: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RunScenarioRef {
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
    pub(crate) fn label(&self) -> String {
        match self {
            Self::BuiltInExample { name, .. } => name.clone(),
            Self::File { path, .. } => path.display().to_string(),
            Self::Stored { reference, .. } => format_content_hash_ref(*reference),
        }
    }

    pub(crate) fn scenario_id(&self) -> crucible::ContentHash {
        match self {
            Self::BuiltInExample { scenario, .. }
            | Self::File { scenario, .. }
            | Self::Stored { scenario, .. } => scenario.id(),
        }
    }

    pub(crate) fn scenario_def(&self) -> &crucible::ScenarioDef {
        match self {
            Self::BuiltInExample { scenario, .. }
            | Self::File { scenario, .. }
            | Self::Stored { scenario, .. } => scenario,
        }
    }

    pub(crate) fn scenario_form(&self) -> &crucible::ScenarioDefForm {
        match self {
            Self::BuiltInExample { form, .. }
            | Self::File { form, .. }
            | Self::Stored { form, .. } => form,
        }
    }

    pub(crate) fn with_form(&self, form: crucible::ScenarioDefForm) -> Self {
        let scenario = form.scenario_def();
        match self {
            Self::BuiltInExample { name, .. } => Self::BuiltInExample {
                name: name.clone(),
                form,
                scenario,
            },
            Self::File { path, .. } => Self::File {
                path: path.clone(),
                form,
                scenario,
            },
            Self::Stored { reference, .. } => Self::Stored {
                reference: *reference,
                form,
                scenario,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifyInvocationPlan {
    pub(crate) mode: VerifyMode,
    pub(crate) requested_runs: usize,
    pub(crate) reductions: Vec<VerifyReductionPlan>,
    pub(crate) compare_canonical_logs: bool,
    pub(crate) compare_fingerprint_streams: bool,
    pub(crate) pairwise_byte_identity: bool,
    pub(crate) bisection_on_divergence: bool,
    pub(crate) print_bisection_state_dump: bool,
    pub(crate) writes_side_artifacts_on_divergence: bool,
    pub(crate) applies_hostile_condition_matrix: bool,
    pub(crate) outcome_exit_codes: Vec<(BackendCommandStatus, i32)>,
}

impl VerifyInvocationPlan {
    pub(crate) fn scenario(&self) -> Option<&RunScenarioRef> {
        match &self.mode {
            VerifyMode::RunScenario { scenario } => Some(scenario),
            VerifyMode::CompareArtifacts { .. } => None,
        }
    }

    pub(crate) fn surface_shape_is_consistent(&self) -> bool {
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
pub(crate) enum VerifyMode {
    RunScenario { scenario: RunScenarioRef },
    CompareArtifacts { left: PathBuf, right: PathBuf },
}

impl VerifyMode {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::RunScenario { .. } => "run-scenario",
            Self::CompareArtifacts { .. } => "compare-artifacts",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifyReductionPlan {
    pub(crate) index: usize,
    pub(crate) run_index: usize,
    pub(crate) host_profile: VerifyHostProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifyHostProfile {
    pub(crate) label: &'static str,
    pub(crate) poll_order: VerifyPollOrder,
    pub(crate) event_timeout_ms: u64,
    pub(crate) state_timeout_ms: u64,
    pub(crate) pre_poll_yields: u8,
    pub(crate) post_poll_yields: u8,
}

impl VerifyHostProfile {
    pub(crate) const fn label(self) -> &'static str {
        self.label
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifyPollOrder {
    EventThenState,
    StateThenEvent,
}

pub(crate) const VERIFY_BASELINE_PROFILE: VerifyHostProfile = VerifyHostProfile {
    label: "baseline",
    poll_order: VerifyPollOrder::EventThenState,
    event_timeout_ms: 1,
    state_timeout_ms: 10,
    pre_poll_yields: 0,
    post_poll_yields: 1,
};
pub(crate) const VERIFY_HOSTILE_PROFILES: &[VerifyHostProfile] = &[
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
pub(crate) enum RunTerminalCondition {
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

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Quiescence => "quiescence",
            Self::VirtualTime => "virtual-time",
            Self::Property => "property",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum RunExecutionMode {
    ToCompletion,
    Interactive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum RunSavePolicy {
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
pub(crate) struct SimBackendLifecycleLoop {
    pub(crate) backend: crucible::SimBackend,
    pub(crate) quanta: u64,
    pub(crate) event_log_events: u64,
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

/// Validates run arguments and constructs the deterministic invocation plan.
///
/// # Errors
///
/// Returns [`CliError`] when scenario resolution, budgets, or terminal conditions are invalid.
pub(crate) fn plan_run_invocation(
    args: &RunArgs,
    store_root: &Path,
) -> Result<RunInvocationPlan, CliError> {
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
        save_store_root: Some(store_root.to_path_buf()),
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

/// Validates save arguments and constructs the savepoint invocation plan.
///
/// # Errors
///
/// Returns [`CliError`] when the save boundary, selector, label, scenario, or
/// derived run plan is invalid.
pub(crate) fn plan_save_invocation(
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
            if args.max_virtual_time.is_some() {
                return Err(usage_error(
                    "save --at quiescence does not accept --max-virtual-time",
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
        save_on: RunSaveOnArg::Never,
        watch: false,
        #[cfg(any(test, feature = "test-double"))]
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

/// Resolves and validates a savepoint label.
///
/// # Errors
///
/// Returns [`CliError`] when the label is empty or contains control whitespace.
pub(crate) fn plan_save_label(label: Option<&str>) -> Result<String, CliError> {
    plan_nonempty_label(label, "savepoint")
}

/// Checks that a save selector names content declared by the scenario.
///
/// # Errors
///
/// Returns [`CliError`] when a property selector names an undeclared assertion.
pub(crate) fn validate_save_selector_for_scenario(
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

/// Normalizes one save selector supplied by `flag`.
///
/// # Errors
///
/// Returns [`CliError`] when the selector is empty or contains control whitespace.
pub(crate) fn plan_save_selector(value: &str, flag: &str) -> Result<String, CliError> {
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

/// Resolves and validates a fork label.
///
/// # Errors
///
/// Returns [`CliError`] when the label is empty or contains control whitespace.
pub(crate) fn plan_fork_label(label: Option<&str>) -> Result<String, CliError> {
    plan_nonempty_label(label, "fork")
}

/// Resolves an optional label and enforces the shared single-line label policy.
///
/// # Errors
///
/// Returns [`CliError`] when the resolved label is empty or contains control
/// whitespace.
pub(crate) fn plan_nonempty_label(
    label: Option<&str>,
    default: &'static str,
) -> Result<String, CliError> {
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

/// Validates resume arguments and constructs the resume invocation plan.
///
/// # Errors
///
/// Returns [`CliError`] when the savepoint cannot be resolved or the duration
/// and terminal-condition arguments are inconsistent.
pub(crate) fn plan_resume_invocation(
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

/// Resolves the savepoint reference accepted by the resume command.
///
/// # Errors
///
/// Returns [`CliError`] when the reference is absent, malformed, unreadable, or
/// does not contain a valid savepoint handle.
pub(crate) fn resolve_resume_savepoint(
    savepoint: Option<&str>,
) -> Result<ResumeSavepointRef, CliError> {
    resolve_savepoint_ref("resume", savepoint)
}

/// Validates fork arguments and constructs the fork invocation plan.
///
/// # Errors
///
/// Returns [`CliError`] when the source savepoint, label, decision overrides,
/// duration, or terminal-condition arguments are invalid.
pub(crate) fn plan_fork_invocation(
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
    validate_fork_decision_override_domain(&decision_overrides)?;
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
/// Constructs a fork plan with the test fixture's conventional local paths.
///
/// # Errors
///
/// Returns [`CliError`] under the same invalid-input conditions as
/// [`plan_fork_invocation`].
pub(crate) fn plan_fork_invocation_for_test(
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

/// Parses one `decision=value` fork override.
///
/// # Errors
///
/// Returns [`CliError`] when the override is multiline, omits either side, or
/// does not contain exactly one separator.
pub(crate) fn parse_fork_decision_override(raw: &str) -> Result<ForkDecisionOverride, CliError> {
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
        decision: decode_fork_override_component(decision)?,
        value: decode_fork_override_component(pinned_value)?,
    })
}

fn decode_fork_override_component(value: &str) -> Result<String, CliError> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let Some(encoded) = bytes.get(index + 1..index + 3) else {
            return Err(usage_error(
                "--override percent escapes must contain two hexadecimal digits",
            ));
        };
        let text = std::str::from_utf8(encoded).map_err(|_| {
            usage_error("--override percent escapes must contain hexadecimal ASCII")
        })?;
        let byte = u8::from_str_radix(text, 16).map_err(|_| {
            usage_error("--override percent escapes must contain two hexadecimal digits")
        })?;
        decoded.push(byte);
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|_| usage_error("--override percent escapes must decode to UTF-8"))
}

/// Rejects fork override coordinates that the production scheduler cannot consume.
///
/// # Errors
///
/// Returns [`CliError`] when an override is outside the live World-network
/// scheduling-point namespace, uses an unsupported choice, or repeats a point.
pub(crate) fn validate_fork_decision_override_domain(
    overrides: &[ForkDecisionOverride],
) -> Result<(), CliError> {
    let mut points = BTreeSet::new();
    for override_plan in overrides {
        let decision = OverrideDecision {
            point: SchedulingPoint {
                key: override_plan.decision.clone(),
            },
            choice: ChoiceTag {
                name: override_plan.value.clone(),
            },
        };
        if !crucible::is_supported_live_world_network_override(&decision) {
            return Err(artifact_error(format!(
                "fork override `{}`=`{}` is unresolvable; expected a scheduler-recorded `live-world-network/...` point and a canonical loss/duplicate/corrupt choice",
                override_plan.decision, override_plan.value
            )));
        }
        if !points.insert(override_plan.decision.as_str()) {
            return Err(artifact_error(format!(
                "fork override point `{}` was specified more than once",
                override_plan.decision
            )));
        }
    }
    Ok(())
}

/// Validates search arguments and constructs the advanced-engine search plan.
///
/// # Errors
///
/// Returns [`CliError`] when the scenario or budget is invalid, incompatible
/// evidence inputs are selected, or an evidence file cannot be loaded.
#[cfg(test)]
pub(crate) fn plan_search_invocation(
    args: &SearchArgs,
    store_root: &Path,
) -> Result<SearchDriverPlan, CliError> {
    let artifact_dir = store_root.parent().unwrap_or(store_root);
    plan_search_invocation_with_artifact_dir(args, store_root, artifact_dir)
}

/// Validates search arguments with the explicit user-facing artifact directory.
///
/// # Errors
///
/// Returns [`CliError`] when the scenario, budget, evidence, or output path is invalid.
pub(crate) fn plan_search_invocation_with_artifact_dir(
    args: &SearchArgs,
    store_root: &Path,
    artifact_dir: &Path,
) -> Result<SearchDriverPlan, CliError> {
    let scenario = resolve_search_scenario(args.scenario.as_deref(), store_root)?;
    validate_positive_optional_budget("--max-depth", args.max_depth)?;
    validate_positive_budget("--max-states", args.max_states)?;
    let engine_strategy = args.strategy.engine_strategy();
    let budget = crucible::SearchBudget::new(args.max_states);
    let explicit_on_violation = args.on_violation.is_some();
    let on_violation = args.on_violation.unwrap_or(SearchOnViolationArg::Stop);
    if let Some(path) = &args.findings_out {
        validate_exploration_path_arg("--findings-out", path)?;
    }
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
        store_root: store_root.to_path_buf(),
        artifact_dir: artifact_dir.to_path_buf(),
        findings_out: args.findings_out.clone(),
        schedule_named_truths,
        retained_evidence,
        delegates_policy_to_advanced_engine: true,
        opportunistic_replay_oracle_sampling: true,
        counterexamples_are_self_contained: true,
    })
}

/// Resolves a scenario for the search command.
///
/// # Errors
///
/// Returns [`CliError`] when the scenario reference cannot be resolved or
/// validated.
pub(crate) fn resolve_search_scenario(
    scenario: Option<&str>,
    store_root: &Path,
) -> Result<RunScenarioRef, CliError> {
    resolve_command_scenario("search", scenario, store_root)
}

/// Loads and validates schedule-named predicate truths from a TOML file.
///
/// # Errors
///
/// Returns [`CliError`] when the file cannot be read or its contents are not a
/// valid predicate-truth document for `scenario`.
pub(crate) fn load_search_schedule_named_truths_file(
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

/// Parses schedule-named predicate truths against a scenario definition.
///
/// # Errors
///
/// Returns [`CliError`] for invalid TOML, an unsupported schema, duplicate
/// predicates, or references to unknown scenario nodes.
pub(crate) fn load_search_schedule_named_truths_toml(
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

/// Loads and validates retained search evidence from a TOML file.
///
/// # Errors
///
/// Returns [`CliError`] when the file cannot be read or its contents cannot be
/// admitted as retained evidence for `scenario`.
pub(crate) fn load_search_retained_evidence_file(
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

/// Parses retained search evidence against a scenario definition.
///
/// # Errors
///
/// Returns [`CliError`] for invalid TOML or schema, malformed evidence, unknown
/// nodes or assertions, duplicate configurations, or inconsistent boundaries.
pub(crate) fn load_search_retained_evidence_toml(
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

/// Adds one validated guest-marker record to retained search evidence.
///
/// # Errors
///
/// Returns [`CliError`] when required marker fields are missing, forbidden
/// fields are present, or the named node is absent from the scenario.
pub(crate) fn push_search_retained_guest_marker_entry(
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

/// Parses one retained assertion-evaluation boundary entry.
///
/// # Errors
///
/// Returns [`CliError`] when required fields are missing or the entry carries
/// fields forbidden for an evaluation boundary.
pub(crate) fn parse_search_retained_evaluation_boundary_entry(
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

/// Parses one retained terminal-quiescence entry.
///
/// # Errors
///
/// Returns [`CliError`] when the entry is not explicitly quiescent or includes
/// fields that are invalid at terminal quiescence.
pub(crate) fn parse_search_retained_terminal_quiescence_entry(
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

/// Parses the content hash identifying one retained-evidence configuration.
///
/// # Errors
///
/// Returns [`CliError`] when the configuration reference is not a valid
/// BLAKE3 content hash.
pub(crate) fn parse_search_retained_evidence_configuration(
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

/// Validates fuzz arguments and constructs the coverage-guided fuzz plan.
///
/// # Errors
///
/// Returns [`CliError`] when budgets, corpus paths, or the scenario-family
/// reference are invalid.
#[cfg(test)]
pub(crate) fn plan_fuzz_invocation(
    args: &FuzzArgs,
    seed: &DeterminismErgonomicsPlan,
    store_root: &Path,
) -> Result<FuzzDriverPlan, CliError> {
    let artifact_dir = store_root.parent().unwrap_or(store_root);
    plan_fuzz_invocation_with_artifact_dir(args, seed, store_root, artifact_dir)
}

/// Validates fuzz arguments with the explicit user-facing artifact directory.
///
/// # Errors
///
/// Returns [`CliError`] when the family, budget, corpus, or output path is invalid.
pub(crate) fn plan_fuzz_invocation_with_artifact_dir(
    args: &FuzzArgs,
    seed: &DeterminismErgonomicsPlan,
    store_root: &Path,
    artifact_dir: &Path,
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
    if let Some(path) = &args.findings_out {
        validate_exploration_path_arg("--findings-out", path)?;
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
        artifact_dir: artifact_dir.to_path_buf(),
        findings_out: args.findings_out.clone(),
        on_violation: args.on_violation.unwrap_or(SearchOnViolationArg::Stop),
        config,
        delegates_policy_to_advanced_engine: true,
        pins_one_scenario_def_per_iteration: true,
        counterexamples_are_self_contained: true,
    })
}

/// Resolves the optional fuzz family reference or selects the built-in family.
///
/// # Errors
///
/// Returns [`CliError`] when the supplied family reference is malformed.
pub(crate) fn resolve_fuzz_family_ref(
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

/// Parses a fuzz family as a built-in name, store reference, or file path.
///
/// # Errors
///
/// Returns [`CliError`] when the reference is empty, multiline, malformed, or
/// names a path that is not a regular file.
pub(crate) fn parse_fuzz_family_ref(raw: &str) -> Result<FuzzFamilyRef, CliError> {
    let value = raw.trim();
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(invalid_scenario(
            "family reference must not be empty or multiline",
        ));
    }
    if value == crucible::FAULT_CAMPAIGN_FAMILY_NAME || value == "builtin:fault-campaign" {
        return Ok(FuzzFamilyRef::BuiltInFaultCampaign);
    }
    if value.starts_with(CONTENT_ADDRESS_PREFIX) {
        return Err(invalid_scenario(format!(
            "family content hash `{value}` is not a DAG-store `blake3:<hash>` reference"
        )));
    }
    if value.starts_with("blake3:") {
        let reference =
            crucible::ContentAddressedBlobRef::parse("family", value).map_err(|error| {
                invalid_scenario(format!(
                    "family content hash `{value}` is malformed: {error}"
                ))
            })?;
        return Ok(FuzzFamilyRef::Stored(reference.hash()));
    }
    let path = Path::new(value);
    validate_exploration_path_arg("FAMILY", path)?;
    if !path.exists() {
        return Err(invalid_scenario(format!("family `{value}` does not exist")));
    }
    if !path.is_file() {
        return Err(invalid_scenario(format!(
            "family `{value}` is not a regular file"
        )));
    }
    Ok(FuzzFamilyRef::File(path.to_path_buf()))
}

/// Materializes the scenario family identified by a fuzz-family reference.
///
/// # Errors
///
/// Returns [`CliError`] when built-in construction fails or file/store content
/// cannot be loaded and validated.
pub(crate) fn load_fuzz_family(
    plan: &FuzzDriverPlan,
) -> Result<crucible::ScenarioFamily, CliError> {
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

/// Loads a scenario family from a TOML file.
///
/// # Errors
///
/// Returns [`CliError`] when the file cannot be read or decoded as a supported
/// scenario-family document.
pub(crate) fn load_fuzz_family_file(path: &Path) -> Result<crucible::ScenarioFamily, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        invalid_scenario(format!(
            "family `{}` could not be read: {error}",
            path.display()
        ))
    })?;
    load_fuzz_family_toml(&format!("file `{}`", path.display()), &text)
}

/// Loads a scenario family from the local content-addressed store.
///
/// # Errors
///
/// Returns [`CliError`] when the referenced object is absent or cannot be
/// decoded as a supported scenario-family document.
pub(crate) fn load_stored_fuzz_family(
    plan: &FuzzDriverPlan,
    reference: crucible::ContentHash,
) -> Result<crucible::ScenarioFamily, CliError> {
    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    let bytes = store.get(&reference).map_err(|error| {
        invalid_scenario(format!(
            "family {} could not be loaded from store `{}`: {error}",
            format_content_hash_ref(reference),
            plan.store_root.display()
        ))
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        invalid_scenario(format!(
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

/// Parses and validates a scenario-family TOML document.
///
/// # Errors
///
/// Returns [`CliError`] when the document is not UTF-8, is invalid TOML, uses
/// an unsupported schema, or cannot form a valid scenario family.
pub(crate) fn load_fuzz_family_toml(
    label: &str,
    text: &str,
) -> Result<crucible::ScenarioFamily, CliError> {
    let authored = toml::from_str::<CliScenarioFamilyToml>(text).map_err(|error| {
        invalid_scenario(format!(
            "family {label} is not valid scenario-family TOML: {error}"
        ))
    })?;
    scenario_family_from_toml(label, authored)
}

/// Converts the CLI scenario-family schema into the core model.
///
/// # Errors
///
/// Returns [`CliError`] when ranges, topology shapes, seeds, or the node
/// template are invalid, or core family validation fails.
pub(crate) fn scenario_family_from_toml(
    label: &str,
    authored: CliScenarioFamilyToml,
) -> Result<crucible::ScenarioFamily, CliError> {
    const SCHEMA: &str = "crucible.scenario-family.v2";

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
    let space = crucible::FamilySpace::new(seeds, topology_size, topology_shapes)
        .map_err(|error| family_file_error(label, format!("has invalid family space: {error}")))?;
    let node_template = node_template_from_toml(label, authored.node_template)?;

    Ok(crucible::ScenarioFamily::new(space, node_template))
}

/// Converts an authored seed-space declaration into the core seed space.
///
/// # Errors
///
/// Returns [`CliError`] when a seed is malformed, the generated count is zero,
/// or the explicit seed list is empty or contains duplicates.
pub(crate) fn seed_space_from_toml(
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

/// Parses one authored topology-shape label.
///
/// # Errors
///
/// Returns [`CliError`] when the label is not a supported topology shape.
pub(crate) fn topology_shape_from_toml(
    label: &str,
    shape: &str,
) -> Result<crucible::TopologyShape, CliError> {
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

/// Converts an authored node template into the core family template.
///
/// # Errors
///
/// Returns [`CliError`] when architecture, white-box mode, artifact references,
/// sizes, clocks, or template invariants are invalid.
pub(crate) fn node_template_from_toml(
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

/// Parses one authored VM architecture label.
///
/// # Errors
///
/// Returns [`CliError`] when the architecture label is unsupported.
pub(crate) fn vm_architecture_from_toml(
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

/// Parses one authored white-box capability label.
///
/// # Errors
///
/// Returns [`CliError`] when the white-box label is unsupported.
pub(crate) fn white_box_from_toml(
    label: &str,
    value: &str,
) -> Result<crucible::WhiteBoxPolicy, CliError> {
    match value {
        "enabled" => Ok(crucible::WhiteBoxPolicy::Enabled),
        "disabled" => Ok(crucible::WhiteBoxPolicy::Disabled),
        value => Err(family_file_error(
            label,
            format!("uses unknown node_template.white_box `{value}`"),
        )),
    }
}

/// Parses one content-addressed blob reference from family TOML.
///
/// # Errors
///
/// Returns [`CliError`] when the reference has invalid syntax or hash material.
pub(crate) fn blob_ref_from_toml(
    label: &str,
    field: &'static str,
    value: &str,
) -> Result<crucible::ContentAddressedBlobRef, CliError> {
    crucible::ContentAddressedBlobRef::parse(field, value)
        .map_err(|error| family_file_error(label, format!("has invalid {field}: {error}")))
}

/// Parses a decimal or hexadecimal family seed.
///
/// # Errors
///
/// Returns [`CliError`] when the seed is empty, out of range, or has invalid
/// decimal or hexadecimal syntax.
pub(crate) fn parse_family_seed(
    label: &str,
    field: &str,
    value: &str,
) -> Result<crucible::Seed, CliError> {
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

/// Parses the hexadecimal form of a family seed.
///
/// # Errors
///
/// Returns [`CliError`] when the hexadecimal payload is empty, too wide, or
/// contains a non-hexadecimal digit.
pub(crate) fn parse_family_seed_hex(
    label: &str,
    field: &str,
    value: &str,
) -> Result<[u8; 32], CliError> {
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

pub(crate) fn family_file_error(label: &str, message: impl Into<String>) -> CliError {
    invalid_scenario(format!("family {label} {}", message.into()))
}

/// Validates that an optional exploration budget is positive.
///
/// # Errors
///
/// Returns [`CliError`] when the supplied budget is zero.
pub(crate) fn validate_positive_optional_budget(
    label: &'static str,
    value: Option<u64>,
) -> Result<(), CliError> {
    if let Some(value) = value {
        validate_positive_budget(label, value)?;
    }
    Ok(())
}

/// Validates that a required exploration budget is positive.
///
/// # Errors
///
/// Returns [`CliError`] when `value` is zero.
pub(crate) fn validate_positive_budget(label: &'static str, value: u64) -> Result<(), CliError> {
    if value == 0 {
        return Err(usage_error(format!("{label} must be greater than zero")));
    }
    Ok(())
}

/// Validates a user-supplied exploration input path.
///
/// # Errors
///
/// Returns [`CliError`] when the path is empty, contains control whitespace, or
/// does not name a regular file.
pub(crate) fn validate_exploration_path_arg(
    label: &'static str,
    path: &Path,
) -> Result<(), CliError> {
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
#[path = "invocations/savepoint.rs"]
mod savepoint;

pub(crate) use savepoint::*;

/// Decodes one hexadecimal payload field from a savepoint handle.
///
/// # Errors
///
/// Returns [`CliError`] when the payload has odd width or contains a non-hex
/// digit.
pub(crate) fn parse_hex_payload_line(
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

/// Parses a BLAKE3 content hash used by a savepoint handle.
///
/// # Errors
///
/// Returns [`CliError`] when the value lacks the BLAKE3 prefix or contains an
/// invalid digest.
pub(crate) fn parse_blake3_content_hash(
    field: &'static str,
    value: &str,
) -> Result<crucible::ContentHash, CliError> {
    crucible::ContentAddressedBlobRef::parse(field, value)
        .map(crucible::ContentAddressedBlobRef::hash)
        .map_err(|error| artifact_error(format!("invalid {field} `{value}`: {error}")))
}

/// Parses the save-boundary label stored in a savepoint handle.
///
/// # Errors
///
/// Returns [`CliError`] when the label is not one of the canonical save-boundary
/// names.
pub(crate) fn parse_save_at_label(
    line_index: usize,
    tag: &str,
    value: &str,
) -> Result<SaveAtArg, CliError> {
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

/// Parses the terminal-condition label stored in a savepoint handle.
///
/// # Errors
///
/// Returns [`CliError`] when the label is not a canonical run terminal
/// condition.
pub(crate) fn parse_run_terminal_condition_label(
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

#[path = "invocations/content_hash.rs"]
mod content_hash;

pub(crate) use content_hash::*;
