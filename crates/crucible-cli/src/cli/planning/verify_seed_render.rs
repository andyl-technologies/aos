//! Verification planning, seed resolution, and deterministic rendering helpers.

use super::*;

/// Validates verify arguments and constructs all deterministic reductions.
///
/// # Errors
///
/// Returns [`CliError`] when comparison inputs, run counts, scenario selection,
/// or the resulting verification-plan invariants are invalid.
pub(crate) fn plan_verify_invocation(
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

pub(crate) fn verify_reduction_plans(
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

/// Resolves a scenario for the run command.
///
/// # Errors
///
/// Returns [`CliError`] when the scenario reference is absent, malformed,
/// unreadable, or fails scenario validation.
pub(crate) fn resolve_run_scenario(
    scenario: Option<&str>,
    store_root: &Path,
) -> Result<RunScenarioRef, CliError> {
    resolve_command_scenario("run", scenario, store_root)
}

/// Resolves a built-in, file-backed, or store-backed command scenario.
///
/// # Errors
///
/// Returns [`CliError`] when the reference is absent or malformed, a file or
/// store object cannot be read, or the scenario fails canonical validation.
pub(crate) fn resolve_command_scenario(
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

/// Resolves a supported built-in example name.
///
/// # Errors
///
/// Returns [`CliError`] when constructing or sampling the named built-in fixture
/// fails validation.
pub(crate) fn resolve_builtin_example_scenario(
    value: &str,
) -> Result<Option<RunScenarioRef>, CliError> {
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

/// Parses canonical scenario TOML from raw bytes.
///
/// # Errors
///
/// Returns [`CliError`] when the bytes are not UTF-8 or do not form a valid
/// canonical scenario definition.
pub(crate) fn parse_run_scenario_bytes(
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

/// Rebuilds a resolved scenario with a pinned verification seed.
///
/// # Errors
///
/// Returns [`CliError`] when the scenario cannot be rematerialized with `seed`.
pub(crate) fn reseed_run_scenario_ref(
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

pub(crate) fn parse_run_duration_budget_ticks(duration: &str) -> Option<u64> {
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

pub(crate) fn run_interactive_session_command_set() -> Vec<SessionCommandKind> {
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

pub(crate) trait SeedEnvironment {
    fn variable(&self, name: &'static str) -> Option<String>;
}

#[derive(Default)]
pub(crate) struct ProcessSeedEnvironment;

impl SeedEnvironment for ProcessSeedEnvironment {
    fn variable(&self, name: &'static str) -> Option<String> {
        std::env::var(name).ok()
    }
}

pub(crate) trait SeedEntropySource {
    fn generated_seed(&mut self) -> Result<u64, CliError>;
}

#[derive(Default)]
pub(crate) struct OsSeedEntropySource;

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

pub(crate) trait DeterminismErgonomicsRecorder {
    fn record_seed_resolution(&mut self, seed: &ResolvedSeed);

    fn record_trace_format(&mut self, format: OutputFormat);

    fn record_failure_artifact_rule(&mut self, rule: &FailureArtifactRule);
}

#[derive(Default)]
pub(crate) struct NullDeterminismErgonomicsRecorder;

impl DeterminismErgonomicsRecorder for NullDeterminismErgonomicsRecorder {
    fn record_seed_resolution(&mut self, _seed: &ResolvedSeed) {}

    fn record_trace_format(&mut self, _format: OutputFormat) {}

    fn record_failure_artifact_rule(&mut self, _rule: &FailureArtifactRule) {}
}

/// Resolves seed and trace policy for a seed-consuming CLI command.
///
/// # Errors
///
/// Returns [`CliError`] when trace format policy or explicit/environment seed
/// syntax is invalid, or OS entropy cannot supply a generated seed.
pub(crate) fn plan_determinism_ergonomics(
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

/// Records and renders an already validated determinism-ergonomics plan.
///
/// # Errors
///
/// Returns [`CliError`] when the plan is internally inconsistent or rendering
/// its canonical trace format fails.
pub(crate) fn execute_determinism_ergonomics_plan(
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

pub(crate) fn subcommand_uses_seed_resolution(command: &Commands) -> bool {
    seed_resolution_mode(command) == SeedResolutionMode::FreshRunIdentity
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SeedResolutionMode {
    FreshRunIdentity,
    ArtifactOrSavepointOwned,
    NotApplicable,
}

pub(crate) fn seed_resolution_mode(command: &Commands) -> SeedResolutionMode {
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

/// Enforces canonical trace-format constraints for the selected command.
///
/// # Errors
///
/// Returns [`CliError`] when the command and requested output format are an
/// unsupported combination.
pub(crate) fn validate_canonical_trace_format(cli: &Cli) -> Result<(), CliError> {
    if cli.format == OutputFormat::Markdown && subcommand_uses_canonical_event_trace(&cli.command) {
        return Err(usage_error(
            "--format markdown is reserved for triage reports, not canonical event-log traces",
        ));
    }
    Ok(())
}

pub(crate) fn subcommand_uses_canonical_event_trace(command: &Commands) -> bool {
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

/// Resolves a seed from the flag, environment, or entropy source.
///
/// # Errors
///
/// Returns [`CliError`] when a supplied seed is malformed or the entropy source
/// cannot generate a seed.
pub(crate) fn resolve_seed(
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

/// Parses a CLI seed in decimal or hexadecimal notation.
///
/// # Errors
///
/// Returns [`CliError`] when the seed is empty, too wide, or contains invalid
/// decimal or hexadecimal syntax.
pub(crate) fn parse_seed_value(field: &'static str, value: &str) -> Result<u64, CliError> {
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

pub(crate) fn format_seed(seed: u64) -> String {
    format!("0x{seed:016x}")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalLogEntry {
    pub(crate) sequence: u64,
    pub(crate) virtual_time_ticks: u64,
    pub(crate) node: String,
    pub(crate) kind: String,
    pub(crate) summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RenderedCanonicalLog {
    pub(crate) format: OutputFormat,
    pub(crate) bytes: Vec<u8>,
    pub(crate) entry_count: usize,
    pub(crate) canonical_digest: String,
    pub(crate) jsonl_streams_entries: bool,
}

/// Renders canonical event-log entries in the requested output format.
///
/// # Errors
///
/// Returns [`CliError`] when an entry cannot be serialized or the requested
/// format has no canonical event-log representation.
pub(crate) fn render_canonical_event_log(
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

pub(crate) fn jsonl_for_canonical_log_entries(entries: &[CanonicalLogEntry]) -> String {
    let mut text = String::new();
    for entry in entries {
        text.push_str(&json_for_canonical_log_entry(entry));
        text.push('\n');
    }
    text
}

pub(crate) fn canonical_log_digest(entries: &[CanonicalLogEntry]) -> String {
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

pub(crate) fn json_for_canonical_log_entry(entry: &CanonicalLogEntry) -> String {
    format!(
        "{{\"seq\":{},\"virtual_time\":{},\"node\":\"{}\",\"kind\":\"{}\",\"summary\":\"{}\"}}",
        entry.sequence,
        entry.virtual_time_ticks,
        json_escape(&entry.node),
        json_escape(&entry.kind),
        json_escape(&entry.summary)
    )
}

pub(crate) fn table_for_canonical_log_entries(entries: &[CanonicalLogEntry]) -> String {
    let mut lines = vec![String::from("seq\tvirtual_time\tnode\tkind\tsummary")];
    for entry in entries {
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}",
            entry.sequence, entry.virtual_time_ticks, entry.node, entry.kind, entry.summary
        ));
    }
    lines.join("\n")
}

pub(crate) fn json_escape(value: &str) -> String {
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

/// Renders the canonical trace-format proof used by CLI self-tests.
///
/// # Errors
///
/// Returns [`CliError`] when the proof event log cannot be rendered in one of
/// the required canonical formats.
pub(crate) fn render_canonical_trace_format_proof() -> Result<Vec<RenderedCanonicalLog>, CliError> {
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

pub(crate) fn canonical_state_wall_clock_guard() -> bool {
    let sources = [
        ("crucible-cli", include_str!("../../main.rs")),
        ("crucible-cli-planning", include_str!("../planning.rs")),
        (
            "crucible-cli-planning-invocations",
            include_str!("invocations.rs"),
        ),
        (
            "crucible-cli-planning-verify",
            include_str!("verify_seed_render.rs"),
        ),
        ("crucible-cli-backend", include_str!("../backend.rs")),
        ("crucible-cli-run-save", include_str!("../run_save.rs")),
        (
            "crucible-cli-resume-fork",
            include_str!("../resume_fork.rs"),
        ),
        (
            "crucible-cli-verify-serve",
            include_str!("../verify_serve.rs"),
        ),
        ("crucible-cli-control", include_str!("../control.rs")),
        ("crucible-cli-dispatch", include_str!("../dispatch.rs")),
        (
            "crucible-cli-exploration",
            include_str!("../exploration.rs"),
        ),
        ("crucible-cli-replay", include_str!("../replay.rs")),
        (
            "crucible-cli-triage-debug",
            include_str!("../triage_debug.rs"),
        ),
        ("crucible-cli-artifact", include_str!("../artifact.rs")),
        ("crucible-cli-report", include_str!("../report.rs")),
        (
            "crucible-model",
            include_str!("../../../../crucible/src/model.rs"),
        ),
        (
            "crucible-session",
            include_str!("../../../../crucible-session/src/lib.rs"),
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
pub(crate) struct FailureReproductionFooter {
    pub(crate) artifact_path: PathBuf,
    pub(crate) replay_command: String,
    pub(crate) debug_command: String,
    pub(crate) self_contained_artifact: bool,
}

pub(crate) fn failure_reproduction_footer(path: PathBuf) -> FailureReproductionFooter {
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

pub(crate) fn shell_quote_command_argument(value: &str) -> String {
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

pub(crate) fn is_shell_safe_unquoted_byte(byte: u8) -> bool {
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
