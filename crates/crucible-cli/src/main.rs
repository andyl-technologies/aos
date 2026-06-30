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

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

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
    #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl, global = true)]
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
    /// Cluster discovered failures.
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
struct TriageArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct DebugArgs {
    /// Read this reproduction artifact.
    #[arg(value_name = "ARTIFACT")]
    artifact: Option<PathBuf>,
    /// Open at the recorded failure point.
    #[arg(long, action = ArgAction::SetTrue)]
    at_failure: bool,
}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct ServeArgs {}

#[derive(Args, Debug, Default, PartialEq, Eq)]
struct CompletionsArgs {}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = dispatch(&cli) {
        eprintln!("crucible: {error}");
        std::process::exit(error.exit_code());
    }
}

fn dispatch(cli: &Cli) -> Result<(), CliError> {
    match &cli.command {
        Commands::Replay(args) => {
            let report = replay_reproduction_artifact(args)?;
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
                let artifact = mock_failure_reproduction_artifact_bytes()?;
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
        Commands::Verify(_)
        | Commands::Selftest(_)
        | Commands::Save(_)
        | Commands::Resume(_)
        | Commands::Fork(_)
        | Commands::Search(_)
        | Commands::Fuzz(_)
        | Commands::Triage(_)
        | Commands::Debug(_)
        | Commands::Serve(_)
        | Commands::Completions(_) => Ok(()),
    }
}

fn replay_reproduction_artifact(args: &ReplayArgs) -> Result<ReplayArtifactReport, CliError> {
    let bytes = fs::read(&args.artifact)?;
    let artifact = decode_reproduction_artifact(&bytes)?;
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
    decode_reproduction_artifact(artifact_bytes)?;
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
    let debug_command = format!("crucible debug {} --at-failure", path.display());

    Ok(FailureArtifactReport {
        path,
        digest,
        replay_command,
        debug_command,
    })
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

#[derive(Debug)]
struct CliIdentity {
    engine_version: String,
    engine_abi: String,
    artifact_abi: String,
    qemu_build_id: String,
    plugin_abi: String,
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

fn mock_failure_reproduction_artifact_bytes() -> Result<Vec<u8>, CliError> {
    let seed = 0xe2e0_0010_u64;
    let scenario_material = b"scenario\tmock-failure\nnode\tnode-a\tserver\n";
    let scenario_digest = content_address_bytes(scenario_material);
    let qemu_build_id = content_address_bytes(b"mock-qemu-build");
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
            env!("CARGO_PKG_VERSION"),
            "engine-abi:v1",
            REPRODUCTION_ARTIFACT_SCHEMA,
            &qemu_build_id,
            "plugin-abi:v1",
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
    decode_reproduction_artifact(&bytes)?;
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

#[derive(Debug)]
enum CliError {
    Io(io::Error),
    Artifact(String),
}

impl CliError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) => 5,
            Self::Artifact(_) => 5,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Artifact(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Artifact(_) => None,
        }
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
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
    fn cli_replay_validates_reproduction_artifact() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("case.crucible");
        let artifact = mock_e2e_reproduction_artifact()?;
        fs::write(&path, artifact.encode()?)?;

        let report = replay_reproduction_artifact(&ReplayArgs {
            artifact: path.clone(),
        })?;

        assert_eq!(report.path, path);
        assert_eq!(report.seed, artifact.seed);
        assert_eq!(report.scenario_digest, artifact.scenario.digest);
        assert_eq!(report.digest, artifact.digest()?);

        Ok(())
    }

    #[test]
    fn cli_failure_artifact_writer_emits_replay_and_debug_commands() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let cli = Cli::parse_from([
            "crucible",
            "--artifact-dir",
            temp.path().to_str().unwrap_or("."),
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
        assert!(report.path.to_string_lossy().contains("property-violation"));
        let debug_cli = Cli::parse_from([
            "crucible",
            "debug",
            report.path.to_str().unwrap_or("."),
            "--at-failure",
        ]);
        assert!(matches!(
            debug_cli.command,
            Commands::Debug(DebugArgs {
                artifact: Some(_),
                at_failure: true,
            })
        ));
        assert_eq!(
            ReproductionArtifact::decode(&fs::read(&report.path)?)?,
            artifact
        );
        assert_eq!(report.digest, artifact.digest()?);

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

        let error = match replay_reproduction_artifact(&ReplayArgs { artifact: path }) {
            Ok(_) => panic!("duplicate singleton line must fail CLI replay validation"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("duplicate singleton line"));

        Ok(())
    }

    #[test]
    fn cli_mock_failure_artifact_is_harness_decodable() -> Result<(), Box<dyn Error>> {
        let bytes = mock_failure_reproduction_artifact_bytes()?;
        let artifact = ReproductionArtifact::decode(&bytes)?;

        assert_eq!(artifact.seed, 0xe2e0_0010);
        assert_eq!(artifact.schema_version, REPRODUCTION_ARTIFACT_SCHEMA);

        Ok(())
    }
}
