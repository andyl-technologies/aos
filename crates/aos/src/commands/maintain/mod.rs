//! Local foreground package-maintenance controller and process-boundary renderer.

mod discovery;
mod inventory;
mod state;

use std::collections::BTreeMap;
use std::io::Write as _;

use anyhow::{Context as _, Result};
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_maintain::MAINTENANCE_CLI_V1;
use aos_maintain::inventory::Classification;
use aos_maintain::presentation::{
    CommandCompletion, CommandData, CommandDisposition, Diagnostic, DiagnosticSeverity,
    EffectClass, MaintainCommandResult, NextAction, PrimaryValue, escape_terminal,
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
        Some(MaintainCommand::Status(command)) => {
            if command.run.is_some() {
                return completion(
                    "status",
                    CommandDisposition::InvalidInvocation,
                    CommandData::default(),
                    vec![diagnostic(
                        "maintain.run-not-found",
                        DiagnosticSeverity::Error,
                        "No durable maintenance runs have been created yet",
                    )],
                    Vec::new(),
                    Vec::new(),
                );
            }
            cached_completion("status", args, None)
        }
    }
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
        },
        diagnostics,
        vec![PrimaryValue {
            name: "discoverySnapshotDigest".to_string(),
            value: digest.to_string(),
        }],
        Vec::new(),
    )
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
