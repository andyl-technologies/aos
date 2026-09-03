//! Local foreground package-maintenance controller and process-boundary renderer.

mod inventory;

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
pub fn run(cli: &Cli, args: &MaintainArgs) -> Result<CommandCompletion> {
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
        None => completion(
            "home",
            CommandDisposition::ActionRequired,
            CommandData::default(),
            vec![diagnostic(
                "maintain.inventory-not-cached",
                DiagnosticSeverity::Warning,
                "No cached maintenance inventory is available yet",
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
                reason: "the home view never evaluates Nix implicitly".to_string(),
                prerequisites: Vec::new(),
                effect_class: EffectClass::ReadOnly,
                bound_context: None,
            }],
        ),
        Some(MaintainCommand::Inventory(command)) => {
            let evaluated = NixRunner::new(cli.verbose, cli.quiet)
                .and_then(|nix| inventory::evaluate(&nix, command.target.as_deref()));
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
    }
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
    }
}

fn option_conflict(cli: &Cli, args: &MaintainArgs) -> Option<String> {
    if cli.json && args.jsonl {
        return Some("--json cannot be combined with --jsonl".to_string());
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
        printer.kv("Units", &envelope.inventory.units.len().to_string());
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
