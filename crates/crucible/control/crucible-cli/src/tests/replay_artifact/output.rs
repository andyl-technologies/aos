//! Exit-code and machine-readable backend output tests.

use super::*;

#[test]
pub(super) fn cli_exit_machine_readable_mapping_matches_rfc_15() {
    let cases = [
        (CliError::Outcome(BackendCommandStatus::Passed), 0),
        (CliError::Outcome(BackendCommandStatus::Failed), 1),
        (CliError::ReplayCheck(String::from("mismatch")), 1),
        (CliError::Outcome(BackendCommandStatus::Timeout), 2),
        (CliError::Outcome(BackendCommandStatus::Crashed), 3),
        (CliError::Serve(String::from("backend error")), 3),
        (
            CliError::Identity(String::from("pinned identity mismatch")),
            3,
        ),
        (CliError::Backend(String::from("discovery/config error")), 4),
        (CliError::InvalidScenario(String::from("bad scenario")), 5),
        (CliError::Artifact(String::from("bad artifact")), 5),
        (CliError::Usage(String::from("bad flags")), 64),
    ];

    for (error, expected) in cases {
        assert_eq!(error.exit_code(), expected, "{error}");
    }
}

#[test]
pub(super) fn cli_exit_machine_readable_output_records_final_outcome() -> Result<(), Box<dyn Error>>
{
    let temp = TempDir::new()?;
    let scenario = write_valid_run_scenario(&temp)?;
    let cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("1"),
        String::from("run"),
        scenario.display().to_string(),
    ]);
    let Commands::Run(args) = &cli.command else {
        panic!("expected run command");
    };
    let run_plan = plan_run_invocation(args, temp.path())?;
    let seed_plan = plan_determinism_ergonomics(
        &cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("run should resolve a seed");
    let outcome = execute_backend_routed_command(
        &plan_cli_invocation(&cli),
        &plan_backend_selection(&cli)?.expect("run should require backend selection"),
        Some(&seed_plan),
        Some(&run_plan),
        None,
        None,
        &mut NullBackendCommandRunner,
    )?;

    let entries = backend_machine_readable_trace_entries(&outcome);
    let final_entry = entries.last().expect("final outcome entry");
    assert_eq!(entries.len(), outcome.canonical_log.len() + 1);
    assert_eq!(final_entry.kind, "final_outcome");
    assert_eq!(final_entry.node, "cli");
    assert!(final_entry.summary.contains("subcommand=run"));
    assert!(final_entry.summary.contains("status=passed"));
    assert!(final_entry.summary.contains("exit_code=0"));
    assert!(final_entry.summary.contains(&outcome.canonical_log_digest));
    assert!(final_entry.summary.contains(&outcome.artifact_digest));

    let jsonl = render_canonical_event_log(OutputFormat::Jsonl, &entries)?;
    let jsonl_text = String::from_utf8(jsonl.bytes)?;
    assert_eq!(jsonl_text.lines().count(), entries.len());
    assert!(
        jsonl_text
            .lines()
            .last()
            .expect("jsonl final line")
            .contains("\"kind\":\"final_outcome\"")
    );
    let json = render_canonical_event_log(OutputFormat::Json, &entries)?;
    assert!(String::from_utf8(json.bytes)?.contains("\"kind\":\"final_outcome\""));
    assert!(!should_emit_human_backend_output(OutputFormat::Jsonl));
    assert!(!should_emit_human_backend_output(OutputFormat::Json));
    assert!(should_emit_human_backend_output(OutputFormat::Table));

    let trace_path = temp.path().join("run.trace.jsonl");
    let trace_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("1"),
        String::from("--format"),
        String::from("jsonl"),
        String::from("--quiet"),
        String::from("--trace"),
        trace_path.display().to_string(),
        String::from("run"),
        scenario.display().to_string(),
    ]);
    emit_backend_command_output(&trace_cli, &outcome)?;
    let trace_bytes = fs::read(&trace_path)?;
    assert_eq!(
        trace_bytes,
        canonical_log_entry_bytes(&outcome.canonical_log)
    );
    assert!(!String::from_utf8(trace_bytes)?.contains("\"kind\":\"final_outcome\""));

    Ok(())
}
