//! Search, replay, artifact, and deterministic execution tests.

use super::*;
#[test]
pub(super) fn cli_search_fuzz_help_surface_lists_wip_flags() {
    let mut command = Cli::command();
    for (name, needles) in [
        (
            "search",
            &[
                "SCENARIO",
                "--strategy <bfs|dfs|guided>",
                "--max-depth <n>",
                "--max-states <n>",
                "--on-violation <stop|collect>",
                "--schedule-named-truths <path>",
            ][..],
        ),
        (
            "fuzz",
            &[
                "FAMILY",
                "--family <path|hash>",
                "--runs <n>",
                "--coverage <basic-block>",
                "--corpus <path>",
            ][..],
        ),
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
pub(super) fn cli_search_fuzz_workflow_plans_drivers_and_rejects_bad_inputs()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario = write_valid_run_scenario(&temp)?;
    let named_truths = write_search_schedule_named_truths(&temp, true)?;
    let search_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("search"),
        scenario.display().to_string(),
        String::from("--strategy"),
        String::from("guided"),
        String::from("--max-depth"),
        String::from("3"),
        String::from("--max-states"),
        String::from("7"),
        String::from("--on-violation"),
        String::from("collect"),
        String::from("--schedule-named-truths"),
        named_truths.display().to_string(),
    ]);
    let Commands::Search(args) = &search_cli.command else {
        panic!("expected search command");
    };
    let search_plan = plan_search_invocation(args, temp.path())?;

    assert!(matches!(search_plan.scenario, RunScenarioRef::File { .. }));
    assert_eq!(search_plan.strategy_arg, SearchStrategyArg::Guided);
    assert_eq!(
        search_plan.engine_strategy,
        crucible::SearchStrategy::CoverageGuided
    );
    assert_eq!(search_plan.max_depth, Some(3));
    assert_eq!(search_plan.max_states, 7);
    assert_eq!(search_plan.budget, crucible::SearchBudget::new(7));
    assert_eq!(search_plan.on_violation, SearchOnViolationArg::Collect);
    assert!(search_plan.explicit_on_violation);
    let search_truths = search_plan
        .schedule_named_truths
        .as_ref()
        .expect("search plan should load schedule-named truths");
    assert_eq!(search_truths.path, named_truths);
    assert_eq!(
        search_truths.digest,
        content_address_bytes(valid_search_schedule_named_truths_toml(true).as_bytes())
    );
    assert!(!search_truths.truths.is_empty());
    assert!(search_plan.delegates_policy_to_advanced_engine);
    assert!(search_plan.opportunistic_replay_oracle_sampling);
    assert!(search_plan.counterexamples_are_self_contained);

    let retained_scenario = write_search_retained_evidence_scenario(&temp)?;
    let retained_evidence = write_search_retained_evidence(&temp)?;
    let retained_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("search"),
        retained_scenario.display().to_string(),
        String::from("--retained-evidence"),
        retained_evidence.display().to_string(),
    ]);
    let Commands::Search(args) = &retained_cli.command else {
        panic!("expected search command");
    };
    let retained_plan = plan_search_invocation(args, temp.path())?;
    let retained_source = retained_plan
        .retained_evidence
        .as_ref()
        .expect("search plan should load retained evidence");
    assert_eq!(retained_source.path, retained_evidence);
    assert_eq!(
        retained_source.digest,
        content_address_bytes(valid_search_retained_evidence_toml("root").as_bytes())
    );
    let retained_root =
        crucible::Configuration::genesis(retained_plan.scenario.scenario_def().clone());
    assert!(retained_source.evidence.contains_key(&retained_root.id()));

    let terminal_quiescence_scenario = write_search_terminal_quiescence_scenario(&temp)?;
    let terminal_quiescence_evidence = write_search_terminal_quiescence_retained_evidence(&temp)?;
    let terminal_quiescence_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("search"),
        terminal_quiescence_scenario.display().to_string(),
        String::from("--retained-evidence"),
        terminal_quiescence_evidence.display().to_string(),
    ]);
    let Commands::Search(args) = &terminal_quiescence_cli.command else {
        panic!("expected search command");
    };
    let terminal_quiescence_plan = plan_search_invocation(args, temp.path())?;
    let terminal_quiescence_source = terminal_quiescence_plan
        .retained_evidence
        .as_ref()
        .expect("search plan should load terminal quiescence retained evidence");
    assert_eq!(
        terminal_quiescence_source.path,
        terminal_quiescence_evidence
    );
    assert_eq!(
        terminal_quiescence_source.digest,
        content_address_bytes(
            valid_search_terminal_quiescence_retained_evidence_toml("root").as_bytes()
        )
    );
    let terminal_quiescence_root =
        crucible::Configuration::genesis(terminal_quiescence_plan.scenario.scenario_def().clone());
    let terminal_quiescence = terminal_quiescence_source
        .evidence
        .get(&terminal_quiescence_root.id())
        .and_then(|evidence| evidence.terminal_quiescence())
        .expect("terminal quiescence retained evidence should bind to the root");
    assert!(terminal_quiescence.is_quiescent());

    let terminal_sometimes_scenario = write_search_terminal_sometimes_scenario(&temp)?;
    let terminal_sometimes_evidence = write_search_terminal_sometimes_retained_evidence(&temp)?;
    let terminal_sometimes_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("search"),
        terminal_sometimes_scenario.display().to_string(),
        String::from("--retained-evidence"),
        terminal_sometimes_evidence.display().to_string(),
    ]);
    let Commands::Search(args) = &terminal_sometimes_cli.command else {
        panic!("expected search command");
    };
    let terminal_sometimes_plan = plan_search_invocation(args, temp.path())?;
    let terminal_sometimes_source = terminal_sometimes_plan
        .retained_evidence
        .as_ref()
        .expect("search plan should load terminal sometimes retained evidence");
    assert_eq!(terminal_sometimes_source.path, terminal_sometimes_evidence);
    assert_eq!(
        terminal_sometimes_source.digest,
        content_address_bytes(
            valid_search_terminal_sometimes_retained_evidence_toml("root").as_bytes()
        )
    );
    let terminal_sometimes_root =
        crucible::Configuration::genesis(terminal_sometimes_plan.scenario.scenario_def().clone());
    let terminal_sometimes = terminal_sometimes_source
        .evidence
        .get(&terminal_sometimes_root.id())
        .expect("terminal sometimes retained evidence should bind to the root");
    assert_eq!(terminal_sometimes.recorded_log().entries().len(), 1);
    let terminal_sometimes_boundary = &terminal_sometimes.recorded_log().entries()[0];
    assert_eq!(terminal_sometimes_boundary.at().ticks, 50);
    assert!(matches!(
        terminal_sometimes_boundary.payload(),
        crucible::SchedulerEventLogPayload::EvaluationBoundary(
            crucible::SchedulerEvaluationBoundaryKind::Quantum
        )
    ));
    assert!(
        terminal_sometimes
            .terminal_quiescence()
            .is_some_and(crucible::SchedulerQuiescence::is_quiescent)
    );

    for args in [
        SearchArgs {
            scenario: Some(scenario.display().to_string()),
            max_depth: Some(0),
            ..SearchArgs::default()
        },
        SearchArgs {
            scenario: Some(scenario.display().to_string()),
            max_states: 0,
            ..SearchArgs::default()
        },
    ] {
        let error = match plan_search_invocation(&args, temp.path()) {
            Ok(_) => panic!("zero search budget must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::Usage(_)));
        assert_eq!(error.exit_code(), 64);
    }

    let missing_scenario_file = temp.path().join("missing-search.toml");
    let error = match plan_search_invocation(
        &SearchArgs {
            scenario: Some(missing_scenario_file.display().to_string()),
            max_states: 1,
            ..SearchArgs::default()
        },
        temp.path(),
    ) {
        Ok(_) => panic!("missing search scenario must be discovery/config"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);

    let malformed_named_truths = temp.path().join("bad-search-named-truths.toml");
    fs::write(&malformed_named_truths, "schema = \"wrong.schema\"\n")?;
    let error = match plan_search_invocation(
        &SearchArgs {
            scenario: Some(scenario.display().to_string()),
            max_states: 1,
            schedule_named_truths: Some(malformed_named_truths),
            ..SearchArgs::default()
        },
        temp.path(),
    ) {
        Ok(_) => panic!("malformed schedule-named truths must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);

    let duplicate_named_truths = temp.path().join("duplicate-search-named-truths.toml");
    fs::write(
        &duplicate_named_truths,
        r#"schema = "crucible.search-schedule-named-truths.v1"

[[truth]]
name = "cli-search/named-truth"
value = true
active_fault_tags = ["network-partition", "network-partition"]

[[truth]]
name = "cli-search/named-truth"
value = false
active_fault_tags = ["network-partition"]
"#,
    )?;
    let error = match plan_search_invocation(
        &SearchArgs {
            scenario: Some(scenario.display().to_string()),
            max_states: 1,
            schedule_named_truths: Some(duplicate_named_truths),
            ..SearchArgs::default()
        },
        temp.path(),
    ) {
        Ok(_) => panic!("duplicate schedule-named truth keys must fail"),
        Err(error) => error,
    };
    assert!(
        matches!(error, CliError::Backend(ref message) if message.contains("duplicates canonical entry 0"))
    );
    assert_eq!(error.exit_code(), 4);

    let malformed_retained_evidence = temp.path().join("bad-search-retained-evidence.toml");
    fs::write(&malformed_retained_evidence, "schema = \"wrong.schema\"\n")?;
    let error = match plan_search_invocation(
        &SearchArgs {
            scenario: Some(retained_scenario.display().to_string()),
            max_states: 1,
            retained_evidence: Some(malformed_retained_evidence),
            ..SearchArgs::default()
        },
        temp.path(),
    ) {
        Ok(_) => panic!("malformed retained evidence must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);

    let unknown_node_retained_evidence = temp
        .path()
        .join("unknown-node-search-retained-evidence.toml");
    fs::write(
        &unknown_node_retained_evidence,
        r#"schema = "crucible.search-retained-evidence.v1"

[[evidence]]
configuration = "root"
kind = "guest-marker"
node = "missing-node"
marker = "forbidden-search-marker"
"#,
    )?;
    let error = match plan_search_invocation(
        &SearchArgs {
            scenario: Some(retained_scenario.display().to_string()),
            max_states: 1,
            retained_evidence: Some(unknown_node_retained_evidence),
            ..SearchArgs::default()
        },
        temp.path(),
    ) {
        Ok(_) => panic!("retained evidence with unknown node must fail"),
        Err(error) => error,
    };
    assert!(
        matches!(error, CliError::Backend(ref message) if message.contains("unknown node `missing-node`"))
    );
    assert_eq!(error.exit_code(), 4);

    let disabled_node_retained_evidence = temp
        .path()
        .join("disabled-node-search-retained-evidence.toml");
    fs::write(
        &disabled_node_retained_evidence,
        r#"schema = "crucible.search-retained-evidence.v1"

[[evidence]]
configuration = "root"
kind = "guest-marker"
node = "cli-search-node"
marker = "forbidden-search-marker"
"#,
    )?;
    let disabled_node_scenario = write_search_frontier_scenario(&temp)?;
    let error = match plan_search_invocation(
        &SearchArgs {
            scenario: Some(disabled_node_scenario.display().to_string()),
            max_states: 1,
            retained_evidence: Some(disabled_node_retained_evidence),
            ..SearchArgs::default()
        },
        temp.path(),
    ) {
        Ok(_) => panic!("guest-marker retained evidence must require white-box nodes"),
        Err(error) => error,
    };
    assert!(
        matches!(error, CliError::Backend(ref message) if message.contains("not white-box enabled"))
    );
    assert_eq!(error.exit_code(), 4);

    let malformed_boundary_evidence = temp.path().join("bad-boundary-retained-evidence.toml");
    fs::write(
        &malformed_boundary_evidence,
        r#"schema = "crucible.search-retained-evidence.v1"

[[evidence]]
configuration = "root"
kind = "evaluation-boundary"
"#,
    )?;
    let error = match plan_search_invocation(
        &SearchArgs {
            scenario: Some(terminal_sometimes_scenario.display().to_string()),
            max_states: 1,
            retained_evidence: Some(malformed_boundary_evidence),
            ..SearchArgs::default()
        },
        temp.path(),
    ) {
        Ok(_) => panic!("evaluation-boundary retained evidence must require virtual time"),
        Err(error) => error,
    };
    assert!(
        matches!(error, CliError::Backend(ref message) if message.contains("missing virtual_time_ticks"))
    );
    assert_eq!(error.exit_code(), 4);

    let blocked_terminal_quiescence_evidence = temp
        .path()
        .join("blocked-terminal-quiescence-evidence.toml");
    fs::write(
        &blocked_terminal_quiescence_evidence,
        r#"schema = "crucible.search-retained-evidence.v1"

[[evidence]]
configuration = "root"
kind = "terminal-quiescence"
quiescent = false
"#,
    )?;
    let error = match plan_search_invocation(
        &SearchArgs {
            scenario: Some(terminal_quiescence_scenario.display().to_string()),
            max_states: 1,
            retained_evidence: Some(blocked_terminal_quiescence_evidence),
            ..SearchArgs::default()
        },
        temp.path(),
    ) {
        Ok(_) => {
            panic!("blocked terminal quiescence evidence must fail until blockers are modeled")
        }
        Err(error) => error,
    };
    assert!(
        matches!(error, CliError::Backend(ref message) if message.contains("only supports quiescent = true"))
    );
    assert_eq!(error.exit_code(), 4);

    let error = match plan_search_invocation(
        &SearchArgs {
            scenario: Some(retained_scenario.display().to_string()),
            max_states: 1,
            schedule_named_truths: Some(named_truths.clone()),
            retained_evidence: Some(write_search_retained_evidence(&temp)?),
            ..SearchArgs::default()
        },
        temp.path(),
    ) {
        Ok(_) => panic!("mixed retained evidence and schedule-named truths must fail"),
        Err(error) => error,
    };
    assert!(
        matches!(error, CliError::Backend(ref message) if message.contains("cannot be combined"))
    );
    assert_eq!(error.exit_code(), 4);

    let family_path = write_valid_fuzz_family(&temp)?;
    let corpus = temp.path().join("corpus");
    fs::create_dir(&corpus)?;
    let fuzz_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--seed"),
        String::from("0x55"),
        String::from("fuzz"),
        family_path.display().to_string(),
        String::from("--runs"),
        String::from("5"),
        String::from("--coverage"),
        String::from("basic-block"),
        String::from("--corpus"),
        corpus.display().to_string(),
    ]);
    let seed_plan = plan_determinism_ergonomics(
        &fuzz_cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("fuzz should resolve a seed");
    let Commands::Fuzz(args) = &fuzz_cli.command else {
        panic!("expected fuzz command");
    };
    let fuzz_plan = plan_fuzz_invocation(args, &seed_plan, temp.path())?;

    assert_eq!(fuzz_plan.family, FuzzFamilyRef::File(family_path.clone()));
    assert_eq!(fuzz_plan.runs, 5);
    assert_eq!(fuzz_plan.coverage, FuzzCoverageArg::BasicBlock);
    assert_eq!(fuzz_plan.corpus.as_deref(), Some(corpus.as_path()));
    assert_eq!(
        fuzz_plan.config,
        crucible::CoverageGuidedFuzzConfig::new(crucible::Seed::from_u64(0x55), 5)
    );
    assert!(fuzz_plan.delegates_policy_to_advanced_engine);
    assert!(fuzz_plan.pins_one_scenario_def_per_iteration);
    assert!(fuzz_plan.counterexamples_are_self_contained);
    assert_eq!(load_fuzz_family(&fuzz_plan)?.space().cardinality()?, 8);

    let reference = format_content_hash_ref(crucible::ContentHash::from_bytes(b"family-ref"));
    let hash_cli = Cli::parse_from(["crucible", "fuzz", "--family", &reference]);
    let Commands::Fuzz(args) = &hash_cli.command else {
        panic!("expected fuzz command");
    };
    let hash_seed = plan_determinism_ergonomics(
        &hash_cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(1),
    )?
    .expect("fuzz should resolve a generated seed");
    let hash_plan = plan_fuzz_invocation(args, &hash_seed, temp.path())?;
    assert!(matches!(hash_plan.family, FuzzFamilyRef::Stored(_)));

    let builtin_cli = Cli::parse_from([
        "crucible",
        "--seed",
        "0x55",
        "fuzz",
        "--family",
        crucible::FAULT_CAMPAIGN_FAMILY_NAME,
    ]);
    let Commands::Fuzz(args) = &builtin_cli.command else {
        panic!("expected fuzz command");
    };
    let builtin_seed = plan_determinism_ergonomics(
        &builtin_cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(2),
    )?
    .expect("built-in fuzz should resolve a seed");
    let builtin_plan = plan_fuzz_invocation(args, &builtin_seed, temp.path())?;
    assert_eq!(builtin_plan.family, FuzzFamilyRef::BuiltInFaultCampaign);
    assert_eq!(
        builtin_plan.config,
        crucible::CoverageGuidedFuzzConfig::new(crucible::Seed::from_u64(0x55), 1)
    );

    let malformed_hash = FuzzArgs {
        family: Some(String::from("blake3:not-a-hash")),
        runs: 1,
        ..FuzzArgs::default()
    };
    let error = match plan_fuzz_invocation(&malformed_hash, &seed_plan, temp.path()) {
        Ok(_) => panic!("malformed fuzz family hash must be discovery/config"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);

    for args in [
        FuzzArgs::default(),
        FuzzArgs {
            family: Some(family_path.display().to_string()),
            family_flag: Some(reference.clone()),
            ..FuzzArgs::default()
        },
        FuzzArgs {
            family: Some(family_path.display().to_string()),
            runs: 0,
            ..FuzzArgs::default()
        },
    ] {
        let error = match plan_fuzz_invocation(&args, &seed_plan, temp.path()) {
            Ok(_) => panic!("malformed fuzz invocation must fail"),
            Err(error) => error,
        };
        assert!(
            matches!(error, CliError::Usage(_)),
            "unexpected error: {error}"
        );
        assert_eq!(error.exit_code(), 64);
    }

    let corpus_file = temp.path().join("corpus-file");
    fs::write(&corpus_file, "not a directory")?;
    let error = match plan_fuzz_invocation(
        &FuzzArgs {
            family: Some(family_path.display().to_string()),
            runs: 1,
            corpus: Some(corpus_file),
            ..FuzzArgs::default()
        },
        &seed_plan,
        temp.path(),
    ) {
        Ok(_) => panic!("file corpus must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);

    Ok(())
}

#[test]
pub(super) fn cli_fuzz_runs_builtin_fault_campaign_family() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse_from([
        "crucible",
        "--quiet",
        "--backend",
        "double",
        "--seed",
        "0x33a4",
        "fuzz",
        "--family",
        crucible::FAULT_CAMPAIGN_FAMILY_NAME,
        "--runs",
        "2",
    ]);

    let Commands::Fuzz(args) = &cli.command else {
        panic!("expected fuzz command");
    };
    let seed_plan = plan_determinism_ergonomics(
        &cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("built-in fuzz should resolve a seed");
    let fuzz_plan = plan_fuzz_invocation(args, &seed_plan, &default_run_store_root(&cli))?;
    let backend_plan = plan_backend_selection(&cli)?.expect("built-in fuzz should route");
    assert_eq!(
        fuzz_dispatch_route(&backend_plan, &fuzz_plan),
        Some(FuzzDispatchRoute::BuiltInFaultCampaignProof)
    );

    dispatch(&cli).expect("built-in fault campaign fuzz should run on the local proof path");
    Ok(())
}

#[test]
pub(super) fn cli_search_fuzz_workflow_executes_local_double_search() -> Result<(), Box<dyn Error>>
{
    assert_eq!(
        local_double_search_status(false, false, SearchOnViolationArg::Stop),
        BackendCommandStatus::Timeout
    );
    assert_eq!(
        local_double_search_status(false, false, SearchOnViolationArg::Collect),
        BackendCommandStatus::Passed
    );
    assert_eq!(
        local_double_search_status(true, false, SearchOnViolationArg::Collect),
        BackendCommandStatus::Failed
    );

    let temp = TempDir::new()?;
    let scenario = write_valid_run_scenario(&temp)?;
    let search_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("search"),
        scenario.display().to_string(),
        String::from("--strategy"),
        String::from("dfs"),
        String::from("--max-states"),
        String::from("1"),
    ]);
    let Commands::Search(args) = &search_cli.command else {
        panic!("expected search command");
    };
    let search_plan = plan_search_invocation(args, temp.path())?;
    let backend_plan =
        plan_backend_selection(&search_cli)?.expect("search should route to backend");

    let frontier_scenario = write_search_frontier_scenario(&temp)?;
    let frontier_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("search"),
        frontier_scenario.display().to_string(),
        String::from("--max-states"),
        String::from("1"),
    ]);
    let Commands::Search(args) = &frontier_cli.command else {
        panic!("expected search command");
    };
    let frontier_plan = plan_search_invocation(args, temp.path())?;
    let frontier_backend =
        plan_backend_selection(&frontier_cli)?.expect("search should route to backend");
    let frontier_root =
        crucible::Configuration::genesis(frontier_plan.scenario.scenario_def().clone());
    let mut frontier_graph = search_frontier_graph(frontier_plan.scenario.scenario_form())?;
    let timeout_outcome = run_local_double_search_workflow_with_graph(
        &plan_cli_invocation(&frontier_cli),
        &frontier_backend,
        None,
        &frontier_plan,
        &frontier_root,
        &mut frontier_graph,
    )?;
    assert_eq!(timeout_outcome.status, BackendCommandStatus::Timeout);
    assert_eq!(timeout_outcome.exit_code, 2);
    assert!(
        timeout_outcome
            .stdout
            .iter()
            .any(|line| line.contains("budget_exhausted=true")
                && line.contains("replay_oracle_considered=1")
                && line.contains("replay_oracle_sampled=1")
                && line.contains("status=timeout"))
    );
    assert!(timeout_outcome.canonical_log.iter().any(|entry| {
        entry.kind == "search_strategy_run" && entry.summary.contains("status=timeout")
    }));

    let artifact_dir = temp.path().join("search-counterexamples");
    let failure_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--artifact-dir"),
        artifact_dir.display().to_string(),
        String::from("search"),
        frontier_scenario.display().to_string(),
        String::from("--max-states"),
        String::from("2"),
    ]);
    let Commands::Search(args) = &failure_cli.command else {
        panic!("expected search command");
    };
    let failure_plan = plan_search_invocation(args, temp.path())?;
    let failure_backend =
        plan_backend_selection(&failure_cli)?.expect("search should route to backend");
    let mut candidate_graph = search_frontier_graph(failure_plan.scenario.scenario_form())?;
    let candidate_run = candidate_graph.search_with_strategy_and_failure_oracle_bounded_depth(
        failure_plan.scenario.scenario_form(),
        &frontier_root,
        failure_plan.engine_strategy,
        crucible::SearchBudget::new(1),
        MaterializationPolicy::with_budget(search_materialization_budget(failure_plan.max_states)),
        MaterializationTrigger::RepeatedForkSource,
        &SearchFailureOracle::none(),
        failure_plan.max_depth,
    )?;
    let failed_configuration = candidate_run
        .expansions
        .first()
        .and_then(|expansion| expansion.search.frontier_report.explored.first())
        .map(|child| child.configuration.id())
        .expect("frontier fixture must expose a child failure candidate");
    let failure_fingerprint = crucible::ContentHash::from_canonical_material(
        "crucible.cli.search.counterexample.test.v1",
        &format!(
            "assertion=cli-search-counterexample\nconfiguration={}",
            format_content_hash_ref(failed_configuration)
        ),
    );
    let failure_oracle =
        SearchFailureOracle::none().with_failure(failed_configuration, failure_fingerprint);
    let mut failure_graph = search_frontier_graph(failure_plan.scenario.scenario_form())?;
    let failure_outcome = run_local_double_search_workflow_with_graph_and_failure_oracle(
        &plan_cli_invocation(&failure_cli),
        &failure_backend,
        None,
        &failure_plan,
        &frontier_root,
        &mut failure_graph,
        &failure_oracle,
        "scenario-assertions",
    )?;
    assert_eq!(failure_outcome.status, BackendCommandStatus::Failed);
    assert_eq!(failure_outcome.exit_code, 1);
    let failure_line = failure_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("search-run\t"))
        .expect("failed search workflow must emit a search-run line");
    assert!(failure_line.contains("failure_oracle=scenario-assertions"));
    assert!(failure_line.contains("failures=1"));
    assert!(failure_line.contains(&format!(
        "counterexample={}",
        format_content_hash_ref(failed_configuration)
    )));
    assert!(failure_line.contains(&format!(
        "counterexample_fingerprint={}",
        format_content_hash_ref(failure_fingerprint)
    )));
    assert!(failure_line.contains("counterexample_artifact=crucible-hash:"));
    assert!(failure_line.contains("status=failed"));
    let artifact = failure_outcome
        .reproduction_artifact
        .as_ref()
        .expect("failed search must attach a counterexample artifact");
    let decoded_artifact = validate_replayable_reproduction_artifact(&failure_cli, artifact)?;
    assert_eq!(
        decoded_artifact
            .fingerprints
            .first()
            .map(|fingerprint| fingerprint.digest.as_str()),
        Some(cli_digest_from_engine_hash(failure_fingerprint).as_str())
    );
    emit_backend_command_output(&failure_cli, &failure_outcome)?;
    let emitted_artifacts = fs::read_dir(&artifact_dir)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(emitted_artifacts.len(), 1);
    assert!(
        emitted_artifacts[0]
            .file_name()
            .to_string_lossy()
            .starts_with("repro-failed-")
    );

    let root_failure_fingerprint = crucible::ContentHash::from_canonical_material(
        "crucible.cli.search.root-counterexample.test.v1",
        &format!(
            "assertion=cli-search-root-counterexample\nconfiguration={}",
            format_content_hash_ref(frontier_root.id())
        ),
    );
    let root_failure_oracle =
        SearchFailureOracle::none().with_failure(frontier_root.id(), root_failure_fingerprint);
    let mut root_failure_graph = search_frontier_graph(failure_plan.scenario.scenario_form())?;
    let root_failure_outcome = run_local_double_search_workflow_with_graph_and_failure_oracle(
        &plan_cli_invocation(&failure_cli),
        &failure_backend,
        None,
        &failure_plan,
        &frontier_root,
        &mut root_failure_graph,
        &root_failure_oracle,
        "scenario-assertions",
    )?;
    assert_eq!(root_failure_outcome.status, BackendCommandStatus::Failed);
    let root_failure_line = root_failure_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("search-run\t"))
        .expect("root-failure search workflow must emit a search-run line");
    assert!(root_failure_line.contains(&format!(
        "counterexample={}",
        format_content_hash_ref(frontier_root.id())
    )));
    let root_artifact = root_failure_outcome
        .reproduction_artifact
        .as_ref()
        .expect("root search failure must attach a counterexample artifact");
    let root_decoded = validate_replayable_reproduction_artifact(&failure_cli, root_artifact)?;
    assert_eq!(root_decoded.decisions.len(), 1);
    assert_eq!(
        root_decoded
            .decisions
            .first()
            .map(|decision| decision.kind.as_str()),
        Some("root-failure")
    );
    assert_eq!(
        root_decoded
            .fingerprints
            .first()
            .map(|fingerprint| fingerprint.digest.as_str()),
        Some(cli_digest_from_engine_hash(root_failure_fingerprint).as_str())
    );

    let named_scenario = write_search_named_truth_scenario(&temp)?;
    let named_truths_false = write_search_schedule_named_truths(&temp, false)?;
    let named_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("search"),
        named_scenario.display().to_string(),
        String::from("--max-states"),
        String::from("1"),
        String::from("--schedule-named-truths"),
        named_truths_false.display().to_string(),
    ]);
    let Commands::Search(args) = &named_cli.command else {
        panic!("expected search command");
    };
    let named_plan = plan_search_invocation(args, temp.path())?;
    let named_backend =
        plan_backend_selection(&named_cli)?.expect("named-truth search should route");
    let named_outcome = run_local_double_search_workflow(
        &plan_cli_invocation(&named_cli),
        &named_backend,
        None,
        &named_plan,
    )?;
    assert_eq!(named_outcome.status, BackendCommandStatus::Failed);
    assert_eq!(named_outcome.exit_code, 1);
    let named_line = named_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("search-run\t"))
        .expect("named-truth search workflow must emit a search-run line");
    assert!(named_line.contains("failure_oracle=scenario-assertions+schedule-named-truths"));
    assert!(named_line.contains(&format!(
        "schedule_named_truths={}",
        named_truths_false.display()
    )));
    let named_truths_false_material = valid_search_schedule_named_truths_toml(false);
    let named_truths_false_digest = content_address_bytes(named_truths_false_material.as_bytes());
    assert!(named_line.contains(&format!(
        "schedule_named_truths_digest={named_truths_false_digest}"
    )));
    assert!(named_line.contains("failures=1"));
    assert!(named_line.contains("status=failed"));
    let named_artifact = decode_reproduction_artifact(
        named_outcome
            .reproduction_artifact
            .as_deref()
            .expect("named-truth failure should emit a reproduction artifact"),
    )?;
    assert!(named_artifact.components.iter().any(|component| {
        component.kind == "search_schedule_named_truths"
            && component.name == "schedule-named-truths.toml"
            && component.digest == named_truths_false_digest
            && component.media_type == SEARCH_SCHEDULE_NAMED_TRUTHS_MEDIA_TYPE
    }));
    assert!(named_artifact.payloads.iter().any(|payload| {
        payload.digest == named_truths_false_digest
            && payload.bytes.as_slice() == named_truths_false_material.as_bytes()
    }));
    assert!(named_artifact.decisions.iter().any(|decision| {
        decision.kind == "search-schedule-named-truths"
            && named_artifact
                .payloads
                .iter()
                .any(|payload| payload.digest == decision.payload_digest)
    }));

    let retained_scenario = write_search_retained_evidence_scenario(&temp)?;
    let retained_evidence = write_search_retained_evidence(&temp)?;
    let retained_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("search"),
        retained_scenario.display().to_string(),
        String::from("--max-states"),
        String::from("1"),
        String::from("--retained-evidence"),
        retained_evidence.display().to_string(),
    ]);
    let Commands::Search(args) = &retained_cli.command else {
        panic!("expected search command");
    };
    let retained_plan = plan_search_invocation(args, temp.path())?;
    let retained_backend =
        plan_backend_selection(&retained_cli)?.expect("retained-evidence search should route");
    let retained_outcome = run_local_double_search_workflow(
        &plan_cli_invocation(&retained_cli),
        &retained_backend,
        None,
        &retained_plan,
    )?;
    assert_eq!(retained_outcome.status, BackendCommandStatus::Failed);
    assert_eq!(retained_outcome.exit_code, 1);
    let retained_line = retained_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("search-run\t"))
        .expect("retained-evidence search workflow must emit a search-run line");
    assert!(retained_line.contains("failure_oracle=scenario-assertions+retained-evidence"));
    assert!(retained_line.contains(&format!(
        "retained_evidence={}",
        retained_evidence.display()
    )));
    let retained_evidence_material = valid_search_retained_evidence_toml("root");
    let retained_evidence_digest = content_address_bytes(retained_evidence_material.as_bytes());
    assert!(retained_line.contains(&format!(
        "retained_evidence_digest={retained_evidence_digest}"
    )));
    assert!(retained_line.contains("failures=1"));
    assert!(retained_line.contains("status=failed"));
    let retained_artifact = decode_reproduction_artifact(
        retained_outcome
            .reproduction_artifact
            .as_deref()
            .expect("retained-evidence failure should emit a reproduction artifact"),
    )?;
    assert!(retained_artifact.components.iter().any(|component| {
        component.kind == "search_retained_evidence"
            && component.name == "retained-evidence.toml"
            && component.digest == retained_evidence_digest
            && component.media_type == SEARCH_RETAINED_EVIDENCE_MEDIA_TYPE
    }));
    assert!(retained_artifact.payloads.iter().any(|payload| {
        payload.digest == retained_evidence_digest
            && payload.bytes.as_slice() == retained_evidence_material.as_bytes()
    }));
    assert!(retained_artifact.decisions.iter().any(|decision| {
        decision.kind == "search-retained-evidence"
            && retained_artifact
                .payloads
                .iter()
                .any(|payload| payload.digest == decision.payload_digest)
    }));

    let terminal_quiescence_scenario = write_search_terminal_quiescence_scenario(&temp)?;
    let terminal_quiescence_evidence = write_search_terminal_quiescence_retained_evidence(&temp)?;
    let terminal_quiescence_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("search"),
        terminal_quiescence_scenario.display().to_string(),
        String::from("--max-states"),
        String::from("1"),
        String::from("--retained-evidence"),
        terminal_quiescence_evidence.display().to_string(),
    ]);
    let Commands::Search(args) = &terminal_quiescence_cli.command else {
        panic!("expected search command");
    };
    let terminal_quiescence_plan = plan_search_invocation(args, temp.path())?;
    let terminal_quiescence_backend = plan_backend_selection(&terminal_quiescence_cli)?
        .expect("terminal quiescence search should route");
    let terminal_quiescence_outcome = run_local_double_search_workflow(
        &plan_cli_invocation(&terminal_quiescence_cli),
        &terminal_quiescence_backend,
        None,
        &terminal_quiescence_plan,
    )?;
    assert_eq!(
        terminal_quiescence_outcome.status,
        BackendCommandStatus::Failed
    );
    assert_eq!(terminal_quiescence_outcome.exit_code, 1);
    let terminal_quiescence_line = terminal_quiescence_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("search-run\t"))
        .expect("terminal quiescence search workflow must emit a search-run line");
    assert!(
        terminal_quiescence_line.contains("failure_oracle=scenario-assertions+retained-evidence")
    );
    assert!(terminal_quiescence_line.contains(&format!(
        "retained_evidence={}",
        terminal_quiescence_evidence.display()
    )));
    let terminal_quiescence_material =
        valid_search_terminal_quiescence_retained_evidence_toml("root");
    let terminal_quiescence_digest = content_address_bytes(terminal_quiescence_material.as_bytes());
    assert!(terminal_quiescence_line.contains(&format!(
        "retained_evidence_digest={terminal_quiescence_digest}"
    )));
    assert!(terminal_quiescence_line.contains("failures=1"));
    assert!(terminal_quiescence_line.contains("status=failed"));
    let terminal_quiescence_artifact = decode_reproduction_artifact(
        terminal_quiescence_outcome
            .reproduction_artifact
            .as_deref()
            .expect("terminal quiescence failure should emit a reproduction artifact"),
    )?;
    assert!(
        terminal_quiescence_artifact
            .components
            .iter()
            .any(|component| {
                component.kind == "search_retained_evidence"
                    && component.name == "retained-evidence.toml"
                    && component.digest == terminal_quiescence_digest
                    && component.media_type == SEARCH_RETAINED_EVIDENCE_MEDIA_TYPE
            })
    );
    assert!(terminal_quiescence_artifact.payloads.iter().any(|payload| {
        payload.digest == terminal_quiescence_digest
            && payload.bytes.as_slice() == terminal_quiescence_material.as_bytes()
    }));
    assert!(
        terminal_quiescence_artifact
            .decisions
            .iter()
            .any(|decision| {
                decision.kind == "search-retained-evidence"
                    && terminal_quiescence_artifact
                        .payloads
                        .iter()
                        .any(|payload| payload.digest == decision.payload_digest)
            })
    );

    let terminal_sometimes_scenario = write_search_terminal_sometimes_scenario(&temp)?;
    let terminal_sometimes_evidence = write_search_terminal_sometimes_retained_evidence(&temp)?;
    let terminal_sometimes_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("search"),
        terminal_sometimes_scenario.display().to_string(),
        String::from("--max-states"),
        String::from("1"),
        String::from("--retained-evidence"),
        terminal_sometimes_evidence.display().to_string(),
    ]);
    let Commands::Search(args) = &terminal_sometimes_cli.command else {
        panic!("expected search command");
    };
    let terminal_sometimes_plan = plan_search_invocation(args, temp.path())?;
    let terminal_sometimes_backend = plan_backend_selection(&terminal_sometimes_cli)?
        .expect("terminal sometimes search should route");
    let terminal_sometimes_outcome = run_local_double_search_workflow(
        &plan_cli_invocation(&terminal_sometimes_cli),
        &terminal_sometimes_backend,
        None,
        &terminal_sometimes_plan,
    )?;
    assert_eq!(
        terminal_sometimes_outcome.status,
        BackendCommandStatus::Failed
    );
    assert_eq!(terminal_sometimes_outcome.exit_code, 1);
    let terminal_sometimes_line = terminal_sometimes_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("search-run\t"))
        .expect("terminal sometimes search workflow must emit a search-run line");
    assert!(
        terminal_sometimes_line.contains("failure_oracle=scenario-assertions+retained-evidence")
    );
    assert!(terminal_sometimes_line.contains(&format!(
        "retained_evidence={}",
        terminal_sometimes_evidence.display()
    )));
    let terminal_sometimes_material =
        valid_search_terminal_sometimes_retained_evidence_toml("root");
    let terminal_sometimes_digest = content_address_bytes(terminal_sometimes_material.as_bytes());
    assert!(terminal_sometimes_line.contains(&format!(
        "retained_evidence_digest={terminal_sometimes_digest}"
    )));
    assert!(terminal_sometimes_line.contains("failures=1"));
    assert!(terminal_sometimes_line.contains("status=failed"));
    let terminal_sometimes_artifact = decode_reproduction_artifact(
        terminal_sometimes_outcome
            .reproduction_artifact
            .as_deref()
            .expect("terminal sometimes failure should emit a reproduction artifact"),
    )?;
    assert!(
        terminal_sometimes_artifact
            .components
            .iter()
            .any(|component| {
                component.kind == "search_retained_evidence"
                    && component.name == "retained-evidence.toml"
                    && component.digest == terminal_sometimes_digest
                    && component.media_type == SEARCH_RETAINED_EVIDENCE_MEDIA_TYPE
            })
    );
    assert!(terminal_sometimes_artifact.payloads.iter().any(|payload| {
        payload.digest == terminal_sometimes_digest
            && payload.bytes.as_slice() == terminal_sometimes_material.as_bytes()
    }));

    let schedule_only_configuration =
        crucible::ContentHash::from_bytes(b"schedule-only-configuration");
    let schedule_only_fingerprint = crucible::ContentHash::from_bytes(b"schedule-only-fingerprint");
    let schedule_oracle = SearchFailureOracle::none()
        .with_failure(schedule_only_configuration, schedule_only_fingerprint);
    let retained_oracle = SearchFailureOracle::none();
    let merged_oracle = merge_search_failure_oracles(
        [schedule_only_configuration],
        &schedule_oracle,
        &retained_oracle,
    );
    assert_eq!(
        merged_oracle.failure_for(schedule_only_configuration),
        Some(schedule_only_fingerprint),
        "retained evidence must not suppress schedule-only failures"
    );

    let outcome = run_local_double_search_workflow(
        &plan_cli_invocation(&search_cli),
        &backend_plan,
        None,
        &search_plan,
    )?;
    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert_eq!(outcome.exit_code, 0);
    let search_line = outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("search-run\t"))
        .expect("search workflow must emit a search-run line");
    assert!(search_line.contains("strategy=dfs"));
    assert!(search_line.contains("max_states=1"));
    assert!(search_line.contains("failure_oracle=none"));
    assert!(search_line.contains("replay_oracle_sampling=1/1"));
    assert!(search_line.contains("replay_oracle_considered=0"));
    assert!(search_line.contains("replay_oracle_sampled=0"));
    assert!(search_line.contains("failures=0"));
    assert!(!search_line.contains("counterexample="));
    assert!(!search_line.contains("counterexample_artifact="));
    assert!(search_line.contains("budget_exhausted=false"));
    assert!(search_line.contains("status=passed"));
    assert!(outcome.canonical_log.iter().any(
        |entry| entry.kind == "search_strategy_run" && entry.summary.contains("status=passed")
    ));
    dispatch(&search_cli)?;

    let collect_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("search"),
        scenario.display().to_string(),
        String::from("--max-states"),
        String::from("1"),
        String::from("--on-violation"),
        String::from("collect"),
    ]);
    let Commands::Search(args) = &collect_cli.command else {
        panic!("expected search command");
    };
    let collect_plan = plan_search_invocation(args, temp.path())?;
    let collect_backend =
        plan_backend_selection(&collect_cli)?.expect("search should route to backend");
    let collect_outcome = run_local_double_search_workflow(
        &plan_cli_invocation(&collect_cli),
        &collect_backend,
        None,
        &collect_plan,
    )?;
    assert_eq!(collect_outcome.status, BackendCommandStatus::Passed);
    assert_eq!(collect_outcome.exit_code, 0);
    let collect_line = collect_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("search-run\t"))
        .expect("collect search workflow must emit a search-run line");
    assert!(collect_line.contains("budget_exhausted=false"));
    assert!(collect_line.contains("replay_oracle_sampling=1/1"));
    assert!(collect_line.contains("status=passed"));
    dispatch(&collect_cli)?;

    let depth_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("search"),
        scenario.display().to_string(),
        String::from("--max-depth"),
        String::from("1"),
        String::from("--on-violation"),
        String::from("collect"),
    ]);
    let Commands::Search(args) = &depth_cli.command else {
        panic!("expected search command");
    };
    let depth_plan = plan_search_invocation(args, temp.path())?;
    let depth_backend =
        plan_backend_selection(&depth_cli)?.expect("search should route to backend");
    let depth_outcome = run_local_double_search_workflow(
        &plan_cli_invocation(&depth_cli),
        &depth_backend,
        None,
        &depth_plan,
    )?;
    assert_eq!(depth_outcome.status, BackendCommandStatus::Passed);
    assert_eq!(depth_outcome.exit_code, 0);
    let depth_line = depth_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("search-run\t"))
        .expect("bounded search must emit a search-run line");
    assert!(depth_line.contains("max_depth=1"));
    assert!(depth_line.contains("expansions=1"));
    assert!(depth_outcome.canonical_log.iter().any(|entry| {
        entry.kind == "search_strategy_run" && entry.summary.contains("max_depth=1")
    }));
    dispatch(&depth_cli)?;

    let violation_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("search"),
        scenario.display().to_string(),
        String::from("--on-violation"),
        String::from("stop"),
        String::from("--max-states"),
        String::from("16"),
    ]);
    let Commands::Search(args) = &violation_cli.command else {
        panic!("expected search command");
    };
    let violation_plan = plan_search_invocation(args, temp.path())?;
    let violation_backend =
        plan_backend_selection(&violation_cli)?.expect("search should route to backend");
    let no_failure_outcome = run_local_double_search_workflow(
        &plan_cli_invocation(&violation_cli),
        &violation_backend,
        None,
        &violation_plan,
    )?;
    assert_eq!(no_failure_outcome.status, BackendCommandStatus::Passed);
    assert_eq!(no_failure_outcome.exit_code, 0);
    let search_line = no_failure_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("search-run\t"))
        .expect("explicit violation search must emit a search-run line");
    assert!(search_line.contains("failure_oracle=none"));
    assert!(search_line.contains("on_violation=stop"));
    assert!(search_line.contains("failures=0"));
    dispatch(&violation_cli)?;

    Ok(())
}

#[test]
pub(super) fn cli_search_fuzz_workflow_executes_local_double_fuzz() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let family_path = write_valid_fuzz_family(&temp)?;
    let corpus = temp.path().join("fuzz-corpus");
    let fuzz_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("9"),
        String::from("fuzz"),
        family_path.display().to_string(),
        String::from("--runs"),
        String::from("2"),
        String::from("--corpus"),
        corpus.display().to_string(),
    ]);
    let Commands::Fuzz(args) = &fuzz_cli.command else {
        panic!("expected fuzz command");
    };
    let seed_plan = plan_determinism_ergonomics(
        &fuzz_cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("fuzz should resolve a seed");
    let fuzz_plan = plan_fuzz_invocation(args, &seed_plan, temp.path())?;
    let backend_plan = plan_backend_selection(&fuzz_cli)?.expect("fuzz should route to backend");
    let outcome = run_local_double_fuzz_workflow(
        &plan_cli_invocation(&fuzz_cli),
        &backend_plan,
        Some(&seed_plan),
        &fuzz_plan,
    )?;
    assert_eq!(outcome.status, BackendCommandStatus::Passed);
    assert_eq!(outcome.exit_code, 0);
    let fuzz_line = outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("fuzz-run\t"))
        .expect("fuzz workflow must emit a fuzz-run line");
    assert!(fuzz_line.contains("runs=2"));
    assert!(fuzz_line.contains("coverage=basic-block"));
    assert!(fuzz_line.contains("iterations=2"));
    assert!(fuzz_line.contains("admissions=2"));
    assert!(fuzz_line.contains("retained_entries=1"));
    assert!(fuzz_line.contains("replay_oracle_validations=3"));
    assert!(fuzz_line.contains("generated_mutants=2"));
    assert!(fuzz_line.contains("store_puts=2"));
    assert!(fuzz_line.contains("status=passed"));
    assert!(outcome.canonical_log.iter().any(|entry| {
        entry.kind == "coverage_guided_fuzz_run"
            && entry.summary.contains("replay_oracle_validations=3")
    }));
    assert!(corpus.is_dir());
    dispatch(&fuzz_cli)?;

    let no_corpus_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--seed"),
        String::from("9"),
        String::from("fuzz"),
        family_path.display().to_string(),
        String::from("--runs"),
        String::from("2"),
    ]);
    let Commands::Fuzz(args) = &no_corpus_cli.command else {
        panic!("expected fuzz command");
    };
    let no_corpus_seed_plan = plan_determinism_ergonomics(
        &no_corpus_cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("no-corpus fuzz should resolve a seed");
    let no_corpus_plan = plan_fuzz_invocation(args, &no_corpus_seed_plan, temp.path())?;
    let no_corpus_backend =
        plan_backend_selection(&no_corpus_cli)?.expect("no-corpus fuzz should route");
    assert_eq!(
        fuzz_dispatch_route(&no_corpus_backend, &no_corpus_plan),
        Some(FuzzDispatchRoute::LocalDouble)
    );
    let no_corpus_outcome = run_local_double_fuzz_workflow(
        &plan_cli_invocation(&no_corpus_cli),
        &no_corpus_backend,
        Some(&no_corpus_seed_plan),
        &no_corpus_plan,
    )?;
    assert_eq!(no_corpus_outcome.status, BackendCommandStatus::Passed);
    let no_corpus_line = no_corpus_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("fuzz-run\t"))
        .expect("no-corpus fuzz workflow must emit a fuzz-run line");
    assert!(no_corpus_line.contains("corpus=none"));
    assert!(no_corpus_line.contains("iterations=2"));
    assert!(no_corpus_line.contains("coverage_order=2"));
    assert!(no_corpus_line.contains("admissions=0"));
    assert!(no_corpus_line.contains("retained_entries=0"));
    assert!(no_corpus_line.contains("replay_oracle_validations=0"));
    assert!(no_corpus_line.contains("generated_mutants=2"));
    assert!(no_corpus_line.contains("store_puts=0"));
    assert!(no_corpus_line.contains("status=passed"));
    dispatch(&no_corpus_cli)?;

    let store_root = temp.path().join("stored-family-store");
    let store = crucible::LocalDagStore::new(store_root.clone());
    let stored_family = store.put(valid_fuzz_family_toml().as_bytes())?;
    let reference = format_content_hash_ref(stored_family);
    let stored_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        store_root.display().to_string(),
        String::from("--seed"),
        String::from("9"),
        String::from("fuzz"),
        String::from("--family"),
        reference.clone(),
        String::from("--runs"),
        String::from("2"),
    ]);
    let Commands::Fuzz(args) = &stored_cli.command else {
        panic!("expected fuzz command");
    };
    let stored_seed_plan = plan_determinism_ergonomics(
        &stored_cli,
        &FakeSeedEnvironment::default(),
        &mut FakeSeedEntropySource::new(0),
    )?
    .expect("stored-family fuzz should resolve a seed");
    let stored_plan = plan_fuzz_invocation(args, &stored_seed_plan, &store_root)?;
    assert_eq!(stored_plan.family, FuzzFamilyRef::Stored(stored_family));
    assert_eq!(stored_plan.store_root, store_root);
    let stored_backend =
        plan_backend_selection(&stored_cli)?.expect("stored-family fuzz should route");
    let stored_outcome = run_local_double_fuzz_workflow(
        &plan_cli_invocation(&stored_cli),
        &stored_backend,
        Some(&stored_seed_plan),
        &stored_plan,
    )?;
    assert_eq!(stored_outcome.status, BackendCommandStatus::Passed);
    let stored_line = stored_outcome
        .stdout
        .iter()
        .find(|line| line.starts_with("fuzz-run\t"))
        .expect("stored-family fuzz workflow must emit a fuzz-run line");
    assert!(stored_line.contains(&format!("family={reference}")));
    assert!(stored_line.contains("iterations=2"));
    assert!(stored_line.contains("status=passed"));
    dispatch(&stored_cli)?;

    let missing_reference =
        format_content_hash_ref(crucible::ContentHash::from_bytes(b"missing-family-ref"));
    let missing_stored_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        store_root.display().to_string(),
        String::from("fuzz"),
        String::from("--family"),
        missing_reference,
    ]);
    let error = match dispatch(&missing_stored_cli) {
        Ok(_) => panic!("missing stored family hashes must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("could not be loaded from store"));

    let corrupt_family = store.put(
        valid_fuzz_family_toml()
            .replace("crucible.scenario-family.v2", "wrong.schema")
            .as_bytes(),
    )?;
    let corrupt_reference = format_content_hash_ref(corrupt_family);
    let corrupt_stored_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        store_root.display().to_string(),
        String::from("fuzz"),
        String::from("--family"),
        corrupt_reference,
    ]);
    let error = match dispatch(&corrupt_stored_cli) {
        Ok(_) => panic!("corrupt stored family TOML must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(error.to_string().contains("unsupported schema"));

    let invalid_utf8_family = store.put(&[0xff, 0xfe])?;
    let invalid_utf8_reference = format_content_hash_ref(invalid_utf8_family);
    let invalid_utf8_stored_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        store_root.display().to_string(),
        String::from("fuzz"),
        String::from("--family"),
        invalid_utf8_reference,
    ]);
    let error = match dispatch(&invalid_utf8_stored_cli) {
        Ok(_) => panic!("non-UTF-8 stored family bytes must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(
        error
            .to_string()
            .contains("is not UTF-8 scenario-family TOML")
    );

    let malformed_family = store.put(b"schema = [")?;
    let malformed_reference = format_content_hash_ref(malformed_family);
    let malformed_stored_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--quiet"),
        String::from("--backend"),
        String::from("double"),
        String::from("--store"),
        store_root.display().to_string(),
        String::from("fuzz"),
        String::from("--family"),
        malformed_reference,
    ]);
    let error = match dispatch(&malformed_stored_cli) {
        Ok(_) => panic!("malformed stored family TOML must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(
        error
            .to_string()
            .contains("is not valid scenario-family TOML")
    );

    Ok(())
}

#[test]
pub(super) fn cli_run_workflow_plans_start_continue_stream_and_budgets()
-> Result<(), Box<dyn Error>> {
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
pub(super) fn cli_run_workflow_supports_virtual_time_budget() -> Result<(), Box<dyn Error>> {
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
pub(super) fn cli_run_workflow_interactive_pauses_at_genesis_and_accepts_session_commands()
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
pub(super) fn cli_run_workflow_rejects_bad_scenarios_and_invalid_budgets()
-> Result<(), Box<dyn Error>> {
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

    let invalid_with_qemu = Cli::parse_from([
        "crucible",
        "selftest",
        "--with-qemu",
        "--gates",
        "gate:not-real",
    ]);
    let Commands::Selftest(args) = &invalid_with_qemu.command else {
        panic!("expected selftest command");
    };
    let error = match run_selftest(&invalid_with_qemu, args) {
        Ok(_) => panic!("invalid selftest gate must be rejected before qemu discovery"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Usage(_)));
    assert_eq!(error.exit_code(), 64);

    let with_qemu = Cli::parse_from(["crucible", "selftest", "--with-qemu"]);
    let Commands::Selftest(args) = &with_qemu.command else {
        panic!("expected selftest command");
    };
    let error = match run_selftest(&with_qemu, args) {
        Ok(_) => panic!("selftest --with-qemu without artifacts must fail discovery"),
        Err(error) => error,
    };
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    assert!(
        error
            .to_string()
            .contains("could not discover both patched QEMU and plugin")
    );

    Ok(())
}

#[test]
pub(super) fn cli_run_workflow_uses_uniform_outcome_exit_code_mapping() -> Result<(), Box<dyn Error>>
{
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

    Ok(())
}

#[test]
pub(super) fn cli_run_workflow_executes_remote_daemon_session_against_production_server()
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
pub(super) fn cli_run_workflow_parses_interactive_session_commands() -> Result<(), Box<dyn Error>> {
    let commands =
        parse_interactive_session_commands("\n# comment\nquery\nstep\ninject\nsave\nfork\nstop\n")?;

    assert_eq!(
        commands,
        vec![
            SessionCommandKind::Query,
            SessionCommandKind::StepQuantum,
            SessionCommandKind::Inject,
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
pub(super) async fn cli_run_workflow_acknowledges_interactive_reader_commands()
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
    let request = CreateSessionRequest::inline_form(
        run_plan.scenario.scenario_form().clone(),
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
pub(super) fn cli_backend_selection_covers_every_backend_routed_subcommand()
-> Result<(), Box<dyn Error>> {
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
        assert!(auto_plan.has_consistent_route());

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
        assert!(double_plan.has_consistent_route());

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
        assert!(qemu_plan.has_consistent_route());

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
        assert!(daemon_plan.has_consistent_route());
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
pub(super) fn cli_verify_workflow_plans_runs_adversarial_matrix_and_bisection()
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
pub(super) fn cli_verify_builtin_example_corpus_adversarial() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    for scenario_name in [
        crucible::HAPPY_PATH_SCENARIO_NAME,
        crucible::PARTITION_RECOVERY_SCENARIO_NAME,
        crucible::CRASH_RESTART_SCENARIO_NAME,
        crucible::FAULT_CAMPAIGN_FAMILY_NAME,
    ] {
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("--seed"),
            String::from("31"),
            String::from("verify"),
            scenario_name.to_owned(),
            String::from("--runs"),
            String::from("2"),
            String::from("--adversarial"),
            String::from("--bisect"),
        ]);
        let Commands::Verify(args) = &cli.command else {
            panic!("expected verify command");
        };

        let verify_plan = plan_verify_invocation(args, temp.path())?;
        assert!(matches!(
            &verify_plan.mode,
            VerifyMode::RunScenario {
                scenario: RunScenarioRef::BuiltInExample { .. }
            }
        ));
        assert_eq!(
            verify_plan.reductions.len(),
            2 * VERIFY_HOSTILE_PROFILES.len()
        );
        assert!(verify_plan.applies_hostile_condition_matrix);
        assert!(verify_plan.print_bisection_state_dump);

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
            None,
            &mut NullBackendCommandRunner,
        )?;

        assert_eq!(outcome.status, BackendCommandStatus::Passed);
        assert_eq!(
            outcome
                .stdout
                .iter()
                .filter(|line| line.starts_with("verify-run\t"))
                .count(),
            2 * VERIFY_HOSTILE_PROFILES.len()
        );
        for profile in VERIFY_HOSTILE_PROFILES {
            assert!(
                outcome
                    .stdout
                    .iter()
                    .any(|line| line.contains(&format!("\tprofile={}", profile.label()))),
                "missing verify output for hostile profile {}",
                profile.label()
            );
        }
        assert!(
            outcome
                .stdout
                .iter()
                .any(|line| line.contains("verify-result\tstatus=passed"))
        );
    }

    Ok(())
}

#[test]
pub(super) fn cli_verify_workflow_rejects_single_fresh_reduction() -> Result<(), Box<dyn Error>> {
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
pub(super) fn cli_verify_sim_backend_loop_fingerprints_backend_state_after_quantum()
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

    let mut driver = crucible_session::SessionDriver::new(loop_impl);
    driver.drive_quantum/* session-boundary call */(crucible::QuantumRequest {
        configuration,
        control: Vec::new(),
    })?;
    let mut loop_impl = driver.into_inner();
    let after = crucible::QuantumLoop::sample_fingerprint(&mut loop_impl, node)?;

    assert_eq!(before.at.ticks, 0);
    assert_eq!(after.at.ticks, 1);
    assert_ne!(before.fingerprint, after.fingerprint);

    Ok(())
}

#[test]
pub(super) fn cli_verify_workflow_collects_post_step_backend_fingerprint()
-> Result<(), Box<dyn Error>> {
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
pub(super) fn cli_verify_workflow_runs_fresh_local_double_reductions() -> Result<(), Box<dyn Error>>
{
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
        None,
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
            .all(|line| line.contains("\tcanonical_log=")
                && line.contains("\tfingerprint=")
                && line.contains("\tsamples=2"))
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
#[path = "replay_artifact/run_budget.rs"]
mod run_budget;
