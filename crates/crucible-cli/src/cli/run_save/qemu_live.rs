//! Live local backend execution through the packaged patched emulator and plugin.

use super::*;

/// Maximum scheduler quanta for one live exploration realization.
///
/// Exact local events and conservative link horizons may split a realization;
/// the bound leaves room for both VM nodes and terminal scheduler settling.
const LIVE_EXPLORATION_QUANTUM_LIMIT: u64 = 16;

/// Terminal instruction-count ceiling for one live exploration realization.
///
/// The certified stock-kernel network workload emits near 3.3 billion
/// instructions and resolves its link delivery below this three-window bound.
const LIVE_EXPLORATION_RUN_CEILING_ICOUNT: u64 = 12_000_000_000;

/// Terminal instruction-count ceiling for a production CLI lifecycle session.
const PRODUCTION_CLI_RUN_CEILING_ICOUNT: u64 = 40_000_000_000;

/// Scheduler-quantum ceiling for a production CLI lifecycle session.
const PRODUCTION_CLI_QUANTUM_BUDGET: u64 = 10_000;

/// Per-node wall-clock timeout for a production CLI lifecycle step.
const PRODUCTION_CLI_COMPLETION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub(crate) struct SelftestGateReport {
    pub(crate) name: String,
    pub(crate) status: SelftestGateStatus,
    pub(crate) corpus_entries: usize,
    pub(crate) runs_per_entry: usize,
    pub(crate) runner: SelftestGateRunner,
    pub(crate) qemu_build_id: Option<String>,
    pub(crate) live_qemu_icount: Option<u64>,
    pub(crate) live_qemu_fingerprint: Option<String>,
}

#[path = "qemu_live/probe.rs"]
mod probe;

pub(crate) use probe::*;

pub(crate) fn is_packaged_backend(backend_plan: &BackendSelectionPlan) -> bool {
    matches!(
        backend_plan.resolved_backend,
        Some(ResolvedLocalBackend::Qemu { .. })
    )
}

pub(crate) fn run_selftest(cli: &Cli, args: &SelftestArgs) -> Result<SelftestReport, CliError> {
    run_selftest_with_probe(cli, args, &mut ProductionLiveQemuProbeRunner)
}

pub(crate) fn run_selftest_with_probe(
    cli: &Cli,
    args: &SelftestArgs,
    probe: &mut impl LiveQemuProbeRunner,
) -> Result<SelftestReport, CliError> {
    let selected_gates = plan_selftest_gates(args)?;
    let qemu_backend = if selected_gates
        .iter()
        .any(|gate| selftest_gate_uses_real_backend(gate))
    {
        Some(require_selftest_qemu_backend(cli)?)
    } else {
        None
    };
    #[cfg(any(test, feature = "test-double"))]
    let verified = verify_selftest_corpus(args)?;
    #[cfg(not(any(test, feature = "test-double")))]
    let verified = Vec::new();
    let mut gates = Vec::with_capacity(selected_gates.len());
    let mut live_baseline = None;
    for gate in selected_gates {
        let runner = if selftest_gate_uses_real_backend(&gate) {
            SelftestGateRunner::RealQemu
        } else {
            #[cfg(any(test, feature = "test-double"))]
            {
                SelftestGateRunner::DoubleBackedCorpus
            }
            #[cfg(not(any(test, feature = "test-double")))]
            {
                return Err(backend_error(format!(
                    "selftest gate `{gate}` requires the `test-double` Cargo feature"
                )));
            }
        };
        let live = if runner == SelftestGateRunner::RealQemu {
            let backend = qemu_backend
                .as_ref()
                .ok_or_else(|| backend_error("real-QEMU selftest requires a resolved backend"))?;
            let evidence = probe.run_probe(backend)?;
            validate_live_qemu_probe_evidence(backend, &evidence)?;
            if live_baseline
                .as_ref()
                .is_some_and(|baseline| baseline != &evidence)
            {
                return Err(backend_error(
                    "live QEMU selftest probes diverged across identical executions",
                ));
            }
            live_baseline.get_or_insert_with(|| evidence.clone());
            Some(evidence)
        } else {
            None
        };
        gates.push(SelftestGateReport {
            name: gate,
            status: SelftestGateStatus::Passed,
            corpus_entries: verified.len(),
            runs_per_entry: DEFAULT_SELFTEST_RUNS,
            runner,
            qemu_build_id: live.as_ref().map(|evidence| evidence.qemu_build_id.clone()),
            live_qemu_icount: live.as_ref().map(|report| report.completed_icount),
            live_qemu_fingerprint: live
                .as_ref()
                .map(|report| report.execution_fingerprint.clone()),
        });
    }
    Ok(SelftestReport { gates, verified })
}

fn validate_live_qemu_probe_evidence(
    backend: &ResolvedLocalBackend,
    evidence: &LiveQemuProbeEvidence,
) -> Result<(), CliError> {
    let observed = BackendExecutionEvidence::LocalProduction {
        build_id: evidence.qemu_build_id.clone(),
        plugin_abi: evidence.plugin_abi.clone(),
    };
    let plan = BackendSelectionPlan {
        subcommand: CliSubcommand::Selftest,
        target: BackendExecutionTarget::Local,
        requested_backend: Backend::Qemu,
        resolved_backend: Some(backend.clone()),
        reason: BackendSelectionReason::ExplicitQemu,
        daemon: None,
        remote_uses_control_api: false,
        local_uses_simulation_backend: true,
        local_remote_equivalence_contract: true,
    };
    let expected = plan
        .expected_execution_evidence()
        .ok_or_else(|| backend_error("live QEMU probe has no selected execution identity"))?;
    if expected != observed || !observed.proves_t_cli_3(&plan) {
        return Err(backend_error(
            "live QEMU probe identity does not match the discovered backend",
        ));
    }
    Ok(())
}

#[cfg(not(test))]
pub(crate) fn require_selftest_qemu_backend(cli: &Cli) -> Result<ResolvedLocalBackend, CliError> {
    require_qemu_artifacts(
        cli,
        &ProcessQemuDiscoveryEnvironment,
        &CompileTimeAosQemuPackageSet,
    )
}

#[cfg(test)]
pub(crate) fn require_selftest_qemu_backend(cli: &Cli) -> Result<ResolvedLocalBackend, CliError> {
    require_qemu_artifacts(cli, &ProcessQemuDiscoveryEnvironment, &NoAosQemuPackageSet)
}

pub(crate) fn run_local_qemu_fuzz_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &FuzzDriverPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU fuzz requires a resolved backend"))?;
    let family = load_fuzz_family(plan)?;
    let config = production_qemu_lifecycle_config(backend)?
        .with_coverage(production_api::ProductionPluginSwitch::On);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let warmup = family
        .fuzz_coverage_guided(plan.config, &[])
        .map_err(|error| backend_error(format!("QEMU fuzz warm-up policy failed: {error}")))?;
    let feedback = execute_qemu_fuzz_iterations(&config, &runtime, &warmup, "warm-up")?;
    let (run, report) = if let Some(corpus) = &plan.corpus {
        fs::create_dir_all(corpus).map_err(|error| {
            backend_error(format!(
                "QEMU fuzz could not create corpus `{}`: {error}",
                corpus.display()
            ))
        })?;
        let store = crucible::LocalDagStore::new(corpus.clone());
        let corpus_run = family
            .fuzz_coverage_guided_corpus(
                &store,
                plan.config,
                crucible::CoverageGuidedCorpusConfig::new(plan.config.meta_seed),
                &feedback,
            )
            .map_err(|error| backend_error(format!("QEMU fuzz corpus policy failed: {error}")))?;
        (
            corpus_run.fuzz.clone(),
            local_double_fuzz_report_from_corpus_run(plan, corpus, &corpus_run),
        )
    } else {
        let run = family
            .fuzz_coverage_guided(plan.config, &feedback)
            .map_err(|error| backend_error(format!("QEMU fuzz policy failed: {error}")))?;
        let report = local_double_fuzz_report_from_run(plan, &run);
        (run, report)
    };
    let guided_feedback = execute_qemu_fuzz_iterations(&config, &runtime, &run, "guided")?;
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    apply_local_double_fuzz_report(&mut outcome, plan, &report);
    for (index, feedback) in guided_feedback.iter().enumerate() {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("qemu"),
            kind: String::from("fuzz_coverage_feedback"),
            summary: format!(
                "iteration={index}\tblocks={}\tfingerprint={}",
                feedback.projection().len(),
                feedback.fingerprint().to_hex()
            ),
        });
    }
    append_qemu_control_plane_execution_proof(&mut outcome, backend, "fuzz-live-campaign");
    Ok(outcome)
}

fn execute_qemu_fuzz_iterations(
    config: &production_api::ProductionVmLifecycleConfig,
    runtime: &tokio::runtime::Runtime,
    run: &crucible::CoverageGuidedFuzzRun,
    phase: &str,
) -> Result<Vec<crucible::EventLogCoverageFeedback>, CliError> {
    let mut feedback = Vec::with_capacity(run.iterations.len());
    for iteration in &run.iterations {
        let form = iteration.scenario.form().clone();
        let run_plan = qemu_fuzz_iteration_plan(iteration.sequence, form);
        // crucible-lint: allow host-nondeterminism-state -- genesis is reconstructed from canonical scenario material, not host observations.
        let branch_base = crucible::Configuration::genesis(iteration.scenario.scenario_def());
        let iteration_config = config.clone().with_branch_prefix_overrides(
            branch_base,
            VirtualTime { ticks: 0 },
            iteration.schedule().decisions().to_vec(),
        );
        let control_plane =
            production_qemu_control_plane(iteration_config, run_plan.scenario.scenario_form());
        let client = InProcessLifecycleClient::new(control_plane);
        let report =
            runtime.block_on(run_control_client_workflow_async(&client, &run_plan, &[]))?;
        if report.status == BackendCommandStatus::Crashed {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {} crashed before producing campaign evidence",
                iteration.sequence,
            )));
        }
        if report.coverage_feedback.projection().is_empty() {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {} produced no basic-block coverage",
                iteration.sequence,
            )));
        }
        let recorded_overrides = report
            .streamed_event_frames
            .iter()
            .filter(|frame| String::from_utf8_lossy(frame).contains("kind=crucible.event.override"))
            .count();
        let expected_overrides = iteration
            .schedule()
            .decisions()
            .iter()
            // crucible-lint: allow host-nondeterminism-state -- counting recorded canonical choices does not alter their values or order.
            .filter(|decision| matches!(decision, crucible::Decision::Override(_)))
            .count();
        if recorded_overrides != expected_overrides {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {} recorded {recorded_overrides} override events, expected {expected_overrides}",
                iteration.sequence,
            )));
        }
        feedback.push(report.coverage_feedback);
    }
    Ok(feedback)
}

fn qemu_fuzz_iteration_plan(sequence: u64, form: crucible::ScenarioDefForm) -> RunInvocationPlan {
    let scenario = form.scenario_def();
    RunInvocationPlan {
        request_seed: Some(scenario.seed()),
        scenario: RunScenarioRef::BuiltInExample {
            name: format!("fuzz-iteration-{sequence}"),
            form,
            scenario,
        },
        terminal_condition: RunTerminalCondition::Quiescence,
        max_virtual_time: None,
        max_virtual_time_ticks: None,
        max_quanta: None,
        execution_mode: RunExecutionMode::ToCompletion,
        save_policy: RunSavePolicy::Never,
        watch_streams_live_status: false,
        startup_commands: vec![SessionCommandKind::Start, SessionCommandKind::Continue],
        initial_control_commands: vec![SessionCommandKind::Query],
        accepted_interactive_commands: Vec::new(),
        observer_profile: VERIFY_BASELINE_PROFILE,
        collect_execution_fingerprints: false,
        bounded_ack_quanta: RUN_INTERACTIVE_ACK_QUANTA_BOUND,
        outcome_exit_codes: vec![
            (BackendCommandStatus::Passed, 0),
            (BackendCommandStatus::Failed, 1),
            (BackendCommandStatus::Timeout, 2),
            (BackendCommandStatus::Crashed, 3),
        ],
        invalid_scenario_exit_code: 4,
    }
}

#[path = "qemu_live/search.rs"]
mod search;

pub(crate) use search::*;
/// Runs one local scenario through the packaged QEMU backend.
pub(crate) fn run_local_qemu_workflow(
    backend: &ResolvedLocalBackend,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let config = production_qemu_lifecycle_config(backend)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = production_qemu_control_plane(config, run_plan.scenario.scenario_form());
    let client = InProcessLifecycleClient::new(control_plane);
    let report = if matches!(run_plan.execution_mode, RunExecutionMode::Interactive) {
        runtime.block_on(run_control_client_workflow_stdin_async(&client, run_plan))?
    } else {
        runtime.block_on(run_control_client_workflow_async(&client, run_plan, &[]))?
    };
    finish_run_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, run_plan, report)
}

/// Verifies every reduction through an independent packaged-QEMU session.
pub(crate) fn run_local_qemu_verify_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU verify requires a resolved backend"))?;
    let scenario = verify_plan.scenario().ok_or_else(|| {
        backend_error("QEMU verify compare mode must use the artifact comparison path")
    })?;
    let config = production_qemu_lifecycle_config(backend)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = production_qemu_control_plane(config, scenario.scenario_form());
    let client = InProcessLifecycleClient::new(control_plane);
    let report = runtime.block_on(run_control_client_verify_workflow_async(
        &client,
        verify_plan,
        Some(backend),
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

pub(crate) fn production_qemu_control_plane(
    config: production_api::ProductionVmLifecycleConfig,
    source: &crucible::ScenarioDefForm,
) -> LifecycleControlPlane<
    production_api::ProductionVmLifecycleLoop,
    production_api::LifecycleLoopFactory<production_api::ProductionVmLifecycleLoop>,
> {
    let white_box_policies = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| (node.id.clone(), node.white_box))
        .collect::<BTreeMap<_, _>>();
    LifecycleControlPlane::new_with_fallible_source_factory(
        "crucible-cli-qemu",
        Vec::new(),
        move |scenario, source, _seed| {
            let source = source.ok_or_else(|| production_api::LifecycleApiError::LoopFactory {
                message: String::from(
                    "production QEMU lifecycle requires an inline scenario definition",
                ),
            })?;
            production_api::build_production_vm_lifecycle_loop(scenario, source, &config)
        },
    )
    .with_thin_replay_resume()
    .with_white_box_policy_provider(move |_scenario| white_box_policies.clone())
}

pub(crate) fn production_qemu_lifecycle_config(
    backend: &ResolvedLocalBackend,
) -> Result<production_api::ProductionVmLifecycleConfig, CliError> {
    let (qemu, plugin) = match backend {
        ResolvedLocalBackend::Qemu { qemu, plugin, .. } => (qemu, plugin),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error(
                "production QEMU lifecycle requires the QEMU backend",
            ));
        }
    };
    let kernel = required_live_qemu_asset(
        "CRUCIBLE_KERNEL",
        option_env!("CRUCIBLE_AOS_KERNEL"),
        "kernel",
    )?;
    let root_image = required_live_qemu_asset(
        "CRUCIBLE_ROOT_IMAGE",
        option_env!("CRUCIBLE_AOS_ROOT_IMAGE"),
        "root image",
    )?;
    let mut config =
        production_api::ProductionVmLifecycleConfig::new(qemu, plugin, kernel, root_image)
            .with_root_image_format(production_api::ProductionRootImageFormat::Raw)
            .with_run_ceiling_icount(PRODUCTION_CLI_RUN_CEILING_ICOUNT)
            .with_quantum_budget(PRODUCTION_CLI_QUANTUM_BUDGET)
            .with_completion_timeout(PRODUCTION_CLI_COMPLETION_TIMEOUT);
    if let Some(kernel_cmdline) = live_qemu_kernel_cmdline() {
        config = config.with_kernel_cmdline_prefix(kernel_cmdline);
    }
    if let Some(initrd) = optional_live_qemu_asset(
        "CRUCIBLE_INITRD",
        option_env!("CRUCIBLE_AOS_INITRD"),
        "initrd",
    )? {
        config = config.with_initrd(initrd);
    }
    Ok(config)
}

pub(crate) fn append_qemu_control_plane_execution_proof(
    outcome: &mut BackendCommandOutcome,
    backend: &ResolvedLocalBackend,
    operation: &'static str,
) {
    let (qemu_build_id, plugin_abi) = match backend {
        ResolvedLocalBackend::Qemu {
            qemu_build_id,
            plugin_abi,
            ..
        } => (qemu_build_id, plugin_abi),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => return,
    };
    outcome.stdout.push(format!(
        "qemu-live\toperation={operation}\tqemu_build_id={qemu_build_id}\tplugin_abi={plugin_abi}"
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("qemu"),
        kind: String::from("live_backend_execution"),
        summary: format!(
            "operation={operation} qemu_build_id={qemu_build_id} plugin_abi={plugin_abi}"
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
}
