//! Live local backend execution through the packaged patched emulator and plugin.

use super::*;

use std::sync::Arc;

#[path = "finding_frames.rs"]
mod finding_frames;
use finding_frames::property_violation_from_frames;

/// Maximum scheduler quanta for one live exploration realization.
///
/// Exact local events and conservative link horizons may split a realization;
/// the bound leaves room for both VM nodes and terminal scheduler settling.
pub(crate) const LIVE_EXPLORATION_QUANTUM_LIMIT: u64 = 16;

/// Maximum scheduler quanta for one live fuzz realization.
///
/// Reaching this exact bound after producing coverage is normal campaign
/// completion. An earlier timeout remains a finding, while a realization with
/// no coverage fails closed before it can influence the corpus.
pub(crate) const LIVE_FUZZ_QUANTUM_LIMIT: u64 = 1_024;

/// Terminal timeline-tick ceiling for one live fuzz realization.
///
/// Production node construction authenticates the guest at the one-million
/// instruction boot boundary. One additional million logical ticks exposes the
/// retained setup coverage while keeping each campaign iteration far below the
/// general 40-billion-tick run ceiling.
pub(crate) const LIVE_FUZZ_RUN_CEILING_TICKS: u64 = 2_000_000;

/// Terminal timeline-tick ceiling for one live exploration realization.
///
/// The certified stock-kernel network workload emits near 3.3 billion
/// logical ticks and resolves its link delivery below this three-window bound.
pub(crate) const LIVE_EXPLORATION_RUN_CEILING_TICKS: u64 = 12_000_000_000;

/// Terminal timeline-tick ceiling for a production CLI lifecycle session.
pub(crate) const PRODUCTION_CLI_RUN_CEILING_TICKS: u64 = 40_000_000_000;

/// Scheduler-quantum ceiling for a production CLI lifecycle session.
pub(crate) const PRODUCTION_CLI_QUANTUM_BUDGET: u64 = 10_000;

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

#[cfg(not(any(test, feature = "test-double")))]
pub(crate) fn run_selftest(cli: &Cli, args: &SelftestArgs) -> Result<SelftestReport, CliError> {
    #[cfg(target_os = "linux")]
    let mut probe = ProductionLiveQemuProbeRunner::new(cli.campaign_deployment.clone());
    #[cfg(not(target_os = "linux"))]
    let mut probe = ProductionLiveQemuProbeRunner;

    run_selftest_with_probe(cli, args, &mut probe)
}

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn run_selftest(cli: &Cli, args: &SelftestArgs) -> Result<SelftestReport, CliError> {
    run_selftest_with_probe(cli, args, &mut TestDoubleSelftestProbeRunner)
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
        daemon_security: None,
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

#[path = "qemu_live/fuzz.rs"]
mod fuzz;

pub(crate) use fuzz::run_local_qemu_fuzz_workflow;

fn attach_qemu_findings_outputs(
    outcome: &mut BackendCommandOutcome,
    store_root: &Path,
    artifact_dir: &Path,
    findings_out: Option<&Path>,
    findings: Vec<crate::cli_report::TriageFindingEvidence>,
    reproduction_artifacts: Vec<Vec<u8>>,
) -> Result<(), CliError> {
    if findings.is_empty() && findings_out.is_none() {
        return Ok(());
    }
    let (path, digest, ledger_bytes) = crate::cli_triage_debug::write_reproduction_findings_ledger(
        artifact_dir,
        findings_out,
        &findings,
    )?;
    let store = crucible::LocalDagStore::new(store_root.to_path_buf());
    let stored = store.put(&ledger_bytes).map_err(CliError::Store)?;
    if stored != digest {
        return Err(artifact_error(
            "stored findings ledger did not match its content identity",
        ));
    }
    outcome.stdout.push(format!(
        "findings-ledger\tpath={}\tdigest={}\tfindings={}",
        path.display(),
        format_content_hash_ref(digest),
        findings.len()
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("crucible"),
        kind: String::from("signed_findings_ledger"),
        summary: format!(
            "digest={} findings={}",
            format_content_hash_ref(digest),
            findings.len()
        ),
    });
    match reproduction_artifacts.as_slice() {
        [artifact] => outcome.reproduction_artifact = Some(artifact.clone()),
        artifacts => {
            outcome.side_reproduction_artifacts = artifacts
                .iter()
                .enumerate()
                .map(|(index, artifact)| (format!("finding-{index}"), artifact.clone()))
                .collect();
        }
    }
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    Ok(())
}

#[path = "qemu_live/search.rs"]
mod search;

pub(crate) use search::*;

#[path = "qemu_live/replay.rs"]
mod replay;
pub(crate) use replay::*;

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
        .ok_or_else(|| backend_error("local QEMU verify requires a resolved production backend"))?;
    if !matches!(backend, ResolvedLocalBackend::Qemu { .. }) {
        return Err(backend_error(
            "local QEMU verify requires the packaged QEMU backend",
        ));
    }
    let scenario = verify_plan.scenario().ok_or_else(|| {
        backend_error("artifact comparison must not enter local QEMU verification")
    })?;
    let request_seed = ergonomics_plan
        .map(|plan| crucible::Seed::from_u64(plan.seed.value))
        .unwrap_or_else(|| scenario.scenario_def().seed());
    let seeded_scenario = reseed_run_scenario_ref(scenario, request_seed)?;
    let mut witnesses = Vec::with_capacity(verify_plan.reductions.len());
    for reduction in &verify_plan.reductions {
        let mut run_plan =
            verify_run_invocation_plan(seeded_scenario.clone(), request_seed, reduction.clone());
        run_plan.startup_commands = vec![SessionCommandKind::Start, SessionCommandKind::Continue];
        run_plan.initial_control_commands = vec![SessionCommandKind::Query];
        run_plan.collect_execution_fingerprints = false;
        let (lifecycle, preemption_evidence) =
            verify_qemu_lifecycle_config(backend, reduction.host_profile)?;
        let host_pressure = VerifyQemuHostPressure::start(reduction.host_profile)?;
        let report = run_local_qemu_campaign_with_hostile_deadlines(
            backend,
            &run_plan,
            lifecycle,
            reduction.host_profile,
        );
        host_pressure.finish()?;
        let report = report?;
        let mut witness = verify_witness_from_run_report(
            reduction.clone(),
            &run_plan,
            &report,
            Some(backend),
            ergonomics_plan,
            &verify_plan.store_root,
        )?;
        witness.host_scheduler_preemption = preemption_evidence
            .map(|evidence| {
                required_scheduler_preemption_snapshot(
                    &evidence,
                    &format!(
                        "verify hostile profile `{}`",
                        reduction.host_profile.label()
                    ),
                    reduction.host_profile.host_io_stall_ms,
                )
            })
            .transpose()?;
        witnesses.push(witness);
    }
    let report = VerifyWorkflowReport {
        divergence: compare_verify_witnesses(&witnesses),
        witnesses,
    };
    let mut outcome = finish_verify_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        verify_plan,
        report,
    )?;
    append_qemu_control_plane_execution_proof(
        &mut outcome,
        backend,
        "verify-campaign-default-path",
    );
    Ok(outcome)
}

fn verify_qemu_lifecycle_config(
    backend: &ResolvedLocalBackend,
    profile: VerifyHostProfile,
) -> Result<
    (
        production_api::ProductionVmLifecycleConfig,
        Option<crucible_api::BoundedSchedulerPreemptionEvidence>,
    ),
    CliError,
> {
    if !profile.is_valid() {
        return Err(backend_error(format!(
            "verify hostile host profile `{}` is invalid",
            profile.label()
        )));
    }

    let mut config = production_qemu_lifecycle_config(backend)?
        .with_maximum_host_workers(profile.executor_workers);
    let preemption_evidence = profile
        .requires_scheduler_preemption()
        .then(crucible_api::BoundedSchedulerPreemptionEvidence::default);
    if let Some(evidence) = preemption_evidence.as_ref() {
        config = config.with_bounded_scheduler_preemption(evidence.clone());
    }
    Ok((config, preemption_evidence))
}

fn run_local_qemu_campaign_with_hostile_deadlines(
    backend: &ResolvedLocalBackend,
    run_plan: &RunInvocationPlan,
    lifecycle: production_api::ProductionVmLifecycleConfig,
    profile: VerifyHostProfile,
) -> Result<RunWorkflowReport, CliError> {
    let completion_timeout = lifecycle.completion_timeout();
    std::thread::scope(|scope| {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let (report_tx, report_rx) = std::sync::mpsc::sync_channel(1);
        scope.spawn(move || {
            if started_tx.send(()).is_err() {
                return;
            }
            let report = crate::cli_verify_serve::campaign_run::run_local_qemu_campaign_report(
                backend, run_plan, lifecycle,
            );
            let _ = report_tx.send(report);
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| {
                backend_error("local QEMU verify worker did not enter its live lifecycle operation")
            })?;

        if profile.applies_deadline_backstep() {
            let forward_timeout_ms = profile.jittered_timeout_ms(10, 1);
            let backstep_timeout_ms =
                profile.jittered_timeout_ms(10, u64::from(profile.wall_clock_backstep_every));
            if backstep_timeout_ms >= forward_timeout_ms {
                return Err(backend_error(format!(
                    "verify hostile profile `{}` did not configure a decreasing deadline sequence",
                    profile.label()
                )));
            }
            require_live_qemu_observer_timeout(
                &report_rx,
                Duration::from_millis(forward_timeout_ms),
                profile,
                "forward",
            )?;
            require_live_qemu_observer_timeout(
                &report_rx,
                Duration::from_millis(backstep_timeout_ms),
                profile,
                "backstep",
            )?;
        }

        report_rx
            .recv_timeout(completion_timeout.saturating_add(Duration::from_secs(5)))
            .map_err(|error| match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => backend_error(format!(
                    "local QEMU verify exceeded its bounded lifecycle observation deadline for profile `{}`",
                    profile.label()
                )),
                std::sync::mpsc::RecvTimeoutError::Disconnected => backend_error(format!(
                    "local QEMU verify worker exited without a report for profile `{}`",
                    profile.label()
                )),
            })?
    })
}

fn require_live_qemu_observer_timeout(
    report_rx: &std::sync::mpsc::Receiver<Result<RunWorkflowReport, CliError>>,
    timeout: Duration,
    profile: VerifyHostProfile,
    phase: &str,
) -> Result<(), CliError> {
    match report_rx.recv_timeout(timeout) {
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(()),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(backend_error(format!(
            "local QEMU verify worker exited during the {phase} deadline for profile `{}`",
            profile.label()
        ))),
        Ok(_) => Err(backend_error(format!(
            "local QEMU verify completed before applying the {phase} deadline for hostile profile `{}`",
            profile.label()
        ))),
    }
}

struct VerifyQemuHostPressure {
    stop: Arc<std::sync::atomic::AtomicBool>,
    wake: Arc<(std::sync::Mutex<()>, std::sync::Condvar)>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl VerifyQemuHostPressure {
    fn start(profile: VerifyHostProfile) -> Result<Self, CliError> {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let wake = Arc::new((std::sync::Mutex::new(()), std::sync::Condvar::new()));
        let pressure_workers = if profile.priority_pressure_iterations == 0 {
            0
        } else {
            profile.logical_cores
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(pressure_workers);
        let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(pressure_workers);
        let mut worker_round = 0_u64;
        for worker_index in 0..pressure_workers {
            let worker_stop = Arc::clone(&stop);
            let worker_wake = Arc::clone(&wake);
            let name = format!("crucible-verify-host-pressure-{worker_index}");
            let initial_round = worker_round;
            worker_round = worker_round.saturating_add(1);
            let worker_ready = ready_tx.clone();
            let worker = std::thread::Builder::new().name(name).spawn(move || {
                let mut round = initial_round;
                let mut ready = Some(worker_ready);
                while !worker_stop.load(std::sync::atomic::Ordering::Acquire) {
                    let mut accumulator = profile.scheduling_seed ^ round.rotate_left(19);
                    for iteration in 0..profile.priority_pressure_iterations {
                        accumulator = accumulator.rotate_left(7)
                            ^ iteration.wrapping_mul(0x517c_c1b7_2722_0a95);
                        std::hint::spin_loop();
                        if iteration.is_multiple_of(profile.priority_yield_every) {
                            std::thread::yield_now();
                        }
                    }
                    std::hint::black_box(accumulator);
                    if profile.host_io_stall_ms > 0 {
                        let (lock, event) = &*worker_wake;
                        let guard = lock
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        drop(
                            event
                                .wait_timeout_while(
                                    guard,
                                    Duration::from_millis(profile.host_io_stall_ms),
                                    |_| !worker_stop.load(std::sync::atomic::Ordering::Acquire),
                                )
                                .unwrap_or_else(std::sync::PoisonError::into_inner),
                        );
                    }
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(());
                    }
                    round = round.saturating_add(1);
                }
            });
            let worker = match worker {
                Ok(worker) => worker,
                Err(error) => {
                    stop.store(true, std::sync::atomic::Ordering::Release);
                    wake.1.notify_all();
                    for started in workers {
                        let _ = started.join();
                    }
                    return Err(backend_error(format!(
                        "start verify host pressure worker {worker_index}: {error}"
                    )));
                }
            };
            workers.push(worker);
        }
        drop(ready_tx);
        for worker_index in 0..pressure_workers {
            if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                stop.store(true, std::sync::atomic::Ordering::Release);
                wake.1.notify_all();
                for started in workers {
                    let _ = started.join();
                }
                return Err(backend_error(format!(
                    "verify host pressure worker {worker_index} did not complete its first perturbation"
                )));
            }
        }
        Ok(Self {
            stop,
            wake,
            workers,
        })
    }

    fn finish(self) -> Result<(), CliError> {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        self.wake.1.notify_all();
        for (worker_index, worker) in self.workers.into_iter().enumerate() {
            worker.join().map_err(|_| {
                backend_error(format!(
                    "verify host pressure worker {worker_index} panicked"
                ))
            })?;
        }
        Ok(())
    }
}

pub(crate) fn required_scheduler_preemption_snapshot(
    evidence: &crucible_api::BoundedSchedulerPreemptionEvidence,
    operation: &str,
    minimum_requested_stopped_milliseconds: u64,
) -> Result<crucible_api::BoundedSchedulerPreemptionEvidenceSnapshot, CliError> {
    let snapshot = evidence.snapshot().ok_or_else(|| {
        backend_error(format!(
            "{operation} did not publish authenticated scheduler-preemption evidence"
        ))
    })?;
    if !snapshot.applied
        || !snapshot.pending_quantum_certified
        || snapshot.perturbations == 0
        || snapshot.requested_stopped_milliseconds == 0
        || snapshot.requested_stopped_milliseconds < minimum_requested_stopped_milliseconds
    {
        return Err(backend_error(format!(
            "{operation} published incomplete scheduler-preemption evidence"
        )));
    }
    Ok(snapshot)
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
    let run_state_root = std::env::var_os("CRUCIBLE_RUN_STATE_ROOT")
        .map(PathBuf::from)
        .ok_or_else(|| {
            backend_error(
                "production QEMU lifecycle requires CRUCIBLE_RUN_STATE_ROOT for durable process recovery",
            )
        })?;
    let native_guest_architecture = live_qemu_native_guest_architecture()?;
    let mut config = crucible_daemon::with_production_qemu_raw_root_image(
        production_api::ProductionVmLifecycleConfig::new_for_guest_architecture(
            qemu,
            plugin,
            native_guest_architecture,
            kernel,
            root_image,
            run_state_root,
        ),
    )
    .with_run_ceiling_ticks(PRODUCTION_CLI_RUN_CEILING_TICKS)
    .with_quantum_budget(PRODUCTION_CLI_QUANTUM_BUDGET)
    .with_completion_timeout(PRODUCTION_CLI_COMPLETION_TIMEOUT);
    if let Some(kernel_cmdline) = live_qemu_kernel_cmdline() {
        config = config.with_kernel_cmdline_prefix(kernel_cmdline);
    }
    if let Some((kernel, root_image, kernel_cmdline)) = live_qemu_aarch64_assets()? {
        config = config.with_guest_assets(
            crucible::VmArchitecture::Aarch64,
            kernel,
            root_image,
            kernel_cmdline,
        );
    }
    if let Some(initrd) = optional_live_qemu_asset(
        "CRUCIBLE_INITRD",
        option_env!("CRUCIBLE_AOS_INITRD"),
        "initrd",
    )? {
        config = config.with_initrd(initrd);
    }
    if let Some(gateway) =
        optional_live_qemu_asset("CRUCIBLE_DEBUG_GATEWAY", None, "debugger gateway")?
    {
        config = config.with_debug_gateway(gateway);
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
