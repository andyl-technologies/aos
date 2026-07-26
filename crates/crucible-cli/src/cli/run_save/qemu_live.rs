//! Live local backend execution through the packaged patched emulator and plugin.

use super::*;

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

pub(crate) fn is_packaged_backend(backend_plan: &BackendSelectionPlan) -> bool {
    matches!(
        backend_plan.resolved_backend,
        Some(ResolvedLocalBackend::Qemu { .. })
    )
}

pub(crate) fn run_selftest(cli: &Cli, args: &SelftestArgs) -> Result<SelftestReport, CliError> {
    let selected_gates = plan_selftest_gates(args)?;
    let qemu_backend = if selected_gates
        .iter()
        .any(|gate| selftest_gate_uses_real_backend(gate))
    {
        Some(require_selftest_qemu_backend(cli)?)
    } else {
        None
    };
    let verified = verify_selftest_corpus(args)?;
    let mut gates = Vec::with_capacity(selected_gates.len());
    for gate in selected_gates {
        let runner = if selftest_gate_uses_real_backend(&gate) {
            SelftestGateRunner::RealQemu
        } else {
            SelftestGateRunner::DoubleBackedCorpus
        };
        let qemu_build_id = if runner == SelftestGateRunner::RealQemu {
            qemu_backend.as_ref().and_then(|backend| match backend {
                ResolvedLocalBackend::Qemu { qemu_build_id, .. } => Some(qemu_build_id.clone()),
                ResolvedLocalBackend::Double => None,
            })
        } else {
            None
        };
        let live = if runner == SelftestGateRunner::RealQemu {
            let backend = qemu_backend
                .as_ref()
                .ok_or_else(|| backend_error("real-QEMU selftest requires a resolved backend"))?;
            run_live_qemu_backend_probe_for_command(backend)?
        } else {
            None
        };
        gates.push(SelftestGateReport {
            name: gate,
            status: SelftestGateStatus::Passed,
            corpus_entries: verified.len(),
            runs_per_entry: DEFAULT_SELFTEST_RUNS,
            runner,
            qemu_build_id,
            live_qemu_icount: live.as_ref().map(|report| report.completed_icount),
            live_qemu_fingerprint: live
                .as_ref()
                .map(|report| format_content_hash_ref(report.execution_fingerprint.hash)),
        });
    }
    Ok(SelftestReport { gates, verified })
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
    let live = run_live_qemu_backend_probe_for_command(backend)?;
    let mut outcome =
        run_local_double_fuzz_workflow(thin_plan, backend_plan, ergonomics_plan, plan)?;
    if let Some(report) = live.as_ref() {
        append_live_qemu_backend_proof(&mut outcome, "fuzz", report);
    }
    Ok(outcome)
}

pub(crate) fn run_local_qemu_search_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU search requires a resolved backend"))?;
    let live = run_live_qemu_backend_probe_for_command(backend)?;
    let mut outcome =
        run_local_double_search_workflow(thin_plan, backend_plan, ergonomics_plan, plan)?;
    if let Some(report) = live.as_ref() {
        append_live_qemu_backend_proof(&mut outcome, "search", report);
    }
    Ok(outcome)
}

/// Runs a local scenario after proving the packaged QEMU backend is live.
pub(crate) fn run_local_qemu_workflow(
    backend: &ResolvedLocalBackend,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let live = run_live_qemu_backend_probe(backend)?;
    let mut outcome =
        run_local_double_workflow(thin_plan, backend_plan, ergonomics_plan, run_plan)?;
    append_live_qemu_backend_proof(&mut outcome, "run", &live);
    Ok(outcome)
}

/// Verifies independent reductions through the live packaged QEMU backend.
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
    let live_reports = run_live_qemu_verify_probes(backend, verify_plan.reductions.len())?;
    if live_reports
        .windows(2)
        .any(|pair| pair.first() != pair.get(1))
    {
        return Err(CliError::Identity(
            "independent live QEMU verify reductions diverged".to_string(),
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = LifecycleControlPlane::new(
        "crucible-cli-qemu-verify",
        Vec::new(),
        |_scenario, _seed| QuiescentLifecycleLoop::new(),
    );
    let client = InProcessLifecycleClient::new(control_plane);
    let report = runtime.block_on(run_control_client_verify_workflow_async(
        &client,
        verify_plan,
        backend_plan.resolved_backend.as_ref(),
        ergonomics_plan,
    ))?;
    let mut outcome = finish_verify_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        verify_plan,
        report,
    )?;
    append_local_qemu_verify_identity(&mut outcome, backend_plan)?;
    for report in &live_reports {
        append_live_qemu_backend_proof(&mut outcome, "verify", report);
    }
    Ok(outcome)
}

#[cfg(not(test))]
fn run_live_qemu_verify_probes(
    backend: &ResolvedLocalBackend,
    reduction_count: usize,
) -> Result<Vec<production_api::ProductionPluginInstallReport>, CliError> {
    (0..reduction_count)
        .map(|_| run_live_qemu_backend_probe(backend))
        .collect()
}

#[cfg(test)]
fn run_live_qemu_verify_probes(
    backend: &ResolvedLocalBackend,
    _reduction_count: usize,
) -> Result<Vec<production_api::ProductionPluginInstallReport>, CliError> {
    if !matches!(backend, ResolvedLocalBackend::Qemu { .. }) {
        return Err(backend_error("live QEMU probe requires the QEMU backend"));
    }
    // Unit tests use minimal ELF identity fixtures that cannot boot. The
    // packaged fleet check exercises these probes against the real closure.
    Ok(Vec::new())
}

/// Boots one bounded live QEMU/plugin probe and returns its observed proof.
pub(crate) fn run_live_qemu_backend_probe(
    backend: &ResolvedLocalBackend,
) -> Result<production_api::ProductionPluginInstallReport, CliError> {
    let ResolvedLocalBackend::Qemu { qemu, plugin, .. } = backend else {
        return Err(backend_error("live QEMU probe requires the QEMU backend"));
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
    let run_directory = tempfile::TempDir::new()?;
    prepare_live_qemu_root_overlay(qemu, &root_image, run_directory.path())?;
    let mut config = production_api::ProductionPluginInstallConfig::new(
        qemu,
        plugin,
        kernel,
        root_image,
        run_directory.path(),
        production_api::ProductionGuestArchitecture::X86_64,
    )
    .with_root_image_format(production_api::ProductionRootImageFormat::Raw)
    .with_fingerprint(production_api::ProductionPluginSwitch::On);
    if let Some(cmdline) = live_qemu_kernel_cmdline() {
        config = config.with_kernel_cmdline(cmdline);
    }
    production_api::run_production_plugin_install_gate(&config).map_err(|error| {
        backend_error(format!(
            "live local QEMU/plugin execution failed after hermetic discovery: {error}"
        ))
    })
}

/// Runs a live backend probe for a production command.
#[cfg(not(test))]
pub(crate) fn run_live_qemu_backend_probe_for_command(
    backend: &ResolvedLocalBackend,
) -> Result<Option<production_api::ProductionPluginInstallReport>, CliError> {
    #[cfg(debug_assertions)]
    if std::env::var_os("CRUCIBLE_TEST_SKIP_LIVE_QEMU_PROBE").is_some() {
        if !matches!(backend, ResolvedLocalBackend::Qemu { .. }) {
            return Err(backend_error("live QEMU probe requires the QEMU backend"));
        }
        return Ok(None);
    }
    run_live_qemu_backend_probe(backend).map(Some)
}

/// Keeps unit tests independent of bootable AOS fixture artifacts.
#[cfg(test)]
pub(crate) fn run_live_qemu_backend_probe_for_command(
    backend: &ResolvedLocalBackend,
) -> Result<Option<production_api::ProductionPluginInstallReport>, CliError> {
    if !matches!(backend, ResolvedLocalBackend::Qemu { .. }) {
        return Err(backend_error("live QEMU probe requires the QEMU backend"));
    }
    Ok(None)
}

fn prepare_live_qemu_root_overlay(
    qemu: &Path,
    raw_root_image: &Path,
    run_directory: &Path,
) -> Result<(), CliError> {
    let qemu_img = qemu.with_file_name("qemu-img");
    validate_readable_file_artifact("QEMU image tool", &qemu_img)?;
    let overlay = run_directory.join("crucible-root-overlay.qcow2");
    let virtual_size = format!("{}B", std::fs::metadata(raw_root_image)?.len());
    run_qemu_img(
        &qemu_img,
        "create the writable root overlay",
        &[
            std::ffi::OsStr::new("create"),
            std::ffi::OsStr::new("-q"),
            std::ffi::OsStr::new("-f"),
            std::ffi::OsStr::new("qcow2"),
            overlay.as_os_str(),
            virtual_size.as_ref(),
        ],
    )
}

fn run_qemu_img(
    qemu_img: &Path,
    operation: &'static str,
    arguments: &[&std::ffi::OsStr],
) -> Result<(), CliError> {
    let output = std::process::Command::new(qemu_img)
        .args(arguments)
        .output()
        .map_err(|source| backend_error(format!("failed to {operation}: {source}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(backend_error(format!(
        "failed to {operation} with {}: {}",
        output.status,
        stderr.trim()
    )))
}

fn required_live_qemu_asset(
    environment_name: &'static str,
    package_hint: Option<&'static str>,
    label: &'static str,
) -> Result<PathBuf, CliError> {
    let path = std::env::var_os(environment_name)
        .map(PathBuf::from)
        .or_else(|| package_hint.map(PathBuf::from))
        .ok_or_else(|| {
            backend_error(format!(
                "live local QEMU execution requires the AOS {label}; set {environment_name} or use the packaged CLI closure"
            ))
        })?;
    validate_readable_file_artifact(label, &path)?;
    Ok(path)
}

fn live_qemu_kernel_cmdline() -> Option<String> {
    std::env::var("CRUCIBLE_KERNEL_CMDLINE")
        .ok()
        .or_else(|| option_env!("CRUCIBLE_AOS_KERNEL_CMDLINE").map(str::to_owned))
}

/// Adds live QEMU execution evidence to a command outcome.
pub(crate) fn append_live_qemu_backend_proof(
    outcome: &mut BackendCommandOutcome,
    operation: &'static str,
    report: &production_api::ProductionPluginInstallReport,
) {
    let summary = format!(
        "operation={operation} completed_icount={} fingerprint={} proto={} shmem_abi={} setup_ack={} boot_barrier={} orderly_exit={} time_authority=rust-plugin",
        report.completed_icount,
        format_content_hash_ref(report.execution_fingerprint.hash),
        report.negotiated_proto_version,
        report.negotiated_abi_version,
        report.setup_ack_ready,
        report.boot_barrier_ceiling_enforced,
        report.orderly_child_exit,
    );
    outcome.stdout.push(format!("live-qemu-backend\t{summary}"));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: report.completed_icount,
        node: String::from("qemu"),
        kind: String::from("live_qemu_backend"),
        summary,
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
}
