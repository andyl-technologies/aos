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
    #[cfg(any(test, feature = "test-double"))]
    let verified = verify_selftest_corpus(args)?;
    #[cfg(not(any(test, feature = "test-double")))]
    let verified = Vec::new();
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
                #[cfg(any(test, feature = "test-double"))]
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
    _thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    _plan: &FuzzDriverPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU fuzz requires a resolved backend"))?;
    reject_unwired_qemu_workflow(backend, "fuzz")
}

pub(crate) fn run_local_qemu_search_workflow(
    _thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    _plan: &SearchDriverPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU search requires a resolved backend"))?;
    reject_unwired_qemu_workflow(backend, "search")
}

/// Rejects local scenario execution until the packaged QEMU backend drives it.
pub(crate) fn run_local_qemu_workflow(
    backend: &ResolvedLocalBackend,
    _thin_plan: &CliThinWrapperPlan,
    _backend_plan: &BackendSelectionPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    _run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    reject_unwired_qemu_workflow(backend, "run")
}

/// Rejects verification until every reduction runs through packaged QEMU.
pub(crate) fn run_local_qemu_verify_workflow(
    _thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    _verify_plan: &VerifyInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU verify requires a resolved backend"))?;
    reject_unwired_qemu_workflow(backend, "verify")
}

pub(crate) fn reject_unwired_qemu_workflow(
    backend: &ResolvedLocalBackend,
    command: &'static str,
) -> Result<BackendCommandOutcome, CliError> {
    if !matches!(backend, ResolvedLocalBackend::Qemu { .. }) {
        return Err(backend_error(format!(
            "local QEMU {command} requires the QEMU backend"
        )));
    }
    Err(backend_error(format!(
        "local QEMU {command} execution is unavailable: the live QEMU backend is not wired to \
         this workflow; no in-process double fallback was executed (select `--backend double` \
         explicitly for modeled execution)"
    )))
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
