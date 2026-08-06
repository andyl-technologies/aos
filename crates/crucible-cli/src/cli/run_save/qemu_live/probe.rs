//! Packaged QEMU probing and delegated debug admission.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveQemuProbeEvidence {
    pub(crate) qemu_build_id: String,
    pub(crate) plugin_abi: String,
    pub(crate) completed_icount: u64,
    pub(crate) execution_fingerprint: String,
}

pub(crate) trait LiveQemuProbeRunner {
    fn run_probe(
        &mut self,
        backend: &ResolvedLocalBackend,
    ) -> Result<LiveQemuProbeEvidence, CliError>;
}

pub(super) struct ProductionLiveQemuProbeRunner;

impl LiveQemuProbeRunner for ProductionLiveQemuProbeRunner {
    fn run_probe(
        &mut self,
        backend: &ResolvedLocalBackend,
    ) -> Result<LiveQemuProbeEvidence, CliError> {
        let (qemu_build_id, plugin_abi) = match backend {
            ResolvedLocalBackend::Qemu {
                qemu_build_id,
                plugin_abi,
                ..
            } => (qemu_build_id, plugin_abi),
            #[cfg(any(test, feature = "test-double"))]
            ResolvedLocalBackend::Double => {
                return Err(backend_error("live QEMU probe requires the QEMU backend"));
            }
        };
        let report = run_live_qemu_backend_probe(backend)?;
        Ok(LiveQemuProbeEvidence {
            qemu_build_id: qemu_build_id.clone(),
            plugin_abi: plugin_abi.clone(),
            completed_icount: report.completed_icount,
            execution_fingerprint: format_content_hash_ref(report.execution_fingerprint.hash),
        })
    }
}

/// Executes the live backend admission required by the delegated debug wrapper.
pub(crate) fn run_local_qemu_debug_workflow(
    backend: &ResolvedLocalBackend,
    plan: &DebugInvocationPlan,
) -> Result<Vec<String>, CliError> {
    run_local_qemu_debug_workflow_with_probe(backend, plan, &mut ProductionLiveQemuProbeRunner)
}

pub(crate) fn run_local_qemu_debug_workflow_with_probe(
    backend: &ResolvedLocalBackend,
    plan: &DebugInvocationPlan,
    probe: &mut impl LiveQemuProbeRunner,
) -> Result<Vec<String>, CliError> {
    let artifact_context = artifact_debug_context(plan)?;
    let evidence = probe.run_probe(backend)?;
    validate_live_qemu_probe_evidence(backend, &evidence)?;
    let target = match &plan.target {
        DebugPlanTarget::Artifact(path) => {
            format!(
                "artifact:{}",
                escape_debug_plan_field(&path.display().to_string())
            )
        }
        DebugPlanTarget::Savepoint(hash) => {
            format!("savepoint:{}", format_content_hash_ref(*hash))
        }
        DebugPlanTarget::Session(address) => {
            format!("session:{}", escape_debug_plan_field(address))
        }
    };
    let coordinate = match &plan.coordinate {
        DebugPlanCoordinate::Current => String::from("current"),
        DebugPlanCoordinate::At(coordinate) => debug_coordinate_label(coordinate),
        DebugPlanCoordinate::AtEvent(sequence) => format!("event:{sequence}"),
        DebugPlanCoordinate::AtFailure => {
            let context = artifact_context.as_ref().ok_or_else(|| {
                artifact_error("failure coordinate requires a reproduction artifact")
            })?;
            format!(
                "failure:vtime:{}:quanta:{}",
                context.frontier_ticks, context.quanta
            )
        }
        DebugPlanCoordinate::AtCheckpoint(hash) => {
            format!("checkpoint:{}", format_content_hash_ref(*hash))
        }
    };
    let requested_operation = match &plan.verb {
        DebugInteractiveVerbPlan::AttachGdb => String::from("attach-gdb"),
        DebugInteractiveVerbPlan::ForkDebug => String::from("fork-debug"),
        DebugInteractiveVerbPlan::Goto(coordinate) => {
            format!("goto:{}", debug_coordinate_label(coordinate))
        }
        DebugInteractiveVerbPlan::ReverseStep { grain } => {
            format!("reverse-step:{}", reverse_step_grain_label(*grain))
        }
        DebugInteractiveVerbPlan::ReverseContinue { condition } => {
            format!("reverse-continue:{}", escape_debug_plan_field(condition))
        }
        DebugInteractiveVerbPlan::Exec { .. } => String::from("exec"),
        DebugInteractiveVerbPlan::Pty { .. } => String::from("pty"),
        DebugInteractiveVerbPlan::Ssh => String::from("ssh"),
    };
    let node = escape_debug_plan_field(plan.node.as_deref().unwrap_or("auto"));
    let gdb_listen = escape_debug_plan_field(&plan.gdb_listen);
    Ok(vec![
        format!(
            "qemu-live\toperation=debug-admission\tqemu_build_id={}\tplugin_abi={}\ticount={}\tfingerprint={}",
            evidence.qemu_build_id,
            evidence.plugin_abi,
            evidence.completed_icount,
            evidence.execution_fingerprint
        ),
        format!(
            "debug-plan\texecution=planned-only\trequested_operation={requested_operation}\ttarget={target}\tcoordinate={coordinate}\tnode={}\tgdb_listen={}\tread_only={}\tallow_mutate={}\tdelegated_session_commands={}\traw_gdb_single_step=false",
            node,
            gdb_listen,
            plan.read_only,
            plan.allow_mutate,
            plan.session_commands.len(),
        ),
    ])
}

struct ArtifactFailureContext {
    frontier_ticks: u64,
    quanta: u64,
}

fn artifact_debug_context(
    plan: &DebugInvocationPlan,
) -> Result<Option<ArtifactFailureContext>, CliError> {
    let DebugPlanTarget::Artifact(path) = &plan.target else {
        return Ok(None);
    };
    let bytes = std::fs::read(path).map_err(|error| {
        artifact_error(format!(
            "debug artifact `{}` could not be read: {error}",
            path.display()
        ))
    })?;
    let artifact = decode_reproduction_artifact(&bytes)?;
    if !matches!(plan.coordinate, DebugPlanCoordinate::AtFailure) {
        return Ok(None);
    }
    let component = artifact
        .components
        .iter()
        .find(|component| component.media_type == LIVE_QEMU_REPLAY_CONTRACT_MEDIA_TYPE)
        .ok_or_else(|| artifact_error("debug artifact has no live-QEMU replay contract"))?;
    let payload = artifact
        .payloads
        .iter()
        .find(|payload| payload.digest == component.digest)
        .ok_or_else(|| artifact_error("debug artifact has no embedded live-QEMU contract"))?;
    let contract = LiveQemuReplayContract::decode(&payload.bytes)?;
    Ok(Some(ArtifactFailureContext {
        frontier_ticks: contract.final_frontier_ticks,
        quanta: contract.final_quanta,
    }))
}

fn reverse_step_grain_label(grain: crucible::DebugReverseStepGrain) -> &'static str {
    match grain {
        crucible::DebugReverseStepGrain::Instruction => "instruction",
        crucible::DebugReverseStepGrain::Quantum => "quantum",
        crucible::DebugReverseStepGrain::Event => "event",
        crucible::DebugReverseStepGrain::Assertion => "assertion",
        crucible::DebugReverseStepGrain::Timer => "timer",
    }
}

fn debug_coordinate_label(coordinate: &crucible::DebugCoordinate) -> String {
    match coordinate {
        crucible::DebugCoordinate::Configuration(configuration) => {
            format!(
                "configuration:{}",
                format_content_hash_ref(configuration.id())
            )
        }
        crucible::DebugCoordinate::Checkpoint(checkpoint) => {
            format!("checkpoint:{}", format_content_hash_ref(*checkpoint))
        }
        crucible::DebugCoordinate::EventSequence(sequence) => format!("event:{sequence}"),
        crucible::DebugCoordinate::VirtualTime(at) => format!("vtime:{}", at.ticks),
        crucible::DebugCoordinate::NodeIcount { node, icount } => format!(
            "icount:{}:{}",
            escape_debug_plan_field(&node.name),
            icount.retired
        ),
    }
}

fn escape_debug_plan_field(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// Boots one bounded live QEMU/plugin probe and returns its observed proof.
pub(crate) fn run_live_qemu_backend_probe(
    backend: &ResolvedLocalBackend,
) -> Result<production_api::ProductionPluginInstallReport, CliError> {
    let (qemu, plugin) = match backend {
        ResolvedLocalBackend::Qemu { qemu, plugin, .. } => (qemu, plugin),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error("live QEMU probe requires the QEMU backend"));
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

pub(super) fn required_live_qemu_asset(
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

pub(super) fn optional_live_qemu_asset(
    environment_name: &'static str,
    package_hint: Option<&'static str>,
    label: &'static str,
) -> Result<Option<PathBuf>, CliError> {
    let Some(path) = std::env::var_os(environment_name)
        .map(PathBuf::from)
        .or_else(|| package_hint.map(PathBuf::from))
    else {
        return Ok(None);
    };
    validate_readable_file_artifact(label, &path)?;
    Ok(Some(path))
}

pub(super) fn live_qemu_kernel_cmdline() -> Option<String> {
    std::env::var("CRUCIBLE_KERNEL_CMDLINE")
        .ok()
        .or_else(|| option_env!("CRUCIBLE_AOS_KERNEL_CMDLINE").map(str::to_owned))
}
