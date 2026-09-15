//! Busy-window driving, launch, priming, and scheduler-preemption support.

use super::*;
use crate::QemuLaunchCommand;
use crate::supervision::HostSupervisionDeadline;

#[path = "support/priming.rs"]
mod priming;
pub(super) use priming::*;

const X86_64_MACHINE_TYPE: &str = "pc-q35-9.2";
const X86_64_CPU_MODEL: &str = "qemu64,-rdrand,-rdseed";
const X86_64_KERNEL_CMDLINE: &str = "console=ttyS0 reboot=k panic=1 quiet";
const AARCH64_MACHINE_TYPE: &str = "virt-9.2";
const AARCH64_CPU_MODEL: &str = "cortex-a57";
const AARCH64_KERNEL_CMDLINE: &str = "console=ttyAMA0 reboot=k panic=1 quiet";
/// Bound on retries before a stalled step is classified as a wake defect.
const MAX_REISSUES_PER_CEILING: u32 = 64;
/// Nonzero boot-barrier ceiling below the first modeled busy window.
const PRIME_CEILING_ICOUNT: u64 = 1_000_000;
/// Host-liveness polling interval for the priming quantum.
const PRIME_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Returns the architecture-specific deterministic launch baseline.
pub(super) fn launch_profile_candidate(
    architecture: LivePluginGuestArchitecture,
) -> LaunchProfileCandidate {
    match architecture {
        LivePluginGuestArchitecture::X86_64 => LaunchProfileCandidate::default()
            .with_machine_type(X86_64_MACHINE_TYPE)
            .with_cpu_model(X86_64_CPU_MODEL)
            .with_kernel_cmdline(X86_64_KERNEL_CMDLINE),
        LivePluginGuestArchitecture::Aarch64 => LaunchProfileCandidate::default()
            .with_machine_type(AARCH64_MACHINE_TYPE)
            .with_cpu_model(AARCH64_CPU_MODEL)
            .with_kernel_cmdline(AARCH64_KERNEL_CMDLINE),
    }
}

pub(super) struct QemuLiveNodeStepQuantum {
    pub(super) completion_icount: u64,
}

struct PrimeDeviceServicers<'a> {
    block: Option<&'a mut QemuLiveBlockIoServicer>,
    ninep: Option<&'a mut QemuLive9pIoServicer>,
}

pub(super) fn advance_to_busy_ceiling(
    node: &mut QemuNode,
    ceiling: u64,
) -> Result<QemuLiveNodeStepQuantum, QemuLiveNodeStepGateError> {
    let mut reissue_count = 0;
    let mut last_icount = node
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read pre-advance icount", source))?
        .retired;
    loop {
        node.advance_to_ceiling(Icount { retired: ceiling })
            .map_err(|source| QemuLiveNodeStepGateError::node_op("advance to ceiling", source))?;
        let idle = node.idle_state().map_err(|source| {
            QemuLiveNodeStepGateError::node_op("read post-advance idle state", source)
        })?;
        let current = idle.current_icount.retired;

        if current >= ceiling {
            return Ok(QemuLiveNodeStepQuantum {
                completion_icount: current,
            });
        }

        // The step parked below the ceiling. In a busy window this only happens
        // when queued work interrupts the advance, so re-issue the same ceiling.
        // If the node made no forward progress across a re-issue, the guest is
        // stalled -- the wake defect the first live node user is expected to
        // surface -- so fail loudly rather than spin.
        if current <= last_icount || reissue_count >= MAX_REISSUES_PER_CEILING {
            return Err(QemuLiveNodeStepGateError::StepStalled {
                ceiling_icount: ceiling,
                last_icount: current,
                next_deadline_icount: idle.next_deadline.map(|deadline| deadline.retired),
                reissue_count,
            });
        }
        last_icount = current;
        reissue_count += 1;
    }
}

fn drive_mapped_prime_chain(
    setup: &crate::QemuHostPluginSetup,
    timeout: Duration,
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    prime_ceiling: u64,
    block: Option<&mut QemuLiveBlockIoServicer>,
    ninep: Option<&mut QemuLive9pIoServicer>,
    report_progress: bool,
) -> Result<Vec<crate::QemuNodeEmittedFrame>, QemuLiveNodeStepGateError> {
    let horizon = crucible::ExecutionHorizon {
        icount: Icount {
            retired: prime_ceiling,
        },
    };
    let pending = QemuShmemHotPathChannel::start_quantum(hot_path, horizon)
        .map_err(|source| QemuLiveNodeStepGateError::prime("start priming quantum", source))?;
    poll_mapped_prime_chain(
        setup,
        timeout,
        hot_path,
        pending,
        prime_ceiling,
        PrimeDeviceServicers { block, ninep },
        report_progress,
    )
}

fn poll_mapped_prime_chain(
    setup: &crate::QemuHostPluginSetup,
    timeout: Duration,
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    initial_pending: crate::QemuNodePendingQuantum,
    prime_ceiling: u64,
    mut servicers: PrimeDeviceServicers<'_>,
    report_progress: bool,
) -> Result<Vec<crate::QemuNodeEmittedFrame>, QemuLiveNodeStepGateError> {
    let horizon = crucible::ExecutionHorizon {
        icount: Icount {
            retired: prime_ceiling,
        },
    };
    let mut pending = Some(initial_pending);
    let deadline = HostSupervisionDeadline::start(timeout);
    let mut emitted_frames = Vec::new();
    let mut next_progress_icount = 250_000_000_u64;
    while deadline.has_time_remaining() {
        setup
            .signal_plugin_wake()
            .map_err(|source| QemuLiveNodeStepGateError::prime("wake priming guest", source))?;
        let current = QemuShmemHotPathChannel::current_icount(hot_path)
            .map_err(|source| QemuLiveNodeStepGateError::prime("poll priming icount", source))?
            .retired;
        if let Some(servicer) = servicers.block.as_deref_mut() {
            servicer
                .service_fault_free_initialization(current)
                .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })?;
        }
        if let Some(servicer) = servicers.ninep.as_deref_mut() {
            servicer
                .service(current)
                .map_err(|source| QemuLiveNodeStepGateError::NinepServicer { source })?;
        }
        let completion = {
            let active = pending.as_mut().ok_or_else(|| {
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: String::from("priming quantum token was unexpectedly absent"),
                }
            })?;
            match QemuShmemHotPathChannel::poll_quantum(hot_path, active) {
                Ok(completion) => Some(completion),
                Err(source) if source.retryable => None,
                Err(source) => {
                    return Err(QemuLiveNodeStepGateError::prime(
                        "poll priming quantum",
                        source,
                    ));
                }
            }
        };
        if let Some(completion) = completion {
            emitted_frames.extend(completion.emitted_frames);
            drop(pending.take());
            let completed_current = QemuShmemHotPathChannel::current_icount(hot_path)
                .map_err(|source| {
                    QemuLiveNodeStepGateError::prime("read completed priming icount", source)
                })?
                .retired;
            if report_progress && completed_current >= next_progress_icount {
                tracing::debug!(
                    phase = "retained-capture",
                    status = "retry-progress",
                    icount = completed_current,
                    "crucible live network I/O"
                );
                next_progress_icount = completed_current.saturating_add(250_000_000);
            }
            if completed_current >= prime_ceiling {
                return Ok(emitted_frames);
            }
            pending = Some(
                QemuShmemHotPathChannel::start_quantum(hot_path, horizon).map_err(|source| {
                    QemuLiveNodeStepGateError::prime("reissue priming quantum", source)
                })?,
            );
        }
        if deadline.has_time_remaining() {
            thread::sleep(PRIME_POLL_INTERVAL);
        }
    }
    Err(QemuLiveNodeStepGateError::PrimeStalled {
        ceiling_icount: prime_ceiling,
    })
}

fn retained_network_at_capture(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    payload: &[u8],
    capture_icount: u64,
) -> Result<crate::QemuNetworkTransportCheckpoint, QemuLiveNodeStepGateError> {
    let checkpoint =
        QemuShmemHotPathChannel::checkpoint_network_transport(hot_path).map_err(|source| {
            QemuLiveNodeStepGateError::prime("capture retained boot network frame", source)
        })?;
    let retained = checkpoint.inbound.frames.first().is_some_and(|frame| {
        frame.delivery_icount == 1
            && frame.delivery_attempts() > 0
            && frame
                .delivery_state()
                .is_ok_and(|state| state == FrameDeliveryState::Retained)
            && frame.payload().is_ok_and(|actual| actual == payload)
            && frame.last_delivery_attempt_icount() <= capture_icount
    });
    if !retained || checkpoint.inbound.frames.len() != 1 {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "boot backpressure canary was not retained at capture icount {capture_icount}: {:?}",
                checkpoint.inbound.frames
            ),
        });
    }
    Ok(checkpoint)
}

/// Builds the configured root-image or diskless-firmware VM launch config.
pub(super) fn vm_launch_config(
    config: &QemuLiveNodeStepGateConfig,
    node_name: &str,
) -> QemuVmLaunchConfig {
    let kernel = launch_artifact("kernel", &config.kernel);
    let vm = if config.firmware_boot {
        QemuVmLaunchConfig::new_firmware_boot(
            node_name,
            launch_artifact("firmware", &config.firmware),
        )
    } else {
        match &config.root_image {
            Some(root_image) => QemuVmLaunchConfig::new(
                node_name,
                kernel,
                launch_artifact("root-image", root_image),
            )
            .with_root_image_format(config.root_image_format),
            None => QemuVmLaunchConfig::new_diskless(
                node_name,
                kernel,
                launch_artifact("firmware", &config.firmware),
            ),
        }
    };
    let vm = match (&config.initrd, config.firmware_boot) {
        (Some(_), true) | (None, _) => vm,
        (Some(initrd), false) => vm.with_initrd(launch_artifact("initrd", initrd)),
    };
    let vm = match &config.shmem_network_mac {
        Some(mac) => {
            vm.with_crucible_shmem_network(CrucibleShmemNetworkDevice::new().with_mac(mac.clone()))
        }
        None => vm,
    };
    let vm = match &config.shmem_block {
        Some(block) => vm.with_crucible_shmem_block(CrucibleShmemBlockDevice::new(
            block.durability.length_bytes,
        )),
        None => vm,
    };
    let vm = match &config.shmem_ninep {
        Some(_) => vm.with_crucible_shmem_9p(CrucibleShmem9pDevice::new()),
        None => vm,
    };
    if config.accelerator {
        vm.with_crucible_accelerator(CrucibleAcceleratorDevice::new())
    } else {
        vm
    }
}

pub(super) fn live_node_plugin_config(
    config: &QemuLiveNodeStepGateConfig,
    profile: &crate::DeterministicLaunchProfile,
    vm: &QemuVmLaunchConfig,
    node_name: &str,
    guarded_probe: Option<(&QemuPreparedRunDirectory, &QemuChildProcessContract)>,
) -> Result<QemuLaunchPluginConfig, QemuLiveNodeStepGateError> {
    let plugin_base = live_node_plugin_base(config).with_fault_target_node(node_name);
    let mut plugin = if config.whitebox == QemuLaunchPluginSwitch::On {
        let probe_command = whitebox_probe_command(config, profile, vm, plugin_base.clone())?;
        let validation = match config.architecture {
            LivePluginGuestArchitecture::X86_64 => {
                let (run_directory, process_contract) = guarded_probe.ok_or_else(|| {
                    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                        reason: String::from(
                            "x86 white-box setup requires guarded process and storage authority",
                        ),
                    }
                })?;
                crate::launch::probe_x86_whitebox_setup_guarded(
                    &probe_command,
                    run_directory,
                    process_contract,
                )
            }
            LivePluginGuestArchitecture::Aarch64 => {
                crate::validate_aarch64_whitebox_setup(config.doorbell_instruction_abi_version)
            }
        }
        .map_err(|source| QemuLiveNodeStepGateError::WhiteboxSetup { source })?;
        plugin_base
            .with_whitebox(config.whitebox)
            .with_whitebox_setup(validation)
    } else {
        plugin_base.with_whitebox(config.whitebox)
    };
    if let Some(app_random) = &config.app_random {
        plugin = plugin.with_app_random(app_random.clone());
    }
    if let Some(selectable_catalog_plan) = &config.selectable_catalog_plan {
        plugin = plugin.with_selectable_catalog_plan(selectable_catalog_plan.clone());
    }
    Ok(plugin)
}

fn whitebox_probe_command(
    config: &QemuLiveNodeStepGateConfig,
    profile: &crate::DeterministicLaunchProfile,
    vm: &QemuVmLaunchConfig,
    plugin: QemuLaunchPluginConfig,
) -> Result<QemuLaunchCommand, QemuLiveNodeStepGateError> {
    let command = QemuLaunchCommandBuilder::new_for_live_gate(
        profile.clone(),
        vm.clone(),
        path_text(&config.qemu_executable),
        plugin,
        crate::LivePluginGuestArchitecture::X86_64,
    );
    config
        .apply_diagnostic_trace(command)
        .build()
        .map_err(|source| QemuLiveNodeStepGateError::LaunchCommand { source })
}

fn live_node_plugin_base(config: &QemuLiveNodeStepGateConfig) -> QemuLaunchPluginConfig {
    QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT)
        .with_process_generation(config.process_generation)
        .with_network_tx_next_sequence(config.network_tx_next_sequence)
        .with_storage_completed_history_limits(
            config.storage_completed_history_epochs,
            config.storage_completed_history_gaps,
        )
        .with_coverage(config.coverage)
        .with_fingerprint(config.fingerprint)
}

/// Returns a shutdown policy with real bounded waits for a gate teardown.
pub(super) fn gate_shutdown_policy() -> QemuShutdownPolicy {
    QemuShutdownPolicy {
        control_quit_wait: Duration::from_secs(2),
        qmp_quit_wait: Duration::from_secs(5),
        sigterm_wait: Duration::from_secs(5),
        sigkill_wait: Duration::from_secs(5),
        reap_wait: Duration::from_secs(5),
    }
}

/// Returns an async-driver policy whose lifecycle and advance budgets share the configured bound.
pub(super) fn gate_async_policy(completion_timeout: Duration) -> QemuAsyncDriverPolicy {
    QemuAsyncDriverPolicy::new(
        completion_timeout,
        completion_timeout,
        completion_timeout,
        completion_timeout,
    )
}

#[path = "support/tail.rs"]
mod tail;
pub(super) use tail::{
    GateSendAuthorizer, basic_block_coverage_config, launch_artifact, node_id, path_text,
};
#[cfg(test)]
#[path = "support/tests.rs"]
mod tests;
