//! Busy-window driving, launch, priming, and scheduler-preemption support.

use std::os::unix::net::UnixStream;

use super::*;
pub(super) use crate::bounded_scheduler_preemption::BoundedSchedulerPreemption as HostAdversary;
use crate::supervision::HostSupervisionDeadline;

const X86_64_MACHINE_TYPE: &str = "pc-q35-9.2";
const X86_64_CPU_MODEL: &str = "qemu64,-rdrand,-rdseed";
const X86_64_KERNEL_CMDLINE: &str = "console=ttyS0 reboot=k panic=1 quiet";
const AARCH64_MACHINE_TYPE: &str = "virt-9.2";
const AARCH64_CPU_MODEL: &str = "cortex-a57";
const AARCH64_KERNEL_CMDLINE: &str = "console=ttyAMA0 reboot=k panic=1 quiet";

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

/// Advances the node through each busy-window ceiling with a caller re-issue loop.
///
/// [`QemuNode::advance_to_ceiling`] drives a single bounded quantum, so a step
/// interrupted by queued work (the patch-0025 reset/advance drain interaction)
/// returns [`AdvanceOutcome::Paused`] before the ceiling. The re-issue loop
/// republishes the same ceiling until the node reaches it, treating a step that
/// makes no progress across the re-issue bound as a stall rather than looping
/// forever.
pub(super) fn drive_busy_window_steps(
    node: &mut QemuNode,
    ceilings: &[u64],
    host_adversary: &mut Option<HostAdversary>,
) -> Result<Vec<QemuLiveNodeStepQuantum>, QemuLiveNodeStepGateError> {
    let mut quanta = Vec::with_capacity(ceilings.len());
    for &ceiling in ceilings {
        let quantum = advance_to_busy_ceiling_with_adversary(node, ceiling, host_adversary)?;
        quanta.push(quantum);
    }
    Ok(quanta)
}

pub(super) fn advance_to_busy_ceiling(
    node: &mut QemuNode,
    ceiling: u64,
) -> Result<QemuLiveNodeStepQuantum, QemuLiveNodeStepGateError> {
    advance_to_busy_ceiling_with_adversary(node, ceiling, &mut None)
}

fn advance_to_busy_ceiling_with_adversary(
    node: &mut QemuNode,
    ceiling: u64,
    host_adversary: &mut Option<HostAdversary>,
) -> Result<QemuLiveNodeStepQuantum, QemuLiveNodeStepGateError> {
    let mut reissue_count = 0;
    let mut last_icount = node
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read pre-advance icount", source))?
        .retired;
    loop {
        let outcome = node
            .advance_to_ceiling_after_publish(Icount { retired: ceiling }, |target, pending| {
                HostAdversary::certify_async_quantum_pending(host_adversary, target, pending)
                    .map_err(|source| {
                        QemuNodeChannelError::new(
                            "certify scheduler preemption over pending quantum",
                            source.to_string(),
                        )
                    })?;
                Ok(())
            })
            .map_err(|source| QemuLiveNodeStepGateError::node_op("advance to ceiling", source))?;
        let idle = node.idle_state().map_err(|source| {
            QemuLiveNodeStepGateError::node_op("read post-advance idle state", source)
        })?;
        let current = idle.current_icount.retired;

        let reached_horizon = matches!(outcome, AdvanceOutcome::ReachedHorizon);
        if current >= ceiling {
            return Ok(QemuLiveNodeStepQuantum {
                target_icount: ceiling,
                completion_icount: current,
                logical_offset: current - ceiling,
                reissue_count,
                reached_horizon,
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

/// Requires the scheduler-preempted run to reproduce the reference byte for byte.
pub(super) fn assert_runs_match(
    reference: &NodeStepOutcome,
    second: &NodeStepOutcome,
) -> Result<(), QemuLiveNodeStepGateError> {
    if reference.quanta != second.quanta {
        return Err(QemuLiveNodeStepGateError::SecondRunDiverged {
            reason: format!(
                "per-step accounting differed: {:?} vs {:?}",
                reference.quanta, second.quanta
            ),
        });
    }
    if reference.fingerprint != second.fingerprint {
        return Err(QemuLiveNodeStepGateError::SecondRunDiverged {
            reason: format!(
                "execution fingerprint differed: {} vs {}",
                reference.fingerprint.hash.to_hex(),
                second.fingerprint.hash.to_hex()
            ),
        });
    }
    Ok(())
}

/// Drives one bounded priming quantum to move the guest off the boot barrier.
///
/// The node's own hot path does not exist yet -- it is built only after QMP
/// connects -- so this maps a temporary hot path over the same shared-memory
/// region. Publishing the first ceiling releases the boot barrier exactly as the
/// M1 install gate does. The loop also pulses the plugin wake eventfd so QEMU's
/// main loop can dispatch asynchronous device completion while the vCPU is
/// parked. The temporary hot path is dropped before the node maps its own view
/// of the region.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the region cannot be mapped, the
/// hot path cannot bind, a quantum boundary cannot be published or read, or the
/// guest never reaches the priming ceiling within `timeout`.
pub(super) struct PrimeGuestOutcome {
    pub(super) emitted_frames: Vec<crate::QemuNodeEmittedFrame>,
    pub(super) retained_network: Option<crate::QemuNetworkTransportCheckpoint>,
}

pub(super) fn prime_guest_off_boot_barrier(
    setup: &crate::QemuHostPluginSetup,
    timeout: Duration,
    identity: LiveNodeIdentity<'_>,
    coverage: QemuLaunchPluginSwitch,
    mut block: Option<&mut QemuLiveBlockIoServicer>,
    mut ninep: Option<&mut QemuLive9pIoServicer>,
    boot_backpressure_payload: Option<&[u8]>,
) -> Result<PrimeGuestOutcome, QemuLiveNodeStepGateError> {
    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLiveNodeStepGateError::PrimeRegionMap { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(identity.node), GATE_SLOT)
        .with_router(node_id(identity.router), SLOT_NET_ROUTER as u32)
        .with_coverage(basic_block_coverage_config(coverage));
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, GateSendAuthorizer)
        .map_err(|source| QemuLiveNodeStepGateError::PrimeHotPath { source })?;

    let prime_ceiling = if let Some(payload) = boot_backpressure_payload {
        QemuShmemHotPathChannel::deliver_frame_at(
            &mut hot_path,
            BackendInput {
                node: node_id(identity.node),
                payload: payload.to_vec(),
            },
            Icount { retired: 1 },
        )
        .map_err(|source| {
            QemuLiveNodeStepGateError::prime("publish boot backpressure canary", source)
        })?;
        1
    } else {
        PRIME_CEILING_ICOUNT
    };
    let emitted_frames = drive_mapped_prime_chain(
        setup,
        timeout,
        &mut hot_path,
        prime_ceiling,
        block.as_deref_mut(),
        ninep.as_deref_mut(),
        false,
    )?;
    QemuShmemHotPathChannel::drain_observable_events(&mut hot_path)
        .map_err(|source| QemuLiveNodeStepGateError::prime("drain priming observations", source))?;
    QemuShmemHotPathChannel::drain_causal_decisions(&mut hot_path)
        .map_err(|source| QemuLiveNodeStepGateError::prime("drain priming decisions", source))?;
    let retained_network = if let Some(payload) = boot_backpressure_payload {
        Some(retained_network_at_capture(
            &mut hot_path,
            payload,
            prime_ceiling,
        )?)
    } else {
        None
    };
    Ok(PrimeGuestOutcome {
        emitted_frames,
        retained_network,
    })
}

pub(super) fn continue_boot_network_backpressure_capture(
    setup: &crate::QemuHostPluginSetup,
    timeout: Duration,
    identity: LiveNodeIdentity<'_>,
    coverage: QemuLaunchPluginSwitch,
    block: Option<&mut QemuLiveBlockIoServicer>,
    ninep: Option<&mut QemuLive9pIoServicer>,
    payload: &[u8],
    capture_icount: u64,
    initial_network: crate::QemuNetworkTransportCheckpoint,
    mut emitted_frames: Vec<crate::QemuNodeEmittedFrame>,
) -> Result<PrimeGuestOutcome, QemuLiveNodeStepGateError> {
    if capture_icount <= 1 {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from("continued boot backpressure capture must be later than icount 1"),
        });
    }
    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLiveNodeStepGateError::PrimeRegionMap { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(identity.node), GATE_SLOT)
        .with_router(node_id(identity.router), SLOT_NET_ROUTER as u32)
        .with_coverage(basic_block_coverage_config(coverage));
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, GateSendAuthorizer)
        .map_err(|source| QemuLiveNodeStepGateError::PrimeHotPath { source })?;
    let current = QemuShmemHotPathChannel::current_icount(&mut hot_path)
        .map_err(|source| {
            QemuLiveNodeStepGateError::prime("read continued priming origin", source)
        })?
        .retired;
    if current != 1 {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "continued boot backpressure capture started at icount {current} instead of 1"
            ),
        });
    }
    QemuShmemHotPathChannel::restore_network_transport(&mut hot_path, &initial_network).map_err(
        |source| {
            QemuLiveNodeStepGateError::prime(
                "bind continued boot backpressure transport cursors",
                source,
            )
        },
    )?;
    let continued = drive_mapped_prime_chain(
        setup,
        timeout,
        &mut hot_path,
        capture_icount,
        block,
        ninep,
        true,
    )?;
    emitted_frames.extend(continued);
    QemuShmemHotPathChannel::drain_observable_events(&mut hot_path).map_err(|source| {
        QemuLiveNodeStepGateError::prime("drain continued priming observations", source)
    })?;
    QemuShmemHotPathChannel::drain_causal_decisions(&mut hot_path).map_err(|source| {
        QemuLiveNodeStepGateError::prime("drain continued priming decisions", source)
    })?;
    let retained_network = Some(retained_network_at_capture(
        &mut hot_path,
        payload,
        capture_icount,
    )?);
    Ok(PrimeGuestOutcome {
        emitted_frames,
        retained_network,
    })
}

fn drive_mapped_prime_chain(
    setup: &crate::QemuHostPluginSetup,
    timeout: Duration,
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    prime_ceiling: u64,
    mut block: Option<&mut QemuLiveBlockIoServicer>,
    mut ninep: Option<&mut QemuLive9pIoServicer>,
    report_progress: bool,
) -> Result<Vec<crate::QemuNodeEmittedFrame>, QemuLiveNodeStepGateError> {
    let horizon = crucible::ExecutionHorizon {
        icount: Icount {
            retired: prime_ceiling,
        },
    };
    let mut pending = Some(
        QemuShmemHotPathChannel::start_quantum(hot_path, horizon)
            .map_err(|source| QemuLiveNodeStepGateError::prime("start priming quantum", source))?,
    );
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
        if let Some(servicer) = block.as_deref_mut() {
            servicer
                .service_fault_free_initialization(current)
                .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })?;
        }
        if let Some(servicer) = ninep.as_deref_mut() {
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
                eprintln!(
                    "crucible-live-network-io phase=retained-capture status=retry-progress icount={completed_current}"
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

/// Connects the typed QMP VMState channel while pulsing the plugin wake eventfd.
///
/// Right after the setup handshake the QEMU main loop parks with no host timeout
/// (the plugin holds time control and no ceiling is published), so it never
/// services the QMP `qmp_capabilities` command and a plain connect times out. A
/// short-lived primer thread pulses the plugin wake -- the same eventfd signal
/// the M1 scheduler raises each quantum -- to cycle the main loop until the
/// capabilities handshake completes. No ceiling is published, so the guest never
/// advances past the boot barrier while priming.
///
/// # Errors
///
/// Returns [`QmpError`] when the QMP capabilities handshake still cannot complete
/// (for example if QEMU never opens the socket or exits during priming).
pub(super) fn connect_qmp_priming_main_loop(
    setup: &crate::QemuHostPluginSetup,
    socket_path: &Path,
    command_timeout: Duration,
) -> Result<crate::QemuQmpVmStateControlChannel<UnixStream>, QmpError> {
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let primer = scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                // Transient wake failures are ignored: the QMP connect result is
                // the authority on whether the main loop became reachable.
                let _ = setup.signal_plugin_wake();
                thread::sleep(QMP_PRIMER_WAKE_INTERVAL);
            }
        });
        let result = crate::QemuQmpVmStateControlChannel::connect_unix_socket_with_policies(
            socket_path,
            crate::QmpJobPollPolicy::default(),
            crate::QmpIoTimeoutPolicy::from_command_timeout(command_timeout),
        );
        stop.store(true, Ordering::Relaxed);
        let _ = primer.join();
        result
    })
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
    run_directory: &Path,
    node_name: &str,
) -> Result<QemuLaunchPluginConfig, QemuLiveNodeStepGateError> {
    let plugin_base = live_node_plugin_base(config).with_fault_target_node(node_name);
    let mut plugin = if config.whitebox == QemuLaunchPluginSwitch::On {
        let probe_command = profile
            .qemu_launch_command_for_live_gate(
                vm.clone(),
                path_text(&config.qemu_executable),
                plugin_base.clone(),
                crate::LivePluginGuestArchitecture::X86_64,
            )
            .map_err(|source| QemuLiveNodeStepGateError::LaunchCommand { source })?;
        let validation = match config.architecture {
            LivePluginGuestArchitecture::X86_64 => {
                crate::probe_x86_whitebox_setup(&probe_command, run_directory)
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
    Ok(plugin)
}

fn live_node_plugin_base(config: &QemuLiveNodeStepGateConfig) -> QemuLaunchPluginConfig {
    QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT)
        .with_process_generation(config.process_generation)
        .with_network_tx_next_sequence(config.network_tx_next_sequence)
        .with_coverage(config.coverage)
        .with_fingerprint(config.fingerprint)
}

pub(super) const fn basic_block_coverage_config(
    coverage: QemuLaunchPluginSwitch,
) -> BasicBlockCoverageConfig {
    match coverage {
        QemuLaunchPluginSwitch::Off => BasicBlockCoverageConfig::off(),
        QemuLaunchPluginSwitch::On => BasicBlockCoverageConfig::on(),
    }
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

pub(super) fn launch_artifact(kind: &str, path: &Path) -> QemuLaunchArtifact {
    let path = path_text(path);
    QemuLaunchArtifact::new(
        crucible::ContentHash::from_canonical_material(GATE_DOMAIN, &format!("{kind}={path}")),
        path,
    )
}

pub(super) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(super) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

/// Send authorizer for the single-node run.
///
/// The gate has one VM and one router slot and never routes a real cross-node
/// frame, so authorization is unconditional.
pub(super) struct GateSendAuthorizer;

impl SchedulerSendAuthorizer for GateSendAuthorizer {
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}

#[cfg(test)]
#[path = "support/tests.rs"]
mod tests;
