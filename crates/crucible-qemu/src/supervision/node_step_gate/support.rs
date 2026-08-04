//! Busy-window driving, launch, priming, and host-load support.

use super::*;

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
) -> Result<Vec<QemuLiveNodeStepQuantum>, QemuLiveNodeStepGateError> {
    let mut quanta = Vec::with_capacity(ceilings.len());
    for &ceiling in ceilings {
        let quantum = advance_to_busy_ceiling(node, ceiling)?;
        quanta.push(quantum);
    }
    Ok(quanta)
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
        let outcome = node
            .advance_to_ceiling(Icount { retired: ceiling })
            .map_err(|source| QemuLiveNodeStepGateError::node_op("advance to ceiling", source))?;
        let current = node
            .current_icount()
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op("read post-advance icount", source)
            })?
            .retired;

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
                reissue_count,
            });
        }
        last_icount = current;
        reissue_count += 1;
    }
}

/// Requires the load run to reproduce the reference run byte for byte.
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
pub(super) fn prime_guest_off_boot_barrier(
    setup: &crate::QemuHostPluginSetup,
    timeout: Duration,
    node_name: &str,
    router_name: &str,
    coverage: QemuLaunchPluginSwitch,
) -> Result<Vec<crate::QemuNodeEmittedFrame>, QemuLiveNodeStepGateError> {
    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLiveNodeStepGateError::PrimeRegionMap { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(node_name), GATE_SLOT)
        .with_router(node_id(router_name), SLOT_NET_ROUTER as u32)
        .with_coverage(basic_block_coverage_config(coverage));
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, GateSendAuthorizer)
        .map_err(|source| QemuLiveNodeStepGateError::PrimeHotPath { source })?;

    let horizon = crucible::ExecutionHorizon {
        icount: Icount {
            retired: PRIME_CEILING_ICOUNT,
        },
    };
    let pending = QemuShmemHotPathChannel::start_quantum(&mut hot_path, horizon)
        .map_err(|source| QemuLiveNodeStepGateError::prime("start priming quantum", source))?;

    let max_polls = bounded_prime_polls(timeout);
    let mut reached = false;
    for _ in 0..max_polls {
        setup
            .signal_plugin_wake()
            .map_err(|source| QemuLiveNodeStepGateError::prime("wake priming guest", source))?;
        let current = QemuShmemHotPathChannel::current_icount(&mut hot_path)
            .map_err(|source| QemuLiveNodeStepGateError::prime("poll priming icount", source))?
            .retired;
        if current >= PRIME_CEILING_ICOUNT {
            reached = true;
            break;
        }
        thread::sleep(PRIME_POLL_INTERVAL);
    }

    if !reached {
        return Err(QemuLiveNodeStepGateError::PrimeStalled {
            ceiling_icount: PRIME_CEILING_ICOUNT,
        });
    }
    let completion = QemuShmemHotPathChannel::finish_quantum(&mut hot_path, pending)
        .map_err(|source| QemuLiveNodeStepGateError::prime("finish priming quantum", source))?;
    QemuShmemHotPathChannel::drain_observable_events(&mut hot_path)
        .map_err(|source| QemuLiveNodeStepGateError::prime("drain priming observations", source))?;
    QemuShmemHotPathChannel::drain_causal_decisions(&mut hot_path)
        .map_err(|source| QemuLiveNodeStepGateError::prime("drain priming decisions", source))?;
    Ok(completion.emitted_frames)
}

/// Returns the number of priming polls that fit within `timeout`, at least one.
pub(super) fn bounded_prime_polls(timeout: Duration) -> u64 {
    let interval = PRIME_POLL_INTERVAL.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
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
        let result = crate::QemuQmpVmStateControlChannel::connect_unix_socket(socket_path);
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
    let vm = match &config.root_image {
        Some(root_image) => {
            QemuVmLaunchConfig::new(node_name, kernel, launch_artifact("root-image", root_image))
                .with_root_image_format(config.root_image_format)
        }
        None => QemuVmLaunchConfig::new_diskless(
            node_name,
            kernel,
            launch_artifact("firmware", &config.firmware),
        ),
    };
    let vm = match &config.initrd {
        Some(initrd) => vm.with_initrd(launch_artifact("initrd", initrd)),
        None => vm,
    };
    match &config.shmem_network_mac {
        Some(mac) => {
            vm.with_crucible_shmem_network(CrucibleShmemNetworkDevice::new().with_mac(mac.clone()))
        }
        None => vm,
    }
}

pub(super) fn live_node_plugin_config(
    config: &QemuLiveNodeStepGateConfig,
    profile: &crate::DeterministicLaunchProfile,
    vm: &QemuVmLaunchConfig,
    run_directory: &Path,
) -> Result<QemuLaunchPluginConfig, QemuLiveNodeStepGateError> {
    let plugin_base = live_node_plugin_base(config);
    let mut plugin = if config.whitebox == QemuLaunchPluginSwitch::On {
        let probe_command = profile
            .qemu_launch_command(
                vm.clone(),
                path_text(&config.qemu_executable),
                plugin_base.clone(),
            )
            .map_err(|source| QemuLiveNodeStepGateError::LaunchCommand { source })?;
        let validation = crate::probe_x86_whitebox_setup(&probe_command, run_directory)
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
    QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT).with_coverage(config.coverage)
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

/// Returns an async-driver policy whose advance budget is the per-step timeout.
pub(super) fn gate_async_policy(completion_timeout: Duration) -> QemuAsyncDriverPolicy {
    QemuAsyncDriverPolicy::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
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

/// A background host-CPU load generator that stresses scheduling around a run.
///
/// The busy threads consume CPU without touching the guest, the plugin, or the
/// shared-memory region, so a deterministic, icount-owning node must produce an
/// identical fingerprint whether or not the load is present.
pub(super) struct HostLoad {
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl HostLoad {
    pub(super) fn start_if(enabled: bool) -> Option<Self> {
        if !enabled {
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(HOST_LOAD_WORKERS);
        for _ in 0..HOST_LOAD_WORKERS {
            let stop = Arc::clone(&stop);
            workers.push(thread::spawn(move || {
                let mut accumulator: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    for value in 0..4096_u64 {
                        accumulator = accumulator
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(value);
                    }
                    std::hint::black_box(accumulator);
                }
            }));
        }
        Some(Self { stop, workers })
    }
}

impl Drop for HostLoad {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
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
mod tests {
    use super::*;

    #[test]
    fn root_image_launch_material_does_not_fall_back_to_firmware() {
        let config = QemuLiveNodeStepGateConfig::new_with_root_image(
            "/aos/bin/qemu-system-x86_64",
            "/aos/lib/crucible-plugin.so",
            "/aos/kernel",
            "/aos/root.raw",
            "/run/crucible",
        )
        .with_root_image_format(QemuRootImageFormat::Raw);

        let material = vm_launch_config(&config, "vm-a").launch_hash_material();

        assert!(material.contains("root_image_format=raw"));
        assert!(material.contains("/aos/root.raw"));
        assert!(!material.contains("firmware"));
    }

    #[test]
    fn diskless_launch_material_retains_firmware() {
        let config = QemuLiveNodeStepGateConfig::new(
            "/aos/bin/qemu-system-x86_64",
            "/aos/lib/crucible-plugin.so",
            "/aos/kernel",
            "/aos/firmware",
            "/run/crucible",
        );

        let material = vm_launch_config(&config, "vm-a").launch_hash_material();

        assert!(material.contains("/aos/firmware"));
        assert!(!material.contains("root_image="));
    }

    #[test]
    fn coverage_switch_reaches_plugin_and_host_drain_configuration() {
        let config = QemuLiveNodeStepGateConfig::new_with_root_image(
            "/aos/bin/qemu-system-x86_64",
            "/aos/lib/crucible-plugin.so",
            "/aos/kernel",
            "/aos/root.raw",
            "/run/crucible",
        )
        .with_coverage(QemuLaunchPluginSwitch::On);

        assert_eq!(
            live_node_plugin_base(&config).coverage(),
            QemuLaunchPluginSwitch::On
        );
        assert_eq!(
            basic_block_coverage_config(config.coverage),
            BasicBlockCoverageConfig::on()
        );
    }
}
