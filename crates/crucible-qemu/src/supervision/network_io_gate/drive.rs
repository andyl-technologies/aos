//! Live QEMU launch, priming, and bounded network exchange drive.

use super::*;
use crate::supervision::bounded_scheduler_preemption::BoundedSchedulerPreemption as HostAdversary;

#[derive(Clone, Copy)]
struct BackpressureProbe {
    key: FrameDeliveryKey,
    delivery_attempts: u32,
    last_attempt_icount: u64,
}

#[path = "drive/prime.rs"]
mod prime;
#[path = "drive/retry.rs"]
mod retry;
use prime::{prime_guest_off_boot_barrier, wait_for_prime_ceiling};
use retry::observe_exact_backpressure_retry;

pub(super) fn run_once(
    config: &QemuLiveNetworkIoGateConfig,
    role: RunRole,
) -> Result<NetworkIoRunOutcome, QemuLiveNetworkIoGateError> {
    let run_directory = config.run_directory.join(role.directory());
    fs::create_dir_all(&run_directory).map_err(|source| {
        QemuLiveNetworkIoGateError::PrepareRunDirectory {
            path: run_directory.clone(),
            source,
        }
    })?;
    let mut candidate = LaunchProfileCandidate::default().with_memory_mib(GATE_MEMORY_MIB);
    if let Some(cmdline) = &config.kernel_cmdline {
        candidate = candidate.with_kernel_cmdline(cmdline.clone());
    }
    let profile = candidate
        .try_into_deterministic()
        .map_err(|source| QemuLiveNetworkIoGateError::LaunchProfile { source })?;
    profile
        .guest_entropy_seed_file()
        .write_to_dir(&run_directory)
        .map_err(|source| QemuLiveNetworkIoGateError::GuestEntropySeed {
            path: run_directory.clone(),
            source,
        })?;

    let qmp_config = QemuQmpChannelConfig::new(GATE_QMP_SOCKET_FILE_NAME)
        .map_err(|source| QemuLiveNetworkIoGateError::LaunchCommand { source })?;
    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT)
        .with_fault_target_node(GATE_NODE);
    let command = QemuLaunchCommandBuilder::new_for_live_gate(
        profile,
        vm_launch_config(config),
        path_text(&config.qemu_executable),
        plugin,
        crate::LivePluginGuestArchitecture::X86_64,
    )
    .with_qmp(qmp_config.clone())
    .build()
    .map_err(|source| QemuLiveNetworkIoGateError::LaunchCommand { source })?;

    let region_config = RegionConfig::new(1, GATE_QUEUE_CAPACITY, 0);
    let allocation = RegionAllocation::new(region_config)
        .map_err(|source| QemuLiveNetworkIoGateError::RegionLayout { source })?;
    let spawned = spawn_qemu_child_with_fds_in_directory(
        &command,
        &run_directory,
        allocation.layout().region_size,
    )
    .map_err(|source| QemuLiveNetworkIoGateError::Spawn { source })?;
    let (mut child, resources) = spawned.into_parts();
    let mut setup = complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        region_config,
        GATE_SLOT,
        command.fault_capability_requirement(),
    )
    .map_err(|source| QemuLiveNetworkIoGateError::HostSetup { source })?;
    if !setup.setup_ack().can_schedule() {
        return Err(QemuLiveNetworkIoGateError::SetupAckNotReady);
    }

    let mut servicer = QemuLiveNetworkIoServicer::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
    )
    .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLiveNetworkIoGateError::DriveRegionMap { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32);
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, GateSendAuthorizer)
        .map_err(|source| QemuLiveNetworkIoGateError::DriveHotPath { source })?;

    let backpressure_probe = prime_guest_off_boot_barrier(
        &mut hot_path,
        &mut servicer,
        &setup,
        &mut child,
        config.completion_timeout,
    )?;
    let qmp = connect_qmp_priming_main_loop(&setup, &qmp_config.socket_path(&run_directory))
        .map_err(|source| QemuLiveNetworkIoGateError::QmpConnect { source })?;
    let mut qmp = qmp.into_inner();
    let status = qmp
        .query_status()
        .map_err(|source| QemuLiveNetworkIoGateError::QmpConnect { source })?;
    if !status.running {
        return Err(QemuLiveNetworkIoGateError::QmpNotRunning {
            status: format!("{:?}", status.status),
        });
    }

    // Start only after identical launch/setup and guest progress past the boot
    // barrier, then run concurrently with the retained retry and probe/reply/ACK
    // exchange. Six short stop/continue pairs perturb the exact QEMU process;
    // unlike CPU burners, the adversary consumes no synthetic CPU and owns an
    // independent two-second resume watchdog.
    let mut scheduler_preemption = HostAdversary::start_if(
        matches!(role, RunRole::Hostile) && config.second_run_scheduler_preemption,
        child.process_id(),
    )
    .map_err(|source| QemuLiveNetworkIoGateError::SchedulerPreemption { source })?;
    let DriveExchangeOutcome {
        acknowledgement_icount,
        backpressure_acknowledgement_icount,
        backpressure_retry_icount,
        delayed_reply_applied,
        scheduler_preemption_pending_quantum,
        completion_owned_frames,
    } = drive_exchange(
        &mut hot_path,
        &mut servicer,
        &setup,
        &mut child,
        DriveExchangeOptions {
            ceiling: config.busy_ceiling_icount,
            timeout: config.completion_timeout,
            reply_wall_delay: role.delay(),
            backpressure_probe,
        },
        &mut scheduler_preemption,
    )?;
    let scheduler_preemption = HostAdversary::finish_if_present(&mut scheduler_preemption)
        .map_err(|source| QemuLiveNetworkIoGateError::SchedulerPreemption { source })?;
    let snapshot = servicer.snapshot();

    let _ = QemuPluginIpcControlChannel::send_quit(&mut setup);
    let orderly_child_exit = reap_child(&mut child, config.completion_timeout);
    drop(hot_path);
    drop(setup);
    drop(child);

    Ok(NetworkIoRunOutcome {
        snapshot,
        acknowledgement_icount,
        boot_backpressure_retained: true,
        canonical_backpressure_retry_delivered: true,
        backpressure_acknowledgement_icount,
        backpressure_delivery_attempts: backpressure_probe.delivery_attempts,
        backpressure_last_attempt_icount: backpressure_probe.last_attempt_icount,
        backpressure_retry_icount,
        delayed_reply_applied,
        orderly_child_exit,
        scheduler_preemption,
        scheduler_preemption_pending_quantum,
        completion_owned_frames,
    })
}

#[derive(Clone, Copy)]
struct DriveExchangeOptions {
    ceiling: u64,
    timeout: Duration,
    reply_wall_delay: Duration,
    backpressure_probe: BackpressureProbe,
}

struct DriveExchangeOutcome {
    acknowledgement_icount: Option<u64>,
    backpressure_acknowledgement_icount: Option<u64>,
    backpressure_retry_icount: Option<u64>,
    delayed_reply_applied: bool,
    scheduler_preemption_pending_quantum: bool,
    completion_owned_frames: usize,
}

/// Finishes one scheduler quantum and transfers every completion-owned guest
/// frame into the sole deterministic router observation path.
///
/// `finish_quantum` drains the guest-to-router SPSC ring. Ignoring the returned
/// frames would silently discard traffic at exactly the completion boundary,
/// so every live-network completion goes through this helper.
fn finish_and_service_network_quantum(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLiveNetworkIoServicer,
    pending: QemuNodePendingQuantum,
    operation: &'static str,
) -> Result<(), QemuLiveNetworkIoGateError> {
    let report = QemuShmemHotPathChannel::finish_quantum(hot_path, pending)
        .map_err(|source| QemuLiveNetworkIoGateError::drive(operation, source))?;
    servicer
        .service_completed_frames_with_before_reply(report.emitted_frames, || {})
        .map(|_step| ())
        .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })
}

fn drive_exchange(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLiveNetworkIoServicer,
    setup: &QemuHostPluginSetup,
    child: &mut QemuNodeChild,
    options: DriveExchangeOptions,
    host_adversary: &mut Option<HostAdversary>,
) -> Result<DriveExchangeOutcome, QemuLiveNetworkIoGateError> {
    let DriveExchangeOptions {
        ceiling,
        timeout,
        reply_wall_delay,
        backpressure_probe,
    } = options;
    let backpressure_retry_icount = Some(observe_exact_backpressure_retry(
        hot_path,
        servicer,
        setup,
        child,
        timeout,
        backpressure_probe,
    )?);
    let mut discovery_pending = Some(
        QemuShmemHotPathChannel::start_quantum(
            hot_path,
            crucible::ExecutionHorizon {
                icount: Icount {
                    retired: PROBE_DISCOVERY_CEILING_ICOUNT,
                },
            },
        )
        .map_err(|source| {
            QemuLiveNetworkIoGateError::drive("start probe-discovery quantum", source)
        })?,
    );
    setup.signal_plugin_wake().map_err(|source| {
        QemuLiveNetworkIoGateError::drive("wake pending network quantum", source)
    })?;
    let pending = discovery_pending.as_mut().ok_or_else(|| {
        QemuLiveNetworkIoGateError::ProbeDiscoveryDidNotPark {
            evidence: String::from("probe-discovery token absent before first stop"),
        }
    })?;
    let scheduler_preemption_pending_quantum =
        HostAdversary::certify_mapped_quantum_pending(host_adversary, hot_path, pending)
            .map_err(|source| QemuLiveNetworkIoGateError::SchedulerPreemption { source })?;
    let mut acknowledgement_icount = None;
    let mut backpressure_acknowledgement_icount = None;
    let mut delay_applied = false;
    let mut discovery_complete = false;
    let mut completion_owned_frames = 0_usize;
    let mut discovery_budget = DrivePollBudget::new(timeout);
    while discovery_budget.begin_attempt() {
        let _ = setup.signal_plugin_wake();
        if completion_owned_frames > 0 {
            let should_delay = !delay_applied && !reply_wall_delay.is_zero();
            let mut delayed_this_call = false;
            let step = servicer
                .service_with_before_reply(|| {
                    if should_delay {
                        thread::park_timeout(reply_wall_delay);
                        delayed_this_call = true;
                    }
                })
                .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
            if step.reply_enqueued && delayed_this_call {
                delay_applied = true;
            }
        }
        let service_snapshot = servicer.snapshot();
        if backpressure_acknowledgement_icount.is_none() {
            backpressure_acknowledgement_icount = service_snapshot
                .tx_frames
                .iter()
                .find(|frame| is_live_network_backpressure_ack(&frame.payload))
                .map(|frame| frame.emit_icount);
        }
        let node_snapshot = servicer
            .vm_node_snapshot()
            .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
        if service_snapshot.reply_delivery_icount.is_some()
            && backpressure_acknowledgement_icount.is_some()
            && node_snapshot.status == STATUS_IDLE
            && node_snapshot.idle_wake_icount > PROBE_DISCOVERY_CEILING_ICOUNT
        {
            discovery_complete = true;
            break;
        }
        if discovery_quantum_report_ready(
            node_snapshot.status,
            node_snapshot.current_icount,
            PROBE_DISCOVERY_CEILING_ICOUNT,
        ) {
            let completed = discovery_pending.as_mut().ok_or_else(|| {
                QemuLiveNetworkIoGateError::ProbeDiscoveryDidNotPark {
                    evidence: String::from("probe-discovery quantum token was already consumed"),
                }
            })?;
            let completion = match QemuShmemHotPathChannel::poll_quantum(hot_path, completed) {
                Ok(completion) => completion,
                Err(source) if source.retryable => continue,
                Err(source) => {
                    return Err(QemuLiveNetworkIoGateError::drive(
                        "poll retained-retry discovery quantum",
                        source,
                    ));
                }
            };
            let owned_frames = completion.emitted_frames.len();
            if owned_frames == 0 {
                drop(discovery_pending.take());
                discovery_pending = Some(
                    QemuShmemHotPathChannel::start_quantum(
                        hot_path,
                        crucible::ExecutionHorizon {
                            icount: Icount {
                                retired: PROBE_DISCOVERY_CEILING_ICOUNT,
                            },
                        },
                    )
                    .map_err(|source| {
                        QemuLiveNetworkIoGateError::drive(
                            "reissue empty probe-discovery quantum",
                            source,
                        )
                    })?,
                );
                continue;
            }
            completion_owned_frames = completion_owned_frames.saturating_add(owned_frames);
            let should_delay = !delay_applied && !reply_wall_delay.is_zero();
            let mut delayed_completion = false;
            let completion_step = servicer
                .service_completed_frames_with_before_reply(completion.emitted_frames, || {
                    if should_delay {
                        thread::park_timeout(reply_wall_delay);
                        delayed_completion = true;
                    }
                })
                .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
            if completion_step.reply_enqueued && delayed_completion {
                delay_applied = true;
            }
            let completed_snapshot = servicer.snapshot();
            if backpressure_acknowledgement_icount.is_none() {
                backpressure_acknowledgement_icount = completed_snapshot
                    .tx_frames
                    .iter()
                    .find(|frame| is_live_network_backpressure_ack(&frame.payload))
                    .map(|frame| frame.emit_icount);
            }
            if completed_snapshot.reply_delivery_icount.is_some()
                && backpressure_acknowledgement_icount.is_some()
                && node_snapshot.idle_wake_icount > PROBE_DISCOVERY_CEILING_ICOUNT
            {
                discovery_complete = true;
                break;
            }
            if node_snapshot.idle_wake_icount > PROBE_DISCOVERY_CEILING_ICOUNT {
                return Err(QemuLiveNetworkIoGateError::ProbeDiscoveryDidNotPark {
                    evidence: format!(
                        "completed probe-discovery quantum without required guest frames: network={completed_snapshot:?}; node={node_snapshot:?}"
                    ),
                });
            }
            drop(discovery_pending.take());
            discovery_pending = Some(
                QemuShmemHotPathChannel::start_quantum(
                    hot_path,
                    crucible::ExecutionHorizon {
                        icount: Icount {
                            retired: PROBE_DISCOVERY_CEILING_ICOUNT,
                        },
                    },
                )
                .map_err(|source| {
                    QemuLiveNetworkIoGateError::drive(
                        "reissue retained-retry discovery quantum",
                        source,
                    )
                })?,
            );
            continue;
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| QemuLiveNetworkIoGateError::ChildWait { source })?
        {
            return Err(QemuLiveNetworkIoGateError::ChildExited {
                status: status.to_string(),
            });
        }
        discovery_budget.park();
    }
    if !discovery_complete {
        let node_evidence = servicer.vm_node_snapshot().map_or_else(
            |error| format!("node_snapshot_error={error}"),
            |node| format!("{node:?}"),
        );
        return Err(QemuLiveNetworkIoGateError::ProbeDiscoveryDidNotPark {
            evidence: format!("network={:?}; node={node_evidence}", servicer.snapshot()),
        });
    }
    let discovery_pending =
        discovery_pending.ok_or_else(|| QemuLiveNetworkIoGateError::ProbeDiscoveryDidNotPark {
            evidence: String::from("probe-discovery quantum token is absent at completion"),
        })?;
    finish_and_service_network_quantum(
        hot_path,
        servicer,
        discovery_pending,
        "finish probe-discovery quantum",
    )?;
    let checkpoint =
        QemuShmemHotPathChannel::checkpoint_network_transport(hot_path).map_err(|source| {
            QemuLiveNetworkIoGateError::drive("inspect backpressure retry", source)
        })?;
    if checkpoint
        .inbound
        .frames
        .iter()
        .any(|frame| frame.delivery_key() == backpressure_probe.key)
    {
        return Err(QemuLiveNetworkIoGateError::BackpressureRetryDidNotDeliver {
            frame: backpressure_probe.key,
        });
    }
    if backpressure_acknowledgement_icount.is_none() {
        return Err(
            QemuLiveNetworkIoGateError::BackpressureAcknowledgementDidNotArrive {
                frame: backpressure_probe.key,
                evidence: format!("{:?}", servicer.snapshot()),
            },
        );
    }
    let reply_delivery_icount = servicer.snapshot().reply_delivery_icount.ok_or_else(|| {
        QemuLiveNetworkIoGateError::ProbeDiscoveryDidNotPark {
            evidence: String::from("discovery completed without a reply stamp"),
        }
    })?;
    if reply_delivery_icount <= PROBE_DISCOVERY_CEILING_ICOUNT {
        return Err(QemuLiveNetworkIoGateError::ReplyOutsideDiscoveryWindow {
            discovery_ceiling_icount: PROBE_DISCOVERY_CEILING_ICOUNT,
            reply_delivery_icount,
        });
    }

    servicer
        .authorize_guest_ceiling(reply_delivery_icount)
        .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
    let mut reply_reached = false;
    let mut reply_budget = DrivePollBudget::new(timeout);
    while reply_budget.begin_attempt() {
        let node_snapshot = servicer
            .vm_node_snapshot()
            .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
        if node_snapshot.current_icount >= reply_delivery_icount {
            reply_reached = true;
            break;
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| QemuLiveNetworkIoGateError::ChildWait { source })?
        {
            return Err(QemuLiveNetworkIoGateError::ChildExited {
                status: status.to_string(),
            });
        }
        reply_budget.park();
    }
    if !reply_reached {
        return Err(QemuLiveNetworkIoGateError::ReplyDeliveryDidNotReach {
            reply_delivery_icount,
            evidence: format!("{:?}", servicer.vm_node_snapshot()),
        });
    }
    servicer
        .authorize_guest_ceiling(ceiling)
        .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
    setup
        .signal_plugin_wake()
        .map_err(|source| QemuLiveNetworkIoGateError::drive("wake post-reply guest", source))?;

    let mut acknowledgement_budget = DrivePollBudget::new(timeout);
    while acknowledgement_budget.begin_attempt() {
        let _ = setup.signal_plugin_wake();
        let step = servicer
            .service()
            .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
        let service_snapshot = servicer.snapshot();
        if step.acknowledgement_seen || service_snapshot.acknowledgement_seen {
            acknowledgement_icount = service_snapshot
                .tx_frames
                .iter()
                .rev()
                .find(|frame| is_live_network_ack(&frame.payload))
                .map(|frame| frame.emit_icount);
            break;
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| QemuLiveNetworkIoGateError::ChildWait { source })?
        {
            return Err(QemuLiveNetworkIoGateError::ChildExited {
                status: status.to_string(),
            });
        }
        acknowledgement_budget.park();
    }
    if acknowledgement_icount.is_none() {
        return Err(QemuLiveNetworkIoGateError::AcknowledgementDidNotArrive {
            evidence: format!(
                "network={:?}; node={:?}",
                servicer.snapshot(),
                servicer.vm_node_snapshot()
            ),
        });
    }
    Ok(DriveExchangeOutcome {
        acknowledgement_icount,
        backpressure_acknowledgement_icount,
        backpressure_retry_icount,
        delayed_reply_applied: delay_applied,
        scheduler_preemption_pending_quantum,
        completion_owned_frames,
    })
}

pub(super) fn discovery_quantum_report_ready(
    status: u8,
    current_icount: u64,
    discovery_ceiling: u64,
) -> bool {
    status == STATUS_IDLE && current_icount <= discovery_ceiling
}
