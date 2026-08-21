//! Live QEMU launch, priming, and bounded network exchange drive.

use super::*;

#[path = "drive/retry.rs"]
mod retry;
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

    // Apply hostile load to the network workload itself, after both runs have
    // completed identical launch, plugin setup, and boot-barrier priming.
    // Otherwise host scheduling noise during control-plane setup can move the
    // workload's origin even though every modeled network interval is exact.
    let host_load =
        HostLoad::start_if(matches!(role, RunRole::Hostile) && config.second_run_host_load);
    let DriveExchangeOutcome {
        acknowledgement_icount,
        backpressure_acknowledgement_icount,
        backpressure_retry_icount,
        delayed_reply_applied,
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
    )?;
    let snapshot = servicer.snapshot();

    let _ = QemuPluginIpcControlChannel::send_quit(&mut setup);
    let orderly_child_exit = reap_child(&mut child, config.completion_timeout);
    drop(hot_path);
    drop(setup);
    drop(child);
    drop(host_load);

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
    })
}

fn prime_guest_off_boot_barrier(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLiveNetworkIoServicer,
    setup: &QemuHostPluginSetup,
    child: &mut QemuNodeChild,
    timeout: Duration,
) -> Result<BackpressureProbe, QemuLiveNetworkIoGateError> {
    let backpressure_payload = QemuLiveNetworkIoServicer::boot_backpressure_probe();
    QemuShmemHotPathChannel::deliver_frame_at(
        hot_path,
        BackendInput {
            node: node_id(GATE_NODE),
            payload: backpressure_payload.clone(),
        },
        Icount {
            retired: BACKPRESSURE_PROBE_CEILING_ICOUNT,
        },
    )
    .map_err(|source| {
        QemuLiveNetworkIoGateError::drive("publish exact backpressure frame", source)
    })?;
    let published = QemuShmemHotPathChannel::checkpoint_network_transport(hot_path)
        .map_err(|source| QemuLiveNetworkIoGateError::drive("inspect pending frame", source))?;
    let backpressure_probe = published
        .inbound
        .frames
        .iter()
        .find(|frame| {
            frame.delivery_icount == BACKPRESSURE_PROBE_CEILING_ICOUNT
                && frame
                    .payload()
                    .is_ok_and(|payload| payload == backpressure_payload)
                && frame
                    .delivery_state()
                    .is_ok_and(|state| state == FrameDeliveryState::Pending)
        })
        .map(crucible_shmem::SnapshotFrameEntry::delivery_key)
        .ok_or_else(|| QemuLiveNetworkIoGateError::BootBackpressureNotRetained {
            evidence: format!(
                "canonical pending publication missing: {:?}",
                published.inbound.frames
            ),
        })?;
    servicer
        .observe_router_publication(backpressure_probe)
        .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
    let backpressure_pending = QemuShmemHotPathChannel::start_quantum(
        hot_path,
        crucible::ExecutionHorizon {
            icount: Icount {
                retired: BACKPRESSURE_PROBE_CEILING_ICOUNT,
            },
        },
    )
    .map_err(|source| QemuLiveNetworkIoGateError::drive("start backpressure quantum", source))?;
    setup
        .signal_plugin_wake()
        .map_err(|source| QemuLiveNetworkIoGateError::drive("wake backpressure quantum", source))?;
    wait_for_prime_ceiling(servicer, child, timeout, BACKPRESSURE_PROBE_CEILING_ICOUNT)?;
    QemuShmemHotPathChannel::finish_quantum(hot_path, backpressure_pending).map_err(|source| {
        QemuLiveNetworkIoGateError::drive("finish backpressure quantum", source)
    })?;
    let checkpoint = QemuShmemHotPathChannel::checkpoint_network_transport(hot_path)
        .map_err(|source| QemuLiveNetworkIoGateError::drive("inspect retained frame", source))?;
    let retained = checkpoint
        .inbound
        .frames
        .first()
        .filter(|frame| frame.delivery_key() == backpressure_probe)
        .filter(|frame| {
            frame
                .delivery_state()
                .is_ok_and(|state| state == FrameDeliveryState::Retained)
                && frame.delivery_attempts() > 0
                && frame.last_delivery_attempt_icount() == BACKPRESSURE_PROBE_CEILING_ICOUNT
        });
    let Some(retained) = retained else {
        return Err(QemuLiveNetworkIoGateError::BootBackpressureNotRetained {
            evidence: format!("{:?}", checkpoint.inbound.frames),
        });
    };
    let retained = BackpressureProbe {
        key: backpressure_probe,
        delivery_attempts: retained.delivery_attempts(),
        last_attempt_icount: retained.last_delivery_attempt_icount(),
    };

    let pending = QemuShmemHotPathChannel::start_quantum(
        hot_path,
        crucible::ExecutionHorizon {
            icount: Icount {
                retired: PRIME_CEILING_ICOUNT,
            },
        },
    )
    .map_err(|source| QemuLiveNetworkIoGateError::drive("start priming quantum", source))?;
    setup
        .signal_plugin_wake()
        .map_err(|source| QemuLiveNetworkIoGateError::drive("wake priming quantum", source))?;
    wait_for_prime_ceiling(servicer, child, timeout, PRIME_CEILING_ICOUNT)?;
    QemuShmemHotPathChannel::finish_quantum(hot_path, pending)
        .map_err(|source| QemuLiveNetworkIoGateError::drive("finish priming quantum", source))?;
    Ok(retained)
}

fn wait_for_prime_ceiling(
    servicer: &QemuLiveNetworkIoServicer,
    child: &mut QemuNodeChild,
    timeout: Duration,
    ceiling: u64,
) -> Result<(), QemuLiveNetworkIoGateError> {
    for _ in 0..bounded_drive_polls(timeout) {
        let snapshot = servicer
            .vm_node_snapshot()
            .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
        if snapshot.current_icount >= ceiling {
            return Ok(());
        }
        if child
            .try_wait_natural_exit()
            .map_err(|source| QemuLiveNetworkIoGateError::ChildWait { source })?
            .is_some()
        {
            break;
        }
        thread::park_timeout(DRIVE_POLL_INTERVAL);
    }
    let evidence = servicer.vm_node_snapshot().map_or_else(
        |error| format!("node_snapshot_error={error}"),
        |snapshot| format!("{snapshot:?}"),
    );
    Err(QemuLiveNetworkIoGateError::PrimeDidNotReach { ceiling, evidence })
}

#[derive(Clone, Copy)]
struct DriveExchangeOptions {
    ceiling: u64,
    timeout: Duration,
    reply_wall_delay: Duration,
    backpressure_probe: BackpressureProbe,
}

#[derive(Clone, Copy)]
struct BackpressureProbe {
    key: FrameDeliveryKey,
    delivery_attempts: u32,
    last_attempt_icount: u64,
}

struct DriveExchangeOutcome {
    acknowledgement_icount: Option<u64>,
    backpressure_acknowledgement_icount: Option<u64>,
    backpressure_retry_icount: Option<u64>,
    delayed_reply_applied: bool,
}

fn drive_exchange(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLiveNetworkIoServicer,
    setup: &QemuHostPluginSetup,
    child: &mut QemuNodeChild,
    options: DriveExchangeOptions,
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
    let discovery_pending = QemuShmemHotPathChannel::start_quantum(
        hot_path,
        crucible::ExecutionHorizon {
            icount: Icount {
                retired: PROBE_DISCOVERY_CEILING_ICOUNT,
            },
        },
    )
    .map_err(|source| QemuLiveNetworkIoGateError::drive("start probe-discovery quantum", source))?;
    let mut acknowledgement_icount = None;
    let mut backpressure_acknowledgement_icount = None;
    let mut delay_applied = false;
    let mut discovery_complete = false;
    for _ in 0..bounded_drive_polls(timeout) {
        let _ = setup.signal_plugin_wake();
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
        let service_snapshot = servicer.snapshot();
        if backpressure_acknowledgement_icount.is_none() {
            backpressure_acknowledgement_icount = service_snapshot
                .tx_frames
                .iter()
                .find(|frame| {
                    frame
                        .payload
                        .windows(LIVE_NETWORK_BACKPRESSURE_ACK_PAYLOAD.len())
                        .any(|window| window == LIVE_NETWORK_BACKPRESSURE_ACK_PAYLOAD)
                })
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
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| QemuLiveNetworkIoGateError::ChildWait { source })?
        {
            return Err(QemuLiveNetworkIoGateError::ChildExited {
                status: status.to_string(),
            });
        }
        thread::park_timeout(DRIVE_POLL_INTERVAL);
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
    QemuShmemHotPathChannel::finish_quantum(hot_path, discovery_pending).map_err(|source| {
        QemuLiveNetworkIoGateError::drive("finish probe-discovery quantum", source)
    })?;
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
    for _ in 0..bounded_drive_polls(timeout) {
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
        thread::park_timeout(DRIVE_POLL_INTERVAL);
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

    for _ in 0..bounded_drive_polls(timeout) {
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
                .find(|frame| {
                    frame
                        .payload
                        .windows(LIVE_NETWORK_ACK_PAYLOAD.len())
                        .any(|window| window == LIVE_NETWORK_ACK_PAYLOAD)
                })
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
        thread::park_timeout(DRIVE_POLL_INTERVAL);
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
    })
}
