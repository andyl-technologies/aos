//! Certifying live guest-network gate over the Crucible shared-memory rings.
//!
//! A diskless Linux guest originates a raw Ethernet probe through virtio-net.
//! The patched QEMU TX callback forwards the exact bytes to the loaded plugin,
//! the host router schedules one reply at a fixed icount offset, and the plugin
//! injects it through QEMU's lossless RX queue. The guest proves receipt by
//! emitting an acknowledgement frame. A hostile-host rerun adds CPU load; the
//! router latency plus protocol frame bytes, order, and sequence must remain
//! identical. Raw probe and acknowledgement stamps remain visible separately
//! because whole-guest trajectory belongs to the independent loaded-QEMU
//! determinism gates.

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

pub use self::error::QemuLiveNetworkIoGateError;
use self::support::{
    GateSendAuthorizer, HostLoad, acknowledgement_offset_icount, bounded_drive_polls, certify_run,
    connect_qmp_priming_main_loop, deterministic_projection, node_id, path_text, probe_emit_icount,
    reap_child, vm_launch_config,
};
use super::network_io_servicer::{
    LIVE_NETWORK_ACK_PAYLOAD, LIVE_NETWORK_PROBE_PAYLOAD, LIVE_NETWORK_REPLY_LATENCY_ICOUNT,
    LiveNetworkIoSnapshot, QemuLiveNetworkIoServicer, QemuLiveNetworkIoServicerError,
};
use crate::{
    LaunchProfileCandidate, QemuHostPluginSetup, QemuLaunchCommandBuilder, QemuLaunchPluginConfig,
    QemuMappedQuantumShmemHotPath, QemuNodeChild, QemuPluginIpcControlChannel,
    QemuQmpChannelConfig, QemuQuantumShmemConfig, QemuShmemHotPathChannel,
    complete_qemu_host_plugin_setup, spawn_qemu_child_with_fds_in_directory,
};
use crucible::Icount;
use crucible_shmem::{
    RegionAllocation, RegionConfig, SLOT_NET_ROUTER, STATUS_IDLE, mmap_setup_region,
};

mod error;
mod support;

const GATE_DOMAIN: &str = "crucible.loaded-qemu-live-network-io.v1";
const GATE_NODE: &str = "live-network-io-vm";
const GATE_ROUTER: &str = "live-network-io-router";
const GATE_SLOT: u32 = 0;
const GATE_QUEUE_CAPACITY: u32 = 64;
const GATE_QMP_SOCKET_FILE_NAME: &str = "crucible-live-network-io-qmp.sock";
const GATE_MEMORY_MIB: u32 = 128;
const HOST_LOAD_WORKERS: usize = 4;
const DRIVE_POLL_INTERVAL: Duration = Duration::from_millis(1);
const PRIME_CEILING_ICOUNT: u64 = 1_000_000;
const PROBE_DISCOVERY_CEILING_ICOUNT: u64 = 2_820_000_000;
const QMP_PRIMER_WAKE_INTERVAL: Duration = Duration::from_millis(10);
const DEFAULT_BUSY_CEILING_ICOUNT: u64 = 3_200_000_000;

/// Inputs for the live network-I/O certification.
#[derive(Clone, Debug)]
pub struct QemuLiveNetworkIoGateConfig {
    qemu_executable: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    firmware: PathBuf,
    initrd: PathBuf,
    run_directory: PathBuf,
    kernel_cmdline: Option<String>,
    busy_ceiling_icount: u64,
    completion_timeout: Duration,
    second_run_host_load: bool,
}

impl QemuLiveNetworkIoGateConfig {
    /// Builds a live network gate configuration with bounded defaults.
    #[must_use]
    pub fn new(
        qemu_executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        firmware: impl Into<PathBuf>,
        initrd: impl Into<PathBuf>,
        run_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            qemu_executable: qemu_executable.into(),
            plugin: plugin.into(),
            kernel: kernel.into(),
            firmware: firmware.into(),
            initrd: initrd.into(),
            run_directory: run_directory.into(),
            kernel_cmdline: None,
            busy_ceiling_icount: DEFAULT_BUSY_CEILING_ICOUNT,
            completion_timeout: Duration::from_secs(60),
            second_run_host_load: true,
        }
    }

    /// Returns this configuration with an explicit kernel command line.
    #[must_use]
    pub fn with_kernel_cmdline(mut self, kernel_cmdline: impl Into<String>) -> Self {
        self.kernel_cmdline = Some(kernel_cmdline.into());
        self
    }

    /// Returns this configuration with a different scheduler ceiling.
    #[must_use]
    pub const fn with_busy_ceiling_icount(mut self, ceiling: u64) -> Self {
        self.busy_ceiling_icount = ceiling;
        self
    }

    /// Returns this configuration with a different bounded completion timeout.
    #[must_use]
    pub const fn with_completion_timeout(mut self, timeout: Duration) -> Self {
        self.completion_timeout = timeout;
        self
    }

    /// Enables or disables host CPU load on the hostile-host rerun.
    #[must_use]
    pub const fn with_second_run_host_load(mut self, enabled: bool) -> Self {
        self.second_run_host_load = enabled;
        self
    }
}

/// Certifying evidence from the loaded-QEMU network exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveNetworkIoReport {
    /// Reference-run guest TX and deterministic reply evidence.
    pub reference: LiveNetworkIoSnapshot,
    /// Whether the loaded guest completed the reply/ack exchange.
    pub acknowledgement_seen: bool,
    /// Whether the hostile-host run reproduced the reference observations.
    pub deterministic_under_host_load: bool,
    /// Absolute probe stamp from the hostile-host run.
    pub hostile_probe_emit_icount: Option<u64>,
    /// Whether the diagnostic absolute probe origins matched.
    ///
    /// This is not part of the network projection: the gate certifies the
    /// complete exchange relative to the first guest-originated network event.
    pub absolute_probe_origin_equal: bool,
    /// Probe-relative acknowledgement offset from the hostile-host run.
    pub hostile_acknowledgement_offset_icount: Option<u64>,
    /// Whether the diagnostic guest acknowledgement offsets matched.
    pub acknowledgement_offset_equal: bool,
    /// Whether CPU load was active during the second run.
    pub host_load_applied: bool,
    /// Whether a diagnostic wall delay was applied before reply publication.
    ///
    /// The certifying path leaves this false: network RX is not device-frozen,
    /// so withholding a scheduled frame could let the guest pass its delivery
    /// icount and would test an invalid router implementation.
    pub delayed_reply_applied: bool,
    /// Whether both QEMU children accepted orderly plugin shutdown.
    pub orderly_child_exit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NetworkIoRunOutcome {
    snapshot: LiveNetworkIoSnapshot,
    acknowledgement_icount: Option<u64>,
    delayed_reply_applied: bool,
    orderly_child_exit: bool,
}

/// Runs the reference and hostile-host loaded-QEMU network certifications.
///
/// # Errors
///
/// Returns [`QemuLiveNetworkIoGateError`] when setup, launch, shared-memory
/// servicing, QMP synchronization, teardown, or deterministic comparison fails.
pub fn run_qemu_live_network_io_gate(
    config: &QemuLiveNetworkIoGateConfig,
) -> Result<QemuLiveNetworkIoReport, QemuLiveNetworkIoGateError> {
    let reference = run_once(config, RunRole::Reference)?;
    certify_run("reference", &reference, false)?;

    let hostile = run_once(config, RunRole::Hostile)?;
    certify_run("hostile-host", &hostile, false)?;
    if deterministic_projection(&reference) != deterministic_projection(&hostile) {
        return Err(QemuLiveNetworkIoGateError::SecondRunDiverged {
            reference: format!("{:?}", deterministic_projection(&reference)),
            hostile: format!("{:?}", deterministic_projection(&hostile)),
        });
    }

    let reference_probe_emit_icount = probe_emit_icount(&reference);
    let hostile_probe_emit_icount = probe_emit_icount(&hostile);
    let reference_acknowledgement_offset_icount = acknowledgement_offset_icount(&reference);
    let hostile_acknowledgement_offset_icount = acknowledgement_offset_icount(&hostile);
    Ok(QemuLiveNetworkIoReport {
        reference: reference.snapshot,
        acknowledgement_seen: reference.acknowledgement_icount.is_some(),
        deterministic_under_host_load: true,
        hostile_probe_emit_icount,
        absolute_probe_origin_equal: reference_probe_emit_icount == hostile_probe_emit_icount,
        hostile_acknowledgement_offset_icount,
        acknowledgement_offset_equal: reference_acknowledgement_offset_icount
            == hostile_acknowledgement_offset_icount,
        host_load_applied: config.second_run_host_load,
        delayed_reply_applied: hostile.delayed_reply_applied,
        orderly_child_exit: reference.orderly_child_exit && hostile.orderly_child_exit,
    })
}

#[derive(Clone, Copy)]
enum RunRole {
    Reference,
    Hostile,
}

impl RunRole {
    const fn directory(self) -> &'static str {
        match self {
            Self::Reference => "run-reference",
            Self::Hostile => "run-hostile",
        }
    }

    const fn delay(self) -> Duration {
        match self {
            Self::Reference => Duration::ZERO,
            Self::Hostile => Duration::ZERO,
        }
    }
}

fn run_once(
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
    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT);
    let command = QemuLaunchCommandBuilder::new(
        profile,
        vm_launch_config(config),
        path_text(&config.qemu_executable),
        plugin,
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
    let mut setup =
        complete_qemu_host_plugin_setup(resources.into_setup_resources(), region_config, GATE_SLOT)
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

    prime_guest_off_boot_barrier(
        &mut hot_path,
        &servicer,
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
    let (acknowledgement_icount, delayed_reply_applied) = drive_exchange(
        &mut hot_path,
        &mut servicer,
        &setup,
        &mut child,
        config.busy_ceiling_icount,
        config.completion_timeout,
        role.delay(),
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
        delayed_reply_applied,
        orderly_child_exit,
    })
}

fn prime_guest_off_boot_barrier(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &QemuLiveNetworkIoServicer,
    child: &mut QemuNodeChild,
    timeout: Duration,
) -> Result<(), QemuLiveNetworkIoGateError> {
    let pending = QemuShmemHotPathChannel::start_quantum(
        hot_path,
        crucible::ExecutionHorizon {
            icount: Icount {
                retired: PRIME_CEILING_ICOUNT,
            },
        },
    )
    .map_err(|source| QemuLiveNetworkIoGateError::drive("start priming quantum", source))?;
    let mut reached = false;
    for _ in 0..bounded_drive_polls(timeout) {
        let snapshot = servicer
            .vm_node_snapshot()
            .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
        if snapshot.current_icount >= PRIME_CEILING_ICOUNT {
            reached = true;
            break;
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
    let _ = QemuShmemHotPathChannel::finish_quantum(hot_path, pending);
    if reached {
        Ok(())
    } else {
        Err(QemuLiveNetworkIoGateError::PrimeDidNotReach)
    }
}

fn drive_exchange(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLiveNetworkIoServicer,
    setup: &QemuHostPluginSetup,
    child: &mut QemuNodeChild,
    ceiling: u64,
    timeout: Duration,
    reply_wall_delay: Duration,
) -> Result<(Option<u64>, bool), QemuLiveNetworkIoGateError> {
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
        let node_snapshot = servicer
            .vm_node_snapshot()
            .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?;
        if service_snapshot.reply_delivery_icount.is_some()
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
    Ok((acknowledgement_icount, delay_applied))
}

#[cfg(test)]
mod tests;
