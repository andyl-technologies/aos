//! Certifying live guest-network gate over the Crucible shared-memory rings.
//!
//! A diskless Linux guest originates a raw Ethernet probe through virtio-net.
//! The patched QEMU TX callback forwards the exact bytes to the loaded plugin,
//! the host router schedules one reply at a fixed icount offset, and the plugin
//! injects it directly while retaining canonical ownership on backpressure. The guest proves receipt by
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
    LIVE_NETWORK_ACK_PAYLOAD, LIVE_NETWORK_BACKPRESSURE_ACK_PAYLOAD, LIVE_NETWORK_PROBE_PAYLOAD,
    LIVE_NETWORK_REPLY_LATENCY_ICOUNT, LiveNetworkIoSnapshot, QemuLiveNetworkIoServicer,
    QemuLiveNetworkIoServicerError,
};
use crate::{
    LaunchProfileCandidate, QemuHostPluginSetup, QemuLaunchCommandBuilder, QemuLaunchPluginConfig,
    QemuLaunchPluginSwitch, QemuLiveNodeStepGateConfig, QemuMappedQuantumShmemHotPath,
    QemuNodeChild, QemuPluginIpcControlChannel, QemuQmpChannelConfig, QemuQuantumShmemConfig,
    QemuShmemHotPathChannel, complete_qemu_host_plugin_setup,
    run_qemu_live_retained_network_snapshot_gate, spawn_qemu_child_with_fds_in_directory,
};
use crucible::{BackendInput, Icount};
use crucible_shmem::{
    FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT, FrameDeliveryKey, FrameDeliveryState, FrameEntry,
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
const BACKPRESSURE_PROBE_CEILING_ICOUNT: u64 = 1;
const PRIME_CEILING_ICOUNT: u64 = 1_000_000;
const PROBE_DISCOVERY_CEILING_ICOUNT: u64 = 3_350_000_000;
const QMP_PRIMER_WAKE_INTERVAL: Duration = Duration::from_millis(10);
const DEFAULT_BUSY_CEILING_ICOUNT: u64 = 4_000_000_000;

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
    /// Whether real QEMU reported boot-time NIC backpressure in both runs.
    pub boot_backpressure_retained: bool,
    /// Whether both retained boot-time frames later left canonical shared memory.
    pub canonical_backpressure_retry_delivered: bool,
    /// Exact first retry coordinate observed in both live runs.
    pub backpressure_retry_icount: Option<u64>,
    /// Whether guest userspace acknowledged the exact retained frame in both runs.
    pub backpressure_guest_acknowledgement_seen: bool,
    /// Whether a retained frame survived source death and a fresh QEMU restore.
    pub retained_frame_fresh_process_restored: bool,
    /// Whether the retained restore crossed the durable canonical envelope.
    pub retained_frame_durable_envelope_restored: bool,
    /// Exact first retry coordinate observed after fresh-process restore.
    pub retained_frame_first_retry_icount: u64,
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
    boot_backpressure_retained: bool,
    canonical_backpressure_retry_delivered: bool,
    backpressure_acknowledgement_icount: Option<u64>,
    backpressure_delivery_attempts: u32,
    backpressure_last_attempt_icount: u64,
    backpressure_retry_icount: Option<u64>,
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
    let mut retained_config = QemuLiveNodeStepGateConfig::new(
        &config.qemu_executable,
        &config.plugin,
        &config.kernel,
        &config.firmware,
        config.run_directory.join("retained-network-exact"),
    )
    .with_initrd(&config.initrd)
    .with_vm_shape(GATE_MEMORY_MIB, 1, 0)
    .with_shmem_network_mac(crate::DEFAULT_CRUCIBLE_SHMEM_NETWORK_MAC)
    .with_fingerprint(QemuLaunchPluginSwitch::On)
    .with_completion_timeout(config.completion_timeout)
    .with_second_run_host_load(false);
    if let Some(cmdline) = &config.kernel_cmdline {
        retained_config = retained_config.with_kernel_cmdline(cmdline.clone());
    }
    let retained_report = run_qemu_live_retained_network_snapshot_gate(
        &retained_config,
        &QemuLiveNetworkIoServicer::boot_backpressure_probe(),
        LIVE_NETWORK_BACKPRESSURE_ACK_PAYLOAD,
        config.busy_ceiling_icount,
    )
    .map_err(|source| QemuLiveNetworkIoGateError::RetainedExactSnapshot { source })?;
    Ok(QemuLiveNetworkIoReport {
        reference: reference.snapshot,
        acknowledgement_seen: reference.acknowledgement_icount.is_some(),
        boot_backpressure_retained: reference.boot_backpressure_retained
            && hostile.boot_backpressure_retained,
        canonical_backpressure_retry_delivered: reference.canonical_backpressure_retry_delivered
            && hostile.canonical_backpressure_retry_delivered,
        backpressure_retry_icount: reference.backpressure_retry_icount,
        backpressure_guest_acknowledgement_seen: reference
            .backpressure_acknowledgement_icount
            .is_some()
            && hostile.backpressure_acknowledgement_icount.is_some(),
        retained_frame_fresh_process_restored: retained_report.source_process_force_crashed
            && retained_report.guest_acknowledgement_seen
            && retained_report.retained_frame_consumed,
        retained_frame_durable_envelope_restored: retained_report.durable_envelope_round_trip,
        retained_frame_first_retry_icount: retained_report.first_retry_icount,
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

#[path = "network_io_gate/drive.rs"]
mod drive;
use drive::run_once;
#[cfg(test)]
mod tests;
