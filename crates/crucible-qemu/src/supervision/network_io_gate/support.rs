//! Deterministic projections and runtime support for the live network gate.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{
    NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};

use super::{
    DRIVE_POLL_INTERVAL, GATE_DOMAIN, GATE_NODE, HOST_LOAD_WORKERS, LIVE_NETWORK_ACK_PAYLOAD,
    LIVE_NETWORK_PROBE_PAYLOAD, LIVE_NETWORK_REPLY_LATENCY_ICOUNT, NetworkIoRunOutcome,
    QMP_PRIMER_WAKE_INTERVAL, QemuLiveNetworkIoGateConfig, QemuLiveNetworkIoGateError,
};
use crate::{
    CrucibleShmemNetworkDevice, QemuHostPluginSetup, QemuLaunchArtifact, QemuNodeChild,
    QemuQmpVmStateControlChannel, QemuVmLaunchConfig, QmpError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NetworkDeterministicProjection {
    protocol_frames: Vec<(u32, Vec<u8>)>,
    reply_latency_icount: Option<u64>,
}

pub(super) fn deterministic_projection(
    outcome: &NetworkIoRunOutcome,
) -> NetworkDeterministicProjection {
    let protocol_frames = protocol_frames(outcome);
    let probe_icount = protocol_frames.first().map(|frame| frame.0);
    let protocol_frames = protocol_frames
        .into_iter()
        .map(|(_emit_icount, sequence, payload)| (sequence, payload))
        .collect();
    NetworkDeterministicProjection {
        reply_latency_icount: probe_icount
            .zip(outcome.snapshot.reply_delivery_icount)
            .and_then(|(probe, reply)| reply.checked_sub(probe)),
        protocol_frames,
    }
}

fn protocol_frames(outcome: &NetworkIoRunOutcome) -> Vec<(u64, u32, Vec<u8>)> {
    outcome
        .snapshot
        .tx_frames
        .iter()
        .filter(|frame| {
            frame
                .payload
                .windows(LIVE_NETWORK_PROBE_PAYLOAD.len())
                .any(|window| window == LIVE_NETWORK_PROBE_PAYLOAD)
                || frame
                    .payload
                    .windows(LIVE_NETWORK_ACK_PAYLOAD.len())
                    .any(|window| window == LIVE_NETWORK_ACK_PAYLOAD)
        })
        .map(|frame| (frame.emit_icount, frame.sequence, frame.payload.clone()))
        .collect()
}

pub(super) fn probe_emit_icount(outcome: &NetworkIoRunOutcome) -> Option<u64> {
    protocol_frames(outcome).first().map(|frame| frame.0)
}

pub(super) fn acknowledgement_offset_icount(outcome: &NetworkIoRunOutcome) -> Option<u64> {
    probe_emit_icount(outcome)
        .zip(outcome.acknowledgement_icount)
        .and_then(|(probe, acknowledgement)| acknowledgement.checked_sub(probe))
}

pub(super) fn certify_run(
    run: &'static str,
    outcome: &NetworkIoRunOutcome,
    require_delay: bool,
) -> Result<(), QemuLiveNetworkIoGateError> {
    let projection = deterministic_projection(outcome);
    let probes = projection
        .protocol_frames
        .iter()
        .filter(|(_, frame)| {
            frame
                .windows(LIVE_NETWORK_PROBE_PAYLOAD.len())
                .any(|window| window == LIVE_NETWORK_PROBE_PAYLOAD)
        })
        .count();
    let acknowledgements = projection
        .protocol_frames
        .iter()
        .filter(|(_, frame)| {
            frame
                .windows(LIVE_NETWORK_ACK_PAYLOAD.len())
                .any(|window| window == LIVE_NETWORK_ACK_PAYLOAD)
        })
        .count();
    let reason = if probes != 1 {
        Some("expected exactly one guest-originated probe")
    } else if outcome.snapshot.reply_delivery_icount.is_none() {
        Some("router did not enqueue a deterministic reply")
    } else if projection.reply_latency_icount != Some(LIVE_NETWORK_REPLY_LATENCY_ICOUNT) {
        Some("reply was not stamped at the fixed icount latency")
    } else if acknowledgements != 1 || outcome.acknowledgement_icount.is_none() {
        Some("guest did not receive the reply and emit one acknowledgement")
    } else if require_delay && !outcome.delayed_reply_applied {
        Some("hostile-host leg did not delay physical reply publication")
    } else if !outcome.orderly_child_exit {
        Some("QEMU did not exit orderly after plugin shutdown")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(QemuLiveNetworkIoGateError::CertificationFailed {
            run,
            reason,
            evidence: format!("{outcome:?}"),
        });
    }
    Ok(())
}

pub(super) fn vm_launch_config(config: &QemuLiveNetworkIoGateConfig) -> QemuVmLaunchConfig {
    QemuVmLaunchConfig::new_diskless(
        GATE_NODE,
        launch_artifact("kernel", &config.kernel),
        launch_artifact("firmware", &config.firmware),
    )
    .with_initrd(launch_artifact("initrd", &config.initrd))
    .with_crucible_shmem_network(CrucibleShmemNetworkDevice::new())
}

fn launch_artifact(kind: &str, path: &Path) -> QemuLaunchArtifact {
    let path = path.to_string_lossy().into_owned();
    QemuLaunchArtifact::new(
        crucible::ContentHash::from_canonical_material(GATE_DOMAIN, &format!("{kind}={path}")),
        path,
    )
}

pub(super) fn connect_qmp_priming_main_loop(
    setup: &QemuHostPluginSetup,
    socket_path: &Path,
) -> Result<QemuQmpVmStateControlChannel<UnixStream>, QmpError> {
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let primer = scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                let _ = setup.signal_plugin_wake();
                thread::sleep(QMP_PRIMER_WAKE_INTERVAL);
            }
        });
        let result = QemuQmpVmStateControlChannel::connect_unix_socket(socket_path);
        stop.store(true, Ordering::Relaxed);
        let _ = primer.join();
        result
    })
}

pub(super) fn reap_child(child: &mut QemuNodeChild, timeout: Duration) -> bool {
    for _ in 0..bounded_drive_polls(timeout) {
        match child.try_wait_natural_exit() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => thread::sleep(DRIVE_POLL_INTERVAL),
            Err(_) => return false,
        }
    }
    false
}

pub(super) fn bounded_drive_polls(timeout: Duration) -> u64 {
    let interval = DRIVE_POLL_INTERVAL.as_micros().max(1);
    u64::try_from(timeout.as_micros().saturating_add(interval - 1) / interval)
        .unwrap_or(u64::MAX)
        .max(1)
}

pub(super) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

pub(super) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

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
                let mut accumulator = 0_u64;
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
