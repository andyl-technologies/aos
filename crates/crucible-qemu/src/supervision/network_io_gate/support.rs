//! Deterministic projections and runtime support for the live network gate.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{
    NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};

use super::{
    DRIVE_POLL_INTERVAL, FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT, GATE_DOMAIN, GATE_NODE,
    LIVE_NETWORK_ACK_PAYLOAD, LIVE_NETWORK_PROBE_PAYLOAD, LIVE_NETWORK_REPLY_LATENCY_ICOUNT,
    NetworkIoRunOutcome, QMP_PRIMER_WAKE_INTERVAL, QemuLiveNetworkIoGateConfig,
    QemuLiveNetworkIoGateError,
};
use crate::supervision::network_io_servicer::{
    is_live_network_ack, is_live_network_backpressure_ack, is_live_network_probe,
};
use crate::{
    CrucibleShmemNetworkDevice, QemuHostPluginSetup, QemuLaunchArtifact, QemuNodeChild,
    QemuQmpVmStateControlChannel, QemuVmLaunchConfig, QmpError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NetworkDeterministicProjection {
    protocol_frames: Vec<(u32, Vec<u8>)>,
    reply_latency_icount: Option<u64>,
    backpressure_delivery_attempts: u32,
    backpressure_last_attempt_icount: u64,
    backpressure_retry_icount: Option<u64>,
    backpressure_acknowledgement_icount: Option<u64>,
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
        backpressure_delivery_attempts: outcome.backpressure_delivery_attempts,
        backpressure_last_attempt_icount: outcome.backpressure_last_attempt_icount,
        backpressure_retry_icount: outcome.backpressure_retry_icount,
        backpressure_acknowledgement_icount: outcome.backpressure_acknowledgement_icount,
    }
}

fn protocol_frames(outcome: &NetworkIoRunOutcome) -> Vec<(u64, u32, Vec<u8>)> {
    outcome
        .snapshot
        .tx_frames
        .iter()
        .filter(|frame| {
            is_live_network_probe(&frame.payload)
                || is_live_network_ack(&frame.payload)
                || is_live_network_backpressure_ack(&frame.payload)
        })
        .map(|frame| (frame.emit_icount, frame.sequence, frame.payload.clone()))
        .collect()
}

pub(super) fn probe_emit_icount(outcome: &NetworkIoRunOutcome) -> Option<u64> {
    outcome
        .snapshot
        .tx_frames
        .iter()
        .find(|frame| is_live_network_probe(&frame.payload))
        .map(|frame| frame.emit_icount)
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
    } else if outcome.acknowledgement_icount < outcome.snapshot.reply_delivery_icount {
        Some("guest acknowledgement preceded the exact router reply delivery coordinate")
    } else if !outcome.snapshot.backpressure_acknowledgement_seen
        || outcome.backpressure_acknowledgement_icount.is_none()
    {
        Some("guest did not acknowledge the exact retained backpressure frame")
    } else if outcome.backpressure_retry_icount
        != outcome
            .backpressure_last_attempt_icount
            .checked_add(FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT)
    {
        Some("retained backpressure retry missed its canonical deadline")
    } else if outcome.completion_owned_frames == 0 {
        Some("no guest TX batch crossed the completion-owned transfer path")
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
                thread::park_timeout(QMP_PRIMER_WAKE_INTERVAL);
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
            Ok(None) => thread::park_timeout(DRIVE_POLL_INTERVAL),
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
