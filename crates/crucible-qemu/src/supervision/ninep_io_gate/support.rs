//! Deterministic projections and runtime support for the live 9p-I/O gate.

use std::path::Path;
use std::time::Duration;

use crucible::{
    NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};

use super::{
    DRIVE_POLL_INTERVAL, GATE_DOMAIN, GATE_NODE, NinepIoDiagnosticsSnapshot, QemuLive9pIoGateConfig,
};
pub(super) use crate::bounded_scheduler_preemption::BoundedSchedulerPreemption as HostAdversary;
use crate::{CrucibleShmem9pDevice, QemuLaunchArtifact, QemuVmLaunchConfig};

/// The determinism-relevant device subset of a run's 9p observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NinepDeterministicObservations {
    forwarded_request: bool,
    delivered_response: bool,
    first_completion_latency_icount: Option<u64>,
    last_device_io_active: bool,
}

/// Projects request-independent deterministic device behavior from a snapshot.
pub(super) fn deterministic_projection(
    snapshot: &NinepIoDiagnosticsSnapshot,
) -> NinepDeterministicObservations {
    NinepDeterministicObservations {
        forwarded_request: snapshot.frames_processed > 0,
        delivered_response: snapshot.frames_delivered > 0,
        first_completion_latency_icount: snapshot
            .first_request_icount
            .zip(snapshot.first_completion_horizon)
            .and_then(|(request, horizon)| horizon.checked_sub(request)),
        last_device_io_active: snapshot.last_device_io_active,
    }
}

/// Returns the number of drive polls that fit within `timeout`, at least one.
pub(super) fn bounded_drive_polls(timeout: Duration) -> u64 {
    let interval = DRIVE_POLL_INTERVAL.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
}

/// Builds the diskless-firmware VM launch config with a crucible-shmem 9p device.
pub(super) fn vm_launch_config(config: &QemuLive9pIoGateConfig) -> QemuVmLaunchConfig {
    let kernel = launch_artifact("kernel", &config.kernel);
    let vm = QemuVmLaunchConfig::new_diskless(
        GATE_NODE,
        kernel,
        launch_artifact("firmware", &config.firmware),
    )
    .with_crucible_shmem_9p(CrucibleShmem9pDevice::new());
    match &config.initrd {
        Some(initrd) => vm.with_initrd(launch_artifact("initrd", initrd)),
        None => vm,
    }
}

fn launch_artifact(kind: &str, path: &Path) -> QemuLaunchArtifact {
    let path = path.to_string_lossy().into_owned();
    QemuLaunchArtifact::new(
        crucible::ContentHash::from_canonical_material(GATE_DOMAIN, &format!("{kind}={path}")),
        path,
    )
}

pub(super) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

pub(super) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Authorizes the single node's 9p-I/O traffic.
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
