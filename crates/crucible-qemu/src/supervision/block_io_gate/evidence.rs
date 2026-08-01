//! Canonical evidence joining and launch helpers for the block-I/O gate.

use super::*;

pub(super) fn canonical_block_io_log(
    observations: &[BlockCompletionObservation],
) -> Result<Vec<u8>, QemuLiveBlockIoGateError> {
    let node = node_id(GATE_NODE);
    let events = observations.iter().map(|observation| {
        let mut payload = Vec::with_capacity(16);
        payload.extend_from_slice(&observation.request_icount.to_le_bytes());
        payload.extend_from_slice(&observation.completion_icount.to_le_bytes());
        ObservableEvent::io_completion(
            VirtualTime {
                ticks: observation.completion_icount,
            },
            node.clone(),
            if observation.write {
                IoEventKind::BlockWrite
            } else {
                IoEventKind::BlockRead
            },
            payload,
        )
    });
    let mut log = EventLog::new();
    log.append_observable_events(events)
        .map(|append| append.segment_bytes)
        .map_err(|source| QemuLiveBlockIoGateError::CanonicalLog { source })
}

/// Reaps the child within a bounded poll budget, force-killing on drop otherwise.
pub(super) fn reap_child(child: &mut QemuNodeChild, timeout: Duration) -> bool {
    let max_polls = bounded_drive_polls(timeout);
    for _ in 0..max_polls {
        match child.try_wait_natural_exit() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => thread::sleep(PRIME_POLL_INTERVAL),
            Err(_) => return false,
        }
    }
    false
}

/// Requires the load run to reproduce the reference run's block observations.
pub(super) fn assert_runs_match(
    reference: &BlockIoRunOutcome,
    second: &BlockIoRunOutcome,
    role: &'static str,
) -> Result<(), QemuLiveBlockIoGateError> {
    if !same_advance_class(&reference.advance, &second.advance) {
        return Err(QemuLiveBlockIoGateError::SecondRunDiverged {
            reason: format!(
                "{role} advance outcome class differed: {:?} vs {:?}",
                reference.advance, second.advance
            ),
        });
    }
    if !reference
        .diagnostics
        .deterministic_observation_eq(&second.diagnostics)
    {
        return Err(QemuLiveBlockIoGateError::SecondRunDiverged {
            reason: format!(
                "{role} block observations differed: {:?} vs {:?}",
                reference.diagnostics, second.diagnostics
            ),
        });
    }
    if reference.canonical_log != second.canonical_log {
        return Err(QemuLiveBlockIoGateError::SecondRunDiverged {
            reason: format!(
                "{role} canonical I/O log differed from synchronous run: {:?} vs {:?}",
                reference.completion_observations, second.completion_observations
            ),
        });
    }
    Ok(())
}

/// Compares scheduler outcomes without host-poll sampling coordinates.
pub(super) fn same_advance_class(
    first: &BlockIoAdvanceOutcome,
    second: &BlockIoAdvanceOutcome,
) -> bool {
    matches!(
        (first, second),
        (
            BlockIoAdvanceOutcome::ReachedCeiling { .. },
            BlockIoAdvanceOutcome::ReachedCeiling { .. }
        ) | (
            BlockIoAdvanceOutcome::PausedBelowCeiling { .. },
            BlockIoAdvanceOutcome::PausedBelowCeiling { .. }
        )
    ) || matches!(
        (first, second),
        (
            BlockIoAdvanceOutcome::Failed { detail: first },
            BlockIoAdvanceOutcome::Failed { detail: second }
        ) if first == second
    )
}

/// Returns the number of drive polls that fit within `timeout`, at least one.
pub(super) fn bounded_drive_polls(timeout: Duration) -> u64 {
    let interval = PRIME_POLL_INTERVAL.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
}

/// Builds the diskless-firmware VM launch config with a crucible-shmem block device.
pub(super) fn vm_launch_config(config: &QemuLiveBlockIoGateConfig) -> QemuVmLaunchConfig {
    let kernel = launch_artifact("kernel", &config.kernel);
    let vm = QemuVmLaunchConfig::new_diskless(
        GATE_NODE,
        kernel,
        launch_artifact("firmware", &config.firmware),
    )
    .with_crucible_shmem_block(CrucibleShmemBlockDevice::new(config.device_size_bytes));
    match &config.initrd {
        Some(initrd) => vm.with_initrd(launch_artifact("initrd", initrd)),
        None => vm,
    }
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
