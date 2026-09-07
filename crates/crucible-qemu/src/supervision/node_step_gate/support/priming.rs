//! Boot-barrier priming and retained setup-time coverage.

use super::*;
use crucible::ObservableEvent;

/// Carries outputs captured while moving a guest beyond its boot barrier.
pub(in crate::supervision::node_step_gate) struct PrimeGuestOutcome {
    pub(in crate::supervision::node_step_gate) emitted_frames: Vec<crate::QemuNodeEmittedFrame>,
    pub(in crate::supervision::node_step_gate) retained_network:
        Option<crate::QemuNetworkTransportCheckpoint>,
    pub(in crate::supervision::node_step_gate) observable_events: Vec<ObservableEvent>,
}

fn retain_priming_coverage(events: &mut Vec<ObservableEvent>) {
    // Boot priming remains outside modeled scenario execution. Coverage alone
    // crosses the ready boundary as steering feedback; admitting setup-time
    // markers or device observations could fire scenario conditions early.
    events.retain(|event| {
        matches!(
            event.payload(),
            crucible::ObservableEventPayload::CoverageBlock { .. }
        )
    });
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
pub(in crate::supervision::node_step_gate) fn prime_guest_off_boot_barrier(
    setup: &crate::QemuHostPluginSetup,
    timeout: Duration,
    identity: QemuLiveNodeIdentity<'_>,
    coverage: QemuLaunchPluginSwitch,
    block: Option<&mut QemuLiveBlockIoServicer>,
    ninep: Option<&mut QemuLive9pIoServicer>,
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
            // crucible-lint: allow host-nondeterminism-state -- this fixed boot canary is canonical gate input, not host-derived state.
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
        block,
        ninep,
        false,
    )?;
    let mut observable_events = QemuShmemHotPathChannel::drain_observable_events(&mut hot_path)
        .map_err(|source| QemuLiveNodeStepGateError::prime("drain priming observations", source))?;
    retain_priming_coverage(&mut observable_events);
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
        observable_events,
    })
}

/// Carries the state needed to continue a boot-time retained-network capture.
pub(in crate::supervision::node_step_gate) struct BootNetworkBackpressureContinuation<'a> {
    pub(in crate::supervision::node_step_gate) block: Option<&'a mut QemuLiveBlockIoServicer>,
    pub(in crate::supervision::node_step_gate) ninep: Option<&'a mut QemuLive9pIoServicer>,
    pub(in crate::supervision::node_step_gate) payload: &'a [u8],
    pub(in crate::supervision::node_step_gate) capture_icount: u64,
    pub(in crate::supervision::node_step_gate) initial_network:
        crate::QemuNetworkTransportCheckpoint,
    pub(in crate::supervision::node_step_gate) emitted_frames: Vec<crate::QemuNodeEmittedFrame>,
    pub(in crate::supervision::node_step_gate) observable_events: Vec<ObservableEvent>,
}

pub(in crate::supervision::node_step_gate) fn continue_boot_network_backpressure_capture(
    setup: &crate::QemuHostPluginSetup,
    timeout: Duration,
    identity: QemuLiveNodeIdentity<'_>,
    coverage: QemuLaunchPluginSwitch,
    continuation: BootNetworkBackpressureContinuation<'_>,
) -> Result<PrimeGuestOutcome, QemuLiveNodeStepGateError> {
    let BootNetworkBackpressureContinuation {
        block,
        ninep,
        payload,
        capture_icount,
        initial_network,
        mut emitted_frames,
        mut observable_events,
    } = continuation;
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
    let mut continued_observations =
        QemuShmemHotPathChannel::drain_observable_events(&mut hot_path).map_err(|source| {
            QemuLiveNodeStepGateError::prime("drain continued priming observations", source)
        })?;
    retain_priming_coverage(&mut continued_observations);
    observable_events.append(&mut continued_observations);
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
        observable_events,
    })
}
