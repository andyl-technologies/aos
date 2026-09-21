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

/// Retains the first published quantum while QMP authenticates the stopped VM.
pub(in crate::supervision::node_step_gate) struct PreparedGuestPrime {
    hot_path: QemuMappedQuantumShmemHotPath,
    pending: crate::QemuNodePendingQuantum,
    prime_ceiling: u64,
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

/// Publishes the first bounded quantum while the guest remains stopped.
///
/// The node's own hot path does not exist yet -- it is built only after QMP
/// connects -- so this maps a temporary hot path over the same shared-memory
/// region. Publishing the first ceiling releases the plugin's installation-time
/// boot barrier exactly as the M1 install gate does. QEMU was launched with
/// `-S`, so no guest instruction can retire before QMP capabilities and the
/// realized projection manifest are authenticated.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the region cannot be mapped or the
/// hot path cannot bind and publish the first quantum.
pub(in crate::supervision::node_step_gate) fn prepare_guest_prime(
    setup: &crate::QemuHostPluginSetup,
    identity: QemuLiveNodeIdentity<'_>,
    coverage: QemuLaunchPluginSwitch,
    boot_backpressure_payload: Option<&[u8]>,
) -> Result<PreparedGuestPrime, QemuLiveNodeStepGateError> {
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
    let horizon = crucible::ExecutionHorizon {
        icount: Icount {
            retired: prime_ceiling,
        },
    };
    let pending = QemuShmemHotPathChannel::start_quantum(
        &mut hot_path,
        horizon,
        crate::QemuQuantumStopCondition::Ceiling,
    )
    .map_err(|source| QemuLiveNodeStepGateError::prime("start priming quantum", source))?;

    Ok(PreparedGuestPrime {
        hot_path,
        pending,
        prime_ceiling,
    })
}

/// Drives and collects the first quantum after QMP resumes the guest.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the quantum cannot be polled, a
/// setup-time device request fails, or the guest does not reach its ceiling.
pub(in crate::supervision::node_step_gate) fn complete_guest_prime(
    setup: &crate::QemuHostPluginSetup,
    timeout: Duration,
    prepared: PreparedGuestPrime,
    block: Option<&mut QemuLiveBlockIoServicer>,
    ninep: Option<&mut QemuLive9pIoServicer>,
    boot_backpressure_payload: Option<&[u8]>,
) -> Result<PrimeGuestOutcome, QemuLiveNodeStepGateError> {
    let PreparedGuestPrime {
        mut hot_path,
        pending,
        prime_ceiling,
    } = prepared;
    let emitted_frames = poll_mapped_prime_chain(
        setup,
        timeout,
        &mut hot_path,
        pending,
        prime_ceiling,
        PrimeDeviceServicers { block, ninep },
        false,
    )?;
    let mut observable_events = QemuShmemHotPathChannel::drain_observable_events(&mut hot_path)
        .map_err(|source| QemuLiveNodeStepGateError::prime("drain priming observations", source))?;
    retain_priming_coverage(&mut observable_events);
    QemuShmemHotPathChannel::drain_rng_evidence(&mut hot_path)
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

/// Transfers setup-time device and callback ownership to the live runtime.
pub(in crate::supervision::node_step_gate) fn finish_guest_prime_runtime(
    mut runtime: QemuLiveHostIoRuntime,
    mut block: Option<QemuLiveBlockIoServicer>,
    ninep: Option<QemuLive9pIoServicer>,
    accelerator: Option<QemuLiveAcceleratorServicer>,
    block_latency: Option<BlockLatency>,
    timeout: Duration,
) -> Result<QemuLiveHostIoRuntime, QemuLiveNodeStepGateError> {
    if let (Some(servicer), Some(latency)) = (block.as_mut(), block_latency) {
        servicer
            .set_latency_model(latency)
            .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })?;
    }
    if let Some(servicer) = block {
        runtime = runtime
            .with_block_servicer(servicer, BlockIoDiagnostics::shared())
            .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })?;
    }
    if let Some(servicer) = ninep {
        runtime = runtime.with_ninep_servicer(servicer, NinepIoDiagnostics::shared());
    }
    if let Some(servicer) = accelerator {
        runtime = runtime.with_accelerator_servicer(servicer);
    }
    runtime
        .fence_priming_handoff(timeout)
        .map_err(|source| QemuLiveNodeStepGateError::PrimeHandoff { source })?;
    Ok(runtime)
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
    QemuShmemHotPathChannel::drain_rng_evidence(&mut hot_path).map_err(|source| {
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
