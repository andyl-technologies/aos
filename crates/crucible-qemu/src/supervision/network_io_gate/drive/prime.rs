//! Exact boot-boundary network backpressure priming.

use super::*;

pub(super) fn prime_guest_off_boot_barrier(
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
    finish_and_service_network_quantum(
        hot_path,
        servicer,
        backpressure_pending,
        "finish backpressure quantum",
    )?;
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
    finish_and_service_network_quantum(hot_path, servicer, pending, "finish priming quantum")?;
    Ok(retained)
}

pub(super) fn wait_for_prime_ceiling(
    servicer: &QemuLiveNetworkIoServicer,
    child: &mut QemuNodeChild,
    timeout: Duration,
    ceiling: u64,
) -> Result<(), QemuLiveNetworkIoGateError> {
    let mut budget = DrivePollBudget::new(timeout);
    while budget.begin_attempt() {
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
        budget.park();
    }
    let evidence = servicer.vm_node_snapshot().map_or_else(
        |error| format!("node_snapshot_error={error}"),
        |snapshot| format!("{snapshot:?}"),
    );
    Err(QemuLiveNetworkIoGateError::PrimeDidNotReach { ceiling, evidence })
}
