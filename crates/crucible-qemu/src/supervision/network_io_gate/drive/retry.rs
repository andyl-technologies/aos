//! Exact retained-frame retry boundary evidence.

use super::*;

pub(super) fn observe_exact_backpressure_retry(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLiveNetworkIoServicer,
    setup: &QemuHostPluginSetup,
    child: &mut QemuNodeChild,
    timeout: Duration,
    probe: BackpressureProbe,
) -> Result<u64, QemuLiveNetworkIoGateError> {
    let retry_icount = probe
        .last_attempt_icount
        .checked_add(FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT)
        .ok_or_else(|| QemuLiveNetworkIoGateError::BackpressureRetryCoordinate {
            frame: probe.key,
            expected_retry_icount: u64::MAX,
            evidence: String::from("retry coordinate overflowed u64"),
        })?;
    let before_retry = retry_icount.checked_sub(1).ok_or_else(|| {
        QemuLiveNetworkIoGateError::BackpressureRetryCoordinate {
            frame: probe.key,
            expected_retry_icount: retry_icount,
            evidence: String::from("retry coordinate has no preceding boundary"),
        }
    })?;

    advance_network_quantum_to(
        hot_path,
        servicer,
        setup,
        child,
        timeout,
        probe.key,
        before_retry,
    )?;
    let before =
        QemuShmemHotPathChannel::checkpoint_network_transport(hot_path).map_err(|source| {
            QemuLiveNetworkIoGateError::drive("inspect pre-retry retained frame", source)
        })?;
    let unchanged = before.inbound.frames.iter().any(|frame| {
        frame.delivery_key() == probe.key
            && frame.delivery_state() == Ok(FrameDeliveryState::Retained)
            && frame.delivery_attempts() == probe.delivery_attempts
            && frame.last_delivery_attempt_icount() == probe.last_attempt_icount
    });
    if !unchanged {
        return Err(QemuLiveNetworkIoGateError::BackpressureRetryCoordinate {
            frame: probe.key,
            expected_retry_icount: retry_icount,
            evidence: format!("frame changed before retry: {:?}", before.inbound.frames),
        });
    }

    advance_network_quantum_to(
        hot_path,
        servicer,
        setup,
        child,
        timeout,
        probe.key,
        retry_icount,
    )?;
    let at_retry =
        QemuShmemHotPathChannel::checkpoint_network_transport(hot_path).map_err(|source| {
            QemuLiveNetworkIoGateError::drive("inspect exact retained retry", source)
        })?;
    if let Some(frame) = at_retry
        .inbound
        .frames
        .iter()
        .find(|frame| frame.delivery_key() == probe.key)
        && (frame.delivery_state() != Ok(FrameDeliveryState::Retained)
            || frame.delivery_attempts() != probe.delivery_attempts.saturating_add(1)
            || frame.last_delivery_attempt_icount() != retry_icount)
    {
        return Err(QemuLiveNetworkIoGateError::BackpressureRetryCoordinate {
            frame: probe.key,
            expected_retry_icount: retry_icount,
            evidence: format!("invalid retry state: {:?}", at_retry.inbound.frames),
        });
    }
    Ok(retry_icount)
}

fn advance_network_quantum_to(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLiveNetworkIoServicer,
    setup: &QemuHostPluginSetup,
    child: &mut QemuNodeChild,
    timeout: Duration,
    frame: FrameDeliveryKey,
    ceiling: u64,
) -> Result<(), QemuLiveNetworkIoGateError> {
    let pending = QemuShmemHotPathChannel::start_quantum(
        hot_path,
        crucible::ExecutionHorizon {
            icount: Icount { retired: ceiling },
        },
    )
    .map_err(|source| QemuLiveNetworkIoGateError::drive("start exact retry quantum", source))?;
    setup
        .signal_plugin_wake()
        .map_err(|source| QemuLiveNetworkIoGateError::drive("wake exact retry quantum", source))?;
    wait_for_prime_ceiling(servicer, child, timeout, ceiling)?;
    finish_and_service_network_quantum(hot_path, servicer, pending, "finish exact retry quantum")?;
    let actual = servicer
        .vm_node_snapshot()
        .map_err(|source| QemuLiveNetworkIoGateError::NetworkServicer { source })?
        .current_icount;
    if actual != ceiling {
        return Err(QemuLiveNetworkIoGateError::BackpressureRetryCoordinate {
            frame,
            expected_retry_icount: ceiling,
            evidence: format!("quantum reached {actual}"),
        });
    }
    Ok(())
}
