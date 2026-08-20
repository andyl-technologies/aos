//! Scheduler-channel and device-state behavior for QEMU quanta.

use super::*;

#[test]
fn qemu_quantum_reports_device_io_freeze_across_burst_release() {
    let slot = NodeSlot::default();
    slot.mark_device_io_active();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );

    let pending = match hot_path.start_quantum(horizon(10)) {
        Ok(pending) => pending,
        Err(error) => panic!("device-I/O freeze quantum should start: {error}"),
    };
    slot.clear_device_io_active();
    if let Err(error) = slot.publish_reached_icount(10, 0) {
        panic!("plugin report should publish through shared node slot: {error}");
    }
    let report = match hot_path.finish_quantum(pending) {
        Ok(report) => report,
        Err(error) => panic!("device-I/O freeze quantum should finish: {error}"),
    };

    assert_eq!(
        report.device_io_freeze,
        QemuDeviceIoFreezeReport {
            initial: QemuDeviceIoFreezeObservation {
                current_icount: icount(0),
                device_io_active: true,
                publish_generation: 2,
            },
            final_state: QemuDeviceIoFreezeObservation {
                current_icount: icount(10),
                device_io_active: false,
                publish_generation: 6,
            },
        }
    );
    assert!(report.device_io_freeze.was_active());
}
#[test]
fn qemu_quantum_drains_plugin_emitted_frames_toward_router() {
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );
    let enqueue = hot_path.enqueue_outbound_frame_from_plugin(QemuOutboundFrame {
        emit_icount: icount(3),
        sequence: 9,
        payload: vec![8, 9],
    });
    assert!(enqueue.is_ok());
    let pending = match hot_path.start_quantum(horizon(3)) {
        Ok(pending) => pending,
        Err(error) => panic!("quantum start should publish ceiling: {error}"),
    };
    if let Err(error) = slot.publish_reached_icount(3, 0) {
        panic!("plugin report should publish through shared node slot: {error}");
    }

    let report = match hot_path.finish_quantum(pending) {
        Ok(report) => report,
        Err(error) => panic!("quantum should drain emitted frame: {error}"),
    };

    assert_eq!(
        report.emitted_frames,
        vec![QemuNodeEmittedFrame {
            source: node_id("vm-a"),
            destination: node_id("net-router"),
            emit_icount: icount(3),
            sequence: 9,
            payload: vec![8, 9],
        }]
    );
    assert!(
        hot_path
            .operation_log()
            .contains(&QemuQuantumOperation::EnqueueOutboundFrame)
    );
    assert!(
        report
            .operations
            .contains(&QemuQuantumOperation::DequeueOutboundFrame)
    );
    assert!(assert_qemu_quantum_hot_path_is_shmem_only(hot_path.operation_log()).is_ok());
}

#[test]
fn qemu_quantum_outbound_enqueue_uses_scheduler_send_authorizer() {
    let scheduler = pending_topology_scheduler();
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path_with_send_authorizer(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
        &scheduler,
    );

    let result = hot_path.enqueue_outbound_frame_from_plugin(QemuOutboundFrame {
        emit_icount: icount(3),
        sequence: 9,
        payload: vec![8, 9],
    });

    assert!(matches!(
        &result,
        Err(QemuQuantumError::SchedulerSendAuthorization {
            operation: "enqueue outbound frame",
            ..
        })
    ));
    assert!(
        result
            .expect_err("enqueue should be frozen")
            .to_string()
            .contains("cross-node sends frozen")
    );
    assert_eq!(
        hot_path
            .view
            .outbound_ring
            .peek(hot_path.view.outbound_entries),
        Ok(None)
    );
}

#[test]
fn qemu_quantum_outbound_dequeue_uses_scheduler_send_authorizer() {
    let scheduler = pending_topology_scheduler();
    let slot = NodeSlot::default();
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    enqueue_raw(
        &outbound_ring,
        &mut outbound_entries,
        frame(3, 0, 9, b"frozen"),
    );
    let mut hot_path = hot_path_with_send_authorizer(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
        &scheduler,
    );

    let result = QemuShmemHotPathChannel::emit_frame(&mut hot_path);

    assert!(matches!(
        &result,
        Err(QemuNodeChannelError {
            operation: "qemu_quantum_shmem_hot_path",
            ..
        })
    ));
    assert!(
        result
            .expect_err("dequeue should be frozen")
            .to_string()
            .contains("cross-node sends frozen")
    );
    assert_eq!(hot_path.view.outbound_ring.read_index(), 0);
    assert!(
        !hot_path
            .operation_log()
            .contains(&QemuQuantumOperation::DequeueOutboundFrame)
    );
}

#[test]
fn qemu_quantum_hot_path_rejects_qmp_or_plugin_ipc_operations() {
    let result = assert_qemu_quantum_hot_path_is_shmem_only(&[
        QemuQuantumOperation::ReadNodeReport,
        QemuQuantumOperation::PluginIpcControlFrame {
            operation: "run-quantum",
        },
    ]);
    assert!(matches!(
        result,
        Err(QemuQuantumError::NonShmemHotPathOperation {
            operation: "run-quantum",
            plane: QemuQuantumOperationPlane::PluginIpcControl,
        })
    ));

    let result = assert_qemu_quantum_hot_path_is_shmem_only(&[
        QemuQuantumOperation::StoreSchedulerCeiling,
        QemuQuantumOperation::QmpCommand {
            command: "cont-until",
        },
    ]);
    assert!(matches!(
        result,
        Err(QemuQuantumError::NonShmemHotPathOperation {
            operation: "cont-until",
            plane: QemuQuantumOperationPlane::QmpMachineControl,
        })
    ));
}

#[test]
fn qemu_quantum_implements_existing_shmem_hot_path_trait() {
    let slot = NodeSlot::default();
    if let Err(error) = slot.publish_scheduler_ceiling(ceiling(0, 6)) {
        panic!("initial ceiling should publish: {error}");
    }
    if let Err(error) = slot.publish_reached_icount(6, 0) {
        panic!("initial reached icount should publish: {error}");
    }
    let inbound_ring = RingHeader::new();
    let outbound_ring = RingHeader::new();
    let mut inbound_entries = frame_entries(8);
    let mut outbound_entries = frame_entries(8);
    let mut hot_path = hot_path(
        &slot,
        &inbound_ring,
        &mut inbound_entries,
        &outbound_ring,
        &mut outbound_entries,
    );

    let outcome = match QemuShmemHotPathChannel::advance_to_horizon(&mut hot_path, horizon(6)) {
        Ok(outcome) => outcome,
        Err(error) => panic!("trait advance should use quantum path: {error}"),
    };
    assert_eq!(outcome, AdvanceOutcome::ReachedHorizon);
    assert_eq!(
        QemuShmemHotPathChannel::current_icount(&mut hot_path),
        Ok(icount(6))
    );
    assert!(
        hot_path
            .operation_log()
            .iter()
            .all(|operation| operation.plane() == QemuQuantumOperationPlane::SharedMemory)
    );
}
