//! QEMU quantum completion-boundary tests.

use super::*;

#[test]
fn qemu_quantum_accepts_an_existing_idle_report_beyond_the_new_ceiling() {
    let slot = NodeSlot::default();
    if let Err(error) = slot.publish_idle(0, 20, 0) {
        panic!("plugin idle report should publish through shared node slot: {error}");
    }
    let report_generation = slot.snapshot().publish_gen;
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
        Err(error) => panic!("quantum start should publish ceiling: {error}"),
    };
    assert_eq!(slot.snapshot().publish_gen, report_generation);
    let report = match hot_path.finish_quantum(pending) {
        Ok(report) => report,
        Err(error) => panic!("existing beyond-ceiling idle report should finish: {error}"),
    };

    assert_eq!(report.outcome, AdvanceOutcome::Paused { at: icount(0) });
    assert_eq!(report.final_state.next_deadline, Some(icount(20)));
}

#[test]
fn qemu_quantum_retries_a_later_report_that_is_not_at_a_boundary() {
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

    let pending = match hot_path.start_quantum(horizon(10)) {
        Ok(pending) => pending,
        Err(error) => panic!("quantum start should publish ceiling: {error}"),
    };
    slot.mark_running();
    assert_ne!(slot.snapshot().publish_gen, pending.report_generation);

    assert!(matches!(
        hot_path.finish_quantum(pending),
        Err(QemuQuantumError::PluginReportNotPublished {
            current_icount: 0,
            ceiling: 10,
        })
    ));
}

#[test]
fn qemu_quantum_accepts_a_release_acknowledged_runtime_clamp() {
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

    let pending = match hot_path.start_quantum(horizon(10)) {
        Ok(pending) => pending,
        Err(error) => panic!("quantum start should publish ceiling: {error}"),
    };
    if let Err(error) = slot.publish_idle(4, 12, 0) {
        panic!("plugin idle report should publish through shared node slot: {error}");
    }
    let clamp = match authorize_advance_ceiling(4, 4, None) {
        Ok(clamp) => clamp,
        Err(error) => panic!("completed coordinate should authorize a clamp: {error}"),
    };
    if let Err(error) = slot.publish_scheduler_ceiling(clamp) {
        panic!("completed quantum clamp should publish: {error}");
    }
    if let Err(error) = slot.request_control_boundary() {
        panic!("runtime clamp should request a control boundary: {error}");
    }
    if let Err(error) = slot.publish_control_boundary(4, 4, 0) {
        panic!("plugin should publish the requested control boundary: {error}");
    }
    slot.acknowledge_control_boundary();
    slot.mark_running();

    let report = match hot_path.finish_quantum(pending) {
        Ok(report) => report,
        Err(error) => panic!("release-acknowledged runtime clamp should finish: {error}"),
    };
    assert_eq!(report.outcome, AdvanceOutcome::Paused { at: icount(4) });
    assert_eq!(report.final_state.current_icount, icount(4));
    assert_eq!(report.final_state.next_deadline, None);
}

#[test]
fn qemu_quantum_rejects_an_unacknowledged_or_device_active_clamp() {
    for device_active in [false, true] {
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

        let pending = match hot_path.start_quantum(horizon(10)) {
            Ok(pending) => pending,
            Err(error) => panic!("quantum start should publish ceiling: {error}"),
        };
        if let Err(error) = slot.publish_idle(4, 12, 0) {
            panic!("plugin idle report should publish through shared node slot: {error}");
        }
        let clamp = match authorize_advance_ceiling(4, 4, None) {
            Ok(clamp) => clamp,
            Err(error) => panic!("completed coordinate should authorize a clamp: {error}"),
        };
        if let Err(error) = slot.publish_scheduler_ceiling(clamp) {
            panic!("completed quantum clamp should publish: {error}");
        }
        if device_active {
            if let Err(error) = slot.request_control_boundary() {
                panic!("runtime clamp should request a control boundary: {error}");
            }
            if let Err(error) = slot.publish_control_boundary(4, 4, 0) {
                panic!("plugin should publish the requested control boundary: {error}");
            }
            slot.acknowledge_control_boundary();
            slot.mark_device_io_active();
        }
        slot.mark_running();

        assert!(matches!(
            hot_path.finish_quantum(pending),
            Err(QemuQuantumError::PluginReportNotPublished {
                current_icount: 4,
                ceiling: 10,
            })
        ));
    }
}
