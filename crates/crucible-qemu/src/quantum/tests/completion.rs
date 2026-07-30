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
