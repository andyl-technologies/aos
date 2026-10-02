//! Actual shared-memory quantum completion at an early output stop.

use super::*;

#[test]
fn network_output_batch_finishes_at_the_fresh_physical_pause()
-> Result<(), Box<dyn std::error::Error>> {
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
    let pending = hot_path.start_quantum(horizon(2_000), QemuQuantumStopCondition::Ceiling)?;
    let initial_control_ack = slot.snapshot().control_boundary_ack;
    for sequence in 0..2 {
        let frame = frame(1_000, 0, sequence, &[sequence as u8]);
        hot_path
            .view
            .outbound_ring
            .enqueue(hot_path.view.outbound_entries, &frame)?;
    }
    slot.publish_pause_quiesced(1_000, 20)?;

    let report = hot_path.finish_quantum(pending)?;

    assert_eq!(report.final_state.current_icount, icount(1_000));
    assert_eq!(report.outcome, AdvanceOutcome::Paused { at: icount(1_000) });
    assert_eq!(report.emitted_frames.len(), 2);
    for (sequence, frame) in report.emitted_frames.iter().enumerate() {
        assert_eq!(frame.emit_icount, icount(1_000));
        assert_eq!(frame.sequence, sequence as u64);
        assert_eq!(frame.payload, [sequence as u8]);
    }
    assert_eq!(outbound_ring.read_index(), outbound_ring.write_index());
    assert_eq!(slot.snapshot().control_boundary_ack, initial_control_ack);
    Ok(())
}
