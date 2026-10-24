//! Exercises mapped bytes and local custody, never Source writer permission.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crucible_qemu_protocol::boundary_action::{ActionBinding, ActionReturn};
use crucible_qemu_protocol::parent_park_return::PARENT_PARK_PHYSICAL_RESOLUTION_ALL;

fn returned() -> ParentParkReturn {
    ParentParkReturn {
        binding: ActionBinding {
            cap: [1; 32],
            reservation: [2; 32],
            account_generation: 3,
            process_generation: 4,
            loan_sequence: 2,
            token: 0,
            capture: None,
            park_request: Some(5),
            frontier: 6,
        },
        first: -libc::ECANCELED,
        post: -libc::ETIMEDOUT,
        physical_resolution_mask: PARENT_PARK_PHYSICAL_RESOLUTION_ALL,
        publication_count: 2,
        pair_view_return_mask: 3,
        original_statuses: [-libc::ECANCELED, -libc::ETIMEDOUT],
        operation_status: -libc::EIO,
        return_status: 0,
        stopped_generation: 17,
        native_generation: 19,
    }
}

#[test]
fn actual_local_publication_preserves_both_canonical_negative_statuses() {
    let slot = NodeSlot::new(0);
    slot.retain_action_frontier(2).unwrap();
    let writer = ProtectedWriter::new();
    let wire = returned().encode().unwrap();

    let progress = writer.write(&slot, &wire);

    assert_eq!(progress.status(), 0);
    assert_eq!(progress.return_published, 1);
    assert_eq!(progress.writer_released, 1);
    assert_eq!(slot.observe_parent_park_return().unwrap(), Some(returned()));
    assert_eq!(slot.observe_action_return().unwrap(), None);
    assert!(slot.action_frontier_is_retained());
    assert_eq!(writer.write(&slot, &wire).status(), -libc::EALREADY);
}

#[test]
fn wrong_variant_is_retained_before_refusal_and_never_written() {
    let slot = NodeSlot::new(0);
    let writer = ProtectedWriter::new();
    let mut binding = returned().binding;
    binding.park_request = None;
    binding.capture = Some(1);
    let control = ActionReturn {
        binding,
        first: 0,
        post: 0,
        physical_state: 1,
        returned_mask: 3,
        borrowed_mask: 3,
        row_count: 2,
        progress_kind: 0,
        progress_row: 0,
        progress_ns: 0,
        progress_witness: 0,
    };
    let bytes = control.encode().unwrap();

    let progress = writer.write(&slot, &bytes);

    assert_eq!(progress.first_status, -libc::EPROTO);
    assert_eq!(progress.write_attempted, 0);
    assert_eq!(progress.writer_released, 1);
    assert_eq!(writer.journal.lock().unwrap().bytes, bytes);
    assert_eq!(slot.observe_parent_park_return().unwrap(), None);
}

#[test]
fn publication_failure_retains_input_and_cannot_replay_after_frontier_appears() {
    let slot = NodeSlot::new(0);
    let writer = ProtectedWriter::new();
    let bytes = returned().encode().unwrap();

    let progress = writer.write(&slot, &bytes);
    slot.retain_action_frontier(2).unwrap();
    let retry = writer.write(&slot, &bytes);

    assert_eq!(progress.first_status, -libc::EIO);
    assert_eq!(progress.publication_uncertain, 1);
    assert_eq!(retry.first_status, -libc::EALREADY);
    assert_eq!(retry.write_attempted, 0);
    assert_eq!(slot.observe_parent_park_return().unwrap(), None);
    assert_eq!(writer.journal.lock().unwrap().bytes, bytes);
}

#[test]
fn negative_post_keeps_known_publication_and_unknown_closing_debt() {
    let slot = NodeSlot::new(0);
    slot.retain_action_frontier(2).unwrap();
    let writer = ProtectedWriter::new();
    let bytes = returned().encode().unwrap();
    let mut replaced = returned();
    replaced.first = -libc::EIO;

    let progress = writer.write_with_post(&slot, &bytes, || {
        slot.publish_parent_park_return(2, replaced).unwrap();
    });

    assert_eq!(progress.return_published, 1);
    assert_eq!(progress.post_status, -libc::EAGAIN);
    assert_eq!(progress.publication_uncertain, 1);
    assert_eq!(progress.writer_released, 1);
    assert_eq!(writer.write(&slot, &bytes).status(), -libc::EALREADY);
    assert_eq!(writer.journal.lock().unwrap().bytes, bytes);
}

#[test]
fn overlapping_writer_refuses_without_overwriting_actual_input() {
    let slot = NodeSlot::new(0);
    slot.retain_action_frontier(2).unwrap();
    let writer = ProtectedWriter::new();
    let bytes = returned().encode().unwrap();

    let progress = writer.write_with_post(&slot, &bytes, || {
        assert_eq!(writer.write(&slot, &bytes).status(), -libc::EBUSY);
    });

    assert_eq!(progress.status(), 0);
    assert_eq!(writer.journal.lock().unwrap().bytes, bytes);
}

#[test]
fn callback_without_genuine_child_retains_source_custody_and_writes_no_return() {
    let wire = returned().encode().unwrap();
    let mut progress = WriteProgress::default();

    let status = protected_park_return_writer(
        wire.as_ptr(),
        wire.len(),
        &mut progress,
        std::ptr::null_mut(),
    );

    assert_eq!(status, -libc::EINVAL);
    assert_eq!(progress.first_status, -libc::EINVAL);
    assert_eq!(progress.write_attempted, 0);
    assert_eq!(progress.return_published, 0);
    assert_eq!(progress.writer_released, 0);
    assert_eq!(progress.publication_uncertain, 0);
}

#[test]
fn callback_without_progress_refuses_before_reading_input_or_child() {
    let status = protected_park_return_writer(
        std::ptr::null(),
        PARENT_PARK_RETURN_BYTES,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );

    assert_eq!(status, -libc::EINVAL);
}

#[test]
fn obsolete_pending_and_incomplete_records_never_reach_the_mapped_journal() {
    let valid = returned().encode().unwrap();
    for (offset, replacement) in [
        (0, b"CRUCPRR1".to_vec()),
        (128, 1_u32.to_be_bytes().to_vec()),
        (132, 127_u32.to_be_bytes().to_vec()),
    ] {
        let slot = NodeSlot::new(0);
        slot.retain_action_frontier(2).unwrap();
        let writer = ProtectedWriter::new();
        let mut bytes = valid;
        bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);

        let progress = writer.write(&slot, &bytes);

        assert_eq!(progress.first_status, -libc::EPROTO);
        assert_eq!(progress.write_attempted, 0);
        assert_eq!(progress.return_published, 0);
        assert_eq!(writer.journal.lock().unwrap().bytes, bytes);
        assert_eq!(slot.observe_parent_park_return().unwrap(), None);
        assert!(slot.action_frontier_is_retained());
    }
}

#[test]
fn published_bytes_can_precede_callback_completion_without_returning_host_custody() {
    let slot = NodeSlot::new(0);
    slot.retain_action_frontier(2).unwrap();
    let writer = ProtectedWriter::new();
    let bytes = returned().encode().unwrap();

    let progress = writer.write_with_post(&slot, &bytes, || {
        assert_eq!(slot.observe_parent_park_return().unwrap(), Some(returned()));
        assert!(slot.action_frontier_is_retained());
        assert_eq!(writer.write(&slot, &bytes).status(), -libc::EBUSY);
    });

    assert_eq!(progress.writer_released, 1);
    assert!(slot.action_frontier_is_retained());
}
