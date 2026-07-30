//! Checks the max-advance lookahead gate.

#![forbid(unsafe_code)]

use crucible_shmem::{
    FrameDeliveryKey, FrameEntry, LookaheadGateError, authorize_advance_ceiling,
    validate_frame_delivery_is_future,
};

#[test]
fn lookahead_gate_authorizes_ceiling_before_possible_delivery() {
    let ceiling = match authorize_advance_ceiling(40, 49, Some(50)) {
        Ok(ceiling) => ceiling,
        Err(error) => panic!("lookahead authorization should be valid: {error}"),
    };

    assert_eq!(ceiling.current_icount(), 40);
    assert_eq!(ceiling.max_advance_icount(), 49);
}

#[test]
fn lookahead_gate_rejects_ceiling_at_possible_delivery() {
    assert_eq!(
        authorize_advance_ceiling(40, 50, Some(50)),
        Err(LookaheadGateError::AdvanceReachesPossibleDelivery {
            max_advance_icount: 50,
            earliest_possible_delivery_icount: 50,
        })
    );
}

#[test]
fn lookahead_gate_rejects_ceiling_past_possible_delivery() {
    assert_eq!(
        authorize_advance_ceiling(40, 51, Some(50)),
        Err(LookaheadGateError::AdvanceReachesPossibleDelivery {
            max_advance_icount: 51,
            earliest_possible_delivery_icount: 50,
        })
    );
}

#[test]
fn lookahead_gate_rejects_ceiling_before_current_icount() {
    assert_eq!(
        authorize_advance_ceiling(40, 39, None),
        Err(LookaheadGateError::CeilingBeforeCurrent {
            current_icount: 40,
            max_advance_icount: 39,
        })
    );
}

#[test]
fn lookahead_gate_allows_exact_current_delivery_icount() {
    let frame = frame(50, 7, 3);

    assert_eq!(validate_frame_delivery_is_future(&frame, 50), Ok(()));
    assert!(frame.is_deliverable_at(50));
}

#[test]
fn lookahead_gate_rejects_already_passed_delivery_icount() {
    let frame = frame(50, 7, 3);

    assert_eq!(
        validate_frame_delivery_is_future(&frame, 51),
        Err(LookaheadGateError::DeliveryAlreadyPassed {
            consumer_current_icount: 51,
            frame: FrameDeliveryKey {
                delivery_icount: 50,
                src_node: 7,
                seq: 3,
            },
        })
    );
}

#[test]
fn lookahead_gate_allows_future_frame_to_deliver_at_exact_icount() {
    let frame = frame(50, 7, 3);

    assert_eq!(validate_frame_delivery_is_future(&frame, 49), Ok(()));
    assert!(!frame.is_deliverable_at(49));
    assert!(frame.is_deliverable_at(50));
}

fn frame(delivery_icount: u64, src_node: u32, seq: u32) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, b"payload") {
        Ok(frame) => frame,
        Err(error) => panic!("frame entry should be valid: {error}"),
    }
}
