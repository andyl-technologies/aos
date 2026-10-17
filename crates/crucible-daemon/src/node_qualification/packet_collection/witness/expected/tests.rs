//! Checks fixed semantic case geometry only; no process or class is qualified.
#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These fixed-template controls panic on malformed fixtures or a changed refusal invariant.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::Bytes;
use crucible_node_provider::reference_packet::PacketEvent;

fn position(tick: u64, microstep: u64, phase: Phase) -> Position {
    Position::new(U64::new(tick), U64::new(microstep), phase)
}

fn program() -> PacketProgramDefinition {
    PacketProgramDefinition {
        schema: "source-owned.packet-program.v1".to_owned(),
        events: vec![
            PacketEvent {
                id: Id::new("private-1").unwrap(),
                evaluation: position(4, 0, Phase::Reaction),
                completion: position(4, 0, Phase::Reaction),
                payload: None,
            },
            PacketEvent {
                id: Id::new("packet-1").unwrap(),
                evaluation: position(5, 0, Phase::Reaction),
                completion: position(5, 1, Phase::Publication),
                payload: Some(Bytes::new(b"actual\0packet\xff".to_vec())),
            },
        ],
    }
}

fn case(acknowledged: bool) -> PacketNativeCase {
    PacketNativeCase {
        case: if acknowledged {
            "after-ack"
        } else {
            "before-ack"
        }
        .to_owned(),
        oracle: crucible_node_contract::canonical::content_ref(
            b"independent-template",
            "text/plain",
        )
        .unwrap(),
        operation: Id::new("packet-grant-1").unwrap(),
        request: OperationRequest::ExactRun {
            start: position(0, 0, Phase::BoundaryControl),
            limit: position(9, 0, Phase::BoundaryControl),
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        },
        acknowledged,
    }
}

#[test]
fn whole_programme_case_excludes_equal_cut_and_atomic_straddle() {
    let program = program();
    let mut expected = case(false);
    assert!(template_window(&program, &expected).is_ok());

    for limit in [
        position(5, 0, Phase::Reaction),
        position(5, 1, Phase::Publication),
    ] {
        expected.request = OperationRequest::ExactRun {
            start: position(0, 0, Phase::BoundaryControl),
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        };
        assert!(template_window(&program, &expected).is_err());
    }
}

#[test]
fn prelaunch_pair_refuses_changed_operation_node_horizon_or_ack() {
    let program = program();
    let node = Id::new("packet-node").unwrap();
    let foreign = Id::new("foreign").unwrap();
    let before = case(false);
    let mut after = case(true);
    let operation = &before.operation;

    assert!(
        case_pair(
            &program,
            &node,
            &node,
            operation,
            U64::new(9),
            &before,
            &after
        )
        .is_ok()
    );
    assert!(
        case_pair(
            &program,
            &node,
            &foreign,
            operation,
            U64::new(9),
            &before,
            &after
        )
        .is_err()
    );
    assert!(
        case_pair(
            &program,
            &node,
            &node,
            &foreign,
            U64::new(9),
            &before,
            &after
        )
        .is_err()
    );
    assert!(
        case_pair(
            &program,
            &node,
            &node,
            operation,
            U64::new(8),
            &before,
            &after
        )
        .is_err()
    );
    after.acknowledged = false;
    assert!(
        case_pair(
            &program,
            &node,
            &node,
            operation,
            U64::new(9),
            &before,
            &after
        )
        .is_err()
    );
}

#[test]
fn post_ack_case_cannot_replace_request_or_original_case_identity() {
    let program = program();
    let node = Id::new("packet-node").unwrap();
    let before = case(false);
    let mut after = case(true);
    after.case = before.case.clone();

    assert!(
        case_pair(
            &program,
            &node,
            &node,
            &before.operation,
            U64::new(9),
            &before,
            &after
        )
        .is_err()
    );
    after.case = "after-ack".to_owned();
    after.request = OperationRequest::BoundarySettle {
        start: position(0, 0, Phase::BoundaryControl),
        limit: position(9, 0, Phase::BoundaryControl),
    };
    assert!(template_window(&program, &after).is_err());
}
