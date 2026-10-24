//! Predeclares every original full cut and distinct connected observation.

use super::id;
use crucible_daemon::node_qualification::{
    PacketConnectedCase, PacketConnectedCaseKind, PacketConnectedGrant, PacketConnectedSchedule,
};
use crucible_engine::node_contract::{ExactBoundaryPolicy, OperationRequest};
use crucible_node_format::{Id, Phase, Position, U64};

/// Bounds the complete original fixture ledger before any native birth.
pub(super) const GRANT_COUNT: usize = 13;

/// Retains every genuine reactive staging identity for the full lifetime.
pub(super) const INPUT_STAGE_COUNT: usize = 11;

/// Charges grants and retained input stages against one common ledger.
pub(super) const RETAINED_OPERATION_CAPACITY: usize = GRANT_COUNT + INPUT_STAGE_COUNT;

pub(super) fn position(time: u64, microstep: u64, phase: Phase) -> Position {
    Position::new(U64::new(time), U64::new(microstep), phase)
}

pub(super) fn scene() -> PacketConnectedSchedule {
    let zero = position(0, 0, Phase::BoundaryControl);
    let one = position(1, 0, Phase::BoundaryControl);
    // Source2 parks ExactRun at a physical boundary; its event positions stay superdense.
    let producer_end = position(6, 0, Phase::BoundaryControl);
    let physical_boundary = position(6, 0, Phase::BoundaryControl);
    let relay_delivery = position(6, 0, Phase::Delivery);
    let relay_reaction = position(6, 0, Phase::Reaction);
    let relay_publication = position(6, 1, Phase::Publication);
    let sink_delivery = position(6, 1, Phase::Delivery);
    let sink_reaction = position(6, 1, Phase::Reaction);
    let sink_end = position(6, 2, Phase::Publication);
    let rows = [
        (0, "producer-bootstrap", zero, one),
        (1, "relay-initial-empty", zero, one),
        (2, "sink-initial-empty", zero, one),
        (0, "producer-original", one, producer_end),
        // CNP ExactRun stops before the tick; BoundarySettle then admits its phases.
        (1, "relay-physical-horizon", one, physical_boundary),
        (
            1,
            "relay-before-delivery",
            physical_boundary,
            relay_delivery,
        ),
        (1, "relay-delivery", relay_delivery, relay_reaction),
        (1, "relay-reaction", relay_reaction, relay_publication),
        (1, "relay-publication", relay_publication, sink_delivery),
        (2, "sink-physical-horizon", one, physical_boundary),
        (2, "sink-before-delivery", physical_boundary, sink_delivery),
        (2, "sink-delivery", sink_delivery, sink_reaction),
        (2, "sink-reaction", sink_reaction, sink_end),
    ];
    let grants = rows
        .into_iter()
        .map(|(member, name, start, limit)| PacketConnectedGrant {
            node: id(&format!("packet-{member}")),
            operation: id(name),
            request: if start.time_ps == limit.time_ps {
                OperationRequest::BoundarySettle { start, limit }
            } else {
                OperationRequest::ExactRun {
                    start,
                    limit,
                    boundary_policy: ExactBoundaryPolicy::HorizonPark,
                }
            },
        })
        .collect::<Vec<_>>();
    let mut cases = Vec::new();
    for grant in &grants {
        for (suffix, kind) in [
            ("before", PacketConnectedCaseKind::BeforeRetirement),
            ("after", PacketConnectedCaseKind::AfterRetirement),
        ] {
            cases.push(PacketConnectedCase {
                id: format!("packet-connected-{}-{suffix}", grant.operation.as_str()),
                kind,
                node: grant.node.clone(),
                operation: Some(grant.operation.clone()),
            });
        }
    }
    for (name, kind, member, operation) in [
        ("stage", PacketConnectedCaseKind::Stage, 1, None),
        (
            "input-acknowledgement",
            PacketConnectedCaseKind::InputAcknowledgement,
            1,
            None,
        ),
        ("commit", PacketConnectedCaseKind::Commit, 1, None),
        (
            "delivery",
            PacketConnectedCaseKind::Delivery,
            1,
            Some("relay-delivery"),
        ),
        (
            "reaction",
            PacketConnectedCaseKind::Reaction,
            1,
            Some("relay-reaction"),
        ),
        (
            "publication",
            PacketConnectedCaseKind::Publication,
            1,
            Some("relay-publication"),
        ),
        (
            "slow-producer-refusal",
            PacketConnectedCaseKind::SlowProducerRefusal,
            1,
            None,
        ),
        (
            "zero-delay-closure",
            PacketConnectedCaseKind::ZeroDelayClosure,
            2,
            Some("sink-delivery"),
        ),
        (
            "positive-delay-coordinate",
            PacketConnectedCaseKind::PositiveDelayCoordinate,
            1,
            Some("relay-delivery"),
        ),
        (
            "durable-root",
            PacketConnectedCaseKind::DurableRoot,
            0,
            None,
        ),
    ] {
        cases.push(PacketConnectedCase {
            id: format!("packet-connected-{name}"),
            kind,
            node: id(&format!("packet-{member}")),
            operation: operation.map(id),
        });
    }
    PacketConnectedSchedule {
        nodes: std::array::from_fn(|member| id(&format!("packet-{member}"))),
        grants,
        cases,
    }
}

pub(super) fn node(member: usize) -> Id {
    id(&format!("packet-{member}"))
}
