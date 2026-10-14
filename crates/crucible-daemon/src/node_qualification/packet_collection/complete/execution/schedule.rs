//! Matches the original thirteen grants against the complete source's finite scene.
//!
//! Matching data does not issue an operation token. Core still reserves every
//! actual grant, stages its original inputs and authenticates the owning source.

use crucible::node_contract::{ExactBoundaryPolicy, OperationRequest};
use crucible_node_contract::{Phase, Position, U64};

use super::super::{PacketCompleteNativeOracle, QualificationError, refused};

pub(super) const GRANTS: usize = 13;

pub(super) fn position(time: u64, microstep: u64, phase: Phase) -> Position {
    Position::new(U64::new(time), U64::new(microstep), phase)
}

pub(super) fn row(index: usize) -> Option<(usize, &'static str, OperationRequest)> {
    use Phase::{BoundaryControl as B, Delivery as D, Publication as P, Reaction as R};
    let rows = [
        (
            0,
            "producer-bootstrap",
            position(0, 0, B),
            position(1, 0, B),
        ),
        (
            1,
            "relay-initial-empty",
            position(0, 0, B),
            position(1, 0, B),
        ),
        (
            2,
            "sink-initial-empty",
            position(0, 0, B),
            position(1, 0, B),
        ),
        (0, "producer-original", position(1, 0, B), position(6, 0, B)),
        (
            1,
            "relay-physical-horizon",
            position(1, 0, B),
            position(6, 0, B),
        ),
        (
            1,
            "relay-before-delivery",
            position(6, 0, B),
            position(6, 0, D),
        ),
        (1, "relay-delivery", position(6, 0, D), position(6, 0, R)),
        (1, "relay-reaction", position(6, 0, R), position(6, 1, P)),
        (1, "relay-publication", position(6, 1, P), position(6, 1, D)),
        (
            2,
            "sink-physical-horizon",
            position(1, 0, B),
            position(6, 0, B),
        ),
        (
            2,
            "sink-before-delivery",
            position(6, 0, B),
            position(6, 1, D),
        ),
        (2, "sink-delivery", position(6, 1, D), position(6, 1, R)),
        (2, "sink-reaction", position(6, 1, R), position(6, 2, P)),
    ];
    let &(member, operation, start, limit) = rows.get(index)?;
    let request = if start.time_ps == limit.time_ps {
        OperationRequest::BoundarySettle { start, limit }
    } else {
        OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        }
    };
    Some((member, operation, request))
}

/// Checks the retained oracle's actual model and full original schedule.
pub(super) fn authenticate(
    oracle: &PacketCompleteNativeOracle,
    world: &crucible_node_contract::WorldBinding,
) -> Result<(), QualificationError> {
    oracle.authenticate_fixed_execution_data(world)?;
    let schedule = oracle.execution_schedule();
    if schedule.grants.len() != GRANTS {
        return Err(refused());
    }
    for (index, grant) in schedule.grants.iter().enumerate() {
        let (member, operation, request) = row(index).ok_or_else(refused)?;
        if grant.node != schedule.nodes[member]
            || grant.operation.as_str() != operation
            || grant.request != request
        {
            return Err(refused());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_chain_keeps_deferred_publication_and_delivery_as_distinct_grants() {
        let Some((1, _, OperationRequest::BoundarySettle { start, limit })) = row(8) else {
            panic!("missing original relay publication grant");
        };
        assert_eq!(start, position(6, 1, Phase::Publication));
        assert_eq!(limit, position(6, 1, Phase::Delivery));
        assert!(row(GRANTS).is_none());
    }

    #[test]
    fn fixed_chain_has_eleven_separate_input_cuts_without_flattening_time() {
        let reactive = (0..GRANTS)
            .filter_map(row)
            .filter(|(member, _, _)| *member != 0)
            .count();
        assert_eq!(reactive, 11);
        let Some((
            0,
            _,
            OperationRequest::ExactRun {
                boundary_policy, ..
            },
        )) = row(3)
        else {
            panic!("missing original producer exact run");
        };
        assert_eq!(boundary_policy, ExactBoundaryPolicy::HorizonPark);
    }
}
