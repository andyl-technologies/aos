//! Matches the original thirteen grants against the complete source's finite scene.
//!
//! Matching data does not issue an operation token. Core still reserves every
//! actual grant, stages its original inputs and authenticates the owning source.

use crucible_engine::node_contract::{ExactBoundaryPolicy, OperationRequest};
use crucible_node_format::{Phase, Position, U64};

use super::super::{PacketCompleteNativeOracle, QualificationError, refused};
use crate::node_qualification::packet_collection::connected::{
    PacketConnectedGrant, PacketConnectedSchedule,
};

/// Selects one of the two closed original thirteen-grant schedules.
///
/// Selection is inert DATA. Every actual grant, source result and durable ACK
/// still uses the same original runtime, oracle and publication admissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node_qualification::packet_collection::complete) enum Bootstrap {
    InitialEmpty,
    PrivateMutation,
}

impl Bootstrap {
    pub(in crate::node_qualification::packet_collection::complete) fn row(
        self,
        index: usize,
    ) -> Option<(usize, &'static str, OperationRequest)> {
        let (member, operation, mut request) = row(index)?;
        if self == Self::PrivateMutation {
            let boundary = position(5, 0, Phase::BoundaryControl);
            match &mut request {
                OperationRequest::ExactRun { limit, .. } if index < 3 => *limit = boundary,
                OperationRequest::ExactRun { start, .. } if matches!(index, 3 | 4 | 9) => {
                    *start = boundary
                }
                _ => {}
            }
        }
        Some((member, operation, request))
    }
}

/// Authenticates the complete retained schedule, not only its first limit.
pub(in crate::node_qualification::packet_collection::complete) fn bootstrap_data(
    selected: &PacketConnectedSchedule,
) -> Result<Bootstrap, QualificationError> {
    if selected.grants.len() != GRANTS {
        return Err(refused());
    }

    for bootstrap in [Bootstrap::InitialEmpty, Bootstrap::PrivateMutation] {
        let matches = selected.grants.iter().enumerate().all(|(index, grant)| {
            let Some((member, operation, request)) = bootstrap.row(index) else {
                return false;
            };
            grant.node == selected.nodes[member]
                && grant.operation.as_str() == operation
                && grant.request == request
        });
        if matches {
            return Ok(bootstrap);
        }
    }

    Err(refused())
}

pub(in crate::node_qualification::packet_collection::complete) fn bootstrap_counter_scratch_data()
-> usize {
    use std::mem::size_of;

    size_of::<Bootstrap>()
        + size_of::<Option<Bootstrap>>()
        + size_of::<Result<Bootstrap, QualificationError>>()
        + size_of::<Result<Bootstrap, crucible_engine::node_contract::RuntimeError>>()
        + size_of::<Option<(usize, &'static str, OperationRequest)>>()
        + size_of::<(usize, &'static str, OperationRequest)>()
        + size_of::<[Bootstrap; 2]>()
        + size_of::<std::array::IntoIter<Bootstrap, 2>>()
        + size_of::<&PacketConnectedSchedule>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, PacketConnectedGrant>>>()
        + size_of::<Option<(usize, &PacketConnectedGrant)>>()
}

pub(super) const GRANTS: usize = 13;

pub(super) fn position(time: u64, microstep: u64, phase: Phase) -> Position {
    Position::new(U64::new(time), U64::new(microstep), phase)
}

pub(in crate::node_qualification::packet_collection::complete) fn row(
    index: usize,
) -> Option<(usize, &'static str, OperationRequest)> {
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
pub(in crate::node_qualification::packet_collection::complete) fn authenticate(
    oracle: &PacketCompleteNativeOracle,
    world: &crucible_node_format::WorldBinding,
) -> Result<(), QualificationError> {
    oracle.authenticate_fixed_execution_data(world)?;
    bootstrap_data(oracle.execution_schedule())?;
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

    #[test]
    fn private_mutation_schedule_authenticates_all_thirteen_contiguous_rows() {
        use crate::node_qualification::packet_collection::connected::{
            PacketConnectedGrant, PacketConnectedSchedule,
        };
        use crucible_node_format::Id;
        let mut selected = PacketConnectedSchedule {
            nodes: std::array::from_fn(|i| Id::new(format!("packet-{i}")).unwrap()),
            grants: Vec::new(),
            cases: Vec::new(),
        };
        for n in 0..GRANTS {
            let (member, operation, request) = Bootstrap::PrivateMutation.row(n).unwrap();
            selected.grants.push(PacketConnectedGrant {
                node: selected.nodes[member].clone(),
                operation: Id::new(operation).unwrap(),
                request,
            });
        }
        assert_eq!(
            bootstrap_data(&selected).unwrap(),
            Bootstrap::PrivateMutation
        );
        let cut = position(5, 0, Phase::BoundaryControl);
        for index in 0..3 {
            let (_, _, OperationRequest::ExactRun { start, limit, .. }) =
                Bootstrap::PrivateMutation.row(index).unwrap()
            else {
                panic!("missing initial exact grant");
            };
            assert_eq!(start, position(0, 0, Phase::BoundaryControl));
            assert_eq!(limit, cut);
        }
        for index in [3, 4, 9] {
            let (_, _, OperationRequest::ExactRun { start, .. }) =
                Bootstrap::PrivateMutation.row(index).unwrap()
            else {
                panic!("missing continuation grant");
            };
            assert_eq!(start, cut);
        }
        // A time-five prefix cannot be attached to the unchanged time-one
        // continuation rows. The whole retained tuple must agree.
        selected.grants[3].request = row(3).unwrap().2;
        assert!(bootstrap_data(&selected).is_err());
    }
}
