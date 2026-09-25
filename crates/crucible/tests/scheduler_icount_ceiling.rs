//! Checks exact-tick scheduler horizons and anchored retired-instruction counters.

#![forbid(unsafe_code)]

use crucible::{
    Icount, NetworkLookahead, NodeCounter, NodeTimeMapping, SchedulerHorizonLimit, SharedTimeline,
    SimDuration, SimInstant, TimeConversionError, VirtualTime, network_horizon_from_lookahead,
};

#[test]
fn shared_timeline_preserves_both_sides_of_nanosecond_boundary() {
    let timeline = SharedTimeline::new();

    for tick in [999, 1_000, 1_001] {
        let horizon = SimInstant { ticks: tick };
        assert_eq!(
            timeline.max_advance_counter_for_horizon(horizon),
            NodeCounter { ticks: tick }
        );
        assert_eq!(
            timeline.max_advance_counter_for_conservative_horizon(horizon),
            NodeCounter { ticks: tick }
        );
    }

    assert_eq!(SimInstant { ticks: 999 }.nanoseconds_floor(), 0);
    assert_eq!(SimInstant { ticks: 1_000 }.nanoseconds_floor(), 1);
    assert_eq!(SimInstant { ticks: 1_001 }.nanoseconds_floor(), 1);
}

#[test]
fn idle_jump_keeps_the_phase_of_the_next_retired_instruction() {
    let mapping = NodeTimeMapping {
        anchor_counter: NodeCounter { ticks: 5 },
        anchor_time: SimInstant { ticks: 7 },
    };

    assert_eq!(
        mapping.logical_time(NodeCounter { ticks: 6 }),
        Ok(SimInstant { ticks: 8 })
    );
    assert_eq!(
        mapping.logical_time(NodeCounter { ticks: 7 }),
        Ok(SimInstant { ticks: 9 })
    );
    assert_eq!(
        mapping.counter_for_logical_time_ceil(SimInstant { ticks: 8 }),
        Ok(NodeCounter { ticks: 6 })
    );
    assert_eq!(
        mapping.counter_for_logical_time_floor(SimInstant { ticks: 9 }),
        Ok(NodeCounter { ticks: 7 })
    );
}

#[test]
fn anchored_projection_fails_closed_at_counter_bounds() {
    let upper = NodeTimeMapping {
        anchor_counter: NodeCounter { ticks: u64::MAX },
        anchor_time: SimInstant::EPOCH,
    };
    assert_eq!(
        upper.counter_for_logical_time_ceil(SimInstant { ticks: 1 }),
        Err(TimeConversionError::VirtualTimeOverflow {
            icount: Icount { retired: u64::MAX },
        })
    );

    let lower = NodeTimeMapping {
        anchor_counter: NodeCounter { ticks: 0 },
        anchor_time: SimInstant { ticks: 1 },
    };
    assert_eq!(
        lower.counter_for_logical_time_floor(SimInstant::EPOCH),
        Err(TimeConversionError::VirtualTimeOverflow {
            icount: Icount { retired: 0 },
        })
    );
}

#[test]
fn network_lookahead_uses_exact_tick_horizon() {
    let horizon = network_horizon_from_lookahead(
        SimInstant { ticks: 7 },
        NetworkLookahead::Finite(SimDuration { ticks: 2 }),
    );

    assert_eq!(
        horizon,
        SchedulerHorizonLimit::Finite {
            virtual_time: SimInstant { ticks: 9 },
            ceiling: NodeCounter { ticks: 9 },
        }
    );
    assert_eq!(VirtualTime { ticks: 9 }.ticks, 9);
}
