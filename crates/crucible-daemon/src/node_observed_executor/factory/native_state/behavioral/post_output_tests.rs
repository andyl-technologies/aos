//! Inert exit-shape negatives only; no prior runtime/case can be manufactured.

use super::*;

fn lifecycle() -> ProgressEvidence {
    ProgressEvidence::Exact {
        reached: Position::new(10.into(), 1.into(), Phase::BoundaryControl),
        stop: StopReason::Lifecycle,
    }
}

#[test]
fn source_exit_shape_has_exact_success_code_and_no_new_output() {
    let progress = lifecycle();
    assert!(source_exit_matches(
        Some(SOURCE_EXIT_CAUSE),
        Some(0),
        0,
        0,
        0,
        0,
        &progress
    ));
    for code in [None, Some(1), Some(-1)] {
        assert!(!source_exit_matches(
            Some(SOURCE_EXIT_CAUSE),
            code,
            0,
            0,
            0,
            0,
            &progress
        ));
    }
    assert!(!source_exit_matches(
        Some("foreign exit"),
        Some(0),
        0,
        0,
        0,
        0,
        &progress
    ));
    assert!(!source_exit_matches(None, Some(0), 0, 0, 0, 0, &progress));
    for counts in [(1, 0, 0, 0), (0, 8, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)] {
        assert!(!source_exit_matches(
            Some(SOURCE_EXIT_CAUSE),
            Some(0),
            counts.0,
            counts.1,
            counts.2,
            counts.3,
            &progress
        ));
    }
}

#[test]
fn lifecycle_is_not_relabelled_output_or_horizon() {
    for stop in [StopReason::HorizonPark, StopReason::Output] {
        let progress = ProgressEvidence::Exact {
            reached: Position::new(10.into(), 1.into(), Phase::BoundaryControl),
            stop,
        };
        assert!(!source_exit_matches(
            Some(SOURCE_EXIT_CAUSE),
            Some(0),
            0,
            0,
            0,
            0,
            &progress
        ));
    }
}

#[test]
fn early_exit_or_foreign_prior_cannot_enter_selected_progress() {
    assert!(!source_terminal_selection(
        CaseKind::LcgProgress,
        false,
        false,
        false,
        true
    ));
    assert!(!source_terminal_selection(
        CaseKind::LcgProgress,
        false,
        false,
        true,
        true
    ));
    assert!(!source_terminal_selection(
        CaseKind::PostOutputProgress,
        false,
        false,
        false,
        true
    ));
    assert!(!source_terminal_selection(
        CaseKind::PostOutputProgress,
        false,
        true,
        false,
        false
    ));
    assert!(!source_terminal_selection(
        CaseKind::PostOutputProgress,
        false,
        false,
        true,
        false
    ));
    assert!(source_terminal_selection(
        CaseKind::PostOutputProgress,
        false,
        false,
        true,
        true
    ));
    assert!(source_terminal_selection(
        CaseKind::PostOutputProgress,
        false,
        true,
        true,
        false
    ));
}

#[test]
fn original_stopped_lifecycle_coordinate_is_not_birth_evaluation() {
    let tick = U64::new(700_677_000);
    let tick_ordinal = U64::new(2);
    let maximum_microsteps = U64::new(128);
    let stopped = Position::new(tick, U64::new(3), Phase::BoundaryControl);

    assert!(source_lifecycle_coordinate_matches(
        tick,
        tick_ordinal,
        maximum_microsteps,
        stopped
    ));
    for phase in [Phase::Reaction, Phase::Publication] {
        assert!(!source_lifecycle_coordinate_matches(
            tick,
            tick_ordinal,
            maximum_microsteps,
            Position::new(tick, U64::new(3), phase),
        ));
    }
    for reached in [
        Position::new(tick, U64::new(2), Phase::BoundaryControl),
        Position::new(U64::new(700_677_001), U64::new(3), Phase::BoundaryControl),
    ] {
        assert!(!source_lifecycle_coordinate_matches(
            tick,
            tick_ordinal,
            maximum_microsteps,
            reached
        ));
    }
    assert!(!source_lifecycle_coordinate_matches(
        tick,
        U64::new(0),
        maximum_microsteps,
        stopped
    ));
    assert!(!source_lifecycle_coordinate_matches(
        tick,
        U64::new(u64::MAX),
        maximum_microsteps,
        stopped
    ));
    assert!(!source_lifecycle_coordinate_matches(
        tick,
        tick_ordinal,
        U64::new(3),
        stopped
    ));
}
