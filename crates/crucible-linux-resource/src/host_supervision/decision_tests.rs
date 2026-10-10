//! Parity checks for allocation-free deadline decisions and owned reporting.

// crucible-lint: allow panic-shortcut -- test fixtures panic to localize deadline and ownership regressions.
#![allow(clippy::unwrap_used)]

use super::super::{
    BTreeMap, HostOperationBudget, HostOperationBudgets, HostOperationSupervisor,
    evaluate_operation, evaluate_operation_decision, require_running,
};
use super::*;

fn fixture(class: HostOperationClass) -> SupervisionState {
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[class as usize].progress_timeout = Some(Duration::from_secs(6));
    budgets.classes[class as usize].total_timeout = Some(Duration::from_secs(8));
    SupervisionState {
        cap_id: [19; 32],
        budgets,
        policy_revision: 7,
        cap_revision: 11,
        cap_allowance: Some(Duration::from_secs(10)),
        cap_state: HostOperationState::Running,
        next_operation: 1,
        operations: BTreeMap::from([(
            1,
            Operation {
                class,
                control: class == HostOperationClass::Cleanup,
                started: Duration::from_secs(2),
                last_progress: Duration::from_secs(4),
                started_revision: 3,
                completed: 2,
                required: 9,
                state: HostOperationState::Running,
                startup_cancellation: None,
            },
        )]),
    }
}

#[test]
fn deadline_limits_preserve_every_tie_and_source_order() {
    let choices = [
        None,
        Some(Duration::ZERO),
        Some(Duration::from_secs(3)),
        Some(Duration::from_secs(9)),
    ];
    let state = fixture(HostOperationClass::Preparation);
    let source_order = [
        HostDeadlineSource::Progress(7),
        HostDeadlineSource::Total(7),
        HostDeadlineSource::Outer {
            cap_id: [19; 32],
            revision: 11,
        },
    ];

    for progress in choices {
        for total in choices {
            for outer in choices {
                let limits = DeadlineLimits {
                    progress,
                    total,
                    outer,
                };
                let decision = limits.decision();
                let entries = [progress, total, outer];
                let expected = entries.iter().flatten().copied().min();

                assert_eq!(decision.map(|value| value.remaining), expected);
                if let Some(decision) = decision {
                    let status = decision.into_status(&state);
                    let sources: Vec<_> = entries
                        .into_iter()
                        .zip(source_order)
                        .filter_map(|(value, source)| (value == expected).then_some(source))
                        .collect();
                    assert_eq!(status.sources, sources);
                    assert_eq!(status.sources.capacity(), 3);
                }
            }
        }
    }
}

#[test]
fn decisions_preserve_terminal_precedence_for_every_class() {
    let states = [
        HostOperationState::Running,
        HostOperationState::Completed,
        HostOperationState::Expired,
        HostOperationState::Canceled,
    ];

    for class in HostOperationClass::ALL {
        for cap_state in states {
            for operation_state in states {
                for elapsed in [0, 5, 9, 10, 11] {
                    let mut state = fixture(class);
                    state.cap_state = cap_state;
                    state.operations.get_mut(&1).unwrap().state = operation_state;
                    let original_cap = state.cap_id;
                    let decision =
                        evaluate_operation_decision(&mut state, 1, Duration::from_secs(elapsed))
                            .unwrap();
                    let expected_cap = if cap_state == HostOperationState::Running && elapsed >= 10
                    {
                        HostOperationState::Expired
                    } else {
                        cap_state
                    };
                    let expected_state = if operation_state != HostOperationState::Running {
                        operation_state
                    } else if class != HostOperationClass::Cleanup
                        && expected_cap != HostOperationState::Running
                    {
                        expected_cap
                    } else if elapsed >= 10 {
                        HostOperationState::Expired
                    } else {
                        HostOperationState::Running
                    };

                    assert_eq!(decision.state, expected_state);
                    assert_eq!(state.operations[&1].state, expected_state);
                    assert_eq!(state.cap_state, expected_cap);
                    assert_eq!(state.cap_id, original_cap);
                    assert_eq!(state.policy_revision, 7);
                    assert_eq!(state.cap_revision, 11);
                    assert_eq!(state.operations[&1].started, Duration::from_secs(2));
                    assert_eq!(state.operations[&1].last_progress, Duration::from_secs(4));
                    assert_eq!(state.operations[&1].completed, 2);
                    assert_eq!(state.operations[&1].required, 9);

                    let status =
                        operation_status_from_decision(&state, 1, &state.operations[&1], decision);
                    assert_eq!(status.state, expected_state);
                    assert_eq!(decision.require_running(1), require_running(&status));
                    assert_eq!(status.completed_work_units, 2);
                    assert_eq!(status.outstanding_work_units, 7);
                    assert_eq!(status.started_policy_revision, 3);
                    let progress_seconds = 6u64.saturating_sub(elapsed.saturating_sub(4));
                    let total_seconds = 8u64.saturating_sub(elapsed.saturating_sub(2));
                    let outer_seconds = 10u64.saturating_sub(elapsed);
                    let minimum = if class == HostOperationClass::Cleanup {
                        progress_seconds.min(total_seconds)
                    } else {
                        progress_seconds.min(total_seconds).min(outer_seconds)
                    };
                    let mut expected_sources = Vec::new();
                    if progress_seconds == minimum {
                        expected_sources.push(HostDeadlineSource::Progress(7));
                    }
                    if total_seconds == minimum {
                        expected_sources.push(HostDeadlineSource::Total(7));
                    }
                    if class != HostOperationClass::Cleanup && outer_seconds == minimum {
                        expected_sources.push(HostDeadlineSource::Outer {
                            cap_id: [19; 32],
                            revision: 11,
                        });
                    }
                    let deadline = status.effective_deadline.unwrap();
                    assert_eq!(deadline.remaining, Duration::from_secs(minimum));
                    assert_eq!(deadline.sources, expected_sources);
                }
            }
        }
    }
}

#[test]
fn unlimited_decision_preserves_reporting_without_a_source_vector() {
    let mut state = fixture(HostOperationClass::Quantum);
    state.budgets.classes[HostOperationClass::Quantum as usize] =
        HostOperationBudget::unlimited_quantum();
    state.cap_allowance = None;
    DEADLINE_STATUS_CONSTRUCTIONS.with(|count| count.set(0));

    let status = evaluate_operation(&mut state, 1, Duration::from_secs(1_000_000)).unwrap();

    assert_eq!(status.state, HostOperationState::Running);
    assert!(status.effective_deadline.is_none());
    assert_eq!(DEADLINE_STATUS_CONSTRUCTIONS.with(std::cell::Cell::get), 0);
}

#[test]
fn guard_checks_do_not_construct_owned_deadline_source_lists() {
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[HostOperationClass::Preparation as usize].poll_interval =
        Duration::from_millis(1);
    let supervisor = HostOperationSupervisor::new(budgets, None).unwrap();
    let operation = supervisor
        .begin_work(HostOperationClass::Preparation, 2)
        .unwrap();
    let original_binding = supervisor.outer_cap_binding().unwrap();
    DEADLINE_STATUS_CONSTRUCTIONS.with(|count| count.set(0));

    assert_eq!(operation.wait_slice().unwrap(), Duration::from_millis(1));
    operation.progress(1).unwrap();
    operation.wait_for_change().unwrap();

    assert_eq!(DEADLINE_STATUS_CONSTRUCTIONS.with(std::cell::Cell::get), 0);
    assert_eq!(supervisor.outer_cap_binding().unwrap(), original_binding);
    // The binding getter itself intentionally renders an owned status snapshot.
    assert_eq!(DEADLINE_STATUS_CONSTRUCTIONS.with(std::cell::Cell::get), 1);
    DEADLINE_STATUS_CONSTRUCTIONS.with(|count| count.set(0));

    let status = operation.status().unwrap();
    assert_eq!(status.completed_work_units, 1);
    assert_eq!(DEADLINE_STATUS_CONSTRUCTIONS.with(std::cell::Cell::get), 1);

    DEADLINE_STATUS_CONSTRUCTIONS.with(|count| count.set(0));
    assert_eq!(
        operation.complete().unwrap().state,
        HostOperationState::Completed
    );
    assert_eq!(DEADLINE_STATUS_CONSTRUCTIONS.with(std::cell::Cell::get), 1);
}

#[test]
fn expired_and_canceled_guard_checks_preserve_original_errors_without_reporting() {
    for terminal in [HostOperationState::Expired, HostOperationState::Canceled] {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let operation = supervisor.begin(HostOperationClass::Preparation).unwrap();
        supervisor.shared.outer.lock().unwrap().state = terminal;
        DEADLINE_STATUS_CONSTRUCTIONS.with(|count| count.set(0));
        let expected = if terminal == HostOperationState::Expired {
            HostSupervisionError::DeadlineExpired {
                operation_id: operation.id,
                class: HostOperationClass::Preparation,
            }
        } else {
            HostSupervisionError::Terminal { state: terminal }
        };

        assert_eq!(operation.wait_slice().unwrap_err(), expected);
        assert_eq!(operation.progress(1).unwrap_err(), expected);
        assert_eq!(operation.wait_for_change().unwrap_err(), expected);
        assert_eq!(operation.complete().unwrap_err(), expected);
        assert_eq!(DEADLINE_STATUS_CONSTRUCTIONS.with(std::cell::Cell::get), 0);
    }
}
