//! Exact trigger deadline projection, pulse edges, and portable continuation.

use std::collections::BTreeMap;

use crucible::{
    Action, Condition, ConditionEvaluationPass, ConditionEventLogPrefix, Event, EventFirings,
    EventGraph, EventGraphState, EventId, SchedulerEvaluationBoundaryKind, Shift, SimDuration,
    TimerId, VirtualTime,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn evaluate(
    graph: &EventGraph,
    state: &mut EventGraphState,
    at: u64,
    timers: &BTreeMap<TimerId, VirtualTime>,
) -> TestResult<EventFirings> {
    let prefix = ConditionEventLogPrefix::from_evaluation_boundary(
        0,
        VirtualTime { ticks: at },
        SchedulerEvaluationBoundaryKind::Quantum,
    )?;
    let mut pass =
        ConditionEvaluationPass::from_log_prefix(prefix, |_leaf: crucible::ConditionLeaf<'_>| {
            false
        })
        .with_timer_fires(timers.clone());
    Ok(pass.evaluate_event_graph(graph, state))
}

#[test]
fn relative_and_timer_deadlines_reconstruct_after_restore_cancel_and_rearm() -> TestResult {
    let begin = EventId::from_name("begin");
    let timer = TimerId {
        name: String::from("finish"),
    };
    let graph = EventGraph::new(vec![
        Event::once(
            begin.clone(),
            Some(Condition::at(VirtualTime { ticks: 0 })),
            Action::arm_timer(timer.clone(), SimDuration { nanos: 13 }),
        ),
        Event::once(
            EventId::from_name("relative"),
            Some(Condition::after(SimDuration { nanos: 7 }, begin)),
            Action::Group(Vec::new()),
        ),
        Event::once(
            EventId::from_name("timer"),
            Some(Condition::timer(timer.clone())),
            Action::Group(Vec::new()),
        ),
    ])?;
    let shift = Shift::new(0)?;
    let mut state = EventGraphState::new();
    let mut timers = BTreeMap::new();
    assert_eq!(evaluate(&graph, &mut state, 0, &timers)?.len(), 1);
    timers.insert(timer.clone(), VirtualTime { ticks: 13 });
    assert_eq!(
        state.next_evaluation_deadline(&graph, &timers, VirtualTime { ticks: 0 }, shift)?,
        Some(VirtualTime { ticks: 7 })
    );
    assert_eq!(evaluate(&graph, &mut state, 7, &timers)?.len(), 1);

    let mut restored = EventGraphState::from_compact_binary(&state.to_compact_binary())?;
    assert_eq!(
        restored.next_evaluation_deadline(&graph, &timers, VirtualTime { ticks: 7 }, shift)?,
        Some(VirtualTime { ticks: 13 })
    );
    timers.clear();
    assert_eq!(
        restored.next_evaluation_deadline(&graph, &timers, VirtualTime { ticks: 7 }, shift)?,
        None
    );
    timers.insert(timer, VirtualTime { ticks: 29 });
    assert_eq!(
        restored.next_evaluation_deadline(&graph, &timers, VirtualTime { ticks: 7 }, shift)?,
        Some(VirtualTime { ticks: 29 })
    );
    assert_eq!(evaluate(&graph, &mut restored, 29, &timers)?.len(), 1);
    assert_eq!(
        restored.next_evaluation_deadline(&graph, &timers, VirtualTime { ticks: 29 }, shift)?,
        None
    );
    Ok(())
}

#[test]
fn repeatable_disjunction_observes_falling_edges_between_exact_pulses() -> TestResult {
    let graph = EventGraph::new(vec![Event::repeatable(
        EventId::from_name("pulses"),
        Some(Condition::AnyOf {
            predicates: vec![
                Condition::at(VirtualTime { ticks: 7 }),
                Condition::at(VirtualTime { ticks: 13 }),
            ],
        }),
        Action::Group(Vec::new()),
    )])?;
    let mut state = EventGraphState::new();
    let timers = BTreeMap::new();
    let mut at = 0;
    let mut fired = Vec::new();
    let mut boundaries = Vec::new();
    while let Some(next) = state.next_evaluation_deadline(
        &graph,
        &timers,
        VirtualTime { ticks: at },
        Shift::new(0)?,
    )? {
        at = next.ticks;
        boundaries.push(at);
        if !evaluate(&graph, &mut state, at, &timers)?.is_empty() {
            fired.push(at);
        }
        assert!(boundaries.len() <= 4, "time projection must terminate");
    }
    assert_eq!(boundaries, vec![7, 8, 13, 14]);
    assert_eq!(fired, vec![7, 13]);
    Ok(())
}

#[test]
fn latched_once_predicates_do_not_keep_waking_the_scheduler() -> TestResult {
    let graph = EventGraph::new(vec![Event::repeatable(
        EventId::from_name("latched"),
        Some(Condition::Once {
            predicate: Box::new(Condition::at(VirtualTime { ticks: 8 })),
        }),
        Action::Group(Vec::new()),
    )])?;
    let mut state = EventGraphState::new();
    let timers = BTreeMap::new();
    assert_eq!(evaluate(&graph, &mut state, 8, &timers)?.len(), 1);
    assert_eq!(
        state.next_evaluation_deadline(
            &graph,
            &timers,
            VirtualTime { ticks: 8 },
            Shift::new(2)?
        )?,
        None
    );
    assert!(
        state
            .next_evaluation_deadline(
                &graph,
                &timers,
                VirtualTime { ticks: 8 },
                Shift { bits: 64 }
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn activation_projection_distinguishes_negation_from_quiescent_bookkeeping() -> TestResult {
    let pulse = Condition::at(VirtualTime { ticks: 7 });
    let quiet = EventGraph::new(vec![Event::repeatable(
        EventId::from_name("quiet-at-seven"),
        Some(Condition::AllOf {
            predicates: vec![pulse.clone(), Condition::Quiescent],
        }),
        Action::Group(Vec::new()),
    )])?;
    let negated = EventGraph::new(vec![Event::repeatable(
        EventId::from_name("not-seven"),
        Some(Condition::Not {
            predicate: Box::new(pulse),
        }),
        Action::Group(Vec::new()),
    )])?;
    let state = EventGraphState::new();
    let timers = BTreeMap::new();
    let at = VirtualTime { ticks: 7 };
    let shift = Shift::new(0)?;
    assert_eq!(
        state.next_evaluation_deadline(&quiet, &timers, at, shift)?,
        Some(VirtualTime { ticks: 8 })
    );
    assert_eq!(
        state.next_activation_deadline(&quiet, &timers, at, shift)?,
        None
    );
    assert_eq!(
        state.next_activation_deadline(&negated, &timers, at, shift)?,
        Some(VirtualTime { ticks: 8 })
    );
    Ok(())
}

#[test]
fn intervening_once_latches_preserve_later_activation_and_overflow_is_terminal() -> TestResult {
    let graph = EventGraph::new(vec![Event::once(
        EventId::from_name("later"),
        Some(Condition::AllOf {
            predicates: vec![
                Condition::Once {
                    predicate: Box::new(Condition::at(VirtualTime { ticks: 7 })),
                },
                Condition::at(VirtualTime { ticks: 13 }),
            ],
        }),
        Action::Group(Vec::new()),
    )])?;
    let mut state = EventGraphState::new();
    let timers = BTreeMap::new();
    let shift = Shift::new(0)?;
    assert_eq!(
        state.next_activation_deadline(&graph, &timers, VirtualTime { ticks: 0 }, shift)?,
        Some(VirtualTime { ticks: 13 })
    );
    assert_eq!(
        state.next_evaluation_deadline(&graph, &timers, VirtualTime { ticks: 0 }, shift)?,
        Some(VirtualTime { ticks: 7 })
    );
    assert!(evaluate(&graph, &mut state, 7, &timers)?.is_empty());
    assert_eq!(
        state.next_activation_deadline(&graph, &timers, VirtualTime { ticks: 7 }, shift)?,
        Some(VirtualTime { ticks: 13 })
    );
    assert_eq!(evaluate(&graph, &mut state, 13, &timers)?.len(), 1);

    let final_pulse = EventGraph::new(vec![Event::repeatable(
        EventId::from_name("final"),
        Some(Condition::at(VirtualTime { ticks: u64::MAX })),
        Action::Group(Vec::new()),
    )])?;
    assert_eq!(
        state.next_evaluation_deadline(
            &final_pulse,
            &timers,
            VirtualTime { ticks: u64::MAX },
            shift
        )?,
        None
    );
    Ok(())
}

#[test]
fn leading_node_prefix_cannot_consume_a_global_time_trigger() -> TestResult {
    let graph = EventGraph::new(vec![Event::once(
        EventId::from_name("global"),
        Some(Condition::Once {
            predicate: Box::new(Condition::at(VirtualTime { ticks: 7 })),
        }),
        Action::Group(Vec::new()),
    )])?;
    let prefix = ConditionEventLogPrefix::from_evaluation_boundary(
        0,
        VirtualTime { ticks: 7 },
        SchedulerEvaluationBoundaryKind::Quantum,
    )?;
    let mut pass =
        ConditionEvaluationPass::from_log_prefix(prefix, |_leaf: crucible::ConditionLeaf<'_>| {
            false
        });
    let mut state = EventGraphState::new();
    let before = state.to_compact_binary();
    assert!(
        pass.evaluate_event_graph_at_frontier(&graph, &mut state, VirtualTime { ticks: 0 })
            .is_empty()
    );
    assert_eq!(state.to_compact_binary(), before);
    assert_eq!(
        pass.evaluate_event_graph_at_frontier(&graph, &mut state, VirtualTime { ticks: 7 })
            .len(),
        1
    );
    assert!(
        pass.evaluate_event_graph_at_frontier(&graph, &mut state, VirtualTime { ticks: 7 })
            .is_empty()
    );
    Ok(())
}
