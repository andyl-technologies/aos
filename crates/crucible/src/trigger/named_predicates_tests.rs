//! Named predicate folds are partition-independent and fail closed.

use super::named_predicates::encode_named_state;
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn frame_entry(sequence: u64, at: u64, frame: &[u8]) -> SchedulerEventLogEntry {
    let event = ObservableEvent::network_delivered(VirtualTime { ticks: at }, None, frame.to_vec());
    SchedulerEventLogEntry::with_payload_for_test(
        sequence,
        event.at(),
        SchedulerEventLogPayload::Observable(event.payload().clone()),
    )
}

fn boundary_entry(sequence: u64, at: u64) -> SchedulerEventLogEntry {
    SchedulerEventLogEntry::evaluation_boundary(
        sequence,
        VirtualTime { ticks: at },
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

/// Boundaries interleaved with frames, every prefix of which is valid.
fn frame_log() -> Vec<SchedulerEventLogEntry> {
    vec![
        boundary_entry(0, 1),
        frame_entry(1, 2, b"first"),
        boundary_entry(2, 2),
        frame_entry(3, 3, b"second"),
        boundary_entry(4, 4),
    ]
}

fn prefix(entries: &[SchedulerEventLogEntry]) -> TestResult<ConditionEventLogPrefix> {
    Ok(ConditionEventLogPrefix::from_scheduler_event_log_entries(
        entries.to_vec(),
    )?)
}

fn named_properties(property: Property) -> TestResult<Properties> {
    let world = World::from_nodes(Vec::new())?;
    Ok(Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("named"),
            message: String::from("named predicate assertion"),
            property,
        }],
    )?)
}

fn sometimes(name: &str) -> TestResult<Properties> {
    named_properties(Property::Sometimes {
        predicate: Predicate::named(name),
    })
}

/// Counts folded observable events and points; holds once two events arrived.
struct CountEvents;

impl HostAssertionPredicate for CountEvents {
    type State = (u64, u64);

    fn initial(&self, _leaf: NamedLeaf<'_>) -> (u64, u64) {
        (0, 0)
    }

    fn step(
        &self,
        _leaf: NamedLeaf<'_>,
        (events, points): &(u64, u64),
        batch: &ObservedBatch<'_>,
    ) -> Result<(u64, u64), NamedPredicateError> {
        Ok((events + batch.observable_events().len() as u64, points + 1))
    }

    fn leaf_is_true(&self, _leaf: NamedLeaf<'_>, (events, _points): &(u64, u64)) -> bool {
        *events >= 2
    }
}

/// Grows its state by 40 KiB per folded entry.
struct GrowingState;

impl HostAssertionPredicate for GrowingState {
    type State = Vec<u8>;

    fn initial(&self, _leaf: NamedLeaf<'_>) -> Vec<u8> {
        Vec::new()
    }

    fn step(
        &self,
        _leaf: NamedLeaf<'_>,
        state: &Vec<u8>,
        _batch: &ObservedBatch<'_>,
    ) -> Result<Vec<u8>, NamedPredicateError> {
        let mut state = state.clone();
        state.resize(state.len() + 40 * 1024, 0);
        Ok(state)
    }

    fn leaf_is_true(&self, _leaf: NamedLeaf<'_>, _state: &Vec<u8>) -> bool {
        true
    }
}

/// Refuses the first batch carrying an observable event.
struct RefuseEvents;

impl HostAssertionPredicate for RefuseEvents {
    type State = ();

    fn initial(&self, _leaf: NamedLeaf<'_>) {}

    fn step(
        &self,
        _leaf: NamedLeaf<'_>,
        _state: &(),
        batch: &ObservedBatch<'_>,
    ) -> Result<(), NamedPredicateError> {
        if batch.observable_events().is_empty() {
            Ok(())
        } else {
            Err(NamedPredicateError::new("events are not expected"))
        }
    }

    fn leaf_is_true(&self, _leaf: NamedLeaf<'_>, _state: &()) -> bool {
        false
    }
}

#[test]
fn fold_states_do_not_depend_on_which_prefixes_are_observed() -> TestResult {
    let properties = sometimes("two-events")?;
    let entries = frame_log();
    let mut oracle = unchecked_host_assertion_oracle_for_test(CountEvents);

    let mut every_prefix = HostAssertionEvaluator::new(&properties);
    for len in 1..entries.len() {
        every_prefix.observe_prefix(&prefix(&entries[..len])?, &mut oracle);
    }
    every_prefix.finalize_prefix(&prefix(&entries)?, &mut oracle);

    let mut terminal_only = HostAssertionEvaluator::new(&properties);
    terminal_only.finalize_prefix(&prefix(&entries)?, &mut oracle);

    let expected = encode_named_state(NamedLeaf::new("two-events", &[]), &(2_u64, 5_u64))?;
    assert_eq!(every_prefix.named.to_wire(), terminal_only.named.to_wire());
    assert_eq!(
        every_prefix.named.states().values().collect::<Vec<_>>(),
        vec![&expected],
        "every entry is folded exactly once"
    );
    Ok(())
}

#[test]
fn live_and_offline_folds_reach_the_same_verdict() -> TestResult {
    let properties = sometimes("two-events")?;
    let entries = frame_log();
    let mut oracle = unchecked_host_assertion_oracle_for_test(CountEvents);

    let mut live = HostAssertionEvaluator::new(&properties);
    live.observe_prefix(&prefix(&entries[..3])?, &mut oracle);
    let live_report = live.finalize_prefix(&prefix(&entries)?, &mut oracle);
    let mut check =
        OfflineAssertionChecker::new().start_check(&properties, RecordedLogShape::of(&entries));
    for entry in &entries {
        check.push(entry.clone(), &mut oracle);
    }
    let offline_report = check.finish(&mut oracle)?;

    assert_eq!(live_report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(offline_report.verdict(), live_report.verdict());
    Ok(())
}

#[test]
fn oversized_states_fail_the_offline_check_closed() -> TestResult {
    let properties = sometimes("growing")?;
    let entries = frame_log();
    let mut oracle = unchecked_host_assertion_oracle_for_test(GrowingState);

    let mut check =
        OfflineAssertionChecker::new().start_check(&properties, RecordedLogShape::of(&entries));
    for entry in &entries {
        check.push(entry.clone(), &mut oracle);
    }
    let result = check.finish(&mut oracle);

    assert!(
        matches!(
            result,
            Err(OfflineAssertionCheckError::NamedPredicate(
                NamedPredicateFailure::StateLimit { ref name, bytes, .. }
            )) if name == "growing" && bytes > MAX_NAMED_PREDICATE_STATE_BYTES
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn refused_batches_stop_the_fold_and_answer_false() -> TestResult {
    let properties = sometimes("no-events")?;
    let entries = frame_log();
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = unchecked_host_assertion_oracle_for_test(RefuseEvents);

    evaluator.observe_prefix(&prefix(&entries[..1])?, &mut oracle);
    assert_eq!(evaluator.named_predicate_failure(), None);
    evaluator.observe_prefix(&prefix(&entries[..2])?, &mut oracle);

    assert!(matches!(
        evaluator.named_predicate_failure(),
        Some(NamedPredicateFailure::Refused { name, error, .. })
            if name == "no-events" && error.message() == "events are not expected"
    ));
    assert!(evaluator.named.states().is_empty());
    Ok(())
}

#[test]
fn a_prefix_of_another_log_fails_closed() -> TestResult {
    let properties = sometimes("two-events")?;
    let entries = frame_log();
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = unchecked_host_assertion_oracle_for_test(CountEvents);
    evaluator.observe_prefix(&prefix(&entries[..2])?, &mut oracle);

    let other = vec![
        boundary_entry(0, 1),
        boundary_entry(1, 2),
        boundary_entry(2, 3),
    ];
    evaluator.observe_prefix(&prefix(&other)?, &mut oracle);

    assert_eq!(
        evaluator.named_predicate_failure(),
        Some(&NamedPredicateFailure::Discontinuous {
            folded: 2,
            base_sequence: 0,
            end_sequence: 3,
        })
    );
    Ok(())
}

#[test]
fn checkpoints_carry_states_and_bind_to_declared_leaves() -> TestResult {
    let properties = sometimes("two-events")?;
    let entries = frame_log();
    let mut oracle = unchecked_host_assertion_oracle_for_test(CountEvents);
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let checkpoint_prefix = prefix(&entries[..2])?;
    evaluator.observe_prefix(&checkpoint_prefix, &mut oracle);

    let bytes = evaluator.checkpoint().canonical_bytes()?;
    let checkpoint = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&bytes)?;
    let mut restored = HostAssertionEvaluator::new(&properties);
    checkpoint.restore_into(&mut restored, &checkpoint_prefix)?;
    assert_eq!(restored.named, evaluator.named);

    let terminal = prefix(&entries)?;
    assert_eq!(
        restored.finalize_prefix(&terminal, &mut oracle),
        evaluator.finalize_prefix(&terminal, &mut oracle)
    );

    let renamed = sometimes("other-leaf")?;
    let mut mismatched = HostAssertionEvaluator::new(&renamed);
    assert_eq!(
        checkpoint.restore_into(&mut mismatched, &checkpoint_prefix),
        Err(HostAssertionCheckpointError::Binding)
    );
    Ok(())
}
