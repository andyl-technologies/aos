//! Assertion folds of named leaves and console matchers are
//! partition-independent, checkpointed, and fail closed.

use super::assertion_fold::{AssertionFold, FoldedLeafStates, encode_named_state};
use super::*;
use crate::model::{NodeTemplate, VmArchitecture, WorldNode};

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
    assert_eq!(every_prefix.fold.to_wire(), terminal_only.fold.to_wire());
    assert_eq!(
        every_prefix.fold.states().values().collect::<Vec<_>>(),
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
    live.observe_prefix(&prefix(&entries[..5])?, &mut oracle);
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
            Err(OfflineAssertionCheckError::Fold(
                AssertionFoldFailure::StateLimit { ref name, bytes, .. }
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
    assert_eq!(evaluator.assertion_fold_failure(), None);
    evaluator.observe_prefix(&prefix(&entries[..2])?, &mut oracle);

    assert!(matches!(
        evaluator.assertion_fold_failure(),
        Some(AssertionFoldFailure::Refused { name, error, .. })
            if name == "no-events" && error.message() == "events are not expected"
    ));
    assert!(evaluator.fold.states().is_empty());
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
        evaluator.assertion_fold_failure(),
        Some(&AssertionFoldFailure::Discontinuous {
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
    assert_eq!(restored.fold, evaluator.fold);

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

fn console_entry(sequence: u64, at: u64, bytes: &[u8]) -> SchedulerEventLogEntry {
    let event = ObservableEvent::console_output(VirtualTime { ticks: at }, node(), bytes.to_vec());
    SchedulerEventLogEntry::with_payload_for_test(
        sequence,
        event.at(),
        SchedulerEventLogPayload::Observable(event.payload().clone()),
    )
}

fn node() -> NodeId {
    NodeId {
        name: String::from("server"),
    }
}

/// A line split across two console writes, then an unrelated write.
///
/// A console match is true only at the instant it ends, so the boundary at
/// tick 3 is where an evaluator can observe it.
fn console_log() -> Vec<SchedulerEventLogEntry> {
    vec![
        boundary_entry(0, 1),
        console_entry(1, 2, b"rea"),
        boundary_entry(2, 2),
        console_entry(3, 3, b"dy\n"),
        boundary_entry(4, 3),
        console_entry(5, 5, b"later\n"),
        boundary_entry(6, 6),
    ]
}

fn console_world() -> TestResult<World> {
    Ok(World::from_nodes(vec![WorldNode {
        id: node(),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?)
}

fn console_ready(pattern: &str) -> TestResult<Properties> {
    Ok(Properties::from_assertions_for_world(
        &console_world()?,
        vec![AssertionDef {
            id: AssertionId::from_name("console"),
            message: String::from("console assertion"),
            property: Property::Sometimes {
                predicate: Predicate::console_match(node(), RegexProgram::from_pattern(pattern)),
            },
        }],
    )?)
}

#[test]
fn console_matchers_fold_once_per_entry_without_a_declaring_prefix() -> TestResult {
    let properties = console_ready("ready\\n")?;
    let entries = console_log();
    let mut oracle = BlackBoxHostOracle;

    // The prefixes declare no console matcher; the evaluator folds its own.
    let mut every_prefix = HostAssertionEvaluator::new(&properties);
    for len in 1..entries.len() {
        every_prefix.observe_prefix(&prefix(&entries[..len])?, &mut oracle);
    }
    let every_report = every_prefix.finalize_prefix(&prefix(&entries)?, &mut oracle);

    let mut terminal_only = HostAssertionEvaluator::new(&properties);
    terminal_only.finalize_prefix(&prefix(&entries)?, &mut oracle);

    assert_eq!(every_prefix.fold.to_wire(), terminal_only.fold.to_wire());
    assert_eq!(every_report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(every_prefix.assertion_fold_failure(), None);
    Ok(())
}

#[test]
fn console_matchers_reach_the_offline_verdict() -> TestResult {
    let properties = console_ready("ready\\n")?;
    let entries = console_log();
    let mut oracle = BlackBoxHostOracle;

    let mut live = HostAssertionEvaluator::new(&properties);
    live.observe_prefix(&prefix(&entries[..3])?, &mut oracle);
    live.observe_prefix(&prefix(&entries[..5])?, &mut oracle);
    let live_report = live.finalize_prefix(&prefix(&entries)?, &mut oracle);
    let mut check =
        OfflineAssertionChecker::new().start_check(&properties, RecordedLogShape::of(&entries));
    for entry in &entries {
        check.push(entry.clone(), &mut oracle);
    }
    let offline_report = check.finish(&mut oracle)?;

    assert_eq!(offline_report.verdict(), live_report.verdict());
    Ok(())
}

#[test]
fn checkpoints_carry_console_matchers_and_bind_to_their_patterns() -> TestResult {
    let properties = console_ready("ready\\n")?;
    let entries = console_log();
    let mut oracle = BlackBoxHostOracle;
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    // Checkpoint between the two halves of the line.
    let checkpoint_prefix = prefix(&entries[..3])?;
    evaluator.observe_prefix(&checkpoint_prefix, &mut oracle);

    let bytes = evaluator.checkpoint().canonical_bytes()?;
    let checkpoint = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&bytes)?;
    let mut restored = HostAssertionEvaluator::new(&properties);
    checkpoint.restore_into(&mut restored, &checkpoint_prefix)?;
    assert_eq!(restored.fold, evaluator.fold);

    let matched = prefix(&entries[..5])?;
    restored.observe_prefix(&matched, &mut oracle);
    evaluator.observe_prefix(&matched, &mut oracle);
    let terminal = prefix(&entries)?;
    let restored_report = restored.finalize_prefix(&terminal, &mut oracle);
    assert_eq!(restored_report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        restored_report,
        evaluator.finalize_prefix(&terminal, &mut oracle)
    );

    let other_pattern = console_ready("later\\n")?;
    let mut mismatched = HostAssertionEvaluator::new(&other_pattern);
    assert_eq!(
        checkpoint.restore_into(&mut mismatched, &checkpoint_prefix),
        Err(HostAssertionCheckpointError::Binding)
    );
    Ok(())
}

/// Builds the `sequence`th entry: one native console byte emitted at `at`.
fn native_console_entry(sequence: u64, at: u64, byte: u8) -> TestResult<SchedulerEventLogEntry> {
    let event = ObservableEvent::native_console_byte(
        VirtualTime { ticks: at },
        node(),
        crate::NativeConsoleByteOrigin {
            device: ContentHash { bytes: [9; 32] },
            stream: 1,
            logical_generation: 0,
            node_sequence: sequence + 1,
            stream_sequence: sequence + 1,
            emitted_ps: at,
            raw_prefix: 0,
            vcpu: 0,
            byte,
        },
    )?;
    Ok(SchedulerEventLogEntry::with_payload_for_test(
        sequence,
        event.at(),
        SchedulerEventLogPayload::Observable(event.payload().clone()),
    ))
}

/// One quantum whose native bytes complete `ok` before its t=200 frontier,
/// then a quantum without console output.
fn native_console_log() -> TestResult<Vec<SchedulerEventLogEntry>> {
    Ok(vec![
        native_console_entry(0, 100, b'o')?,
        native_console_entry(1, 100, b'k')?,
        boundary_entry(2, 200),
        boundary_entry(3, 300),
    ])
}

#[test]
fn native_console_matches_hold_at_the_boundary_of_their_quantum() -> TestResult {
    let properties = console_ready("ok")?;
    let entries = native_console_log()?;
    let mut oracle = BlackBoxHostOracle;

    let mut live = HostAssertionEvaluator::new(&properties);
    live.observe_prefix(&prefix(&entries[..3])?, &mut oracle);
    let live_report = live.finalize_prefix(&prefix(&entries)?, &mut oracle);

    assert_eq!(live_report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(live.assertion_fold_failure(), None);
    Ok(())
}

#[test]
fn checkpoints_between_a_native_match_and_its_boundary_resume_identically() -> TestResult {
    let properties = console_ready("ok")?;
    let entries = native_console_log()?;
    let mut oracle = BlackBoxHostOracle;
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    // Checkpoint after the byte that completes the match, before its boundary.
    let checkpoint_prefix = prefix(&entries[..2])?;
    evaluator.observe_prefix(&checkpoint_prefix, &mut oracle);

    let bytes = evaluator.checkpoint().canonical_bytes()?;
    let checkpoint = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&bytes)?;
    let mut restored = HostAssertionEvaluator::new(&properties);
    checkpoint.restore_into(&mut restored, &checkpoint_prefix)?;
    assert_eq!(restored.fold, evaluator.fold);

    let quantum = prefix(&entries[..3])?;
    restored.observe_prefix(&quantum, &mut oracle);
    evaluator.observe_prefix(&quantum, &mut oracle);
    assert_eq!(restored.fold, evaluator.fold);
    let terminal = prefix(&entries)?;
    let restored_report = restored.finalize_prefix(&terminal, &mut oracle);
    assert_eq!(restored_report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        restored_report,
        evaluator.finalize_prefix(&terminal, &mut oracle)
    );
    Ok(())
}

#[test]
fn unstreamable_console_patterns_fail_the_fold_at_declaration() {
    let refused = Predicate::console_match(node(), RegexProgram::from_pattern("ready$"));

    let fold = AssertionFold::declared_by([&refused]);

    assert!(matches!(
        fold.failure(),
        Some(AssertionFoldFailure::ConsolePattern { pattern, .. }) if pattern == "ready$"
    ));
}

#[test]
fn undeclared_console_matchers_answer_false_and_fail_closed() {
    let fold = AssertionFold::declared_by(std::iter::empty());
    let mut oracle = BlackBoxHostOracle;
    let mut leaves = FoldedLeafStates::new(&mut oracle, fold.states(), fold.console());

    let matched = leaves.console_match(&node(), "ready", VirtualTime { ticks: 3 });

    assert!(!matched);
    assert_eq!(
        leaves.into_failure(),
        Some(AssertionFoldFailure::UndeclaredConsoleMatcher(
            UndeclaredConsoleMatcher {
                node: node(),
                pattern: String::from("ready"),
            }
        ))
    );
}
