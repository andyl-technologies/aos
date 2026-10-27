//! Checks live assertion continuation over authenticated growing log prefixes.

#![forbid(unsafe_code)]

use crucible_engine::{
    AssertionDef, AssertionId, AssertionRunVerdict, EventLog, HostAssertionCheckpointError,
    HostAssertionEvaluator, HostAssertionEvaluatorCheckpoint, HostAssertionOutcomeKind, NamedLeaf,
    ObservedBatch, Predicate, Properties, Property, SchedulerEvaluationBoundaryKind, VirtualTime,
    World,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn append_boundaries(log: &mut EventLog, count: u64) -> TestResult {
    let start = log.offset().events;
    let entries = (start..start + count)
        .map(|sequence| {
            crucible_engine::test_support::condition_boundary_entry_for_test(
                sequence,
                time(sequence + 1),
                SchedulerEvaluationBoundaryKind::Quantum,
            )
        })
        .collect();
    log.append_entries(entries)?;
    Ok(())
}

#[test]
fn growing_authenticated_history_preserves_empty_continuation() -> TestResult {
    let properties = Properties::empty();

    for initial_entries in [512, 2048, 10958] {
        let mut log = EventLog::new();
        append_boundaries(&mut log, initial_entries)?;
        let mut evaluator = HostAssertionEvaluator::new(&properties);
        let mut oracle = crucible_engine::BlackBoxHostOracle;

        for _ in 0..64 {
            append_boundaries(&mut log, 1)?;
            assert!(
                evaluator
                    .observe_prefix(log.condition_prefix(), &mut oracle)
                    .is_empty()
            );
        }
        let encoded = evaluator.checkpoint().canonical_bytes()?;
        let checkpoint = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&encoded)?;
        let mut restored = HostAssertionEvaluator::new(&properties);
        checkpoint.restore_into(&mut restored, log.condition_prefix())?;

        assert_eq!(restored.checkpoint().canonical_bytes()?, encoded);
        append_boundaries(&mut log, 1)?;
        assert_eq!(
            restored.finalize_prefix(log.condition_prefix(), &mut oracle),
            evaluator.finalize_prefix(log.condition_prefix(), &mut oracle)
        );
        println!(
            "live_assertion_continuation initial_entries={initial_entries} observations=64 checkpoint_hash={}",
            blake3::hash(&encoded)
        );
    }
    Ok(())
}

#[test]
fn restored_deadline_crossing_preserves_equal_points() -> TestResult {
    let world = World::from_nodes(Vec::new())?;
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("deadline-crossing"),
            message: "The original deadline remains observable after restore".into(),
            property: Property::Eventually {
                trigger: Predicate::named("trigger"),
                property: Predicate::named("at-deadline"),
                deadline: time(2),
            },
        }],
    )?;
    // The second boundary repeats the first point; the third crosses the
    // deadline at 5 without an entry there.
    let entries = [3, 3, 10]
        .into_iter()
        .zip(0..)
        .map(|(ticks, sequence)| {
            crucible_engine::test_support::condition_boundary_entry_for_test(
                sequence,
                time(ticks),
                SchedulerEvaluationBoundaryKind::Quantum,
            )
        })
        .collect::<Vec<_>>();
    let prefix = |len: usize| {
        crucible_engine::test_support::condition_prefix_from_scheduler_entries_for_test(
            entries[..len].to_vec(),
        )
    };
    let first = prefix(1)?;
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = crucible_engine::test_support::unchecked_host_assertion_oracle_for_test(
        |leaf: NamedLeaf<'_>, batch: &ObservedBatch<'_>| match leaf.name() {
            "trigger" => batch.at() == time(3),
            "at-deadline" => batch.at() == time(5),
            _ => false,
        },
    );
    evaluator.observe_prefix(&first, &mut oracle);
    let encoded = evaluator.checkpoint().canonical_bytes()?;
    let checkpoint = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&encoded)?;
    let mut restored = HostAssertionEvaluator::new(&properties);
    checkpoint.restore_into(&mut restored, &first)?;

    for len in [2, 3] {
        let prefix = prefix(len)?;
        assert_eq!(
            restored.observe_prefix(&prefix, &mut oracle),
            evaluator.observe_prefix(&prefix, &mut oracle)
        );
        assert_eq!(
            restored.checkpoint().canonical_bytes()?,
            evaluator.checkpoint().canonical_bytes()?
        );
    }
    let terminal = prefix(entries.len())?;
    let report = evaluator.finalize_prefix(&terminal, &mut oracle);

    assert_eq!(report, restored.finalize_prefix(&terminal, &mut oracle));
    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(report.outcomes().len(), 1);
    assert_eq!(
        report.outcomes()[0].kind,
        HostAssertionOutcomeKind::Satisfied
    );
    assert_eq!(report.outcomes()[0].at, time(5));
    println!(
        "live_assertion_deadline checkpoint_hash={}",
        blake3::hash(&encoded)
    );
    Ok(())
}

#[test]
fn mismatched_prefix_restore_preserves_original_continuation() -> TestResult {
    let properties = Properties::empty();
    let mut log = EventLog::new();
    append_boundaries(&mut log, 128)?;
    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = crucible_engine::BlackBoxHostOracle;
    evaluator.observe_prefix(log.condition_prefix(), &mut oracle);
    let checkpoint = evaluator.checkpoint();
    append_boundaries(&mut log, 1)?;
    let mut target = HostAssertionEvaluator::new(&properties);
    target.observe_prefix(log.condition_prefix(), &mut oracle);
    let before = target.checkpoint().canonical_bytes()?;

    assert_eq!(
        checkpoint.restore_into(&mut target, log.condition_prefix()),
        Err(HostAssertionCheckpointError::Binding)
    );
    assert_eq!(target.checkpoint().canonical_bytes()?, before);
    Ok(())
}
