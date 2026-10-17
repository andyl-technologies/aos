//! Streaming offline checks defer atomic batches and validate the declared shape.

use super::*;
use crate::model::{NodeTemplate, VmArchitecture, WorldNode};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn node() -> NodeId {
    NodeId {
        name: String::from("vm-a"),
    }
}

fn marker_entry(sequence: u64, at: u64, name: &str) -> SchedulerEventLogEntry {
    let event =
        ObservableEvent::guest_marker(Icount { retired: at }, node(), MarkerId::from_name(name));
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

fn next_sequence(entries: &[SchedulerEventLogEntry]) -> u64 {
    entries.last().map_or(0, |entry| entry.sequence() + 1)
}

/// Builds batches of quantum boundaries closed by one atomic marker pair.
///
/// The second marker precedes the first, so the prefix ending at it hides an
/// entry and is refused until the batch's closing boundary admits both.
fn atomic_marker_log(batches: u64, boundaries_per_batch: u64) -> Vec<SchedulerEventLogEntry> {
    let mut entries = Vec::new();
    let mut at = 0;
    for _batch in 0..batches {
        for _boundary in 0..boundaries_per_batch {
            at += 10;
            entries.push(boundary_entry(next_sequence(&entries), at));
        }
        entries.push(marker_entry(next_sequence(&entries), at + 5, "traffic"));
        entries.push(marker_entry(next_sequence(&entries), at + 1, "late"));
        entries.push(boundary_entry(next_sequence(&entries), at + 5));
        at += 5;
    }
    entries
}

fn white_box_world() -> TestResult<World> {
    Ok(World::from_nodes(vec![WorldNode {
        id: node(),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?)
}

fn marker_properties(world: &World) -> TestResult<Properties> {
    Ok(Properties::from_assertions_for_world(
        world,
        vec![AssertionDef::guest_sometimes(
            AssertionId::from_name("traffic"),
            "traffic is observed",
        )],
    )?)
}

#[test]
fn atomic_batches_closed_by_a_boundary_are_deferred() -> TestResult {
    let world = white_box_world()?;
    let properties = marker_properties(&world)?;
    let event_log = atomic_marker_log(3, 2);
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);

    let whole = checker.check_run(&properties, &event_log)?;
    let mut oracle = BlackBoxHostOracle;
    let mut streamed = checker.start_check(&properties, RecordedLogShape::of(&event_log));
    for entry in &event_log {
        streamed.push(entry.clone(), &mut oracle);
    }

    assert_eq!(streamed.finish(&mut oracle)?, whole);
    Ok(())
}

#[test]
fn an_atomic_batch_without_its_boundary_is_refused() -> TestResult {
    let world = white_box_world()?;
    let properties = marker_properties(&world)?;
    let mut event_log = atomic_marker_log(1, 2);
    // Replace the batch's closing boundary with a diagnostic entry, so the
    // late marker's prefix hides the earlier one with no boundary to defer to.
    let closing = event_log.len() - 1;
    let at = event_log[closing].at();
    event_log[closing] =
        SchedulerEventLogEntry::execution_budget_exhausted(closing as u64, at, "virtual-time");
    event_log.push(boundary_entry(next_sequence(&event_log), at.ticks + 10));

    let checked = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .check_run(&properties, &event_log);

    assert!(
        matches!(
            checked,
            Err(OfflineAssertionCheckError::ConditionEvaluation(
                ConditionEvaluationError::FutureEventLogEntry { .. }
            ))
        ),
        "an unclosed atomic batch cannot be deferred: {checked:?}"
    );
    Ok(())
}

#[test]
fn streamed_trace_hash_matches_the_exported_trace() {
    let event_log = atomic_marker_log(2, 3);
    let mut streamed = ExternalFormalTraceHash::new(event_log.len() as u64);
    for entry in &event_log {
        streamed.update(entry);
    }

    assert_eq!(
        streamed.finish(),
        ContentHash::from_bytes(&external_formal_trace_bytes(&event_log))
    );
}

#[test]
fn entries_must_match_the_declared_shape() -> TestResult {
    let world = white_box_world()?;
    let properties = marker_properties(&world)?;
    let event_log = atomic_marker_log(1, 2);
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(&world);
    let mut oracle = BlackBoxHostOracle;

    let mut short = checker.start_check(&properties, RecordedLogShape::of(&event_log));
    for entry in &event_log[..event_log.len() - 1] {
        short.push(entry.clone(), &mut oracle);
    }
    assert_eq!(
        short.finish(&mut oracle),
        Err(OfflineAssertionCheckError::RecordedLogShapeMismatch)
    );

    let mut long = checker.start_check(
        &properties,
        RecordedLogShape::of(&event_log[..event_log.len() - 1]),
    );
    for entry in &event_log {
        long.push(entry.clone(), &mut oracle);
    }
    assert_eq!(
        long.finish(&mut oracle),
        Err(OfflineAssertionCheckError::RecordedLogShapeMismatch)
    );
    Ok(())
}

/// Mirrors a long production log: mostly boundaries with sparse observations
/// and declared guest-marker states, which observe every intermediate prefix.
#[test]
fn declared_guest_markers_check_a_long_boundary_log() -> TestResult {
    let world = white_box_world()?;
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![
            AssertionDef::guest_unreachable(
                AssertionId::from_name("persistent-forwarding-loop"),
                "no forwarding loop",
            ),
            AssertionDef::guest_unreachable(
                AssertionId::from_name("forbidden-destination-delivery"),
                "no forbidden delivery",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("bounded-recovery-outcome"),
                "recovery is bounded",
            ),
        ],
    )?;
    let event_log = atomic_marker_log(640, 60);

    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .check_run(&properties, &event_log)?;

    assert_eq!(event_log.len(), 40_320);
    assert_eq!(report.outcomes().len(), 3);
    Ok(())
}
