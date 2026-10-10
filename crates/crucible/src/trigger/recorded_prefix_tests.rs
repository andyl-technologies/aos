//! Incremental recorded prefixes match whole-prefix reconstruction.

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

#[test]
fn cursor_prefixes_match_whole_prefix_reconstruction() {
    let recorded = RecordedAssertionLog::from_entries(atomic_marker_log(3, 2));
    let mut cursor = RecordedPrefixCursor::new(&recorded);
    let mut refused = 0;

    for prefix_len in 1..=recorded.entries().len() {
        let rebuilt = condition_prefix_from_recorded_log(&recorded, prefix_len, false);
        let extended = cursor.prefix(prefix_len, false).cloned();
        if rebuilt.is_err() {
            refused += 1;
        }
        assert_eq!(extended, rebuilt, "prefix length {prefix_len}");
    }

    // Each batch hides one marker behind its predecessor.
    assert_eq!(refused, 3);
}

#[test]
fn cursor_refuses_a_request_that_does_not_extend_its_prefix() {
    let recorded = RecordedAssertionLog::from_entries(atomic_marker_log(1, 2));
    let mut cursor = RecordedPrefixCursor::new(&recorded);

    assert!(cursor.prefix(2, false).is_ok());
    assert!(cursor.prefix(2, false).is_err());
    assert!(cursor.prefix(recorded.entries().len() + 1, false).is_err());
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
