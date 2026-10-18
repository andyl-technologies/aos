//! Continuing prefixes leave end-of-run obligations undecided.

use super::*;
use crate::model::{NodeTemplate, VmArchitecture, WorldNode};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn node() -> NodeId {
    NodeId {
        name: String::from("vm-a"),
    }
}

/// Builds a true guest assertion marker carrying its declared `message`.
fn guest_assertion_entry(
    sequence: u64,
    at: u64,
    id: &str,
    message: &str,
    kind: GuestAssertionKind,
) -> SchedulerEventLogEntry {
    let event = ObservableEvent::guest_assertion_marker(
        Icount { retired: at },
        node(),
        GuestAssertionMarker::new(
            AssertionId::from_name(id),
            String::from(message),
            kind,
            true,
            false,
            Vec::new(),
            format!("{id}.rs:1"),
        ),
    );
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

/// Declares one guest existential, one guest safety marker, and one host
/// existential whose predicate never holds within the test logs.
fn mixed_properties(world: &World) -> TestResult<Properties> {
    Ok(Properties::from_assertions_for_world(
        world,
        vec![
            AssertionDef::guest_sometimes(AssertionId::from_name("recovered"), "recovery happens"),
            AssertionDef::guest_unreachable(
                AssertionId::from_name("forbidden"),
                "no forbidden delivery",
            ),
            AssertionDef {
                id: AssertionId::from_name("late-deadline"),
                message: String::from("the late deadline is reached"),
                property: Property::Sometimes {
                    predicate: Predicate::At {
                        at: VirtualTime { ticks: u64::MAX },
                    },
                },
            },
        ],
    )?)
}

fn check(
    world: &World,
    log: &[SchedulerEventLogEntry],
    continuing: bool,
) -> TestResult<HostAssertionReport> {
    let checker = OfflineAssertionChecker::new().with_world_white_box_policies(world);
    let checker = if continuing {
        checker.with_continuing_prefix()
    } else {
        checker
    };
    Ok(checker.check_run(&mixed_properties(world)?, log)?)
}

fn outcome_kind(report: &HostAssertionReport, assertion: &str) -> Option<HostAssertionOutcomeKind> {
    report
        .outcomes()
        .iter()
        .find(|outcome| outcome.assertion.name == assertion)
        .map(|outcome| outcome.kind)
}

#[test]
fn continuing_prefix_leaves_unreached_existentials_undecided() -> TestResult {
    let world = white_box_world()?;
    let log = [boundary_entry(0, 10), boundary_entry(1, 20)];

    let terminal = check(&world, &log, false)?;
    let continuing = check(&world, &log, true)?;

    for existential in ["recovered", "late-deadline"] {
        assert_eq!(
            outcome_kind(&terminal, existential),
            Some(HostAssertionOutcomeKind::Violated)
        );
        assert_eq!(
            outcome_kind(&continuing, existential),
            Some(HostAssertionOutcomeKind::Undecided)
        );
    }
    assert_eq!(
        outcome_kind(&continuing, "forbidden"),
        Some(HostAssertionOutcomeKind::Passed)
    );
    assert!(continuing.verdict().failures().is_empty());
    Ok(())
}

#[test]
fn continuing_prefix_still_fails_decided_violations() -> TestResult {
    let world = white_box_world()?;
    let log = [
        boundary_entry(0, 10),
        guest_assertion_entry(
            1,
            15,
            "forbidden",
            "no forbidden delivery",
            GuestAssertionKind::Unreachable,
        ),
        guest_assertion_entry(
            2,
            16,
            "recovered",
            "recovery happens",
            GuestAssertionKind::Sometimes,
        ),
        boundary_entry(3, 20),
    ];

    let continuing = check(&world, &log, true)?;

    assert_eq!(
        outcome_kind(&continuing, "forbidden"),
        Some(HostAssertionOutcomeKind::Violated)
    );
    assert_eq!(
        outcome_kind(&continuing, "recovered"),
        Some(HostAssertionOutcomeKind::Satisfied)
    );
    assert_eq!(continuing.verdict().failures().len(), 1);
    Ok(())
}
