//! Checks T-GHC-1 black-box guest/host observation surface.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use crucible::{
    AssertionId, BLACK_BOX_OBSERVATION_KIND_COUNT, BLACK_BOX_OBSERVATION_KINDS,
    BlackBoxObservationKind, ConditionEvaluationError, EventClass, EventLog, EventLogIcountStamp,
    GuestAssertionDetail, GuestAssertionKind, GuestAssertionMarker, Icount, IoEventKind, MarkerId,
    NodeId, NodeLifecycle, ObservableEvent, ResolvedMemPlace, SchedulerEvaluationBoundaryKind,
    VirtualTime,
};

#[test]
fn black_box_surface_catalog_is_closed_and_complete() {
    let actual = BLACK_BOX_OBSERVATION_KINDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        BlackBoxObservationKind::NetworkTraffic,
        BlackBoxObservationKind::DiskOrNinePIo,
        BlackBoxObservationKind::ConsoleSerialOutput,
        BlackBoxObservationKind::ArchitecturalStateSample,
        BlackBoxObservationKind::RunOutcome,
        BlackBoxObservationKind::CrashOrHangDetection,
        BlackBoxObservationKind::BasicBlockCoverage,
    ]);

    assert_eq!(BLACK_BOX_OBSERVATION_KIND_COUNT, 7);
    assert_eq!(BLACK_BOX_OBSERVATION_KINDS.len(), 7);
    assert_eq!(actual, expected);
}

#[test]
fn black_box_surface_events_are_icount_stamped_observational_entries() {
    let expected_surface = BTreeSet::from([
        BlackBoxObservationKind::NetworkTraffic,
        BlackBoxObservationKind::DiskOrNinePIo,
        BlackBoxObservationKind::ConsoleSerialOutput,
        BlackBoxObservationKind::ArchitecturalStateSample,
        BlackBoxObservationKind::RunOutcome,
        BlackBoxObservationKind::CrashOrHangDetection,
        BlackBoxObservationKind::BasicBlockCoverage,
    ]);
    let cases = [
        (
            BlackBoxObservationKind::NetworkTraffic,
            ObservableEvent::network_delivered(time(10), None, b"raft:append".to_vec()),
            10,
            None,
            "network_delivered",
        ),
        (
            BlackBoxObservationKind::DiskOrNinePIo,
            ObservableEvent::io_completion(
                time(11),
                node("db-0"),
                IoEventKind::NineP,
                b"walk /srv".to_vec(),
            ),
            11,
            Some(node("db-0")),
            "observed_io_completion",
        ),
        (
            BlackBoxObservationKind::ConsoleSerialOutput,
            ObservableEvent::console_output(time(12), node("db-0"), b"login: ".to_vec()),
            12,
            Some(node("db-0")),
            "console_output",
        ),
        (
            BlackBoxObservationKind::ArchitecturalStateSample,
            ObservableEvent::memory_sample(
                time(13),
                icount(13),
                node("db-0"),
                ResolvedMemPlace::register("rax", 8),
                0xfeed,
            ),
            13,
            Some(node("db-0")),
            "memory_sample",
        ),
        (
            BlackBoxObservationKind::RunOutcome,
            ObservableEvent::node_state(time(14), node("db-0"), NodeLifecycle::Exited),
            14,
            Some(node("db-0")),
            "node_state",
        ),
        (
            BlackBoxObservationKind::CrashOrHangDetection,
            ObservableEvent::node_state(time(15), node("db-0"), NodeLifecycle::Hung),
            15,
            Some(node("db-0")),
            "node_state",
        ),
        (
            BlackBoxObservationKind::BasicBlockCoverage,
            ObservableEvent::coverage_block(icount(16), node("db-0"), 0x4010, 0x20),
            16,
            Some(node("db-0")),
            "coverage",
        ),
    ];

    let mut entries = Vec::new();
    for (sequence, (kind, event, expected_icount, expected_node, payload_kind)) in
        cases.into_iter().enumerate()
    {
        assert_eq!(event.black_box_observation_kind(), Some(kind));

        let entry =
            crucible::test_support::condition_observation_entry_for_test(sequence as u64, &event);
        assert_eq!(entry.class(), EventClass::Observational);
        assert_eq!(entry.time().icount.icount, icount(expected_icount));
        assert_eq!(&entry.time().icount.node, &expected_node);
        assert_eq!(entry.event_payload().kind(), payload_kind);
        entries.push(entry);
    }

    let prefix =
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(entries.clone())
            .expect("black-box observation entries should form a checked condition prefix");
    assert_eq!(prefix.black_box_observation_kinds(), &expected_surface);

    let append = EventLog::new()
        .append_entries(entries)
        .expect("black-box observation entries should append in order");
    let segment = append.segment_text;

    for payload_kind in [
        "network_delivered",
        "observed_io_completion",
        "console_output",
        "memory_sample",
        "node_state",
        "coverage",
    ] {
        assert!(segment.contains(&format!("entry.payload.kind={payload_kind}")));
    }
    assert!(segment.contains("event_payload.attribute.state.value.value=Hung"));
    assert!(segment.contains("entry.class=observational"));
}

#[test]
fn condition_prefix_enforces_black_box_surface_stamps() {
    let sample = ObservableEvent::memory_sample(
        time(13),
        icount(13),
        node("db-0"),
        ResolvedMemPlace::register("rax", 8),
        0xfeed,
    );
    let entry = crucible::test_support::condition_observation_entry_for_test(0, &sample);
    let corrupt = crucible::test_support::condition_entry_with_icount_stamp_for_test(
        entry,
        Some(node("db-0")),
        icount(12),
    );

    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![corrupt]),
        Err(ConditionEvaluationError::InvalidBlackBoxObservationStamp {
            sequence: 0,
            kind: BlackBoxObservationKind::ArchitecturalStateSample,
            expected: EventLogIcountStamp {
                node: Some(node("db-0")),
                icount: icount(13),
            },
            actual: EventLogIcountStamp {
                node: Some(node("db-0")),
                icount: icount(12),
            },
        })
    );
}

#[test]
fn condition_prefix_rejects_out_of_order_observation_stamps() {
    let later = ObservableEvent::network_delivered(time(9), None, b"later".to_vec());
    let earlier = ObservableEvent::network_delivered(time(7), None, b"earlier".to_vec());

    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
            crucible::test_support::condition_observation_entry_for_test(0, &later),
            crucible::test_support::condition_observation_entry_for_test(1, &earlier),
            crucible::test_support::condition_boundary_entry_for_test(
                2,
                time(10),
                SchedulerEvaluationBoundaryKind::Quantum,
            ),
        ]),
        Err(ConditionEvaluationError::OutOfOrderEventLogEntry {
            previous_sequence: 0,
            previous_at: time(9),
            sequence: 1,
            event_at: time(7),
        })
    );
}

#[test]
fn white_box_markers_are_not_required_black_box_surface() {
    let white_box_marker = ObservableEvent::guest_marker(icount(20), node("db-0"), marker("ready"));
    let white_box_assertion = ObservableEvent::guest_assertion_marker(
        icount(21),
        node("db-0"),
        GuestAssertionMarker::new(
            assertion("ready"),
            "ready marker",
            GuestAssertionKind::Reachable,
            true,
            true,
            vec![GuestAssertionDetail::new("source", "doorbell")],
            "guest.rs:1",
        ),
    );
    let white_box_coverage =
        ObservableEvent::coverage_marker(icount(22), node("db-0"), marker("hot"));
    let host_assertion_sample = ObservableEvent::assertion_proximity(
        time(23),
        assertion("eventually-ready"),
        crucible::AssertionQuantifierKind::Eventually,
        4,
        Some(node("db-0")),
    );

    for event in [
        white_box_marker,
        white_box_assertion,
        white_box_coverage,
        host_assertion_sample,
    ] {
        assert_eq!(event.black_box_observation_kind(), None);
    }
}

#[test]
fn io_wildcard_is_not_a_concrete_black_box_surface_category() {
    let wildcard = ObservableEvent::io_completion(
        time(24),
        node("db-0"),
        IoEventKind::Any,
        b"predicate wildcard".to_vec(),
    );

    assert_eq!(wildcard.black_box_observation_kind(), None);
}

#[test]
fn hung_lifecycle_round_trips_through_property_serialization() {
    let world = crucible::World::from_nodes(vec![crucible::WorldNode {
        id: node("db-0"),
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: crucible::NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: crucible::ReadyPoint::FixedIcount { icount: icount(1) },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: crucible::NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: crucible::NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("black-box test world should build");
    let properties = crucible::Properties::from_assertions_for_world(
        &world,
        vec![crucible::AssertionDef {
            id: assertion("no-hang"),
            message: String::from("node should not hang"),
            property: crucible::Property::Always {
                predicate: crucible::Predicate::not(crucible::Predicate::node_state(
                    node("db-0"),
                    NodeLifecycle::Hung,
                )),
            },
        }],
    )
    .expect("hung lifecycle property should validate");

    let toml = properties
        .to_canonical_toml()
        .expect("hung lifecycle property should serialize");
    assert!(toml.contains("state = \"hung\""));
    let from_toml = crucible::Properties::from_canonical_toml_for_world(&world, &toml)
        .expect("hung lifecycle property TOML should parse");
    let binary = properties.to_compact_binary();
    let from_binary = crucible::Properties::from_compact_binary_for_world(&world, &binary)
        .expect("hung lifecycle property binary should parse");

    assert_eq!(from_toml, properties);
    assert_eq!(from_binary, properties);
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn assertion(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}
