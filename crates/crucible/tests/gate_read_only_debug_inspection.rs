//! Gates read-only debugger inspection as observational-only event logging.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;

use crucible::{
    ChoiceTag, Configuration, ContentHash, DebugAttachRequest, DebugReadOnlyInspectionKind,
    DebugReadOnlyInspectionRequest, Decision, EngineError, EventClass, Icount, NodeId,
    NodeTemplate, OverrideDecision, ReadyPoint, RngDecision, RngStreamId,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, SchedulerEventLogPayload,
    SchedulingPoint, TemporalGraph, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
    bake, compare_event_log_determinism, event_log_causal_projection, try_step,
};

#[test]
fn debug_read_only_inspection_preserves_causal_log_and_virtual_time() -> Result<(), Box<dyn Error>>
{
    let world = single_node_world("read-only-debug-inspection")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let branch = try_step(&root, override_decision("debug-point", "branch"))?;
    let mut graph = TemporalGraph::new(ContentHash::from_canonical_material(
        "crucible.test.read-only-debug-inspection",
        "graph",
    ))
    .with_baked_genesis(&scenario, bake(&world)?)?;

    let attach = graph.debug_attach(&DebugAttachRequest::new(
        branch.clone(),
        node_id("guest-a"),
        "unix:/tmp/crucible-qemu-gdbstub.sock,server=on,wait=off",
        "127.0.0.1:9000",
    )?)?;
    let no_debug_log = vec![
        rng_entry(0, 12, "read-only-debug-causal", 31),
        boundary_entry(1, 13),
    ];
    let request_time = VirtualTime {
        ticks: u64::try_from(branch.schedule.len())?,
    };
    let request = DebugReadOnlyInspectionRequest::new(
        request_time,
        [
            DebugReadOnlyInspectionKind::RegisterRead,
            DebugReadOnlyInspectionKind::MemoryRead,
            DebugReadOnlyInspectionKind::Backtrace,
            DebugReadOnlyInspectionKind::ThreadEnumeration,
            DebugReadOnlyInspectionKind::WatchpointValueRead,
        ],
    );

    let report = graph.read_only_debug_inspection(&attach, &request, &no_debug_log);

    assert!(report.proves_read_only());
    assert!(report.graph_unchanged());
    assert!(report.configuration_unchanged());
    assert!(report.checkpoint_unchanged());
    assert!(report.runtime_unchanged());
    assert!(report.requested_virtual_time_matches_checkpoint());
    assert!(report.virtual_time_unchanged());
    assert_eq!(report.footprint_before.attached_configuration, branch.id());
    assert_eq!(report.footprint_after.attached_configuration, branch.id());
    assert_eq!(report.footprint_before.attached_checkpoint, branch.id());
    assert_eq!(report.footprint_after.attached_checkpoint, branch.id());
    assert!(report.footprint_before.attached_checkpoint_recorded);
    assert!(report.footprint_after.attached_checkpoint_recorded);
    assert_eq!(
        report.footprint_before.attached_runtime_node_icounts,
        report.footprint_after.attached_runtime_node_icounts
    );
    assert_eq!(
        report.footprint_before.attached_runtime_scheduler,
        report.footprint_after.attached_runtime_scheduler
    );
    assert_eq!(
        report.causal_event_log_before.canonical_bytes(),
        event_log_causal_projection(&no_debug_log).canonical_bytes()
    );
    assert_eq!(
        report.causal_event_log_before.canonical_bytes(),
        report.causal_event_log_after.canonical_bytes()
    );
    assert_eq!(report.observational_entries.len(), 7);
    assert_eq!(
        diagnostic_names(&report.observational_entries),
        vec![
            "debug.attach",
            "debug.inspect.register_read",
            "debug.inspect.memory_read",
            "debug.inspect.backtrace",
            "debug.inspect.thread_enumeration",
            "debug.inspect.watchpoint_value_read",
            "debug.detach",
        ]
    );
    assert!(
        report
            .observational_entries
            .iter()
            .all(|entry| entry.class() == EventClass::Observational
                && entry.event_payload().kind() == "diagnostic")
    );
    assert!(
        report
            .observational_entries
            .iter()
            .all(|entry| entry.at() == report.footprint_before.virtual_time)
    );

    assert_eq!(
        report.event_log_with_observations.len(),
        no_debug_log.len() + report.observational_entries.len()
    );
    assert_eq!(
        &report.event_log_with_observations[..2],
        no_debug_log.as_slice()
    );
    assert_eq!(
        &report.event_log_with_observations[2..],
        report.observational_entries.as_slice()
    );

    let comparison =
        compare_event_log_determinism(&no_debug_log, &report.event_log_with_observations);

    assert!(comparison.passes());
    assert_eq!(
        comparison.expected().canonical_bytes(),
        comparison.reproduced().canonical_bytes()
    );
    assert_eq!(comparison.expected().len(), 2);
    assert_eq!(comparison.reproduced().len(), 2);
    assert_eq!(
        comparison
            .reproduced()
            .entries()
            .iter()
            .map(|entry| entry.raw_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );

    let mismatched_request = DebugReadOnlyInspectionRequest::new(
        different_time(report.footprint_before.virtual_time),
        [DebugReadOnlyInspectionKind::RegisterRead],
    );
    let mismatched_report =
        graph.read_only_debug_inspection(&attach, &mismatched_request, &no_debug_log);
    assert!(!mismatched_report.proves_read_only());
    assert!(!mismatched_report.requested_virtual_time_matches_checkpoint());
    assert!(mismatched_report.virtual_time_unchanged());
    assert!(
        mismatched_report
            .observational_entries
            .iter()
            .all(
                |entry| entry.at() == mismatched_report.footprint_before.virtual_time
                    && entry.at() != mismatched_report.requested_virtual_time
            )
    );

    Ok(())
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("guest-a"),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-read-only-debug={label}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 100 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
}

fn diagnostic_names(entries: &[SchedulerEventLogEntry]) -> Vec<&str> {
    entries
        .iter()
        .map(|entry| match entry.payload() {
            SchedulerEventLogPayload::Diagnostic(diagnostic) => diagnostic.name.as_str(),
            payload => panic!("debug inspection entry must be diagnostic, got {payload:?}"),
        })
        .collect()
}

fn rng_entry(sequence: u64, ticks: u64, stream: &str, value: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name(stream),
            value,
        })),
    )
}

fn boundary_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn different_time(time: VirtualTime) -> VirtualTime {
    if time.ticks == u64::MAX {
        VirtualTime {
            ticks: time.ticks - 1,
        }
    } else {
        VirtualTime {
            ticks: time.ticks + 1,
        }
    }
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn override_decision(point: &str, choice: &str) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: point.to_owned(),
        },
        choice: ChoiceTag {
            name: choice.to_owned(),
        },
    })
}
