//! Gates non-canonical debug branches.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;

use crucible::test_support::condition_payload_entry_for_test;
use crucible::{
    ChoiceTag, Configuration, ControlOperation, ControlOperationKind, DebugAttachRequest,
    DebugCoordinate, DebugGuestEdit, DebugGuestEditKind, DebugNonCanonicalBranchAction,
    DebugNonCanonicalBranchRequest, DebugNonCanonicalBranchTrigger, DebugOperatorControlKind,
    Decision, EngineError, Icount, NodeId, NodeTemplate, OverrideDecision, ReadyPoint,
    SchedulerEventLogClass, SchedulerEventLogPayload, SchedulingPoint, TemporalGraph, VirtualTime,
    VmArchitecture, WhiteBoxPolicy, World, WorldNode, bake, try_step,
};

#[test]
fn non_canonical_debug_branch_marks_and_preserves_canonical_run() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-non-canonical")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(&root, override_decision("debug/noncanonical", "first"))?;
    let second = try_step(&first, override_decision("debug/noncanonical", "second"))?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    graph.record_thin_checkpoint(&first)?;
    graph.materialize_checkpoint(&second)?;
    let replay_before = graph.replay(&second)?;
    let attach = graph.debug_attach(&attach_request(&second)?)?;
    let canonical_event_log = vec![condition_payload_entry_for_test(
        7,
        VirtualTime { ticks: 2 },
        SchedulerEventLogPayload::Decision(override_decision("debug/log", "canonical")),
    )];

    let request = DebugNonCanonicalBranchRequest::new(
        second.clone(),
        VirtualTime { ticks: 2 },
        DebugNonCanonicalBranchTrigger::GuestMemoryWrite,
    )
    .with_action(DebugNonCanonicalBranchAction::guest_edit(
        DebugGuestEdit::new(
            node_id("guest-a"),
            DebugGuestEditKind::MemoryWrite,
            DebugCoordinate::node_icount(node_id("guest-a"), Icount { retired: 102 }),
            "guest-phys:0x1000",
            [0xde, 0xad, 0xbe, 0xef],
        ),
    ))
    .with_action(DebugNonCanonicalBranchAction::decision(override_decision(
        "debug/noncanonical",
        "operator-choice",
    )))
    .with_action(DebugNonCanonicalBranchAction::control_operation(
        ControlOperation {
            sequence: 42,
            kind: ControlOperationKind::Fork,
        },
    ))
    .with_action(DebugNonCanonicalBranchAction::operator_control(
        DebugOperatorControlKind::Continue,
    ));

    let report = graph.debug_non_canonical_branch(&attach, &request, &canonical_event_log)?;
    let replay_after = graph.replay(&second)?;
    let branch = graph
        .debug_non_canonical_branch_view(report.branch.id)
        .ok_or("branch should be visible in temporal graph view")?;

    assert_eq!(replay_before, replay_after);
    assert_eq!(graph.debug_non_canonical_branch_count(), 1);
    assert_eq!(branch, &report.branch);
    assert!(report.canonical_run_bit_identical());
    assert!(report.proves_non_canonical_debug_branch());
    assert!(report.excluded_from_oracles_and_artifacts());
    assert!(report.visibly_marked_non_canonical());
    assert!(report.inside_virtual_time_single_execution_path());
    assert!(report.branch.ordinary_fork_shape());
    assert!(report.branch.records_schedule_expressible_edits());
    assert!(
        report
            .branch
            .records_arbitrary_guest_edits_as_debug_script()
    );
    assert_eq!(report.branch.schedule_expressible_decisions.len(), 1);
    assert_eq!(report.branch.control_log_entries.len(), 1);
    assert_eq!(
        report.branch.operator_controls,
        vec![DebugOperatorControlKind::Continue]
    );
    assert_eq!(report.branch.debug_edit_script.entries.len(), 1);
    assert!(!report.branch.seed_scenario_schedule_artifact);
    assert!(report.branch.replay_oracle_excluded);
    assert_eq!(
        report.event_log_with_fork_marker.len(),
        canonical_event_log.len() + 1
    );
    assert_eq!(
        report
            .event_log_with_fork_marker
            .last()
            .map(|entry| entry.sequence()),
        Some(8)
    );
    assert_eq!(
        report
            .event_log_with_fork_marker
            .last()
            .map(|entry| entry.class()),
        Some(SchedulerEventLogClass::Causal)
    );
    assert_eq!(
        report
            .event_log_with_fork_marker
            .last()
            .map(|entry| entry.event_payload().kind()),
        Some("fork")
    );
    assert!(report.branch.fork_marker.visibly_marks_non_canonical_fork());
    assert!(report.branch.live_status.visibly_distinguishes_branch());
    assert_eq!(
        report.branch.live_status.runtime,
        report.branch.fork_runtime
    );

    Ok(())
}

#[test]
fn operator_controlled_continue_branches_without_guest_edit_script() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-non-canonical-continue")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(&root, override_decision("debug/noncanonical", "first"))?;
    let second = try_step(&first, override_decision("debug/noncanonical", "second"))?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    graph.record_thin_checkpoint(&first)?;
    graph.materialize_checkpoint(&second)?;
    let replay_before = graph.replay(&second)?;
    let attach = graph.debug_attach(&attach_request(&second)?)?;
    let request = DebugNonCanonicalBranchRequest::new(
        second.clone(),
        VirtualTime { ticks: 2 },
        DebugNonCanonicalBranchTrigger::OperatorContinue,
    )
    .with_action(DebugNonCanonicalBranchAction::operator_control(
        DebugOperatorControlKind::Continue,
    ));

    let report = graph.debug_non_canonical_branch(&attach, &request, &[])?;
    let replay_after = graph.replay(&second)?;

    assert_eq!(replay_before, replay_after);
    assert!(report.proves_non_canonical_debug_branch());
    assert!(report.branch.ordinary_fork_shape());
    assert!(report.branch.debug_edit_script.entries.is_empty());
    assert_eq!(
        report.branch.operator_controls,
        vec![DebugOperatorControlKind::Continue]
    );
    assert!(report.branch.fork_marker.visibly_marks_non_canonical_fork());
    assert!(report.branch.live_status.visibly_distinguishes_branch());

    Ok(())
}

#[test]
fn non_canonical_debug_branch_requires_matching_trigger_evidence() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-non-canonical-invalid")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(
        &root,
        override_decision("debug/noncanonical-invalid", "first"),
    )?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    graph.record_thin_checkpoint(&first)?;
    let attach = graph.debug_attach(&attach_request(&first)?)?;
    let request = DebugNonCanonicalBranchRequest::new(
        first.clone(),
        VirtualTime { ticks: 1 },
        DebugNonCanonicalBranchTrigger::GuestRegisterWrite,
    )
    .with_action(DebugNonCanonicalBranchAction::guest_edit(
        DebugGuestEdit::new(
            node_id("guest-a"),
            DebugGuestEditKind::MemoryWrite,
            DebugCoordinate::node_icount(node_id("guest-a"), Icount { retired: 101 }),
            "guest-phys:0x2000",
            [0xff],
        ),
    ));

    let error = graph
        .debug_non_canonical_branch(&attach, &request, &[])
        .unwrap_err();

    assert!(matches!(
        error,
        EngineError::DebugNonCanonicalBranchMissingTriggerEvidence { .. }
    ));
    assert_eq!(graph.debug_non_canonical_branch_count(), 0);

    let late_matching_request = DebugNonCanonicalBranchRequest::new(
        first.clone(),
        VirtualTime { ticks: 1 },
        DebugNonCanonicalBranchTrigger::GuestMemoryWrite,
    )
    .with_action(DebugNonCanonicalBranchAction::decision(override_decision(
        "debug/noncanonical-invalid",
        "first-action",
    )))
    .with_action(DebugNonCanonicalBranchAction::guest_edit(
        DebugGuestEdit::new(
            node_id("guest-a"),
            DebugGuestEditKind::MemoryWrite,
            DebugCoordinate::node_icount(node_id("guest-a"), Icount { retired: 101 }),
            "guest-phys:0x2000",
            [0xff],
        ),
    ));

    let error = graph
        .debug_non_canonical_branch(&attach, &late_matching_request, &[])
        .unwrap_err();

    assert!(matches!(
        error,
        EngineError::DebugNonCanonicalBranchMissingTriggerEvidence { .. }
    ));
    assert_eq!(graph.debug_non_canonical_branch_count(), 0);

    Ok(())
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("guest-a"),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-debug-non-canonical={label}"),
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

fn attach_request(configuration: &Configuration) -> Result<DebugAttachRequest, EngineError> {
    DebugAttachRequest::new(
        configuration.clone(),
        node_id("guest-a"),
        "unix:/tmp/crucible-qemu-gdbstub.sock,server=on,wait=off",
        "127.0.0.1:9000",
    )
}
