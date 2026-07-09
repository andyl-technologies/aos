//! Gates debug attach as ordinary temporal-graph instantiation.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;

use crucible::{
    ChoiceTag, Configuration, ContentHash, DebugAttachChannelKind, DebugAttachRequest, Decision,
    EngineError, Icount, NodeId, NodeTemplate, OverrideDecision, ReadyPoint, SchedulingPoint,
    TemporalGraph, VmArchitecture, WhiteBoxPolicy, World, WorldNode, bake, reduce, try_step,
};

#[test]
fn debug_attach_instantiates_checkpoint_and_reports_fourth_channel() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-attach")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let branch = try_step(&root, override_decision("debug-point", "branch"))?;
    let mut graph = TemporalGraph::new(ContentHash::from_canonical_material(
        "crucible.test.debug-attach",
        "attach",
    ))
    .with_baked_genesis(&scenario, bake(&world)?)?;

    let request = DebugAttachRequest::new(
        branch.clone(),
        node_id("guest-a"),
        "unix:/tmp/crucible-qemu-gdbstub.sock,server=on,wait=off",
        "127.0.0.1:9000",
    )?;
    let report = graph.debug_attach(&request)?;
    let reduced = reduce(&branch.def, &branch.schedule)?;

    assert_eq!(report.configuration, branch.id());
    assert_eq!(report.checkpoint, branch.id());
    assert_eq!(report.runtime.configuration, branch.id());
    assert_eq!(report.runtime.runtime.configuration, branch.id());
    assert_eq!(report.reduced_state, reduced.id);
    assert!(report.uses_instantiated_runtime());
    assert!(report.has_four_channel_debug_boundary());
    assert!(
        report
            .channel_set
            .channels
            .contains(&DebugAttachChannelKind::PluginIpcControl)
    );
    assert!(
        report
            .channel_set
            .channels
            .contains(&DebugAttachChannelKind::SharedMemoryHotPath)
    );
    assert!(
        report
            .channel_set
            .channels
            .contains(&DebugAttachChannelKind::QmpMachineControl)
    );
    assert!(
        report
            .channel_set
            .channels
            .contains(&DebugAttachChannelKind::Gdbstub)
    );
    assert_eq!(report.gdbstub.node, node_id("guest-a"));
    assert_eq!(
        report.gdbstub.qemu_endpoint.as_str(),
        "unix:/tmp/crucible-qemu-gdbstub.sock,server=on,wait=off"
    );
    assert_eq!(report.gdbstub.operator_listen.as_str(), "127.0.0.1:9000");
    assert!(report.gdbstub.mediated_by_crucible);
    assert!(report.gdbstub.out_of_band);
    assert!(!report.gdbstub.carries_per_quantum_timing);
    assert!(!report.gdbstub.carries_frame_data);

    Ok(())
}

#[test]
fn debug_attach_rejects_invalid_endpoint_and_unknown_node() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("debug-attach-reject")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;

    assert!(matches!(
        DebugAttachRequest::new(root.clone(), node_id("guest-a"), "", "127.0.0.1:9000"),
        Err(EngineError::DebugGdbEndpointInvalid {
            field: "qemu_gdbstub",
            ..
        })
    ));
    assert!(matches!(
        DebugAttachRequest::new(
            root.clone(),
            node_id("guest-a"),
            "unix:/tmp/crucible-qemu-gdbstub.sock,server=on,wait=off",
            "127.0.0.1:9000\n"
        ),
        Err(EngineError::DebugGdbEndpointInvalid {
            field: "gdb_listen",
            ..
        })
    ));

    let request = DebugAttachRequest::new(
        root,
        node_id("missing"),
        "unix:/tmp/crucible-qemu-gdbstub.sock,server=on,wait=off",
        "127.0.0.1:9000",
    )?;
    assert!(matches!(
        graph.debug_attach(&request),
        Err(EngineError::DebugAttachUnknownNode { node, .. }) if node == node_id("missing")
    ));

    Ok(())
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("guest-a"),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-debug-attach={label}"),
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
