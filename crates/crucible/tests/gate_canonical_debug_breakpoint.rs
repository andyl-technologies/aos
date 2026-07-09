//! Gates canonical debugger breakpoints as out-of-band only.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;

use crucible::{
    ChoiceTag, Configuration, ContentHash, DebugAttachRequest, DebugBreakpointClientKind,
    DebugBreakpointMechanism, DebugBreakpointRequest, DebugBreakpointTarget, Decision, EngineError,
    Icount, NodeId, NodeTemplate, OverrideDecision, ReadyPoint, SchedulingPoint, TemporalGraph,
    VmArchitecture, WhiteBoxPolicy, World, WorldNode, bake, try_step,
};

#[test]
fn canonical_debug_breakpoint_uses_out_of_band_mechanisms() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("canonical-breakpoint")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let branch = try_step(&root, override_decision("debug-point", "branch"))?;
    let mut graph = TemporalGraph::new(ContentHash::from_canonical_material(
        "crucible.test.canonical-debug-breakpoint",
        "graph",
    ))
    .with_baked_genesis(&scenario, bake(&world)?)?;
    let attach = graph.debug_attach(&DebugAttachRequest::new(
        branch.clone(),
        node_id("guest-a"),
        "unix:/tmp/crucible-qemu-gdbstub.sock,server=on,wait=off",
        "127.0.0.1:9000",
    )?)?;

    let software_request =
        DebugBreakpointRequest::software_guest_address(node_id("guest-a"), 0x401000);
    let software_report = graph.canonical_debug_breakpoint(&attach, &software_request)?;

    assert_eq!(software_report.configuration, branch.id());
    assert_eq!(software_report.checkpoint, branch.id());
    assert_eq!(
        software_report.requested_client_kind,
        DebugBreakpointClientKind::Software
    );
    assert_eq!(
        software_report.mechanism,
        DebugBreakpointMechanism::QemuHardwareBreakpoint
    );
    assert!(software_report.is_canonical_out_of_band());
    assert!(software_report.transparently_satisfies_software_request());
    assert!(!software_report.mutates_guest_memory);
    assert!(!software_report.memory_patch_used);
    assert!(!software_report.requires_allow_mutate);

    let condition_request = DebugBreakpointRequest::new(
        node_id("guest-a"),
        DebugBreakpointClientKind::EngineCondition,
        DebugBreakpointTarget::EngineCondition {
            condition: String::from("pc == 0x401000"),
        },
    );
    let condition_report = graph.canonical_debug_breakpoint(&attach, &condition_request)?;

    assert_eq!(
        condition_report.mechanism,
        DebugBreakpointMechanism::EngineCondition
    );
    assert!(condition_report.is_canonical_out_of_band());
    assert!(!condition_report.memory_patch_used);

    Ok(())
}

#[test]
fn canonical_debug_breakpoint_refuses_memory_patch_only_breakpoint() -> Result<(), Box<dyn Error>> {
    let world = single_node_world("canonical-breakpoint-refuse")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let branch = try_step(&root, override_decision("debug-point", "branch"))?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let attach = graph.debug_attach(&DebugAttachRequest::new(
        branch,
        node_id("guest-a"),
        "unix:/tmp/crucible-qemu-gdbstub.sock,server=on,wait=off",
        "127.0.0.1:9000",
    )?)?;

    let memory_patch_only = DebugBreakpointRequest::software_memory_patch_only_guest_address(
        node_id("guest-a"),
        0x402000,
    );
    let error = graph
        .canonical_debug_breakpoint(&attach, &memory_patch_only)
        .expect_err("memory-patch-only breakpoint must be refused on canonical attach");
    let error_text = error.to_string();

    assert!(matches!(
        error,
        EngineError::DebugBreakpointRequiresAllowMutate {
            ref node,
            target: DebugBreakpointTarget::GuestMemoryPatchOnly { address: 0x402000 },
            requested_client_kind: DebugBreakpointClientKind::Software,
        } if *node == node_id("guest-a")
    ));
    assert!(error_text.contains("--allow-mutate"));

    let unknown_node = DebugBreakpointRequest::software_guest_address(node_id("missing"), 0x402000);
    assert!(matches!(
        graph.canonical_debug_breakpoint(&attach, &unknown_node),
        Err(EngineError::DebugAttachUnknownNode { node, .. }) if node == node_id("missing")
    ));

    Ok(())
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("guest-a"),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-canonical-breakpoint={label}"),
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
