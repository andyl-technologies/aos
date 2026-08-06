//! Emits a deliberately failing scenario for hands-on debugger exercises.
//!
//! The guest remains healthy, while the scenario incorrectly requires it to
//! crash shortly after starting. The resulting assertion failure is small and
//! deterministic, but still requires the operator to compare the assertion,
//! event history, and live VM state to identify the scenario-authoring error.

use std::error::Error;

use crucible::{
    Action, AssertionDef, AssertionId, AssertionPhase, ContentAddressedBlobRef, ContentHash,
    EventGraph, Icount, NodeId, NodeLifecycle, NodeTemplate, Plan, Predicate, Properties, Property,
    ReadyPoint, ScenarioDefForm, Seed, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn main() -> Result<(), Box<dyn Error>> {
    print!("{}", failing_scenario()?.to_canonical_toml()?);
    Ok(())
}

fn failing_scenario() -> Result<ScenarioDefForm, Box<dyn Error>> {
    let suspect = NodeId {
        name: String::from("suspect"),
    };
    let world = World::from_nodes_and_links(
        vec![WorldNode {
            id: suspect.clone(),
            arch: VmArchitecture::X86_64,
            memory_mib: 256,
            cmdline: String::from(
                "console=ttyS0 quiet net.ifnames=0 port=8080 crucible.workload=httpd",
            ),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: 0,
            kernel: Some(blob("aos-linux-crucible")),
            root_image: Some(blob("aos-minimal-root-image")),
            initrd: None,
        }],
        Vec::new(),
    )?;
    let assertion_id = AssertionId::from_name("suspect-must-crash");
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: assertion_id.clone(),
            message: String::from("the suspect VM must remain crashed"),
            property: Property::Always {
                predicate: Predicate::node_state(suspect, NodeLifecycle::Crashed),
            },
        }],
    )?;
    let assertion_ids = vec![assertion_id.clone()];
    let graph = EventGraph::builder()
        .event("fail-on-inverted-expectation")
        .when(Predicate::assertion_state(
            assertion_id,
            AssertionPhase::Violated,
        ))
        .action(Action::fail("the suspect VM did not crash"))
        .build_with_assertions_for_world(assertion_ids.clone(), &world)?;
    let plan = Plan::from_event_graph_with_assertions_for_world(&world, assertion_ids, graph)?;
    Ok(ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(0xdeb6),
        0,
    )?)
}

fn blob(name: &str) -> ContentAddressedBlobRef {
    ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
        "crucible.debugger-failing-scenario.asset.v1",
        name,
    ))
}
