//! Explicit scripted inventory binding and operational default refusal.
//!
//! These model fixtures do not install native Source or Mode8 authority.

// crucible-lint: allow panic-shortcut -- test fixtures assert explicit binding/refusal outcomes.
#![allow(clippy::expect_used)]

use super::*;
use crucible::{
    ContentAddressedBlobRef, ContentHash, NodeTemplate, ReadyPoint, VmArchitecture, WhiteBoxPolicy,
    WorldBlockLatency, WorldIoCoreConfig, WorldIoNode, WorldNode, WorldNodeDef,
};

fn node(name: &str) -> NodeId {
    NodeId { name: name.into() }
}

fn world(with_queue: bool) -> crucible::model::World {
    let mut nodes = ["a", "b"]
        .into_iter()
        .map(|name| {
            WorldNodeDef::Vm(WorldNode {
                id: node(name),
                arch: VmArchitecture::X86_64,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::FixedIcount {
                    icount: Icount { retired: 0 },
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: 1,
                kernel: None,
                root_image: None,
                initrd: None,
            })
        })
        .collect::<Vec<_>>();
    if with_queue {
        nodes.push(WorldNodeDef::Io(WorldIoNode::block(
            node("disk"),
            node("a"),
            WorldIoCoreConfig::new(),
            ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(&[0; 512])),
            512,
            WorldBlockLatency::new(0, 0, 0, 0, 0),
        )));
    }
    crucible::model::World::from_node_defs_and_links(nodes, Vec::new()).expect("fixture World")
}

#[test]
fn unbound_and_foreign_scripted_inventory_refuses() {
    let mut runtime = ScriptedHostIoRuntime::default();
    assert!(matches!(
        runtime
            .observe_scripted_io_inventory_for_test(&node("a"), crucible::NodeCounter { ticks: 0 }),
        Err(BackendError::Unsupported { .. })
    ));
    assert!(
        runtime
            .bind_scripted_io_inventory_for_test(&world(false), &node("foreign"))
            .is_err()
    );

    runtime
        .bind_scripted_io_inventory_for_test(&world(false), &node("a"))
        .expect("bound owner");
    assert!(
        runtime
            .observe_scripted_io_inventory_for_test(&node("b"), crucible::NodeCounter { ticks: 0 })
            .is_err()
    );
    assert!(
        runtime
            .bind_scripted_io_inventory_for_test(&world(false), &node("b"))
            .is_err()
    );
}

#[test]
fn configured_physical_queue_is_never_manufactured_absent() {
    let mut runtime = ScriptedHostIoRuntime::default();
    assert!(
        runtime
            .bind_scripted_io_inventory_for_test(&world(true), &node("a"))
            .is_err()
    );
    assert!(runtime.io_world.is_none());
    assert!(
        runtime
            .observe_scripted_io_inventory_for_test(&node("a"), crucible::NodeCounter { ticks: 0 })
            .is_err()
    );
}

#[test]
fn cloned_scripted_continuation_retains_the_exact_fixture_binding() {
    let mut runtime = ScriptedHostIoRuntime::default();
    let world = world(false);
    runtime
        .bind_scripted_io_inventory_for_test(&world, &node("a"))
        .expect("bound owner");
    let clone = runtime.clone();
    let observed = crucible::NodeCounter { ticks: 17 };
    let inventory = clone
        .observe_scripted_io_inventory_for_test(&node("a"), observed)
        .expect("model inventory");
    assert_eq!(inventory.node, node("a"));
    assert_eq!(inventory.observed, observed);
    assert!(inventory.queues.is_empty());
    assert_eq!(
        inventory.native_caps.timer,
        crucible::BackendIoNativeCap::ObservedAbsent
    );
    assert_eq!(
        inventory.native_caps.input,
        crucible::BackendIoNativeCap::ObservedAbsent
    );
    assert_eq!(
        clone.io_world.as_ref().expect("cloned binding").0.id(),
        world.id()
    );
}

#[test]
fn node_set_observation_requires_explicit_scripted_runtime_binding() {
    let mut source =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("scripted source");
    assert!(source.observe_node_io_inventory(&node("a")).is_err());
    let mut nodes = crate::QemuNodeSet::new();
    nodes.insert(node("a"), source);
    assert!(matches!(
        nodes.observe_node_io_inventory(&node("a")),
        Err(BackendError::Unsupported {
            capability: "observe_node_io_inventory"
        })
    ));
    source = nodes.take(&node("a")).expect("owned source");
    source
        .bind_scripted_io_inventory_for_test(&world(false), &node("a"))
        .expect("explicit model binding");
    assert!(source.observe_node_io_inventory(&node("a")).is_ok());
    nodes.insert(node("a"), source);
    assert!(
        nodes
            .observe_node_io_inventory(&node("a"))
            .expect("bound inventory")
            .queues
            .is_empty()
    );
    assert!(nodes.observe_node_io_inventory(&node("b")).is_err());
}

fn admissions(world: &crucible::model::World) -> Vec<crucible::PreparedRunAdmission> {
    let runtime = crucible::SchedulerLivenessScenario::from_runnable_world(
        "scripted-admission-fixture",
        4,
        crucible::SimInstant { ticks: 20 },
        0,
        world,
    );
    let scheduler = crucible::SingleScheduler::from_world(
        runtime,
        world,
        &crucible::model::MemoryDagStore::new(),
        crucible::WorldIoLayoutPolicy::default(),
    )
    .expect("actual World scheduler");
    scheduler
        .prepare_run_admissions_for_test(2)
        .expect("actual actor-issued RUNs")
}

#[test]
fn scripted_admission_authenticates_the_exact_actor_world_node_and_cap() {
    let world = world(false);
    let runs = admissions(&world);
    let admitted = runs
        .iter()
        .find(|run| run.node() == &node("a"))
        .expect("a RUN");
    let foreign = runs
        .iter()
        .find(|run| run.node() == &node("b"))
        .expect("b RUN");
    assert_eq!(admitted.input_inventory().world(), Some(world.id()));
    assert!(
        admitted.dispatch_horizon().icount.retired <= admitted.semantic_horizon().icount.retired
    );

    let mut runtime = ScriptedHostIoRuntime::default();
    assert!(
        runtime
            .validate_scripted_run_admission_for_test(admitted)
            .is_err()
    );
    runtime
        .bind_scripted_io_inventory_for_test(&world, &node("a"))
        .expect("bound fixture");
    assert!(
        runtime
            .validate_scripted_run_admission_for_test(admitted)
            .is_ok()
    );
    assert!(
        runtime
            .validate_scripted_run_admission_for_test(foreign)
            .is_err()
    );

    let mut changed_nodes = world.vm_nodes().iter().cloned().collect::<Vec<_>>();
    changed_nodes[0].memory_mib += 1;
    let changed_world = crucible::model::World::from_node_defs_and_links(
        changed_nodes.into_iter().map(WorldNodeDef::Vm).collect(),
        Vec::new(),
    )
    .expect("different immutable World");
    assert_ne!(changed_world.id(), world.id());
    let changed_runs = admissions(&changed_world);
    let changed = changed_runs
        .iter()
        .find(|run| run.node() == &node("a"))
        .expect("changed a RUN");
    assert!(
        runtime
            .validate_scripted_run_admission_for_test(changed)
            .is_err()
    );
}

#[test]
fn scripted_admission_refuses_before_effects_and_steps_to_the_actor_cap() {
    let world = world(false);
    let runs = admissions(&world);
    let admitted = runs
        .iter()
        .find(|run| run.node() == &node("a"))
        .expect("a RUN");
    let foreign = runs
        .iter()
        .find(|run| run.node() == &node("b"))
        .expect("b RUN");
    let mut source =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("scripted source");
    let before = source.now();
    assert!(source.step_node_with_admission(admitted).is_err());
    assert_eq!(source.now(), before);
    source
        .bind_scripted_io_inventory_for_test(&world, &node("a"))
        .expect("bound fixture");
    assert!(source.step_node_with_admission(foreign).is_err());
    assert_eq!(source.now(), before);

    let mut nodes = crate::QemuNodeSet::new();
    nodes.insert(node("a"), source);
    let crucible::BackendRunResult::Completed(step) = nodes
        .step_node_with_admission(admitted)
        .expect("explicit scripted model RUN")
    else {
        panic!("scripted completed step");
    };
    assert_eq!(
        step.reached.ticks,
        admitted.dispatch_horizon().icount.retired
    );
    assert_eq!(
        nodes.node_now(&node("a")).expect("model counter"),
        step.reached
    );
}
