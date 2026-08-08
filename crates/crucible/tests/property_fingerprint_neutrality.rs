//! Checks T-ASRT-2 property identity and run-fingerprint neutrality.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(feature = "test-double")]
use crucible::{
    AdvanceOutcome, AssertionDef, AssertionId, Backend, BackendInput, Configuration, Decision,
    DecisionRecorder, ExecutionFingerprint, ExecutionHorizon, FaultId, FaultRateBasisPoints,
    Icount, NodeId, Plan, Predicate, Properties, Property, RngStreamId, ScenarioDefForm, Seed,
    SimBackend, VirtualTime, World,
};

#[cfg(feature = "test-double")]
#[test]
fn property_changes_move_scenario_identity_without_moving_run_material() {
    let world = World::from_nodes(Vec::new()).expect("empty world should build");
    let plan = Plan::empty();
    let seed = Seed::from_u64(0xa5a5_0010);
    let removed_properties = Properties::empty();
    let declared_properties = properties(
        &world,
        vec![assertion(
            "cluster-settled",
            "cluster eventually settles",
            Property::Eventually {
                trigger: Predicate::quiescent(),
                property: Predicate::named("cluster-settled"),
                deadline: VirtualTime { ticks: 50 },
            },
        )],
    );
    let amended_properties = properties(
        &world,
        vec![assertion(
            "cluster-settled",
            "cluster settles under the amended predicate",
            Property::Eventually {
                trigger: Predicate::quiescent(),
                property: Predicate::named("cluster-settled-after-restart"),
                deadline: VirtualTime { ticks: 75 },
            },
        )],
    );

    let removed = form(&world, &plan, &removed_properties, seed);
    let declared = form(&world, &plan, &declared_properties, seed);
    let amended = form(&world, &plan, &amended_properties, seed);

    assert_same_run_components(&removed, &declared);
    assert_same_run_components(&declared, &amended);
    assert_ne!(
        removed.properties().content_hash(),
        declared.properties().content_hash()
    );
    assert_ne!(
        declared.properties().content_hash(),
        amended.properties().content_hash()
    );
    assert_ne!(
        removed.id(),
        declared.id(),
        "property declaration must move the scenario hash"
    );
    assert_ne!(
        declared.id(),
        amended.id(),
        "property amendment must move the scenario hash"
    );
    assert_ne!(
        removed.id(),
        amended.id(),
        "property removal must move the scenario hash"
    );
    assert_scenario_material_points_at_properties(&removed);
    assert_scenario_material_points_at_properties(&declared);
    assert_scenario_material_points_at_properties(&amended);

    let removed_run = deterministic_run_material(&removed);
    let declared_run = deterministic_run_material(&declared);
    let amended_run = deterministic_run_material(&amended);

    assert_eq!(
        removed_run, declared_run,
        "declaring properties must not perturb seed-derived schedule decisions or node fingerprints"
    );
    assert_eq!(
        declared_run, amended_run,
        "amending properties must not perturb seed-derived schedule decisions or node fingerprints"
    );

    assert_ne!(
        declared_run.node_fingerprint,
        run_node_to_fingerprint(
            &declared,
            NodeRun {
                payload: vec![0x43, 0x52, 0x55, 0x44],
                horizon: 12_288,
            },
        ),
        "the node fingerprint witness must change when delivered input changes"
    );
    assert_ne!(
        declared_run.node_fingerprint,
        run_node_to_fingerprint(
            &declared,
            NodeRun {
                payload: vec![0x43, 0x52, 0x55, 0x43],
                horizon: 12_289,
            },
        ),
        "the node fingerprint witness must change when the instruction horizon changes"
    );
}

#[cfg(feature = "test-double")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct RunMaterial {
    schedule: Vec<Decision>,
    launch: LaunchMaterial,
    node_fingerprint: ExecutionFingerprint,
}

#[cfg(feature = "test-double")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct LaunchMaterial {
    world: crucible::ContentHash,
    plan: crucible::ContentHash,
    seed: Seed,
}

#[cfg(feature = "test-double")]
fn deterministic_run_material(form: &ScenarioDefForm) -> RunMaterial {
    let mut recorder = DecisionRecorder::new(Configuration::genesis(form.scenario_def()));
    let _node_draw = recorder.draw_u64(RngStreamId::for_node("node-a/faults/0"));
    let _network_draw = recorder.draw_u64(RngStreamId::for_node("node-a/network/1"));
    recorder
        .serve_app_random(
            node_id("node-a"),
            RngStreamId::for_node("node-a/app-random"),
            16,
        )
        .expect("test app-random width should be valid");
    let configuration = recorder.into_configuration();

    RunMaterial {
        schedule: configuration.schedule.decisions().to_vec(),
        launch: launch_material(form),
        node_fingerprint: run_node_to_fingerprint(
            form,
            NodeRun {
                payload: vec![0x43, 0x52, 0x55, 0x43],
                horizon: 12_288,
            },
        ),
    }
}

#[cfg(feature = "test-double")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeRun {
    payload: Vec<u8>,
    horizon: u64,
}

#[cfg(feature = "test-double")]
fn launch_material(form: &ScenarioDefForm) -> LaunchMaterial {
    LaunchMaterial {
        world: form.world().id(),
        plan: form.plan().content_hash(),
        seed: form.seed(),
    }
}

#[cfg(feature = "test-double")]
fn run_node_to_fingerprint(form: &ScenarioDefForm, run: NodeRun) -> ExecutionFingerprint {
    let launch = launch_material(form);
    assert_eq!(launch.world, form.world().id());
    assert_eq!(launch.plan, form.plan().content_hash());
    assert_eq!(launch.seed, form.seed());

    let mut backend = SimBackend::new();
    backend
        .deliver_input(BackendInput {
            node: node_id("node-a"),
            payload: run.payload,
        })
        .unwrap_or_else(|error| panic!("property-neutral backend input should deliver: {error}"));
    assert_eq!(
        backend.advance_to_horizon(ExecutionHorizon {
            icount: Icount {
                retired: run.horizon,
            },
        }),
        Ok(AdvanceOutcome::ReachedHorizon)
    );
    backend
        .fingerprint()
        .unwrap_or_else(|error| panic!("property-neutral backend fingerprint should read: {error}"))
}

#[cfg(feature = "test-double")]
fn assert_same_run_components(left: &ScenarioDefForm, right: &ScenarioDefForm) {
    assert_eq!(left.world().id(), right.world().id());
    assert_eq!(left.plan().content_hash(), right.plan().content_hash());
    assert_eq!(left.seed(), right.seed());
    assert_eq!(
        left.seed()
            .stream_seed(&RngStreamId::for_node("node-a/faults/0")),
        right
            .seed()
            .stream_seed(&RngStreamId::for_node("node-a/faults/0")),
        "property changes must not change seed-derived decision streams"
    );
}

#[cfg(feature = "test-double")]
fn assert_scenario_material_points_at_properties(form: &ScenarioDefForm) {
    let material = String::from_utf8(form.canonical_bytes())
        .expect("scenario canonical material should be UTF-8");
    assert!(
        material.contains(&format!(
            "properties_ref={}",
            form.properties().content_hash().to_hex()
        )),
        "ScenarioDef material must include the properties component reference"
    );
}

#[cfg(feature = "test-double")]
fn form(world: &World, plan: &Plan, properties: &Properties, seed: Seed) -> ScenarioDefForm {
    ScenarioDefForm::from_components(world, plan, properties, seed)
        .unwrap_or_else(|error| panic!("scenario form should compose: {error}"))
}

#[cfg(feature = "test-double")]
fn properties(world: &World, assertions: Vec<AssertionDef>) -> Properties {
    Properties::from_assertions_for_world(world, assertions)
        .unwrap_or_else(|error| panic!("properties should validate: {error}"))
}

#[cfg(feature = "test-double")]
fn assertion(id: &str, message: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: message.to_owned(),
        property,
    }
}

#[cfg(feature = "test-double")]
fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}
