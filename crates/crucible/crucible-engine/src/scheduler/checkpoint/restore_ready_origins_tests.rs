//! Production World construction and immutable checkpoint ready-origin controls.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<(ScenarioDef, World), Box<dyn std::error::Error>> {
    let source = crate::crash_restart_scenario()?.scenario;
    Ok((source.scenario_def(), source.world().clone()))
}

fn fresh_scenario(definition: &ScenarioDef, world: &World) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_runnable_world(
        &definition.id().to_hex(),
        16,
        SimInstant {
            ticks: 1_000_000_000,
        },
        0,
        world,
    )
    .with_scenario_def(definition.clone())
}

fn primed_scheduler(
    definition: &ScenarioDef,
    world: &World,
) -> Result<SingleScheduler, SchedulerError> {
    let mut scenario = fresh_scenario(definition, world);
    for (index, node) in scenario.nodes.iter_mut().enumerate() {
        node.counter = NodeCounter {
            ticks: 1_000_000 + index as u64 * 37,
        };
        scenario
            .ready_point_counters
            .insert(node.id.clone(), node.counter);
    }
    SingleScheduler::new(scenario)
}

fn encoded(scheduler: &SingleScheduler) -> Result<Vec<u8>, SingleSchedulerCheckpointError> {
    scheduler.checkpoint()?.canonical_bytes()
}

#[test]
fn production_zero_origin_restore_is_refused_then_prepared_restore_is_exact() -> TestResult {
    let (definition, world) = fixture()?;
    let source = primed_scheduler(&definition, &world)?;
    assert_eq!(source.nodes.len(), 3);
    let bytes = encoded(&source)?;
    let checkpoint = SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)?;

    let mut unprepared = SingleScheduler::new(fresh_scenario(&definition, &world))?;
    let unchanged = encoded(&unprepared)?;
    assert_eq!(unprepared.nodes.len(), checkpoint.wire.nodes.len());
    for (node, retained) in unprepared.nodes.iter().zip(&checkpoint.wire.nodes) {
        assert_eq!(node.id, retained.id);
        assert_eq!(node.ready_point_mapping.anchor_counter.ticks, 0);
        assert_ne!(node.ready_point_mapping, retained.ready_point_mapping);
    }
    assert_eq!(
        checkpoint.restore_into(&mut unprepared),
        Err(SingleSchedulerCheckpointError::Node)
    );
    assert_eq!(encoded(&unprepared)?, unchanged);

    let prepared = checkpoint.prepare_restore_scenario(fresh_scenario(&definition, &world))?;
    let mut restored = SingleScheduler::new(prepared)?;
    checkpoint.restore_into(&mut restored)?;
    assert_eq!(encoded(&restored)?, bytes);
    Ok(())
}

#[test]
fn progressed_checkpoint_keeps_cold_origins_and_exact_continuation() -> TestResult {
    let (definition, world) = fixture()?;
    let mut source = primed_scheduler(&definition, &world)?;
    for _ in 0..3 {
        source.drive_quantum(QuantumRequest {
            configuration: source.configuration().clone(),
            control: Vec::new(),
        })?;
    }
    let bytes = encoded(&source)?;
    let checkpoint = SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)?;
    assert_eq!(checkpoint.quanta(), 3);
    assert!(checkpoint.wire.nodes.iter().any(|node| {
        node.counter != node.ready_point_mapping.anchor_counter.ticks
            && checkpoint
                .epoch_ready_point_counter_for_node(&node.id.node)
                .is_none()
    }));

    let prepared = checkpoint.prepare_restore_scenario(fresh_scenario(&definition, &world))?;
    let mut restored = SingleScheduler::new(prepared)?;
    checkpoint.restore_into(&mut restored)?;
    assert_eq!(encoded(&restored)?, bytes);
    for (node, retained) in restored.nodes.iter().zip(&checkpoint.wire.nodes) {
        assert_eq!(node.ready_point_mapping, retained.ready_point_mapping);
    }

    let request = QuantumRequest {
        configuration: source.configuration().clone(),
        control: Vec::new(),
    };
    assert_eq!(
        restored.drive_quantum(request.clone())?,
        source.drive_quantum(request)?
    );
    assert_eq!(encoded(&restored)?, encoded(&source)?);
    Ok(())
}

#[test]
fn preparation_refuses_foreign_duplicate_missing_nodes_and_wrong_epoch() -> TestResult {
    let (definition, world) = fixture()?;
    let checkpoint = primed_scheduler(&definition, &world)?.checkpoint()?;
    let original = checkpoint.canonical_bytes()?;
    let base = fresh_scenario(&definition, &world);

    let foreign = base
        .clone()
        .with_scenario_def(ScenarioDef::from_canonical_material_with_seed(
            "foreign",
            "ready-origin",
            crate::Seed::default(),
        ));
    assert_eq!(
        checkpoint.prepare_restore_scenario(foreign),
        Err(SingleSchedulerCheckpointError::Configuration)
    );
    let mut missing = base.clone();
    missing.nodes.pop();
    assert_eq!(
        checkpoint.prepare_restore_scenario(missing),
        Err(SingleSchedulerCheckpointError::Node)
    );
    let mut duplicate = base.clone();
    duplicate.nodes[1] = duplicate.nodes[0].clone();
    assert_eq!(
        checkpoint.prepare_restore_scenario(duplicate),
        Err(SingleSchedulerCheckpointError::Node)
    );
    let mut renamed = base.clone();
    renamed.nodes[0].id.node.name.push_str("-foreign");
    assert_eq!(
        checkpoint.prepare_restore_scenario(renamed),
        Err(SingleSchedulerCheckpointError::Node)
    );

    let mut wrong_epoch = checkpoint.clone();
    wrong_epoch.wire.nodes[0].ready_point_mapping.anchor_time = SimInstant { ticks: 1 };
    assert_eq!(
        wrong_epoch.prepare_restore_scenario(base.clone()),
        Err(SingleSchedulerCheckpointError::Node)
    );
    let mut unordered = checkpoint.clone();
    unordered.wire.nodes.swap(0, 1);
    assert_eq!(
        unordered.prepare_restore_scenario(base),
        Err(SingleSchedulerCheckpointError::State)
    );
    assert_eq!(checkpoint.canonical_bytes()?, original);
    Ok(())
}

#[test]
fn strict_restore_still_refuses_changed_origin_after_preparation() -> TestResult {
    let (definition, world) = fixture()?;
    let checkpoint = primed_scheduler(&definition, &world)?.checkpoint()?;
    let prepared = checkpoint.prepare_restore_scenario(fresh_scenario(&definition, &world))?;
    let mut destination = SingleScheduler::new(prepared)?;
    destination.nodes[0]
        .ready_point_mapping
        .anchor_counter
        .ticks += 1;
    let unchanged = encoded(&destination)?;
    assert_eq!(
        checkpoint.restore_into(&mut destination),
        Err(SingleSchedulerCheckpointError::Node)
    );
    assert_eq!(encoded(&destination)?, unchanged);
    Ok(())
}
