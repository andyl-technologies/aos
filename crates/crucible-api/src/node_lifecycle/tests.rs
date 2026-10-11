//! World lifecycle integration without a simulator or native process adapter.

use super::*;
use crucible::{
    NodeLifecycle, Plan, Properties, QuantumLoop, QuantumRequest, ScenarioDefForm,
    SchedulerLivenessScenario, Seed, SimDuration, SimInstant, TimerId,
};

#[test]
fn shared_world_core_restores_deadlines_without_replaying_initial_observations()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = crucible::crash_restart_scenario()?;
    let world = fixture.scenario.world();
    let graph = EventGraph::builder()
        .event("begin")
        .entrypoint()
        .action(Action::arm_timer(
            TimerId {
                name: "finish".into(),
            },
            SimDuration { ticks: 3 },
        ))
        .event("complete")
        .when(crucible::Condition::timer(TimerId {
            name: "finish".into(),
        }))
        .action(Action::Pass)
        .build_for_world(world)?;
    let properties = Properties::empty();
    let plan = Plan::from_event_graph_for_world(world, graph.clone())?;
    let source = ScenarioDefForm::from_components(world, &plan, &properties, Seed::from_u64(42))?;
    let scenario = source.scenario_def();
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_runnable_world(
            &scenario.id().to_hex(),
            4,
            SimInstant { ticks: 4 },
            0,
            world,
        )
        .with_scenario_def(scenario),
    )?;
    let mut trigger_state = EventGraphState::default();
    let mut evaluator =
        HostAssertionEvaluator::new(&properties).with_world_white_box_policies(world);
    let mut oracle = BlackBoxHostOracle;
    let mut terminal = None;
    let mut initial_pending = true;

    {
        let mut lifecycle = WorldTriggerLifecycle::new(
            &mut scheduler,
            WorldTriggerState {
                trigger_graph: &graph,
                trigger_state: &mut trigger_state,
                trigger_world: world,
                assertion_evaluator: &mut evaluator,
                assertion_oracle: &mut oracle,
                terminal_verdict: &mut terminal,
                initial_lifecycle_observations_pending: &mut initial_pending,
            },
        );
        assert!(lifecycle.settle_genesis_entrypoints()?.is_some());
        lifecycle.settle_trigger_graph(|at| {
            world
                .vm_nodes()
                .iter()
                .map(|node| {
                    ObservableEvent::node_state(at, node.id.clone(), NodeLifecycle::Started)
                })
                .collect()
        })?;
    }
    assert!(!initial_pending);
    assert_eq!(scheduler.quanta(), 0);
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 0 });
    assert_eq!(scheduler.trigger_wakeup(), Some(SimInstant { ticks: 3 }));

    let captured = trigger_state.to_compact_binary();
    trigger_state = EventGraphState::from_compact_binary(&captured)?;
    scheduler.set_trigger_wakeup(None, None)?;
    {
        let mut restored = WorldTriggerLifecycle::new(
            &mut scheduler,
            WorldTriggerState {
                trigger_graph: &graph,
                trigger_state: &mut trigger_state,
                trigger_world: world,
                assertion_evaluator: &mut evaluator,
                assertion_oracle: &mut oracle,
                terminal_verdict: &mut terminal,
                initial_lifecycle_observations_pending: &mut initial_pending,
            },
        );
        restored.settle_trigger_graph(|_| {
            panic!("restored world must not replay its initial observations")
        })?;
    }
    assert_eq!(scheduler.trigger_wakeup(), Some(SimInstant { ticks: 3 }));

    for _ in world.vm_nodes() {
        scheduler.drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })?;
    }
    {
        let mut restored = WorldTriggerLifecycle::new(
            &mut scheduler,
            WorldTriggerState {
                trigger_graph: &graph,
                trigger_state: &mut trigger_state,
                trigger_world: world,
                assertion_evaluator: &mut evaluator,
                assertion_oracle: &mut oracle,
                terminal_verdict: &mut terminal,
                initial_lifecycle_observations_pending: &mut initial_pending,
            },
        );
        restored.settle_trigger_graph(|_| Vec::new())?;
        assert!(restored.terminal_stop_ready());
    }
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 3 });
    assert_eq!(scheduler.trigger_wakeup(), None);
    assert_eq!(terminal, Some(QuantumTerminalVerdict::Passed));
    Ok(())
}
