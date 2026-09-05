//! Lifecycle-owned exact deadline reconstruction before scheduler advancement.

use super::*;

#[test]
fn restored_trigger_state_rearms_the_exact_scheduler_cap_before_run()
-> Result<(), Box<dyn std::error::Error>> {
    let base = initially_violated_scenario();
    let world = base.world();
    let timer = crucible::TimerId {
        name: "finish".into(),
    };
    let graph = EventGraph::builder()
        .event("begin")
        .entrypoint()
        .action(crucible::Action::arm_timer(
            timer.clone(),
            SimDuration { nanos: 3 },
        ))
        .event("complete")
        .when(crucible::Condition::AllOf {
            predicates: vec![
                crucible::Condition::at(VirtualTime { ticks: 3 }),
                crucible::Condition::after(
                    SimDuration { nanos: 3 },
                    crucible::EventId::from_name("begin"),
                ),
                crucible::Condition::timer(timer),
            ],
        })
        .action(crucible::Action::Pass)
        .build_for_world(world)?;
    let plan = crucible::Plan::from_event_graph_for_world(world, graph)?;
    let source = ScenarioDefForm::from_components(
        world,
        &plan,
        &crucible::Properties::empty(),
        crucible::Seed::from_u64(42),
    )?;
    let mut lifecycle = production_loop_without_backends(&source);
    lifecycle.settle_genesis_entrypoints()?;
    lifecycle.settle_trigger_graph()?;
    assert_eq!(
        lifecycle.inner.loop_impl().trigger_wakeup(),
        Some(SimInstant { nanos: 3 })
    );

    // The wakeup itself is not checkpoint authority. Recreate it from the
    // portable trigger continuation and scheduler-owned armed timers.
    let saved = lifecycle.trigger_state.to_compact_binary();
    lifecycle
        .inner
        .loop_impl_mut()
        .set_trigger_wakeup(None, None)?;
    lifecycle.trigger_state = EventGraphState::from_compact_binary(&saved)?;
    lifecycle.settle_trigger_graph()?;
    assert_eq!(
        lifecycle.inner.loop_impl().trigger_wakeup(),
        Some(SimInstant { nanos: 3 })
    );

    // Drive the scheduler model directly; this unit test intentionally owns no
    // real QEMU backend. The packaged flight covers the actual RUN boundary.
    for _ in 0..world.vm_nodes().len() {
        let scheduler = lifecycle.inner.loop_impl_mut();
        scheduler.drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })?;
    }
    assert_eq!(
        lifecycle.inner.loop_impl().frontier(),
        VirtualTime { ticks: 3 }
    );
    let appends = lifecycle.settle_trigger_graph()?;
    assert!(appends.iter().flat_map(|append| &append.entries).any(|entry| {
        matches!(entry.payload(), crucible::SchedulerEventLogPayload::TriggerFired(firing)
            if firing.event() == &crucible::EventId::from_name("complete") && firing.at() == VirtualTime { ticks: 3 })
    }));
    assert_eq!(lifecycle.inner.loop_impl().trigger_wakeup(), None);
    assert!(matches!(
        lifecycle.terminal_verdict_for_stop(),
        Some(QuantumTerminalVerdict::Passed)
    ));
    Ok(())
}
