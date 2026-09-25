//! Lifecycle-owned exact deadline reconstruction before scheduler advancement.

use super::*;

#[test]
fn restored_trigger_state_rearms_the_exact_scheduler_cap_before_run()
-> Result<(), Box<dyn std::error::Error>> {
    restored_trigger_deadline(false)
}

#[test]
fn restored_trigger_state_reaches_its_deadline_with_no_active_nodes()
-> Result<(), Box<dyn std::error::Error>> {
    restored_trigger_deadline(true)
}

fn restored_trigger_deadline(inactive: bool) -> Result<(), Box<dyn std::error::Error>> {
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
            SimDuration { ticks: 3 },
        ))
        .event("complete")
        .when(crucible::Condition::AllOf {
            predicates: vec![
                crucible::Condition::at(VirtualTime { ticks: 3 }),
                crucible::Condition::after(
                    SimDuration { ticks: 3 },
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
    if inactive {
        for node in world.vm_nodes() {
            lifecycle
                .inner
                .loop_impl_mut()
                .set_vm_node_activity(&node.id, SchedulerNodeActivity::Halted)?;
        }
    }
    lifecycle.settle_genesis_entrypoints()?;
    lifecycle.settle_trigger_graph()?;
    assert_eq!(
        lifecycle.inner.loop_impl().trigger_wakeup(),
        Some(SimInstant { ticks: 3 })
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
        Some(SimInstant { ticks: 3 })
    );

    // Drive the scheduler model directly; this unit test intentionally owns no
    // real QEMU backend. The packaged flight covers the actual RUN boundary.
    for _ in 0..if inactive { 1 } else { world.vm_nodes().len() } {
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

#[test]
fn terminal_network_pass_waits_for_the_shared_frontier_to_commit_prior_output()
-> Result<(), Box<dyn std::error::Error>> {
    let base = initially_violated_scenario();
    let world = base.world();
    let source_node = NodeId {
        name: String::from("db-0"),
    };
    let peer_node = NodeId {
        name: String::from("db-1"),
    };
    let link = crucible::LinkId::for_endpoints(&source_node, &peer_node);
    let graph = EventGraph::builder()
        .event("peer-observed")
        .when(crucible::Predicate::network_match(
            Some(link.clone()),
            crucible::FramePredicate::contains(b"selected".to_vec()),
        ))
        .action(Action::Pass)
        .build_for_world(world)?;
    let plan = crucible::Plan::from_event_graph_for_world(world, graph)?;
    let scenario = ScenarioDefForm::from_components(
        world,
        &plan,
        &crucible::Properties::empty(),
        Seed::from_u64(42),
    )?;
    let mut lifecycle = production_loop_without_backends(&scenario);
    lifecycle.settle_genesis_entrypoints()?;
    lifecycle.settle_trigger_graph()?;
    lifecycle.initial_lifecycle_observations_pending = false;
    assert!(lifecycle.exact_checkpoint_ready()?);

    let mut frame = vec![0_u8; 60];
    frame[..6].copy_from_slice(&crucible::deterministic_node_mac(&peer_node));
    frame[6..12].copy_from_slice(&crucible::deterministic_node_mac(&source_node));
    frame[12..14].copy_from_slice(&[0x88, 0xb5]);
    frame[14..26].copy_from_slice(b"prior-output");
    let pending = crucible::BackendNetworkOutput {
        source: source_node.clone(),
        destination: peer_node,
        emit_icount: Icount { retired: 2 },
        sequence: 3,
        payload: frame,
        route: None,
        fault_continuation: crucible::BackendNetworkFaultContinuation::default(),
    };
    lifecycle
        .inner
        .network_transaction_parts_mut()
        .3
        .push(pending);
    assert!(!lifecycle.exact_checkpoint_ready()?);
    lifecycle
        .inner
        .loop_impl_mut()
        .append_observable_events(vec![ObservableEvent::network_delivered(
            VirtualTime { ticks: 3 },
            Some(link),
            b"selected".to_vec(),
        )])?;

    lifecycle.settle_trigger_graph()?;

    assert_eq!(lifecycle.inner.pending_network_output_count(), 1);
    assert_eq!(
        lifecycle.inner.loop_impl().frontier(),
        VirtualTime { ticks: 0 }
    );
    assert_eq!(
        lifecycle.inner.loop_impl().trigger_wakeup(),
        Some(SimInstant { ticks: 3 })
    );
    assert!(lifecycle.terminal_verdict_for_stop().is_none());
    assert!(matches!(
        lifecycle.terminal_verdict,
        Some(QuantumTerminalVerdict::Passed)
    ));

    // The cap lets every modeled node reach the pass point without running
    // beyond it. The sender's earlier frame is admitted exactly once there.
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

    // This model-only test has no QEMU backend to publish a quantum. Restore
    // the adapter at the scheduler's committed frontier with the same queued
    // frame, then exercise its ordinary network settlement path.
    let scheduler = lifecycle.inner.loop_impl().clone();
    let interceptor = lifecycle.inner.network_output_interceptor().clone();
    let pending = std::mem::take(lifecycle.inner.network_transaction_parts_mut().3);
    lifecycle.inner = BackendQuantumLoop::from_restored_network_state(
        scheduler,
        QemuNodeSet::new(),
        interceptor,
        pending,
        VirtualTime { ticks: 3 },
    );
    lifecycle
        .inner
        .settle_pending_network_outputs_at_current_frontier()?;
    assert_eq!(lifecycle.inner.pending_network_output_count(), 0);
    assert!(lifecycle.exact_checkpoint_ready()?);
    let repeated = lifecycle
        .inner
        .settle_pending_network_outputs_at_current_frontier()?;
    let (decisions, configuration, appends) = repeated.into_parts();
    assert!(decisions.is_empty());
    assert!(configuration.is_none());
    assert!(appends.is_empty());

    lifecycle.settle_trigger_graph()?;
    assert_eq!(lifecycle.inner.loop_impl().trigger_wakeup(), None);
    assert!(matches!(
        lifecycle.terminal_verdict_for_stop(),
        Some(QuantumTerminalVerdict::Passed)
    ));
    Ok(())
}
