//! Exact global trigger caps for runnable/idle nodes and independent fault cadence.

use crucible::{
    ConcurrentQuantumLoop, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop,
    QuantumRequest, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerNodeVcpuIdleSnapshot, SchedulerQuiescenceBlocker, SchedulerRendezvous,
    SchedulerScenarioNode, SchedulerVcpuIdleState, SchedulingNodeKind, Shift, SimDuration,
    SimInstant, SingleScheduler, VcpuId, VirtualTime,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn scheduler(activity: SchedulerNodeActivity, shift: u8) -> TestResult<SingleScheduler> {
    Ok(SingleScheduler::new(scenario(activity, shift)?)?)
}

fn scenario(activity: SchedulerNodeActivity, shift: u8) -> TestResult<SchedulerLivenessScenario> {
    let nodes = ["a", "b"]
        .into_iter()
        .map(|name| SchedulerScenarioNode {
            id: SchedulerNodeId {
                node: NodeId { name: name.into() },
                kind: SchedulingNodeKind::Vm,
            },
            counter: NodeCounter { ticks: 0 },
            activity,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        })
        .collect();
    let mut scenario = SchedulerLivenessScenario::from_canonical_material(
        "exact-trigger-wakeup",
        Shift::new(shift)?,
        16,
        SimInstant { nanos: 100 },
        nodes,
        Vec::new(),
    );
    scenario.rendezvous = SchedulerRendezvous::every(SimDuration { nanos: 32 })?;
    Ok(scenario)
}

fn advance_both(scheduler: &mut SingleScheduler, expected: u64) -> TestResult {
    for _ in 0..2 {
        scheduler.drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })?;
    }
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: expected });
    for node in scheduler.effective_clocks()? {
        assert_eq!(node.current_time, SimInstant { nanos: expected });
    }
    Ok(())
}

#[test]
fn trigger_and_signal_wakeups_are_independent_between_rendezvous() -> TestResult {
    for activity in [SchedulerNodeActivity::Runnable, SchedulerNodeActivity::Idle] {
        let mut scheduler = scheduler(activity, 0)?;
        scheduler.set_signal_fault_wakeup(Some(5))?;
        let trigger = Some(VirtualTime { ticks: 7 });
        scheduler.set_trigger_wakeup(trigger, trigger)?;
        advance_both(&mut scheduler, 5)?;
        scheduler.set_signal_fault_wakeup(Some(11))?;
        assert_eq!(scheduler.trigger_wakeup(), Some(SimInstant { nanos: 7 }));
        advance_both(&mut scheduler, 7)?;
        scheduler.set_trigger_wakeup(None, None)?;
        assert_eq!(
            scheduler.signal_fault_wakeup(),
            Some(SimInstant { nanos: 11 })
        );
        advance_both(&mut scheduler, 11)?;
        scheduler.set_signal_fault_wakeup(None)?;
        assert!(scheduler.quiescence()?.is_quiescent());
    }
    Ok(())
}

#[test]
fn unrepresentable_or_stale_deadlines_leave_the_previous_cap_unchanged() -> TestResult {
    let mut scheduler = scheduler(SchedulerNodeActivity::Idle, 2)?;
    let valid = Some(VirtualTime { ticks: 12 });
    scheduler.set_trigger_wakeup(valid, valid)?;
    for invalid in [0, 6] {
        let at = Some(VirtualTime { ticks: invalid });
        assert!(scheduler.set_trigger_wakeup(at, at).is_err());
        assert_eq!(scheduler.trigger_wakeup(), Some(SimInstant { nanos: 12 }));
    }
    assert!(scheduler.set_trigger_wakeup(None, valid).is_err());
    advance_both(&mut scheduler, 12)?;
    assert!(scheduler.set_trigger_wakeup(valid, valid).is_err());
    Ok(())
}

#[test]
fn bookkeeping_does_not_hide_other_quiescence_blockers() -> TestResult {
    let mut scheduler = scheduler(SchedulerNodeActivity::Idle, 0)?;
    scheduler.set_trigger_wakeup(Some(VirtualTime { ticks: 8 }), None)?;
    assert!(scheduler.quiescence()?.is_quiescent());
    scheduler.set_signal_fault_wakeup(Some(13))?;
    assert!(!scheduler.quiescence()?.is_quiescent());
    scheduler.set_trigger_wakeup(
        Some(VirtualTime { ticks: 8 }),
        Some(VirtualTime { ticks: 21 }),
    )?;
    scheduler.set_signal_fault_wakeup(None)?;
    assert!(!scheduler.quiescence()?.is_quiescent());
    Ok(())
}

#[test]
fn a_new_global_deadline_cannot_rewind_an_already_advanced_node() -> TestResult {
    let mut scheduler = scheduler(SchedulerNodeActivity::Idle, 0)?;
    scheduler.set_signal_fault_wakeup(Some(15))?;
    scheduler.drive_quantum(QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    })?;
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 0 });
    assert!(
        scheduler
            .set_trigger_wakeup(
                Some(VirtualTime { ticks: 7 }),
                Some(VirtualTime { ticks: 7 })
            )
            .is_err()
    );
    assert_eq!(scheduler.trigger_wakeup(), None);
    assert_eq!(
        scheduler.signal_fault_wakeup(),
        Some(SimInstant { nanos: 15 })
    );
    Ok(())
}

#[test]
fn inactive_nodes_do_not_hold_back_the_live_frontier() -> TestResult {
    for activity in [SchedulerNodeActivity::Halted, SchedulerNodeActivity::Done] {
        let mut scheduler = scheduler(SchedulerNodeActivity::Idle, 0)?;
        let inactive = NodeId { name: "b".into() };
        scheduler.set_vm_node_activity(&inactive, activity)?;
        let at = Some(VirtualTime { ticks: 7 });
        scheduler.set_trigger_wakeup(at, at)?;
        let outcome = scheduler.drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })?;
        assert_eq!(outcome.frontier, VirtualTime { ticks: 7 });
        assert_eq!(scheduler.vm_node_activity(&inactive)?, activity);
        assert_eq!(
            scheduler.scheduler_time_for_node(&inactive)?,
            VirtualTime { ticks: 0 }
        );
    }
    Ok(())
}

#[test]
fn inactive_world_reaches_an_exact_deadline_without_running_a_backend() -> TestResult {
    let mut scheduler = scheduler(SchedulerNodeActivity::Halted, 0)?;
    let at = Some(VirtualTime { ticks: 7 });
    scheduler.set_trigger_wakeup(at, at)?;
    assert!(!scheduler.quiescence()?.is_quiescent());
    let outcome = scheduler.drive_quantum(QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    })?;
    assert_eq!(outcome.frontier, VirtualTime { ticks: 7 });
    assert_eq!(outcome.advanced_node, None);
    assert_eq!(
        scheduler.condition_event_log_prefix().point().at(),
        VirtualTime { ticks: 7 }
    );
    assert_eq!(scheduler.quanta(), 1);
    assert!(
        scheduler
            .effective_clocks()?
            .iter()
            .all(|node| node.current_time == SimInstant::EPOCH)
    );
    scheduler.set_trigger_wakeup(None, None)?;
    assert!(scheduler.quiescence()?.is_quiescent());
    Ok(())
}

#[test]
fn reactivated_node_joins_the_current_frontier_without_retiring_instructions() -> TestResult {
    let mut scheduler = scheduler(SchedulerNodeActivity::Idle, 0)?;
    let node = NodeId { name: "b".into() };
    scheduler.set_vm_node_activity(&node, SchedulerNodeActivity::Halted)?;
    let at = Some(VirtualTime { ticks: 7 });
    scheduler.set_trigger_wakeup(at, at)?;
    scheduler.drive_quantum(QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    })?;
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 7 });
    scheduler.set_trigger_wakeup(None, None)?;
    scheduler.set_vm_node_activity(&node, SchedulerNodeActivity::Runnable)?;
    assert_eq!(
        scheduler.scheduler_time_for_node(&node)?,
        VirtualTime { ticks: 7 }
    );
    assert_eq!(
        scheduler.backend_effect_time(&node, VirtualTime { ticks: 7 })?,
        VirtualTime { ticks: 0 }
    );
    let at = Some(VirtualTime { ticks: 13 });
    scheduler.set_trigger_wakeup(at, at)?;
    advance_both(&mut scheduler, 13)?;
    assert_eq!(
        scheduler.backend_effect_time(&node, VirtualTime { ticks: 13 })?,
        VirtualTime { ticks: 6 }
    );
    Ok(())
}

#[test]
fn inactive_clock_is_identical_across_serial_concurrent_and_restored_execution() -> TestResult {
    let mut serial = scheduler(SchedulerNodeActivity::Halted, 0)?;
    serial.set_signal_fault_wakeup(Some(5))?;
    serial.set_trigger_wakeup(
        Some(VirtualTime { ticks: 7 }),
        Some(VirtualTime { ticks: 7 }),
    )?;
    let mut concurrent = serial.clone();
    let request = QuantumRequest {
        configuration: serial.configuration().clone(),
        control: Vec::new(),
    };
    let first = serial.drive_quantum(request.clone())?;
    let concurrent_first = concurrent.drive_concurrent_quantum(request, 2)?;
    assert!(concurrent_first.run_set.candidates.is_empty());
    assert_eq!(
        first.event_log_segment_hash,
        concurrent_first.outcomes[0].event_log_segment_hash
    );
    assert_eq!(first.frontier, VirtualTime { ticks: 5 });
    let bytes = serial.checkpoint()?.canonical_bytes()?;
    let mut restored = scheduler(SchedulerNodeActivity::Halted, 0)?;
    crucible::SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)?
        .restore_into(&mut restored)?;
    for scheduler in [&mut serial, &mut concurrent, &mut restored] {
        scheduler.set_signal_fault_wakeup(None)?;
        scheduler.set_trigger_wakeup(
            Some(VirtualTime { ticks: 7 }),
            Some(VirtualTime { ticks: 7 }),
        )?;
    }
    let request = QuantumRequest {
        configuration: serial.configuration().clone(),
        control: Vec::new(),
    };
    let second = serial.drive_quantum(request.clone())?;
    let concurrent_second = concurrent.drive_concurrent_quantum(request.clone(), 2)?;
    let restored_second = restored.drive_quantum(request)?;
    assert_eq!(second.frontier, VirtualTime { ticks: 7 });
    assert_eq!(
        second.event_log_segment_hash,
        concurrent_second.outcomes[0].event_log_segment_hash
    );
    assert_eq!(
        second.event_log_segment_hash,
        restored_second.event_log_segment_hash
    );
    assert_eq!(serial.checkpoint()?, restored.checkpoint()?);
    Ok(())
}

#[test]
fn inactive_clock_obeys_branch_and_terminal_time_caps() -> TestResult {
    let mut scheduler = scheduler(SchedulerNodeActivity::Done, 0)?;
    scheduler.set_trigger_wakeup(
        Some(VirtualTime { ticks: 150 }),
        Some(VirtualTime { ticks: 150 }),
    )?;
    scheduler.set_branch_frontier_cap(VirtualTime { ticks: 5 })?;
    for expected in [5, 5] {
        let outcome = scheduler.drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })?;
        assert_eq!(outcome.frontier, VirtualTime { ticks: expected });
        assert!(outcome.advanced_node.is_none());
    }
    assert_eq!(scheduler.quanta(), 1);
    scheduler.clear_branch_frontier_cap();
    for expected in [100, 100] {
        let outcome = scheduler.drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })?;
        assert_eq!(outcome.frontier, VirtualTime { ticks: expected });
    }
    assert_eq!(scheduler.quanta(), 2);
    Ok(())
}

#[test]
fn stopped_vcpu_reports_do_not_block_quiescence_and_resume_preserves_timer_delays() -> TestResult {
    let mut scenario = scenario(SchedulerNodeActivity::Halted, 0)?;
    let node = scenario.nodes[1].id.clone();
    scenario.nodes[1].exact_local_event = ExactLocalEvent::TimerDeadline {
        virtual_time: SimInstant { nanos: 2 },
    };
    let scenario = scenario.with_vcpu_idle_snapshot(SchedulerNodeVcpuIdleSnapshot::new(
        node.clone(),
        1,
        vec![SchedulerVcpuIdleState {
            vcpu: VcpuId { index: 0 },
            halted: false,
            next_deadline: Some(SimInstant { nanos: 3 }),
            pending_input: true,
        }],
    )?)?;
    let mut scheduler = SingleScheduler::new(scenario)?;
    assert!(scheduler.quiescence()?.is_quiescent());
    scheduler.set_trigger_wakeup(
        Some(VirtualTime { ticks: 7 }),
        Some(VirtualTime { ticks: 7 }),
    )?;
    scheduler.drive_quantum(QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    })?;
    scheduler.set_trigger_wakeup(None, None)?;
    scheduler.set_vm_node_activity(&node.node, SchedulerNodeActivity::Idle)?;
    let quiescence = scheduler.quiescence()?;
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingVcpuTimer {
                node: node.clone(),
                vcpu: VcpuId { index: 0 },
                deadline: SimInstant { nanos: 10 },
            })
    );
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingExactLocalEvent {
                node,
                event: ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 9 }
                },
            })
    );
    Ok(())
}

#[test]
fn overflowing_resume_timer_rejects_the_entire_activity_batch() -> TestResult {
    let mut scenario = scenario(SchedulerNodeActivity::Halted, 0)?;
    let nodes = scenario
        .nodes
        .iter()
        .map(|node| node.id.node.clone())
        .collect::<Vec<_>>();
    scenario.nodes[1].exact_local_event = ExactLocalEvent::TimerDeadline {
        virtual_time: SimInstant { nanos: u64::MAX },
    };
    let mut scheduler = SingleScheduler::new(scenario)?;
    scheduler.set_trigger_wakeup(
        Some(VirtualTime { ticks: 7 }),
        Some(VirtualTime { ticks: 7 }),
    )?;
    scheduler.drive_quantum(QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    })?;
    let before = scheduler.checkpoint()?;
    assert!(
        scheduler
            .set_vm_nodes_activity(&nodes, SchedulerNodeActivity::Runnable)
            .is_err()
    );
    assert_eq!(scheduler.checkpoint()?, before);
    assert!(
        scheduler
            .set_vm_node_activities(
                &nodes
                    .iter()
                    .cloned()
                    .map(|node| (node, SchedulerNodeActivity::Runnable))
                    .collect::<Vec<_>>()
            )
            .is_err()
    );
    assert_eq!(scheduler.checkpoint()?, before);
    assert!(
        scheduler
            .set_vm_nodes_activity(
                &[nodes[0].clone(), nodes[0].clone()],
                SchedulerNodeActivity::Runnable
            )
            .is_err()
    );
    assert_eq!(scheduler.checkpoint()?, before);
    Ok(())
}

#[test]
fn initially_inactive_world_preserves_its_supplied_clock_origin() -> TestResult {
    let mut scenario = scenario(SchedulerNodeActivity::Halted, 0)?;
    for node in &mut scenario.nodes {
        node.counter = NodeCounter { ticks: 5 };
    }
    let mut scheduler = SingleScheduler::new(scenario)?;
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 5 });
    scheduler.set_trigger_wakeup(
        Some(VirtualTime { ticks: 7 }),
        Some(VirtualTime { ticks: 7 }),
    )?;
    scheduler.drive_quantum(QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    })?;
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 7 });
    assert!(
        scheduler
            .effective_clocks()?
            .iter()
            .all(|node| node.current_time == SimInstant { nanos: 5 })
    );
    Ok(())
}

#[test]
fn inactive_topology_activation_waits_for_its_global_time() -> TestResult {
    let mut scenario = scenario(SchedulerNodeActivity::Halted, 0)?;
    scenario = scenario.with_topology_change(
        crucible::SchedulerTopologyChange::partition(0, Vec::new())
            .with_activation_time(SimInstant { nanos: 7 }),
    );
    let mut scheduler = SingleScheduler::new(scenario.clone())?;
    assert!(!scheduler.apply_queued_topology_changes_at_boundary()?);
    assert!(scheduler.rendezvous_records().is_empty());
    scheduler.drive_quantum(QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    })?;
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 7 });
    assert!(scheduler.apply_queued_topology_changes_at_boundary()?);
    assert_eq!(scheduler.rendezvous_records().len(), 1);
    assert!(scheduler.rendezvous_records()[0].nodes.is_empty());
    let report = crucible::check_scheduler_liveness(scenario)?;
    assert_eq!(report.frontier, VirtualTime { ticks: 7 });
    assert_eq!(report.terminal, crucible::SchedulerTerminal::Quiescent);
    assert!(report.advanced_nodes.is_empty());
    Ok(())
}

#[test]
fn stopping_the_lagging_node_publishes_the_already_reached_frontier() -> TestResult {
    let mut scheduler = scheduler(SchedulerNodeActivity::Idle, 0)?;
    scheduler.set_trigger_wakeup(
        Some(VirtualTime { ticks: 7 }),
        Some(VirtualTime { ticks: 7 }),
    )?;
    scheduler.drive_quantum(QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    })?;
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 0 });
    scheduler.set_vm_node_activity(&NodeId { name: "b".into() }, SchedulerNodeActivity::Halted)?;
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 7 });
    assert_eq!(
        scheduler.condition_event_log_prefix().point().at(),
        VirtualTime { ticks: 7 }
    );
    Ok(())
}
