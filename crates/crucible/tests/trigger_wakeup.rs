//! Exact global trigger caps for runnable/idle nodes and independent fault cadence.

use crucible::{
    ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerRendezvous,
    SchedulerScenarioNode, SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler,
    VirtualTime,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn scheduler(activity: SchedulerNodeActivity, shift: u8) -> TestResult<SingleScheduler> {
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
    Ok(SingleScheduler::new(scenario)?)
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
