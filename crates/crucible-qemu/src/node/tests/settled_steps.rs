//! Node-set steps that settle through a ceiling their clock stopped below.
//!
//! A ceiling is an upper bound (RFC-0010 SCHED-12). The scheduler must see the
//! node's actual clock and, separately, the ceiling it is settled through.

use super::*;

const CEILING: u64 = 1_000;

fn scripted_node_set(completion: ScriptedNetworkOutput) -> Result<QemuNodeSet, Box<dyn Error>> {
    let node = scripted_node_with_options(
        shared_log(),
        ScriptedNodeOptions {
            network_output: Some(completion),
            ..ScriptedNodeOptions::default()
        },
        [QemuAsyncWaitOutcome::Completed; 2],
    )?;
    let mut nodes = QemuNodeSet::new();
    nodes.insert(node_id("vm-a"), node);
    Ok(nodes)
}

#[test]
fn a_settled_horizon_reports_the_last_retirement_and_the_settled_ceiling()
-> Result<(), Box<dyn Error>> {
    let mut nodes = scripted_node_set(ScriptedNetworkOutput {
        emit_tick: 0,
        stopped_tick: 951,
        outcome: AdvanceOutcome::ReachedHorizon,
        next_deadline: None,
        frames: 0,
    })?;

    let step = nodes.step_node_to(&node_id("vm-a"), VirtualTime { ticks: CEILING })?;

    assert_eq!(step.reached, VirtualTime { ticks: 951 });
    assert_eq!(step.settled_through, VirtualTime { ticks: CEILING });
    assert!(step.is_settled());
    assert_eq!(step.outcome, AdvanceOutcome::ReachedHorizon);
    assert_eq!(step.physical_stop, BackendPhysicalStop::Horizon);
    nodes.shutdown()?;
    Ok(())
}

#[test]
fn an_idle_park_without_a_wake_keeps_its_physical_point() -> Result<(), Box<dyn Error>> {
    let mut nodes = scripted_node_set(ScriptedNetworkOutput {
        emit_tick: 0,
        stopped_tick: 400,
        outcome: AdvanceOutcome::Paused {
            at: Icount { retired: 400 },
        },
        next_deadline: Some(crucible_shmem::IDLE_WAKE_NONE),
        frames: 0,
    })?;

    let step = nodes.step_node_to(&node_id("vm-a"), VirtualTime { ticks: CEILING })?;

    // The halted node is not advanced to the ceiling; it is settled through it.
    assert_eq!(step.reached, VirtualTime { ticks: 400 });
    assert_eq!(step.settled_through, VirtualTime { ticks: CEILING });
    assert_eq!(step.physical_stop, BackendPhysicalStop::Idle);
    nodes.shutdown()?;
    Ok(())
}

#[test]
fn an_exact_event_ceiling_is_published_as_an_exact_event() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

    let step = node.step_to_with_stop(
        VirtualTime { ticks: 19 },
        crucible::RunCeilingStop::ExactEvent,
    )?;

    // The scheduler's exact event reaches the node slot as an exact event.
    let log = recorded(&log);
    assert!(log.contains(&ChannelCall::ShmemStartExact(19)), "{log:?}");
    assert!(!log.contains(&ChannelCall::ShmemStart(19)), "{log:?}");
    assert_eq!(step.reached, VirtualTime { ticks: 19 });
    assert_eq!(step.settled_through, VirtualTime { ticks: 19 });
    node.shutdown_child()?;
    Ok(())
}

fn settled_exact_event_step(stopped_tick: u64) -> Result<StepObservation, Box<dyn Error>> {
    let mut nodes = scripted_node_set(ScriptedNetworkOutput {
        emit_tick: 0,
        stopped_tick,
        outcome: AdvanceOutcome::ReachedHorizon,
        next_deadline: None,
        frames: 0,
    })?;

    let result = nodes.step_node_to_with_stop(
        &node_id("vm-a"),
        VirtualTime { ticks: CEILING },
        crucible::RunCeilingStop::ExactEvent,
    );
    nodes.shutdown()?;
    Ok(result?)
}

#[test]
fn a_running_node_settles_an_exact_event_ceiling_it_cannot_land_on() -> Result<(), Box<dyn Error>> {
    // The next retirement from 951 would end at 1001, past the exact event,
    // so the running node settles through it at its last boundary (TIME-30).
    let step = settled_exact_event_step(CEILING - crucible::SIM_TICKS_PER_INSTRUCTION + 1)?;

    assert_eq!(step.reached, VirtualTime { ticks: 951 });
    assert_eq!(step.settled_through, VirtualTime { ticks: CEILING });
    assert_eq!(step.physical_stop, BackendPhysicalStop::Horizon);
    Ok(())
}

#[test]
fn an_exact_event_ceiling_refuses_a_settlement_a_whole_retirement_below_it() {
    // From 950 a whole retirement still fits, so settling would skip the event.
    let result = settled_exact_event_step(CEILING - crucible::SIM_TICKS_PER_INSTRUCTION);

    assert!(
        matches!(
            &result,
            Err(error) if error.to_string().contains(
                "settled exact-event ceiling 1000 without arriving from 950"
            )
        ),
        "{result:?}"
    );
}

#[test]
fn an_idle_park_never_settles_past_a_staged_inbound_frame() -> Result<(), Box<dyn Error>> {
    const DELIVERY: u64 = 700;
    let node = scripted_node_with_options(
        shared_log(),
        ScriptedNodeOptions {
            // The halted guest first republishes its idle park without having
            // observed the frame, then wakes at the delivery and consumes it.
            network_output: Some(ScriptedNetworkOutput {
                emit_tick: 0,
                stopped_tick: 400,
                outcome: AdvanceOutcome::Paused {
                    at: Icount { retired: 400 },
                },
                next_deadline: Some(crucible_shmem::IDLE_WAKE_NONE),
                frames: 0,
            }),
            later_network_outputs: vec![ScriptedNetworkOutput {
                emit_tick: 0,
                stopped_tick: DELIVERY,
                outcome: AdvanceOutcome::Paused {
                    at: Icount { retired: DELIVERY },
                },
                next_deadline: None,
                frames: 0,
            }],
            cap_quanta_at_staged_inbound: true,
            ..ScriptedNodeOptions::default()
        },
        [QemuAsyncWaitOutcome::Completed; 4],
    )?;
    let mut nodes = QemuNodeSet::new();
    nodes.insert(node_id("vm-a"), node);
    nodes.apply_to_node(
        &node_id("vm-a"),
        &BackendEffect::DeliverInput(BackendInput {
            node: node_id("vm-a"),
            payload: vec![1],
        }),
        VirtualTime { ticks: DELIVERY },
    )?;

    let step = nodes.step_node_to(&node_id("vm-a"), VirtualTime { ticks: CEILING })?;

    // The staged frame's delivery tick is a wake inside the ceiling. A park
    // reported before the guest took it attests nothing past that tick, so
    // the step must carry the node through the delivery, not settle past it.
    assert_ne!(step.physical_stop, BackendPhysicalStop::Idle, "{step:?}");
    assert!(step.reached.ticks >= DELIVERY, "{step:?}");
    nodes.shutdown()?;
    Ok(())
}
