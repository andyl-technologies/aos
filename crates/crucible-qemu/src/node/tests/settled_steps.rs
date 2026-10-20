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
