//! Production node-step output boundaries and explicit resume ordering.

use super::*;

const FRAME_TICK: u64 = 664_186_219_000;
const REQUESTED_CEILING: u64 = 664_250_999_999;

fn output_node(
    log: SharedLog,
    output: ScriptedNetworkOutput,
) -> Result<QemuNodeSet, Box<dyn Error>> {
    let node = scripted_node_with_options(
        log,
        ScriptedNodeOptions {
            network_output: Some(output),
            ..ScriptedNodeOptions::default()
        },
        [QemuAsyncWaitOutcome::Completed; 2],
    )?;
    let mut nodes = QemuNodeSet::new();
    nodes.insert(node_id("vm-a"), node);
    Ok(nodes)
}

#[test]
fn network_output_stops_at_its_frame_coordinate_before_idle_frontier_promotion()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut nodes = output_node(
        Arc::clone(&log),
        ScriptedNetworkOutput {
            emit_tick: FRAME_TICK,
            stopped_tick: FRAME_TICK,
            outcome: AdvanceOutcome::Paused {
                at: Icount {
                    retired: FRAME_TICK,
                },
            },
            next_deadline: Some(REQUESTED_CEILING + 1),
        },
    )?;

    let first = nodes.step_node_to(
        &node_id("vm-a"),
        VirtualTime {
            ticks: REQUESTED_CEILING,
        },
    )?;

    assert_eq!(first.physical_stop, BackendPhysicalStop::NetworkOutput);
    assert_eq!(first.reached.ticks, FRAME_TICK);
    assert_eq!(
        first.outcome,
        AdvanceOutcome::Paused {
            at: Icount {
                retired: FRAME_TICK
            }
        }
    );
    let frames = nodes.drain_network_outputs()?;
    assert_eq!(frames.len(), 2);
    assert_eq!(
        frames
            .iter()
            .map(|frame| frame.sequence)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert!(
        frames
            .iter()
            .all(|frame| frame.emit_icount.retired == FRAME_TICK)
    );
    assert_eq!(
        recorded(&log)
            .iter()
            .filter(|call| matches!(call, ChannelCall::ShmemStart(_)))
            .count(),
        1
    );
    assert!(recorded(&log).contains(&ChannelCall::QmpStop));
    assert!(!recorded(&log).contains(&ChannelCall::QmpContinue));

    log.lock().unwrap().clear();
    let next = nodes.step_node_to(
        &node_id("vm-a"),
        VirtualTime {
            ticks: REQUESTED_CEILING,
        },
    )?;
    let calls = recorded(&log);
    let ceiling_publication = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::ShmemStart(_)))
        .unwrap();
    let resume = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpContinue))
        .unwrap();
    assert!(ceiling_publication < resume);
    assert_eq!(next.physical_stop, BackendPhysicalStop::Horizon);
    assert_eq!(next.reached.ticks, REQUESTED_CEILING);
    assert!(nodes.drain_network_outputs()?.is_empty());
    nodes.shutdown()?;
    Ok(())
}

#[test]
fn retained_http_frame_and_later_physical_pause_remain_a_boundary_refusal()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut nodes = output_node(
        Arc::clone(&log),
        ScriptedNetworkOutput {
            emit_tick: FRAME_TICK,
            stopped_tick: 664_187_986_400,
            outcome: AdvanceOutcome::Paused {
                at: Icount {
                    retired: 664_187_986_400,
                },
            },
            next_deadline: Some(REQUESTED_CEILING + 1),
        },
    )?;

    let failure = nodes
        .step_node_to(
            &node_id("vm-a"),
            VirtualTime {
                ticks: REQUESTED_CEILING,
            },
        )
        .unwrap_err();

    assert!(
        failure.to_string().contains(
            "frame 0 was emitted at 664186219000 but the producer stopped at 664187986400"
        )
    );
    assert!(!recorded(&log).contains(&ChannelCall::QmpStop));
    assert!(!recorded(&log).contains(&ChannelCall::QmpContinue));
    nodes.shutdown()?;
    Ok(())
}

#[test]
fn network_output_source_checkpoint_resume_releases_the_retained_native_stop()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            network_output: Some(ScriptedNetworkOutput {
                emit_tick: 11,
                stopped_tick: 11,
                outcome: AdvanceOutcome::Paused {
                    at: Icount { retired: 11 },
                },
                next_deadline: Some(20),
            }),
            ..ScriptedNodeOptions::default()
        },
        [QemuAsyncWaitOutcome::Completed; 2],
    )?;
    let output = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 19 })?;
    assert_eq!(output.physical_stop, BackendPhysicalStop::NetworkOutput);
    assert!(node.network_output_resume_pending);

    node.pause_at_exact_checkpoint_boundary()?;
    assert!(node.network_output_resume_pending);
    node.resume_after_exact_snapshot()?;
    assert!(!node.network_output_resume_pending);
    log.lock().unwrap().clear();

    let next = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 19 })?;
    assert_eq!(next.physical_stop, BackendPhysicalStop::Horizon);
    assert!(recorded(&log).contains(&ChannelCall::ShmemStart(19)));
    assert!(!recorded(&log).contains(&ChannelCall::QmpContinue));
    node.shutdown_child()?;
    Ok(())
}
