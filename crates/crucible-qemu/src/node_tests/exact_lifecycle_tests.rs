//! Exact snapshot, teardown, and coverage lifecycle tests.

use super::*;

#[test]
fn exact_snapshot_rejects_staged_fault_event_ownership() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node =
        scripted_node_with_fault_events(Arc::clone(&log), [fault_event_with_sequence(1)])?;
    let mut checkpoint = checkpoint("pending-fault-event");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );

    let error = node
        .capture_exact_snapshot(&node_identity, checkpoint)
        .expect_err("staged occurrence ownership must reject canonical capture");
    assert!(error.to_string().contains("empty fault-event continuation"));
    assert!(!recorded(&log).contains(&ChannelCall::QmpStop));
    node.shutdown_child()?;
    Ok(())
}

#[test]
fn qemu_node_captures_one_identity_bound_vmstate_and_host_io_pair() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let mut checkpoint = checkpoint("paired-exact");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );

    let snapshot = node.capture_exact_snapshot(&node_identity, checkpoint.clone())?;

    assert_eq!(snapshot.checkpoint(), &checkpoint);
    assert_eq!(
        snapshot.host_io().execution_binding(),
        snapshot.checkpoint().id
    );
    assert_eq!(
        snapshot.replay_oracle_validation(),
        crate::QemuReplayOracleValidation::NotRun
    );
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpStop,
            ChannelCall::HostCheckpointClearWhileStopped,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpExactSave(snapshot.checkpoint().id),
            ChannelCall::QmpContinue,
        ]
    );
    Ok(())
}

#[test]
fn publication_exact_capture_resumes_only_after_explicit_release() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let mut checkpoint = checkpoint("paused-exact");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );

    let snapshot = node.capture_exact_snapshot_for_publication(&node_identity, checkpoint)?;
    assert_eq!(
        snapshot.host_io().execution_binding(),
        snapshot.checkpoint().id
    );
    assert!(!recorded(&log).contains(&ChannelCall::QmpContinue));

    node.resume_after_exact_snapshot()?;
    assert_eq!(recorded(&log).last(), Some(&ChannelCall::QmpContinue));
    Ok(())
}

#[test]
fn terminal_lifecycle_capture_uses_the_existing_qemu_stop_fence() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let mut checkpoint = checkpoint("terminal-exact");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );

    let snapshot = node.capture_terminal_lifecycle_snapshot(&node_identity, checkpoint.clone())?;

    assert_eq!(snapshot.checkpoint(), &checkpoint);
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpStop,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpExactSave(snapshot.checkpoint().id),
        ]
    );
    Ok(())
}

#[test]
fn qemu_node_terminates_after_failed_exact_capture() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, true)?;
    let mut checkpoint = checkpoint("failed-exact");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );

    let error = node
        .capture_exact_snapshot(&node_identity, checkpoint.clone())
        .expect_err("failed QMP save must reject the paired checkpoint");

    assert!(error.to_string().contains("save_checkpoint_vmstate"));
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpStop,
            ChannelCall::HostCheckpointClearWhileStopped,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpExactSave(checkpoint.id),
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );
    assert!(node.child_reaped());
    Ok(())
}

#[test]
fn qemu_node_actively_aborts_plugin_pause_when_qmp_stop_fails() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            fail_qmp_stop: true,
            ..ScriptedNodeOptions::default()
        },
        [QemuAsyncWaitOutcome::Completed],
    )?;
    let mut checkpoint = checkpoint("failed-stop");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );

    let error = node
        .capture_exact_snapshot(&node_identity, checkpoint)
        .expect_err("failed QMP stop must reject the checkpoint");
    let calls = recorded(&log);

    assert!(error.to_string().contains("injected QMP stop failure"));
    assert!(calls.contains(&ChannelCall::QmpStop));
    assert!(calls.contains(&ChannelCall::HostCheckpointAbort));
    assert!(!calls.contains(&ChannelCall::HostCheckpointClearWhileStopped));
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call, ChannelCall::QmpExactSave(_)))
    );
    Ok(())
}

#[test]
fn qemu_node_appends_quantum_coverage_to_the_unified_event_log() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let event = ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
    let mut node = scripted_node_with_coverage(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        [QemuAsyncWaitOutcome::Completed],
        [vec![event]],
        std::iter::empty(),
    )?;
    let mut event_log = EventLog::new();

    let (outcome, append) =
        node.advance_to_ceiling_with_event_log(Icount { retired: 19 }, &mut event_log)?;

    assert_eq!(outcome, AdvanceOutcome::ReachedHorizon);
    assert_eq!(append.entries.len(), 1);
    let projection = event_log_coverage_projection(&append.entries);
    assert_eq!(projection.len(), 1);
    assert_eq!(projection.entries()[0].at.icount, Icount { retired: 17 });
    assert_eq!(
        projection.entries()[0].observation,
        EventLogCoverageObservation::BasicBlock {
            node: node_id("vm-a"),
            guest_pc: 0x4010,
            block_len: 4,
        }
    );
    let (shutdown, _final_append) = node.shutdown_child_with_event_log(&mut event_log)?;
    assert!(shutdown.reaped);
    Ok(())
}

#[test]
fn qemu_node_rejects_a_coverage_quantum_without_an_event_log() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let event = ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
    let mut node = scripted_node_with_coverage(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        [QemuAsyncWaitOutcome::Completed],
        [vec![event]],
        std::iter::empty(),
    )?;

    assert_eq!(
        node.advance_to_ceiling(Icount { retired: 19 }),
        Err(QemuNodeError::CoverageEventLogRequired)
    );
    let mut event_log = EventLog::new();
    let (shutdown, append) = node.shutdown_child_with_event_log(&mut event_log)?;
    assert!(shutdown.reaped);
    assert!(append.entries.is_empty());
    Ok(())
}

#[test]
fn qemu_node_rejects_authoritative_warm_restore_without_coverage_generation_reset()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let setup_event =
        ObservableEvent::coverage_block(Icount { retired: 3 }, node_id("vm-a"), 0x4010, 4);
    let mut node = scripted_node_with_coverage(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        std::iter::empty(),
        [vec![setup_event]],
        std::iter::empty(),
    )?;

    let error = node
        .prepare_authoritative_observation_stream()
        .expect_err("publish-once setup coverage must fail closed");
    assert!(matches!(error, QemuNodeError::CoverageEventLog { .. }));

    let mut event_log = EventLog::new();
    let (shutdown, _) = node.shutdown_child_with_event_log(&mut event_log)?;
    assert!(shutdown.reaped);
    Ok(())
}

#[test]
fn qemu_node_generic_backend_drains_coverage_without_a_local_side_record()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let event = ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
    let mut node = scripted_node_with_coverage(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        [QemuAsyncWaitOutcome::Completed],
        [vec![event]],
        std::iter::empty(),
    )?;

    let step = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 19 })?;
    assert_eq!(step.reached, VirtualTime { ticks: 19 });
    let observations = SimulationBackend::drain_observable_events(&mut node)?;
    assert_eq!(observations.len(), 1);
    assert!(SimulationBackend::drain_observable_events(&mut node)?.is_empty());

    let mut event_log = EventLog::new();
    let append = event_log.append_observable_events(observations)?;
    assert_eq!(event_log_coverage_projection(&append.entries).len(), 1);
    SimulationBackend::shutdown(&mut node)?;
    assert!(node.child_reaped());
    SimulationBackend::shutdown(&mut node)?;
    assert!(node.child_reaped());
    Ok(())
}

#[test]
fn qemu_node_stamps_polled_console_at_the_scheduler_boundary() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let spool = QemuConsoleObservationSpool::new();
    spool.append(b"guest output")?;
    let mut node = scripted_node_with_options(
        log,
        ScriptedNodeOptions::default(),
        [QemuAsyncWaitOutcome::Completed],
    )?
    .with_console_observation(node_id("vm-a"), spool);

    let boundary = VirtualTime { ticks: 97 };
    SimulationBackend::step_to(&mut node, boundary)?;
    node.last_observed_time = VirtualTime { ticks: 3 };
    let observations = SimulationBackend::drain_observable_events(&mut node)?;

    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].at(), boundary);
    SimulationBackend::shutdown(&mut node)?;
    Ok(())
}

#[test]
fn qemu_node_drains_final_coverage_before_teardown() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let event = ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
    let mut node = scripted_node_with_coverage(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        std::iter::empty(),
        std::iter::empty(),
        [event],
    )?;
    let mut event_log = EventLog::new();

    let (report, append) = node.shutdown_child_with_event_log(&mut event_log)?;

    assert!(report.reaped);
    assert!(node.child_reaped());
    let projection = event_log_coverage_projection(&append.entries);
    assert_eq!(projection.len(), 1);
    assert_eq!(projection.entries()[0].at.icount, Icount { retired: 17 });
    Ok(())
}

#[test]
fn qemu_node_satisfies_simulation_backend_trait() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_runtime(
        Arc::clone(&log),
        false,
        false,
        false,
        [
            QemuAsyncWaitOutcome::Completed,
            QemuAsyncWaitOutcome::Completed,
        ],
    )?;

    let observation = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 23 })?;
    assert_eq!(observation.reached, VirtualTime { ticks: 23 });
    assert_eq!(SimulationBackend::now(&node), VirtualTime { ticks: 23 });

    assert!(matches!(
        SimulationBackend::apply(
            &mut node,
            &BackendEffect::Noop,
            VirtualTime { ticks: 22 },
        ),
        Err(BackendError::Rejected { message })
            if message.contains("does not match physical node time")
    ));
    SimulationBackend::apply(
        &mut node,
        &BackendEffect::DeliverInput(BackendInput {
            node: node_id("vm-a"),
            payload: vec![3, 2, 1],
        }),
        VirtualTime { ticks: 23 },
    )?;
    let sample = SimulationBackend::fingerprint(&mut node, node_id("vm-a"))?;
    assert_eq!(sample.node, node_id("vm-a"));
    assert_eq!(sample.at, VirtualTime { ticks: 23 });
    assert_eq!(
        sample.fingerprint,
        ExecutionFingerprint {
            hash: content_hash("fingerprint", "vm-a"),
        }
    );

    assert!(matches!(
        SimulationBackend::snapshot(&mut node),
        Err(BackendError::Rejected { message })
            if message.contains("capture_exact_snapshot")
    ));
    let later = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 29 })?;
    assert_eq!(later.reached, VirtualTime { ticks: 29 });
    assert_eq!(SimulationBackend::now(&node), VirtualTime { ticks: 29 });
    SimulationBackend::shutdown(&mut node)?;

    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::HostYield,
            ChannelCall::ShmemStart(23),
            ChannelCall::HostAwait {
                wait: QemuAsyncWait::AdvanceCompletion,
                timeout: Duration::from_millis(4),
                outcome: QemuAsyncWaitOutcome::Completed,
            },
            ChannelCall::ShmemFinish(23),
            ChannelCall::HostYield,
            ChannelCall::ShmemDeliver {
                node: String::from("vm-a"),
                payload: vec![3, 2, 1],
            },
            ChannelCall::ShmemFingerprint,
            ChannelCall::HostYield,
            ChannelCall::ShmemStart(29),
            ChannelCall::HostAwait {
                wait: QemuAsyncWait::AdvanceCompletion,
                timeout: Duration::from_millis(4),
                outcome: QemuAsyncWaitOutcome::Completed,
            },
            ChannelCall::ShmemFinish(29),
            ChannelCall::HostYield,
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );

    Ok(())
}
