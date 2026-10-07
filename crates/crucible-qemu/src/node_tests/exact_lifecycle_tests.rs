//! Exact snapshot, teardown, and coverage lifecycle tests.

use super::*;

#[test]
fn exact_checkpoint_pause_orders_quiesce_stop_and_release() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    node.synchronize_observed_time()?;
    log.lock().unwrap().clear();

    node.pause_at_exact_checkpoint_boundary()?;

    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::HostCheckpointQuiesce,
            ChannelCall::QmpStop,
            ChannelCall::HostCheckpointClearWhileStopped,
            ChannelCall::ShmemCurrentIcount,
        ]
    );
    node.shutdown_child()?;
    Ok(())
}

#[test]
fn exact_checkpoint_pause_aborts_plugin_pause_when_qmp_stop_fails() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            fail_qmp_stop: true,
            ..ScriptedNodeOptions::default()
        },
        std::iter::empty(),
    )?;
    node.synchronize_observed_time()?;
    log.lock().unwrap().clear();

    let error = node
        .pause_at_exact_checkpoint_boundary()
        .expect_err("QMP stop failure must reject exact pause");

    assert!(error.to_string().contains("injected QMP stop failure"));
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::HostCheckpointQuiesce,
            ChannelCall::QmpStop,
            ChannelCall::HostCheckpointAbort,
        ]
    );
    node.shutdown_child()?;
    Ok(())
}

#[test]
fn permanent_failure_retires_and_removes_the_authoritative_generation() -> Result<(), Box<dyn Error>>
{
    let log = shared_log();
    let identity = node_id("vm-a");
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    node.force_quarantine_and_reap()?;
    let mut nodes = QemuNodeSet::new();
    assert!(nodes.insert(identity.clone(), node).is_none());

    let plan = nodes.prepare_terminal_replacements(vec![identity.clone()])?;
    let retired = nodes.commit_terminal_replacements(plan, vec![None]);

    assert!(nodes.is_empty());
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].0, identity);
    assert!(nodes.fault_capabilities(&retired[0].0).is_err());
    Ok(())
}

#[test]
fn restored_replacement_requires_explicit_release_after_install() -> Result<(), Box<dyn Error>> {
    let current_log = shared_log();
    let replacement_log = shared_log();
    let identity = node_id("vm-a");
    let mut current = scripted_node(Arc::clone(&current_log), false, false, false)?;
    current.force_quarantine_and_reap()?;
    let replacement = scripted_node(Arc::clone(&replacement_log), false, false, false)?;
    let mut nodes = QemuNodeSet::new();
    assert!(nodes.insert(identity.clone(), current).is_none());

    let plan = nodes.prepare_terminal_replacements(vec![identity.clone()])?;
    let retired = nodes.commit_terminal_replacements(plan, vec![Some(replacement)]);
    assert_eq!(retired.len(), 1);
    assert!(!recorded(&replacement_log).contains(&ChannelCall::QmpContinue));

    nodes.resume_restored_generation(&identity)?;
    assert!(recorded(&replacement_log).contains(&ChannelCall::QmpContinue));
    nodes.shutdown()?;
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

    let snapshot = node
        .capture_terminal_lifecycle_snapshot_shared(&node_identity, Arc::new(checkpoint.clone()))?;
    let cloned = snapshot.clone();

    assert_eq!(snapshot.checkpoint(), &checkpoint);
    assert!(std::ptr::eq(snapshot.checkpoint(), cloned.checkpoint()));
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
    assert_eq!(
        projection.entries()[0].at.retired,
        Some(Icount { retired: 17 })
    );
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
fn qemu_node_preserves_priming_coverage_for_the_authoritative_drain() -> Result<(), Box<dyn Error>>
{
    let log = shared_log();
    let event = ObservableEvent::coverage_block(Icount { retired: 7 }, node_id("vm-a"), 0x4010, 4);
    let ready_boundary = VirtualTime { ticks: 19 };
    let mut node =
        scripted_node_with_options(log, ScriptedNodeOptions::default(), std::iter::empty())?
            .with_priming_observable_events(vec![event.clone()], ready_boundary);

    let observations = SimulationBackend::drain_observable_events(&mut node)?;
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].at(), ready_boundary);
    assert_eq!(observations[0].payload(), event.payload());
    assert!(SimulationBackend::drain_observable_events(&mut node)?.is_empty());
    SimulationBackend::shutdown(&mut node)?;
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
fn qemu_node_discards_pre_authoritative_observations_after_coverage_generation_reset()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let setup_event =
        ObservableEvent::coverage_block(Icount { retired: 3 }, node_id("vm-a"), 0x4010, 4);
    let mut node = scripted_node_with_coverage(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        std::iter::empty(),
        std::iter::empty::<Vec<ObservableEvent>>(),
        [setup_event],
    )?;

    assert_eq!(node.prepare_authoritative_observation_stream()?, 1);

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
fn console_socket_availability_changes_boundaries_without_changing_steps_or_bytes() {
    use crate::console_observation::QemuConsoleObservationReader;
    use crucible::ObservableEventPayload;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    struct ObservedPartition {
        steps: [crucible::StepObservation; 2],
        events: [Vec<ObservableEvent>; 2],
    }

    fn observe(split_at_boundary: bool) -> ObservedPartition {
        let (mut writer, output) = UnixStream::pair().expect("console socket pair");
        let spool = QemuConsoleObservationSpool::new();
        let mut reader = QemuConsoleObservationReader::new(output, spool.clone())
            .expect("nonblocking console observation reader");
        let mut node = scripted_node_with_options(
            shared_log(),
            ScriptedNodeOptions::default(),
            [QemuAsyncWaitOutcome::Completed; 2],
        )
        .expect("scripted node with original completion provider")
        .with_console_observation(node_id("vm-a"), spool);

        writer
            .write_all(if split_at_boundary {
                b"kernel"
            } else {
                b"kernel boot"
            })
            .expect("first console write");
        reader.drain_available().expect("first socket drain");
        let first_step = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 100 })
            .expect("first exact boundary");
        let first_events = SimulationBackend::drain_observable_events(&mut node)
            .expect("first original boundary observation");

        if split_at_boundary {
            writer.write_all(b" boot").expect("second console write");
        }
        reader.drain_available().expect("second socket drain");
        let second_step = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 200 })
            .expect("second exact boundary");
        let second_events = SimulationBackend::drain_observable_events(&mut node)
            .expect("second original boundary observation");
        SimulationBackend::shutdown(&mut node).expect("owned child shutdown");

        ObservedPartition {
            steps: [first_step, second_step],
            events: [first_events, second_events],
        }
    }

    let together = observe(false);
    let split = observe(true);

    assert_eq!(together.steps, split.steps);
    assert_eq!(together.events[0].len(), 1);
    assert!(together.events[1].is_empty());
    assert_eq!(split.events[0].len(), 1);
    assert_eq!(split.events[1].len(), 1);
    assert_eq!(split.events[0][0].at(), VirtualTime { ticks: 100 });
    assert_eq!(split.events[1][0].at(), VirtualTime { ticks: 200 });

    let ordered_bytes = |events: &[Vec<ObservableEvent>; 2]| {
        events
            .iter()
            .flatten()
            .flat_map(|event| match event.payload() {
                ObservableEventPayload::ConsoleOutput { node, bytes } => {
                    assert_eq!(node, &node_id("vm-a"));
                    bytes.clone()
                }
                _ => panic!("unexpected non-console observation"),
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(ordered_bytes(&together.events), b"kernel boot");
    assert_eq!(ordered_bytes(&split.events), b"kernel boot");
    assert_ne!(together.events, split.events);
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
    assert_eq!(
        projection.entries()[0].at.retired,
        Some(Icount { retired: 17 })
    );
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
    assert!(matches!(
        SimulationBackend::restore(
            &mut node,
            &BackendSnapshot::new(checkpoint("simulation-backend-restore")),
        ),
        Err(BackendError::Rejected { message })
            if message.contains("paired VMState and host-I/O realization")
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
