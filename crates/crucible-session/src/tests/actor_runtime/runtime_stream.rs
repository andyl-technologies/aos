//! Live snapshots, retained event streams, and terminal capture tests.

use super::*;

#[test]
pub(super) fn session_actor_live_snapshot_starts_as_loaded_without_mailbox() {
    let scenario = generated_scenario(17);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, AppendingLoop::default());
    let (_sender, receiver) = mpsc::channel(4);
    let actor = SessionActor::new(engine, receiver);
    let live = actor.live_snapshot();

    let view = live.read();

    assert_eq!(view.state_kind, LiveStateKind::Loaded);
    assert_eq!(view.virtual_time, VirtualTime { ticks: 0 });
    assert_eq!(view.event_log_len, 0);
    assert_eq!(view.quanta_stepped, 0);
}

#[tokio::test]
pub(super) async fn session_actor_live_query_reads_atomic_mirror_without_mailbox_query() {
    let scenario = generated_scenario(18);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, AppendingLoop::default());
    let (sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);

    let initial = actor.live_status();
    assert_eq!(initial, actor.live_snapshot().read());
    assert_eq!(
        actor.live_snapshot().query(LiveQueryKind::Status),
        LiveQueryResult::Status(initial)
    );
    assert_eq!(
        actor.live_snapshot().query(LiveQueryKind::State),
        LiveQueryResult::State(LifecycleStateKind::Loaded)
    );
    assert_eq!(initial.state_kind, LiveStateKind::Loaded);

    if let Err(error) = sender.send(SessionCommand::Start).await {
        panic!("start command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("start command should publish live status: {error}");
    }

    let after_start = actor.live_status();
    assert_eq!(after_start, actor.live_snapshot().read());
    assert_eq!(
        actor.live_snapshot().query(LiveQueryKind::State),
        LiveQueryResult::State(LifecycleStateKind::Paused)
    );
    assert_eq!(
        actor.live_snapshot().query(LiveQueryKind::EventLogLength),
        LiveQueryResult::EventLogLength(0)
    );
    assert_eq!(after_start.state_kind, LiveStateKind::Paused);
    assert_eq!(after_start.quanta_stepped, 0);
}

#[tokio::test]
pub(super) async fn session_actor_live_snapshot_publishes_monotone_progress() {
    let scenario = generated_scenario(19);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, AppendingLoop::default());
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }
    let (_sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);
    let live = actor.live_snapshot();
    let before = live.read();

    if let Err(error) = actor.run_once().await {
        panic!("running actor iteration should step: {error}");
    }
    let after = live.read();

    assert_eq!(before.state_kind, LiveStateKind::Running);
    assert_eq!(before.quanta_stepped, 0);
    assert_eq!(after.state_kind, LiveStateKind::Running);
    assert!(after.quanta_stepped > before.quanta_stepped);
    assert!(after.virtual_time >= before.virtual_time);
}

#[tokio::test]
pub(super) async fn session_actor_state_transition_bus_broadcasts_actor_owned_transitions() {
    let scenario = generated_scenario(20);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, AppendingLoop::default());
    let (sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);
    let mut transitions = actor.state_transition_stream();

    if let Err(error) = sender.send(SessionCommand::Start).await {
        panic!("start command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("start command should run: {error}");
    }
    let started = receive_state_transition(&mut transitions).await;
    assert_eq!(started.sequence, 1);
    assert_eq!(started.from_state, EngineState::Loaded);
    assert_eq!(
        started.to_state,
        EngineState::Paused {
            reason: PauseReason::Instantiated,
        }
    );
    assert_eq!(started.from.state_kind, LiveStateKind::Loaded);
    assert_eq!(started.to.state_kind, LiveStateKind::Paused);

    if let Err(error) = sender.send(SessionCommand::Pause).await {
        panic!("paused pause command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("paused pause command should run: {error}");
    }
    let repaused = receive_state_transition(&mut transitions).await;
    assert_eq!(repaused.sequence, 2);
    assert_eq!(
        repaused.from_state,
        EngineState::Paused {
            reason: PauseReason::Instantiated,
        }
    );
    assert_eq!(
        repaused.to_state,
        EngineState::Paused {
            reason: PauseReason::UserRequested,
        }
    );
    assert_eq!(repaused.from.state_kind, LiveStateKind::Paused);
    assert_eq!(repaused.to.state_kind, LiveStateKind::Paused);

    if let Err(error) = sender.send(SessionCommand::Continue).await {
        panic!("continue command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("continue command should run: {error}");
    }
    let continued = receive_state_transition(&mut transitions).await;
    assert_eq!(continued.sequence, 3);
    assert_eq!(
        continued.from_state,
        EngineState::Paused {
            reason: PauseReason::UserRequested,
        }
    );
    assert_eq!(continued.to_state, EngineState::Running);
    assert_eq!(continued.from.state_kind, LiveStateKind::Paused);
    assert_eq!(continued.to.state_kind, LiveStateKind::Running);

    if let Err(error) = actor.run_once().await {
        panic!("running quantum should not block state stream: {error}");
    }
    if let Err(error) = sender.send(SessionCommand::Pause).await {
        panic!("pause command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("pause command should run: {error}");
    }
    let paused = receive_state_transition(&mut transitions).await;
    assert_eq!(paused.sequence, 4);
    assert_eq!(paused.from_state, EngineState::Running);
    assert_eq!(
        paused.to_state,
        EngineState::Paused {
            reason: PauseReason::UserRequested,
        }
    );
    assert_eq!(paused.from.state_kind, LiveStateKind::Running);
    assert_eq!(paused.to.state_kind, LiveStateKind::Paused);

    if let Err(error) = sender.send(SessionCommand::Stop).await {
        panic!("stop command should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("stop command should run: {error}");
    }
    let stopped = receive_state_transition(&mut transitions).await;
    assert_eq!(stopped.sequence, 5);
    assert_eq!(
        stopped.from_state,
        EngineState::Paused {
            reason: PauseReason::UserRequested,
        }
    );
    assert_eq!(
        stopped.to_state,
        EngineState::Stopped {
            outcome: Outcome::Stopped,
        }
    );
    assert_eq!(stopped.from.state_kind, LiveStateKind::Paused);
    assert_eq!(stopped.to.state_kind, LiveStateKind::Stopped);
    assert_eq!(stopped.to.outcome, Some(OutcomeKind::Stopped));
    assert_eq!(stopped.to.state_transition_sequence, stopped.sequence);
}

#[tokio::test]
pub(super) async fn session_state_transition_stream_reports_lag_without_backpressure() {
    let bus = SessionStateTransitionBus::new();
    let mut stream = bus.subscribe();
    let view = LiveSnapshotView {
        state_kind: LiveStateKind::Loaded,
        outcome: None,
        terminal_savepoint: None,
        configuration: crucible::ContentHash::from_bytes(b"state-transition-test"),
        virtual_time: VirtualTime { ticks: 0 },
        event_log_len: 0,
        quanta_stepped: 0,
        control_acknowledgements: 0,
        state_transition_sequence: 0,
    };

    for sequence in 0..=usize_to_u64(SESSION_STATE_BROADCAST_CAPACITY) {
        bus.publish(SessionStateTransitionFrame {
            sequence,
            from_state: EngineState::Loaded,
            to_state: EngineState::Loaded,
            from: view,
            to: view,
        });
    }

    match stream.recv().await {
        Err(SessionStateTransitionStreamError::Lagged { skipped }) => assert!(skipped > 0),
        Ok(frame) => panic!("lagged state stream should not deliver frame {frame:?}"),
    }
}

#[tokio::test]
pub(super) async fn state_transition_floor_suppresses_pre_snapshot_frames() {
    let bus = SessionStateTransitionBus::new();
    let mut stream = bus.subscribe();
    let view = LiveSnapshotView {
        state_kind: LiveStateKind::Paused,
        outcome: None,
        terminal_savepoint: None,
        configuration: crucible::ContentHash::from_bytes(b"state-transition-floor"),
        virtual_time: VirtualTime { ticks: 3 },
        event_log_len: 0,
        quanta_stepped: 3,
        control_acknowledgements: 3,
        state_transition_sequence: 3,
    };
    for sequence in 1..=3 {
        let transition = LiveSnapshotView {
            state_transition_sequence: sequence,
            ..view
        };
        bus.publish(SessionStateTransitionFrame {
            sequence,
            from_state: EngineState::Loaded,
            to_state: EngineState::Paused {
                reason: PauseReason::UserRequested,
            },
            from: transition,
            to: transition,
        });
    }

    stream.set_sequence_floor(2);
    let update = stream
        .recv_latest()
        .await
        .unwrap_or_else(|| panic!("post-snapshot transition should remain queued"));
    assert_eq!(update.sequence, 3);
}

#[test]
pub(super) fn event_log_stream_recovers_broadcast_lag_from_the_retained_log() {
    let event_log = SessionEventLog::new();
    let mut stream = event_log.subscribe(EventLogCursor::new(0));
    let entry_count = usize_to_u64(SESSION_EVENT_LOG_BROADCAST_CAPACITY).saturating_add(257);
    let entries = (0..entry_count)
        .map(|sequence| {
            SchedulerEventLogEntry::assertion_state_observation(
                sequence,
                VirtualTime { ticks: sequence },
                AssertionId::from_name("retained-log-lag-recovery"),
                AssertionPhase::Satisfied,
            )
        })
        .collect::<Vec<_>>();
    event_log.append_entries(&entries);

    let mut observed = Vec::new();
    while let Some(frame) = stream
        .try_recv()
        .unwrap_or_else(|error| panic!("retained replay should recover broadcast lag: {error}"))
    {
        observed.push(frame.entry.sequence());
    }

    assert_eq!(observed, (0..entry_count).collect::<Vec<_>>());
    assert_eq!(stream.cursor(), EventLogCursor::new(entry_count));
}

#[test]
pub(super) fn engine_rejects_event_log_offset_mismatch() {
    let scenario = generated_scenario(21);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, InvalidEventLogLoop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }

    let error = engine
        .step_quantum()
        .expect_err("invalid event-log offset must be rejected");

    assert!(matches!(
        error,
        SessionError::EventLogOffsetMismatch {
            current: 0,
            emitted: 0,
            next: 1,
        }
    ));
}

#[test]
pub(super) fn engine_rejects_event_log_offset_regression() {
    let scenario = generated_scenario(22);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, RegressingEventLogLoop::default());
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }

    engine
        .step_quantum()
        .expect("first event-log offset should be accepted");
    let error = engine
        .step_quantum()
        .expect_err("regressed event-log offset must be rejected");

    assert!(matches!(
        error,
        SessionError::EventLogOffsetRegression {
            current: 1,
            next: 0,
        }
    ));
}

#[test]
pub(super) fn engine_rejects_non_dense_final_shutdown_entries() {
    let scenario = generated_scenario(225);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, NonDenseShutdownLoop);

    let error = engine
        .apply_command(SessionCommand::Stop)
        .expect_err("shutdown entries must continue the canonical sequence");

    assert_eq!(
        error,
        SessionError::EventLogOffsetMismatch {
            current: 0,
            emitted: 1,
            next: 1,
        }
    );
}

#[test]
pub(super) fn engine_captures_terminal_checkpoint_before_shutdown() {
    let scenario = generated_scenario(226);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let operations = Arc::new(Mutex::new(Vec::new()));
    let loop_impl = CaptureBeforeShutdownLoop {
        operations: Arc::clone(&operations),
    };
    let mut engine = Engine::new(config, graph, loop_impl);

    engine
        .apply_command(SessionCommand::Stop)
        .expect("terminal stop should capture and shut down");

    let observed = operations.lock().expect("operation log lock").clone();
    assert_eq!(observed, vec!["capture", "shutdown"]);
}
