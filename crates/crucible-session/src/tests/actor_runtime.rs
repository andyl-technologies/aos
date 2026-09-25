//! Session-actor mailbox, lifecycle, and runtime-isolation unit tests.

use super::*;

#[test]
pub(super) fn session_actor_source_does_not_lock_engine_across_run() {
    let source = concat!(include_str!("../session/actor.rs"), "\n#[cfg(test)]");
    let actor_struct = source_section(
        source,
        "pub struct SessionActor<L> {",
        "\n}\n\nimpl<L> SessionActor<L>",
    );
    let actor_impl = source_section(
        source,
        "impl<L> SessionActor<L> {",
        "\nimpl<L> SessionActor<L>\nwhere",
    );
    let actor_quantum_impl = source_section(
        source,
        "impl<L> SessionActor<L>\nwhere\n    L: QuantumLoop + Send + 'static,\n{",
        "\n#[cfg(test)]",
    );
    let actor_engine_field = ["engine", ": Engine<L>"].concat();
    let actor_mailbox_field = ["mailbox", ": mpsc::Receiver<SessionCommand>"].concat();
    let actor_event_log_field = ["event_log", ": SessionEventLog"].concat();
    assert!(actor_struct.contains(&actor_engine_field));
    assert!(actor_struct.contains(&actor_mailbox_field));
    assert!(actor_struct.contains(&actor_event_log_field));
    let Some((_, actor_fields)) = actor_struct.split_once('{') else {
        panic!("SessionActor source should contain a field body");
    };
    assert!(!actor_fields.contains("pub "));

    for forbidden in [
        ["engine", ": Arc<"].concat(),
        ["engine", ": std::sync::Arc<"].concat(),
        ["engine", ": Mutex<"].concat(),
        ["engine", ": std::sync::Mutex<"].concat(),
        ["engine", ": RwLock<"].concat(),
        ["engine", ": std::sync::RwLock<"].concat(),
        ["Arc<", "Mutex<", "Engine"].concat(),
        ["Arc<", "std::sync::Mutex<", "Engine"].concat(),
        ["Arc<", "RwLock<", "Engine"].concat(),
        ["Arc<", "std::sync::RwLock<", "Engine"].concat(),
        ["tokio::sync::", "Mutex"].concat(),
        ["tokio::sync::", "RwLock"].concat(),
        ["parking_lot::", "Mutex"].concat(),
        ["parking_lot::", "RwLock"].concat(),
    ] {
        assert!(
            !actor_struct.contains(&forbidden),
            "session-owned engine state must remain actor-owned by value, not locked: {forbidden}"
        );
    }

    for forbidden in [
        ["pub fn ", "engine_mut"].concat(),
        ["pub fn ", "defer_boundary_command"].concat(),
        ["pub fn ", "run_once"].concat(),
    ] {
        assert!(
            !actor_impl.contains(&forbidden),
            "live session actor must not expose direct mutation outside the mailbox: {forbidden}"
        );
    }

    for forbidden in [
        ["pub fn ", "apply_command"].concat(),
        ["pub fn ", "step_quantum"].concat(),
        ["pub fn ", "run_once"].concat(),
        ["pub fn ", "next_boundary_command"].concat(),
        ["pub fn ", "drain_read_only_commands"].concat(),
    ] {
        assert!(
            !actor_quantum_impl.contains(&forbidden),
            "live session actor must not expose direct mutation outside the mailbox: {forbidden}"
        );
    }
}

pub(super) fn source_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let Some(start_index) = source.find(start) else {
        panic!("source should contain section start {start}");
    };
    let tail = &source[start_index..];
    let Some(end_index) = tail.find(end) else {
        panic!("source should contain section end {end}");
    };
    &tail[..end_index]
}

pub(super) fn deterministic_command_index(seed: u64, step: u64) -> usize {
    let mixed = seed
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(step.wrapping_mul(0xbf58_476d_1ce4_e5b9));
    (mixed as usize) % SessionCommandKind::ALL.len()
}

pub(super) fn engine_with_lifecycle_state(state: LifecycleStateKind) -> Engine<AppendingLoop> {
    let seed = match state {
        LifecycleStateKind::Loaded => 9_001,
        LifecycleStateKind::Running => 9_002,
        LifecycleStateKind::Paused => 9_003,
        LifecycleStateKind::Stopped => 9_004,
    };
    let scenario = generated_scenario(seed);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, AppendingLoop::default());
    engine.state = match state {
        LifecycleStateKind::Loaded => EngineState::Loaded,
        LifecycleStateKind::Running => EngineState::Running,
        LifecycleStateKind::Paused => EngineState::Paused {
            reason: PauseReason::Instantiated,
        },
        LifecycleStateKind::Stopped => EngineState::Stopped {
            outcome: Outcome::Stopped,
        },
    };
    engine.runtime_instantiated = !matches!(state, LifecycleStateKind::Loaded);
    engine
}

pub(super) async fn receive_reply<T: fmt::Debug>(
    receiver: oneshot::Receiver<Result<T, SessionError>>,
) -> T {
    match receiver.await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => panic!("reply should succeed: {error}"),
        Err(error) => panic!("reply sender should complete: {error}"),
    }
}

pub(super) async fn receive_reply_error<T: fmt::Debug>(
    receiver: oneshot::Receiver<Result<T, SessionError>>,
) -> SessionError {
    match receiver.await {
        Ok(Ok(value)) => panic!("reply should fail, got {value:?}"),
        Ok(Err(error)) => error,
        Err(error) => panic!("reply sender should complete: {error}"),
    }
}

pub(super) async fn receive_state_transition(
    stream: &mut SessionStateTransitionStream,
) -> SessionStateTransitionFrame {
    match stream.recv().await {
        Ok(Some(frame)) => frame,
        Ok(None) => panic!("state-transition stream should remain open"),
        Err(error) => panic!("state-transition stream should not lag: {error}"),
    }
}

pub(super) fn assert_boundary_log_entry(
    entry: &SessionControlLogEntry,
    sequence: u64,
    command: SessionCommandKind,
    scheduler_control: Option<ControlOperationKind>,
) {
    assert_eq!(entry.sequence, sequence);
    assert_eq!(entry.command, command);
    assert_eq!(entry.scheduler_control, scheduler_control);
}

pub(super) fn recorded_control_batches(
    control_batches: &Arc<Mutex<Vec<Vec<ControlOperationKind>>>>,
) -> Vec<Vec<ControlOperationKind>> {
    match control_batches.lock() {
        Ok(batches) => batches.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

pub(super) async fn assert_actor_step_completes_after_second_quantum(
    seed: u64,
    mode: StepMode,
    quantum_loop: ScriptedStepLoop,
) {
    let scenario = generated_scenario(seed);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, quantum_loop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime before scripted step: {error}");
    }
    let (sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = sender.send(SessionCommand::Step { mode }).await {
        panic!("{mode:?} step should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("{mode:?} step should start bounded execution: {error}");
    }
    assert_eq!(actor.engine().quanta(), 0);
    assert!(matches!(actor.engine().state(), EngineState::Running));

    if let Err(error) = actor.run_once().await {
        panic!("{mode:?} step should stay running before the stop boundary: {error}");
    }
    assert_eq!(actor.engine().quanta(), 1);
    assert!(matches!(actor.engine().state(), EngineState::Running));

    if let Err(error) = actor.run_once().await {
        panic!("{mode:?} step should complete at its deterministic boundary: {error}");
    }
    assert_eq!(actor.engine().quanta(), 2);
    assert_eq!(actor.engine().configuration().schedule.len(), 2);
    assert_eq!(
        actor.engine().state(),
        &EngineState::Paused {
            reason: PauseReason::StepComplete { mode },
        }
    );
}

pub(super) fn assert_engine_step_completes_after_second_quantum(
    seed: u64,
    mode: StepMode,
    quantum_loop: ScriptedStepLoop,
) {
    let scenario = generated_scenario(seed);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, quantum_loop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime before scripted engine step: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Step { mode }) {
        panic!("{mode:?} step should start bounded execution: {error}");
    }
    assert_eq!(engine.state(), &EngineState::Running);
    assert_eq!(engine.quanta(), 0);

    if let Err(error) = engine.step_quantum() {
        panic!("{mode:?} step should stay running before the stop boundary: {error}");
    }
    assert_eq!(engine.quanta(), 1);
    assert_eq!(engine.state(), &EngineState::Running);

    if let Err(error) = engine.step_quantum() {
        panic!("{mode:?} step should complete at its deterministic boundary: {error}");
    }
    assert_eq!(engine.quanta(), 2);
    assert_eq!(
        engine.state(),
        &EngineState::Paused {
            reason: PauseReason::StepComplete { mode },
        }
    );
    assert_eq!(engine.active_step, None);
}

pub(super) fn assert_rejection_names_state_and_command(
    error: SessionError,
    expected_state: EngineState,
    expected_command: SessionCommand,
) {
    match error {
        SessionError::InvalidTransition { state, command } => {
            assert_eq!(*state, expected_state);
            assert_eq!(*command, expected_command);
        }
        other => panic!("unexpected rejection type: {other}"),
    }
}

#[test]
pub(super) fn engine_rejects_invalid_transition_without_changing_state() {
    let scenario = generated_scenario(12);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, StubLoop);

    let error = match engine.apply_command(SessionCommand::Continue) {
        Ok(_) => panic!("continue from loaded should be rejected"),
        Err(error) => error,
    };

    assert_eq!(engine.state(), &EngineState::Loaded);
    assert_rejection_names_state_and_command(error, EngineState::Loaded, SessionCommand::Continue);
}

#[test]
pub(super) fn engine_instantiate_runtime_cannot_bypass_state_transitions() {
    let scenario = generated_scenario(15);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, StubLoop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }

    let running_error = match engine.instantiate_runtime() {
        Ok(_) => panic!("direct instantiate should be rejected while running"),
        Err(error) => error,
    };
    assert_eq!(engine.state(), &EngineState::Running);
    assert!(matches!(
        running_error,
        SessionError::InvalidEngineState {
            state: EngineState::Running,
            operation: "instantiate_runtime",
        }
    ));

    if let Err(error) = engine.apply_command(SessionCommand::Stop) {
        panic!("stop should enter terminal state: {error}");
    }
    let stopped_error = match engine.instantiate_runtime() {
        Ok(_) => panic!("direct instantiate should be rejected while stopped"),
        Err(error) => error,
    };
    assert_eq!(
        engine.state(),
        &EngineState::Stopped {
            outcome: Outcome::Stopped
        }
    );
    assert!(matches!(
        stopped_error,
        SessionError::InvalidEngineState {
            state: EngineState::Stopped {
                outcome: Outcome::Stopped
            },
            operation: "instantiate_runtime",
        }
    ));
}

#[test]
pub(super) fn engine_runtime_cache_reinstantiates_without_observable_change_at_pause_boundary() {
    let scenario = generated_scenario(19);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, StubLoop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    let before_snapshot = engine.snapshot();
    let before_runtime = match engine.runtime().cloned() {
        Some(runtime) => runtime,
        None => panic!("started engine should have a runtime cache"),
    };

    let evicted_snapshot = engine.evict_runtime_cache();

    assert_eq!(evicted_snapshot, before_snapshot);
    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime(), None);

    let rebuilt_snapshot = match engine.reinstantiate_runtime_cache() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("runtime cache should reinstantiate at pause boundary: {error}"),
    };

    assert_eq!(rebuilt_snapshot, before_snapshot);
    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime(), Some(&before_runtime));

    let refreshed_snapshot = match engine.refresh_runtime_cache() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("runtime cache should refresh at pause boundary: {error}"),
    };

    assert_eq!(refreshed_snapshot, before_snapshot);
    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime(), Some(&before_runtime));
}

#[test]
pub(super) fn engine_runtime_cache_reinstantiates_after_running_quantum_boundary() {
    let scenario = generated_scenario(20);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, AppendingLoop::default());
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }
    if let Err(error) = engine.step_quantum() {
        panic!("running engine should complete a quantum: {error}");
    }
    let before_snapshot = engine.snapshot();
    let before_runtime = match engine.runtime().cloned() {
        Some(runtime) => runtime,
        None => panic!("running engine should have a runtime cache"),
    };

    let evicted_snapshot = engine.evict_runtime_cache();

    assert_eq!(before_snapshot.state, EngineState::Running);
    assert_eq!(before_snapshot.configuration.schedule.len(), 1);
    assert_eq!(evicted_snapshot, before_snapshot);
    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime(), None);

    let rebuilt_snapshot = match engine.reinstantiate_runtime_cache() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("runtime cache should reinstantiate after quantum: {error}"),
    };

    assert_eq!(rebuilt_snapshot, before_snapshot);
    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime(), Some(&before_runtime));
}

#[test]
pub(super) fn engine_runtime_cache_reinstantiate_rejects_loaded_state_without_mutation() {
    let scenario = generated_scenario(21);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, StubLoop);
    let before_snapshot = engine.snapshot();

    let rebuild_error = match engine.reinstantiate_runtime_cache() {
        Ok(_) => panic!("loaded engine should reject runtime cache reinstantiate"),
        Err(error) => error,
    };

    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime(), None);
    assert!(matches!(
        rebuild_error,
        SessionError::InvalidEngineState {
            state: EngineState::Loaded,
            operation: "reinstantiate_runtime_cache",
        }
    ));

    let refresh_error = match engine.refresh_runtime_cache() {
        Ok(_) => panic!("loaded engine should reject runtime cache refresh"),
        Err(error) => error,
    };

    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime(), None);
    assert!(matches!(
        refresh_error,
        SessionError::InvalidEngineState {
            state: EngineState::Loaded,
            operation: "refresh_runtime_cache",
        }
    ));
}

#[test]
pub(super) fn engine_runtime_cache_reinstantiate_rejects_never_instantiated_stopped_state() {
    let scenario = generated_scenario(22);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, StubLoop);
    if let Err(error) = engine.apply_command(SessionCommand::Stop) {
        panic!("loaded engine should stop without instantiating runtime: {error}");
    }
    let before_snapshot = engine.snapshot();

    let rebuild_error = match engine.reinstantiate_runtime_cache() {
        Ok(_) => panic!("never-instantiated stopped engine should reject cache rebuild"),
        Err(error) => error,
    };

    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime(), None);
    assert!(matches!(
        rebuild_error,
        SessionError::InvalidEngineState {
            state: EngineState::Stopped {
                outcome: Outcome::Stopped
            },
            operation: "reinstantiate_runtime_cache",
        }
    ));
}

#[test]
pub(super) fn engine_runtime_cache_refresh_preserves_cache_when_reinstantiate_fails() {
    let scenario = generated_scenario(23);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, StubLoop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    let before_snapshot = engine.snapshot();
    let before_runtime = match engine.runtime().cloned() {
        Some(runtime) => runtime,
        None => panic!("started engine should have a runtime cache"),
    };
    engine.graph = TemporalGraph::empty();

    let refresh_error = match engine.refresh_runtime_cache() {
        Ok(_) => panic!("runtime refresh should fail without a replay source"),
        Err(error) => error,
    };

    assert!(matches!(refresh_error, SessionError::Engine(_)));
    assert_eq!(engine.snapshot(), before_snapshot);
    assert_eq!(engine.runtime(), Some(&before_runtime));
}

#[tokio::test]
pub(super) async fn session_actor_services_pending_command_before_quantum() {
    let scenario = generated_scenario(13);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, CountingLoop::default());
    let (sender, receiver) = mpsc::channel(8);
    for command in [
        SessionCommand::Start,
        SessionCommand::Continue,
        SessionCommand::Pause,
        SessionCommand::Stop,
    ] {
        if let Err(error) = sender.send(command).await {
            panic!("command should enqueue: {error}");
        }
    }

    let report = match SessionActor::new(engine, receiver).run().await {
        Ok(report) => report,
        Err(error) => panic!("actor should stop cleanly: {error}"),
    };

    assert_eq!(report.quanta, 0);
    assert_eq!(report.commands_applied, 4);
    assert_eq!(
        report.final_snapshot.state,
        EngineState::Stopped {
            outcome: Outcome::Stopped
        }
    );
}

#[tokio::test]
pub(super) async fn session_actor_steps_one_quantum_then_yields() {
    let scenario = generated_scenario(14);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, AppendingLoop::default());
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }
    let (sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = actor.run_once().await {
        panic!("running actor iteration should step: {error}");
    }
    if let Err(error) = sender.send(SessionCommand::Stop).await {
        panic!("stop should enqueue after first yield: {error}");
    }
    let report = match actor.run().await {
        Ok(report) => report,
        Err(error) => panic!("actor should stop after yielded quantum: {error}"),
    };

    assert_eq!(report.quanta, 1);
    assert_eq!(report.yielded_after_quanta, 1);
    assert_eq!(report.final_snapshot.configuration.schedule.len(), 1);
}

#[tokio::test]
pub(super) async fn session_actor_publishes_non_backend_scheduler_failure_as_terminal_crash() {
    let scenario = generated_scenario(226);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, NonDenseShutdownLoop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }
    let (sender, receiver) = mpsc::channel(1);
    let actor = SessionActor::new(engine, receiver);
    let live = actor.live_snapshot();

    let report = actor
        .run()
        .await
        .unwrap_or_else(|error| panic!("actor failure should become a crash outcome: {error}"));

    let EngineState::Stopped {
        outcome: Outcome::Crashed { detail },
    } = report.final_snapshot.state
    else {
        panic!("actor failure should stop with a crashed outcome");
    };
    assert!(
        detail.contains("non-dense shutdown test must not drive a quantum"),
        "unexpected crash detail: {detail}"
    );
    let status = live.read();
    assert_eq!(status.state_kind, LiveStateKind::Stopped);
    assert_eq!(status.outcome, Some(OutcomeKind::Crashed));
    drop(sender);
}

#[tokio::test]
pub(super) async fn session_actor_terminalizes_mismatched_debug_runtime_evidence() {
    let (_root, first, second, graph) = debug_time_travel_fixture();
    let engine = Engine::new(second.clone(), graph, MismatchingDebugRepositionLoop);
    let (sender, receiver) = mpsc::channel(4);
    for command in [
        SessionCommand::Start,
        SessionCommand::AttachGdb {
            node: node_id("guest-a"),
            listen: gdb_listen("127.0.0.1:9000"),
            debug_genesis: None,
            reply: CommandReply::discard(),
        },
        SessionCommand::DebugGoto {
            request: DebugGotoRequest::at_configuration(second, first),
            reply: CommandReply::discard(),
        },
    ] {
        sender
            .send(command)
            .await
            .unwrap_or_else(|error| panic!("debug command should enqueue: {error}"));
    }

    let actor = SessionActor::new(engine, receiver);
    let live = actor.live_snapshot();
    let report = actor
        .run()
        .await
        .unwrap_or_else(|error| panic!("runtime mismatch should terminalize: {error}"));

    let EngineState::Stopped {
        outcome: Outcome::Crashed { detail },
    } = report.final_snapshot.state
    else {
        panic!("runtime mismatch should stop with a crashed outcome");
    };
    assert!(detail.contains("debug runtime reposition evidence mismatch"));
    let status = live.read();
    assert_eq!(status.state_kind, LiveStateKind::Stopped);
    assert_eq!(status.outcome, Some(OutcomeKind::Crashed));
    drop(sender);
}

#[tokio::test]
pub(super) async fn rejected_direct_debug_command_does_not_terminate_the_actor() {
    let (root, _first, _second, graph) = debug_time_travel_fixture();
    let engine = Engine::new(root.clone(), graph, DebugGdbLoop)
        .with_white_box_policies([(node_id("guest-a"), WhiteBoxPolicy::Enabled)]);
    let (sender, receiver) = mpsc::channel(5);
    let (reverse_reply, reverse_receiver) = CommandReply::channel();
    for command in [
        SessionCommand::Start,
        SessionCommand::AttachGdb {
            node: node_id("guest-a"),
            listen: gdb_listen("127.0.0.1:9000"),
            debug_genesis: None,
            reply: CommandReply::discard(),
        },
        SessionCommand::DebugReverseStep {
            request: DebugReverseStepRequest::new(root, DebugReverseStepGrain::Quantum, Vec::new()),
            reply: reverse_reply,
        },
        SessionCommand::Stop,
    ] {
        sender
            .send(command)
            .await
            .unwrap_or_else(|error| panic!("debug command should enqueue: {error}"));
    }

    let report = SessionActor::new(engine, receiver)
        .run()
        .await
        .unwrap_or_else(|error| panic!("rejected debug command should be recoverable: {error}"));
    let rejection = receive_reply_error::<DebugReverseStepReport>(reverse_receiver).await;

    assert!(matches!(rejection, SessionError::Engine(_)));
    assert!(matches!(
        report.final_snapshot.state,
        EngineState::Stopped {
            outcome: Outcome::Stopped,
        }
    ));
}

#[tokio::test]
pub(super) async fn session_actor_yields_after_command_driven_accepted_step() {
    let scenario = generated_scenario(16);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, AppendingLoop::default());
    let (sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);
    for command in [
        SessionCommand::Start,
        SessionCommand::Step {
            mode: StepMode::Quantum,
        },
    ] {
        if let Err(error) = sender.send(command).await {
            panic!("command should enqueue: {error}");
        }
    }

    if let Err(error) = actor.run_once().await {
        panic!("start command should instantiate runtime: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("step command should start bounded execution: {error}");
    }
    assert_eq!(actor.engine().quanta(), 0);
    assert!(matches!(actor.engine().state(), EngineState::Running));
    if let Err(error) = actor.run_once().await {
        panic!("quantum step should complete after one scheduler boundary: {error}");
    }
    assert_eq!(actor.engine().quanta(), 1);
    assert_eq!(actor.yielded_after_quanta(), 1);
    assert_eq!(
        actor.engine().state(),
        &EngineState::Paused {
            reason: PauseReason::StepComplete {
                mode: StepMode::Quantum,
            }
        }
    );

    if let Err(error) = sender.send(SessionCommand::Stop).await {
        panic!("stop should enqueue after step completion: {error}");
    }
    let report = match actor.run().await {
        Ok(report) => report,
        Err(error) => panic!("actor should stop after command-driven step: {error}"),
    };

    assert_eq!(report.quanta, 1);
    assert_eq!(report.yielded_after_quanta, 1);
    assert_eq!(
        report.final_snapshot.state,
        EngineState::Stopped {
            outcome: Outcome::Stopped
        }
    );
}

#[tokio::test]
pub(super) async fn session_actor_command_driven_step_acknowledges_preexisting_running_controls() {
    let scenario = generated_scenario(24);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, AppendingLoop::default());
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }
    let (sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = sender.send(SessionCommand::query_snapshot()).await {
        panic!("snapshot should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("snapshot command should be accepted while running: {error}");
    }
    assert_eq!(actor.control_acknowledgements(), 0);
    assert_eq!(actor.engine().pending_control_len(), 1);

    if let Err(error) = sender
        .send(SessionCommand::Step {
            mode: StepMode::Quantum,
        })
        .await
    {
        panic!("quantum step should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("running quantum step should start bounded execution: {error}");
    }
    assert_eq!(actor.control_acknowledgements(), 0);
    assert_eq!(actor.engine().pending_control_len(), 1);
    assert_eq!(actor.engine().quanta(), 0);
    assert!(matches!(actor.engine().state(), EngineState::Running));

    if let Err(error) = actor.run_once().await {
        panic!("running quantum step should drain pending control: {error}");
    }

    assert_eq!(actor.control_acknowledgements(), 1);
    assert_eq!(actor.engine().pending_control_len(), 0);
    assert_eq!(actor.engine().quanta(), 1);
    assert!(matches!(
        actor.engine().state(),
        EngineState::Paused {
            reason: PauseReason::StepComplete {
                mode: StepMode::Quantum
            }
        }
    ));
}

#[tokio::test]
pub(super) async fn session_actor_paused_step_acknowledges_preexisting_running_controls() {
    let scenario = generated_scenario(25);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, AppendingLoop::default());
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::Continue) {
        panic!("continue should enter running state: {error}");
    }
    let (sender, receiver) = mpsc::channel(4);
    let mut actor = SessionActor::new(engine, receiver);

    if let Err(error) = sender.send(SessionCommand::query_snapshot()).await {
        panic!("snapshot should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("snapshot command should be accepted while running: {error}");
    }
    assert_eq!(actor.control_acknowledgements(), 0);
    assert_eq!(actor.engine().pending_control_len(), 1);

    if let Err(error) = sender.send(SessionCommand::Pause).await {
        panic!("pause should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("pause command should be accepted while running: {error}");
    }
    assert_eq!(actor.control_acknowledgements(), 1);
    assert_eq!(actor.engine().pending_control_len(), 1);
    assert!(matches!(
        actor.engine().state(),
        EngineState::Paused {
            reason: PauseReason::UserRequested
        }
    ));

    if let Err(error) = sender
        .send(SessionCommand::Step {
            mode: StepMode::Quantum,
        })
        .await
    {
        panic!("quantum step should enqueue: {error}");
    }
    if let Err(error) = actor.run_once().await {
        panic!("paused quantum step should start bounded execution: {error}");
    }
    assert_eq!(actor.control_acknowledgements(), 1);
    assert_eq!(actor.engine().pending_control_len(), 1);
    assert_eq!(actor.engine().quanta(), 0);
    assert!(matches!(actor.engine().state(), EngineState::Running));

    if let Err(error) = actor.run_once().await {
        panic!("paused quantum step should drain pending control: {error}");
    }

    assert_eq!(actor.control_acknowledgements(), 2);
    assert_eq!(actor.engine().pending_control_len(), 0);
    assert_eq!(actor.engine().quanta(), 1);
    assert!(matches!(
        actor.engine().state(),
        EngineState::Paused {
            reason: PauseReason::StepComplete {
                mode: StepMode::Quantum
            }
        }
    ));
}

#[tokio::test]
pub(super) async fn session_actor_step_modes_stop_on_deterministic_boundaries() {
    let cases = vec![
        (
            30,
            StepMode::Event,
            ScriptedStepLoop::with_payload(2, resolved_backend_input_payload(2)),
        ),
        (
            31,
            StepMode::Assertion,
            ScriptedStepLoop::with_payload(2, assertion_state_change_payload()),
        ),
        (
            32,
            StepMode::Timer,
            ScriptedStepLoop::with_payload(2, timer_fire_payload(2)),
        ),
        (
            33,
            StepMode::Duration(SimDuration { ticks: 2 }),
            ScriptedStepLoop::default(),
        ),
    ];

    for (seed, mode, quantum_loop) in cases {
        assert_actor_step_completes_after_second_quantum(seed, mode, quantum_loop).await;
    }
}

#[tokio::test]
pub(super) async fn session_actor_step_modes_are_interruptible_by_pause_and_stop() {
    for command in [SessionCommand::Pause, SessionCommand::Stop] {
        let scenario = generated_scenario(34);
        let config = Configuration::genesis(scenario.clone());
        let graph = graph_with_baked_genesis(&scenario);
        let mut engine = Engine::new(config, graph, ScriptedStepLoop::default());
        if let Err(error) = engine.apply_command(SessionCommand::Start) {
            panic!("start should instantiate runtime before interruptible step: {error}");
        }
        let (sender, receiver) = mpsc::channel(4);
        let mut actor = SessionActor::new(engine, receiver);
        if let Err(error) = sender
            .send(SessionCommand::Step {
                mode: StepMode::Duration(SimDuration { ticks: 8 }),
            })
            .await
        {
            panic!("duration step should enqueue: {error}");
        }

        if let Err(error) = actor.run_once().await {
            panic!("duration step should start bounded execution: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("first duration-step quantum should run: {error}");
        }
        assert_eq!(actor.engine().quanta(), 1);
        assert!(matches!(actor.engine().state(), EngineState::Running));

        if let Err(error) = sender.send(command.clone()).await {
            panic!("interrupt command should enqueue: {error}");
        }
        if let Err(error) = actor.run_once().await {
            panic!("interrupt command should be serviced before the next quantum: {error}");
        }

        assert_eq!(actor.engine().quanta(), 1);
        assert_eq!(actor.engine().active_step, None);
        match command {
            SessionCommand::Pause => assert!(matches!(
                actor.engine().state(),
                EngineState::Paused {
                    reason: PauseReason::UserRequested
                }
            )),
            SessionCommand::Stop => assert!(matches!(
                actor.engine().state(),
                EngineState::Stopped {
                    outcome: Outcome::Stopped
                }
            )),
            _ => panic!("test only covers pause and stop interrupts"),
        }
    }
}

#[path = "actor_runtime/runtime_stream.rs"]
mod runtime_stream;
#[path = "actor_runtime/support.rs"]
mod support;

pub(super) use support::*;
