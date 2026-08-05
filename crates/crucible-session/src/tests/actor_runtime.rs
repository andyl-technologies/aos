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
pub(super) async fn session_actor_yields_after_command_driven_step() {
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

    if let Err(error) = sender.send(SessionCommand::Snapshot).await {
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

    if let Err(error) = sender.send(SessionCommand::Snapshot).await {
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
            StepMode::Duration(SimDuration { nanos: 2 }),
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
                mode: StepMode::Duration(SimDuration { nanos: 8 }),
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

pub(super) struct NonDenseShutdownLoop;

impl QuantumLoop for NonDenseShutdownLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("non-dense shutdown test must not drive a quantum"),
        })
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(vec![test_event_log_entry(1)])
    }
}

pub(super) struct BackendCrashLoop;

impl QuantumLoop for BackendCrashLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        Err(BackendError::Rejected {
            message: String::from("backend process exited unexpectedly"),
        }
        .into())
    }
}

#[derive(Default)]
pub(super) struct CoverageAppendingLoop {
    event_log: crucible::EventLog,
}

impl QuantumLoop for CoverageAppendingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: 19 },
            advanced_node: Some(SchedulerNodeId {
                node: node_id("vm-a"),
                kind: SchedulingNodeKind::Vm,
            }),
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: self.event_log.offset(),
            scheduler_quiescence: None,
        })
    }

    fn append_backend_observable_events(
        &mut self,
        events: Vec<crucible::ObservableEvent>,
    ) -> Result<crucible::SchedulerEventLogAppend, SchedulerError> {
        self.event_log.append_observable_events(events)
    }

    fn append_backend_observations_at_boundary(
        &mut self,
        events: Vec<crucible::ObservableEvent>,
        at: VirtualTime,
    ) -> Result<crucible::SchedulerEventLogAppend, SchedulerError> {
        self.event_log.append_observations_at_boundary(
            events,
            at,
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        )
    }
}

pub(super) struct CoverageBackend {
    now: VirtualTime,
    events: Vec<crucible::ObservableEvent>,
}

impl CoverageBackend {
    fn new(event: crucible::ObservableEvent) -> Self {
        Self {
            now: VirtualTime::default(),
            events: vec![event],
        }
    }
}

impl crucible::SimulationBackend for CoverageBackend {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<crucible::StepObservation, BackendError> {
        self.now = ceiling;
        Ok(crucible::StepObservation::from_advance_outcome(
            ceiling,
            crucible::AdvanceOutcome::ReachedHorizon,
        ))
    }

    fn drain_observable_events(&mut self) -> Result<Vec<crucible::ObservableEvent>, BackendError> {
        Ok(std::mem::take(&mut self.events))
    }

    fn apply(
        &mut self,
        _effect: &crucible::BackendEffect,
        _at: VirtualTime,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn snapshot(&mut self) -> Result<crucible::BackendSnapshot, BackendError> {
        Err(BackendError::NotImplemented {
            operation: "coverage test snapshot",
        })
    }

    fn restore(&mut self, _snapshot: &crucible::BackendSnapshot) -> Result<(), BackendError> {
        Err(BackendError::NotImplemented {
            operation: "coverage test restore",
        })
    }

    fn now(&self) -> VirtualTime {
        self.now
    }

    fn fingerprint(&mut self, _node: NodeId) -> Result<FingerprintSample, BackendError> {
        Err(BackendError::NotImplemented {
            operation: "coverage test fingerprint",
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
}

pub(super) struct StubLoop;

impl QuantumLoop for StubLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: 0 },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: Default::default(),
            scheduler_quiescence: None,
        })
    }
}

pub(super) struct TerminalVerdictLoop {
    verdict: Option<QuantumTerminalVerdict>,
}

impl TerminalVerdictLoop {
    pub(super) fn new(verdict: QuantumTerminalVerdict) -> Self {
        Self {
            verdict: Some(verdict),
        }
    }
}

impl QuantumLoop for TerminalVerdictLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        StubLoop.drive_quantum(request)
    }

    fn take_terminal_verdict(&mut self) -> Option<QuantumTerminalVerdict> {
        self.verdict.take()
    }
}

#[derive(Default)]
pub(super) struct CountingLoop {
    quanta: u64,
}

impl QuantumLoop for CountingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: Default::default(),
            scheduler_quiescence: None,
        })
    }
}

pub(super) struct RecordingLoop {
    quanta: u64,
    control_batches: Arc<Mutex<Vec<Vec<ControlOperationKind>>>>,
    shutdowns: Option<Arc<AtomicU64>>,
}

impl RecordingLoop {
    pub(super) fn new(control_batches: Arc<Mutex<Vec<Vec<ControlOperationKind>>>>) -> Self {
        Self {
            quanta: 0,
            control_batches,
            shutdowns: None,
        }
    }

    pub(super) fn with_shutdown(
        control_batches: Arc<Mutex<Vec<Vec<ControlOperationKind>>>>,
        shutdowns: Arc<AtomicU64>,
    ) -> Self {
        Self {
            quanta: 0,
            control_batches,
            shutdowns: Some(shutdowns),
        }
    }
}

impl QuantumLoop for RecordingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        let control_batch = request
            .control
            .iter()
            .map(|control| control.kind.clone())
            .collect::<Vec<_>>();
        match self.control_batches.lock() {
            Ok(mut batches) => batches.push(control_batch),
            Err(poisoned) => poisoned.into_inner().push(control_batch),
        }
        self.quanta = self.quanta.saturating_add(1);
        let decision = generated_decision(self.quanta);
        let configuration = step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            event_log_entries: vec![test_event_log_entry(self.quanta - 1)],
            event_log_segment_bytes: vec![b'x'],
            event_log_segment_text: String::from("x"),
            event_log_segment_hash: Some(crucible::ContentHash::from_bytes(b"x")),
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, self.quanta),
            scheduler_quiescence: None,
        })
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let control_batch = control
            .iter()
            .map(|operation| operation.kind.clone())
            .collect::<Vec<_>>();
        match self.control_batches.lock() {
            Ok(mut batches) => batches.push(control_batch),
            Err(poisoned) => poisoned.into_inner().push(control_batch),
        }
        Ok(Vec::new())
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        if let Some(shutdowns) = &self.shutdowns {
            shutdowns.fetch_add(1, Ordering::SeqCst);
        }
        Ok(Vec::new())
    }
}

pub(super) struct ControlEventLoop;

impl QuantumLoop for ControlEventLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime::default(),
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn apply_control_at_boundary(
        &mut self,
        _control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(vec![test_event_log_entry(0)])
    }
}

#[derive(Default)]
pub(super) struct ControlSensitiveLoop {
    quanta: u64,
    active_faults: std::collections::BTreeSet<FaultTag>,
    legacy_injects: u64,
    control_batches: u64,
}

impl ControlSensitiveLoop {
    fn apply_control_batch(&mut self, controls: &[ControlOperation]) {
        if controls.is_empty() {
            return;
        }
        self.control_batches = self.control_batches.saturating_add(1);
        for control in controls {
            match &control.kind {
                ControlOperationKind::Inject => {
                    self.legacy_injects = self.legacy_injects.saturating_add(1);
                }
                ControlOperationKind::InjectFault { tag, .. } => {
                    self.active_faults.insert(tag.clone());
                }
                ControlOperationKind::HealFault { tag } => {
                    self.active_faults.remove(tag);
                }
                ControlOperationKind::Pause
                | ControlOperationKind::Resume
                | ControlOperationKind::Step
                | ControlOperationKind::Snapshot
                | ControlOperationKind::Fork
                | ControlOperationKind::Query => {}
            }
        }
    }

    fn decision_seed(&self) -> u64 {
        self.quanta
            .saturating_add((self.active_faults.len() as u64).saturating_mul(1_000))
            .saturating_add(self.legacy_injects.saturating_mul(10_000))
            .saturating_add(self.control_batches.saturating_mul(100_000))
    }
}

impl QuantumLoop for ControlSensitiveLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.apply_control_batch(&request.control);
        self.quanta = self.quanta.saturating_add(1);
        let decision = generated_decision(self.decision_seed());
        let configuration = step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            event_log_entries: vec![test_event_log_entry(self.quanta - 1)],
            event_log_segment_bytes: vec![b'x'],
            event_log_segment_text: String::from("x"),
            event_log_segment_hash: Some(crucible::ContentHash::from_bytes(b"x")),
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, self.quanta),
            scheduler_quiescence: None,
        })
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.apply_control_batch(&control);
        Ok(Vec::new())
    }
}

pub(super) struct ShutdownLoop {
    quanta: u64,
    shutdowns: Arc<AtomicU64>,
}

impl ShutdownLoop {
    pub(super) fn new(shutdowns: Arc<AtomicU64>) -> Self {
        Self {
            quanta: 0,
            shutdowns,
        }
    }
}

impl QuantumLoop for ShutdownLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: Default::default(),
            scheduler_quiescence: None,
        })
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
}

#[derive(Default)]
pub(super) struct ScriptedStepLoop {
    quanta: u64,
    event_log_entries: u64,
    payloads_by_quantum: std::collections::BTreeMap<u64, Vec<SchedulerEventLogPayload>>,
    scheduler_quiescence: Option<SchedulerQuiescence>,
}

impl ScriptedStepLoop {
    pub(super) fn with_payload(quantum: u64, payload: SchedulerEventLogPayload) -> Self {
        Self::with_payloads(quantum, vec![payload])
    }

    pub(super) fn with_payloads(quantum: u64, payloads: Vec<SchedulerEventLogPayload>) -> Self {
        let mut payloads_by_quantum = std::collections::BTreeMap::new();
        payloads_by_quantum.insert(quantum, payloads);
        Self {
            quanta: 0,
            event_log_entries: 0,
            payloads_by_quantum,
            scheduler_quiescence: None,
        }
    }

    pub(super) fn with_quiescence(scheduler_quiescence: SchedulerQuiescence) -> Self {
        Self {
            scheduler_quiescence: Some(scheduler_quiescence),
            ..Self::default()
        }
    }
}

impl QuantumLoop for ScriptedStepLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let at = VirtualTime { ticks: self.quanta };
        let entries = if let Some(payloads) = self.payloads_by_quantum.remove(&self.quanta) {
            payloads
                .into_iter()
                .enumerate()
                .map(|(index, payload)| {
                    crucible::test_support::condition_payload_entry_for_test(
                        self.event_log_entries + usize_to_u64(index),
                        at,
                        payload,
                    )
                })
                .collect::<Vec<_>>()
        } else {
            vec![crucible::test_support::condition_boundary_entry_for_test(
                self.event_log_entries,
                at,
                crucible::SchedulerEvaluationBoundaryKind::Quantum,
            )]
        };
        self.event_log_entries = self
            .event_log_entries
            .saturating_add(usize_to_u64(entries.len()));
        let decision = generated_decision(self.quanta);
        let configuration = step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: at,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            event_log_entries: entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::new(
                Default::default(),
                0,
                self.event_log_entries,
            ),
            scheduler_quiescence: self.scheduler_quiescence.clone(),
        })
    }
}

pub(super) struct NoEventQuiescenceLoop {
    pub(super) quiescence: SchedulerQuiescence,
}

impl QuantumLoop for NoEventQuiescenceLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: 1 },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: Some(self.quiescence.clone()),
        })
    }
}

pub(super) struct PriorEventThenNoEventQuiescenceLoop {
    pub(super) quanta: u64,
    pub(super) quiescence: SchedulerQuiescence,
}

impl QuantumLoop for PriorEventThenNoEventQuiescenceLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let at = VirtualTime { ticks: self.quanta };
        let entries = if self.quanta == 1 {
            vec![crucible::test_support::condition_boundary_entry_for_test(
                0,
                at,
                crucible::SchedulerEvaluationBoundaryKind::Quantum,
            )]
        } else {
            Vec::new()
        };
        let decision = generated_decision(self.quanta);
        let configuration = step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: at,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            event_log_entries: entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, 1),
            scheduler_quiescence: Some(self.quiescence.clone()),
        })
    }
}

pub(super) struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("session step-mode tests should not evaluate host leaf predicates")
            }
        }
    }
}

#[derive(Default)]
pub(super) struct AppendingLoop {
    quanta: u64,
}

pub(super) struct InvalidEventLogLoop;

impl QuantumLoop for InvalidEventLogLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: 1 },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, 1),
            scheduler_quiescence: None,
        })
    }
}

#[derive(Default)]
pub(super) struct RegressingEventLogLoop {
    quanta: u64,
}

impl QuantumLoop for RegressingEventLogLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let (entries, offset) = if self.quanta == 1 {
            (
                vec![test_event_log_entry(0)],
                crucible::EventLogOffset::new(Default::default(), 0, 1),
            )
        } else {
            (Vec::new(), crucible::EventLogOffset::default())
        };
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: offset,
            scheduler_quiescence: None,
        })
    }
}

impl QuantumLoop for AppendingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let decision = generated_decision(self.quanta);
        let configuration = step(&request.configuration, decision.clone());
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            event_log_entries: vec![test_event_log_entry(self.quanta - 1)],
            event_log_segment_bytes: vec![b'x'],
            event_log_segment_text: String::from("x"),
            event_log_segment_hash: Some(crucible::ContentHash::from_bytes(b"x")),
            event_log_offset: crucible::EventLogOffset::new(Default::default(), 0, self.quanta),
            scheduler_quiescence: None,
        })
    }
}

pub(super) struct DebugGdbLoop;

impl QuantumLoop for DebugGdbLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime::default(),
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        GdbAttachInfo::new(node, "tcp:127.0.0.1:9001", listen).map_err(SchedulerError::from)
    }
}

pub(super) fn debug_time_travel_fixture()
-> (Configuration, Configuration, Configuration, TemporalGraph) {
    let world = single_node_debug_world("session-command")
        .unwrap_or_else(|error| panic!("debug world should build: {error}"));
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let first = try_step(
        &root,
        override_decision("session/debug-time-travel", "first"),
    )
    .unwrap_or_else(|error| panic!("first debug step should build: {error}"));
    let second = try_step(
        &first,
        override_decision("session/debug-time-travel", "second"),
    )
    .unwrap_or_else(|error| panic!("second debug step should build: {error}"));
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            bake(&world).unwrap_or_else(|error| panic!("debug world should bake: {error}")),
        )
        .unwrap_or_else(|error| panic!("debug graph should have baked genesis: {error}"));
    graph
        .record_thin_checkpoint(&first)
        .unwrap_or_else(|error| panic!("first checkpoint should record: {error}"));
    graph
        .record_thin_checkpoint(&second)
        .unwrap_or_else(|error| panic!("second checkpoint should record: {error}"));
    (root, first, second, graph)
}

pub(super) fn single_node_debug_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("guest-a"),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-session-debug={label}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: crucible::Icount { retired: 100 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
}

pub(super) fn override_decision(point: &str, choice: &str) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: point.to_owned(),
        },
        choice: ChoiceTag {
            name: choice.to_owned(),
        },
    })
}

pub(super) fn gdb_listen(endpoint: &str) -> GdbListen {
    GdbListen::new(endpoint)
        .unwrap_or_else(|error| panic!("test gdb listen should be stable: {error}"))
}

pub(super) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

pub(super) fn graph_with_baked_genesis(scenario: &ScenarioDef) -> TemporalGraph {
    let genesis = Configuration::genesis(scenario.clone());
    match TemporalGraph::empty().with_baked_genesis(scenario, genesis_checkpoint(&genesis)) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    }
}

pub(super) fn genesis_checkpoint(configuration: &Configuration) -> GenesisCheckpoint {
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        None,
        VirtualTime::default(),
        std::collections::BTreeMap::new(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("genesis checkpoint should be recorded-shaped: {error}"));
    GenesisCheckpoint { checkpoint }
}

pub(super) fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.session.test.scenario",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}

pub(super) fn test_event_log_entry(sequence: u64) -> crucible::SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        VirtualTime {
            ticks: sequence.saturating_add(1),
        },
        crucible::SchedulerEvaluationBoundaryKind::Quantum,
    )
}

pub(super) fn resolved_backend_input_payload(seed: u64) -> SchedulerEventLogPayload {
    let node = scheduler_node("node-a");
    SchedulerEventLogPayload::ResolvedHappening(ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime { ticks: seed },
            node.clone(),
            node.clone(),
            seed,
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: node.node,
            payload: vec![1, 2, 3],
        }),
    })
}

pub(super) fn assertion_state_change_payload() -> SchedulerEventLogPayload {
    SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionStateChanged {
        name: AssertionId::from_name("session-step-assertion"),
        state: AssertionPhase::Satisfied,
    })
}

pub(super) fn trigger_fired_payload(
    sequence: u64,
    event: EventId,
    predicate: Predicate,
) -> SchedulerEventLogPayload {
    let graph = EventGraph::new(vec![Event::once(
        event.clone(),
        Some(predicate),
        Action::Log {
            level: LogLevel::Info,
            message: String::from("session breakpoint trigger fired"),
        },
    )])
    .unwrap_or_else(|error| panic!("trigger-fired event graph should build: {error}"));
    let mut graph_state = EventGraphState::new();
    let mut pass = ConditionEvaluationPass::from_log_prefix(
        crucible::test_support::condition_prefix_at_quantum_boundary_for_test(sequence),
        NoLeaves,
    );
    let firings = pass.evaluate_event_graph(&graph, &mut graph_state);
    let Some(firing) = firings
        .iter()
        .find(|firing| firing.event() == &event)
        .cloned()
    else {
        panic!("trigger-fired event graph should produce the requested firing");
    };
    SchedulerEventLogPayload::TriggerFired(firing)
}

pub(super) fn timer_fire_payload(sequence: u64) -> SchedulerEventLogPayload {
    let timer = TimerId {
        name: String::from("session-step-timer"),
    };
    let graph = EventGraph::new(vec![
        Event::once(
            EventId::from_name("session-step-arm-timer"),
            None,
            Action::arm_timer(timer.clone(), SimDuration { nanos: sequence }),
        ),
        Event::once(
            EventId::from_name("session-step-timer"),
            Some(Predicate::timer(timer.clone())),
            Action::Log {
                level: LogLevel::Info,
                message: String::from("session step timer fired"),
            },
        ),
    ])
    .unwrap_or_else(|error| panic!("timer fire event graph should build: {error}"));
    let mut graph_state = EventGraphState::new();
    let mut timer_fires = std::collections::BTreeMap::new();
    timer_fires.insert(timer, VirtualTime { ticks: sequence });
    let mut pass = ConditionEvaluationPass::from_log_prefix(
        crucible::test_support::condition_prefix_at_quantum_boundary_for_test(sequence),
        NoLeaves,
    )
    .with_timer_fires(timer_fires);
    let firings = pass.evaluate_event_graph(&graph, &mut graph_state);
    let Some(firing) = firings
        .iter()
        .find(|firing| condition_summary_is_timer_fire(firing.condition_summary()))
        .cloned()
    else {
        panic!("timer fire event graph should produce a timer predicate firing");
    };
    SchedulerEventLogPayload::TriggerFired(firing)
}

pub(super) fn timer_action_payload(sequence: u64) -> SchedulerEventLogPayload {
    SchedulerEventLogPayload::TriggerActionApplied(TriggerActionApplication {
        sequence,
        event: EventId::from_name("session-step-timer"),
        at: VirtualTime { ticks: sequence },
        path: Vec::new(),
        action: Action::cancel_timer(TimerId {
            name: String::from("session-step-timer"),
        }),
    })
}

pub(super) fn generated_decision(seed: u64) -> Decision {
    let node = scheduler_node("control-plane");
    Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: seed },
        order: vec![EventKey::new(
            VirtualTime { ticks: seed },
            node.clone(),
            node,
            seed,
        )],
    })
}

pub(super) fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::ControlPlane,
    }
}
#[path = "actor_runtime/coverage.rs"]
mod coverage;
