//! Phase-6 exploration fork checks for independent child sessions.

#![forbid(unsafe_code)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, Decision, DeliveryOrderDecision, EventKey,
    GenesisCheckpoint, NodeId, QuantumLoop, QuantumOutcome, QuantumRequest, ScenarioDef,
    SchedulerError, SchedulerNodeId, SchedulingNodeKind, Seed, TemporalGraph, VirtualTime, step,
};
use crucible_session::{
    CheckpointRef, CommandReply, Engine, EngineState, LiveSnapshot, LiveStateKind, Outcome,
    PauseReason, SessionActor, SessionCommand, SessionError,
};
use tokio::sync::mpsc;

#[tokio::test(flavor = "current_thread")]
async fn fork_child_uses_temporal_graph_fork_and_independent_child_actor() {
    let scenario = generated_scenario(301);
    let genesis = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut parent = Engine::new(genesis.clone(), graph, AppendingLoop::new(10));

    start_and_run_quanta(&mut parent, 3);
    parent
        .apply_command(SessionCommand::Pause)
        .unwrap_or_else(|error| panic!("parent should pause at fork boundary: {error}"));
    let parent_before = parent.snapshot();
    let base = prefix_configuration(&parent_before.configuration, 1);
    let fork_decision = generated_decision(99, 0);
    let expected_branch = step(&base, fork_decision.clone());

    let fork = parent
        .fork_child(&base, [fork_decision.clone()], AppendingLoop::new(400))
        .unwrap_or_else(|error| panic!("paused parent should fork child session: {error}"));
    let parent_after_fork = parent.snapshot();

    assert_eq!(parent_after_fork, parent_before);
    assert!(matches!(fork.parent_state, EngineState::Paused { .. }));
    assert_eq!(fork.base_configuration, base.id());
    assert_eq!(fork.branch_configuration, expected_branch);
    assert_eq!(fork.branch_checkpoint.id, expected_branch.id());
    assert_eq!(fork.branch_checkpoint.kind, CheckpointKind::Thin);
    assert_eq!(fork.branch_checkpoint.parent, Some(base.id()));
    assert!(fork.branch_checkpoint.state.is_none());
    assert_eq!(fork.record.from_checkpoint, base.id());
    assert_eq!(fork.record.branch_checkpoint, expected_branch.id());
    assert_eq!(fork.record.schedule_delta.decisions(), &[fork_decision]);
    assert!(matches!(
        fork.child_actor.engine().state(),
        EngineState::Paused {
            reason: PauseReason::Instantiated
        }
    ));
    assert_eq!(fork.child_actor.engine().configuration(), &expected_branch);
    assert_eq!(
        fork.child_actor.engine().frontier(),
        VirtualTime { ticks: 99 }
    );

    let child_sender = fork.child_sender.clone();
    let child_live = fork.child_actor.live_snapshot();
    let child_task = tokio::spawn(async move { fork.child_actor.run().await });

    send_command(&child_sender, SessionCommand::Continue).await;
    wait_for_quanta(&child_live, 1).await;
    send_command(&child_sender, SessionCommand::Stop).await;
    let child_report = join_child(child_task).await;

    assert!(matches!(
        child_report.final_snapshot.state,
        EngineState::Stopped {
            outcome: Outcome::Stopped
        }
    ));
    assert_eq!(child_report.quanta, 1);
    assert_ne!(
        child_report.final_snapshot.configuration,
        parent_before.configuration
    );
    assert_eq!(parent.snapshot(), parent_before);
}

#[test]
fn fork_child_rejects_loaded_and_running_parent_without_pause() {
    let scenario = generated_scenario(302);
    let genesis = Configuration::genesis(scenario.clone());
    let mut loaded = Engine::new(
        genesis.clone(),
        graph_with_baked_genesis(&scenario),
        AppendingLoop::new(20),
    );
    assert_invalid_fork_state(loaded.fork_child(
        &genesis,
        [generated_decision(1, 0)],
        AppendingLoop::new(21),
    ));

    let mut running = Engine::new(
        genesis.clone(),
        graph_with_baked_genesis(&scenario),
        AppendingLoop::new(22),
    );
    running
        .apply_command(SessionCommand::Start)
        .unwrap_or_else(|error| panic!("running fixture should start: {error}"));
    running
        .apply_command(SessionCommand::Continue)
        .unwrap_or_else(|error| panic!("running fixture should continue: {error}"));
    assert_invalid_fork_state(running.fork_child(
        &genesis,
        [generated_decision(2, 0)],
        AppendingLoop::new(23),
    ));
}

#[test]
fn stopped_parent_can_fork_from_final_checkpoint_without_mutation() {
    let scenario = generated_scenario(303);
    let genesis = Configuration::genesis(scenario.clone());
    let mut parent = Engine::new(
        genesis,
        graph_with_baked_genesis(&scenario),
        AppendingLoop::new(30),
    );
    start_and_run_quanta(&mut parent, 2);
    parent
        .apply_command(SessionCommand::Stop)
        .unwrap_or_else(|error| panic!("parent should stop before final fork: {error}"));
    let parent_before = parent.snapshot();
    let fork_decision = generated_decision(303, 0);
    let expected_branch = step(&parent_before.configuration, fork_decision.clone());

    let fork = parent
        .fork_child(
            &parent_before.configuration,
            [fork_decision],
            AppendingLoop::new(31),
        )
        .unwrap_or_else(|error| panic!("stopped parent should fork final checkpoint: {error}"));

    assert!(matches!(fork.parent_state, EngineState::Stopped { .. }));
    assert_eq!(fork.base_configuration, parent_before.configuration.id());
    assert_eq!(fork.branch_configuration, expected_branch);
    assert_eq!(fork.branch_checkpoint.kind, CheckpointKind::Thin);
    assert_eq!(parent.snapshot(), parent_before);
}

#[tokio::test(flavor = "current_thread")]
async fn actor_fork_command_spawns_independent_child_handle() {
    let scenario = generated_scenario(304);
    let genesis = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut parent = Engine::new(genesis, graph, AppendingLoop::new(40));

    start_and_run_quanta(&mut parent, 2);
    parent
        .apply_command(SessionCommand::Pause)
        .unwrap_or_else(|error| panic!("parent should pause before command fork: {error}"));
    let parent_before_fork = parent.snapshot();
    let expected_child_configuration = parent_before_fork.configuration.id();
    let (parent_sender, parent_receiver) = mpsc::channel(8);
    let actor = SessionActor::new_with_fork_loop_factory(parent, parent_receiver, move |request| {
        assert_eq!(request.configuration, expected_child_configuration);
        AppendingLoop::new(700)
    });
    let parent_task = tokio::spawn(async move { actor.run().await });

    let (fork_reply, fork_receiver) = CommandReply::channel();
    send_command(
        &parent_sender,
        SessionCommand::Fork {
            from: CheckpointRef::Current,
            reply: fork_reply,
        },
    )
    .await;
    let handle = receive_reply(fork_receiver).await;
    assert_eq!(handle.checkpoint, expected_child_configuration);
    assert_eq!(handle.configuration, expected_child_configuration);
    let child_sender = handle
        .child_sender()
        .unwrap_or_else(|| panic!("fork command should return a child sender"));
    let child_live = handle
        .child_live_snapshot()
        .unwrap_or_else(|| panic!("fork command should return a child live snapshot"));
    assert_eq!(child_live.read().state_kind, LiveStateKind::Paused);

    send_command(&child_sender, SessionCommand::Continue).await;
    wait_for_quanta(&child_live, 1).await;
    send_command(&child_sender, SessionCommand::Stop).await;

    send_command(&parent_sender, SessionCommand::Stop).await;
    let parent_report = join_child(parent_task).await;
    assert_eq!(
        parent_report.final_snapshot.configuration,
        parent_before_fork.configuration
    );
}

#[tokio::test(flavor = "current_thread")]
async fn actor_fork_command_completes_reply_on_missing_checkpoint() {
    let scenario = generated_scenario(305);
    let genesis = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut parent = Engine::new(genesis, graph, AppendingLoop::new(41));

    start_and_run_quanta(&mut parent, 1);
    parent
        .apply_command(SessionCommand::Pause)
        .unwrap_or_else(|error| panic!("parent should pause before bad fork: {error}"));
    let (parent_sender, parent_receiver) = mpsc::channel(8);
    let actor = SessionActor::new_with_fork_loop_factory(parent, parent_receiver, |_request| {
        AppendingLoop::new(702)
    });
    let parent_task = tokio::spawn(async move { actor.run().await });
    let missing = crucible::ContentHash::from_bytes(b"missing-session-fork-checkpoint");

    let (fork_reply, fork_receiver) = CommandReply::channel();
    send_command(
        &parent_sender,
        SessionCommand::Fork {
            from: CheckpointRef::Checkpoint(missing),
            reply: fork_reply,
        },
    )
    .await;

    let reply_error = receive_reply_error::<crucible_session::SessionHandle>(fork_receiver).await;
    assert!(matches!(
        reply_error,
        SessionError::Engine(crucible::EngineError::CheckpointNotRecorded { checkpoint })
            if checkpoint == missing
    ));
    match parent_task.await {
        Ok(Err(SessionError::Engine(crucible::EngineError::CheckpointNotRecorded {
            checkpoint,
        }))) => assert_eq!(checkpoint, missing),
        Ok(Ok(report)) => panic!("actor should fail after bad fork, got report: {report:?}"),
        Ok(Err(error)) => panic!("actor should return missing checkpoint error: {error}"),
        Err(error) => panic!("actor task should join after bad fork: {error}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn resume_session_from_savepoint_uses_graph_checkpoint_and_independent_actor() {
    let scenario = generated_scenario(306);
    let genesis = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut parent = Engine::new(genesis, graph, AppendingLoop::new(40));

    start_and_run_quanta(&mut parent, 2);
    parent
        .apply_command(SessionCommand::Pause)
        .unwrap_or_else(|error| panic!("parent should pause before savepoint resume: {error}"));
    let savepoint = create_savepoint(&mut parent, "resume-source").await;
    let parent_before_resume = parent.snapshot();

    let resumed = parent
        .resume_session_from_checkpoint(savepoint.checkpoint.id, AppendingLoop::new(500))
        .unwrap_or_else(|error| panic!("savepoint resume should build a session actor: {error}"));

    assert_eq!(parent.snapshot(), parent_before_resume);
    assert_eq!(resumed.checkpoint, savepoint.checkpoint.id);
    assert_eq!(resumed.configuration.id(), savepoint.configuration);
    assert_eq!(resumed.runtime.configuration, savepoint.configuration);
    assert!(matches!(
        resumed.session_actor.engine().state(),
        EngineState::Paused {
            reason: PauseReason::Instantiated
        }
    ));
    assert_eq!(
        resumed.session_actor.engine().configuration().id(),
        savepoint.configuration
    );
    assert_eq!(
        resumed.session_actor.live_snapshot().read().state_kind,
        crucible_session::LiveStateKind::Paused
    );

    let resumed_sender = resumed.session_sender.clone();
    let resumed_live = resumed.session_actor.live_snapshot();
    let resumed_task = tokio::spawn(async move { resumed.session_actor.run().await });

    send_command(&resumed_sender, SessionCommand::Continue).await;
    wait_for_quanta(&resumed_live, 1).await;
    send_command(&resumed_sender, SessionCommand::Stop).await;
    let resumed_report = join_child(resumed_task).await;

    assert_eq!(resumed_report.quanta, 1);
    assert_ne!(
        resumed_report.final_snapshot.configuration,
        parent_before_resume.configuration
    );
    assert_eq!(parent.snapshot(), parent_before_resume);
}

#[tokio::test(flavor = "current_thread")]
async fn resume_session_from_cached_snapshot_without_thin_node() {
    let scenario = generated_scenario(307);
    let genesis = Configuration::genesis(scenario.clone());
    let config = step(&genesis, generated_decision(306, 0));
    let mut materializer = graph_with_baked_genesis(&scenario);
    let checkpoint = materializer
        .save_checkpoint(&config)
        .unwrap_or_else(|error| panic!("fat checkpoint should save: {error}"));
    let graph = TemporalGraph::empty()
        .with_cached_snapshot(&config, checkpoint.clone())
        .unwrap_or_else(|error| panic!("cached snapshot should register: {error}"));
    assert!(graph.checkpoint_node(config.id()).is_none());
    assert_eq!(graph.checkpoint_record(config.id()), Some(&checkpoint));

    let mut parent = Engine::new(config.clone(), graph, AppendingLoop::new(70));
    let parent_before_resume = parent.snapshot();
    let resumed = parent
        .resume_session_from_checkpoint(config.id(), AppendingLoop::new(701))
        .unwrap_or_else(|error| panic!("cached snapshot should resume as a session: {error}"));

    assert_eq!(parent.snapshot(), parent_before_resume);
    assert_eq!(resumed.checkpoint, config.id());
    assert_eq!(resumed.configuration, config);
    assert_eq!(resumed.runtime.configuration, resumed.configuration.id());
    assert!(matches!(
        resumed.session_actor.engine().state(),
        EngineState::Paused {
            reason: PauseReason::Instantiated
        }
    ));

    let resumed_sender = resumed.session_sender.clone();
    let resumed_task = tokio::spawn(async move { resumed.session_actor.run().await });
    send_command(&resumed_sender, SessionCommand::Stop).await;
    let resumed_report = join_child(resumed_task).await;

    assert_eq!(resumed_report.quanta, 0);
    assert!(matches!(
        resumed_report.final_snapshot.state,
        EngineState::Stopped {
            outcome: Outcome::Stopped
        }
    ));
    assert_eq!(parent.snapshot(), parent_before_resume);
}

#[tokio::test(flavor = "current_thread")]
async fn fork_child_from_checkpoint_instantiates_prefix_child_without_parent_mutation() {
    let scenario = generated_scenario(308);
    let genesis = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut parent = Engine::new(genesis, graph, AppendingLoop::new(50));

    start_and_run_quanta(&mut parent, 3);
    parent
        .apply_command(SessionCommand::Pause)
        .unwrap_or_else(|error| panic!("parent should pause before checkpoint fork: {error}"));
    let parent_before_fork = parent.snapshot();
    let base = prefix_configuration(&parent_before_fork.configuration, 1);

    let fork = parent
        .fork_child_from_checkpoint(
            CheckpointRef::Checkpoint(base.id()),
            AppendingLoop::new(600),
        )
        .unwrap_or_else(|error| panic!("recorded prefix checkpoint should fork: {error}"));

    assert_eq!(parent.snapshot(), parent_before_fork);
    assert!(matches!(fork.parent_state, EngineState::Paused { .. }));
    assert_eq!(fork.base_configuration, base.id());
    assert_eq!(fork.branch_configuration, base);
    assert_eq!(fork.record.from_checkpoint, fork.base_configuration);
    assert_eq!(fork.record.branch_checkpoint, fork.branch_checkpoint.id);
    assert!(fork.record.schedule_delta.is_empty());
    assert!(matches!(
        fork.child_actor.engine().state(),
        EngineState::Paused {
            reason: PauseReason::Instantiated
        }
    ));
    assert_eq!(
        fork.child_actor.engine().configuration(),
        &fork.branch_configuration
    );

    let child_sender = fork.child_sender.clone();
    let child_live = fork.child_actor.live_snapshot();
    let child_task = tokio::spawn(async move { fork.child_actor.run().await });

    send_command(&child_sender, SessionCommand::Continue).await;
    wait_for_quanta(&child_live, 1).await;
    send_command(&child_sender, SessionCommand::Stop).await;
    let child_report = join_child(child_task).await;

    assert_eq!(child_report.quanta, 1);
    assert_eq!(parent.snapshot(), parent_before_fork);
}

#[test]
fn fork_child_from_checkpoint_rejects_loaded_and_running_parent_without_pause() {
    let scenario = generated_scenario(309);
    let genesis = Configuration::genesis(scenario.clone());
    let mut loaded = Engine::new(
        genesis.clone(),
        graph_with_baked_genesis(&scenario),
        AppendingLoop::new(60),
    );
    assert_invalid_checkpoint_fork_state(
        loaded.fork_child_from_checkpoint(CheckpointRef::Current, AppendingLoop::new(61)),
    );

    let mut running = Engine::new(
        genesis,
        graph_with_baked_genesis(&scenario),
        AppendingLoop::new(62),
    );
    running
        .apply_command(SessionCommand::Start)
        .unwrap_or_else(|error| panic!("running fixture should start: {error}"));
    running
        .apply_command(SessionCommand::Continue)
        .unwrap_or_else(|error| panic!("running fixture should continue: {error}"));
    assert_invalid_checkpoint_fork_state(
        running.fork_child_from_checkpoint(CheckpointRef::Current, AppendingLoop::new(63)),
    );
}

fn start_and_run_quanta(engine: &mut Engine<AppendingLoop>, quanta: usize) {
    engine
        .apply_command(SessionCommand::Start)
        .unwrap_or_else(|error| panic!("engine should start: {error}"));
    engine
        .apply_command(SessionCommand::Continue)
        .unwrap_or_else(|error| panic!("engine should continue: {error}"));
    for _ in 0..quanta {
        engine
            .step_quantum()
            .unwrap_or_else(|error| panic!("engine quantum should step: {error}"));
    }
}

fn assert_invalid_fork_state(
    result: Result<crucible_session::SessionFork<AppendingLoop>, SessionError>,
) {
    assert!(matches!(
        result,
        Err(SessionError::InvalidEngineState {
            operation: "fork_child",
            ..
        })
    ));
}

fn assert_invalid_checkpoint_fork_state(
    result: Result<crucible_session::SessionFork<AppendingLoop>, SessionError>,
) {
    assert!(matches!(
        result,
        Err(SessionError::InvalidEngineState {
            operation: "fork_child_from_checkpoint",
            ..
        })
    ));
}

async fn create_savepoint(
    engine: &mut Engine<AppendingLoop>,
    label: &str,
) -> crucible_session::SavepointInfo {
    let (reply, receiver) = CommandReply::channel();
    engine
        .apply_command(SessionCommand::CreateSavepoint {
            label: label.to_owned(),
            reply,
        })
        .unwrap_or_else(|error| panic!("savepoint should materialize through graph: {error}"));
    receive_reply(receiver).await
}

async fn receive_reply<T>(receiver: tokio::sync::oneshot::Receiver<Result<T, SessionError>>) -> T {
    match receiver.await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => panic!("reply should complete successfully: {error}"),
        Err(error) => panic!("reply sender should complete: {error}"),
    }
}

async fn receive_reply_error<T: std::fmt::Debug>(
    receiver: tokio::sync::oneshot::Receiver<Result<T, SessionError>>,
) -> SessionError {
    match receiver.await {
        Ok(Ok(value)) => panic!("reply should fail, got success: {value:?}"),
        Ok(Err(error)) => error,
        Err(error) => panic!("reply sender should return a typed error: {error}"),
    }
}

async fn send_command(sender: &mpsc::Sender<SessionCommand>, command: SessionCommand) {
    sender
        .send(command)
        .await
        .unwrap_or_else(|error| panic!("session command should enqueue: {error}"));
}

async fn wait_for_quanta(live: &LiveSnapshot, quanta: u64) {
    for _ in 0..256 {
        if live.read().quanta_stepped >= quanta {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("child session should reach {quanta} quanta within bounded actor yields");
}

async fn join_child(
    task: tokio::task::JoinHandle<Result<crucible_session::SessionRunReport, SessionError>>,
) -> crucible_session::SessionRunReport {
    match task.await {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => panic!("child session should stop cleanly: {error}"),
        Err(error) => panic!("child task should join cleanly: {error}"),
    }
}

fn prefix_configuration(configuration: &Configuration, len: usize) -> Configuration {
    Configuration {
        def: configuration.def.clone(),
        schedule: configuration
            .schedule
            .prefix(len)
            .unwrap_or_else(|error| panic!("prefix configuration should build: {error}")),
    }
}

struct AppendingLoop {
    seed: u64,
    quanta: u64,
    event_log_events: u64,
}

impl AppendingLoop {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            quanta: 0,
            event_log_events: 0,
        }
    }
}

impl QuantumLoop for AppendingLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        let decision = generated_decision(self.seed, self.quanta);
        let configuration = step(&request.configuration, decision.clone());
        let entry = crucible::test_support::condition_boundary_entry_for_test(
            self.event_log_events,
            VirtualTime { ticks: self.quanta },
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        );
        self.event_log_events = self.event_log_events.saturating_add(1);
        Ok(QuantumOutcome {
            configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            event_log_entries: vec![entry],
            event_log_segment_bytes: vec![b'f'],
            event_log_segment_text: String::from("fork"),
            event_log_segment_hash: Some(crucible::ContentHash::from_bytes(b"fork")),
            event_log_offset: crucible::EventLogOffset::new(
                Default::default(),
                0,
                self.event_log_events,
            ),
            scheduler_quiescence: None,
        })
    }
}

fn graph_with_baked_genesis(scenario: &ScenarioDef) -> TemporalGraph {
    let genesis = Configuration::genesis(scenario.clone());
    TemporalGraph::empty()
        .with_baked_genesis(scenario, genesis_checkpoint(&genesis))
        .unwrap_or_else(|error| panic!("valid baked genesis should register: {error}"))
}

fn genesis_checkpoint(configuration: &Configuration) -> GenesisCheckpoint {
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

fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.session.exploration-fork",
        &format!("seed={seed}"),
        Seed::from_u64(seed),
    )
}

fn generated_decision(seed: u64, sequence: u64) -> Decision {
    let node = scheduler_node("exploration-fork");
    Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime {
            ticks: seed.saturating_add(sequence),
        },
        order: vec![EventKey::new(
            VirtualTime {
                ticks: seed.saturating_add(sequence),
            },
            node.clone(),
            node,
            sequence,
        )],
    })
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::ControlPlane,
    }
}
