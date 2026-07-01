//! Phase-6 exploration fork checks for independent child sessions.

#![forbid(unsafe_code)]

use crucible::{
    Checkpoint, CheckpointKind, Configuration, Decision, DeliveryOrderDecision, EventKey,
    GenesisCheckpoint, NodeId, QuantumLoop, QuantumOutcome, QuantumRequest, ScenarioDef,
    SchedulerError, SchedulerNodeId, SchedulingNodeKind, Seed, TemporalGraph, VirtualTime, step,
};
use crucible_session::{Engine, EngineState, LiveSnapshot, Outcome, SessionCommand, SessionError};
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
        EngineState::Loaded
    ));
    assert_eq!(fork.child_actor.engine().configuration(), &expected_branch);

    let child_sender = fork.child_sender.clone();
    let child_live = fork.child_actor.live_snapshot();
    let child_task = tokio::spawn(async move { fork.child_actor.run().await });

    send_command(&child_sender, SessionCommand::Start).await;
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
