//! Session-actor canonical coverage publication tests.

use super::*;

#[tokio::test]
pub(super) async fn actor_publishes_backend_coverage_from_the_canonical_event_log() {
    let scenario = generated_scenario(223);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let event = crucible::ObservableEvent::coverage_block(
        crucible::Icount { retired: 17 },
        node_id("vm-a"),
        0x4010,
        4,
    );
    let quantum_loop = crucible::BackendQuantumLoop::new(
        CoverageAppendingLoop::default(),
        CoverageBackend::new(event),
    );
    let mut engine = Engine::new(config, graph, quantum_loop);
    engine
        .apply_command(SessionCommand::Start)
        .expect("coverage actor should instantiate");
    engine
        .apply_command(SessionCommand::Continue)
        .expect("coverage actor should enter running state");
    let (_sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);
    let mut stream = actor.event_log_stream(EventLogCursor::new(0));

    actor
        .run_once()
        .await
        .expect("coverage quantum should reach the actor boundary");

    let frame = stream
        .try_recv()
        .expect("coverage stream should remain readable")
        .expect("coverage stream should receive one canonical entry");
    assert_eq!(frame.entry.class(), SchedulerEventLogClass::Observational);
    let projection = crucible::event_log_coverage_projection(&[frame.entry]);
    assert_eq!(projection.len(), 1);
    assert_eq!(projection.entries()[0].at.icount.retired, 17);
    assert_eq!(actor.event_log().len(), 2);
    assert_eq!(actor.engine().event_log_len(), 2);
}

#[tokio::test]
pub(super) async fn actor_publishes_final_backend_coverage_before_shutdown_completes() {
    let scenario = generated_scenario(224);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let event = crucible::ObservableEvent::coverage_block(
        crucible::Icount { retired: 0 },
        node_id("vm-a"),
        0x4020,
        8,
    );
    let quantum_loop = crucible::BackendQuantumLoop::new(
        CoverageAppendingLoop::default(),
        CoverageBackend::new(event),
    );
    let mut engine = Engine::new(config, graph, quantum_loop);
    engine
        .apply_command(SessionCommand::Start)
        .expect("coverage actor should instantiate");
    engine
        .apply_command(SessionCommand::Continue)
        .expect("coverage actor should enter running state");
    let (sender, receiver) = mpsc::channel(1);
    let mut actor = SessionActor::new(engine, receiver);
    let mut stream = actor.event_log_stream(EventLogCursor::new(0));

    sender
        .send(SessionCommand::Stop)
        .await
        .expect("stop command should enqueue");
    actor
        .run_once()
        .await
        .expect("shutdown should publish its final coverage drain");

    let frame = stream
        .try_recv()
        .expect("coverage stream should remain readable")
        .expect("coverage stream should receive the final canonical entry");
    assert_eq!(frame.entry.sequence(), 0);
    assert_eq!(frame.entry.class(), SchedulerEventLogClass::Observational);
    let projection = crucible::event_log_coverage_projection(&[frame.entry]);
    assert_eq!(projection.len(), 1);
    assert_eq!(projection.entries()[0].at.icount.retired, 0);
    assert_eq!(actor.event_log().len(), 2);
    assert_eq!(actor.engine().event_log_len(), 2);
    assert!(matches!(
        actor.engine().state(),
        EngineState::Stopped {
            outcome: Outcome::Stopped
        }
    ));
}
