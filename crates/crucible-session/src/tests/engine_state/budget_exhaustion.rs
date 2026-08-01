//! Budget-exhaustion terminal-outcome test.

use super::*;

#[test]
fn control_replay_artifact_reproduces_interactive_scheduler_state() {
    let scenario = generated_scenario(44);
    let initial = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut interactive = Engine::new(
        initial.clone(),
        graph.clone(),
        ControlSensitiveLoop::default(),
    );
    if let Err(error) = interactive.apply_command(SessionCommand::Start) {
        panic!("interactive replay producer should instantiate: {error}");
    }
    if let Err(error) = interactive.apply_command(SessionCommand::Continue) {
        panic!("interactive replay producer should run: {error}");
    }
    if let Err(error) = interactive.step_quantum() {
        panic!("first producer quantum should establish a control boundary: {error}");
    }

    let fault_tag = FaultTag::from_name("control-replay-fault");
    let fault = Fault::Node(crucible::NodeFault::Crash {
        node: NodeId {
            name: String::from("node-a"),
        },
        restart: crucible::RestartPolicy::StayDown,
    });
    if let Err(error) = interactive.apply_command(SessionCommand::Inject) {
        panic!("producer legacy inject should apply at the current boundary: {error}");
    }
    let (inject_reply, inject_receiver) = CommandReply::channel();
    if let Err(error) = interactive.apply_command(SessionCommand::InjectFault {
        spec: FaultSpec::new(fault_tag.clone(), fault),
        reply: inject_reply,
    }) {
        panic!("producer inject-fault should apply at the current boundary: {error}");
    }
    drop(inject_receiver);
    if let Err(error) = interactive.step_quantum() {
        panic!("second producer quantum should observe injected scheduler state: {error}");
    }

    let (heal_reply, heal_receiver) = CommandReply::channel();
    if let Err(error) = interactive.apply_command(SessionCommand::HealFault {
        tag: fault_tag,
        reply: heal_reply,
    }) {
        panic!("producer heal-fault should apply at the current boundary: {error}");
    }
    drop(heal_receiver);
    if let Err(error) = interactive.step_quantum() {
        panic!("third producer quantum should observe healed scheduler state: {error}");
    }

    let artifact = interactive.control_replay_artifact(initial);
    let replay = match Engine::<ControlSensitiveLoop>::replay_control_replay_artifact(
        &artifact,
        graph_with_baked_genesis(&scenario),
        ControlSensitiveLoop::default(),
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            panic!("control replay artifact should reproduce scheduler state: {error}")
        }
    };

    assert_eq!(
        replay.configuration.id(),
        artifact.final_snapshot.configuration.id()
    );
    assert_eq!(replay.frontier, artifact.final_snapshot.frontier);
    assert_eq!(replay.event_log_len, artifact.final_snapshot.event_log_len);
    assert_eq!(replay.quanta, artifact.final_snapshot.quanta);
    assert_eq!(artifact.control_log.len(), 3);
    assert!(
        artifact
            .control_log
            .iter()
            .all(|entry| entry.frontier.ticks > 0 && entry.quanta > 0),
        "replay controls should be keyed by virtual-time boundaries"
    );
    assert_eq!(
        artifact.control_log[0].quanta,
        artifact.control_log[1].quanta
    );
    assert_ne!(
        artifact.control_log[0].scheduler_batch, artifact.control_log[1].scheduler_batch,
        "separate operator commands at the same boundary must remain separate scheduler batches"
    );
}

#[test]
fn budget_exhaustion_command_produces_timeout_terminal_outcome() {
    let scenario = generated_scenario(4_702);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config, graph, StubLoop);
    if let Err(error) = engine.apply_command(SessionCommand::Start) {
        panic!("timeout-outcome start should instantiate runtime: {error}");
    }
    if let Err(error) = engine.apply_command(SessionCommand::ExhaustBudget) {
        panic!("budget exhaustion should stop the engine: {error}");
    }
    assert!(matches!(
        engine.state(),
        EngineState::Stopped {
            outcome: Outcome::Timeout
        }
    ));
}
