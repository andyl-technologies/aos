//! Runtime ownership and startup smoke tests.

use super::*;

#[test]
fn session_driver_delegates_to_quantum_loop() {
    let config = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.session.quantum-loop",
        "scenario=stub",
    ));
    let request = QuantumRequest {
        configuration: config.clone(),
        control: Vec::new(),
    };
    let mut driver = SessionDriver::new(StubLoop);

    let outcome = driver.drive_quantum(request);

    assert_eq!(
        outcome.as_ref().map(|outcome| &outcome.configuration),
        Ok(&config)
    );
}

#[test]
fn engine_start_instantiates_runtime_and_pauses() {
    let scenario = generated_scenario(11);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(config.clone(), graph, StubLoop);

    let snapshot = match engine.apply_command(SessionCommand::Start) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("start should instantiate runtime: {error}"),
    };

    assert_eq!(
        snapshot.state,
        EngineState::Paused {
            reason: PauseReason::Instantiated
        }
    );
    assert_eq!(
        engine.runtime().map(|runtime| runtime.configuration),
        Some(config.id())
    );
}

#[test]
fn session_actor_owns_breakpoint_set_with_runtime_state() {
    let scenario = generated_scenario(10);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let engine = Engine::new(config, graph, StubLoop);
    let (_sender, receiver) = mpsc::channel(4);
    let actor = SessionActor::new(engine, receiver);

    assert!(actor.engine().breakpoints().is_empty());
    assert_eq!(actor.engine().breakpoints().len(), 0);
}
