//! Terminal-verdict regression tests for production-owned trigger evaluation.

use super::*;

#[tokio::test]
async fn terminal_quantum_verdict_is_not_reapplied_as_a_breakpoint_action() {
    let scenario = generated_scenario(4_706);
    let config = Configuration::genesis(scenario.clone());
    let graph = graph_with_baked_genesis(&scenario);
    let mut engine = Engine::new(
        config,
        graph,
        TerminalVerdictLoop::new(QuantumTerminalVerdict::Failed(vec![String::from(
            "production trigger invariant violated",
        )])),
    );
    engine
        .apply_command(SessionCommand::Start)
        .unwrap_or_else(|error| panic!("terminal-verdict engine must start: {error}"));
    let (reply, receiver) = CommandReply::channel();
    engine
        .apply_command(SessionCommand::SetBreakpoint {
            spec: BreakpointSpec::fail_once(
                Predicate::at(VirtualTime { ticks: 0 }),
                "duplicate breakpoint verdict",
            ),
            reply,
        })
        .unwrap_or_else(|error| panic!("terminal-verdict breakpoint must register: {error}"));
    let _breakpoint_id = receive_reply(receiver).await;
    engine
        .apply_command(SessionCommand::Continue)
        .unwrap_or_else(|error| panic!("terminal-verdict engine must continue: {error}"));
    engine
        .step_quantum()
        .unwrap_or_else(|error| panic!("terminal-verdict quantum must complete: {error}"));

    let entries = vec![crucible::test_support::condition_boundary_entry_for_test(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEvaluationBoundaryKind::Quantum,
    )];
    engine
        .evaluate_breakpoints(&entries, entries.len())
        .unwrap_or_else(|error| panic!("terminal breakpoint evaluation must be inert: {error}"));

    assert!(matches!(
        engine.state(),
        EngineState::Stopped {
            outcome: Outcome::Failed { violations }
        } if violations == &[String::from("production trigger invariant violated")]
    ));
    assert!(engine.breakpoint_firings().is_empty());
}
