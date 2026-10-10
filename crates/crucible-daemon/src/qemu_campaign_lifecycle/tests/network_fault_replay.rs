//! Start replay parks network fault phase markers like the modeled driver.

use super::*;

fn replay_lifecycle() -> FakeFreshLifecycle {
    FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: Vec::new(),
        replies: Arc::new(Mutex::new(Vec::new())),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        released_host_outcome: None,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    }
}

fn network_fault_input() -> CrucibleAttemptExecution {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let selectables = ScenarioSelectables::new(
        scenario.world(),
        ScenarioSelectableLimits::default(),
        vec![crucible::NetworkFaultSelectable::declaration().expect("network declaration")],
    )
    .expect("network selectables");
    let scenario = scenario
        .with_selectables(selectables)
        .expect("attach network selectables");
    modeled_fresh_runner_input_for_scenario(scenario, StopCondition::Terminal)
}

fn replay_step(parent: &Configuration) -> Configuration {
    accepted_step(
        parent,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
    )
}

/// A replay crossing staggered phase markers parks each held VM per quantum.
#[test]
fn start_replay_parks_network_phase_markers_only_when_declared() {
    let cases = [
        (fresh_runner_input(), vec!["replay", "replay"]),
        (
            network_fault_input(),
            vec!["replay", "park", "replay", "park"],
        ),
    ];

    for (input, expected) in cases {
        let parent = input.start().configuration().clone();
        let target = replay_step(&replay_step(&parent));
        let mut lifecycle = replay_lifecycle();

        let replay = materialize_start_from::<(), ()>(
            &mut lifecycle,
            &input,
            parent,
            &target,
            &fresh_runner_context(),
            QemuFreshStartMaterialization::genesis(),
        )
        .expect("start replay reaches its target");

        assert_eq!(replay.into_parts().2, 2);
        assert_eq!(*lifecycle.order.lock().expect("operation order"), expected);
    }
}
