//! Checks original nonce exclusion through actual installed Clock CLI/daemon processes.

use super::*;

#[test]
#[ignore = "requires the source-built companion and actual owning CLI/daemon executable"]
fn actual_ordinary_clock_result_and_capability_pending_route_cannot_replace_each_other() {
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("original");
    let (policy_path, socket) = policy(&original, &device);
    let _daemon = Daemon::start(&policy_path, &socket);
    let selections = json!([{
        "node": "clock", "owner": "clock-owner", "kind": {"implementation": "host_clock"}
    }]);
    let selected = original.join("selections.json");
    fs::write(&selected, serde_json::to_vec(&selections).unwrap()).unwrap();
    let scenario_path = original.join("scenario.json");
    let compiled = cli(&[
        "node",
        "compile",
        "--socket",
        socket.to_str().unwrap(),
        "--selections",
        selected.to_str().unwrap(),
        "--output",
        scenario_path.to_str().unwrap(),
    ]);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let scenario = NodeScenario::from_json(&fs::read(&scenario_path).unwrap()).unwrap();
    let configuration = original.join("configuration.json");
    fs::write(&configuration, br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"10","maximum_rounds":"8"}"#).unwrap();
    let execution = "85858585858585858585858585858585";

    // The ordinary actor authenticates and executes a genuine native Clock.
    // A later data-only capability reservation cannot replace that history.
    let original_observation = success(&[
        "node",
        "observe",
        "--socket",
        socket.to_str().unwrap(),
        "--ledger",
        "ordinary-claim",
        "--execution",
        execution,
        "--selections",
        selected.to_str().unwrap(),
        "--scenario",
        scenario_path.to_str().unwrap(),
        "--configuration",
        configuration.to_str().unwrap(),
    ]);
    assert!(original_observation.is_object());
    let deadline = Instant::now() + Duration::from_secs(20);
    let original_state = loop {
        assert!(Instant::now() < deadline);
        let state = success(&[
            "node",
            "status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]);
        assert!(Instant::now() < deadline);
        if state["status"] == "completed" {
            break state;
        }
        assert_eq!(state["status"], "reserved");
    };
    let demand = demands(&scenario);
    let candidates = json!([{"id":"installed/clock","selections":selections}]);
    let request_path = original.join("request.json");
    let conflicting = request(
        execution,
        &demand,
        candidates.clone(),
        json!({"operation":"observe"}),
        10,
    );
    fs::write(&request_path, serde_json::to_vec(&conflicting).unwrap()).unwrap();
    let refused = cli(&[
        "node",
        "capability",
        "--socket",
        socket.to_str().unwrap(),
        "--request",
        request_path.to_str().unwrap(),
    ]);
    assert!(!refused.status.success());
    assert_eq!(
        success(&[
            "node",
            "status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution
        ]),
        original_state
    );

    // A separately retained unavailable admission still owns its nonce. It is
    // not permission for another route to create a replacement Clock runtime.
    let pending_execution = "86868686868686868686868686868686";
    let mut unsupported = demand;
    unsupported.nodes[0].guarantees.conditional_replay = true;
    let unavailable = request(
        pending_execution,
        &unsupported,
        candidates,
        json!({"operation":"observe"}),
        10,
    );
    let admitted = submit(&socket, &request_path, &unavailable);
    let record = finished(&socket, &admitted.execution);
    assert!(matches!(
        record.outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));
    let refused = cli(&[
        "node",
        "observe",
        "--socket",
        socket.to_str().unwrap(),
        "--ledger",
        "ordinary-claim",
        "--execution",
        pending_execution,
        "--selections",
        selected.to_str().unwrap(),
        "--scenario",
        scenario_path.to_str().unwrap(),
        "--configuration",
        configuration.to_str().unwrap(),
    ]);
    assert!(!refused.status.success());
    let retained: CapabilityPreparationRecord = serde_json::from_value(success(&[
        "node",
        "capability-status",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        pending_execution,
    ]))
    .unwrap();
    assert_eq!(
        serde_json::to_value(retained).unwrap(),
        serde_json::to_value(record).unwrap()
    );
}
