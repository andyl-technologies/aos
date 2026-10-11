//! Requires genuine no-archive retirement of the same published four-owner world.
//!
//! The authored one-round limit refuses further work after the first original
//! planner round. Durable failure roots are checked as data, never as permission
//! to discard the capsule. Successful owning service retirement is a separate
//! conjunction; assertion failure retains its original Child through the parent
//! fixture's parking guard. No native process is killed or replaced here.

use super::*;

#[path = "failed_retirement/evidence.rs"]
mod evidence;

#[test]
#[ignore = "requires installed accepted SE four-owner behavior, current CLI/daemon and genuine original no-archive Shutdown/reap; parks failed custody"]
fn original_round_exhaustion_retires_without_a_capture_archive() {
    let directory = tempfile::Builder::new()
        .prefix("gem5-capability-failed-retirement-")
        .tempdir()
        .unwrap()
        .keep();
    eprintln!("original failed-world custody: {}", directory.display());
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let state = directory.join("state");
    let (policy_path, socket) = policy(&state, &device);
    let (selections, base, script) = authored(&directory);
    let mut installed: Value = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    installed["immutable_artifacts"] = json!([base, script]);
    fs::write(&policy_path, serde_json::to_vec(&installed).unwrap()).unwrap();
    let mut service = OriginalService::start(&policy_path, &socket);

    let selected_path = directory.join("selections.json");
    let baseline_path = directory.join("baseline.json");
    fs::write(&selected_path, serde_json::to_vec(&selections).unwrap()).unwrap();
    let compiled = cli(&[
        "node",
        "compile",
        "--socket",
        socket.to_str().unwrap(),
        "--selections",
        selected_path.to_str().unwrap(),
        "--output",
        baseline_path.to_str().unwrap(),
    ]);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let baseline = NodeScenario::from_json(&fs::read(&baseline_path).unwrap()).unwrap();
    let execution = "47474747474747474747474747474747";
    let mut original_request = request(
        execution,
        &complete_demands(&baseline),
        json!([{"id":"complete-four-owners","selections":selections}]),
        json!({"operation":"capture"}),
        11,
    );
    original_request["configuration"] = serde_json::to_value(Bytes::new(
        serde_json::to_vec(&json!({
            "format":"crucible.node-run-configuration", "version":1,
            "horizon_ps":"11", "maximum_rounds":"1"
        }))
        .unwrap(),
    ))
    .unwrap();
    let request_path = directory.join("request.json");
    submit(&socket, &request_path, &original_request);

    let refused = wait_original(&socket, execution);
    let CapabilityPreparationState::Unavailable { reason } = &refused.outcome else {
        panic!("one-round original did not refuse: {:?}", refused.outcome);
    };
    assert!(
        reason.ends_with("original common planner exceeds bounded round credit"),
        "{reason}"
    );
    assert_eq!(
        serde_json::to_value(submit(&socket, &request_path, &original_request)).unwrap(),
        serde_json::to_value(&refused).unwrap(),
    );
    fs::write(
        directory.join("original-refusal.json"),
        serde_json::to_vec(&refused).unwrap(),
    )
    .unwrap();

    // This root is published before native supervisor release. Its presence
    // proves retained data only, not that any owner or queue credit was released.
    let retained = evidence::await_original(&state, &directory, &refused, &baseline);
    service.retire();
    // Service success follows the worker's authenticated native release and the
    // same runtime release. Fresh readers now require unchanged durable bytes.
    evidence::verify_original(&state, &directory, &refused, &baseline, Some(&retained)).unwrap();
}
