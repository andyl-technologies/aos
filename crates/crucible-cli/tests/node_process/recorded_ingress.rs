//! Ordinary queued CLI execution of independently installed recorded Block inputs.
//!
//! The actual daemon owns the source FIFO and native Block model. Restart reads
//! the original completed record rather than restoring or redispatching a source
//! cursor; captured-cursor continuation remains a separate qualified codec.

// crucible-lint: allow panic-shortcut -- Native byte, identity and durable-record disagreements fail this one fixture attempt.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow clippy-disallowed-method -- The absolute original request deadline bounds status polling; it never retries a failed test or enters modeled state.
#![allow(clippy::disallowed_methods)]

use super::*;
use crucible_core::node_adapters::{RecordedLogicalInput, RecordedLogicalInputSource};
use crucible_core::node_contract::OperationOutcome;
use crucible_core::node_scheduling::InputPayload;
use crucible_daemon::node_observed_executor::{
    InstalledHostIoProfile, InstalledNodeKind, InstalledNodeSelection,
    InstalledRecordedIngressProfile,
};
use crucible_daemon::node_scenario::NodeRunConfiguration;
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::{Endpoint, Id, Phase, Position, U64};

fn write_json(path: &Path, document: &impl serde::Serialize) {
    fs::write(
        path,
        canonical::canonical_json(&serde_json::to_value(document).unwrap()).unwrap(),
    )
    .unwrap();
}

fn completed_original(socket: &str, execution: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            Instant::now() < deadline,
            "original queued Block request exceeded its deadline"
        );
        let status = successful(&[
            "node",
            "status",
            "--socket",
            socket,
            "--execution",
            execution,
        ]);
        assert!(
            Instant::now() < deadline,
            "original queued Block request exceeded its deadline"
        );
        if status["status"] != "reserved" {
            assert_eq!(status["status"], "completed", "{status}");
            return status;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "requires the source-built installed companion identity; executes real daemon and host Block model"]
fn queued_recorded_block_retains_original_input_proof_nonce_and_result_after_source_removal() {
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path();
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
    let source_path = state.join("original-input.json");
    let base_path = state.join("base");
    let socket = state.join("node.sock");
    let policy = state.join("policy.json");
    let selections_path = state.join("selections.json");
    let scenario_path = state.join("scenario.json");
    let configuration_path = state.join("configuration.json");
    let node = Id::new("disk").unwrap();
    let configuration = NodeRunConfiguration {
        format: "crucible.node-run-configuration".into(),
        version: 1,
        horizon_ps: 100_000.into(),
        maximum_rounds: 64.into(),
    };
    let source = RecordedLogicalInputSource {
        format: "crucible.recorded-logical-input".into(),
        version: 1,
        endpoint: Endpoint {
            node_id: node.clone(),
            port_id: Id::new("data").unwrap(),
            lane_id: Id::new("input").unwrap(),
        },
        closed_before: Position::new(200_000.into(), 0.into(), Phase::BoundaryControl),
        inputs: [BlockRequest::get_length(101), BlockRequest::read(102, 0, 3)]
            .into_iter()
            .enumerate()
            .map(|(index, request)| {
                let bytes = request.encode().unwrap();
                RecordedLogicalInput {
                    event: Id::new(format!("original/input/{index}")).unwrap(),
                    sequence: U64::new(17 + index as u64),
                    publication: Position::new(
                        U64::new(if index == 0 { 10 } else { 50_000 }),
                        0.into(),
                        Phase::Publication,
                    ),
                    payload: InputPayload {
                        reference: canonical::content_ref(&bytes, "application/octet-stream")
                            .unwrap(),
                        bytes,
                    },
                }
            })
            .collect(),
    };
    write_json(&source_path, &source);
    let source_reference =
        canonical::content_ref(&fs::read(&source_path).unwrap(), "application/json").unwrap();
    fs::write(&base_path, vec![0xab; 4096]).unwrap();
    let base_reference =
        canonical::content_ref(&fs::read(&base_path).unwrap(), "application/octet-stream").unwrap();
    let selections = vec![InstalledNodeSelection {
        node,
        owner: Id::new("disk-owner").unwrap(),
        kind: InstalledNodeKind::HostRecordedBlock {
            profile: InstalledRecordedIngressProfile {
                source: source_reference.clone(),
                configuration: configuration.clone(),
                storage: InstalledHostIoProfile::Block {
                    base_image: base_reference.clone(),
                    source_node: 7,
                    read_ns: 1.into(),
                    write_ns: 1.into(),
                    flush_ns: 1.into(),
                    get_length_ns: 1.into(),
                    per_byte_ns: 1.into(),
                },
            },
        },
    }];
    write_json(&selections_path, &selections);
    write_json(&configuration_path, &configuration);
    let companion = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    // Independent fixture measurements enroll fixed source-built artifacts in
    // local operator policy. Remote selections contain references, never paths.
    let expected_device =
        canonical::content_ref(&fs::read(&companion).unwrap(), "application/octet-stream").unwrap();
    write_json(
        &policy,
        &json!({
            "format":"crucible.node-daemon-policy", "version":1,
            "state_directory":state, "socket":socket,
            "device_executable":companion, "expected_device":expected_device,
            "control_timeout_ms":3000, "maximum_worlds":2, "maximum_pending_requests":4,
            "immutable_artifacts":[
                {"path":source_path,"expected":source_reference},
                {"path":base_path,"expected":base_reference}
            ]
        }),
    );
    let daemon = launch(&policy, &socket);
    let socket = socket.to_str().unwrap();
    let selected = selections_path.to_str().unwrap();
    let scenario = scenario_path.to_str().unwrap();
    let configured = configuration_path.to_str().unwrap();
    assert!(
        cli(&[
            "node",
            "compile",
            "--socket",
            socket,
            "--selections",
            selected,
            "--output",
            scenario
        ])
        .status
        .success()
    );
    let original_scenario = fs::read(&scenario_path).unwrap();
    let execution = "94949494949494949494949494949494";
    let observe = [
        "node",
        "observe",
        "--socket",
        socket,
        "--ledger",
        "recorded-originals",
        "--execution",
        execution,
        "--selections",
        selected,
        "--scenario",
        scenario,
        "--configuration",
        configured,
    ];
    let _original_admission = successful(&observe);
    let completed = completed_original(socket, execution);
    assert_eq!(completed["outcome"], "completed");

    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "node-observations",
        state.join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(DirectoryRefBackend::new(state.join("refs")));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let retained = repository
        .observed_execution_state(ExecutionId::from_bytes([148; 16]).unwrap())
        .unwrap()
        .unwrap();
    let ObservedAttemptState::Completed(result) = &retained else {
        panic!("original queued result missing");
    };
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let input_bytes = blobs
        .read(result.request().inputs(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let inputs: Value = serde_json::from_slice(&input_bytes).unwrap();
    assert_eq!(inputs["version"], 2);
    assert_eq!(
        inputs["external_inputs"][0]["original_objects"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let outgoing = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let outgoing: Value = serde_json::from_slice(&outgoing).unwrap();
    let outcomes: Vec<OperationOutcome> =
        serde_json::from_value(outgoing["events"].clone()).unwrap();
    let responses: Vec<_> = outcomes
        .iter()
        .flat_map(|outcome| &outcome.scheduling.as_ref().unwrap().publications)
        .map(|publication| BlockResponse::decode(&publication.payload_bytes).unwrap())
        .collect();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].request_id, 101);
    assert_eq!(responses[0].data, 4096_u64.to_le_bytes());
    assert_eq!(responses[1].request_id, 102);
    assert_eq!(responses[1].data, vec![0xab; 3]);
    let evidence = blobs
        .read(result.evidence(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let evidence: Value = serde_json::from_slice(&evidence).unwrap();
    let initial = evidence["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["format"] == "crucible.recorded-input-initial-boundary")
        .unwrap();
    assert_eq!(initial["objects"].as_array().unwrap().len(), 8);
    let original_inputs = initial["observation"]["external_inputs"][0]["inputs"]
        .as_array()
        .unwrap();
    assert_eq!(original_inputs.len(), 2);
    assert_eq!(original_inputs[0]["event_id"], "original/input/0");
    assert_eq!(original_inputs[0]["native_sequence"], "17");
    assert_eq!(original_inputs[1]["event_id"], "original/input/1");
    assert_eq!(original_inputs[1]["native_sequence"], "18");

    assert_eq!(successful(&observe), completed);
    let mut changed = configuration.clone();
    changed.maximum_rounds = 63.into();
    write_json(&configuration_path, &changed);
    assert!(
        !cli(&observe).status.success(),
        "original nonce admitted a changed source-bound run"
    );
    assert_eq!(completed_original(socket, execution), completed);
    write_json(&configuration_path, &configuration);

    // Removing original installation files cannot mint a new source cursor.
    // Status retrieval remains independent of re-admission or redispatch.
    fs::remove_file(&source_path).unwrap();
    fs::remove_file(&base_path).unwrap();
    assert!(!cli(&observe).status.success());
    assert_eq!(completed_original(socket, execution), completed);
    let activation_name = RefName::new(format!("node-world-activations/{execution}")).unwrap();
    let original_activation = refs.read_ref(&activation_name).unwrap().unwrap();
    drop(daemon);

    // Explicit archive-only enrollment permits original record inspection. It
    // grants no recorded-input native construction, capture or continuation.
    let mut inspection_policy: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
    inspection_policy["version"] = json!(2);
    inspection_policy["maximum_host_state_worlds"] = json!(2);
    inspection_policy["immutable_artifacts"] = json!([
        {"mode":"archive_only","expected":source_reference},
        {"mode":"archive_only","expected":base_reference}
    ]);
    write_json(&policy, &inspection_policy);
    let _restarted = launch(&policy, &state.join("node.sock"));
    assert_eq!(completed_original(socket, execution), completed);
    assert!(!cli(&observe).status.success());
    assert_eq!(
        refs.read_ref(&activation_name).unwrap(),
        Some(original_activation)
    );
    assert_eq!(fs::read(&scenario_path).unwrap(), original_scenario);
    assert_eq!(
        repository
            .observed_execution_state(ExecutionId::from_bytes([148; 16]).unwrap())
            .unwrap()
            .unwrap(),
        retained
    );
}
