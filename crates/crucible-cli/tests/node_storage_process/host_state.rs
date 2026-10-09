//! Actual dirty-storage continuation after original daemon and source files retire.

use super::*;

use crucible_core::node_state::{HostArchive, StateLimits};
use crucible_node_contract::ContentRef;

fn exact_terminal(socket: &Path, execution: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let record = successful(&[
            "node",
            "state-status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]);
        if record["state"]["status"] != "reserved" {
            return record;
        }
        assert!(
            Instant::now() < deadline,
            "actual exact storage stayed unresolved"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn captured_disk(state: &Path, completed: &Value) -> Value {
    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let archive = HostArchive::open(state.join("host-state-archives"), limits).unwrap();
    let artifact: ContentRef =
        serde_json::from_value(completed["state"]["artifact"].clone()).unwrap();
    let record = archive.load(&artifact).unwrap();
    let owner = record
        .manifest()
        .owners
        .iter()
        .find(|owner| owner.capture_owner_id.as_str() == "disk-owner")
        .unwrap();
    serde_json::from_slice(
        &record
            .content_bytes(owner.state_ref.as_ref().unwrap(), 16 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap()
}

fn original_outputs(disk: &Value) -> Vec<crucible_core::node_scheduling::NativePublication> {
    let mut outputs = Vec::new();
    for original in disk["operations"].as_array().unwrap() {
        let outcome: OperationOutcome =
            serde_json::from_value(original["outcome"].clone()).unwrap();
        if let Some(observation) = outcome.scheduling {
            outputs.extend(observation.publications);
        }
    }
    outputs.sort_by_key(|output| output.native_sequence);
    outputs
}

fn assert_fresh_input_authority(original: &mut Value, restored: &Value, source: &Value) {
    let old_ack = &original["acknowledgement"];
    let new_ack = &restored["acknowledgement"];
    let old_owners = old_ack["owners"].as_array().unwrap();
    let new_owners = new_ack["owners"].as_array().unwrap();
    assert_eq!(old_owners.len(), new_owners.len());
    for (old_owner, new_owner) in old_owners.iter().zip(new_owners) {
        assert_eq!(new_owner["owner"], old_owner["owner"]);
        assert_ne!(new_owner["incarnation"], old_owner["incarnation"]);
        let old_generation: u64 = old_owner["generation"].as_str().unwrap().parse().unwrap();
        let new_generation: u64 = new_owner["generation"].as_str().unwrap().parse().unwrap();
        assert_eq!(new_generation, old_generation + 1);
    }

    let body = &restored["acknowledgement_body"];
    let reference: ContentRef = serde_json::from_value(body["reference"].clone()).unwrap();
    let bytes: Vec<u8> = serde_json::from_value(body["bytes"].clone()).unwrap();
    reference.verify(&bytes).unwrap();
    assert_eq!(new_ack["proof_ref"], body["reference"]);
    let proof: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(proof["original_acknowledgement"], old_ack["proof_ref"]);
    assert_eq!(proof["source_capture"], *source);
    assert_eq!(proof["owners"], new_ack["owners"]);
    assert_eq!(proof["generation"], "2");
    assert_eq!(proof["node"], "disk");
    for field in ["stage_operation", "batch", "cutoff", "inventory"] {
        assert_eq!(proof[field], old_ack[field]);
        assert_eq!(new_ack[field], old_ack[field]);
    }

    // Fresh physical custody needs fresh authorization. Its immutable proof
    // pins the exact original ACK; every input/model/operation field is compared
    // unchanged below, independently of the new owner incarnation.
    let mut expected_ack = old_ack.clone();
    expected_ack["owners"] = new_ack["owners"].clone();
    expected_ack["proof_ref"] = new_ack["proof_ref"].clone();
    assert!(
        expected_ack == *new_ack,
        "fresh ACK changed its original scope"
    );
    original["acknowledgement"] = new_ack.clone();
    original["acknowledgement_body"] = body.clone();
    assert!(
        *original == *restored,
        "restoration changed an original input, consumption prefix, or custody identity"
    );
}

fn assert_unchanged_native_state(original: &Value, restored: &Value, source: &Value) {
    let mut expected = original.clone();
    let history = expected["input_history"].as_array_mut().unwrap();
    let restored_history = restored["input_history"].as_array().unwrap();
    assert_eq!(history.len(), restored_history.len());
    for (old_input, new_input) in history.iter_mut().zip(restored_history) {
        assert_fresh_input_authority(old_input, new_input, source);
    }
    if !expected["staged"].is_null() {
        assert_fresh_input_authority(&mut expected["staged"], &restored["staged"], source);
    }

    // The stopped original operations acquire the same fresh physical owner
    // route as their input authorizations. Their requests, scheduling facts,
    // proofs and immutable original receipt bodies remain byte-for-byte equal.
    let fresh_owners = &restored["staged"]["acknowledgement"]["owners"];
    assert!(fresh_owners.is_array());
    let original_operations = expected["operations"].as_array_mut().unwrap();
    let restored_operations = restored["operations"].as_array().unwrap();
    assert_eq!(original_operations.len(), restored_operations.len());
    for (old_operation, new_operation) in original_operations.iter_mut().zip(restored_operations) {
        let old_owners = old_operation["outcome"]["owners"].as_array().unwrap();
        let new_owners = new_operation["outcome"]["owners"].as_array().unwrap();
        assert_eq!(new_operation["outcome"]["owners"], *fresh_owners);
        assert_eq!(old_owners.len(), new_owners.len());
        for (old_owner, new_owner) in old_owners.iter().zip(new_owners) {
            assert_eq!(old_owner["owner"], new_owner["owner"]);
            assert_ne!(old_owner["incarnation"], new_owner["incarnation"]);
            let original_generation: u64 =
                old_owner["generation"].as_str().unwrap().parse().unwrap();
            let restored_generation: u64 =
                new_owner["generation"].as_str().unwrap().parse().unwrap();
            assert_eq!(restored_generation, original_generation + 1);
        }
        old_operation["outcome"]["owners"] = fresh_owners.clone();
        if !old_operation["outcome"]["scheduling"].is_null() {
            assert_eq!(
                new_operation["outcome"]["scheduling"]["owners"],
                *fresh_owners
            );
            old_operation["outcome"]["scheduling"]["owners"] = fresh_owners.clone();
        }
    }
    assert!(
        expected == *restored,
        "unchanged cut changed native model bytes, original operations, pending causes or sequences"
    );
}

#[test]
#[ignore = "requires actual companion and qualified connected exact-storage capture"]
fn actual_cli_restores_dirty_storage_and_original_pending_reply_without_source_paths() {
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path();
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = state.join("node.sock");
    let policy = state.join("policy.json");
    let selections = state.join("selections.json");
    let scenario = state.join("scenario.json");
    let source = state.join("captured.json");
    let unchanged = state.join("unchanged.json");
    let base_path = state.join("base.img");
    let script_path = state.join("requests.bin");
    let base = vec![0xab; 4096];
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(101, 0, vec![7, 8, 9]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 50_000,
                payload: BlockRequest::read(102, 0, 3).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    fs::write(&base_path, &base).unwrap();
    fs::write(&script_path, &script).unwrap();
    let reference =
        |bytes: &[u8]| canonical::content_ref(bytes, "application/octet-stream").unwrap();
    let mut installed = json!({
        "format":"crucible.node-daemon-policy", "version":2, "state_directory":state,
        "socket":socket,"device_executable":device,"expected_device":reference(&fs::read(&device).unwrap()),
        "control_timeout_ms":3000,"maximum_worlds":2,"maximum_host_state_worlds":2,"maximum_pending_requests":4,
        "immutable_artifacts":[{"path":base_path,"expected":reference(&base)},{"path":script_path,"expected":reference(&script)}]
    });
    fs::write(&policy, serde_json::to_vec(&installed).unwrap()).unwrap();
    fs::write(&selections, serde_json::to_vec(&json!([
        {"node":"disk","owner":"disk-owner","kind":{"implementation":"host_io","profile":{
            "kind":"block","base_image":reference(&base),"source_node":7,
            "read_ns":"1","write_ns":"1","flush_ns":"1","get_length_ns":"1","per_byte_ns":"1"}}},
        {"node":"source","owner":"source-owner","kind":{"implementation":"host_scripted","profile":{
            "script":reference(&script),"consumer":"disk"}}}
    ])).unwrap()).unwrap();
    let daemon = Daemon::start(&policy, &socket);
    let compiled = cli(&[
        "node",
        "compile",
        "--socket",
        socket.to_str().unwrap(),
        "--selections",
        selections.to_str().unwrap(),
        "--output",
        scenario.to_str().unwrap(),
    ]);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let original_nonce = "61616161616161616161616161616161";
    let capture = [
        "node",
        "capture",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        original_nonce,
        "--selections",
        selections.to_str().unwrap(),
        "--scenario",
        scenario.to_str().unwrap(),
        "--horizon-ps",
        "11",
    ];
    successful(&capture);
    let captured = exact_terminal(&socket, original_nonce);
    assert_eq!(captured["state"]["status"], "completed", "{captured}");
    let disk = captured_disk(state, &captured);
    assert_eq!(disk["pending_causes"].as_array().unwrap().len(), 1);
    let original_inputs = disk["input_history"]
        .as_array()
        .unwrap()
        .iter()
        .chain(disk.get("staged").filter(|input| !input.is_null()));
    let consumed: u64 = original_inputs
        .map(|input| input["consumed"].as_str().unwrap().parse::<u64>().unwrap())
        .sum();
    assert_eq!(consumed, 1, "the original write is consumed exactly once");
    assert!(
        original_outputs(&disk).is_empty(),
        "delayed reply must still be pending"
    );
    assert_eq!(
        fs::read(&base_path).unwrap(),
        base,
        "dirty bytes stay in native COW state"
    );
    fs::write(&source, serde_json::to_vec(&captured).unwrap()).unwrap();
    drop(daemon);

    // Archive-only is explicit independent operator policy; absent paths never fall back.
    fs::remove_file(&base_path).unwrap();
    fs::remove_file(&script_path).unwrap();
    installed["immutable_artifacts"] = json!([
        {"mode":"archive_only","expected":reference(&base)},
        {"mode":"archive_only","expected":reference(&script)}
    ]);
    fs::write(&policy, serde_json::to_vec(&installed).unwrap()).unwrap();
    let daemon = Daemon::start(&policy, &socket);
    assert_eq!(
        successful(&capture),
        captured,
        "original request is only an authenticated read"
    );
    let restored_nonce = "62626262626262626262626262626262";
    successful(&[
        "node",
        "restore",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        restored_nonce,
        "--selections",
        selections.to_str().unwrap(),
        "--scenario",
        scenario.to_str().unwrap(),
        "--source",
        source.to_str().unwrap(),
        "--horizon-ps",
        "11",
    ]);
    let restored = exact_terminal(&socket, restored_nonce);
    assert_eq!(restored["state"]["status"], "completed", "{restored}");
    assert_eq!(
        restored["state"]["manifest"]["cut"],
        captured["state"]["manifest"]["cut"]
    );
    assert_eq!(
        restored["state"]["manifest"]["event_ordinal"],
        captured["state"]["manifest"]["event_ordinal"]
    );
    let native_source = captured["state"]["manifest"]["owners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|owner| owner["capture_owner_id"] == "disk-owner")
        .unwrap()["state_ref"]
        .clone();
    assert_unchanged_native_state(&disk, &captured_disk(state, &restored), &native_source);
    fs::write(&unchanged, serde_json::to_vec(&restored).unwrap()).unwrap();
    drop(daemon);

    let daemon = Daemon::start(&policy, &socket);
    let mut sibling_outputs = None;
    for (nonce, parent) in [
        ("63636363636363636363636363636363", source.as_path()),
        ("64646464646464646464646464646464", unchanged.as_path()),
    ] {
        successful(&[
            "node",
            "restore",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            nonce,
            "--selections",
            selections.to_str().unwrap(),
            "--scenario",
            scenario.to_str().unwrap(),
            "--source",
            parent.to_str().unwrap(),
            "--horizon-ps",
            "200000",
        ]);
        let completed = exact_terminal(&socket, nonce);
        assert_eq!(completed["state"]["status"], "completed", "{completed}");
        let outputs = original_outputs(&captured_disk(state, &completed));
        assert_eq!(outputs.len(), 2, "original write must publish exactly once");
        let responses: Vec<_> = outputs
            .iter()
            .map(|output| {
                output.payload.verify(&output.payload_bytes).unwrap();
                assert_eq!(output.causal_parents.len(), 1);
                BlockResponse::decode(&output.payload_bytes).unwrap()
            })
            .collect();
        assert_eq!(responses[0].request_id, 101);
        assert_eq!(responses[1].request_id, 102);
        assert_eq!(
            responses[1].data,
            vec![7, 8, 9],
            "continued read sees captured dirty COW bytes"
        );
        assert_eq!(outputs[0].native_sequence.get(), 0);
        assert_eq!(outputs[1].native_sequence.get(), 1);

        // Newly executed publications use the new operation nonce. Their
        // simulated timing, native sequence and complete content must agree
        // across both authenticated restoration lineages.
        let semantics: Vec<_> = outputs
            .iter()
            .map(|output| {
                json!({
                    "endpoint": output.endpoint,
                    "native_sequence": output.native_sequence,
                    "publication": output.publication,
                    "evaluation": output.evaluation,
                    "causal_parents": output.causal_parents,
                    "payload": output.payload,
                    "payload_bytes": output.payload_bytes,
                })
            })
            .collect();
        if let Some(original) = &sibling_outputs {
            assert_eq!(
                &semantics, original,
                "cold siblings changed semantic outputs"
            );
        } else {
            sibling_outputs = Some(semantics);
        }
    }
    let fresh_nonce = "65656565656565656565656565656565";
    successful(&[
        "node",
        "capture",
        "--socket",
        socket.to_str().unwrap(),
        "--execution",
        fresh_nonce,
        "--selections",
        selections.to_str().unwrap(),
        "--scenario",
        scenario.to_str().unwrap(),
        "--horizon-ps",
        "11",
    ]);
    assert_eq!(
        exact_terminal(&socket, fresh_nonce)["state"]["status"],
        "refused",
        "archive-only source cannot construct a fresh native world"
    );
    let refs = DirectoryRefBackend::new(state.join("refs"));
    assert!(
        refs.read_ref(
            &RefName::new(format!("node-world-activations/state-{fresh_nonce}")).unwrap()
        )
        .unwrap()
        .is_none()
    );
    drop(daemon);
    assert!(!base_path.exists());
    assert!(!script_path.exists());
}
