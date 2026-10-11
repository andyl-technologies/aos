//! Exercises the ordinary complete-owner operator route without borrowing native7.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Original source, signed archives and genuine process assertions deliberately fail this fixture.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow clippy-disallowed-method -- Absolute operational watchdogs observe one original service and never replay failed native work.
#![allow(clippy::disallowed_methods)]

use super::*;
use crucible_core::{
    node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource},
    node_contract::{RuntimeSnapshot, SavedRuntimeResult},
    node_scheduling::NativePublication,
    node_state::NativeArchiveRecord,
};
use crucible_device::{BlockRequest, BlockResponse, BlockStatus};
use crucible_node_contract::{ContentRef, Id};

struct OriginalService {
    child: Child,
    stopping: bool,
}

impl OriginalService {
    fn start(policy: &Path, socket: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_crucible"))
            .args(["node", "serve", "--policy", policy.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut original = Self {
            child,
            stopping: false,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while !socket.exists() {
            assert!(original.child.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        original
    }

    fn retire(&mut self) {
        if !self.stopping && self.child.try_wait().unwrap().is_none() {
            let pid = rustix::process::Pid::from_raw(self.child.id() as i32).unwrap();
            rustix::process::kill_process(pid, rustix::process::Signal::INT).unwrap();
            self.stopping = true;
        }
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            assert!(
                Instant::now() < deadline,
                "owning service retained unresolved original work"
            );
            std::thread::yield_now();
        }
    }
}

impl Drop for OriginalService {
    fn drop(&mut self) {
        // Failure keeps this original Child and its owning native lanes alive.
        // Only the explicit successful retirement path requests service shutdown.
        while self.child.try_wait().ok().flatten().is_none() {
            std::thread::park_timeout(Duration::from_secs(1));
        }
    }
}

fn authored(directory: &Path) -> (Value, Value, Value) {
    let base_path = directory.join("original-base");
    let base = vec![0x11; 4096];
    fs::write(&base_path, &base).unwrap();
    let base_ref = canonical::content_ref(&base, "application/octet-stream").unwrap();
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(9, 0, vec![0x33; 512]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 1_000_000_000,
                payload: BlockRequest::read(10, 0, 512).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let script_path = directory.join("original-script");
    fs::write(&script_path, &script).unwrap();
    let script_ref = canonical::content_ref(&script, "application/octet-stream").unwrap();
    let selected = json!([
        {"node":"clock","owner":"owner/clock","kind":{"implementation":"host_clock"}},
        {"node":"cpu","owner":"owner/cpu","kind":{"implementation":"gem5_closed_preserving","isa":"x86_64"}},
        {"node":"disk-a","owner":"owner/disk-a","kind":{"implementation":"host_io","profile":{
            "kind":"block","base_image":base_ref,"source_node":17,
            "read_ns":"1","write_ns":"1","flush_ns":"1","get_length_ns":"1","per_byte_ns":"1"
        }}},
        {"node":"source-a","owner":"owner/source-a","kind":{"implementation":"host_scripted","profile":{
            "script":script_ref,"consumer":"disk-a"
        }}}
    ]);
    (
        selected,
        json!({"path":base_path,"expected":base_ref}),
        json!({"path":script_path,"expected":script_ref}),
    )
}

fn complete_demands(scenario: &NodeScenario) -> CapabilityRequirements {
    let mut nodes = Vec::new();
    for binding in &scenario.compatibility {
        let body = |reference: &ContentRef| {
            &scenario
                .content
                .iter()
                .find(|body| &body.reference == reference)
                .unwrap()
                .bytes
        };
        let capabilities: CapabilityProfile =
            serde_json::from_slice(body(&binding.capabilities_ref)).unwrap();
        let guarantee: GuaranteeProfile =
            serde_json::from_slice(body(&binding.guarantees_ref)).unwrap();
        let exact = if binding.node_id.as_str() == "cpu" {
            crucible_core::node_adapters::gem5::GEM5_CLOSED_EXACT_PROFILE
        } else {
            "host/exact-v1"
        };
        let preservation = match binding.node_id.as_str() {
            "cpu" => "gem5/public-process-preservation-v1",
            "clock" => crucible_core::node_adapters::HOST_PUBLIC_CLOCK_CONTINUATION_PROFILE,
            _ => crucible_core::node_adapters::HOST_PUBLIC_OWNED_MODEL_CONTINUATION_PROFILE,
        };
        let operations = ["boundary_settle", "capture", "durable_restart", "exact_run"]
            .into_iter()
            .map(|operation| {
                let id = if matches!(operation, "capture" | "durable_restart") {
                    preservation
                } else {
                    exact
                };
                OperationRequirement {
                    operation: Id::new(operation).unwrap(),
                    facet: capabilities
                        .facets
                        .iter()
                        .find(|facet| facet.id.as_str() == id)
                        .unwrap()
                        .clone(),
                }
            })
            .collect();
        nodes.push(NodeCapabilityRequirement {
            node: binding.node_id.clone(),
            roles: scenario
                .descriptors
                .iter()
                .find(|node| node.id == binding.node_id)
                .unwrap()
                .roles
                .clone(),
            timing: TimingRequirement {
                mode: binding.operating_contract.mode,
                resolution_ps: binding.operating_contract.resolution_ps,
                phase_ps: binding.operating_contract.phase_ps,
                policy_ref: binding.operating_contract.policy_ref.clone(),
            },
            operations,
            guarantees: GuaranteeRequirement {
                repeatability: guarantee.repeatability,
                capture_scope: guarantee.capture_scope,
                continuation: guarantee.continuation,
                durable_restart: true,
                isolated_fork: false,
                conditional_replay: false,
            },
            compute: None,
            extensions: Vec::new(),
        });
    }
    CapabilityRequirements {
        format: CAPABILITY_REQUIREMENTS_FORMAT.into(),
        schema_version: 1,
        nodes,
    }
}

fn wait_original(socket: &Path, execution: &str) -> CapabilityPreparationRecord {
    let deadline = Instant::now() + Duration::from_secs(1200);
    loop {
        let record: CapabilityPreparationRecord = serde_json::from_value(success(&[
            "node",
            "capability-status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]))
        .unwrap();
        if !matches!(
            record.outcome,
            CapabilityPreparationState::AwaitingAdmission {}
        ) {
            return record;
        }
        assert!(
            Instant::now() < deadline,
            "original complete native lane did not settle"
        );
        std::thread::yield_now();
    }
}

fn archive(state: &Path, record: &CapabilityPreparationRecord) -> NativeArchiveRecord {
    let CapabilityPreparationState::Native { artifact, .. } = &record.outcome else {
        panic!(
            "original complete native route refused: {:?}",
            record.outcome
        );
    };
    let mut limits = NativeArchiveLimits::default();
    limits.state.maximum_content_bytes = 512 * 1024 * 1024;
    limits.state.maximum_total_content_bytes = 2 * 1024 * 1024 * 1024;
    limits.state.maximum_record_bytes = 16 * 1024 * 1024;
    limits.native.maximum_objects = 20_000;
    limits.native.maximum_record_bytes = 16 * 1024 * 1024;
    limits.native.maximum_total_record_bytes = 64 * 1024 * 1024;
    limits.native.maximum_artifact_bytes = 2 * 1024 * 1024 * 1024;
    limits.native.maximum_total_artifact_bytes = 8 * 1024 * 1024 * 1024;
    NativeArchive::open(state.join("capability-clock-archive"), limits)
        .unwrap()
        .load(artifact)
        .unwrap()
}

fn preserve_prefix(original: &RuntimeSnapshot, fresh: &RuntimeSnapshot) {
    for saved in &original.operations {
        let current = fresh
            .operations
            .iter()
            .find(|operation| operation.operation == saved.operation)
            .unwrap();
        assert_eq!(current.request, saved.request);
        assert_eq!(current.scheduling_commit, saved.scheduling_commit);
        assert!(matches!(
            current.result,
            SavedRuntimeResult::Acknowledged(_)
        ));
    }
    for saved in &original.inputs {
        let current = fresh
            .inputs
            .iter()
            .find(|input| input.batch == saved.batch)
            .unwrap();
        assert_eq!(current.inventory, saved.inventory);
        assert_eq!(current.deliveries, saved.deliveries);
        assert_eq!(current.payloads, saved.payloads);
    }
}

fn suffix(record: &CapabilityPreparationRecord) -> Vec<(Id, NativePublication)> {
    let CapabilityPreparationState::Native { progress, .. } = &record.outcome else {
        panic!("no native suffix");
    };
    let publications: Vec<(Id, NativePublication)> =
        serde_json::from_slice(progress.as_slice()).unwrap();
    for (_, publication) in &publications {
        publication
            .payload
            .verify(&publication.payload_bytes)
            .unwrap();
    }
    let disk: Vec<_> = publications
        .iter()
        .filter(|(node, _)| node.as_str() == "disk-a")
        .map(|(_, publication)| publication)
        .collect();
    assert_eq!(disk.len(), 2);
    for (index, publication) in disk.iter().enumerate() {
        assert_eq!(publication.native_sequence.get(), index as u64);
        let response = BlockResponse::decode(&publication.payload_bytes).unwrap();
        assert_eq!(response.status, BlockStatus::Ok);
        assert_eq!(response.request_id, 9 + index as u32);
        if index == 1 {
            assert_eq!(response.data, vec![0x33; 512]);
        }
    }
    let cpu: Vec<_> = publications
        .iter()
        .filter(|(node, _)| node.as_str() == "cpu")
        .map(|(_, publication)| publication)
        .collect();
    assert_eq!(cpu.len(), 1);
    assert_eq!(cpu[0].payload_bytes, cpu_checksum());
    publications
}

fn cpu_checksum() -> Vec<u8> {
    // This independently executes the pinned SE guest's authored arithmetic.
    // The native source/profile qualification separately authenticates its ELF.
    let mut arena = vec![0_u64; 262_144 / 8];
    let mut state = 3_u32;
    let mut answer = 0_u64;
    for _ in 0..20_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let index = (state & 262_136) as usize / 8;
        arena[index] ^= u64::from(state);
        answer = answer.wrapping_add(arena[index]);
        if state & 1 != 0 {
            answer = answer.wrapping_add(19);
        }
    }
    answer.to_le_bytes().to_vec()
}

fn refuse_stronger_demands(
    socket: &Path,
    path: &Path,
    demands: &CapabilityRequirements,
    candidates: &Value,
) {
    let mut fork = demands.clone();
    fork.nodes[0].guarantees.isolated_fork = true;
    let unsupported = request(
        "44444444444444444444444444444444",
        &fork,
        candidates.clone(),
        json!({"operation":"capture"}),
        11,
    );
    submit(socket, path, &unsupported);
    let refused = wait_original(socket, "44444444444444444444444444444444");
    assert!(matches!(
        refused.outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));
    assert_eq!(
        serde_json::to_value(submit(socket, path, &unsupported)).unwrap(),
        serde_json::to_value(&refused).unwrap()
    );

    let mut foreign = demands.clone();
    let cpu = foreign
        .nodes
        .iter_mut()
        .find(|node| node.node.as_str() == "cpu")
        .unwrap();
    let capture = cpu
        .operations
        .iter_mut()
        .find(|operation| operation.operation.as_str() == "capture")
        .unwrap();
    capture.facet.id = Id::new("foreign/preservation-v1").unwrap();
    let unsupported = request(
        "45454545454545454545454545454545",
        &foreign,
        candidates.clone(),
        json!({"operation":"capture"}),
        11,
    );
    submit(socket, path, &unsupported);
    let refused = wait_original(socket, "45454545454545454545454545454545");
    assert!(matches!(
        refused.outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));
    assert_eq!(
        serde_json::to_value(submit(socket, path, &unsupported)).unwrap(),
        serde_json::to_value(&refused).unwrap()
    );

    let mut unsupported_roster = candidates.clone();
    let cpu = unsupported_roster[0]["selections"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|selection| selection["node"] == "cpu")
        .unwrap();
    cpu["kind"]["isa"] = json!("aarch64");
    let unsupported = request(
        "46464646464646464646464646464646",
        demands,
        unsupported_roster,
        json!({"operation":"capture"}),
        11,
    );
    submit(socket, path, &unsupported);
    let refused = wait_original(socket, "46464646464646464646464646464646");
    assert!(matches!(
        refused.outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));
    assert_eq!(
        serde_json::to_value(submit(socket, path, &unsupported)).unwrap(),
        serde_json::to_value(&refused).unwrap()
    );
}

#[test]
#[ignore = "requires genuine source-built SE profile, actual CLI and owning four-owner source-gone Capture/Continue; retains failures without force killing"]
fn ordinary_signed_capture_and_two_source_gone_continues_keep_original_history() {
    let root = tempfile::Builder::new()
        .prefix("gem5-capability-preserving-")
        .tempdir()
        .unwrap()
        .keep();
    eprintln!("original ordinary preserving custody: {}", root.display());
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let state = root.join("state");
    let (policy_path, socket) = policy(&state, &device);
    let (selections, base, script) = authored(&root);
    let mut installed: Value = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    installed["immutable_artifacts"] = json!([base, script]);
    fs::write(&policy_path, serde_json::to_vec(&installed).unwrap()).unwrap();
    let mut source_service = OriginalService::start(&policy_path, &socket);
    let selected = root.join("selections.json");
    let baseline = root.join("baseline.json");
    fs::write(&selected, serde_json::to_vec(&selections).unwrap()).unwrap();
    let compiled = cli(&[
        "node",
        "compile",
        "--socket",
        socket.to_str().unwrap(),
        "--selections",
        selected.to_str().unwrap(),
        "--output",
        baseline.to_str().unwrap(),
    ]);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let baseline = NodeScenario::from_json(&fs::read(&baseline).unwrap()).unwrap();
    let demands = complete_demands(&baseline);
    let candidates = json!([{"id":"complete-four-owners","selections":selections}]);
    let request_path = root.join("request.json");
    refuse_stronger_demands(&socket, &request_path, &demands, &candidates);
    let mut capture = request(
        "41414141414141414141414141414141",
        &demands,
        candidates.clone(),
        json!({"operation":"capture"}),
        11,
    );
    capture["configuration"] = serde_json::to_value(Bytes::new(serde_json::to_vec(&json!({
        "format":"crucible.node-run-configuration","version":1,"horizon_ps":"11","maximum_rounds":"128"
    })).unwrap())).unwrap();
    submit(&socket, &request_path, &capture);
    let captured = wait_original(&socket, "41414141414141414141414141414141");
    let source = archive(&state, &captured);
    let original = source.runtime_snapshot().unwrap();
    assert_eq!(source.owners().len(), 4);
    assert_eq!(original.source_activation.owners.len(), 4);
    assert_eq!(
        serde_json::to_value(submit(&socket, &request_path, &capture)).unwrap(),
        serde_json::to_value(&captured).unwrap()
    );
    fs::write(
        root.join("source-runtime.json"),
        serde_json::to_vec(&original).unwrap(),
    )
    .unwrap();
    source_service.retire();

    fs::remove_file(base["path"].as_str().unwrap()).unwrap();
    fs::remove_file(script["path"].as_str().unwrap()).unwrap();
    assert!(!Path::new(base["path"].as_str().unwrap()).exists());
    assert!(!Path::new(script["path"].as_str().unwrap()).exists());
    installed["version"] = json!(2);
    installed["maximum_host_state_worlds"] = json!(4);
    installed["immutable_artifacts"] = json!([
        {"mode":"archive_only","expected":base["expected"]},
        {"mode":"archive_only","expected":script["expected"]}
    ]);
    fs::write(&policy_path, serde_json::to_vec(&installed).unwrap()).unwrap();
    let mut fresh_service = OriginalService::start(&policy_path, &socket);
    assert_eq!(
        wait_original(&socket, "41414141414141414141414141414141").request,
        captured.request
    );
    let mut results = Vec::new();
    for (name, execution) in [
        ("left", "42424242424242424242424242424242"),
        ("right", "43434343434343434343434343434343"),
    ] {
        let mut continuation = request(
            execution,
            &demands,
            candidates.clone(),
            json!({"operation":"continue","source":source.artifact()}),
            2_000_000_000,
        );
        continuation["configuration"] = serde_json::to_value(Bytes::new(serde_json::to_vec(&json!({
            "format":"crucible.node-run-configuration","version":1,"horizon_ps":"2000000000","maximum_rounds":"128"
        })).unwrap())).unwrap();
        submit(&socket, &request_path, &continuation);
        let completed = wait_original(&socket, execution);
        let reopened = archive(&state, &completed);
        let runtime = reopened.runtime_snapshot().unwrap();
        preserve_prefix(&original, &runtime);
        assert_ne!(
            runtime.source_activation.activation_id,
            original.source_activation.activation_id
        );
        let publications = suffix(&completed);
        fs::write(
            root.join(format!("{name}-runtime.json")),
            serde_json::to_vec(&runtime).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join(format!("{name}-suffix.json")),
            serde_json::to_vec(&publications).unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(submit(&socket, &request_path, &continuation)).unwrap(),
            serde_json::to_value(&completed).unwrap()
        );
        results.push((runtime, publications));
    }
    assert_ne!(
        results[0].0.source_activation,
        results[1].0.source_activation
    );
    let semantic = |rows: &[(Id, NativePublication)]| {
        rows.iter()
            .map(|(node, publication)| {
                (
                    node.clone(),
                    publication.endpoint.clone(),
                    publication.native_sequence,
                    publication.publication,
                    publication.evaluation,
                    publication.causal_parents.clone(),
                    publication.payload.clone(),
                    publication.payload_bytes.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(semantic(&results[0].1), semantic(&results[1].1));
    // Fresh operation/publication identities are retained in the raw evidence;
    // only semantic suffix fields are compared across different current owners.
    fresh_service.retire();
}
