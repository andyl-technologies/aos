//! Verifies a complete authored Clock and independent Script/Block world.
//!
//! The actual CLI actor independently enrolls immutable sources and base bytes,
//! admits every raw demand, publishes one all-owner barrier and executes both
//! native Block groups. Model-only construction cannot supply this evidence.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Original source, complete activation and independent native response assertions deliberately fail this process fixture.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_campaign::{
    CampaignRepository, ExecutionId,
    observed_node_attempt::{ObservedAttemptOutcome, ObservedAttemptState},
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};
use crucible_core::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};
use crucible_device::{BlockRequest, BlockResponse, BlockStatus};
use std::sync::Arc;

fn complete_demands(scenario: &NodeScenario) -> CapabilityRequirements {
    let mut nodes = Vec::new();
    for binding in &scenario.compatibility {
        let body = |reference: &crucible_node_contract::ContentRef| {
            &scenario
                .content
                .iter()
                .find(|body| &body.reference == reference)
                .unwrap()
                .bytes
        };
        let capabilities: CapabilityProfile =
            serde_json::from_slice(body(&binding.capabilities_ref)).unwrap();
        let guarantees: GuaranteeProfile =
            serde_json::from_slice(body(&binding.guarantees_ref)).unwrap();
        let facet = capabilities
            .facets
            .iter()
            .find(|facet| facet.id.as_str() == "host/exact-v1")
            .unwrap();

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
            operations: ["boundary_settle", "exact_run"]
                .into_iter()
                .map(|operation| OperationRequirement {
                    operation: crucible_node_contract::Id::new(operation).unwrap(),
                    facet: facet.clone(),
                })
                .collect(),
            guarantees: GuaranteeRequirement {
                repeatability: guarantees.repeatability,
                capture_scope: guarantees.capture_scope,
                continuation: guarantees.continuation,
                durable_restart: false,
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

fn enrolled(path: &Path, bytes: &[u8]) -> Value {
    fs::write(path, bytes).unwrap();
    json!({"path":path,"expected":canonical::content_ref(bytes,"application/octet-stream").unwrap()})
}

fn block_selection(node: &str, source_node: u32, base: &Value) -> Value {
    json!({
        "node":node,"owner":format!("owner/{node}"),
        "kind":{"implementation":"host_io","profile":{
            "kind":"block","base_image":base["expected"],"source_node":source_node,
            "read_ns":"1","write_ns":"1","flush_ns":"1","get_length_ns":"1","per_byte_ns":"1"
        }}
    })
}

fn source_selection(directory: &Path, name: &str, consumer: &str, pattern: u8) -> (Value, Value) {
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(9, 0, vec![pattern; 512])
                    .encode()
                    .unwrap(),
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
    let artifact = enrolled(&directory.join(format!("{name}.script")), &script);
    let selection = json!({
        "node":name,"owner":format!("owner/{name}"),
        "kind":{"implementation":"host_scripted","profile":{"script":artifact["expected"],"consumer":consumer}}
    });
    (selection, artifact)
}

// crucible-lint: allow clippy-disallowed-method -- One original actor/status watchdog bounds host waiting and never retries failed native work.
// crucible-lint: allow rust-allow -- Operational expiry does not determine modeled time or grant an execution permit.
#[allow(
    clippy::disallowed_methods,
    reason = "Original CLI actor completion has one absolute host watchdog"
)]
fn await_original(socket: &Path, execution: &str, capability: bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let record = success(&[
            "node",
            if capability {
                "capability-status"
            } else {
                "status"
            },
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution,
        ]);
        assert!(
            Instant::now() < deadline,
            "original source-selected execution exceeded watchdog"
        );
        if if capability {
            record["outcome"]["state"] != "awaiting_admission"
        } else {
            record["status"] != "reserved"
        } {
            return record;
        }
        std::thread::yield_now();
    }
}

struct OriginalService {
    child: Child,
    stopping: bool,
}

impl OriginalService {
    // crucible-lint: allow clippy-disallowed-method -- One original process startup is bounded without replacing the service or native work.
    // crucible-lint: allow rust-allow -- Host expiry is only an operational diagnostic.
    #[allow(
        clippy::disallowed_methods,
        reason = "Original owning service must publish its endpoint before control"
    )]
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

    fn stop(&mut self) {
        if self.stopping || matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        self.stopping = true;
        let pid = rustix::process::Pid::from_raw(self.child.id() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::INT).unwrap();
    }
}

impl Drop for OriginalService {
    fn drop(&mut self) {
        self.stop();
        loop {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::yield_now();
        }
    }
}

#[test]
#[ignore = "requires actual source-built owning CLI/daemon and independently installed Host artifacts"]
fn authored_five_owner_roster_keeps_two_native_block_groups_independent() {
    let directory = tempfile::tempdir().unwrap().keep();
    eprintln!("original five-owner Host roster: {}", directory.display());
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let (policy_path, socket) = policy(&directory, &device);
    let base_path = directory.join("shared-immutable-base");
    let base = enrolled(&base_path, &[0x11; 4096]);
    let (source_a, artifact_a) = source_selection(&directory, "source-a", "disk-a", 0x33);
    let (source_b, artifact_b) = source_selection(&directory, "source-b", "disk-b", 0x7c);
    let mut installed: Value = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    installed["immutable_artifacts"] = json!([base, artifact_a, artifact_b]);
    fs::write(&policy_path, serde_json::to_vec(&installed).unwrap()).unwrap();
    let mut service = OriginalService::start(&policy_path, &socket);
    let selections = json!([
        {"node":"clock","owner":"owner/clock","kind":{"implementation":"host_clock"}},
        block_selection("disk-a", 17, &base), block_selection("disk-b", 18, &base), source_a, source_b
    ]);
    let selections_path = directory.join("selections.json");
    fs::write(&selections_path, serde_json::to_vec(&selections).unwrap()).unwrap();
    let baseline_path = directory.join("baseline.json");
    let compiled = cli(&[
        "node",
        "compile",
        "--socket",
        socket.to_str().unwrap(),
        "--selections",
        selections_path.to_str().unwrap(),
        "--output",
        baseline_path.to_str().unwrap(),
    ]);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let baseline_bytes = fs::read(&baseline_path).unwrap();
    let baseline = NodeScenario::from_json(&baseline_bytes).unwrap();
    assert_eq!(baseline.owners.len(), 5);
    assert_eq!(baseline.world.connections.len(), 2);
    let demands = complete_demands(&baseline);
    let candidates = json!([{"id":"installed/independent-host-roster","selections":selections}]);
    let execution = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    let mut original = request(
        execution,
        &demands,
        candidates.clone(),
        json!({"operation":"observe"}),
        2_000_000_000,
    );
    original["configuration"] = serde_json::to_value(Bytes::new(serde_json::to_vec(&json!({
        "format":"crucible.node-run-configuration","version":1,"horizon_ps":"2000000000","maximum_rounds":"64"
    })).unwrap())).unwrap();
    fs::write(
        directory.join("original-authored-request.json"),
        serde_json::to_vec(&original).unwrap(),
    )
    .unwrap();
    let request_path = directory.join("request.json");
    submit(&socket, &request_path, &original);
    let admitted = await_original(&socket, execution, true);
    assert_eq!(admitted["outcome"]["state"], "admitted", "{admitted}");
    let completed = await_original(&socket, execution, false);
    assert_eq!(completed["status"], "completed", "{completed}");
    assert_eq!(completed["outcome"], "completed");
    assert_eq!(fs::read(&baseline_path).unwrap(), baseline_bytes);
    assert_eq!(
        serde_json::to_value(submit(&socket, &request_path, &original)).unwrap(),
        admitted
    );

    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "original-host-roster",
        directory.join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let repository = CampaignRepository::new(blobs.clone(), refs);
    let state = repository
        .observed_execution_state(ExecutionId::from_bytes([0xa1; 16]).unwrap())
        .unwrap()
        .unwrap();
    let ObservedAttemptState::Completed(result) = state else {
        panic!("original roster did not complete");
    };
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    assert_eq!(result.request().capabilities().roster().owners().len(), 5);
    let outgoing = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 << 20)
        .unwrap();
    fs::write(directory.join("original-outgoing.json"), &outgoing).unwrap();
    let outgoing: Value = serde_json::from_slice(&outgoing).unwrap();
    let outcomes = outgoing["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            serde_json::from_value::<crucible_core::node_contract::OperationOutcome>(row.clone())
                .unwrap()
        })
        .collect::<Vec<_>>();
    for node in ["clock", "disk-a", "disk-b", "source-a", "source-b"] {
        assert!(outcomes.iter().any(|outcome| outcome.node.as_str() == node));
    }
    for (disk, pattern) in [("disk-a", 0x33), ("disk-b", 0x7c)] {
        let responses = outcomes
            .iter()
            .flat_map(|outcome| outcome.scheduling.as_ref().unwrap().publications.iter())
            .filter(|publication| publication.endpoint.node_id.as_str() == disk)
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        for publication in &responses {
            publication
                .payload
                .verify(&publication.payload_bytes)
                .unwrap();
        }
        let write = BlockResponse::decode(&responses[0].payload_bytes).unwrap();
        let read = BlockResponse::decode(&responses[1].payload_bytes).unwrap();
        assert_eq!((write.request_id, write.status), (9, BlockStatus::Ok));
        assert_eq!((read.request_id, read.status), (10, BlockStatus::Ok));
        assert_eq!(read.data, vec![pattern; 512]);
        assert_ne!(responses[0].publication_id, responses[1].publication_id);
    }
    assert_eq!(fs::read(&base_path).unwrap(), vec![0x11; 4096]);

    for axis in 0..4 {
        let mut changed = demands.clone();
        match axis {
            0 => changed.nodes[1].operations[0].facet.version += 1,
            1 => changed.nodes[1].guarantees.durable_restart = true,
            2 => {
                changed.nodes[1].operations[1].operation =
                    crucible_node_contract::Id::new("physical_pause").unwrap()
            }
            _ => {
                changed.nodes.pop();
            }
        }
        let nonce = format!("{:032x}", 0xa2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2u128 + axis);
        let refused = request(
            &nonce,
            &changed,
            candidates.clone(),
            json!({"operation":"observe"}),
            2_000_000_000,
        );
        submit(&socket, &request_path, &refused);
        let refusal: CapabilityPreparationRecord =
            serde_json::from_value(await_original(&socket, &nonce, true)).unwrap();
        assert!(matches!(
            refusal.outcome,
            CapabilityPreparationState::Unavailable { .. }
        ));
    }
    assert_eq!(
        success(&[
            "node",
            "status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution
        ]),
        completed
    );
    // A valid existing backend selector cannot turn this authored Host graph
    // into a native CPU world, and an unimplemented selector stays closed.
    for (name, kind) in [
        (
            "foreign-gem5",
            json!({"implementation":"gem5_closed","isa":"x86_64"}),
        ),
        ("unimplemented-qemu", json!({"implementation":"qemu"})),
    ] {
        let mut foreign = selections.clone();
        foreign[1]["kind"] = kind;
        let path = directory.join(format!("{name}-selections.json"));
        fs::write(&path, serde_json::to_vec(&foreign).unwrap()).unwrap();
        let output = directory.join(format!("{name}-scenario.json"));
        let refused = cli(&[
            "node",
            "compile",
            "--socket",
            socket.to_str().unwrap(),
            "--selections",
            path.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert!(!refused.status.success());
        assert!(!output.exists());
    }

    let script_path = directory.join("source-a.script");
    let original_script = fs::read(&script_path).unwrap();
    fs::write(directory.join("original-source-a.script"), &original_script).unwrap();
    let mut changed_script = original_script;
    let last = changed_script.len() - 1;
    changed_script[last] ^= 1;
    fs::write(&script_path, changed_script).unwrap();
    let changed_artifact = request(
        "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
        &demands,
        candidates,
        json!({"operation":"observe"}),
        2_000_000_000,
    );
    submit(&socket, &request_path, &changed_artifact);
    let refusal: CapabilityPreparationRecord = serde_json::from_value(await_original(
        &socket,
        "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
        true,
    ))
    .unwrap();
    assert!(matches!(
        refusal.outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));
    assert_eq!(
        success(&[
            "node",
            "status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            execution
        ]),
        completed
    );

    service.stop();
    let status = service.child.wait().unwrap();
    assert!(status.success());
    assert!(!socket.exists());
}
