//! Exercises original authored capability custody through actual CLI/daemon processes.

#![cfg(target_os = "linux")]
// crucible-lint: allow panic-shortcut -- Actual process fixtures and independently checked archive invariants deliberately panic on a failed assertion.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// crucible-lint: allow clippy-disallowed-method -- Single-shot process fixtures poll one original operation under an absolute host deadline; no failed test is retried.
#![allow(clippy::disallowed_methods)]

use crucible_core::{
    node_admission::{
        CAPABILITY_REQUIREMENTS_FORMAT, CapabilityRequirements, GuaranteeRequirement,
        NodeCapabilityRequirement, OperationRequirement, TimingRequirement,
    },
    node_state::{NativeArchive, NativeArchiveLimits},
};
use crucible_daemon::{
    node_observed_executor::{CapabilityPreparationRecord, CapabilityPreparationState},
    node_scenario::NodeScenario,
};
use crucible_node_contract::{Bytes, CapabilityProfile, GuaranteeProfile, canonical};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(args)
        .output()
        .unwrap()
}

fn success(args: &[&str]) -> Value {
    let result = cli(args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

struct Daemon(Child);

impl Daemon {
    fn start(policy: &Path, socket: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_crucible"))
            .args(["node", "serve", "--policy", policy.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut daemon = Self(child);

        let deadline = Instant::now() + Duration::from_secs(20);
        while !socket.exists() {
            assert!(
                daemon.0.try_wait().unwrap().is_none(),
                "original daemon exited during installation"
            );
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }

        daemon
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::INT);
        }

        let deadline = Instant::now() + Duration::from_secs(30);
        while self.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}

fn policy(directory: &Path, device: &Path) -> (PathBuf, PathBuf) {
    fs::create_dir_all(directory).unwrap();
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();

    let socket = directory.join("control.sock");
    let path = directory.join("policy.json");
    let expected =
        canonical::content_ref(&fs::read(device).unwrap(), "application/octet-stream").unwrap();
    fs::write(
        &path,
        serde_json::to_vec(&json!({
            "format": "crucible.node-daemon-policy",
            "version": 1,
            "state_directory": directory,
            "socket": socket,
            "device_executable": device,
            "expected_device": expected,
            "control_timeout_ms": 3000,
            "maximum_worlds": 4,
            "maximum_pending_requests": 4
        }))
        .unwrap(),
    )
    .unwrap();

    (path, socket)
}

fn demands(scenario: &NodeScenario) -> CapabilityRequirements {
    let binding = &scenario.compatibility[0];
    let object = |reference| {
        &scenario
            .content
            .iter()
            .find(|item| &item.reference == reference)
            .unwrap()
            .bytes
    };
    let capability: CapabilityProfile =
        serde_json::from_slice(object(&binding.capabilities_ref)).unwrap();
    let guarantee: GuaranteeProfile =
        serde_json::from_slice(object(&binding.guarantees_ref)).unwrap();

    CapabilityRequirements {
        format: CAPABILITY_REQUIREMENTS_FORMAT.into(),
        schema_version: 1,
        nodes: vec![NodeCapabilityRequirement {
            node: binding.node_id.clone(),
            roles: scenario.descriptors[0].roles.clone(),
            timing: TimingRequirement {
                mode: binding.operating_contract.mode,
                resolution_ps: binding.operating_contract.resolution_ps,
                phase_ps: binding.operating_contract.phase_ps,
                policy_ref: binding.operating_contract.policy_ref.clone(),
            },
            operations: vec![OperationRequirement {
                operation: crucible_node_contract::Id::new("exact_run").unwrap(),
                facet: capability
                    .facets
                    .iter()
                    .find(|facet| facet.id.as_str() == "host/exact-v1")
                    .unwrap()
                    .clone(),
            }],
            guarantees: GuaranteeRequirement {
                repeatability: guarantee.repeatability,
                capture_scope: guarantee.capture_scope,
                continuation: guarantee.continuation,
                durable_restart: false,
                isolated_fork: false,
                conditional_replay: false,
            },
            compute: None,
            extensions: vec![],
        }],
    }
}

fn request(
    execution: &str,
    demand: &CapabilityRequirements,
    candidates: Value,
    action: Value,
    horizon: u64,
) -> Value {
    // Leading whitespace is deliberately retained as original authored bytes.
    let raw = [
        b" \n".as_slice(),
        serde_json::to_vec(demand).unwrap().as_slice(),
    ]
    .concat();

    json!({
        "format": "crucible.capability-preparation-request",
        "version": 1,
        "ledger": "operator-capabilities",
        "execution": execution,
        "requirements": Bytes::new(raw),
        "candidates": candidates,
        "configuration": Bytes::new(serde_json::to_vec(&json!({
            "format": "crucible.node-run-configuration",
            "version": 1,
            "horizon_ps": horizon.to_string(),
            "maximum_rounds": "8"
        }))
        .unwrap()),
        "action": action
    })
}

fn submit(socket: &Path, path: &Path, request: &Value) -> CapabilityPreparationRecord {
    fs::write(path, serde_json::to_vec(request).unwrap()).unwrap();
    serde_json::from_value(success(&[
        "node",
        "capability",
        "--socket",
        socket.to_str().unwrap(),
        "--request",
        path.to_str().unwrap(),
    ]))
    .unwrap()
}

fn finished(socket: &Path, execution: &str) -> CapabilityPreparationRecord {
    let deadline = Instant::now() + Duration::from_secs(30);
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
            "original capability admission never completed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn copy_files(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap();
    fs::set_permissions(target, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            copy_files(&entry.path(), &target.join(entry.file_name()));
        } else if kind.is_file() {
            fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
        } else {
            assert!(
                entry.file_name() == "control.sock",
                "unexpected non-file in private retained namespace"
            );
        }
    }
}

fn native_state(
    directory: &Path,
    record: &CapabilityPreparationRecord,
) -> (Vec<u8>, crucible_core::node_contract::RuntimeSnapshot) {
    let CapabilityPreparationState::Native { artifact, .. } = &record.outcome else {
        panic!("actual Clock did not preserve its native state");
    };
    let mut limits = NativeArchiveLimits::default();
    limits.state.maximum_content_bytes = 256 * 1024 * 1024;
    let archive = NativeArchive::open(directory.join("capability-clock-archive"), limits).unwrap();
    let source = archive.load(artifact).unwrap();
    let bytes = source
        .object_bytes(&source.owners()[0].state, 64 * 1024 * 1024)
        .unwrap();
    let wire: Value = serde_json::from_slice(&bytes).unwrap();
    let native: Vec<u8> = serde_json::from_value(wire["native"].clone()).unwrap();
    (native, source.runtime_snapshot().unwrap())
}

#[test]
#[ignore = "requires the source-built companion and actual owning CLI/daemon executable"]
fn actual_cli_capabilities_queue_clock_worker_and_preserve_two_source_gone_branches() {
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original");
    let (policy_path, socket) = policy(&original, &device);
    let daemon = Daemon::start(&policy_path, &socket);
    let selections =
        json!([{"node":"clock","owner":"clock-owner","kind":{"implementation":"host_clock"}}]);
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
    let baseline = NodeScenario::from_json(&fs::read(&scenario_path).unwrap()).unwrap();
    let demand = demands(&baseline);
    let candidates = json!([{"id":"installed/clock","selections":selections}]);
    let path = original.join("request.json");
    let live = request(
        "71717171717171717171717171717171",
        &demand,
        candidates.clone(),
        json!({"operation":"observe"}),
        10,
    );
    let initial = submit(&socket, &path, &live);
    let admitted = finished(&socket, &initial.execution);
    let CapabilityPreparationState::Admitted {
        scenario,
        observed_request,
    } = &admitted.outcome
    else {
        panic!("{admitted:?}");
    };
    let selected_scenario = NodeScenario::from_json(scenario.as_slice()).unwrap();
    assert_eq!(
        selected_scenario.world.scenario_ref.media_type,
        crucible_core::node_admission::CAPABILITY_SELECTION_MEDIA_TYPE
    );
    assert!(!observed_request.as_slice().is_empty());

    let selection: crucible_core::node_admission::CapabilitySelection = serde_json::from_slice(
        &selected_scenario
            .content
            .iter()
            .find(|body| body.reference == selected_scenario.world.scenario_ref)
            .unwrap()
            .bytes,
    )
    .unwrap();
    let original_raw: Bytes = serde_json::from_value(live["requirements"].clone()).unwrap();
    assert_eq!(
        selected_scenario
            .content
            .iter()
            .find(|body| body.reference == selection.requirements_ref)
            .unwrap()
            .bytes,
        original_raw.as_slice()
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let outcome = loop {
        let status = success(&[
            "node",
            "status",
            "--socket",
            socket.to_str().unwrap(),
            "--execution",
            initial.execution.as_str(),
        ]);
        if status["status"] == "completed" {
            break status;
        }
        assert_eq!(status["status"], "reserved");
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(outcome["outcome"], "completed");
    assert_eq!(outcome["repeatable"], true);
    assert_eq!(
        serde_json::to_value(submit(&socket, &path, &live)).unwrap(),
        serde_json::to_value(&admitted).unwrap()
    );

    let mut preservation = demand.clone();
    preservation.nodes[0].guarantees.durable_restart = true;
    let facet = baseline.compatibility[0]
        .operating_contract
        .facets
        .iter()
        .find(|facet| facet.id.as_str() == "host/preservation-v1")
        .unwrap()
        .clone();
    for name in ["capture", "durable_restart"] {
        preservation.nodes[0].operations.push(OperationRequirement {
            operation: crucible_node_contract::Id::new(name).unwrap(),
            facet: facet.clone(),
        });
    }
    preservation.nodes[0]
        .operations
        .sort_by(|left, right| left.operation.cmp(&right.operation));
    let capture = request(
        "72727272727272727272727272727272",
        &preservation,
        candidates.clone(),
        json!({"operation":"capture"}),
        10,
    );
    let initial = submit(&socket, &path, &capture);
    let captured = finished(&socket, &initial.execution);
    let (native, original_runtime) = native_state(&original, &captured);
    assert_eq!(
        native,
        crucible_core::node_adapters::host_clock_initial_bytes(10)
    );
    assert_eq!(original_runtime.operations.len(), 1);
    let CapabilityPreparationState::Native { artifact, .. } = &captured.outcome else {
        panic!("{captured:?}");
    };
    let artifact = artifact.clone();

    // Context and ambiguity negatives cannot allocate a world or change the
    // successful original receipt. Changed original request bytes never retry.
    let mut changed = capture.clone();
    changed["configuration"] = serde_json::to_value(Bytes::new(
        serde_json::to_vec(&json!({
            "format": "crucible.node-run-configuration",
            "version": 1,
            "horizon_ps": "11",
            "maximum_rounds": "8"
        }))
        .unwrap(),
    ))
    .unwrap();
    fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(
        !cli(&[
            "node",
            "capability",
            "--socket",
            socket.to_str().unwrap(),
            "--request",
            path.to_str().unwrap()
        ])
        .status
        .success()
    );

    let mut ambiguous = candidates.clone();
    ambiguous
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"installed/other-clock","selections":selections}));
    let ambiguous = request(
        "73737373737373737373737373737373",
        &demand,
        ambiguous,
        json!({"operation":"observe"}),
        10,
    );
    let original = submit(&socket, &path, &ambiguous);
    assert!(matches!(
        finished(&socket, &original.execution).outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));

    let mut unsupported = demand.clone();
    unsupported.nodes[0].guarantees.conditional_replay = true;
    let refusal = request(
        "74747474747474747474747474747474",
        &unsupported,
        candidates.clone(),
        json!({"operation":"observe"}),
        10,
    );
    let original = submit(&socket, &path, &refusal);
    assert!(matches!(
        finished(&socket, &original.execution).outcome,
        CapabilityPreparationState::Unavailable { .. }
    ));

    drop(daemon);
    let left = directory.path().join("left");
    let right = directory.path().join("right");
    copy_files(&directory.path().join("original"), &left);
    copy_files(&directory.path().join("original"), &right);
    fs::remove_dir_all(directory.path().join("original")).unwrap();
    assert!(!directory.path().join("original").exists());

    let mut branches = Vec::new();
    for (namespace, nonce) in [
        (&left, "75757575757575757575757575757575"),
        (&right, "76767676767676767676767676767676"),
    ] {
        let (policy_path, socket) = policy(namespace, &device);
        let daemon = Daemon::start(&policy_path, &socket);
        let future = request(
            nonce,
            &preservation,
            candidates.clone(),
            json!({"operation":"continue","source":artifact}),
            25,
        );
        let initial = submit(&socket, &namespace.join("future.json"), &future);
        let future = finished(&socket, &initial.execution);
        let (native, runtime) = native_state(namespace, &future);
        assert_eq!(
            native,
            crucible_core::node_adapters::host_clock_initial_bytes(25)
        );
        assert_eq!(
            runtime.operations[0].operation,
            original_runtime.operations[0].operation
        );
        assert_eq!(runtime.capture_cut.time_ps.get(), 25);
        assert_eq!(runtime.operations.len(), 2);
        let CapabilityPreparationState::Native { progress, .. } = &future.outcome else {
            panic!("{future:?}");
        };
        let outcome: Value = serde_json::from_slice(progress.as_slice()).unwrap();
        branches.push((
            runtime.source_activation.owners,
            outcome["progress"].clone(),
            outcome["scheduling"].clone(),
        ));
        assert_eq!(
            serde_json::to_value(submit(
                &socket,
                &namespace.join("future.json"),
                &request(
                    nonce,
                    &preservation,
                    candidates.clone(),
                    json!({"operation":"continue","source":artifact}),
                    25
                )
            ))
            .unwrap(),
            serde_json::to_value(future).unwrap()
        );
        drop(daemon);
    }

    assert_ne!(branches[0].0, branches[1].0);
    assert_eq!(branches[0].1, branches[1].1);
    assert_eq!(branches[0].2["reached"], branches[1].2["reached"]);
    assert_eq!(branches[0].2["publications"], branches[1].2["publications"]);
}

#[path = "node_capability_process/original_claim.rs"]
mod original_claim;
