//! Checks source-selected Clock/gem5 demands through the ordinary owning CLI route.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Exact original capability, native output and complete owner-barrier assertions deliberately fail the fixture.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_campaign::{
    CampaignRepository, ExecutionId,
    observed_node_attempt::{ObservedAttemptOutcome, ObservedAttemptState},
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};
use std::sync::Arc;

fn mixed_demands(scenario: &NodeScenario) -> CapabilityRequirements {
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
        let semantic = if binding.node_id.as_str() == "clock" {
            "host/exact-v1"
        } else {
            crucible_core::node_adapters::gem5::GEM5_CLOSED_EXACT_PROFILE
        };
        let facet = capabilities
            .facets
            .iter()
            .find(|facet| facet.id.as_str() == semantic)
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

// crucible-lint: allow clippy-disallowed-method -- One absolute watchdog bounds each original native preparation or ordinary execution; it does not replace native logical time.
// crucible-lint: allow rust-allow -- The selected process fixture owns only operational expiry, not a semantic timing policy.
#[allow(
    clippy::disallowed_methods,
    reason = "Original source-built gem5 preparation and result polling need one absolute operational deadline"
)]
fn await_original(socket: &Path, execution: &str, capability: bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let state = success(&[
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
            "original native preparation or execution exceeded watchdog"
        );
        let pending = if capability {
            state["outcome"]["state"] == "awaiting_admission"
        } else {
            state["status"] == "reserved"
        };
        if !pending {
            return state;
        }
        std::thread::yield_now();
    }
}

#[test]
#[ignore = "requires genuine compiled source-built closed gem5 profile and actual CLI/daemon/companion"]
fn authored_clock_gem5_demands_prepare_and_execute_one_original_mixed_world() {
    let directory = tempfile::tempdir().unwrap().keep();
    eprintln!(
        "capability Clock/gem5 original custody: {}",
        directory.display()
    );
    let device = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let (policy_path, socket) = policy(&directory, &device);
    let mut daemon = RetainedDaemon::start(&policy_path, &socket);
    let selections = json!([
        {"node":"clock","owner":"owner/clock","kind":{"implementation":"host_clock"}},
        {"node":"cpu","owner":"owner/cpu","kind":{"implementation":"gem5_closed","isa":"x86_64"}}
    ]);
    let selection_path = directory.join("selections.json");
    fs::write(&selection_path, serde_json::to_vec(&selections).unwrap()).unwrap();
    let baseline_path = directory.join("baseline.json");
    let compiled = cli(&[
        "node",
        "compile",
        "--socket",
        socket.to_str().unwrap(),
        "--selections",
        selection_path.to_str().unwrap(),
        "--output",
        baseline_path.to_str().unwrap(),
    ]);
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let baseline = NodeScenario::from_json(&fs::read(&baseline_path).unwrap()).unwrap();
    let requirements = mixed_demands(&baseline);
    let candidates = json!([{"id":"installed/closed-clock-gem5","selections":selections}]);
    let execution = "91919191919191919191919191919191";
    let request_path = directory.join("authored-request.json");
    let mut original = request(
        execution,
        &requirements,
        candidates.clone(),
        json!({"operation":"observe"}),
        1_000_000_000,
    );
    original["configuration"] = serde_json::to_value(Bytes::new(serde_json::to_vec(&json!({
        "format":"crucible.node-run-configuration","version":1,"horizon_ps":"1000000000","maximum_rounds":"64"
    })).unwrap())).unwrap();
    submit(&socket, &request_path, &original);
    let admitted = await_original(&socket, execution, true);
    let admitted: CapabilityPreparationRecord = serde_json::from_value(admitted).unwrap();
    let CapabilityPreparationState::Admitted { scenario, .. } = &admitted.outcome else {
        panic!("{admitted:?}");
    };
    let selected = NodeScenario::from_json(scenario.as_slice()).unwrap();
    assert_eq!(selected.compatibility, baseline.compatibility);
    assert_eq!(selected.descriptors, baseline.descriptors);
    assert_ne!(selected.world.scenario_ref, baseline.world.scenario_ref);
    let raw: Bytes = serde_json::from_value(original["requirements"].clone()).unwrap();
    assert!(
        selected
            .content
            .iter()
            .any(|body| body.bytes == raw.as_slice()
                && body.reference.media_type
                    == crucible_core::node_admission::CAPABILITY_REQUIREMENTS_MEDIA_TYPE)
    );
    let completed = await_original(&socket, execution, false);
    assert_eq!(completed["status"], "completed", "{completed}");
    assert_eq!(completed["outcome"], "completed");
    assert_eq!(
        serde_json::to_value(submit(&socket, &request_path, &original)).unwrap(),
        serde_json::to_value(&admitted).unwrap()
    );

    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "capability-mixed-gem5",
        directory.join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let repository = CampaignRepository::new(blobs.clone(), refs);
    let state = repository
        .observed_execution_state(ExecutionId::from_bytes([0x91; 16]).unwrap())
        .unwrap()
        .unwrap();
    let ObservedAttemptState::Completed(result) = state else {
        panic!("original observed state incomplete");
    };
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    assert_eq!(result.request().capabilities().roster().owners().len(), 2);
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
    assert!(outcomes.iter().any(|row| row.node.as_str() == "clock"));
    let publications = outcomes
        .iter()
        .filter(|row| row.node.as_str() == "cpu")
        .flat_map(|row| row.scheduling.as_ref().unwrap().publications.iter())
        .collect::<Vec<_>>();
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0].payload_bytes, expected_guest_checksum());
    publications[0]
        .payload
        .verify(&publications[0].payload_bytes)
        .unwrap();
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

    // Every refusal uses a fresh original claim, without laundering the successful nonce.
    for axis in 0..6 {
        let mut changed = requirements.clone();
        match axis {
            0 => changed.nodes[1].guarantees.durable_restart = true,
            1 => changed.nodes[1].guarantees.isolated_fork = true,
            2 => changed.nodes[1].guarantees.conditional_replay = true,
            3 => changed.nodes[1].operations[0].facet.version += 1,
            4 => {
                changed.nodes[1].compute = Some(crucible_core::node_admission::ComputeRequirement {
                    architecture: crucible_node_contract::Id::new("x86_64").unwrap(),
                    machine_ref: changed.nodes[1].timing.policy_ref.clone(),
                    devices_ref: changed.nodes[1].timing.policy_ref.clone(),
                })
            }
            _ => {
                let capabilities: CapabilityProfile = serde_json::from_slice(
                    &baseline
                        .content
                        .iter()
                        .find(|body| body.reference == baseline.compatibility[0].capabilities_ref)
                        .unwrap()
                        .bytes,
                )
                .unwrap();
                let facet = capabilities
                    .facets
                    .into_iter()
                    .find(|facet| facet.id.as_str() == "host/physical-pause-v1")
                    .unwrap();
                changed.nodes[0].operations = vec![OperationRequirement {
                    operation: crucible_node_contract::Id::new("physical_pause").unwrap(),
                    facet,
                }];
            }
        }
        let nonce = format!("{:032x}", 0x92929292929292929292929292929292u128 + axis);
        let refused = request(
            &nonce,
            &changed,
            candidates.clone(),
            json!({"operation":"observe"}),
            1_000_000_000,
        );
        submit(&socket, &request_path, &refused);
        let denied: CapabilityPreparationRecord =
            serde_json::from_value(await_original(&socket, &nonce, true)).unwrap();
        assert!(matches!(
            denied.outcome,
            CapabilityPreparationState::Unavailable { .. }
        ));
    }
    retire_original(&mut daemon, &socket);
    drop(daemon);
}

/// Recomputes the installed freestanding guest's integer/memory result independently.
fn expected_guest_checksum() -> [u8; 8] {
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

    answer.to_le_bytes()
}

// crucible-lint: allow clippy-disallowed-method -- One original daemon shutdown watchdog checks that the owning service and native retirement queues exit without a forced kill.
// crucible-lint: allow rust-allow -- The deadline bounds containment only and cannot establish modeled completion.
#[allow(
    clippy::disallowed_methods,
    reason = "Original service shutdown must wait for retained native groups and whole-world custody"
)]
fn retire_original(daemon: &mut RetainedDaemon, socket: &Path) {
    daemon.request_stop();
    let deadline = Instant::now() + Duration::from_secs(180);

    loop {
        if let Some(status) = daemon.child.try_wait().unwrap() {
            assert!(
                status.success(),
                "original service failed during native retirement: {status}"
            );
            assert!(
                !socket.exists(),
                "original service did not retire its control endpoint"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "original native retirement exceeded its watchdog"
        );
        std::thread::yield_now();
    }
}

/// Keeps the original service and native retirement owner alive through fixture failures.
struct RetainedDaemon {
    child: Child,
    stopping: bool,
}

impl RetainedDaemon {
    // crucible-lint: allow clippy-disallowed-method -- One original startup watchdog does not retry preparation or manufacture readiness.
    // crucible-lint: allow rust-allow -- Physical expiry bounds only process installation.
    #[allow(
        clippy::disallowed_methods,
        reason = "The actual owning daemon must publish its original endpoint before control"
    )]
    fn start(policy: &Path, socket: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_crucible"))
            .args(["node", "serve", "--policy", policy.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut owner = Self {
            child,
            stopping: false,
        };
        let deadline = Instant::now() + Duration::from_secs(20);

        while !socket.exists() {
            assert!(
                owner.child.try_wait().unwrap().is_none(),
                "original daemon exited before installation"
            );
            assert!(
                Instant::now() < deadline,
                "original daemon did not install its endpoint"
            );
            std::thread::yield_now();
        }
        owner
    }

    fn request_stop(&mut self) {
        if self.stopping || matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        self.stopping = true;
        if let Some(pid) = rustix::process::Pid::from_raw(self.child.id() as i32) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::INT);
        }
    }
}

impl Drop for RetainedDaemon {
    fn drop(&mut self) {
        self.request_stop();
        // An assertion failure cannot discard the original native capsule. The
        // service retains it until actual queue reclamation; no deadline grants
        // a forced kill or permission to call this failure successful cleanup.
        loop {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::yield_now();
        }
    }
}
