//! Separates data-predicate regressions from actual installed native execution.

// crucible-lint: allow panic-shortcut -- Native and data fixtures deliberately panic on failed capability, custody or immutable-contract invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::InstalledNodeKind;
use super::*;
use crucible::node_admission::{
    CAPABILITY_REQUIREMENTS_FORMAT, GuaranteeRequirement, NodeCapabilityRequirement,
    OperationRequirement, TimingRequirement,
};
use crucible_node_contract::{CapabilityProfile, GuaranteeProfile, U64};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn clock() -> Vec<InstalledNodeSelection> {
    vec![InstalledNodeSelection {
        node: id("clock"),
        owner: id("clock-owner"),
        kind: InstalledNodeKind::HostClock,
    }]
}

// These references exercise source-profile predicates only. They never create
// AdmissionEvidence, a native resource, or an operational qualification seal.
fn model_clock() -> NodeScenario {
    let host = canonical::content_ref(b"model-only host", "application/octet-stream").unwrap();
    let device = canonical::content_ref(b"model-only device", "application/octet-stream").unwrap();
    super::super::profile::build_world(&clock(), &host, &device, &Default::default())
        .unwrap()
        .scenario
}

pub(super) fn requirements(scenario: &NodeScenario) -> CapabilityRequirements {
    CapabilityRequirements {
        format: CAPABILITY_REQUIREMENTS_FORMAT.into(),
        schema_version: 1,
        nodes: scenario
            .compatibility
            .iter()
            .map(|binding| {
                let guarantee: GuaranteeProfile =
                    policy::object(scenario, &binding.guarantees_ref).unwrap();
                let capability: CapabilityProfile =
                    policy::object(scenario, &binding.capabilities_ref).unwrap();
                let operations = if binding.node_id.as_str() == "clock" {
                    vec![OperationRequirement {
                        operation: id("exact_run"),
                        facet: capability
                            .facets
                            .iter()
                            .find(|facet| facet.id.as_str() == "host/exact-v1")
                            .unwrap()
                            .clone(),
                    }]
                } else {
                    let facet = capability
                        .facets
                        .iter()
                        .find(|facet| facet.id.as_str() == "reference-device/quantized-v1")
                        .unwrap();
                    vec![
                        OperationRequirement {
                            operation: id("quantum_begin"),
                            facet: facet.clone(),
                        },
                        OperationRequirement {
                            operation: id("quantum_close"),
                            facet: facet.clone(),
                        },
                    ]
                };
                NodeCapabilityRequirement {
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
                        durable_restart: false,
                        isolated_fork: false,
                        conditional_replay: false,
                    },
                    compute: None,
                    extensions: vec![],
                }
            })
            .collect(),
    }
}

#[test]
fn complete_contract_mismatch_and_unknown_operation_refuse() {
    let scenario = model_clock();
    let demand = requirements(&scenario);
    policy::matches(&clock(), &scenario, &demand).unwrap();

    let mut changed = demand.clone();
    changed.nodes[0].operations[0].facet.version = 2;
    assert!(policy::matches(&clock(), &scenario, &changed).is_err());
    changed = demand.clone();
    changed.nodes[0].operations[0].facet.configuration_ref = scenario.world.scenario_ref.clone();
    assert!(policy::matches(&clock(), &scenario, &changed).is_err());
    changed = demand.clone();
    changed.nodes[0].timing.phase_ps = Some(U64::new(1));
    assert!(policy::matches(&clock(), &scenario, &changed).is_err());
    changed = demand.clone();
    changed.nodes[0].guarantees.isolated_fork = true;
    assert!(policy::matches(&clock(), &scenario, &changed).is_err());
    changed = demand;
    changed.nodes[0].operations[0].operation = id("time_travel");
    assert!(policy::matches(&clock(), &scenario, &changed).is_err());
}

#[test]
fn no_capability_replay_factory_is_inferred_from_native_clock_preservation() {
    let scenario = model_clock();
    let mut demanded = requirements(&scenario);
    demanded.nodes[0].guarantees.conditional_replay = true;
    assert!(policy::matches(&clock(), &scenario, &demanded).is_err());

    demanded = requirements(&scenario);
    demanded.nodes[0].operations[0].operation = id("isolated_fork");
    assert!(policy::matches(&clock(), &scenario, &demanded).is_err());
}

#[test]
fn requirement_identity_changes_without_mutating_legacy_bytes() {
    let scenario = model_clock();
    let original = scenario.canonical_bytes().unwrap();
    let demands = requirements(&scenario);
    let selected = bind_requirements(scenario.clone(), &demands).unwrap();
    let mut changed = demands.clone();
    changed.nodes[0].operations[0].operation = id("boundary_settle");
    let changed = bind_requirements(scenario.clone(), &changed).unwrap();
    assert_ne!(selected.world.scenario_ref, changed.world.scenario_ref);
    assert_ne!(
        selected.world.identity().unwrap(),
        scenario.world.identity().unwrap()
    );
    assert_eq!(original, scenario.canonical_bytes().unwrap());
    assert_eq!(selected.compatibility, scenario.compatibility);
}

#[test]
fn nullable_compute_and_closed_edition_are_mandatory() {
    let demand = requirements(&model_clock());
    let mut value = serde_json::to_value(&demand).unwrap();
    value["nodes"][0].as_object_mut().unwrap().remove("compute");
    assert!(serde_json::from_value::<CapabilityRequirements>(value).is_err());
    let mut value = serde_json::to_value(&demand).unwrap();
    value["nodes"][0]["operations"][0]["guessed_support"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CapabilityRequirements>(value).is_err());
    let mut changed = demand;
    changed.nodes.push(changed.nodes[0].clone());
    assert!(changed.validate().is_err());
}

#[test]
fn complete_roster_and_architecture_device_demand_cannot_be_inferred() {
    let scenario = model_clock();
    let mut demands = requirements(&scenario);
    demands.nodes[0].compute = Some(crucible::node_admission::ComputeRequirement {
        architecture: id("x86_64"),
        machine_ref: scenario.compatibility[0].configuration_ref.clone(),
        devices_ref: policy::object::<CapabilityProfile>(
            &scenario,
            &scenario.compatibility[0].capabilities_ref,
        )
        .unwrap()
        .devices_ref,
    });
    assert!(policy::matches(&clock(), &scenario, &demands).is_err());
    demands = requirements(&scenario);
    demands.nodes[0].node = id("foreign");
    assert!(policy::matches(&clock(), &scenario, &demands).is_err());
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the actual source-built companion"]
// crucible-lint: allow clippy-disallowed-method -- Host monotonic time only bounds the original native fixture's completion or reclamation wait; it never enters modeled state.
// crucible-lint: allow rust-allow -- The existing diagnostic reason documents this test-local host watchdog exception.
#[allow(
    clippy::disallowed_methods,
    reason = "Host time is only an absolute fixture watchdog, never a modeled clock"
)]
fn actual_capability_selected_clock_and_reference_execute_without_legacy_retagging() {
    use crate::node_observed_executor::StoredWorldActivationPublisher;
    use crucible::node_contract::BeginResult;
    use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend, RefName};
    use crucible_node_contract::{Phase, Position};
    use std::{
        sync::Arc,
        task::{Context, Poll, Waker},
        time::{Duration, Instant},
    };

    let directory = tempfile::tempdir().unwrap();
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let native_directory = directory.path().join("native");
    std::fs::create_dir(&native_directory).unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        super::super::measure_executable(&executable).unwrap(),
        native_directory.clone(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let mut selections = clock();
    selections.push(InstalledNodeSelection {
        node: id("device"),
        owner: id("device-owner"),
        kind: InstalledNodeKind::ReferenceDevice {
            quantum_ps: U64::new(50),
            host_budget_ns: U64::new(20_000_000),
        },
    });
    let baseline = catalog.scenario(&selections).unwrap();
    let legacy = baseline.canonical_bytes().unwrap();
    let demand = requirements(&baseline);
    let candidate = InstalledCapabilityCandidate {
        id: id("installed/mixed"),
        selections,
    };
    let mut changed = demand.clone();
    changed.nodes[1].operations[0].operation = id("capture");
    assert!(
        catalog
            .resolve_capabilities(std::slice::from_ref(&candidate), changed)
            .is_err()
    );
    let mut second = candidate.clone();
    second.id = id("installed/second");
    assert!(
        catalog
            .resolve_capabilities(&[candidate.clone(), second], demand.clone())
            .is_err()
    );
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert_eq!(std::fs::read_dir(&native_directory).unwrap().count(), 0);
    assert_eq!(
        legacy,
        catalog
            .scenario(&candidate.selections)
            .unwrap()
            .canonical_bytes()
            .unwrap()
    );

    let resolved = catalog
        .resolve_capabilities(std::slice::from_ref(&candidate), demand)
        .unwrap();
    assert_eq!(resolved.candidate_id(), &candidate.id);
    let prepared = catalog
        .prepare_capability_world(&resolved, ExecutionId::from_bytes([91; 16]).unwrap())
        .unwrap();
    assert!(prepared.graph.capability_requirements().is_some());
    let selected = prepared.graph.capability_selection().unwrap();
    assert_eq!(selected.objects().len(), 3);
    for (reference, bytes) in selected.objects() {
        reference.verify(bytes).unwrap();
        let original = resolved
            .scenario()
            .content
            .iter()
            .find(|object| object.reference == *reference)
            .unwrap();
        assert_eq!(bytes, original.bytes);
    }
    assert!(prepared.graph.selected_extensions().is_empty());
    let graph = prepared.graph;
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let mut publisher = StoredWorldActivationPublisher::new(
        Arc::new(DirectoryBlobBackend::new(
            "capability",
            directory.path().join("blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
        RefName::new("node-world-activations/capability").unwrap(),
    )
    .unwrap();
    let activation = runtime.activate(&mut publisher).unwrap();
    for node in ["clock", "device"] {
        let observation = runtime.observe_scheduling(&activation, &id(node)).unwrap();
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .accept_boundary_observation(observation)
            .unwrap();
    }
    let grant = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&id("clock"), id("clock/advance"), U64::new(50))
        .unwrap();
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
        panic!("actual Clock refused");
    };
    let Poll::Ready(Ok(clock_outcome)) =
        runtime.poll(&token, &mut Context::from_waker(Waker::noop()))
    else {
        panic!("Clock did not complete");
    };
    assert_eq!(
        clock_outcome.scheduling.as_ref().unwrap().reached.time_ps,
        U64::new(50)
    );
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();

    let batch = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .prepare_input_batch(
            &id("device"),
            id("device/stage"),
            id("device/batch"),
            Position::new(U64::new(1), U64::new(0), Phase::BoundaryControl),
        )
        .unwrap();
    let acknowledgement = runtime.stage_inputs(batch).unwrap();
    let commit = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();
    runtime.commit_input_staging(&commit).unwrap();
    let grant = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_quantum(
            &id("device"),
            id("device/run"),
            id("device/window"),
            id("device/batch"),
        )
        .unwrap();
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
        panic!("actual reference child refused");
    };
    assert!(matches!(
        runtime.poll(&token, &mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    assert_eq!(
        runtime.close_quantum(&token).unwrap(),
        crucible::node_contract::Submission::Accepted
    );
    let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut Context::from_waker(Waker::noop()))
    else {
        panic!("authentically closed original window did not complete");
    };
    assert_eq!(
        outcome.scheduling.as_ref().unwrap().reached.time_ps,
        U64::new(50)
    );
    assert_eq!(outcome.scheduling.as_ref().unwrap().publications.len(), 1);
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    drop(runtime);
    let deadline = Instant::now() + Duration::from_secs(5);
    while catalog.custody().reserved_worlds() != 0 {
        assert!(
            Instant::now() < deadline,
            "original child custody was not reclaimed"
        );
        let _ = catalog
            .custody()
            .clone()
            .poll_reclamation(&mut Context::from_waker(Waker::noop()));
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the actual source-built companion"]
// crucible-lint: allow clippy-disallowed-method -- Host monotonic time only bounds the original native fixture's completion or reclamation wait; it never enters modeled state.
// crucible-lint: allow rust-allow -- The existing diagnostic reason documents this test-local host watchdog exception.
#[allow(
    clippy::disallowed_methods,
    reason = "Host time is only an absolute fixture watchdog, never a modeled clock"
)]
fn actual_capability_resolution_flows_through_ordinary_observed_executor() {
    use crucible_campaign::{
        CampaignRepository,
        observed_node_attempt::{
            ObservedAttemptOutcome, ObservedAttemptState, ObservedAttemptWorker,
        },
    };
    use crucible_cas::content_store::{
        DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
    };
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let directory = tempfile::tempdir().unwrap();
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        super::super::measure_executable(&executable).unwrap(),
        directory.path().to_path_buf(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let mut selections = clock();
    selections.push(InstalledNodeSelection {
        node: id("device"),
        owner: id("device-owner"),
        kind: InstalledNodeKind::ReferenceDevice {
            quantum_ps: U64::new(50),
            host_budget_ns: U64::new(20_000_000),
        },
    });
    let baseline = catalog.scenario(&selections).unwrap();
    let demand = requirements(&baseline);
    let resolved = catalog
        .resolve_capabilities(
            &[InstalledCapabilityCandidate {
                id: id("installed/observed"),
                selections,
            }],
            demand,
        )
        .unwrap();
    let bytes = resolved.scenario().canonical_bytes().unwrap();
    assert_eq!(
        bytes,
        NodeScenario::from_json(&bytes)
            .unwrap()
            .canonical_bytes()
            .unwrap()
    );
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "capability-observed",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let execution = ExecutionId::from_bytes([92; 16]).unwrap();
    let backend = catalog
        .prepare_capability(
            &resolved,
            crate::node_scenario::NodeRunConfiguration {
                format: "crucible.node-run-configuration".into(),
                version: 1,
                horizon_ps: U64::new(100),
                maximum_rounds: U64::new(8),
            },
            execution,
            blobs.clone(),
            refs,
        )
        .unwrap();
    let scenario = backend.scenario_artifact();
    repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .unwrap();
    let configuration = backend.configuration_artifact();
    repository
        .publish_configuration_artifact(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            configuration.payload_schema(),
            configuration.payload().to_vec(),
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    assert_eq!(request.capabilities().roster().owners().len(), 2);
    assert!(!request.capabilities().roster().is_repeatable());
    let admission = backend.admission().clone();
    let mut worker = ObservedAttemptWorker::new(repository.clone(), backend, 1).unwrap();
    let _gc = repository.acquire_gc_exclusion_guard().unwrap();
    assert!(matches!(
        worker
            .submit("capability-observed", &request, &admission)
            .unwrap(),
        ObservedAttemptState::Reserved(_)
    ));
    let deadline = Instant::now() + Duration::from_secs(20);
    let result = loop {
        assert!(
            Instant::now() < deadline,
            "original observed execution deadline exceeded"
        );
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(result) => break result,
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("actual selected native world quarantined: {reason}")
            }
            ObservedAttemptState::Reserved(_) => std::thread::sleep(Duration::from_millis(1)),
        }
    };
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let evidence = blobs
        .read(result.evidence(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let evidence: serde_json::Value = serde_json::from_slice(&evidence).unwrap();
    let events = evidence["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);
    for event in events {
        assert!(
            !event["objects"].as_array().unwrap().is_empty(),
            "original native receipt body was not retained"
        );
    }
    assert_eq!(
        repository
            .load_observed_result(result.id().unwrap())
            .unwrap(),
        result
    );
}
