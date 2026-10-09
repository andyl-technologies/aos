//! Source-profile ordering, exact native completion routes and immutable identities.
//!
//! Data-only golden fixtures use fixed source identities and confer no authority.
//! Native cases use independently installed artifacts and the ordinary observed
//! executor; descriptor ordering does not qualify preservation or controls.

// crucible-lint: allow panic-shortcut -- Changed installed identities or original native outcomes fail this single test attempt.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::{BTreeMap, BTreeSet},
    task::{Context, Poll, Waker},
};

use crucible::{
    AssertionDef, AssertionId, IoEventKind, NodeId, Predicate, Properties, Property, VirtualTime,
    model::{PropertyNamespace, PropertyObservation},
    node_adapters::{
        HostSemanticDefinition, HostSemanticInput, HostSemanticInputKind, HostSemanticModel,
        ScriptedRequest, ScriptedRequestKind, ScriptedSource,
    },
    node_contract::{BeginResult, NodeRuntime, OperationOutcome},
    node_scheduling::ExecutionAdmission,
};
use crucible_campaign::observed_node_attempt::{ObservedAttemptBackend, ObservedAttemptOutcome};
use crucible_device::{BlockRequest, BlockResponse, BlockStatus};
use crucible_node_contract::{Bytes, Endpoint, Phase, Position, U64, Validate};

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn definition(version: u16, ingress: bool) -> HostSemanticDefinition {
    let nodes = if ingress {
        BTreeMap::from([(
            NodeId {
                name: "disk".into(),
            },
            BTreeSet::from([PropertyObservation::Io(IoEventKind::Any)]),
        )])
    } else {
        BTreeMap::new()
    };
    let namespace = PropertyNamespace::new(nodes, false, version == 2, BTreeSet::new()).unwrap();
    let predicate = if ingress {
        Predicate::IoPattern {
            node: NodeId {
                name: "disk".into(),
            },
            kind: IoEventKind::Any,
        }
    } else {
        Predicate::at(VirtualTime { ticks: 2 })
    };
    let properties = Properties::from_assertions_for_namespace(
        &namespace,
        vec![AssertionDef {
            id: AssertionId::from_name("original-block-completion"),
            message: "original installed completion satisfies the authored predicate".into(),
            property: Property::Sometimes { predicate },
        }],
    )
    .unwrap();
    HostSemanticDefinition {
        version,
        properties: Bytes::new(properties.to_compact_binary()),
        inputs: if ingress {
            vec![HostSemanticInput {
                source: Endpoint {
                    node_id: id("disk"),
                    port_id: id("data"),
                    lane_id: id("output"),
                },
                kind: HostSemanticInputKind::BlockCompletion,
            }]
        } else {
            Vec::new()
        },
    }
}

fn artifact(directory: &Path, name: &str, bytes: &[u8], media: &str) -> InstalledIoArtifact {
    let path = directory.join(name);
    std::fs::write(&path, bytes).unwrap();
    InstalledIoArtifact::path(path, canonical::content_ref(bytes, media).unwrap())
}

fn fixture(
    directory: &Path,
    version: u16,
    ingress: bool,
) -> (Vec<InstalledNodeSelection>, Vec<InstalledIoArtifact>) {
    let program = artifact(
        directory,
        "program",
        &canonical::canonical_json(&serde_json::to_value(definition(version, ingress)).unwrap())
            .unwrap(),
        "application/json",
    );
    let mut selections = vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("clock-owner"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("observer"),
            owner: id("observer-owner"),
            kind: InstalledNodeKind::HostSemantics {
                profile: InstalledHostSemanticProfile {
                    program: program.expected.clone(),
                },
            },
        },
    ];
    let mut artifacts = vec![program];
    if ingress {
        let script = ScriptedSource::new(
            ScriptedRequestKind::Block,
            vec![ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::get_length(71).encode().unwrap(),
            }],
        )
        .unwrap()
        .script_bytes()
        .unwrap();
        let script = artifact(directory, "script", &script, "application/octet-stream");
        let base = artifact(directory, "base", &[7, 8, 9], "application/octet-stream");
        selections.extend([
            InstalledNodeSelection {
                node: id("disk"),
                owner: id("disk-owner"),
                kind: InstalledNodeKind::HostIo {
                    profile: InstalledHostIoProfile::Block {
                        base_image: base.expected.clone(),
                        source_node: 7,
                        read_ns: 1.into(),
                        write_ns: 1.into(),
                        flush_ns: 1.into(),
                        get_length_ns: 1.into(),
                        per_byte_ns: 1.into(),
                    },
                },
            },
            InstalledNodeSelection {
                node: id("source"),
                owner: id("source-owner"),
                kind: InstalledNodeKind::HostScripted {
                    profile: InstalledScriptedSourceProfile {
                        script: script.expected.clone(),
                        consumer: id("disk"),
                    },
                },
            },
        ]);
        artifacts.extend([base, script]);
    }
    selections.sort_by(|left, right| left.node.cmp(&right.node));
    (selections, artifacts)
}

fn data_scenario(
    selections: &[InstalledNodeSelection],
    artifacts: &[InstalledIoArtifact],
) -> NodeScenario {
    let artifacts = artifacts
        .iter()
        .cloned()
        .map(|artifact| (artifact.expected.hash.digest.clone(), artifact))
        .collect();
    profile::build_world(
        selections,
        &canonical::content_ref(b"fixed data-only host identity", "application/octet-stream")
            .unwrap(),
        &canonical::content_ref(
            b"fixed data-only device identity",
            "application/octet-stream",
        )
        .unwrap(),
        &artifacts,
    )
    .unwrap()
    .scenario
}

fn identities(scenario: &NodeScenario) -> serde_json::Value {
    let binding = scenario
        .compatibility
        .iter()
        .find(|binding| binding.node_id == id("observer"))
        .unwrap();
    let descriptor = scenario
        .descriptors
        .iter()
        .find(|descriptor| descriptor.id == id("observer"))
        .unwrap();
    serde_json::json!({
        "descriptor": descriptor.identity().unwrap(),
        "binding": binding.identity().unwrap(),
        "world": scenario.world.identity().unwrap(),
        "scenario": canonical::content_ref(&scenario.canonical_bytes().unwrap(), "application/json").unwrap(),
        "configuration": descriptor.configuration_ref,
        "model": descriptor.model_ref,
        "initialization": descriptor.initialization_ref,
        "capabilities": binding.capabilities_ref,
        "guarantees": binding.guarantees_ref,
    })
}

#[test]
fn existing_v2_no_ingress_full_profile_and_native_initialization_are_byte_exact() {
    let directory = tempfile::tempdir().unwrap();
    let (selections, artifacts) = fixture(directory.path(), 2, false);
    let scenario = data_scenario(&selections, &artifacts);
    let measured = identities(&scenario);
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("semantic_profile_v2_golden.json")).unwrap();
    assert_eq!(measured, golden);
    let descriptor = scenario
        .descriptors
        .iter()
        .find(|node| node.id == id("observer"))
        .unwrap();
    let original = HostSemanticModel::new(
        definition(2, false),
        semantics::MAXIMUM_SEMANTIC_STATE_BYTES,
        semantics::MAXIMUM_SEMANTIC_EVENTS,
    )
    .unwrap()
    .capture()
    .unwrap();
    assert_eq!(
        descriptor.initialization_ref,
        canonical::content_ref(&original, "application/octet-stream").unwrap()
    );
}

fn catalog(directory: &Path, artifacts: Vec<InstalledIoArtifact>) -> InstalledNodeCatalog {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    catalog.install_artifacts(artifacts).unwrap();
    catalog
}

fn execution(
    catalog: &mut InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    scenario: NodeScenario,
    directory: &Path,
) -> Vec<OperationOutcome> {
    let blobs: Arc<dyn ImmutableBlobBackend> =
        Arc::new(crucible_cas::content_store::DirectoryBlobBackend::new(
            "semantic-source-profile",
            directory.join("blobs"),
        ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(
        crucible_cas::content_store::DirectoryRefBackend::new(directory.join("refs")),
    );
    let execution = ExecutionId::from_bytes([117; 16]).unwrap();
    let mut backend = catalog
        .prepare(
            selections,
            scenario,
            NodeRunConfiguration {
                format: "crucible.node-run-configuration".into(),
                version: 1,
                horizon_ps: 10_000.into(),
                maximum_rounds: 128.into(),
            },
            execution,
            blobs.clone(),
            refs,
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    backend.start(&request).unwrap();
    let mut result = None;
    // All selected native models execute in-process. This finite poll budget
    // advances one original execution and authentic reclamation, never a rerun.
    for _ in 0..512 {
        if let Some(completed) = backend.poll(execution).unwrap() {
            result = Some(completed);
            break;
        }
    }
    let result = result.expect("original installed model exceeded its finite poll budget");
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let bytes = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    drop(backend);
    reclaim(catalog);
    value["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| serde_json::from_value(event.clone()).unwrap())
        .collect()
}

#[test]
#[ignore = "requires installed actual host models and source-built companion identity"]
fn corrected_v1_profile_executes_original_block_route_and_evaluator() {
    let directory = tempfile::tempdir().unwrap();
    let (selections, artifacts) = fixture(directory.path(), 1, true);
    let mut catalog = catalog(directory.path(), artifacts);
    let scenario = catalog.scenario(&selections).unwrap();
    let binding = scenario
        .compatibility
        .iter()
        .find(|binding| binding.node_id == id("observer"))
        .unwrap();
    assert!(
        !binding
            .operating_contract
            .facets
            .iter()
            .any(|facet| facet.id.as_str() == "host/terminal-assertions-v1")
    );
    let descriptor = scenario
        .descriptors
        .iter()
        .find(|node| node.id == id("observer"))
        .unwrap();
    assert_eq!(
        descriptor
            .ports
            .iter()
            .map(|port| port.id.as_str())
            .collect::<Vec<_>>(),
        ["assertions", "data"]
    );
    let original = HostSemanticModel::new(
        definition(1, true),
        semantics::MAXIMUM_SEMANTIC_STATE_BYTES,
        semantics::MAXIMUM_SEMANTIC_EVENTS,
    )
    .unwrap()
    .capture()
    .unwrap();
    assert_eq!(
        descriptor.initialization_ref,
        canonical::content_ref(&original, "application/octet-stream").unwrap()
    );
    eprintln!(
        "actual corrected v1 installed identities: {}",
        serde_json::to_string(&identities(&scenario)).unwrap()
    );
    eprintln!(
        "data-only corrected v1 canonical identities: {}",
        serde_json::to_string(&identities(&data_scenario(
            &selections,
            &catalog.artifacts.values().cloned().collect::<Vec<_>>()
        )))
        .unwrap()
    );
    let outcomes = execution(&mut catalog, &selections, scenario, directory.path());
    let publications = outcomes
        .iter()
        .flat_map(|outcome| outcome.scheduling.as_ref().unwrap().publications.iter())
        .collect::<Vec<_>>();
    let response = publications
        .iter()
        .find(|publication| publication.endpoint.node_id == id("disk"))
        .unwrap();
    let decoded = BlockResponse::decode(&response.payload_bytes).unwrap();
    assert_eq!(decoded.status, BlockStatus::Ok);
    assert_eq!(decoded.request_id, 71);
    assert_eq!(decoded.data, 3_u64.to_le_bytes());
    let assertion = publications
        .iter()
        .find(|publication| publication.endpoint.node_id == id("observer"))
        .unwrap();
    let outcome: serde_json::Value = serde_json::from_slice(&assertion.payload_bytes).unwrap();
    assert_eq!(outcome["kind"], "Satisfied");
    assert_eq!(assertion.causal_parents.len(), 1);
    assert!(assertion.evaluation.unwrap().time_ps >= response.publication.time_ps);
}

#[test]
#[ignore = "requires actual installed artifacts and source-built companion identity"]
fn changed_original_compatibility_program_schema_and_controls_refuse_before_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let (selections, artifacts) = fixture(directory.path(), 1, true);
    let mut catalog = catalog(directory.path(), artifacts);
    let scenario = catalog.scenario(&selections).unwrap();
    let observer = scenario
        .descriptors
        .iter()
        .position(|node| node.id == id("observer"))
        .unwrap();
    let binding = scenario
        .compatibility
        .iter()
        .position(|binding| binding.node_id == id("observer"))
        .unwrap();
    let original_tuple = scenario.compatibility[binding].clone();
    let capabilities: crucible_node_contract::CapabilityProfile = canonical::decode(
        &scenario
            .content
            .iter()
            .find(|body| body.reference == original_tuple.capabilities_ref)
            .unwrap()
            .bytes,
        4 * 1024 * 1024,
    )
    .unwrap();
    let guarantees: crucible_node_contract::GuaranteeProfile = canonical::decode(
        &scenario
            .content
            .iter()
            .find(|body| body.reference == original_tuple.guarantees_ref)
            .unwrap()
            .bytes,
        4 * 1024 * 1024,
    )
    .unwrap();
    assert!(!guarantees.durable_restart);
    assert!(!guarantees.isolated_fork);
    assert!(!guarantees.conditional_replay);
    assert!(
        capabilities
            .facets
            .iter()
            .any(|facet| facet.id.as_str() == "host/exact-v1")
    );
    let mut demands = Vec::new();
    for selected in &scenario.compatibility {
        let descriptor = scenario
            .descriptors
            .iter()
            .find(|node| node.id == selected.node_id)
            .unwrap();
        let capability: crucible_node_contract::CapabilityProfile = canonical::decode(
            &scenario
                .content
                .iter()
                .find(|body| body.reference == selected.capabilities_ref)
                .unwrap()
                .bytes,
            4 * 1024 * 1024,
        )
        .unwrap();
        let guarantee: crucible_node_contract::GuaranteeProfile = canonical::decode(
            &scenario
                .content
                .iter()
                .find(|body| body.reference == selected.guarantees_ref)
                .unwrap()
                .bytes,
            4 * 1024 * 1024,
        )
        .unwrap();
        let facet = capability
            .facets
            .iter()
            .find(|facet| facet.id.as_str() == "host/exact-v1")
            .unwrap();
        demands.push(crucible::node_admission::NodeCapabilityRequirement {
            node: selected.node_id.clone(),
            roles: descriptor.roles.clone(),
            timing: crucible::node_admission::TimingRequirement {
                mode: selected.operating_contract.mode,
                resolution_ps: selected.operating_contract.resolution_ps,
                phase_ps: selected.operating_contract.phase_ps,
                policy_ref: selected.operating_contract.policy_ref.clone(),
            },
            operations: vec![crucible::node_admission::OperationRequirement {
                operation: id("exact_run"),
                facet: facet.clone(),
            }],
            guarantees: crucible::node_admission::GuaranteeRequirement {
                repeatability: guarantee.repeatability,
                capture_scope: guarantee.capture_scope,
                continuation: guarantee.continuation,
                durable_restart: false,
                isolated_fork: false,
                conditional_replay: false,
            },
            compute: None,
            extensions: Vec::new(),
        });
    }
    let requirement = crucible::node_admission::CapabilityRequirements {
        format: crucible::node_admission::CAPABILITY_REQUIREMENTS_FORMAT.into(),
        schema_version: 1,
        nodes: demands,
    };
    let candidate = [InstalledCapabilityCandidate {
        id: id("installed/semantic-route"),
        selections: selections.clone(),
    }];
    assert!(
        catalog
            .resolve_capabilities(&candidate, requirement.clone())
            .is_ok()
    );
    for operation in [
        "capture",
        "durable_restart",
        "conditional_replay",
        "isolated_fork",
        "physical_pause",
        "debug",
        "fault_injection",
    ] {
        let mut changed = requirement.clone();
        changed.nodes[binding].operations[0].operation = id(operation);
        assert!(catalog.resolve_capabilities(&candidate, changed).is_err());
        assert_eq!(catalog.custody().reserved_worlds(), 0);
    }

    for mutation in 0..7 {
        let mut changed = scenario.clone();
        match mutation {
            0 => {
                // Preserve the imported tuple; an unsorted authored descriptor
                // must neither be repaired nor silently retagged on admission.
                changed.descriptors[observer].ports.swap(0, 1);
                assert!(changed.descriptors[observer].validate().is_err());
            }
            1 => {
                changed.descriptors[observer].configuration_ref =
                    scenario.world.scenario_ref.clone()
            }
            2 => {
                changed.descriptors[observer].ports[0].lanes[0]
                    .payload_schema
                    .version = 2
            }
            3 => {
                changed.compatibility[binding].descriptor_hash = scenario.world.identity().unwrap()
            }
            4 => {
                changed.compatibility[binding]
                    .implementation
                    .model_definitions = vec![scenario.world.scenario_ref.clone()]
            }
            5 => {
                let program = selections
                    .iter()
                    .find_map(|selection| {
                        if let InstalledNodeKind::HostSemantics { profile } = &selection.kind {
                            Some(&profile.program)
                        } else {
                            None
                        }
                    })
                    .unwrap();
                let content = changed
                    .content
                    .iter_mut()
                    .find(|body| body.reference == *program)
                    .unwrap();
                content.bytes.push(b' ');
            }
            _ => changed.compatibility[binding].operating_contract.facets[0].version = 2,
        }
        if mutation <= 2 || mutation == 5 {
            assert_eq!(
                changed.compatibility[binding].identity().unwrap(),
                original_tuple.identity().unwrap()
            );
        }
        assert!(
            catalog
                .prepare_world(
                    &selections,
                    changed,
                    ExecutionId::from_bytes([118; 16]).unwrap()
                )
                .is_err(),
            "changed original tuple admitted: {mutation}"
        );
        assert_eq!(catalog.custody().reserved_worlds(), 0);
        assert_eq!(
            catalog
                .scenario(&selections)
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            scenario.canonical_bytes().unwrap()
        );
    }
    std::fs::write(
        directory.path().join("program"),
        b"changed installed program",
    )
    .unwrap();
    assert!(catalog.scenario(&selections).is_err());
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}

#[test]
#[ignore = "requires installed actual host models and source-built companion identity"]
fn v2_original_block_projection_executes_after_complete_inventory_ordering() {
    let directory = tempfile::tempdir().unwrap();
    let (selections, artifacts) = fixture(directory.path(), 2, true);
    let mut catalog = catalog(directory.path(), artifacts);
    let scenario = catalog.scenario(&selections).unwrap();
    let outcomes = execution(&mut catalog, &selections, scenario, directory.path());
    let assertion = outcomes
        .iter()
        .flat_map(|outcome| outcome.scheduling.as_ref().unwrap().publications.iter())
        .find(|publication| publication.endpoint.node_id == id("observer"))
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&assertion.payload_bytes).unwrap();
    assert_eq!(value["kind"], "Satisfied");
    assert_eq!(assertion.causal_parents.len(), 1);
}

fn reclaim(catalog: &InstalledNodeCatalog) {
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..32 {
        if catalog.custody().reserved_worlds() == 0 {
            return;
        }
        let _ = catalog.custody().clone().poll_reclamation(&mut context);
    }
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}

fn commit_native(runtime: &mut NodeRuntime, grant: ExecutionAdmission) -> OperationOutcome {
    let result = runtime.begin_admitted(grant).unwrap();
    let BeginResult::Accepted(token) = result else {
        panic!("original native grant was not accepted");
    };
    let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut Context::from_waker(Waker::noop()))
    else {
        panic!("original in-process native operation was not complete");
    };
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    outcome
}

#[test]
#[ignore = "requires actual selected semantic input custody and source-built companion identity"]
fn semantic_successor_reaction_waits_for_exclusive_cut_and_reuses_original_batch() {
    let directory = tempfile::tempdir().unwrap();
    let (selections, artifacts) = fixture(directory.path(), 1, true);
    let mut catalog = catalog(directory.path(), artifacts);
    let scenario = catalog.scenario(&selections).unwrap();
    let prepared = catalog
        .prepare_world(
            &selections,
            scenario,
            ExecutionId::from_bytes([119; 16]).unwrap(),
        )
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = match prepared.realization.admit(&graph) {
        Ok(runtime) => runtime,
        Err(failure) => panic!("{}", failure.error),
    };
    runtime.arm_all().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> =
        Arc::new(crucible_cas::content_store::DirectoryBlobBackend::new(
            "semantic-exclusive-cuts",
            directory.path().join("blobs"),
        ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(
        crucible_cas::content_store::DirectoryRefBackend::new(directory.path().join("refs")),
    );
    let mut publisher = StoredWorldActivationPublisher::new(
        blobs,
        refs,
        RefName::new("node-world-activations/semantic-exclusive-cuts").unwrap(),
    )
    .unwrap();
    let activation = runtime.activate(&mut publisher).unwrap();
    for node in graph.node_ids() {
        let observed = runtime.observe_scheduling(&activation, node).unwrap();
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .accept_boundary_observation(observed)
            .unwrap();
    }
    let source = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&id("source"), id("source/original"), 5_000.into())
        .unwrap();
    let original_source = commit_native(&mut runtime, source);
    assert_eq!(
        original_source
            .scheduling
            .as_ref()
            .unwrap()
            .publications
            .len(),
        1
    );
    let input = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .prepare_input_batch(
            &id("disk"),
            id("disk/stage"),
            id("disk/input"),
            Position::new(5_000.into(), 0.into(), Phase::BoundaryControl),
        )
        .unwrap();
    let acknowledgement = runtime.stage_inputs(input).unwrap();
    let committed = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();
    runtime.commit_input_staging(&committed).unwrap();
    let disk = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&id("disk"), id("disk/original"), 5_000.into())
        .unwrap();
    let disk = commit_native(&mut runtime, disk);
    let response = disk
        .scheduling
        .as_ref()
        .unwrap()
        .publications
        .first()
        .unwrap();
    assert_eq!(
        BlockResponse::decode(&response.payload_bytes)
            .unwrap()
            .request_id,
        71
    );
    let original = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .pending_inputs(&id("observer"))
        .unwrap()[0]
        .clone();
    let reaction = Position::new(
        original.delivery.time_ps,
        original
            .delivery
            .microstep
            .checked_add(U64::new(1))
            .unwrap(),
        Phase::Reaction,
    );
    let input = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .prepare_input_batch(
            &id("observer"),
            id("observer/stage/original"),
            id("observer/input/original"),
            Position::new(5_000.into(), 0.into(), Phase::BoundaryControl),
        )
        .unwrap();
    assert_eq!(input.deliveries(), std::slice::from_ref(&original));
    let acknowledgement = runtime.stage_inputs(input).unwrap();
    let committed = runtime
        .commit_input_acknowledgement(acknowledgement)
        .unwrap();
    runtime.commit_input_staging(&committed).unwrap();

    // Physical parking excludes the entire instant. A later range ending at
    // the selected reaction must refuse before effects rather than close a
    // prefix past an unconsumed delivery. Original staging survives both.
    let park = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_exact(&id("observer"), id("observer/park"), reaction.time_ps)
        .unwrap();
    let parked = commit_native(&mut runtime, park);
    assert!(parked.scheduling.as_ref().unwrap().publications.is_empty());
    assert!(
        parked
            .scheduling
            .as_ref()
            .unwrap()
            .input_progress
            .as_ref()
            .unwrap()
            .consumed
            .is_empty()
    );
    let excluded = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_boundary_settlement(&id("observer"), id("observer/exclusive"), reaction)
        .unwrap();
    let refused = runtime.begin_admitted(excluded).unwrap();
    let BeginResult::Refused(refusal) = refused else {
        panic!("semantic exclusive cut was not refused before effects");
    };
    assert!(
        refusal
            .reason
            .contains("exclusive cut excludes the original input reaction")
    );
    assert_eq!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .position(&id("observer"))
            .unwrap(),
        Position::new(reaction.time_ps, 0.into(), Phase::BoundaryControl)
    );
    assert_eq!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .pending_inputs(&id("observer"))
            .unwrap(),
        [&original]
    );

    let limit = Position::new(
        reaction.time_ps,
        reaction.microstep.checked_add(U64::new(1)).unwrap(),
        Phase::BoundaryControl,
    );
    let allowed = runtime
        .scheduler(&graph, &activation)
        .unwrap()
        .admit_boundary_settlement(&id("observer"), id("observer/allowed"), limit)
        .unwrap();
    let allowed = commit_native(&mut runtime, allowed);
    let observed = allowed.scheduling.as_ref().unwrap();
    assert_eq!(
        observed.input_progress.as_ref().unwrap().batch,
        id("observer/input/original")
    );
    assert_eq!(observed.input_progress.as_ref().unwrap().consumed.len(), 1);
    assert_eq!(observed.publications.len(), 1);
    assert_eq!(observed.publications[0].evaluation, Some(reaction));
    assert_eq!(observed.publications[0].causal_parents, [original.delivery]);
    assert!(observed.publications[0].publication >= limit);
    assert!(
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .pending_inputs(&id("observer"))
            .unwrap()
            .is_empty()
    );
    let body: serde_json::Value =
        serde_json::from_slice(&observed.publications[0].payload_bytes).unwrap();
    assert_eq!(body["kind"], "Satisfied");
    drop(runtime);
    reclaim(&catalog);
}
