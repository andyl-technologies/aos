//! Exercises authored demands against installed exact models and original native bytes.
//!
//! Predicate tests do not qualify new operations. Native cases use the existing
//! catalog's measured host models, enrolled immutable input artifacts and owning
//! ordinary observed executor; no archive or control authority is inferred.

// crucible-lint: allow panic-shortcut -- These fixtures deliberately fail on changed installed contracts or original native outcomes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};

use crucible::{
    AssertionDef, AssertionId, Predicate, Properties, Property,
    model::PropertyNamespace,
    node_adapters::{HostSemanticDefinition, ScriptedRequest, ScriptedRequestKind, ScriptedSource},
    node_contract::OperationOutcome,
};
use crucible_campaign::{
    ExecutionId,
    observed_node_attempt::{ObservedAttemptBackend, ObservedAttemptOutcome},
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};
use crucible_device::{BlockRequest, BlockResponse, BlockStatus};
use crucible_node_contract::{Bytes, CapabilityProfile, GuaranteeProfile};

use super::super::{
    InstalledHostIoProfile, InstalledHostSemanticProfile, InstalledIoArtifact, InstalledNodeKind,
    InstalledScriptedSourceProfile,
};
use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn demands(scenario: &NodeScenario) -> CapabilityRequirements {
    let mut requirements = CapabilityRequirements {
        format: crucible::node_admission::CAPABILITY_REQUIREMENTS_FORMAT.into(),
        schema_version: 1,
        nodes: Vec::new(),
    };
    for binding in &scenario.compatibility {
        let capabilities: CapabilityProfile =
            policy::object(scenario, &binding.capabilities_ref).unwrap();
        let guarantees: GuaranteeProfile =
            policy::object(scenario, &binding.guarantees_ref).unwrap();
        let exact = capabilities
            .facets
            .iter()
            .find(|facet| facet.id.as_str() == "host/exact-v1");
        let operations = if let Some(facet) = exact {
            ["boundary_settle", "exact_run"]
                .into_iter()
                .map(|operation| crucible::node_admission::OperationRequirement {
                    operation: id(operation),
                    facet: facet.clone(),
                })
                .collect()
        } else {
            let facet = capabilities
                .facets
                .iter()
                .find(|facet| facet.id.as_str() == "reference-device/quantized-v1")
                .unwrap();
            ["quantum_begin", "quantum_close"]
                .into_iter()
                .map(|operation| crucible::node_admission::OperationRequirement {
                    operation: id(operation),
                    facet: facet.clone(),
                })
                .collect()
        };
        requirements
            .nodes
            .push(crucible::node_admission::NodeCapabilityRequirement {
                node: binding.node_id.clone(),
                roles: scenario
                    .descriptors
                    .iter()
                    .find(|node| node.id == binding.node_id)
                    .unwrap()
                    .roles
                    .clone(),
                timing: crucible::node_admission::TimingRequirement {
                    mode: binding.operating_contract.mode,
                    resolution_ps: binding.operating_contract.resolution_ps,
                    phase_ps: binding.operating_contract.phase_ps,
                    policy_ref: binding.operating_contract.policy_ref.clone(),
                },
                operations,
                guarantees: crucible::node_admission::GuaranteeRequirement {
                    repeatability: guarantees.repeatability,
                    capture_scope: guarantees.capture_scope,
                    continuation: guarantees.continuation,
                    durable_restart: false,
                    isolated_fork: false,
                    conditional_replay: false,
                },
                compute: None,
                extensions: vec![],
            });
    }
    requirements
}

fn enroll(
    directory: &std::path::Path,
    name: &str,
    bytes: &[u8],
    media: &str,
) -> InstalledIoArtifact {
    let path = directory.join(name);
    std::fs::write(&path, bytes).unwrap();
    InstalledIoArtifact::path(path, canonical::content_ref(bytes, media).unwrap())
}

fn catalog(directory: &std::path::Path) -> InstalledNodeCatalog {
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    InstalledNodeCatalog::new(
        executable.clone(),
        super::super::measure_executable(&executable).unwrap(),
        directory.to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap()
}

fn storage_source(
    catalog: &mut InstalledNodeCatalog,
    directory: &std::path::Path,
) -> Vec<InstalledNodeSelection> {
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
    let script = enroll(directory, "script", &script, "application/octet-stream");
    let base = enroll(directory, "base", &[7, 8, 9], "application/octet-stream");
    catalog
        .install_artifacts(vec![base.clone(), script.clone()])
        .unwrap();
    vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("clock-owner"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("disk"),
            owner: id("disk-owner"),
            kind: InstalledNodeKind::HostIo {
                profile: InstalledHostIoProfile::Block {
                    base_image: base.expected,
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
                    script: script.expected,
                    consumer: id("disk"),
                },
            },
        },
    ]
}

fn add_semantics(
    catalog: &mut InstalledNodeCatalog,
    directory: &std::path::Path,
    selections: &mut Vec<InstalledNodeSelection>,
) {
    let namespace = PropertyNamespace::new(BTreeMap::new(), false, true, BTreeSet::new()).unwrap();
    let properties = Properties::from_assertions_for_namespace(
        &namespace,
        vec![AssertionDef {
            id: AssertionId::from_name("original-clock-observation"),
            message: "actual host clock evaluation".into(),
            property: Property::Sometimes {
                predicate: Predicate::at(crucible::VirtualTime { ticks: 2 }),
            },
        }],
    )
    .unwrap();
    let definition = HostSemanticDefinition {
        version: 2,
        properties: Bytes::new(properties.to_compact_binary()),
        inputs: Vec::new(),
    };
    let bytes = canonical::canonical_json(&serde_json::to_value(definition).unwrap()).unwrap();
    let program = enroll(directory, "assertions.json", &bytes, "application/json");
    catalog.install_artifacts(vec![program.clone()]).unwrap();
    selections.push(InstalledNodeSelection {
        node: id("observer"),
        owner: id("observer-owner"),
        kind: InstalledNodeKind::HostSemantics {
            profile: InstalledHostSemanticProfile {
                program: program.expected,
            },
        },
    });
    selections.sort_by(|left, right| left.node.cmp(&right.node));
}

// crucible-lint: allow clippy-disallowed-method -- One absolute host watchdog bounds the original native execution, never modeled time or a failed-test rerun.
// crucible-lint: allow rust-allow -- The diagnostic reason documents this fixture's host watchdog exception.
#[allow(
    clippy::disallowed_methods,
    reason = "Original native fixture polling has one absolute operational deadline"
)]
fn execute(
    catalog: &mut InstalledNodeCatalog,
    resolved: &ResolvedCapabilityWorld,
    directory: &std::path::Path,
    horizon: u64,
) -> Vec<OperationOutcome> {
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "host-exact-capabilities",
        directory.join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let execution = ExecutionId::from_bytes([112; 16]).unwrap();
    let mut backend = catalog
        .prepare_capability(
            resolved,
            crate::node_scenario::NodeRunConfiguration {
                format: "crucible.node-run-configuration".into(),
                version: 1,
                horizon_ps: horizon.into(),
                maximum_rounds: 64.into(),
            },
            execution,
            blobs.clone(),
            refs,
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    backend.start(&request).unwrap();
    let mut result = None;
    // Each poll advances one original execution or its genuine reclamation.
    // The absolute watchdog and poll cap never repeat a failed native command.
    for _ in 0..1024 {
        assert!(
            Instant::now() < deadline,
            "original native execution watchdog elapsed"
        );
        if let Some(completed) = backend.poll(execution).unwrap() {
            result = Some(completed);
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let result = result.expect("original native execution exceeded its finite poll budget");
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let bytes = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| serde_json::from_value(event.clone()).unwrap())
        .collect()
}

#[test]
#[ignore = "requires actual source-built companion identity and installed host model execution"]
fn authored_clock_script_and_block_demands_execute_original_native_results() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let selections = storage_source(&mut catalog, directory.path());

    let baseline = catalog.scenario(&selections).unwrap();
    let original = baseline.canonical_bytes().unwrap();
    let required = demands(&baseline);
    let raw = serde_json::to_vec_pretty(&required).unwrap();
    let resolved = catalog
        .resolve_capabilities_raw(
            &[InstalledCapabilityCandidate {
                id: id("installed/host-exact"),
                selections,
            }],
            &raw,
        )
        .unwrap();
    assert_eq!(resolved.requirements_bytes, raw);
    assert_eq!(baseline.canonical_bytes().unwrap(), original);
    assert_ne!(
        resolved.scenario().world.scenario_ref,
        baseline.world.scenario_ref
    );
    let outcomes = execute(&mut catalog, &resolved, directory.path(), 10_000);
    let publications = outcomes
        .iter()
        .flat_map(|outcome| outcome.scheduling.as_ref().unwrap().publications.iter())
        .collect::<Vec<_>>();
    let response = publications
        .iter()
        .find(|publication| publication.endpoint.node_id == id("disk"))
        .unwrap();
    let response = BlockResponse::decode(&response.payload_bytes).unwrap();
    assert_eq!(response.status, BlockStatus::Ok);
    assert_eq!(response.request_id, 71);
    assert_eq!(response.data, 3_u64.to_le_bytes());
    assert!(
        outcomes
            .iter()
            .any(|outcome| outcome.operation.as_str().ends_with("/source"))
    );
    assert!(
        outcomes
            .iter()
            .any(|outcome| outcome.operation.as_str().ends_with("/disk"))
    );
}

#[test]
#[ignore = "requires actual source-built companion identity and installed artifact validation"]
fn authored_host_demands_refuse_uninstalled_controls_changed_contracts_and_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let selections = storage_source(&mut catalog, directory.path());
    let scenario = catalog.scenario(&selections).unwrap();
    let required = demands(&scenario);
    let candidates = [InstalledCapabilityCandidate {
        id: id("installed/host-exact"),
        selections: selections.clone(),
    }];
    let disk = required
        .nodes
        .iter()
        .position(|node| node.node == id("disk"))
        .unwrap();
    for operation in [
        "capture",
        "durable_restart",
        "debug",
        "fault_injection",
        "conditional_replay",
        "isolated_fork",
        "physical_pause",
    ] {
        let mut changed = required.clone();
        changed.nodes[disk].operations[0].operation = id(operation);
        assert!(
            catalog.resolve_capabilities(&candidates, changed).is_err(),
            "unexpected control enrollment: {operation}"
        );
    }
    let mut changed = required.clone();
    changed.nodes[disk].operations[0].facet.configuration_ref = scenario.world.scenario_ref.clone();
    assert!(catalog.resolve_capabilities(&candidates, changed).is_err());
    let mut changed = required.clone();
    changed.nodes[disk].operations[0].facet.version = 2;
    assert!(catalog.resolve_capabilities(&candidates, changed).is_err());
    let mut changed = required.clone();
    changed.nodes[disk].guarantees.durable_restart = true;
    assert!(catalog.resolve_capabilities(&candidates, changed).is_err());
    let mut changed = candidates.to_vec();
    let InstalledNodeKind::HostIo {
        profile: InstalledHostIoProfile::Block { base_image, .. },
    } = &mut changed[0].selections[disk].kind
    else {
        panic!("disk profile missing")
    };
    *base_image = canonical::content_ref(b"uninstalled base", "application/octet-stream").unwrap();
    assert!(
        catalog
            .resolve_capabilities(&changed, required.clone())
            .is_err()
    );
    std::fs::write(directory.path().join("script"), b"changed enrolled source").unwrap();
    assert!(catalog.resolve_capabilities(&candidates, required).is_err());
}

#[test]
#[ignore = "requires two actual source-built native octet peers and installed exact link"]
fn authored_link_demand_preserves_original_native_octets_in_mixed_execution() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let selections = vec![
        InstalledNodeSelection {
            node: id("a-producer"),
            owner: id("producer-owner"),
            kind: InstalledNodeKind::ReferenceNativeLinked {
                quantum_ps: 50.into(),
                host_budget_ns: 20_000_000.into(),
                closed_ingress: true,
            },
        },
        InstalledNodeSelection {
            node: id("b-link"),
            owner: id("link-owner"),
            kind: InstalledNodeKind::HostNetLink {
                producer: id("a-producer"),
                consumer: id("c-consumer"),
                source_node: 7,
                latency_ps: 10.into(),
                floor_ps: 10.into(),
            },
        },
        InstalledNodeSelection {
            node: id("c-consumer"),
            owner: id("consumer-owner"),
            kind: InstalledNodeKind::ReferenceNativeLinked {
                quantum_ps: 50.into(),
                host_budget_ns: 20_000_000.into(),
                closed_ingress: false,
            },
        },
    ];
    let baseline = catalog.scenario(&selections).unwrap();
    let required = demands(&baseline);
    let resolved = catalog
        .resolve_capabilities(
            &[InstalledCapabilityCandidate {
                id: id("installed/native-linked"),
                selections,
            }],
            required,
        )
        .unwrap();
    let outcomes = execute(&mut catalog, &resolved, directory.path(), 150);
    let publications = outcomes
        .iter()
        .flat_map(|outcome| outcome.scheduling.as_ref().unwrap().publications.iter())
        .collect::<Vec<_>>();
    let original = publications
        .iter()
        .find(|publication| publication.endpoint.node_id == id("a-producer"))
        .unwrap();
    let transferred = publications
        .iter()
        .find(|publication| publication.endpoint.node_id == id("b-link"))
        .unwrap();
    assert_eq!(transferred.payload_bytes, original.payload_bytes);
    assert!(transferred.evaluation.unwrap().time_ps > original.publication.time_ps);
    let consumer = publications.iter().find(|publication| {
        publication.endpoint.node_id == id("c-consumer")
                && serde_json::from_slice::<serde_json::Value>(&publication.payload_bytes).unwrap()
                    ["bytes_processed"]
                    .as_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
                    > 0
    });
    assert!(
        consumer.is_some(),
        "actual consumer did not consume the original linked bytes"
    );
}

#[test]
#[ignore = "requires installed no-ingress semantic model and source-built companion identity"]
fn authored_semantic_clock_demand_executes_the_original_installed_evaluator() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let mut selections = vec![InstalledNodeSelection {
        node: id("clock"),
        owner: id("clock-owner"),
        kind: InstalledNodeKind::HostClock,
    }];
    add_semantics(&mut catalog, directory.path(), &mut selections);
    let baseline = catalog.scenario(&selections).unwrap();
    let required = demands(&baseline);
    let resolved = catalog
        .resolve_capabilities(
            &[InstalledCapabilityCandidate {
                id: id("installed/semantic-exact"),
                selections,
            }],
            required,
        )
        .unwrap();
    let outcomes = execute(&mut catalog, &resolved, directory.path(), 10);
    let publications = outcomes
        .iter()
        .flat_map(|outcome| outcome.scheduling.as_ref().unwrap().publications.iter())
        .collect::<Vec<_>>();
    let assertion = publications
        .iter()
        .find(|publication| publication.endpoint.node_id == id("observer"))
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&assertion.payload_bytes).unwrap();
    assert_eq!(value["kind"], "Satisfied");
}
