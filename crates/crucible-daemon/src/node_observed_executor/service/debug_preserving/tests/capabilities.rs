//! Exercises original authored demands through the actual preserving CLI actor.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Original demand, native suffix and owning reclamation mismatches deliberately fail the fixture.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_observed_executor::{InstalledIoArtifact, InstalledNodeCatalog};
use crate::node_scenario::NodeScenario;
use crucible::node_admission::{
    CapabilityRequirements, ComputeRequirement, GuaranteeRequirement, NodeCapabilityRequirement,
    OperationRequirement, TimingRequirement,
};
use crucible_node_contract::{CapabilityProfile, GuaranteeProfile};

fn demands(scenario: &NodeScenario) -> CapabilityRequirements {
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
        let guarantees: GuaranteeProfile =
            serde_json::from_slice(body(&binding.guarantees_ref)).unwrap();
        let facet = |name: &str| {
            capabilities
                .facets
                .iter()
                .find(|facet| facet.id.as_str() == name)
                .unwrap()
                .clone()
        };
        let mut operations = vec![
            OperationRequirement {
                operation: id("capture"),
                facet: facet("host/condition-preservation-v1"),
            },
            OperationRequirement {
                operation: id("durable_restart"),
                facet: facet("host/condition-preservation-v1"),
            },
        ];
        if binding.node_id == id("observer") {
            operations.extend([
                OperationRequirement {
                    operation: id("condition_stop"),
                    facet: facet("host/condition-debug-v1"),
                },
                OperationRequirement {
                    operation: id("condition_resume"),
                    facet: facet("host/condition-debug-v1"),
                },
            ]);
        } else {
            operations.push(OperationRequirement {
                operation: id("exact_run"),
                facet: facet("host/exact-v1"),
            });
        }
        operations.sort_by(|left, right| left.operation.cmp(&right.operation));
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
                repeatability: guarantees.repeatability,
                capture_scope: guarantees.capture_scope,
                continuation: guarantees.continuation,
                durable_restart: true,
                isolated_fork: false,
                conditional_replay: false,
            },
            compute: None,
            extensions: Vec::new(),
        });
    }
    CapabilityRequirements {
        format: crucible::node_admission::CAPABILITY_REQUIREMENTS_FORMAT.into(),
        schema_version: 1,
        nodes,
    }
}

fn catalog(directory: &Path, artifacts: &[NodeImmutableArtifactPolicy]) -> InstalledNodeCatalog {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    catalog
        .install_artifacts(
            artifacts
                .iter()
                .map(|artifact| {
                    let NodeImmutableArtifactPolicy::Path { path, expected } = artifact else {
                        panic!("original enrollment must be independently measured")
                    };
                    InstalledIoArtifact::path(path.clone(), expected.clone())
                })
                .collect(),
        )
        .unwrap();
    catalog
}

fn refuse_unsupported(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    original: &CapabilityRequirements,
) {
    for axis in 0..7 {
        let mut changed = original.clone();
        match axis {
            0 => changed.nodes[0].guarantees.isolated_fork = true,
            1 => changed.nodes[0].guarantees.conditional_replay = true,
            2 => changed.nodes[0].operations[0].operation = id("physical_pause"),
            3 => changed.nodes[0].operations[0].facet.version += 1,
            4 => {
                changed.nodes[0].compute = Some(ComputeRequirement {
                    architecture: id("aarch64"),
                    machine_ref: changed.nodes[0].timing.policy_ref.clone(),
                    devices_ref: changed.nodes[0].timing.policy_ref.clone(),
                })
            }
            5 => {
                changed.nodes.remove(0);
            }
            _ => {
                changed.nodes[0].operations[0].facet.configuration_ref =
                    changed.nodes[0].timing.policy_ref.clone()
            }
        }
        changed.nodes.iter_mut().for_each(|node| {
            node.operations
                .sort_by(|left, right| left.operation.cmp(&right.operation))
        });
        let raw = serde_json::to_vec(&changed).unwrap();
        assert!(
            catalog
                .resolve_condition_capabilities(selections, &raw)
                .is_err(),
            "axis {axis}"
        );
        assert_eq!(catalog.custody().retained_worlds(), 0);
    }
}

#[test]
#[ignore = "requires actual source-built installed host catalog and matching preserving CLI"]
fn authored_condition_demands_capture_source_gone_twins_and_original_suffix_once() {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!(
        "capability preserving original custody: {}",
        directory.display()
    );
    let (selections, artifacts) = fixture(&directory);
    let installed = catalog(&directory, &artifacts);
    let baseline = installed.scenario(&selections).unwrap();
    let requirements = demands(&baseline);
    refuse_unsupported(&installed, &selections, &requirements);
    let raw = serde_json::to_vec_pretty(&requirements).unwrap();
    let resolved = installed
        .resolve_condition_capabilities(&selections, &raw)
        .unwrap();
    assert_ne!(
        resolved.scenario().world.scenario_ref,
        baseline.world.scenario_ref
    );
    std::fs::write(directory.join("authored-requirements.json"), &raw).unwrap();
    let original_policy = policy(&directory, artifacts.clone());
    let server = Server::start(original_policy.clone());
    let request = NodePreservingDebugRequest {
        format: "crucible.preserving-debug-request".into(),
        version: 2,
        requirements: Some(Bytes::new(raw.clone())),
        execution: "11111111111111111111111111111111".into(),
        selections,
        scenario: Bytes::new(resolved.scenario().canonical_bytes().unwrap()),
        observer: id("observer"),
        maximum_physical_cut: 2_000_000.into(),
        maximum_record_bytes: (32 << 20).into(),
        action: NodePreservingDebugAction::Capture {},
    };
    let stopped = adverse::prepare_cli(&server, &directory, request.clone());
    let capture = stopped.capture.clone().unwrap();
    std::fs::write(
        directory.join("source-stopped.json"),
        encode(&stopped).unwrap(),
    )
    .unwrap();
    adverse::refuse_original_nonce_change(&server, &directory, &request);
    let original = adverse::resume_cli(&server, &directory, &request.execution);
    let suffix = native_suffix(&publications(&directory, &original), capture.cut);
    assert_eq!(suffix.len(), 2);
    let read = BlockResponse::decode(&suffix[1].3).unwrap();
    assert_eq!(read.request_id, 9);
    assert_eq!(read.data, vec![0x6d; 64]);
    drop(server);
    drop(installed);

    let mut restored_policy = original_policy;
    restored_policy.immutable_artifacts = artifacts
        .into_iter()
        .map(|artifact| {
            let NodeImmutableArtifactPolicy::Path { path, expected } = artifact else {
                unreachable!()
            };
            std::fs::remove_file(path).unwrap();
            NodeImmutableArtifactPolicy::ArchiveOnly {
                mode: NodeArchiveArtifactMode::ArchiveOnly,
                expected,
            }
        })
        .collect();
    let server = Server::start(restored_policy);
    let mut targets = Vec::new();
    for execution in [
        "22222222222222222222222222222222",
        "33333333333333333333333333333333",
    ] {
        let mut target = request.clone();
        target.execution = execution.into();
        target.action = NodePreservingDebugAction::Restore {
            source_execution: request.execution.clone(),
            capture: capture.artifact.clone(),
        };
        assert_eq!(
            server.prepare(target.clone()).capture.as_ref(),
            Some(&capture)
        );
        targets.push(target);
    }
    for target in &targets {
        let result = adverse::resume_cli(&server, &directory, &target.execution);
        assert_eq!(
            native_suffix(&publications(&directory, &result), capture.cut),
            suffix
        );
        assert_eq!(
            server.resume(&target.execution).resume_request,
            result.resume_request
        );
        std::fs::write(
            directory.join(format!("target-{}.json", target.execution)),
            encode(&result).unwrap(),
        )
        .unwrap();
    }
    assert!(!directory.join("base").exists());
    assert!(!directory.join("script").exists());
    assert!(!directory.join("condition").exists());
    adverse::refuse_changed_current_report(&server, &directory, &request, &capture);
    drop(server);
}

#[test]
fn legacy_request_omits_capabilities_and_explicit_null_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let (selections, _) = fixture(directory.path());
    let request = NodePreservingDebugRequest {
        format: "crucible.preserving-debug-request".into(),
        version: 1,
        requirements: None,
        execution: "44444444444444444444444444444444".into(),
        selections,
        scenario: Bytes::new(b"inert request geometry".to_vec()),
        observer: id("observer"),
        maximum_physical_cut: 2_000_000.into(),
        maximum_record_bytes: (32 << 20).into(),
        action: NodePreservingDebugAction::Capture {},
    };
    request.validate().unwrap();
    let original = encode(&request).unwrap();
    let mut value = serde_json::to_value(&request).unwrap();
    assert!(value.get("requirements").is_none());
    let decoded = NodePreservingDebugRequest::from_json(&original).unwrap();
    assert_eq!(encode(&decoded).unwrap(), original);
    value["requirements"] = serde_json::Value::Null;
    assert!(NodePreservingDebugRequest::from_json(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut changed = request;
    changed.requirements = Some(Bytes::new(b"{}".to_vec()));
    assert!(changed.validate().is_err());
    changed.version = 2;
    changed.requirements = None;
    assert!(changed.validate().is_err());
}
