//! No-effect measured CPU demand checks beneath unchanged native/class gates.

// crucible-lint: allow panic-shortcut -- These controls deliberately panic on a failed source/demand or refusal invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use crucible_engine::node_admission::{
    AdmissionEvidence, CAPABILITY_REQUIREMENTS_FORMAT, CapabilityRequirements, EvidenceError,
    GuaranteeRequirement, NodeCapabilityRequirement, OperationRequirement, QualificationClaim,
    TimingRequirement,
};
use crucible_node_format::{
    CapabilityProfile, ContentRef, GuaranteeProfile, Id, ImplementationIdentity, LiveAuthority,
    NodeBinding, SchemaRef, U64, canonical,
};

use super::super::{InstalledGem5Isa, InstalledNodeKind, InstalledNodeSelection};
use super::{InstalledCapabilityCandidate, InstalledNodeCatalog, ResolvedCapabilityWorld, policy};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn catalog(directory: &std::path::Path) -> InstalledNodeCatalog {
    // The unused device slot is measured test host code. These controls never
    // call native preparation, publish Ready or run any guest/controller child.
    let executable = std::env::current_exe().unwrap();
    let expected = super::super::measure_executable(&executable).unwrap();
    InstalledNodeCatalog::new(
        executable,
        expected,
        directory.into(),
        Duration::from_secs(2),
        1,
    )
    .unwrap()
}

fn selections(isa: InstalledGem5Isa) -> Vec<InstalledNodeSelection> {
    vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("owner/clock"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("cpu"),
            owner: id("owner/cpu"),
            kind: InstalledNodeKind::Gem5Closed { isa },
        },
    ]
}

fn requirements(
    scenario: &crate::node_scenario::NodeScenario,
    compute: crucible_engine::node_admission::ComputeRequirement,
) -> CapabilityRequirements {
    CapabilityRequirements {
        format: CAPABILITY_REQUIREMENTS_FORMAT.into(),
        schema_version: 1,
        nodes: scenario
            .compatibility
            .iter()
            .map(|binding| {
                let capability: CapabilityProfile =
                    policy::object(scenario, &binding.capabilities_ref).unwrap();
                let guarantee: GuaranteeProfile =
                    policy::object(scenario, &binding.guarantees_ref).unwrap();
                let descriptor = scenario
                    .descriptors
                    .iter()
                    .find(|node| node.id == binding.node_id)
                    .unwrap();
                let profile = if binding.node_id.as_str() == "cpu" {
                    crucible_engine::node_adapters::gem5::GEM5_CLOSED_EXACT_PROFILE
                } else {
                    "host/exact-v1"
                };
                let facet = capability
                    .facets
                    .iter()
                    .find(|facet| facet.id.as_str() == profile)
                    .unwrap();
                NodeCapabilityRequirement {
                    node: binding.node_id.clone(),
                    roles: descriptor.roles.clone(),
                    timing: TimingRequirement {
                        mode: binding.operating_contract.mode,
                        resolution_ps: binding.operating_contract.resolution_ps,
                        phase_ps: binding.operating_contract.phase_ps,
                        policy_ref: binding.operating_contract.policy_ref.clone(),
                    },
                    operations: ["boundary_settle", "exact_run"]
                        .into_iter()
                        .map(|operation| OperationRequirement {
                            operation: id(operation),
                            facet: facet.clone(),
                        })
                        .collect(),
                    guarantees: GuaranteeRequirement {
                        repeatability: guarantee.repeatability,
                        capture_scope: guarantee.capture_scope,
                        continuation: guarantee.continuation,
                        durable_restart: false,
                        isolated_fork: false,
                        conditional_replay: false,
                    },
                    compute: (binding.node_id.as_str() == "cpu").then(|| compute.clone()),
                    extensions: vec![],
                }
            })
            .collect(),
    }
}

fn measured(
    isa: InstalledGem5Isa,
) -> (
    tempfile::TempDir,
    InstalledNodeCatalog,
    ResolvedCapabilityWorld,
) {
    let directory = tempfile::tempdir().unwrap();
    let catalog = catalog(directory.path());
    let selected = selections(isa);
    let baseline = catalog.scenario(&selected).unwrap();
    let definition = catalog
        .installed_compute_requirement(&selected, &id("cpu"))
        .unwrap();
    let demands = requirements(&baseline, definition);
    let resolved = catalog
        .resolve_capabilities(
            &[InstalledCapabilityCandidate {
                id: id("measured-se"),
                selections: selected,
            }],
            demands,
        )
        .unwrap();
    (directory, catalog, resolved)
}

#[test]
fn no_measured_source_can_be_inferred_from_compute_metadata() {
    let scenario = super::tests::requirements(&super::tests::model_clock());
    let mut demand = scenario.nodes[0].clone();
    demand.compute = Some(crucible_engine::node_admission::ComputeRequirement {
        architecture: id(super::compute::GEM5_CLOSED_X86_COMPUTE),
        machine_ref: demand.timing.policy_ref.clone(),
        devices_ref: demand.timing.policy_ref.clone(),
    });
    let kind = InstalledNodeKind::HostClock;
    assert!(policy::qualify_kind(&kind, &demand, false, false, false).is_err());
}

#[test]
#[ignore = "requires the compile-time source-built gem5 closed profile; reads only, no native child"]
fn actual_measured_fixed_se_architectures_satisfy_exact_compute_demands() {
    for isa in [InstalledGem5Isa::X86_64, InstalledGem5Isa::Aarch64] {
        let (_directory, _catalog, resolved) = measured(isa);
        policy::matches_with_compute(
            &resolved.candidate.selections,
            &resolved.scenario,
            &resolved.requirements,
            &resolved.compute,
        )
        .unwrap();
        // No qualifier is minted by copying exactly equal demand fields.
        assert!(
            policy::matches(
                &resolved.candidate.selections,
                &resolved.scenario,
                &resolved.requirements,
            )
            .is_err()
        );
    }
}

#[test]
#[ignore = "requires the compile-time source-built gem5 closed profile; reads only, no native child"]
fn actual_measured_compute_scope_refuses_foreign_definitions_and_worlds() {
    let (_directory, _catalog, resolved) = measured(InstalledGem5Isa::X86_64);
    let original = resolved
        .requirements
        .nodes
        .iter()
        .find(|node| node.node.as_str() == "cpu")
        .unwrap();
    let selected = &resolved.candidate.selections[1];
    let mut changed = original.clone();
    changed.compute.as_mut().unwrap().architecture = id(super::compute::GEM5_CLOSED_ARM_COMPUTE);
    assert!(
        resolved
            .compute
            .authenticate(&resolved.scenario, selected, &changed)
            .is_err()
    );
    changed = original.clone();
    changed.compute.as_mut().unwrap().devices_ref.hash.digest = "0".repeat(64);
    assert!(
        resolved
            .compute
            .authenticate(&resolved.scenario, selected, &changed)
            .is_err()
    );
    changed = original.clone();
    changed.compute.as_mut().unwrap().machine_ref.hash.digest = "0".repeat(64);
    assert!(
        resolved
            .compute
            .authenticate(&resolved.scenario, selected, &changed)
            .is_err()
    );

    let mut foreign = resolved.scenario.clone();
    foreign.world.coordinator_contract_ref.hash.digest = "0".repeat(64);
    assert!(
        resolved
            .compute
            .authenticate(&foreign, selected, original)
            .is_err()
    );
    foreign = resolved.scenario.clone();
    foreign.compatibility[1].implementation.artifacts[0]
        .content
        .hash
        .digest = "0".repeat(64);
    assert!(
        resolved
            .compute
            .authenticate(&foreign, selected, original)
            .is_err()
    );
    foreign = resolved.scenario.clone();
    let model = foreign
        .descriptors
        .iter()
        .find(|node| node.id.as_str() == "cpu")
        .unwrap()
        .model_ref
        .clone();
    foreign
        .content
        .iter_mut()
        .find(|object| object.reference == model)
        .unwrap()
        .bytes[0] ^= 1;
    assert!(
        resolved
            .compute
            .authenticate(&foreign, selected, original)
            .is_err()
    );

    let mut wrong_selection = selected.clone();
    wrong_selection.kind = InstalledNodeKind::Gem5Closed {
        isa: InstalledGem5Isa::Aarch64,
    };
    assert!(
        resolved
            .compute
            .authenticate(&resolved.scenario, &wrong_selection, original)
            .is_err()
    );
}

#[test]
#[ignore = "requires the compile-time source-built gem5 closed profile; reads only, no native child"]
fn source_compute_proof_cannot_widen_operations_or_reuse_equal_borrowed_data() {
    let (_directory, _catalog, resolved) = measured(InstalledGem5Isa::X86_64);
    let demand = resolved
        .requirements
        .nodes
        .iter()
        .find(|node| node.node.as_str() == "cpu")
        .unwrap();
    let selected = &resolved.candidate.selections[1];
    let proof = resolved
        .compute
        .authenticate(&resolved.scenario, selected, demand)
        .unwrap()
        .unwrap();
    let copied = demand.clone();
    assert!(!proof.authenticates(&selected.kind, &copied));
    assert!(proof.authenticates(&selected.kind, demand));

    let mut changed = resolved.requirements.clone();
    changed
        .nodes
        .iter_mut()
        .find(|node| node.node.as_str() == "cpu")
        .unwrap()
        .operations[0]
        .operation = id("physical_pause");
    assert!(
        policy::matches_with_compute(
            &resolved.candidate.selections,
            &resolved.scenario,
            &changed,
            &resolved.compute,
        )
        .is_err()
    );
    let cpu = changed
        .nodes
        .iter_mut()
        .find(|node| node.node.as_str() == "cpu")
        .unwrap();
    cpu.operations[0].operation = id("boundary_settle");
    cpu.guarantees.isolated_fork = true;
    assert!(
        policy::matches_with_compute(
            &resolved.candidate.selections,
            &resolved.scenario,
            &changed,
            &resolved.compute,
        )
        .is_err()
    );
}

struct NoNativeAuthority;

impl AdmissionEvidence for NoNativeAuthority {
    fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
        Err(EvidenceError {
            message: "no original immutable authority in this control".into(),
        })
    }
    fn authenticate_implementation(&self, _: &ImplementationIdentity) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "no accepted original implementation".into(),
        })
    }
    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "no actual original live owner".into(),
        })
    }
    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "no installed native scope".into(),
        })
    }
    fn qualify(&self, _: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "no independent accepted class".into(),
        })
    }
}

#[test]
#[ignore = "requires the compile-time source-built gem5 closed profile; reads only, no native child"]
fn actual_measured_compute_does_not_replace_live_authority_or_class_acceptance() {
    let (_directory, _catalog, resolved) = measured(InstalledGem5Isa::X86_64);
    let cpu = resolved
        .scenario
        .compatibility
        .iter()
        .find(|node| node.node_id.as_str() == "cpu")
        .unwrap();
    let demand = resolved
        .requirements
        .nodes
        .iter()
        .find(|node| node.node.as_str() == "cpu")
        .unwrap();
    let binding = NodeBinding {
        compatibility: cpu.clone(),
        authority: LiveAuthority {
            schema_version: 1,
            session_id: id("modeled-session"),
            incarnation_id: id("modeled-incarnation"),
            realization_id: id("modeled-realization"),
            activation_id: None,
            world_generation: U64::new(0),
            owner_generation: U64::new(1),
            input_epoch: id("modeled-input"),
            host_receipt: canonical::content_ref(b"modeled receipt", "application/json").unwrap(),
            extensions: Default::default(),
        },
        extensions: Default::default(),
    };
    let evidence = super::admission::CapabilityAdmission {
        original: &NoNativeAuthority,
        resolved: &resolved,
    };
    assert!(
        evidence
            .qualify_capability(&resolved.scenario.world, &binding, demand)
            .is_err()
    );
    let hash = cpu.identity().unwrap();
    assert!(
        evidence
            .qualify(QualificationClaim::Node {
                binding: cpu,
                binding_hash: &hash,
                qualification_refs: &cpu.qualification_refs,
            })
            .is_err()
    );
}
