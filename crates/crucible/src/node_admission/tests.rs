//! Exercises whole-graph admission with an explicit trusted test evidence store.

// crucible-lint: allow panic-shortcut -- These node admission tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible_node_contract::*;
use serde::Serialize;

use super::*;
use crate::node_scheduling::{ExactCeiling, ExecutionPolicy};

// Matches the selected installed Host envelope definition, rather than treating
// the test byte-lane schema as native continuation qualification.
const HOST_NATIVE_SCHEMA: &[u8] = concat!(
    "crucible installed host native continuation envelope v1: ",
    "bounded complete host model cursor and codec; ",
    "original native request/outcome/input/evidence receipt registries; ",
    "causal cut, publication FIFO sequence and pending progress; ",
    "authentic whole-world runtime/scheduler closure retained separately; ",
    "no raw imported JSON grants authority",
)
.as_bytes();

#[derive(Default)]
struct Evidence {
    blobs: BTreeMap<String, Vec<u8>>,
    reject_qualification: bool,
    reject_authority: bool,
    reject_schema: bool,
}

impl Evidence {
    fn put(&mut self, value: &impl Serialize) -> ContentRef {
        self.bytes(serde_json::to_vec(value).unwrap())
    }

    fn bytes(&mut self, bytes: Vec<u8>) -> ContentRef {
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        self.blobs.insert(reference.hash.digest.clone(), bytes);
        reference
    }
}

impl AdmissionEvidence for Evidence {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        let bytes = self
            .blobs
            .get(&reference.hash.digest)
            .ok_or_else(|| EvidenceError {
                message: "missing content".into(),
            })?;
        if bytes.len() > maximum_bytes {
            return Err(EvidenceError {
                message: "fetch ceiling".into(),
            });
        }
        Ok(bytes.clone())
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        if implementation.implementation_id != id("test.qualified") {
            return Err(EvidenceError {
                message: "unknown installed implementation".into(),
            });
        }
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        if self.reject_authority || binding.authority.session_id != id("host.session") {
            return Err(EvidenceError {
                message: "actual live custody unavailable".into(),
            });
        }
        Ok(())
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        let installed_host_codec = schema.id == id("host/native-continuation-v1")
            && schema.definition
                == canonical::content_ref(HOST_NATIVE_SCHEMA, "text/plain").unwrap()
            && schema.extensions.is_empty();
        if self.reject_schema
            || !([id("test.bytes"), id("crucible/block-request-v1")].contains(&schema.id)
                || installed_host_codec)
            || schema.version != 1
        {
            return Err(EvidenceError {
                message: "no installed schema validator".into(),
            });
        }
        Ok(())
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        if self.reject_qualification {
            return Err(EvidenceError {
                message: "qualification rejected".into(),
            });
        }
        if let QualificationClaim::Scenario {
            scenario_ref,
            requirements_hash,
            ..
        } = claim
        {
            let bytes = self
                .blobs
                .get(&scenario_ref.hash.digest)
                .ok_or_else(|| EvidenceError {
                    message: "missing scenario".into(),
                })?;
            let requirements: ScenarioRequirements =
                serde_json::from_slice(bytes).map_err(|error| EvidenceError {
                    message: error.to_string(),
                })?;
            let expected = canonical::json_hash("cnp.admission-requirements.v1", &requirements)
                .map_err(|error| EvidenceError {
                    message: error.to_string(),
                })?;
            if expected != *requirements_hash {
                return Err(EvidenceError {
                    message: "scenario acceptance substituted".into(),
                });
            }
        }
        // This store is an intentionally trusted model fixture, not production
        // evidence for any QEMU, gem5, KVM, or external-device realization.
        Ok(())
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

pub(super) fn admitted_fixture_with_content() -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    let fixture = Fixture::new();
    let admitted = fixture.admit(AdmissionLimits::default()).unwrap();
    (admitted, fixture.evidence.blobs)
}

pub(super) fn nondeterministic_fixture_with_content() -> (AdmittedGraph, BTreeMap<String, Vec<u8>>)
{
    let mut fixture = Fixture::new();
    fixture.requirements.deterministic = false;
    fixture.requirements.accepted_nondeterministic_nodes = vec![id("a")];
    fixture.guarantee(0, |guarantee| {
        guarantee.repeatability = Repeatability::Nondeterministic
    });
    let admitted = fixture.admit(AdmissionLimits::default()).unwrap();
    (admitted, fixture.evidence.blobs)
}

#[cfg(test)]
pub(super) fn restore_fixture_with_content(
    nondeterministic: bool,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    let mut fixture = Fixture::new();
    if nondeterministic {
        fixture.requirements.deterministic = false;
        fixture.requirements.accepted_nondeterministic_nodes = vec![id("a")];
        fixture.guarantee(0, |guarantee| {
            guarantee.repeatability = Repeatability::Nondeterministic
        });
    }
    for binding in &mut fixture.bindings {
        binding.authority.owner_generation = 2.into();
        binding.authority.incarnation_id =
            id(&format!("live/restored-{}", binding.compatibility.node_id));
    }
    let admitted = fixture.admit(AdmissionLimits::default()).unwrap();
    (admitted, fixture.evidence.blobs)
}

#[cfg(test)]
pub(super) fn execution_fixture_with_content(
    shared_writers: bool,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    let fixture = execution_fixture(shared_writers, false);
    let admitted = fixture.admit(AdmissionLimits::default()).unwrap();
    (admitted, fixture.evidence.blobs)
}

#[cfg(test)]
pub(super) fn isolated_execution_fixture_with_content(
    shared_writers: bool,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    let fixture = execution_fixture(shared_writers, true);
    let admitted = fixture.admit(AdmissionLimits::default()).unwrap();
    (admitted, fixture.evidence.blobs)
}

#[cfg(test)]
fn execution_fixture(shared_writers: bool, isolated: bool) -> Fixture {
    let mut fixture = Fixture::new();
    let proof = fixture.ownership.inventory_proof_ref.clone();
    let facet = FacetSelection {
        id: id("test-execution"),
        version: 1,
        configuration_ref: proof.clone(),
        guarantees_ref: proof,
        extensions: Extensions::new(),
    };
    for binding in &mut fixture.bindings {
        let reference = &binding.compatibility.capabilities_ref;
        let mut capability: CapabilityProfile =
            serde_json::from_slice(fixture.evidence.blobs.get(&reference.hash.digest).unwrap())
                .unwrap();
        capability.facets = vec![facet.clone()];
        binding.compatibility.capabilities_ref = fixture.evidence.put(&capability);
        binding.compatibility.operating_contract.facets = vec![facet.clone()];
    }
    if shared_writers {
        fixture.ownership.domains[1]
            .execution_owner_ids
            .push(id("owner/z"));
        fixture.owners[1]
            .owner
            .state_domain_ids
            .insert(0, id("domain/transfer"));
        fixture.bindings[1].compatibility.execution_owner = fixture.owners[1].owner.clone();
        fixture.bindings[1].compatibility.capture_owner = fixture.owners[1].owner.clone();
    }
    if isolated {
        fixture.world.connections.clear();
        fixture.coordinator.external_inputs.clear();
        for descriptor in &mut fixture.descriptors {
            descriptor.ports.clear();
        }
    }
    fixture.refresh();
    fixture
}

#[cfg(test)]
pub(super) fn host_clock_fixture_with_content() -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    host_clock_fixture(false, false)
}

#[cfg(test)]
pub(super) fn host_clock_execution_fixture_with_content()
-> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    host_clock_fixture(true, false)
}

#[cfg(test)]
pub(super) fn host_clock_restore_fixture_with_content() -> (AdmittedGraph, BTreeMap<String, Vec<u8>>)
{
    host_clock_fixture(true, true)
}

#[cfg(test)]
fn host_clock_fixture(
    execution: bool,
    restored: bool,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    let mut fixture = execution_fixture(false, true);
    let proof = fixture.ownership.inventory_proof_ref.clone();
    let mut facet_names = vec!["host/physical-pause-v1", "host/preservation-v1"];
    if execution {
        facet_names.insert(0, "host/exact-v1");
    }
    let facets = facet_names
        .into_iter()
        .map(|name| FacetSelection {
            id: id(name),
            version: 1,
            configuration_ref: proof.clone(),
            guarantees_ref: proof.clone(),
            extensions: Extensions::new(),
        })
        .collect::<Vec<_>>();
    let mut initialization = b"crucible.host-clock.v1\0".to_vec();
    initialization.extend_from_slice(&0u64.to_le_bytes());
    let initialization_ref =
        canonical::content_ref(&initialization, "application/octet-stream").unwrap();
    fixture
        .evidence
        .blobs
        .insert(initialization_ref.hash.digest.clone(), initialization);
    for descriptor in &mut fixture.descriptors {
        descriptor.roles = vec![id("clock")];
        descriptor.initialization_ref = initialization_ref.clone();
    }
    for binding in &mut fixture.bindings {
        let reference = &binding.compatibility.capabilities_ref;
        let mut capability: CapabilityProfile =
            serde_json::from_slice(fixture.evidence.blobs.get(&reference.hash.digest).unwrap())
                .unwrap();
        capability.facets = facets.clone();
        binding.compatibility.capabilities_ref = fixture.evidence.put(&capability);
        binding.compatibility.operating_contract.facets = facets.clone();
        if restored {
            binding.authority.owner_generation = 2.into();
            binding.authority.incarnation_id =
                id(&format!("live/restored-{}", binding.compatibility.node_id));
        }
    }
    fixture.refresh();
    let admitted = fixture.admit(AdmissionLimits::default()).unwrap();
    (admitted, fixture.evidence.blobs)
}

#[cfg(test)]
pub(super) fn host_model_fixture_with_content(
    role: &str,
    initialization: Vec<u8>,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    host_model_fixture(role, initialization, false)
}

#[cfg(test)]
pub(super) fn host_model_restore_fixture_with_content(
    role: &str,
    initialization: Vec<u8>,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    host_model_fixture(role, initialization, true)
}

#[cfg(test)]
fn host_model_fixture(
    role: &str,
    initialization: Vec<u8>,
    restored: bool,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    host_model_fixture_parameters(role, initialization, restored, false, 2)
}

#[cfg(test)]
pub(super) fn host_initial_queue_fixture_with_content(
    role: &str,
    initialization: Vec<u8>,
    generation: u64,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    assert!(generation > 0);
    host_model_fixture_parameters(role, initialization, generation > 1, true, generation)
}

#[cfg(test)]
fn host_model_fixture_parameters(
    role: &str,
    initialization: Vec<u8>,
    restored: bool,
    initial_queue: bool,
    generation: u64,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    let mut fixture = execution_fixture(false, false);
    fixture.world.connections.clear();
    if initial_queue {
        // Native queued work is committed by the immutable initialization.
        // The remaining input codec is internal to this indivisible native
        // owner, with no public ingress or unobserved external producer.
        fixture.coordinator.external_inputs.clear();
        let policy_ref = &fixture.descriptors[0].ports[0].configuration_ref;
        let mut policy: PortPolicy =
            serde_json::from_slice(&fixture.evidence.blobs[&policy_ref.hash.digest]).unwrap();
        policy.internal = true;
        fixture.descriptors[0].ports[0].configuration_ref = fixture.evidence.put(&policy);
    }
    fixture.descriptors[0].roles = vec![id(role)];
    if role == "scripted_source" {
        fixture.coordinator.external_inputs.clear();
        let port = &mut fixture.descriptors[0].ports[0];
        let mut policy: PortPolicy =
            serde_json::from_slice(&fixture.evidence.blobs[&port.configuration_ref.hash.digest])
                .unwrap();
        port.lanes
            .retain(|lane| lane.direction == Direction::Output);
        policy.lanes.retain(|lane| lane.lane_id == id("output"));
        port.lanes[0].payload_schema.id = id("crucible/block-request-v1");
        fixture.bindings[0]
            .compatibility
            .implementation
            .formats
            .push(port.lanes[0].payload_schema.clone());
        fixture.bindings[0]
            .compatibility
            .implementation
            .formats
            .sort_by(|left, right| left.id.cmp(&right.id));
        port.configuration_ref = fixture.evidence.put(&policy);
    }
    fixture.descriptors[1].roles = vec![id("clock")];
    fixture.descriptors[1].ports.clear();
    let reference = canonical::content_ref(&initialization, "application/octet-stream").unwrap();
    fixture
        .evidence
        .blobs
        .insert(reference.hash.digest.clone(), initialization);
    fixture.descriptors[0].initialization_ref = reference;
    let clock = crate::node_adapters::host_clock_initial_bytes(0);
    let reference = canonical::content_ref(&clock, "application/octet-stream").unwrap();
    fixture
        .evidence
        .blobs
        .insert(reference.hash.digest.clone(), clock);
    fixture.descriptors[1].initialization_ref = reference;
    let proof = fixture.ownership.inventory_proof_ref.clone();
    let facets: Vec<_> = [
        "host/exact-v1",
        "host/physical-pause-v1",
        "host/preservation-v1",
    ]
    .into_iter()
    .map(|name| FacetSelection {
        id: id(name),
        version: 1,
        configuration_ref: proof.clone(),
        guarantees_ref: proof.clone(),
        extensions: Extensions::new(),
    })
    .collect();
    let native_definition = canonical::content_ref(HOST_NATIVE_SCHEMA, "text/plain").unwrap();
    fixture.evidence.blobs.insert(
        native_definition.hash.digest.clone(),
        HOST_NATIVE_SCHEMA.to_vec(),
    );
    let native_schema = SchemaRef {
        id: id("host/native-continuation-v1"),
        version: 1,
        definition: native_definition,
        extensions: Extensions::new(),
    };
    for binding in &mut fixture.bindings {
        binding
            .compatibility
            .implementation
            .formats
            .push(native_schema.clone());
        binding
            .compatibility
            .implementation
            .formats
            .sort_by(|left, right| left.id.cmp(&right.id));
        let mut capability: CapabilityProfile = serde_json::from_slice(
            fixture
                .evidence
                .blobs
                .get(&binding.compatibility.capabilities_ref.hash.digest)
                .unwrap(),
        )
        .unwrap();
        capability.facets = facets.clone();
        binding.compatibility.capabilities_ref = fixture.evidence.put(&capability);
        binding.compatibility.operating_contract.facets = facets.clone();
        if restored {
            binding.authority.owner_generation = generation.into();
            binding.authority.incarnation_id = if initial_queue {
                id(&format!(
                    "live/restored-{generation}-{}",
                    binding.compatibility.node_id
                ))
            } else {
                id(&format!("live/restored-{}", binding.compatibility.node_id))
            };
        }
    }
    fixture.refresh();
    let admitted = fixture.admit(AdmissionLimits::default()).unwrap();
    (admitted, fixture.evidence.blobs)
}

#[cfg(test)]
pub(super) fn reference_device_fixture_with_content(
    executable: Vec<u8>,
) -> (AdmittedGraph, BTreeMap<String, Vec<u8>>) {
    let mut fixture = Fixture::new();
    fixture.world.connections.clear();
    fixture.coordinator.external_inputs.clear();
    fixture.requirements = ScenarioRequirements {
        deterministic: false,
        exact_capture: false,
        exact_continuation: false,
        durable_restart: false,
        isolated_fork: false,
        accepted_quantized_nodes: vec![id("a"), id("z")],
        accepted_nondeterministic_nodes: vec![id("a"), id("z")],
        accepted_limited_state_nodes: vec![id("a"), id("z")],
        accepted_visibility_conversions: vec![],
    };
    let proof = fixture.ownership.inventory_proof_ref.clone();
    let policy_ref = fixture.evidence.put(&ExecutionPolicy::Quantized {
        schema_version: 1,
        quantum_ps: 100.into(),
        phase_ps: 0.into(),
        host_budget_ns: 1_000_000_000.into(),
        window_proof_ref: proof.clone(),
    });
    let facet = FacetSelection {
        id: id("reference-device/quantized-v1"),
        version: 1,
        configuration_ref: proof.clone(),
        guarantees_ref: proof.clone(),
        extensions: Extensions::new(),
    };
    let capability_ref = fixture.evidence.put(&CapabilityProfile {
        schema_version: 1,
        facets: vec![facet.clone()],
        devices_ref: proof.clone(),
        requirements_ref: proof.clone(),
        extensions: Extensions::new(),
    });
    let guarantee_ref = fixture.evidence.put(&GuaranteeProfile {
        schema_version: 1,
        repeatability: Repeatability::Nondeterministic,
        capture_scope: CaptureScope::None,
        continuation: Continuation::Unsupported,
        durable_restart: false,
        isolated_fork: false,
        conditional_replay: false,
        limitations_ref: proof.clone(),
        extensions: Extensions::new(),
    });
    let executable_ref = canonical::content_ref(&executable, "application/octet-stream").unwrap();
    fixture
        .evidence
        .blobs
        .insert(executable_ref.hash.digest.clone(), executable);
    let initial = canonical::canonical_json(&serde_json::json!({"schema_version":1,"quantum":"0","bytes_processed":"0","checksum":"0","input":"empty"})).unwrap();
    let initial_ref = canonical::content_ref(&initial, "application/json").unwrap();
    fixture
        .evidence
        .blobs
        .insert(initial_ref.hash.digest.clone(), initial);
    for descriptor in &mut fixture.descriptors {
        descriptor.roles = vec![id("external_device")];
        descriptor.initialization_ref = initial_ref.clone();
        descriptor.ports[0]
            .lanes
            .retain(|lane| lane.direction == Direction::Output);
        let mut port: PortPolicy = serde_json::from_slice(
            fixture
                .evidence
                .blobs
                .get(&descriptor.ports[0].configuration_ref.hash.digest)
                .unwrap(),
        )
        .unwrap();
        port.lanes.retain(|lane| lane.lane_id == id("output"));
        port.lanes[0].visibility = LaneVisibility::Quantized {
            quantum_ps: 100.into(),
            phase_ps: 0.into(),
            contract_ref: proof.clone(),
        };
        descriptor.ports[0].configuration_ref = fixture.evidence.put(&port);
    }
    for binding in &mut fixture.bindings {
        binding.compatibility.implementation.artifacts[0].role = id("device-executable");
        binding.compatibility.implementation.artifacts[0].content = executable_ref.clone();
        binding.compatibility.operating_contract.mode = OperatingMode::Quantized;
        binding.compatibility.operating_contract.policy_ref = policy_ref.clone();
        binding.compatibility.operating_contract.facets = vec![facet.clone()];
        binding.compatibility.capabilities_ref = capability_ref.clone();
        binding.compatibility.guarantees_ref = guarantee_ref.clone();
    }
    for capture in &mut fixture.ownership.capture_owners {
        capture.complete_model = false;
        capture.exact_continuation = false;
        capture.durable_restart = false;
        capture.isolated_fork = false;
    }
    fixture.refresh();
    let graph = fixture.admit(AdmissionLimits::default()).unwrap();
    (graph, fixture.evidence.blobs)
}

struct Fixture {
    evidence: Evidence,
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerBinding>,
    world: WorldBinding,
    requirements: ScenarioRequirements,
    ownership: OwnershipPolicy,
    coordinator: CoordinatorPolicy,
}

impl Fixture {
    fn new() -> Self {
        let mut evidence = Evidence::default();
        let shared = evidence.put(&serde_json::json!({"qualified_test_contract": 1}));
        let schema = SchemaRef {
            id: id("test.bytes"),
            version: 1,
            definition: shared.clone(),
            extensions: Extensions::new(),
        };
        let guarantee = GuaranteeProfile {
            schema_version: 1,
            repeatability: Repeatability::Qualified,
            capture_scope: CaptureScope::CompleteModel,
            continuation: Continuation::Exact,
            durable_restart: true,
            isolated_fork: true,
            conditional_replay: false,
            limitations_ref: shared.clone(),
            extensions: Extensions::new(),
        };
        let guarantee_ref = evidence.put(&guarantee);
        let capability_ref = evidence.put(&CapabilityProfile {
            schema_version: 1,
            facets: vec![],
            devices_ref: shared.clone(),
            requirements_ref: shared.clone(),
            extensions: Extensions::new(),
        });
        let operating_ref = evidence.put(&ExecutionPolicy::Exact {
            schema_version: 1,
            execution_proof_ref: shared.clone(),
            ceiling: ExactCeiling::StrictPredecessor,
            boundary_settlement_ref: Some(shared.clone()),
        });
        let mut descriptors = Vec::new();
        let mut bindings = Vec::new();
        let mut owners = Vec::new();
        for name in ["a", "z"] {
            let node_id = id(name);
            let owner_id = id(&format!("owner/{name}"));
            let state_domain_ids = if name == "a" {
                vec![id("domain/a"), id("domain/transfer")]
            } else {
                vec![id("domain/z")]
            };
            let owner = OwnerRef {
                id: owner_id.clone(),
                participant_ids: vec![node_id.clone()],
                state_domain_ids,
            };
            let lane_policy = |lane_id: &str| LanePolicy {
                lane_id: id(lane_id),
                ordering_ref: shared.clone(),
                correlation_ref: shared.clone(),
                flow_control: FlowControl::Credit,
                maximum_pending_bytes: 128.into(),
                visibility: LaneVisibility::Exact,
                effect_phases: vec![1, 2, 3],
                minimum_lookahead_ps: 0.into(),
            };
            let policy_ref = evidence.put(&PortPolicy {
                schema_version: 1,
                lanes: vec![lane_policy("input"), lane_policy("output")],
                maximum_producers: 8.into(),
                maximum_consumers: 8.into(),
                arbitration_ref: shared.clone(),
                execution_owner_id: owner_id.clone(),
                state_domain_ids: vec![id(&format!("domain/{name}"))],
                internal: false,
            });
            let descriptor = NodeDescriptor {
                schema_version: 1,
                id: node_id.clone(),
                roles: vec![id("compute")],
                model_ref: shared.clone(),
                configuration_ref: shared.clone(),
                initialization_ref: shared.clone(),
                ports: vec![PortDescriptor {
                    id: id("data"),
                    lanes: vec![
                        LaneDescriptor {
                            id: id("input"),
                            direction: Direction::Input,
                            payload_schema: schema.clone(),
                            maximum_payload_bytes: 64.into(),
                            maximum_pending_events: 2.into(),
                            extensions: Extensions::new(),
                        },
                        LaneDescriptor {
                            id: id("output"),
                            direction: Direction::Output,
                            payload_schema: schema.clone(),
                            maximum_payload_bytes: 64.into(),
                            maximum_pending_events: 2.into(),
                            extensions: Extensions::new(),
                        },
                    ],
                    interface_id: id("test.bytes/1"),
                    features: vec![],
                    configuration_ref: policy_ref,
                    extensions: Extensions::new(),
                }],
                extensions: Extensions::new(),
            };
            let binding = NodeBinding {
                compatibility: BindingCompatibility {
                    schema_version: 1,
                    node_id: node_id.clone(),
                    descriptor_hash: descriptor.identity().unwrap(),
                    implementation: ImplementationIdentity {
                        schema_version: 1,
                        implementation_id: id("test.qualified"),
                        artifacts: vec![ArtifactIdentity {
                            id: id("executable"),
                            role: id("executable"),
                            content: shared.clone(),
                            extensions: Extensions::new(),
                        }],
                        model_definitions: vec![shared.clone()],
                        formats: vec![schema.clone()],
                        extensions: Extensions::new(),
                    },
                    profile_ref: shared.clone(),
                    configuration_ref: shared.clone(),
                    operating_contract: OperatingContract {
                        schema_version: 1,
                        mode: OperatingMode::Exact,
                        scheduling_role: SchedulingRole::Active,
                        ordering_profile: "superdense-v1".into(),
                        policy_ref: operating_ref.clone(),
                        resolution_ps: Some(1.into()),
                        phase_ps: Some(0.into()),
                        facets: vec![],
                        extensions: Extensions::new(),
                    },
                    execution_owner: owner.clone(),
                    capture_owner: owner.clone(),
                    capabilities_ref: capability_ref.clone(),
                    guarantees_ref: guarantee_ref.clone(),
                    qualification_refs: vec![shared.clone()],
                    extensions: Extensions::new(),
                },
                authority: LiveAuthority {
                    schema_version: 1,
                    session_id: id("host.session"),
                    incarnation_id: id(&format!("live/{name}")),
                    realization_id: id("realization"),
                    activation_id: None,
                    world_generation: 0.into(),
                    owner_generation: 1.into(),
                    input_epoch: id(&format!("input/{name}")),
                    host_receipt: shared.clone(),
                    extensions: Extensions::new(),
                },
                extensions: Extensions::new(),
            };
            owners.push(OwnerBinding {
                schema_version: 1,
                owner,
                owner_roles: vec![id("capture"), id("execution")],
                node_bindings: vec![NodeBindingRef {
                    node_id,
                    binding_hash: binding.identity().unwrap(),
                    extensions: Extensions::new(),
                }],
                ownership_ref: shared.clone(),
                extensions: Extensions::new(),
            });
            descriptors.push(descriptor);
            bindings.push(binding);
        }
        let requirements = ScenarioRequirements {
            deterministic: true,
            exact_capture: true,
            exact_continuation: true,
            durable_restart: true,
            isolated_fork: true,
            ..Default::default()
        };
        let ownership = OwnershipPolicy {
            schema_version: 1,
            domains: vec![
                StateDomain {
                    id: id("domain/a"),
                    capture_owner_id: id("owner/a"),
                    execution_owner_ids: vec![id("owner/a")],
                    future_affecting: true,
                },
                StateDomain {
                    id: id("domain/transfer"),
                    capture_owner_id: id("owner/a"),
                    execution_owner_ids: vec![id("owner/a")],
                    future_affecting: true,
                },
                StateDomain {
                    id: id("domain/z"),
                    capture_owner_id: id("owner/z"),
                    execution_owner_ids: vec![id("owner/z")],
                    future_affecting: true,
                },
            ],
            objects: vec![
                StateObject {
                    id: id("object/a"),
                    node_ids: vec![id("a")],
                    future_affecting: true,
                    state: ObjectState::Mutable {
                        domain_id: id("domain/a"),
                    },
                },
                StateObject {
                    id: id("object/transfer"),
                    node_ids: vec![],
                    future_affecting: true,
                    state: ObjectState::Mutable {
                        domain_id: id("domain/transfer"),
                    },
                },
                StateObject {
                    id: id("object/z"),
                    node_ids: vec![id("z")],
                    future_affecting: true,
                    state: ObjectState::Mutable {
                        domain_id: id("domain/z"),
                    },
                },
            ],
            internal_dependencies: vec![],
            capture_owners: vec![
                OwnerCapturePolicy {
                    owner_id: id("owner/a"),
                    complete_model: true,
                    unchanged_cut: true,
                    exact_continuation: true,
                    durable_restart: true,
                    isolated_fork: true,
                    dependencies: vec![id("owner/z")],
                    cut_procedure_ref: shared.clone(),
                },
                OwnerCapturePolicy {
                    owner_id: id("owner/z"),
                    complete_model: true,
                    unchanged_cut: true,
                    exact_continuation: true,
                    durable_restart: true,
                    isolated_fork: true,
                    dependencies: vec![id("owner/a")],
                    cut_procedure_ref: shared.clone(),
                },
            ],
            inventory_proof_ref: shared.clone(),
        };
        let coordinator = CoordinatorPolicy {
            schema_version: 1,
            state_closure_ref: shared.clone(),
            maximum_microsteps_per_instant: 32.into(),
            same_time_closure: vec![],
            operational_policy_ref: shared.clone(),
            external_inputs: vec![Endpoint {
                node_id: id("a"),
                port_id: id("data"),
                lane_id: id("input"),
            }],
        };
        let connection_policy_ref = evidence.put(&ConnectionPolicy {
            schema_version: 1,
            maximum_payload_bytes: 64.into(),
            maximum_pending_events: 2.into(),
            maximum_pending_bytes: 128.into(),
            visibility: VisibilityConversion::Direct,
            delivery: ConnectionDelivery::Fixed {
                latency_ps: 1.into(),
            },
            causal_proof_ref: shared.clone(),
            state_domain_ids: vec![id("domain/transfer")],
        });
        let world = WorldBinding {
            schema_version: 1,
            scenario_ref: evidence.put(&requirements),
            node_bindings: bindings
                .iter()
                .map(|binding| NodeBindingRef {
                    node_id: binding.compatibility.node_id.clone(),
                    binding_hash: binding.identity().unwrap(),
                    extensions: Extensions::new(),
                })
                .collect(),
            connections: vec![ConnectionDescriptor {
                schema_version: 1,
                id: id("connection/a-z"),
                producer: Endpoint {
                    node_id: id("a"),
                    port_id: id("data"),
                    lane_id: id("output"),
                },
                consumer: Endpoint {
                    node_id: id("z"),
                    port_id: id("data"),
                    lane_id: id("input"),
                },
                interface_id: id("test.bytes/1"),
                features: vec![],
                payload_schema: schema,
                minimum_latency_ps: 1.into(),
                policy_ref: connection_policy_ref,
                capture_owner_id: id("owner/a"),
                extensions: Extensions::new(),
            }],
            ownership_ref: evidence.put(&ownership),
            coordinator_contract_ref: evidence.put(&coordinator),
            ordering_profile: "superdense-v1".into(),
            initialization_ref: shared,
            extensions: Extensions::new(),
        };
        Self {
            evidence,
            descriptors,
            bindings,
            owners,
            world,
            requirements,
            ownership,
            coordinator,
        }
    }

    fn refresh(&mut self) {
        for (node, binding) in self.descriptors.iter().zip(&mut self.bindings) {
            binding.compatibility.descriptor_hash = node.identity().unwrap();
        }
        self.world.node_bindings = self
            .bindings
            .iter()
            .map(|binding| NodeBindingRef {
                node_id: binding.compatibility.node_id.clone(),
                binding_hash: binding.identity().unwrap(),
                extensions: Extensions::new(),
            })
            .collect();
        for owner in &mut self.owners {
            owner.node_bindings = self
                .world
                .node_bindings
                .iter()
                .filter(|binding| owner.owner.participant_ids.contains(&binding.node_id))
                .cloned()
                .collect();
        }
        self.world.scenario_ref = self.evidence.put(&self.requirements);
        self.world.ownership_ref = self.evidence.put(&self.ownership);
        self.world.coordinator_contract_ref = self.evidence.put(&self.coordinator);
    }

    fn admit(&self, limits: AdmissionLimits) -> Result<AdmittedGraph, AdmissionError> {
        admit_graph(
            AdmissionRequest {
                world: &self.world,
                descriptors: &self.descriptors,
                bindings: &self.bindings,
                owners: &self.owners,
                requirements: &self.requirements,
            },
            &self.evidence,
            limits,
        )
    }

    fn guarantee(&mut self, node: usize, edit: impl FnOnce(&mut GuaranteeProfile)) {
        let bytes = self
            .evidence
            .blobs
            .get(&self.bindings[node].compatibility.guarantees_ref.hash.digest)
            .unwrap();
        let mut guarantee: GuaranteeProfile = serde_json::from_slice(bytes).unwrap();
        edit(&mut guarantee);
        self.bindings[node].compatibility.guarantees_ref = self.evidence.put(&guarantee);
        self.refresh();
    }
}

#[test]
fn complete_exact_graph_seals_actual_descriptors_bindings_and_owners() {
    let fixture = Fixture::new();
    let admitted = fixture.admit(AdmissionLimits::default()).unwrap();
    assert_eq!(
        admitted.world_binding_hash(),
        &fixture.world.identity().unwrap()
    );
    assert_eq!(admitted.binding(&id("a")), Some(&fixture.bindings[0]));
    assert_eq!(admitted.descriptor(&id("z")), Some(&fixture.descriptors[1]));
    assert_eq!(admitted.owners().count(), 2);
    assert_eq!(admitted.world_repeatability(), Repeatability::Qualified);
}

#[test]
fn valid_reference_with_corrupt_or_missing_bytes_never_establishes_evidence() {
    for missing in [false, true] {
        let mut fixture = Fixture::new();
        let digest = fixture.descriptors[0].model_ref.hash.digest.clone();
        if missing {
            fixture.evidence.blobs.remove(&digest);
        } else {
            fixture.evidence.blobs.get_mut(&digest).unwrap()[0] ^= 1;
        }
        let error = fixture.admit(AdmissionLimits::default()).unwrap_err();
        assert_eq!(error.code, AdmissionCode::IdentityMismatch);
        assert_eq!(error.effects, EffectCertainty::Absent);
    }
}

#[test]
fn copied_live_authority_and_unaccepted_qualification_are_refused() {
    let mut fixture = Fixture::new();
    fixture.evidence.reject_authority = true;
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::IdentityMismatch
    );

    fixture.evidence.reject_authority = false;
    fixture.evidence.reject_qualification = true;
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::QualificationUnavailable
    );
}

#[test]
fn scenario_acceptance_cannot_be_added_without_binding_the_selected_scenario() {
    let mut fixture = Fixture::new();
    fixture.requirements.deterministic = false;
    fixture
        .requirements
        .accepted_nondeterministic_nodes
        .push(id("a"));
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::QualificationUnavailable
    );
}

#[test]
fn changed_actual_descriptor_refuses_the_frozen_binding() {
    let mut fixture = Fixture::new();
    fixture.descriptors[0].roles.push(id("storage"));
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::IdentityMismatch
    );
}

#[test]
fn duplicate_nodes_owners_and_state_domains_refuse_admission() {
    let mut fixture = Fixture::new();
    fixture
        .descriptors
        .insert(0, fixture.descriptors[0].clone());
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::InvalidSchema
    );

    let mut fixture = Fixture::new();
    fixture.owners.insert(0, fixture.owners[0].clone());
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::InvalidSchema
    );

    let mut fixture = Fixture::new();
    fixture
        .ownership
        .domains
        .insert(0, fixture.ownership.domains[0].clone());
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::InvalidSchema
    );
}

#[test]
fn same_family_different_schema_direction_or_features_is_incompatible() {
    let mut fixture = Fixture::new();
    fixture.world.connections[0].payload_schema.version = 2;
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::FeatureMismatch
    );

    let mut fixture = Fixture::new();
    fixture.world.connections[0].consumer.lane_id = id("output");
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::DirectionMismatch
    );

    let mut fixture = Fixture::new();
    fixture.world.connections[0]
        .features
        .push(id("unsupported"));
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::FeatureMismatch
    );
}

#[test]
fn valid_schema_bytes_without_installed_validator_refuse_admission() {
    let mut fixture = Fixture::new();
    fixture.evidence.reject_schema = true;
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::UnknownInterface
    );
}

#[test]
fn architectural_or_draining_capture_does_not_satisfy_exact_world_contract() {
    let mut fixture = Fixture::new();
    fixture.requirements.accepted_limited_state_nodes = vec![id("a")];
    fixture.guarantee(0, |guarantee| {
        guarantee.capture_scope = CaptureScope::Architectural
    });
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::CaptureUnsupported
    );

    let mut fixture = Fixture::new();
    fixture.ownership.capture_owners[0].unchanged_cut = false;
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::CaptureUnsupported
    );
}

#[test]
fn hidden_future_affecting_object_missing_domain_or_transfer_dependency_is_refused() {
    let mut fixture = Fixture::new();
    fixture.ownership.objects[0].state = ObjectState::OutsideScope;
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::CaptureUnsupported
    );

    let mut fixture = Fixture::new();
    fixture.ownership.objects.remove(1);
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::OwnerConflict
    );

    let mut fixture = Fixture::new();
    fixture.ownership.capture_owners[0].dependencies.clear();
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::CaptureUnsupported
    );
}

#[test]
fn explicit_nondeterminism_taints_world_and_shared_capture_neighbors() {
    let mut fixture = Fixture::new();
    fixture.requirements.deterministic = false;
    fixture.requirements.accepted_nondeterministic_nodes = vec![id("a")];
    fixture.guarantee(0, |guarantee| {
        guarantee.repeatability = Repeatability::Nondeterministic
    });
    let admitted = fixture.admit(AdmissionLimits::default()).unwrap();
    assert_eq!(
        admitted.world_repeatability(),
        Repeatability::Nondeterministic
    );
    assert_eq!(
        admitted.effective_repeatability(&id("z")),
        Some(Repeatability::Nondeterministic)
    );
}

#[test]
fn nondeterminism_cannot_be_accepted_by_speed_or_omission() {
    let mut fixture = Fixture::new();
    fixture.requirements.deterministic = false;
    fixture.guarantee(0, |guarantee| {
        guarantee.repeatability = Repeatability::Nondeterministic
    });
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::NondeterminismUnaccepted
    );
}

#[test]
fn zero_latency_cycle_requires_every_owner_closure_and_finite_microstep_cap() {
    let mut fixture = Fixture::new();
    fixture.world.connections[0].minimum_latency_ps = 0.into();
    let policy_ref = fixture.world.connections[0].policy_ref.clone();
    let mut policy: ConnectionPolicy =
        serde_json::from_slice(fixture.evidence.blobs.get(&policy_ref.hash.digest).unwrap())
            .unwrap();
    policy.delivery = ConnectionDelivery::Fixed {
        latency_ps: 0.into(),
    };
    fixture.world.connections[0].policy_ref = fixture.evidence.put(&policy);
    let mut reverse = fixture.world.connections[0].clone();
    reverse.id = id("connection/z-a");
    std::mem::swap(&mut reverse.producer.node_id, &mut reverse.consumer.node_id);
    fixture.world.connections.push(reverse);
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::CausalProgressUnavailable
    );

    let proof = fixture.ownership.inventory_proof_ref.clone();
    fixture.coordinator.same_time_closure = vec![
        SameTimeClosure {
            execution_owner_id: id("owner/a"),
            proof_ref: proof.clone(),
        },
        SameTimeClosure {
            execution_owner_id: id("owner/z"),
            proof_ref: proof,
        },
    ];
    fixture.refresh();
    fixture.admit(AdmissionLimits::default()).unwrap();
    fixture.coordinator.maximum_microsteps_per_instant = 0.into();
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::CausalProgressUnavailable
    );
}

#[test]
fn unknown_input_source_and_undeclared_internal_path_refuse_progress() {
    let mut fixture = Fixture::new();
    fixture.coordinator.external_inputs.clear();
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::LookaheadUnproven
    );

    let mut fixture = Fixture::new();
    fixture
        .ownership
        .internal_dependencies
        .push(InternalDependency {
            id: id("hidden-clock"),
            producer_node_id: id("missing"),
            consumer_node_id: id("z"),
            minimum_latency_ps: 1.into(),
            proof_ref: fixture.ownership.inventory_proof_ref.clone(),
        });
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::OwnerConflict
    );
}

#[test]
fn oversized_graph_content_and_queue_reservations_are_refused() {
    let fixture = Fixture::new();
    let limits = AdmissionLimits {
        maximum_nodes: 1,
        ..Default::default()
    };
    assert_eq!(
        fixture.admit(limits).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );

    let limits = AdmissionLimits {
        maximum_content_bytes: 1,
        ..Default::default()
    };
    assert_eq!(
        fixture.admit(limits).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );

    let limits = AdmissionLimits {
        maximum_total_core_bytes: 1,
        ..Default::default()
    };
    assert_eq!(
        fixture.admit(limits).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );

    let limits = AdmissionLimits {
        maximum_total_pending_bytes: 127,
        ..Default::default()
    };
    assert_eq!(
        fixture.admit(limits).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );
}

#[test]
fn unknown_nested_extensions_cannot_acquire_semantic_support_by_hashing() {
    let mut fixture = Fixture::new();
    fixture.bindings[0].compatibility.implementation.artifacts[0]
        .extensions
        .insert("mandatory.vendor".into(), serde_json::json!(true));
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::UnknownInterface
    );
}

#[test]
fn mixed_activation_generations_refuse_a_partially_bound_world() {
    let mut fixture = Fixture::new();
    fixture.bindings[1].authority.world_generation = 2.into();

    let error = fixture.admit(AdmissionLimits::default()).unwrap_err();
    assert_eq!(error.code, AdmissionCode::OwnerConflict);
    assert_eq!(error.effects, EffectCertainty::Absent);
}

#[test]
fn quantized_mode_requires_matching_policy_and_explicit_visibility_conversion() {
    let mut fixture = Fixture::new();
    let proof = fixture.ownership.inventory_proof_ref.clone();
    let policy_ref = fixture.evidence.put(&ExecutionPolicy::Quantized {
        schema_version: 1,
        quantum_ps: 100.into(),
        phase_ps: 0.into(),
        host_budget_ns: 1000.into(),
        window_proof_ref: proof.clone(),
    });
    fixture.bindings[0].compatibility.operating_contract.mode = OperatingMode::Quantized;
    fixture.bindings[0]
        .compatibility
        .operating_contract
        .policy_ref = policy_ref;
    let port_ref = &fixture.descriptors[0].ports[0].configuration_ref;
    let mut port: PortPolicy =
        serde_json::from_slice(fixture.evidence.blobs.get(&port_ref.hash.digest).unwrap()).unwrap();
    for lane in &mut port.lanes {
        lane.visibility = LaneVisibility::Quantized {
            quantum_ps: 100.into(),
            phase_ps: 0.into(),
            contract_ref: proof.clone(),
        };
    }
    fixture.descriptors[0].ports[0].configuration_ref = fixture.evidence.put(&port);
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::NondeterminismUnaccepted
    );

    fixture.requirements.accepted_quantized_nodes = vec![id("a")];
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::VisibilityMismatch
    );

    let connection_ref = &fixture.world.connections[0].policy_ref;
    let mut connection: ConnectionPolicy = serde_json::from_slice(
        fixture
            .evidence
            .blobs
            .get(&connection_ref.hash.digest)
            .unwrap(),
    )
    .unwrap();
    connection.visibility = VisibilityConversion::Adapter {
        contract_ref: proof,
    };
    fixture.world.connections[0].policy_ref = fixture.evidence.put(&connection);
    fixture.refresh();
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::VisibilityMismatch
    );

    fixture.requirements.accepted_visibility_conversions = vec![id("connection/a-z")];
    fixture.refresh();
    let admitted = fixture.admit(AdmissionLimits::default()).unwrap();
    // A qualified deterministic quantized model does not become hardware KVM
    // merely because its timing axis is quantized. The axes stay independent.
    assert_eq!(admitted.world_repeatability(), Repeatability::Qualified);
}

#[test]
fn queue_capacity_multiplication_and_total_content_accounting_are_checked() {
    let mut fixture = Fixture::new();
    let reference = fixture.world.connections[0].policy_ref.clone();
    let mut policy: ConnectionPolicy =
        serde_json::from_slice(fixture.evidence.blobs.get(&reference.hash.digest).unwrap())
            .unwrap();
    policy.maximum_payload_bytes = u64::MAX.into();
    policy.maximum_pending_events = 2.into();
    fixture.world.connections[0].policy_ref = fixture.evidence.put(&policy);
    assert_eq!(
        fixture.admit(AdmissionLimits::default()).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );

    let fixture = Fixture::new();
    let limits = AdmissionLimits {
        maximum_total_content_bytes: 1,
        ..Default::default()
    };
    assert_eq!(
        fixture.admit(limits).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );
}

#[test]
fn shared_domain_matrix_covers_distinct_writer_and_capture_owners() {
    let (admitted, _) = execution_fixture_with_content(true);
    assert!(
        admitted
            .owner_conflicts(&id("owner/a"))
            .unwrap()
            .contains(&id("owner/z"))
    );
    assert!(
        admitted
            .owner_conflicts(&id("owner/z"))
            .unwrap()
            .contains(&id("owner/a"))
    );
    assert!(
        !admitted
            .owner_conflicts(&id("owner/a"))
            .unwrap()
            .contains(&id("owner/a"))
    );
    let (isolated, _) = execution_fixture_with_content(false);
    assert!(isolated.owner_conflicts(&id("owner/a")).unwrap().is_empty());
}

#[test]
fn owner_conflict_derivation_has_a_finite_host_work_ceiling() {
    let fixture = execution_fixture(true, true);
    let limits = AdmissionLimits {
        maximum_owner_conflict_checks: 1,
        ..Default::default()
    };
    assert_eq!(
        fixture.admit(limits).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );
    let limits = AdmissionLimits {
        maximum_owner_conflict_pairs: 1,
        ..Default::default()
    };
    assert_eq!(
        fixture.admit(limits).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );
}

#[path = "tests/conformance.rs"]
mod conformance;
