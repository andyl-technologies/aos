//! Complete conservative world fixture for two actual installed public providers.

use std::{collections::BTreeMap, path::PathBuf};

use crucible_node_contract::*;
use crucible_node_provider::reference_service::ReferenceProfile;
use serde::Serialize;

use crate::node_admission::*;

use super::{Installed, id};

pub(super) struct Definition {
    pub world: WorldBinding,
    pub descriptors: Vec<NodeDescriptor>,
    pub requirements: ScenarioRequirements,
    pub content: BTreeMap<ContentRef, Vec<u8>>,
    artifacts: BTreeMap<ContentRef, PathBuf>,
    qualification: ContentRef,
}

impl Definition {
    pub fn build(
        profiles: &[ReferenceProfile],
        qualification_bytes: Vec<u8>,
        artifacts: BTreeMap<ContentRef, PathBuf>,
    ) -> Self {
        assert_eq!(profiles.len(), 2);
        let mut content = BTreeMap::new();
        for profile in profiles {
            for object in profile.content_objects() {
                content.insert(object.reference.clone(), object.bytes.clone());
            }
        }
        let qualification = put(&mut content, qualification_bytes, "text/plain");
        let requirements = ScenarioRequirements {
            accepted_quantized_nodes: vec![id("consumer"), id("producer")],
            accepted_nondeterministic_nodes: vec![id("consumer"), id("producer")],
            accepted_limited_state_nodes: vec![id("consumer"), id("producer")],
            accepted_visibility_conversions: vec![id("connection/producer/consumer")],
            ..ScenarioRequirements::default()
        };
        let mut bindings = Vec::new();
        let mut domains = Vec::new();
        let mut objects = Vec::new();
        let mut captures = Vec::new();
        for profile in profiles {
            let authority = initial_authority(&profile.descriptor.id, &qualification);
            let (binding, _) = profile
                .bind_qualified(authority, std::slice::from_ref(&qualification))
                .unwrap();
            bindings.push(NodeBindingRef {
                node_id: profile.descriptor.id.clone(),
                binding_hash: binding.identity().unwrap(),
                extensions: Extensions::new(),
            });
            let domain = profile.owner.state_domain_ids[0].clone();
            domains.push(StateDomain {
                id: domain.clone(),
                capture_owner_id: profile.owner.id.clone(),
                execution_owner_ids: vec![profile.owner.id.clone()],
                future_affecting: true,
            });
            objects.push(StateObject {
                id: profile.descriptor.id.clone(),
                node_ids: vec![profile.descriptor.id.clone()],
                future_affecting: true,
                state: ObjectState::Mutable { domain_id: domain },
            });
            captures.push(OwnerCapturePolicy {
                owner_id: profile.owner.id.clone(),
                complete_model: false,
                unchanged_cut: false,
                exact_continuation: false,
                durable_restart: false,
                isolated_fork: false,
                dependencies: Vec::new(),
                cut_procedure_ref: qualification.clone(),
            });
        }
        let source = profiles
            .iter()
            .find(|profile| profile.descriptor.id == id("producer"))
            .unwrap();
        let sink = profiles
            .iter()
            .find(|profile| profile.descriptor.id == id("consumer"))
            .unwrap();
        let port = source
            .descriptor
            .ports
            .iter()
            .find(|port| port.id == id("data"))
            .unwrap();
        let lane = port
            .lanes
            .iter()
            .find(|lane| lane.id == id("output"))
            .unwrap();
        let custody_domain = sink.owner.state_domain_ids[0].clone();
        let connection_policy = ConnectionPolicy {
            schema_version: 1,
            maximum_payload_bytes: U64::new(4096),
            maximum_pending_events: U64::new(1),
            maximum_pending_bytes: U64::new(4096),
            visibility: VisibilityConversion::BoundarySampling {
                contract_ref: qualification.clone(),
            },
            delivery: ConnectionDelivery::Fixed {
                latency_ps: U64::new(0),
            },
            causal_proof_ref: qualification.clone(),
            state_domain_ids: vec![custody_domain.clone()],
        };
        let connection = ConnectionDescriptor {
            schema_version: 1,
            id: id("connection/producer/consumer"),
            producer: Endpoint {
                node_id: id("producer"),
                port_id: id("data"),
                lane_id: id("output"),
            },
            consumer: Endpoint {
                node_id: id("consumer"),
                port_id: id("data"),
                lane_id: id("input"),
            },
            interface_id: port.interface_id.clone(),
            features: Vec::new(),
            payload_schema: lane.payload_schema.clone(),
            minimum_latency_ps: U64::new(0),
            policy_ref: put_json(&mut content, &connection_policy),
            capture_owner_id: sink.owner.id.clone(),
            extensions: Extensions::new(),
        };
        // These bounded coordinator queues participate in the consumer's
        // existing domain. No provider binding is silently expanded, and no
        // capture procedure is advertised for the native/coordinator pair.
        objects.push(StateObject {
            id: connection.id.clone(),
            node_ids: vec![id("consumer"), id("producer")],
            future_affecting: true,
            state: ObjectState::Mutable {
                domain_id: custody_domain,
            },
        });
        domains.sort_by(|a, b| a.id.cmp(&b.id));
        objects.sort_by(|a, b| a.id.cmp(&b.id));
        captures.sort_by(|a, b| a.owner_id.cmp(&b.owner_id));
        let ownership = OwnershipPolicy {
            schema_version: 1,
            domains,
            objects,
            internal_dependencies: Vec::new(),
            capture_owners: captures,
            inventory_proof_ref: qualification.clone(),
        };
        let coordinator = CoordinatorPolicy {
            schema_version: 1,
            state_closure_ref: qualification.clone(),
            maximum_microsteps_per_instant: U64::new(1024),
            same_time_closure: Vec::new(),
            operational_policy_ref: qualification.clone(),
            external_inputs: Vec::new(),
        };
        let ownership_ref = put_json(&mut content, &ownership);
        let coordinator_ref = put_json(&mut content, &coordinator);
        let scenario_ref = put_json(&mut content, &requirements);
        let initialization = profiles
            .iter()
            .map(|profile| {
                (
                    &profile.descriptor.id,
                    &profile.descriptor.initialization_ref,
                )
            })
            .collect::<Vec<_>>();
        let initialization_ref = put_json(&mut content, &initialization);
        let world = WorldBinding {
            schema_version: 1,
            scenario_ref,
            node_bindings: bindings,
            connections: vec![connection],
            ownership_ref,
            coordinator_contract_ref: coordinator_ref,
            ordering_profile: "superdense-v1".into(),
            initialization_ref,
            extensions: Extensions::new(),
        };
        Self {
            world,
            descriptors: profiles
                .iter()
                .map(|profile| profile.descriptor.clone())
                .collect(),
            requirements,
            content,
            artifacts,
            qualification,
        }
    }

    pub fn qualification(&self) -> &ContentRef {
        &self.qualification
    }

    pub fn admit(
        &self,
        installations: &[Installed],
        prepared: &[super::CnpReferencePreparation],
    ) -> AdmittedGraph {
        let bindings = prepared
            .iter()
            .map(|node| node.binding().clone())
            .collect::<Vec<_>>();
        let owners = prepared
            .iter()
            .map(|node| node.owner_binding().clone())
            .collect::<Vec<_>>();
        let evidence = Evidence {
            definition: self,
            installations,
            prepared,
            bindings: &bindings,
        };
        admit_graph(
            AdmissionRequest {
                world: &self.world,
                descriptors: &self.descriptors,
                bindings: &bindings,
                owners: &owners,
                requirements: &self.requirements,
            },
            &evidence,
            AdmissionLimits {
                maximum_content_bytes: 8 * 1024 * 1024,
                ..AdmissionLimits::default()
            },
        )
        .unwrap()
    }
}

pub(super) fn initial_authority(node: &Id, host_receipt: &ContentRef) -> LiveAuthority {
    LiveAuthority {
        schema_version: 1,
        session_id: id(&format!("session/{node}")),
        incarnation_id: id(&format!("incarnation/{node}")),
        realization_id: id(&format!("realization/{node}")),
        activation_id: None,
        world_generation: U64::new(0),
        owner_generation: U64::new(1),
        input_epoch: id(&format!("input-epoch/{node}")),
        host_receipt: host_receipt.clone(),
        extensions: Extensions::new(),
    }
}

fn put(content: &mut BTreeMap<ContentRef, Vec<u8>>, bytes: Vec<u8>, media: &str) -> ContentRef {
    let reference = canonical::content_ref(&bytes, media).unwrap();
    content.insert(reference.clone(), bytes);
    reference
}

fn put_json(content: &mut BTreeMap<ContentRef, Vec<u8>>, value: &impl Serialize) -> ContentRef {
    let bytes = canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap();
    put(content, bytes, "application/json")
}

struct Evidence<'a> {
    definition: &'a Definition,
    installations: &'a [Installed],
    prepared: &'a [super::CnpReferencePreparation],
    bindings: &'a [NodeBinding],
}

fn evidence_error() -> EvidenceError {
    EvidenceError {
        message: "actual public fixture scope changed or unsupported".into(),
    }
}

impl AdmissionEvidence for Evidence<'_> {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        if reference.length.get() > maximum_bytes as u64 {
            return Err(evidence_error());
        }
        if let Some(bytes) = self.definition.content.get(reference) {
            return Ok(bytes.clone());
        }
        for installed in self.installations {
            if let Some(object) = installed
                .bootstrap
                .installed_content
                .iter()
                .find(|object| &object.reference == reference)
            {
                return Ok(object.bytes.as_slice().to_vec());
            }
        }
        if let Some(path) = self.definition.artifacts.get(reference) {
            use std::io::Read;
            let file = std::fs::File::open(path).map_err(|_| evidence_error())?;
            if file.metadata().map_err(|_| evidence_error())?.len() != reference.length.get() {
                return Err(evidence_error());
            }
            let mut bytes = Vec::new();
            file.take(reference.length.get() + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| evidence_error())?;
            reference.verify(&bytes).map_err(|_| evidence_error())?;
            return Ok(bytes);
        }
        Err(evidence_error())
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        if self
            .installations
            .iter()
            .any(|installed| &installed.profile.implementation == implementation)
        {
            Ok(())
        } else {
            Err(evidence_error())
        }
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        let original = self
            .prepared
            .iter()
            .find(|node| node.binding() == binding)
            .ok_or_else(evidence_error)?;
        let installed = self
            .installations
            .iter()
            .find(|installed| installed.profile.descriptor.id == binding.compatibility.node_id)
            .ok_or_else(evidence_error)?;
        super::CnpReferenceQualification::authenticate_provider(
            installed,
            &original.guard,
            &installed.profile,
        )
        .map_err(|_| evidence_error())?;
        super::verify_companion(
            original.companion_pid,
            original.guard.provider_pid().ok_or_else(evidence_error)?,
            &installed.profile,
        )
        .map_err(|_| evidence_error())
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        if self
            .installations
            .iter()
            .flat_map(|installed| &installed.profile.implementation.formats)
            .any(|installed| installed == schema)
        {
            Ok(())
        } else {
            Err(evidence_error())
        }
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        let world = self
            .definition
            .world
            .identity()
            .map_err(|_| evidence_error())?;
        let accepted = match claim {
            QualificationClaim::Scenario {
                world_binding_hash,
                scenario_ref,
                requirements_hash,
            } => {
                world_binding_hash == &world
                    && scenario_ref == &self.definition.world.scenario_ref
                    && requirements_hash
                        == &canonical::json_hash(
                            "cnp.admission-requirements.v1",
                            &self.definition.requirements,
                        )
                        .map_err(|_| evidence_error())?
            }
            QualificationClaim::Node {
                binding,
                binding_hash,
                qualification_refs,
            } => {
                self.bindings
                    .iter()
                    .any(|actual| &actual.compatibility == binding)
                    && binding_hash == &binding.identity().map_err(|_| evidence_error())?
                    && qualification_refs == [self.definition.qualification.clone()]
            }
            QualificationClaim::Port {
                node_id,
                binding_hash,
                port_id,
                policy_ref,
            } => {
                self.bindings.iter().any(|binding| {
                    &binding.compatibility.node_id == node_id
                        && binding.identity().as_ref().ok() == Some(binding_hash)
                }) && self
                    .definition
                    .descriptors
                    .iter()
                    .find(|node| &node.id == node_id)
                    .is_some_and(|node| {
                        node.ports.iter().any(|port| {
                            &port.id == port_id && &port.configuration_ref == policy_ref
                        })
                    })
            }
            QualificationClaim::CompleteInventory {
                world_binding_hash,
                ownership_ref,
                proof_ref,
            } => {
                world_binding_hash == &world
                    && ownership_ref == &self.definition.world.ownership_ref
                    && proof_ref == &self.definition.qualification
            }
            QualificationClaim::Connection {
                world_binding_hash,
                connection_id,
                proof_ref,
            } => {
                world_binding_hash == &world
                    && connection_id == &self.definition.world.connections[0].id
                    && proof_ref == &self.definition.qualification
            }
            QualificationClaim::Capture {
                world_binding_hash,
                capture_owner_id,
                procedure_ref,
            } => {
                world_binding_hash == &world
                    && self
                        .prepared
                        .iter()
                        .any(|node| &node.owner_binding().owner.id == capture_owner_id)
                    && procedure_ref == &self.definition.qualification
            }
            QualificationClaim::Coordinator {
                world_binding_hash,
                policy_ref,
            } => {
                world_binding_hash == &world
                    && policy_ref == &self.definition.world.coordinator_contract_ref
            }
            QualificationClaim::SameTimeClosure { .. } => false,
        };
        if accepted {
            Ok(())
        } else {
            Err(evidence_error())
        }
    }
}
