//! Builds explicitly model-qualified whole graphs for owner-dispatch regressions.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Model fixture failures deliberately fail the regression.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::node_admission::*;
use crucible_node_contract::*;
use serde::Serialize;

use crate::node_scenario::NodeScenario;

use super::id;

/// Selects alias, domain-conflict or independent-owner model coverage.
pub(super) enum Topology {
    SharedTransfer,
    SharedIsolated,
    Conflicting,
    Disjoint,
}

struct ModelEvidence(BTreeMap<String, Vec<u8>>);

impl ModelEvidence {
    fn put(&mut self, value: &impl Serialize) -> ContentRef {
        let bytes = serde_json::to_vec(value).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        self.0.insert(reference.hash.digest.clone(), bytes);
        reference
    }

    fn decode<T: serde::de::DeserializeOwned>(&self, reference: &ContentRef) -> T {
        serde_json::from_slice(&self.0[&reference.hash.digest]).unwrap()
    }
}

impl AdmissionEvidence for ModelEvidence {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.0
            .get(&reference.hash.digest)
            .filter(|bytes| bytes.len() <= maximum_bytes)
            .cloned()
            .ok_or_else(|| EvidenceError {
                message: "model content unavailable".into(),
            })
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        assert_eq!(implementation.implementation_id, id("test.qualified"));
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        assert_eq!(binding.authority.session_id, id("host.session"));
        Ok(())
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        assert_eq!(schema.id, id("test.bytes"));
        assert_eq!(schema.version, 1);
        Ok(())
    }

    fn qualify(&self, _: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        // This policy authenticates only the synthetic in-process model fixture.
        // It supplies no installed Host, QEMU, gem5 or external-device qualification.
        Ok(())
    }
}

/// Admits the complete model graph after refreshing every changed identity.
pub(super) fn graph(topology: Topology) -> (AdmittedGraph, NodeScenario) {
    let (original, contents) = test_double_graph(false);
    let mut evidence = ModelEvidence(contents);
    let mut descriptors: Vec<_> = original
        .node_ids()
        .map(|node| original.descriptor(node).unwrap().clone())
        .collect();
    let mut bindings: Vec<_> = original
        .node_ids()
        .map(|node| original.binding(node).unwrap().clone())
        .collect();
    let mut owners: Vec<_> = original.owners().cloned().collect();
    let mut world = original.world().clone();
    let mut ownership = original.ownership_policy().clone();
    let mut coordinator = original.coordinator_policy().clone();
    coordinator.external_inputs.clear();
    let shared = matches!(
        topology,
        Topology::SharedTransfer | Topology::SharedIsolated
    );

    if shared {
        owners.truncate(1);
        owners[0].owner.participant_ids = vec![id("a"), id("z")];
        owners[0].owner.state_domain_ids = ownership
            .domains
            .iter()
            .map(|domain| domain.id.clone())
            .collect();
        ownership.capture_owners.truncate(1);
        ownership.capture_owners[0].dependencies.clear();
        for domain in &mut ownership.domains {
            domain.capture_owner_id = id("owner/a");
            domain.execution_owner_ids = vec![id("owner/a")];
        }
        let authority = bindings[0].authority.clone();
        for binding in &mut bindings {
            binding.compatibility.execution_owner = owners[0].owner.clone();
            binding.compatibility.capture_owner = owners[0].owner.clone();
            binding.authority = authority.clone();
        }
        for connection in &mut world.connections {
            connection.capture_owner_id = id("owner/a");
        }
    } else if matches!(topology, Topology::Conflicting) {
        ownership.domains[1].execution_owner_ids.push(id("owner/z"));
        owners[1]
            .owner
            .state_domain_ids
            .insert(0, id("domain/transfer"));
        bindings[1].compatibility.execution_owner = owners[1].owner.clone();
        bindings[1].compatibility.capture_owner = owners[1].owner.clone();
    }

    let facet = FacetSelection {
        id: id("test-execution"),
        version: 1,
        configuration_ref: ownership.inventory_proof_ref.clone(),
        guarantees_ref: ownership.inventory_proof_ref.clone(),
        extensions: Extensions::new(),
    };
    for (descriptor, binding) in descriptors.iter_mut().zip(&mut bindings) {
        if matches!(topology, Topology::SharedTransfer) {
            let direction = if descriptor.id == id("a") {
                Direction::Output
            } else {
                Direction::Input
            };
            let port = &mut descriptor.ports[0];
            port.lanes.retain(|lane| lane.direction == direction);
            let mut policy: PortPolicy = evidence.decode(&port.configuration_ref);
            policy.execution_owner_id = id("owner/a");
            policy.lanes.retain(|lane| {
                port.lanes
                    .iter()
                    .any(|selected| selected.id == lane.lane_id)
            });
            port.configuration_ref = evidence.put(&policy);
        } else {
            descriptor.ports.clear();
        }
        let mut capabilities: CapabilityProfile =
            evidence.decode(&binding.compatibility.capabilities_ref);
        capabilities.facets = vec![facet.clone()];
        binding.compatibility.capabilities_ref = evidence.put(&capabilities);
        binding.compatibility.operating_contract.facets = vec![facet.clone()];
        binding.compatibility.descriptor_hash = descriptor.identity().unwrap();
    }
    if !matches!(topology, Topology::SharedTransfer) {
        world.connections.clear();
    }
    world.node_bindings = bindings
        .iter()
        .map(|binding| NodeBindingRef {
            node_id: binding.compatibility.node_id.clone(),
            binding_hash: binding.identity().unwrap(),
            extensions: Extensions::new(),
        })
        .collect();
    for owner in &mut owners {
        owner.node_bindings = world
            .node_bindings
            .iter()
            .filter(|binding| owner.owner.participant_ids.contains(&binding.node_id))
            .cloned()
            .collect();
    }
    world.ownership_ref = evidence.put(&ownership);
    world.coordinator_contract_ref = evidence.put(&coordinator);
    let requirements = original.requirements().clone();
    world.scenario_ref = evidence.put(&requirements);
    let admitted = admit_graph(
        AdmissionRequest {
            world: &world,
            descriptors: &descriptors,
            bindings: &bindings,
            owners: &owners,
            requirements: &requirements,
        },
        &evidence,
        AdmissionLimits::default(),
    )
    .unwrap();
    let scenario = NodeScenario {
        format: "crucible.node-scenario".into(),
        version: 1,
        world,
        descriptors,
        compatibility: bindings
            .into_iter()
            .map(|binding| binding.compatibility)
            .collect(),
        owners,
        requirements,
        content: vec![],
    };
    (admitted, scenario)
}
