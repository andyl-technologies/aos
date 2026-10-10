//! Bounded immutable data projection from an actual admitted core graph.
//!
//! This projection walks explicit typed fields only. It neither interprets
//! opaque contract bodies nor supplies installed, live, or capture authority.

use std::io::{self, Write};

use crucible_node_contract::{
    BindingCompatibility, ContentRef, Extensions, NodeDescriptor, OwnerBinding, WorldBinding,
    canonical,
};
use serde::Serialize;

use crate::node_admission::{
    AdmittedGraph, ConnectionPolicy, CoordinatorPolicy, LaneVisibility, ObjectState,
    OwnershipPolicy, PortPolicy, VisibilityConversion,
};
use crate::node_scheduling::InputPayload;

use super::{StateError, StateErrorCode, StateLimits, closure::limit, schema};

/// Contains one canonical admitted record projection and its direct typed references.
///
/// The regenerated body uses `application/json`; it does not establish the
/// original encoding of a referenced policy. The caller must compare that
/// encoding with its independently retained original body.
/// Dependencies are sorted full ContentRefs;
/// their bytes and semantics must still be supplied by the installed reader.
#[derive(Debug)]
pub struct AdmittedGraphRecord {
    object: InputPayload,
    dependencies: Vec<ContentRef>,
}

impl AdmittedGraphRecord {
    /// Borrows the regenerated canonical body and its data content identity.
    pub fn object(&self) -> &InputPayload {
        &self.object
    }

    /// Borrows the explicit direct references in the admitted record.
    pub fn dependencies(&self) -> &[ContentRef] {
        &self.dependencies
    }
}

/// Projects closed core records from the exact admitted graph without effects.
///
/// It includes World, Owner, durable BindingCompatibility, Descriptor,
/// OwnershipPolicy, CoordinatorPolicy, and admitted Port/Connection policies.
/// Live authority, opaque referenced bytes and selected extension semantics are
/// excluded. Nonempty extension maps refuse rather than becoming inferred edges.
/// Every record, aggregate encoded bytes and direct-edge occurrence is charged
/// before canonical bodies or reference copies are allocated. Returned records
/// confer no additional admission, readiness or preservation authority.
///
/// # Errors
/// Refuses missing admitted records, unsupported extensions, byte/record/edge
/// limits, allocation failures, or canonical serialization failures.
pub fn admitted_graph_records(
    graph: &AdmittedGraph,
    limits: StateLimits,
) -> Result<Vec<AdmittedGraphRecord>, StateError> {
    let mut record_count = 0usize;
    let mut total_bytes = 0usize;
    let mut total_edges = 0usize;
    walk(graph, |record| {
        record_count = charged(record_count, 1, limits.maximum_content_objects)?;
        let size = record.encoded_size(limits.maximum_record_bytes)?;
        if size > limits.maximum_content_bytes {
            return Err(limit("admitted graph record bytes"));
        }
        total_bytes = charged(total_bytes, size, limits.maximum_total_content_bytes)?;
        record.references(&mut |_| {
            total_edges = charged(total_edges, 1, limits.maximum_dependency_edges)?;
            Ok(())
        })
    })?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(record_count)
        .map_err(|_| limit("admitted graph rows"))?;
    walk(graph, |record| {
        let mut count = 0usize;
        record.references(&mut |_| {
            count += 1;
            Ok(())
        })?;
        let mut dependencies = Vec::new();
        dependencies
            .try_reserve_exact(count)
            .map_err(|_| limit("admitted graph edges"))?;
        record.references(&mut |reference| {
            dependencies.push(reference.clone());
            Ok(())
        })?;
        dependencies.sort();
        dependencies.dedup();
        let bytes = record.canonical_body()?;
        let reference = canonical::content_ref(&bytes, "application/json").map_err(schema)?;
        output.push(AdmittedGraphRecord {
            object: InputPayload { reference, bytes },
            dependencies,
        });
        Ok(())
    })?;
    Ok(output)
}

#[derive(Clone, Copy)]
enum Record<'a> {
    World(&'a WorldBinding),
    Owner(&'a OwnerBinding),
    Compatibility(&'a BindingCompatibility),
    Descriptor(&'a NodeDescriptor),
    Ownership(&'a OwnershipPolicy),
    Coordinator(&'a CoordinatorPolicy),
    Port(&'a PortPolicy),
    Connection(&'a ConnectionPolicy),
}

impl Serialize for Record<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::World(value) => value.serialize(serializer),
            Self::Owner(value) => value.serialize(serializer),
            Self::Compatibility(value) => value.serialize(serializer),
            Self::Descriptor(value) => value.serialize(serializer),
            Self::Ownership(value) => value.serialize(serializer),
            Self::Coordinator(value) => value.serialize(serializer),
            Self::Port(value) => value.serialize(serializer),
            Self::Connection(value) => value.serialize(serializer),
        }
    }
}

impl Record<'_> {
    fn encoded_size(self, maximum: usize) -> Result<usize, StateError> {
        let mut counter = Counter { size: 0, maximum };
        serde_json::to_writer(&mut counter, &self)
            .map_err(|_| limit("admitted graph encoded bytes"))?;
        Ok(counter.size)
    }

    fn canonical_body(self) -> Result<Vec<u8>, StateError> {
        canonical::canonical_json(&serde_json::to_value(self).map_err(schema)?).map_err(schema)
    }

    fn references(
        self,
        visit: &mut impl FnMut(&ContentRef) -> Result<(), StateError>,
    ) -> Result<(), StateError> {
        match self {
            Self::World(value) => {
                empty(&value.extensions)?;
                for binding in &value.node_bindings {
                    empty(&binding.extensions)?;
                }
                visit(&value.scenario_ref)?;
                visit(&value.ownership_ref)?;
                visit(&value.coordinator_contract_ref)?;
                visit(&value.initialization_ref)?;
                for connection in &value.connections {
                    empty(&connection.extensions)?;
                    empty(&connection.payload_schema.extensions)?;
                    visit(&connection.payload_schema.definition)?;
                    visit(&connection.policy_ref)?;
                }
            }
            Self::Owner(value) => {
                empty(&value.extensions)?;
                for binding in &value.node_bindings {
                    empty(&binding.extensions)?;
                }
                visit(&value.ownership_ref)?;
            }
            Self::Compatibility(value) => {
                empty(&value.extensions)?;
                empty(&value.implementation.extensions)?;
                for artifact in &value.implementation.artifacts {
                    empty(&artifact.extensions)?;
                    visit(&artifact.content)?;
                }
                for reference in &value.implementation.model_definitions {
                    visit(reference)?;
                }
                for format in &value.implementation.formats {
                    empty(&format.extensions)?;
                    visit(&format.definition)?;
                }
                visit(&value.profile_ref)?;
                visit(&value.configuration_ref)?;
                visit(&value.capabilities_ref)?;
                visit(&value.guarantees_ref)?;
                for reference in &value.qualification_refs {
                    visit(reference)?;
                }
                empty(&value.operating_contract.extensions)?;
                visit(&value.operating_contract.policy_ref)?;
                for facet in &value.operating_contract.facets {
                    empty(&facet.extensions)?;
                    visit(&facet.configuration_ref)?;
                    visit(&facet.guarantees_ref)?;
                }
            }
            Self::Descriptor(value) => {
                empty(&value.extensions)?;
                visit(&value.model_ref)?;
                visit(&value.configuration_ref)?;
                visit(&value.initialization_ref)?;
                for port in &value.ports {
                    empty(&port.extensions)?;
                    visit(&port.configuration_ref)?;
                    for lane in &port.lanes {
                        empty(&lane.extensions)?;
                        empty(&lane.payload_schema.extensions)?;
                        visit(&lane.payload_schema.definition)?;
                    }
                }
            }
            Self::Ownership(value) => {
                visit(&value.inventory_proof_ref)?;
                for object in &value.objects {
                    if let ObjectState::Immutable { content_ref } = &object.state {
                        visit(content_ref)?;
                    }
                }
                for dependency in &value.internal_dependencies {
                    visit(&dependency.proof_ref)?;
                }
                for owner in &value.capture_owners {
                    visit(&owner.cut_procedure_ref)?;
                }
            }
            Self::Coordinator(value) => {
                visit(&value.state_closure_ref)?;
                visit(&value.operational_policy_ref)?;
                for closure in &value.same_time_closure {
                    visit(&closure.proof_ref)?;
                }
            }
            Self::Port(value) => {
                visit(&value.arbitration_ref)?;
                for lane in &value.lanes {
                    visit(&lane.ordering_ref)?;
                    visit(&lane.correlation_ref)?;
                    if let LaneVisibility::Quantized { contract_ref, .. } = &lane.visibility {
                        visit(contract_ref)?;
                    }
                }
            }
            Self::Connection(value) => {
                visit(&value.causal_proof_ref)?;
                match &value.visibility {
                    VisibilityConversion::Direct => {}
                    VisibilityConversion::PublicationPreserving { contract_ref }
                    | VisibilityConversion::BoundarySampling { contract_ref }
                    | VisibilityConversion::Adapter { contract_ref } => visit(contract_ref)?,
                }
            }
        }
        Ok(())
    }
}

fn walk(
    graph: &AdmittedGraph,
    mut visit: impl FnMut(Record<'_>) -> Result<(), StateError>,
) -> Result<(), StateError> {
    visit(Record::World(graph.world()))?;
    for owner in graph.owners() {
        visit(Record::Owner(owner))?;
    }
    for id in graph.node_ids() {
        let binding = graph.binding(id).ok_or_else(|| missing("binding"))?;
        let descriptor = graph.descriptor(id).ok_or_else(|| missing("descriptor"))?;
        visit(Record::Compatibility(&binding.compatibility))?;
        visit(Record::Descriptor(descriptor))?;
        for port in &descriptor.ports {
            visit(Record::Port(
                graph
                    .port_policy(id, &port.id)
                    .ok_or_else(|| missing("port policy"))?,
            ))?;
        }
    }
    visit(Record::Ownership(graph.ownership_policy()))?;
    visit(Record::Coordinator(graph.coordinator_policy()))?;
    for connection in &graph.world().connections {
        visit(Record::Connection(
            graph
                .connection_policy(&connection.id)
                .ok_or_else(|| missing("connection policy"))?,
        ))?;
    }
    Ok(())
}

fn empty(extensions: &Extensions) -> Result<(), StateError> {
    if extensions.is_empty() {
        Ok(())
    } else {
        Err(StateError::new(
            StateErrorCode::Schema,
            "admitted graph projection",
            "selected extension edges require their installed codec",
        ))
    }
}

fn charged(current: usize, additional: usize, maximum: usize) -> Result<usize, StateError> {
    current
        .checked_add(additional)
        .filter(|value| *value <= maximum)
        .ok_or_else(|| limit("admitted graph aggregate credit"))
}

fn missing(role: &str) -> StateError {
    StateError::new(
        StateErrorCode::IncompleteClosure,
        "admitted graph projection",
        format!("missing admitted {role}"),
    )
}

struct Counter {
    size: usize,
    maximum: usize,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.size = self
            .size
            .checked_add(bytes.len())
            .filter(|size| *size <= self.maximum)
            .ok_or_else(|| io::Error::other("admitted record byte credit exhausted"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "admitted_graph_references_tests.rs"]
mod tests;
