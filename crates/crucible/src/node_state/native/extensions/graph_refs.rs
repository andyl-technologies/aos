//! Enumerates closed admitted graph records without interpreting extension values.
//!
//! Every extension map encountered here must match its original independently
//! admitted application, including the full containing record and typed scope.
//! Its complete parameter dependencies belong to the separately authenticated
//! selected codec inventory. Generic runtime/native record parsing is unchanged.

use crucible_node_contract::{
    BindingCompatibility, ContentRef, Extensions, HashRef, Id, NodeBindingRef, NodeDescriptor,
    SchemaRef, Validate, canonical,
};
use serde::Serialize;

use crate::node_admission::{
    AdmittedGraph, ExtensionRecordKind as Kind, ExtensionRecordPath as Path,
};
use crate::node_state::{StateError, StateErrorCode, StateLimits};

use super::PreparedExtensionClosure;

/// Retains exact graph roots without exposing a caller-issued omission grant.
#[derive(Debug)]
pub(crate) struct SelectedGraphReferences {
    world: HashRef,
    selection: HashRef,
    record_ceiling: usize,
    references: Vec<ContentRef>,
}

impl SelectedGraphReferences {
    /// Borrows the complete original immutable roots under the installed codec.
    pub(crate) fn roots(&self) -> &[ContentRef] {
        &self.references
    }

    /// Rechecks original graph identity and the preflight's finite credit scope.
    ///
    /// # Errors
    /// Refuses another original graph/selection or credits smaller than those
    /// under which the complete typed record projection was authenticated.
    pub(crate) fn verify(
        &self,
        graph: &AdmittedGraph,
        limits: StateLimits,
    ) -> Result<(), StateError> {
        if self.world != *graph.world_binding_hash()
            || self.selection != graph.selected_extensions().identity().map_err(invalid)?
        {
            return Err(refused(
                "immutable projection belongs to another original graph",
            ));
        }
        if self.record_ceiling > limits.maximum_record_bytes
            || self.references.len() > limits.maximum_content_objects
        {
            return Err(limit("original graph projection preflight credits differ"));
        }
        Ok(())
    }
}

/// Resolves only actual typed graph records under the installed selected codec.
///
/// # Errors
/// Refuses mismatched selected identities, unknown or altered original map
/// applications, changed typed scope, unsupported closed policies, or exhausted
/// serialization/reference credits before exposing any root inventory.
pub(crate) fn immutable_refs(
    graph: &AdmittedGraph,
    selected: &PreparedExtensionClosure,
    limits: StateLimits,
) -> Result<SelectedGraphReferences, StateError> {
    let supported = StateLimits::default();
    if limits.maximum_record_bytes > supported.maximum_record_bytes
        || limits.maximum_content_objects > supported.maximum_content_objects
    {
        return Err(limit("supported selected graph projection ceilings"));
    }
    if graph.selected_extensions().is_empty()
        || selected.inventory.world_binding_hash != *graph.world_binding_hash()
        || selected.inventory.selection_identity
            != graph.selected_extensions().identity().map_err(invalid)?
    {
        return Err(refused(
            "selected graph projection belongs to another original world",
        ));
    }
    let mut collector = Collector {
        graph,
        limits,
        references: Vec::new(),
    };
    collector.world()?;
    for owner in graph.owners() {
        crate::node_state::closure::bounded_record(owner, limits.maximum_record_bytes)?;
        collector.check_map(
            owner,
            &owner.extensions,
            Kind::OwnerBinding,
            None,
            Path::Owner {
                owner: owner.owner.id.clone(),
            },
        )?;
        collector.reference(&owner.ownership_ref)?;
        for binding in &owner.node_bindings {
            collector.binding_ref(
                binding,
                Path::OwnerNodeBindingRef {
                    owner: owner.owner.id.clone(),
                    node: binding.node_id.clone(),
                },
            )?;
        }
    }
    for node in graph.node_ids() {
        let binding = graph
            .binding(node)
            .ok_or_else(|| refused("actual admitted node binding is absent"))?;
        let descriptor = graph
            .descriptor(node)
            .ok_or_else(|| refused("actual admitted node descriptor is absent"))?;
        collector.binding(&binding.compatibility)?;
        collector.descriptor(descriptor)?;
    }

    // These closed host policies have no extensible record locations. Retain
    // their normal parser refusal instead of permitting arbitrary JSON skips.
    collector.closed_policy(graph.ownership_policy())?;
    collector.closed_policy(graph.coordinator_policy())?;
    collector.reference(&selected.record.reference)?;
    collector.references.sort();
    collector.references.dedup();
    Ok(SelectedGraphReferences {
        world: selected.inventory.world_binding_hash.clone(),
        selection: selected.inventory.selection_identity.clone(),
        record_ceiling: limits.maximum_record_bytes,
        references: collector.references,
    })
}

struct Collector<'a> {
    graph: &'a AdmittedGraph,
    limits: StateLimits,
    references: Vec<ContentRef>,
}

impl Collector<'_> {
    fn world(&mut self) -> Result<(), StateError> {
        let world = self.graph.world();
        self.check_map(
            world,
            &world.extensions,
            Kind::WorldBinding,
            None,
            Path::World,
        )?;
        for reference in [
            &world.scenario_ref,
            &world.ownership_ref,
            &world.coordinator_contract_ref,
            &world.initialization_ref,
        ] {
            self.reference(reference)?;
        }
        for binding in &world.node_bindings {
            self.binding_ref(
                binding,
                Path::WorldNodeBindingRef {
                    node: binding.node_id.clone(),
                },
            )?;
        }
        for connection in &world.connections {
            self.check_map(
                connection,
                &connection.extensions,
                Kind::ConnectionDescriptor,
                None,
                Path::Connection {
                    connection: connection.id.clone(),
                },
            )?;
            self.reference(&connection.policy_ref)?;
            self.schema(
                &connection.payload_schema,
                None,
                Path::ConnectionSchema {
                    connection: connection.id.clone(),
                    schema: connection.payload_schema.id.clone(),
                },
            )?;
        }
        Ok(())
    }

    fn binding_ref(&self, binding: &NodeBindingRef, path: Path) -> Result<(), StateError> {
        self.check_map(
            binding,
            &binding.extensions,
            Kind::NodeBindingRef,
            Some(&binding.node_id),
            path,
        )
    }

    fn descriptor(&mut self, descriptor: &NodeDescriptor) -> Result<(), StateError> {
        self.check_map(
            descriptor,
            &descriptor.extensions,
            Kind::NodeDescriptor,
            Some(&descriptor.id),
            Path::Node,
        )?;
        for reference in [
            &descriptor.model_ref,
            &descriptor.configuration_ref,
            &descriptor.initialization_ref,
        ] {
            self.reference(reference)?;
        }
        for port in &descriptor.ports {
            self.check_map(
                port,
                &port.extensions,
                Kind::PortDescriptor,
                Some(&descriptor.id),
                Path::Port {
                    port: port.id.clone(),
                },
            )?;
            self.reference(&port.configuration_ref)?;
            for lane in &port.lanes {
                self.check_map(
                    lane,
                    &lane.extensions,
                    Kind::LaneDescriptor,
                    Some(&descriptor.id),
                    Path::Lane {
                        port: port.id.clone(),
                        lane: lane.id.clone(),
                    },
                )?;
                self.schema(
                    &lane.payload_schema,
                    Some(&descriptor.id),
                    Path::LaneSchema {
                        port: port.id.clone(),
                        lane: lane.id.clone(),
                        schema: lane.payload_schema.id.clone(),
                    },
                )?;
            }
        }
        Ok(())
    }

    fn binding(&mut self, binding: &BindingCompatibility) -> Result<(), StateError> {
        let node = &binding.node_id;
        self.check_map(
            binding,
            &binding.extensions,
            Kind::BindingCompatibility,
            Some(node),
            Path::Node,
        )?;
        let implementation = &binding.implementation;
        self.check_map(
            implementation,
            &implementation.extensions,
            Kind::ImplementationIdentity,
            Some(node),
            Path::Node,
        )?;
        for artifact in &implementation.artifacts {
            self.check_map(
                artifact,
                &artifact.extensions,
                Kind::ArtifactIdentity,
                Some(node),
                Path::Artifact {
                    artifact: artifact.id.clone(),
                },
            )?;
            self.reference(&artifact.content)?;
        }
        for reference in &implementation.model_definitions {
            self.reference(reference)?;
        }
        for schema in &implementation.formats {
            self.schema(
                schema,
                Some(node),
                Path::ImplementationSchema {
                    schema: schema.id.clone(),
                    version: schema.version,
                },
            )?;
        }
        for reference in [
            &binding.profile_ref,
            &binding.configuration_ref,
            &binding.capabilities_ref,
            &binding.guarantees_ref,
        ] {
            self.reference(reference)?;
        }
        for reference in &binding.qualification_refs {
            self.reference(reference)?;
        }
        let operating = &binding.operating_contract;
        self.check_map(
            operating,
            &operating.extensions,
            Kind::OperatingContract,
            Some(node),
            Path::Node,
        )?;
        self.reference(&operating.policy_ref)?;
        for facet in &operating.facets {
            self.check_map(
                facet,
                &facet.extensions,
                Kind::FacetSelection,
                Some(node),
                Path::SelectedFacet {
                    facet: facet.id.clone(),
                },
            )?;
            self.reference(&facet.configuration_ref)?;
            self.reference(&facet.guarantees_ref)?;
        }
        Ok(())
    }

    fn schema(
        &mut self,
        schema: &SchemaRef,
        node: Option<&Id>,
        path: Path,
    ) -> Result<(), StateError> {
        self.check_map(schema, &schema.extensions, Kind::SchemaRef, node, path)?;
        self.reference(&schema.definition)
    }

    fn check_map(
        &self,
        record: &impl Serialize,
        map: &Extensions,
        kind: Kind,
        node: Option<&Id>,
        path: Path,
    ) -> Result<(), StateError> {
        crate::node_state::closure::bounded_record(record, self.limits.maximum_record_bytes)?;
        if map.is_empty() {
            return Ok(());
        }
        let record_hash =
            canonical::json_hash("cnp.extension-application-record.v1", record).map_err(invalid)?;
        let binding_hash = node
            .map(|id| {
                self.graph
                    .binding(id)
                    .ok_or_else(|| refused("extension map has no actual selected node"))?
                    .compatibility
                    .identity()
                    .map_err(invalid)
            })
            .transpose()?;
        for (identifier, raw) in map {
            let raw_hash =
                canonical::json_hash("crucible.native-extension-use.v1", raw).map_err(invalid)?;
            let original = self
                .graph
                .selected_extensions()
                .applications()
                .find(|application| {
                    let scope = application.scope();
                    scope.record_kind() == kind
                        && scope.record_path() == &path
                        && scope.node() == node
                        && scope.binding_hash() == binding_hash.as_ref()
                        && scope.world_hash() == self.graph.world_binding_hash()
                        && scope.record_hash() == &record_hash
                        && application.selected().selection.identifier.as_str() == identifier
                })
                .ok_or_else(|| {
                    refused("extension map lacks its exact admitted record application")
                })?;
            if canonical::json_hash("crucible.native-extension-use.v1", original.selected())
                .map_err(invalid)?
                != raw_hash
            {
                return Err(refused(
                    "original extension parameters or exact selection differ",
                ));
            }
        }
        Ok(())
    }

    fn reference(&mut self, reference: &ContentRef) -> Result<(), StateError> {
        reference.validate().map_err(invalid)?;
        if self.references.len() >= self.limits.maximum_content_objects {
            return Err(limit("selected graph immutable reference slots"));
        }
        self.references
            .try_reserve(1)
            .map_err(|_| limit("selected graph immutable reference slots"))?;
        self.references.push(reference.clone());
        Ok(())
    }

    fn closed_policy(&mut self, policy: &impl Serialize) -> Result<(), StateError> {
        crate::node_state::closure::bounded_record(policy, self.limits.maximum_record_bytes)?;
        let value = serde_json::to_value(policy).map_err(invalid)?;
        let mut pending = Vec::new();
        pending
            .try_reserve(1)
            .map_err(|_| limit("closed policy traversal"))?;
        pending.push(&value);
        while let Some(value) = pending.pop() {
            match value {
                serde_json::Value::Object(object) => {
                    if object
                        .get("extensions")
                        .is_some_and(|map| !map.as_object().is_some_and(|map| map.is_empty()))
                    {
                        return Err(refused(
                            "closed host policy cannot reinterpret extension maps",
                        ));
                    }
                    if object.contains_key("hash")
                        && object.contains_key("length")
                        && object.contains_key("media_type")
                    {
                        let reference = serde_json::from_value(value.clone()).map_err(invalid)?;
                        self.reference(&reference)?;
                    } else {
                        pending
                            .try_reserve(object.len())
                            .map_err(|_| limit("closed policy traversal"))?;
                        pending.extend(object.values());
                    }
                }
                serde_json::Value::Array(array) => {
                    pending
                        .try_reserve(array.len())
                        .map_err(|_| limit("closed policy traversal"))?;
                    pending.extend(array);
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn invalid(error: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::Content,
        "selected graph immutable inputs",
        error.to_string(),
    )
}

fn refused(reason: &'static str) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "selected graph immutable inputs",
        reason,
    )
}

fn limit(reason: &'static str) -> StateError {
    StateError::new(
        StateErrorCode::ResourceLimit,
        "selected graph immutable inputs",
        reason,
    )
}

#[cfg(test)]
#[path = "graph_refs_tests.rs"]
mod tests;
