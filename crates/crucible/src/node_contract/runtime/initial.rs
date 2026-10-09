//! Bounded initial coordinator extraction with authentic fresh native preparation.
//!
//! `crucible/coordinator-initial/1` preserves the complete admitted world,
//! original native preparation records, routing, ownership and scheduling
//! policies. Empty ledgers and an uninitialized scheduler are valid only after
//! every actual node authenticates fresh initial state. This codec cannot restore
//! a world or serialize process-local execution authority.
//!
//! ```text
//! {"schema":"crucible/coordinator-initial/1","schema_version":1,
//!  "scheduler":{"state":"not_initialized","operations":[],"inputs":[],
//!               "publications":[],"deliveries":[],"reservations":[]}, ...}
//! ```

use std::io::Write;

use crucible_node_contract::{Id, canonical};
use serde::Serialize;

use super::*;
use crate::{
    node_admission::{AdmittedGraph, ConnectionPolicy, PortPolicy},
    node_contract::{
        MAXIMUM_ACTIVATION_COORDINATOR_BYTES, SavedRuntimeActivation, SavedRuntimeOwner,
    },
    node_scheduling::{ExecutionPolicy, InputPayload},
};

#[derive(Serialize)]
struct InitialNode<'a> {
    descriptor: &'a NodeDescriptor,
    binding: &'a NodeBinding,
    route: &'a NodeRoute,
    facets: Vec<&'static str>,
    native_thread_custody: &'static str,
    operating_policy: Option<&'a ExecutionPolicy>,
    guarantees: &'a crucible_node_contract::GuaranteeProfile,
    effective_repeatability: crucible_node_contract::Repeatability,
    ports: Vec<(&'a Id, &'a PortPolicy)>,
}

#[derive(Serialize)]
struct InitialScheduler {
    state: &'static str,
    operations: [Id; 0],
    inputs: [Id; 0],
    publications: [Id; 0],
    deliveries: [Id; 0],
    reservations: [Id; 0],
}

impl NodeRuntime {
    /// Extracts the complete coordinator state of a genuinely fresh armed world.
    ///
    /// Every actual node must authenticate its original fresh native realization.
    /// Restored nodes cannot qualify merely because host ledgers are still empty.
    /// The returned data grants no execution authority and must be durably bound
    /// by the complete activation publisher before public `WorldActivate`.
    /// Process-local handles and thread IDs remain under native supervision;
    /// this object records their selected custody policy, never a reusable ID.
    ///
    /// # Errors
    /// Refuses unarmed, published, uncertain, restored or changed worlds, native
    /// fresh-state refusal, retained work or bytes exceeding the finite ceiling.
    pub fn initial_coordinator_snapshot(
        &self,
        graph: &AdmittedGraph,
        maximum_record_bytes: usize,
    ) -> Result<InputPayload, RuntimeError> {
        let record = self.barrier.record();
        let preparations = self.prepared_node_records()?;
        if maximum_record_bytes == 0
            || maximum_record_bytes > MAXIMUM_ACTIVATION_COORDINATOR_BYTES
            || self.activated
            || self.scheduler.is_some()
            || !self.operations.is_empty()
            || !self.input_batches.is_empty()
            || preparations.len() != self.nodes.len()
            || record.world_binding_hash != *graph.world_binding_hash()
            || record.boundary
                != crucible_node_contract::Position::new(
                    crucible_node_contract::U64::new(0),
                    crucible_node_contract::U64::new(0),
                    crucible_node_contract::Phase::BoundaryControl,
                )
            || graph.node_ids().ne(self.nodes.keys())
            || self
                .owners
                .values()
                .any(|owner| owner.lifecycle != Lifecycle::Prepared || owner.operation.is_some())
        {
            return Err(RuntimeError::OutstandingObligations);
        }

        for prepared in preparations {
            let node = self
                .nodes
                .get(prepared.node())
                .ok_or(RuntimeError::UnknownNode)?;
            let snapshot = self
                .snapshots
                .get(prepared.node())
                .ok_or(RuntimeError::UnknownNode)?;
            if graph.descriptor(prepared.node()) != Some(&snapshot.descriptor)
                || graph.binding(prepared.node()) != Some(&snapshot.binding)
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            snapshot.validate_current(node.as_ref())?;
            node.validate_initial_preparation(record, prepared.readiness())
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            snapshot.validate_current(node.as_ref())?;
        }

        let nodes = self
            .snapshots
            .iter()
            .map(|(id, node)| {
                let ports = node
                    .descriptor
                    .ports
                    .iter()
                    .map(|port| {
                        graph
                            .port_policy(id, &port.id)
                            .map(|policy| (&port.id, policy))
                            .ok_or(RuntimeError::InvalidRoute)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(InitialNode {
                    descriptor: &node.descriptor,
                    binding: &node.binding,
                    route: &node.route,
                    facets: node.facets.iter().copied().map(facet_name).collect(),
                    native_thread_custody: match node.thread_affinity {
                        super::super::ThreadAffinity::OwnerThread(_) => "owner-thread",
                        super::super::ThreadAffinity::OwningActor => "owning-actor",
                    },
                    operating_policy: graph.operating_policy(id),
                    guarantees: graph.guarantees(id).ok_or(RuntimeError::InvalidRoute)?,
                    effective_repeatability: graph
                        .effective_repeatability(id)
                        .ok_or(RuntimeError::InvalidRoute)?,
                    ports,
                })
            })
            .collect::<Result<Vec<_>, RuntimeError>>()?;
        let connections = graph
            .world()
            .connections
            .iter()
            .map(|connection| {
                graph
                    .connection_policy(&connection.id)
                    .map(|policy| (&connection.id, policy))
                    .ok_or(RuntimeError::InvalidRoute)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let owners = self
            .owners
            .values()
            .map(|owner| SavedRuntimeOwner {
                identity: owner.identity.clone(),
                lifecycle: owner.lifecycle,
                operation: owner.operation.clone(),
                domains: owner.domains.iter().cloned().collect(),
            })
            .collect::<Vec<_>>();
        let owner_bindings = graph.owners().collect::<Vec<_>>();
        let owner_conflicts = graph
            .owners()
            .map(|owner| {
                graph
                    .owner_conflicts(&owner.owner.id)
                    .map(|conflicts| (&owner.owner.id, conflicts))
                    .ok_or(RuntimeError::InvalidRoute)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let object = InitialObject {
            schema: "crucible/coordinator-initial/1",
            schema_version: 1,
            activation: record.into(),
            world: graph.world(),
            ownership: graph.ownership_policy(),
            coordinator: graph.coordinator_policy(),
            requirements: graph.requirements(),
            nodes,
            owners,
            owner_bindings,
            owner_conflicts,
            preparations,
            connections,
            limits: InitialLimits {
                maximum_nodes: self.limits.maximum_nodes,
                maximum_owners: self.limits.maximum_owners,
                maximum_operations: self.limits.maximum_operations,
                maximum_retained_outputs: self.limits.maximum_retained_outputs,
            },
            world_repeatability: graph.world_repeatability(),
            clock: record.boundary,
            scheduler: InitialScheduler {
                state: "not_initialized",
                operations: [],
                inputs: [],
                publications: [],
                deliveries: [],
                reservations: [],
            },
        };
        // Bound serialization before building the canonical JSON value. Native
        // payloads cannot cause unbounded cloning during initial extraction.
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            maximum: maximum_record_bytes,
        };
        serde_json::to_writer(&mut writer, &object).map_err(|_| RuntimeError::ResourceLimit)?;
        let value = canonical::parse_json(&writer.bytes, maximum_record_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let bytes = canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
        if bytes.len() > maximum_record_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(InputPayload { reference, bytes })
    }
}

#[derive(Serialize)]
struct InitialObject<'a> {
    schema: &'static str,
    schema_version: u16,
    activation: SavedRuntimeActivation,
    world: &'a crucible_node_contract::WorldBinding,
    ownership: &'a crate::node_admission::OwnershipPolicy,
    coordinator: &'a crate::node_admission::CoordinatorPolicy,
    requirements: &'a crate::node_admission::ScenarioRequirements,
    nodes: Vec<InitialNode<'a>>,
    owners: Vec<SavedRuntimeOwner>,
    owner_bindings: Vec<&'a crucible_node_contract::OwnerBinding>,
    owner_conflicts: Vec<(&'a Id, &'a std::collections::BTreeSet<Id>)>,
    preparations: &'a [ValidatedNodePreparation],
    connections: Vec<(&'a Id, &'a ConnectionPolicy)>,
    limits: InitialLimits,
    world_repeatability: crucible_node_contract::Repeatability,
    clock: crucible_node_contract::Position,
    scheduler: InitialScheduler,
}

#[derive(Serialize)]
struct InitialLimits {
    maximum_nodes: usize,
    maximum_owners: usize,
    maximum_operations: usize,
    maximum_retained_outputs: usize,
}

fn facet_name(facet: FacetKind) -> &'static str {
    match facet {
        FacetKind::ExactExecution => "exact-execution",
        FacetKind::QuantizedExecution => "quantized-execution",
        FacetKind::PhysicalPause => "physical-pause",
        FacetKind::Preservation => "preservation",
        FacetKind::Replay => "replay",
        FacetKind::FaultInjection => "fault-injection",
        FacetKind::Coverage => "coverage",
        FacetKind::Introspection => "introspection",
        FacetKind::Debugging => "debugging",
        FacetKind::TerminalAssertions => "terminal-assertions",
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("initial coordinator byte ceiling"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
