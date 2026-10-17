//! Rechecks the same original independent graph policy at the final fence.
//!
//! Exact query data is not authority. The source-installed evidence object is
//! retained by original Rc identity, all independent predicates are re-evaluated,
//! and its trusted direct current-scope read is last. That read defaults to
//! refusal: copied answers, unrelated local gates and file hashes cannot issue
//! an independent graph-policy lease.

use std::{collections::BTreeMap, rc::Rc};

use crucible::{
    node_adapters::cnp::{CnpSemanticInstallation, CnpSemanticSource, PacketSemanticSource},
    node_admission::{
        AdmissionEvidence, EvidenceError, NodeCapabilityRequirement, QualificationClaim,
        ScenarioRequirements,
    },
};
use crucible_node_contract::{ContentRef, HashRef, Id, SchemaRef, WorldBinding};
use serde::{Serialize, Serializer, ser::SerializeSeq};

use super::{QualificationError, scope};

#[cfg(test)]
mod tests;

/// Defines one exact non-Node predicate supported by the independent host policy.
///
/// These are installation inputs, not evidence or accepted qualification.
/// Node, preservation, connection and same-time closure claims are unavailable.
/// The explicit NoPreservation variant authenticates only a limitation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum PacketGraphPredicate {
    /// Supports the complete authored scenario and weaker-contract acceptance.
    Scenario {
        /// Binds the complete source scenario.
        scenario: ContentRef,
    },
    /// Supports one complete selected port policy and interpretation.
    Port {
        /// Names the selected source port.
        port: Id,
        /// Binds its complete interpretation policy.
        policy: ContentRef,
    },
    /// Supports the actual complete owner inventory and its original proof.
    Inventory {
        /// Binds all actual ownership domains and objects.
        ownership: ContentRef,
        /// Binds the independent completeness proof.
        proof: ContentRef,
    },
    /// Supports only the exact all-false preservation limitation for this owner.
    ///
    /// This cannot qualify a preservation procedure or capture facet.
    NoPreservation {
        /// Names the original owner whose installed policy has no preservation.
        owner: Id,
        /// Binds the exact independently interpreted no-preservation body.
        limitation: ContentRef,
    },
    /// Supports the exact coordinator policy and its selected containment rules.
    Coordinator {
        /// Binds the complete selected coordinator policy.
        policy: ContentRef,
    },
}

/// Borrows a complete finite independent host graph policy before retention.
///
/// The original host policy must authenticate actual installed meanings, including
/// actual schema validators and semantic support. No initial answer is retained as authorization. Current source-installed
/// predicates are re-evaluated and joined to the same original direct read.
pub struct PacketGraphPolicyTable<'a> {
    /// Borrows complete public objects needed by this selected admission.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
    /// Borrows each actual independently installed schema validator identity.
    pub schemas: &'a [SchemaRef],
    /// Borrows exact independently supported operation capability requirements.
    pub capabilities: &'a [NodeCapabilityRequirement],
    /// Borrows complete independent scenario/port/inventory/coordinator predicates.
    pub predicates: &'a [PacketGraphPredicate],
}

/// Borrows the actual full scope read from one original independent host policy.
///
/// No field grants authority. The installed implementation must directly read
/// its actual original policy/validator/owner revision after all query callbacks,
/// covering every listed predicate and the complete selected source/world.
pub struct PacketGraphCurrentScope<'a> {
    /// Borrows the exact original source installation.
    pub selection: &'a CnpSemanticInstallation,
    /// Borrows its complete original selected world.
    pub world: &'a WorldBinding,
    /// Commits to the complete original scenario requirements.
    pub requirements_hash: &'a HashRef,
    /// Borrows all original immutable objects used by the independent graph policy.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
    /// Enumerates every independently installed schema validator being used.
    pub schemas: &'a [SchemaRef],
    /// Enumerates exact independently installed operation semantics being used.
    pub capabilities: &'a [NodeCapabilityRequirement],
    /// Enumerates every independent non-Node graph predicate being used.
    pub predicates: &'a [PacketGraphPredicate],
}

/// Supplies independently installed graph evidence and its actual current read.
///
/// The terminal hook must read the SAME original policy's actual current
/// authorization directly, without calling arbitrary vendor/node callbacks.
/// It must cover schema, authority, inventory and coordinator revisions even
/// when source files, native owner and collection plan remain unchanged.
/// Implementations cannot return success merely because the query callbacks
/// returned success or the supplied data has matching hashes.
pub trait PacketGraphEvidence: AdmissionEvidence {
    /// Authenticates actual original independent graph scope after all callbacks.
    ///
    /// # Errors
    /// Refuses missing direct source-owned currentness, any foreign or revoked
    /// revision/scope, or unsupported predicates. The default always refuses.
    fn authenticate_current_packet_graph_scope(
        &self,
        _scope: PacketGraphCurrentScope<'_>,
    ) -> Result<(), EvidenceError> {
        Err(evidence(refused()))
    }
}

/// Retains original independent host policy and bounded exact query data.
///
/// This non-deserializable wrapper retains no successful qualification token.
/// Every final read re-evaluates the independent predicates on the SAME original
/// evidence and then requires its direct actual scope read. A fixture lacking
/// that independently installed implementation remains refused.
pub struct InstalledPacketGraphPolicy {
    source: Rc<PacketSemanticSource>,
    world: WorldBinding,
    requirements: HashRef,
    binding_hash: HashRef,
    original: Rc<dyn PacketGraphEvidence>,
    content: BTreeMap<ContentRef, Vec<u8>>,
    schemas: Vec<SchemaRef>,
    capabilities: Vec<NodeCapabilityRequirement>,
    predicates: Vec<PacketGraphPredicate>,
}

impl InstalledPacketGraphPolicy {
    /// Retains one independently configured policy and exact finite graph scope.
    ///
    /// All data is precharged before copying; every supplied body is checked
    /// against the original independent evidence. No Child or native operation
    /// occurs here, and no initial answer is converted into permanent authority.
    ///
    /// # Errors
    /// Refuses oversized or foreign scope, unsupported callbacks, incorrect
    /// original content, changed independent policy or missing terminal read.
    ///
    /// # Panics
    /// Propagates an independently installed evidence callback panic.
    pub fn install(
        source: Rc<PacketSemanticSource>,
        world: &WorldBinding,
        requirements: &ScenarioRequirements,
        table: PacketGraphPolicyTable<'_>,
        original: Rc<dyn PacketGraphEvidence>,
    ) -> Result<Rc<Self>, QualificationError> {
        if table.content.len() > 128
            || table.schemas.len() > 64
            || table.capabilities.len() > 16
            || table.predicates.len() > 32
        {
            return Err(refused());
        }
        let selected = source.installation();
        scope::encoded_size(
            &(
                world,
                requirements,
                &selected.provider,
                &selected.descriptor,
                &selected.binding,
                &selected.owner,
            ),
            1024 * 1024,
        )?;
        scope::encoded_size(
            &(
                GraphBodies(table.content),
                table.schemas,
                table.capabilities,
                table.predicates,
            ),
            8 * 1024 * 1024 / 3,
        )?;
        if world.identity()? != selected.world_binding_hash
            || world.node_bindings.len() != 1
            || !world.connections.is_empty()
        {
            return Err(refused());
        }
        let binding_hash = selected.binding.compatibility.identity()?;
        for (reference, body) in table.content {
            if body.len() > 1024 * 1024 {
                return Err(refused());
            }
            reference.verify(body)?;
            let observed = original.content(reference, body.len()).map_err(external)?;
            if observed != *body {
                return Err(refused());
            }
        }
        let installed = Rc::new(Self {
            source,
            world: world.clone(),
            requirements: requirements_hash(requirements)?,
            binding_hash,
            original,
            content: (*table.content).clone(),
            schemas: table.schemas.to_vec(),
            capabilities: table.capabilities.to_vec(),
            predicates: table.predicates.to_vec(),
        });
        installed.read_current()?;
        Ok(installed)
    }

    pub(super) fn current(
        &self,
        source: &Rc<PacketSemanticSource>,
        world: &WorldBinding,
        requirements: &HashRef,
    ) -> Result<(), QualificationError> {
        if !Rc::ptr_eq(source, &self.source)
            || world != &self.world
            || requirements != &self.requirements
        {
            return Err(refused());
        }
        self.read_current()
    }

    fn read_current(&self) -> Result<(), QualificationError> {
        read_after_callbacks(
            || self.check_predicates(),
            || {
                // The same installed independent authority reads its original
                // full scope directly. No callback follows this terminal read.
                self.original
                    .authenticate_current_packet_graph_scope(PacketGraphCurrentScope {
                        selection: self.source.installation(),
                        world: &self.world,
                        requirements_hash: &self.requirements,
                        content: &self.content,
                        schemas: &self.schemas,
                        capabilities: &self.capabilities,
                        predicates: &self.predicates,
                    })
                    .map_err(external)
            },
        )
    }

    fn check_predicates(&self) -> Result<(), QualificationError> {
        let selected = self.source.installation();
        self.original
            .authenticate_implementation(&selected.provider.implementation)
            .map_err(external)?;
        self.original
            .authenticate_authority(&selected.binding)
            .map_err(external)?;
        for schema in &self.schemas {
            self.original
                .authenticate_schema(schema)
                .map_err(external)?;
        }
        for capability in &self.capabilities {
            if capability.node != selected.descriptor.id {
                return Err(refused());
            }
            self.original
                .qualify_capability(&self.world, &selected.binding, capability)
                .map_err(external)?;
        }
        for predicate in &self.predicates {
            self.original
                .qualify(predicate.claim(
                    &self.world,
                    &self.requirements,
                    &self.binding_hash,
                    &self.source,
                )?)
                .map_err(external)?;
        }
        Ok(())
    }
}

impl AdmissionEvidence for InstalledPacketGraphPolicy {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        let expected = self
            .content
            .get(reference)
            .ok_or_else(|| evidence(refused()))?;
        if expected.len() > maximum_bytes {
            return Err(evidence(refused()));
        }
        let body = self.original.content(reference, maximum_bytes)?;
        if body != *expected {
            return Err(evidence(refused()));
        }
        self.read_current().map_err(evidence)?;
        Ok(body)
    }

    fn authenticate_implementation(
        &self,
        implementation: &crucible_node_contract::ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        if implementation != &self.source.installation().provider.implementation {
            return Err(evidence(refused()));
        }
        self.original.authenticate_implementation(implementation)?;
        self.read_current().map_err(evidence)
    }

    fn authenticate_authority(
        &self,
        binding: &crucible_node_contract::NodeBinding,
    ) -> Result<(), EvidenceError> {
        if binding != &self.source.installation().binding {
            return Err(evidence(refused()));
        }
        self.original.authenticate_authority(binding)?;
        self.read_current().map_err(evidence)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        if !self.schemas.contains(schema) {
            return Err(evidence(refused()));
        }
        self.original.authenticate_schema(schema)?;
        self.read_current().map_err(evidence)
    }

    fn qualify_capability(
        &self,
        world: &WorldBinding,
        binding: &crucible_node_contract::NodeBinding,
        requirement: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        if world != &self.world
            || binding != &self.source.installation().binding
            || !self
                .capabilities
                .iter()
                .map(capability_hash)
                .collect::<Result<Vec<_>, _>>()
                .map_err(evidence)?
                .contains(&capability_hash(requirement).map_err(evidence)?)
        {
            return Err(evidence(refused()));
        }
        self.original
            .qualify_capability(world, binding, requirement)?;
        self.read_current().map_err(evidence)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        let mut matched = false;
        for predicate in &self.predicates {
            matched |= predicate.matches(&claim, &self.world, &self.requirements, &self.source)?;
        }
        if !matched {
            return Err(evidence(refused()));
        }
        self.original.qualify(claim)?;
        self.read_current().map_err(evidence)
    }
}

impl PacketGraphPredicate {
    fn claim<'a>(
        &'a self,
        world: &'a WorldBinding,
        requirements: &'a HashRef,
        binding_hash: &'a HashRef,
        source: &'a PacketSemanticSource,
    ) -> Result<QualificationClaim<'a>, QualificationError> {
        let selected = source.installation();
        Ok(match self {
            Self::Scenario { scenario } if scenario == &world.scenario_ref => {
                QualificationClaim::Scenario {
                    world_binding_hash: &selected.world_binding_hash,
                    scenario_ref: scenario,
                    requirements_hash: requirements,
                }
            }
            Self::Port { port, policy }
                if selected
                    .descriptor
                    .ports
                    .iter()
                    .any(|selected| &selected.id == port) =>
            {
                QualificationClaim::Port {
                    node_id: &selected.descriptor.id,
                    binding_hash,
                    port_id: port,
                    policy_ref: policy,
                }
            }
            Self::Inventory { ownership, proof } => QualificationClaim::CompleteInventory {
                world_binding_hash: &selected.world_binding_hash,
                ownership_ref: ownership,
                proof_ref: proof,
            },
            Self::NoPreservation { owner, limitation }
                if owner == &selected.owner.owner.id
                    && selected.guarantees.capture_scope
                        == crucible_node_contract::CaptureScope::None
                    && selected.guarantees.continuation
                        == crucible_node_contract::Continuation::Unsupported
                    && !selected.guarantees.durable_restart
                    && !selected.guarantees.isolated_fork
                    && !selected.guarantees.conditional_replay =>
            {
                QualificationClaim::Capture {
                    world_binding_hash: &selected.world_binding_hash,
                    capture_owner_id: owner,
                    procedure_ref: limitation,
                }
            }
            Self::Coordinator { policy } => QualificationClaim::Coordinator {
                world_binding_hash: &selected.world_binding_hash,
                policy_ref: policy,
            },
            _ => return Err(refused()),
        })
    }

    pub(super) fn matches(
        &self,
        claim: &QualificationClaim<'_>,
        world: &WorldBinding,
        requirements: &HashRef,
        source: &PacketSemanticSource,
    ) -> Result<bool, EvidenceError> {
        let selected = source.installation();
        let matching = match (self, claim) {
            (
                Self::Scenario { scenario },
                QualificationClaim::Scenario {
                    world_binding_hash,
                    scenario_ref,
                    requirements_hash,
                },
            ) => {
                **world_binding_hash == selected.world_binding_hash
                    && *scenario_ref == scenario
                    && *requirements_hash == requirements
                    && scenario == &world.scenario_ref
            }
            (
                Self::Port { port, policy },
                QualificationClaim::Port {
                    node_id,
                    binding_hash,
                    port_id,
                    policy_ref,
                },
            ) => {
                *node_id == &selected.descriptor.id
                    && **binding_hash
                        == selected
                            .binding
                            .compatibility
                            .identity()
                            .map_err(|error| evidence(error.into()))?
                    && *port_id == port
                    && *policy_ref == policy
            }
            (
                Self::Inventory { ownership, proof },
                QualificationClaim::CompleteInventory {
                    world_binding_hash,
                    ownership_ref,
                    proof_ref,
                },
            ) => {
                **world_binding_hash == selected.world_binding_hash
                    && *ownership_ref == ownership
                    && *proof_ref == proof
            }
            (
                Self::NoPreservation { owner, limitation },
                QualificationClaim::Capture {
                    world_binding_hash,
                    capture_owner_id,
                    procedure_ref,
                },
            ) => {
                **world_binding_hash == selected.world_binding_hash
                    && *capture_owner_id == owner
                    && *procedure_ref == limitation
                    && owner == &selected.owner.owner.id
                    && selected.guarantees.capture_scope
                        == crucible_node_contract::CaptureScope::None
                    && selected.guarantees.continuation
                        == crucible_node_contract::Continuation::Unsupported
                    && !selected.guarantees.durable_restart
                    && !selected.guarantees.isolated_fork
                    && !selected.guarantees.conditional_replay
            }
            (
                Self::Coordinator { policy },
                QualificationClaim::Coordinator {
                    world_binding_hash,
                    policy_ref,
                },
            ) => **world_binding_hash == selected.world_binding_hash && *policy_ref == policy,
            _ => false,
        };
        Ok(matching)
    }
}

fn requirements_hash(requirements: &ScenarioRequirements) -> Result<HashRef, QualificationError> {
    Ok(crucible_node_contract::canonical::json_hash(
        "cnp.admission-requirements.v1",
        requirements,
    )?)
}

fn capability_hash(requirement: &NodeCapabilityRequirement) -> Result<HashRef, QualificationError> {
    scope::encoded_size(requirement, 1024 * 1024)?;
    Ok(crucible_node_contract::canonical::json_hash(
        "cnp.packet-graph-capability.v1",
        requirement,
    )?)
}

fn refused() -> QualificationError {
    QualificationError::Refused("original installed packet graph policy unavailable")
}

fn external(error: EvidenceError) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}

fn evidence(error: QualificationError) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}

// Borrow complete body associations as a sequence, not JSON object keys.
struct GraphBodies<'a>(&'a BTreeMap<ContentRef, Vec<u8>>);

impl Serialize for GraphBodies<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for association in self.0 {
            sequence.serialize_element(&association)?;
        }
        sequence.end()
    }
}

// All arbitrary evidence callbacks finish before the same policy's direct read.
fn read_after_callbacks(
    queries: impl FnOnce() -> Result<(), QualificationError>,
    current: impl FnOnce() -> Result<(), QualificationError>,
) -> Result<(), QualificationError> {
    queries()?;
    current()
}
