//! Owns immutable compiled graph interpretations for one three-owner packet world.
//!
//! This installer interprets original source, schema, program and inventory
//! objects itself. It accepts no arbitrary evidence callback and copies no
//! successful answers into permission. Its non-clone original owner controls
//! the same revision retained by every graph-policy view. Native owners and
//! Refused behavioral collection remain separate mandatory conjunctions.

use std::{cell::Cell, collections::BTreeMap, rc::Rc};

use crucible_engine::{
    node_adapters::cnp::{CnpSemanticSource, PacketSemanticSource},
    node_admission::{
        AdmissionEvidence, EvidenceError, NodeCapabilityRequirement, QualificationClaim,
        ScenarioRequirements,
    },
};
use crucible_node_format::{
    ContentRef, HashRef, ImplementationIdentity, NodeBinding, SchemaRef, WorldBinding,
};
use crucible_node_transport::reference_packet::coordinator::PacketWorldCoordinatorInstallation;

use super::{PacketFixtureMeasurements, QualificationError, current_files::CurrentFiles};

mod records;

pub use records::packet_world_independent_graph_contract;

/// Borrows the complete original three-source policy before file or native effects.
pub struct PacketWorldIndependentGraphRequest<'a> {
    /// Retains three exact world-scoped semantic sources in coordinator order.
    pub sources: [Rc<PacketSemanticSource>; 3],
    /// Pins the actual host and independently selected peer/source roles per owner.
    pub measurements: [&'a PacketFixtureMeasurements; 3],
    /// Borrows one complete world, never three independent singleton worlds.
    pub world: &'a WorldBinding,
    /// Borrows the same complete source-authored scenario requirements.
    pub requirements: &'a ScenarioRequirements,
    /// Borrows every original program, policy and schema body used by the issuer.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
    /// Borrows the full static installation, with no predicted Ready rows.
    pub coordinator: &'a PacketWorldCoordinatorInstallation,
}

/// Owns the live original revision of the installed three-owner structural policy.
///
/// Drop revokes retained policy views. It neither drops native custody nor issues
/// Node qualification; callers retain it alongside the complete collecting actor.
#[must_use = "retain the original world issuer until all collecting work is contained"]
pub struct PacketWorldIndependentGraphOwner {
    policy: Rc<InstalledPacketWorldGraphPolicy>,
}

impl PacketWorldIndependentGraphOwner {
    /// Interprets and measures the complete three-owner scope before native launch.
    ///
    /// # Errors
    /// Refuses foreign or incomplete rosters, changed measurements, unsupported
    /// policy/schema/program semantics, preservation demands or finite ceilings.
    pub fn install(
        request: PacketWorldIndependentGraphRequest<'_>,
    ) -> Result<Self, QualificationError> {
        let validated = records::validate(&request)?;
        // Share only the complete equal role/path/pin tuple. Distinct path
        // selection or future measurement fields remain separate originals.
        let first = Rc::new(CurrentFiles::install(request.measurements[0])?);
        let second = if request.measurements[1] == request.measurements[0] {
            Rc::clone(&first)
        } else {
            Rc::new(CurrentFiles::install(request.measurements[1])?)
        };
        let third = if request.measurements[2] == request.measurements[0] {
            Rc::clone(&first)
        } else if request.measurements[2] == request.measurements[1] {
            Rc::clone(&second)
        } else {
            Rc::new(CurrentFiles::install(request.measurements[2])?)
        };
        let files = [first, second, third];
        let policy = Rc::new(InstalledPacketWorldGraphPolicy {
            sources: request.sources,
            world: request.world.clone(),
            requirements: validated.requirements,
            content: request.content.clone(),
            schemas: validated.schemas,
            proof: validated.proof,
            files,
            measurements: [
                request.measurements[0].clone(),
                request.measurements[1].clone(),
                request.measurements[2].clone(),
            ],
            revision: Cell::new(true),
        });
        policy.read_current()?;
        Ok(Self { policy })
    }

    /// Borrows the same installed policy without extending its owner's revision.
    ///
    /// # Errors
    /// Refuses revoked original owner or changed actual measured files.
    pub fn graph_policy(&self) -> Result<Rc<InstalledPacketWorldGraphPolicy>, QualificationError> {
        self.policy.read_current()?;
        Ok(Rc::clone(&self.policy))
    }

    /// Revokes every retained view of this same original full-world policy.
    pub fn revoke(&mut self) {
        self.policy.revision.set(false);
    }
}

impl Drop for PacketWorldIndependentGraphOwner {
    fn drop(&mut self) {
        self.policy.revision.set(false);
    }
}

/// Retains source-owned graph predicates for the exact full three-owner world.
///
/// Only the compiled issuer constructs this policy. It has no deserializer or
/// public permission constructor. Every query and terminal read checks the same
/// original revision and measured file descriptors. Ordinary Node, extension,
/// connection, same-time closure and preservation qualification remain refused.
pub struct InstalledPacketWorldGraphPolicy {
    sources: [Rc<PacketSemanticSource>; 3],
    world: WorldBinding,
    requirements: HashRef,
    content: BTreeMap<ContentRef, Vec<u8>>,
    schemas: Vec<SchemaRef>,
    proof: ContentRef,
    files: [Rc<CurrentFiles>; 3],
    measurements: [PacketFixtureMeasurements; 3],
    revision: Cell<bool>,
}

impl InstalledPacketWorldGraphPolicy {
    pub(in super::super) fn current(
        &self,
        sources: &[Rc<PacketSemanticSource>; 3],
        world: &WorldBinding,
        requirements: &HashRef,
    ) -> Result<(), QualificationError> {
        if world != &self.world
            || requirements != &self.requirements
            || sources
                .iter()
                .zip(&self.sources)
                .any(|(a, b)| !Rc::ptr_eq(a, b))
        {
            return Err(refused());
        }
        self.read_current()
    }

    pub(in super::super) fn measurements(&self) -> &[PacketFixtureMeasurements; 3] {
        &self.measurements
    }

    fn read_current(&self) -> Result<(), QualificationError> {
        if !self.revision.get() {
            return Err(refused());
        }
        for (index, files) in self.files.iter().enumerate() {
            // Deduplication is local to this current read. No earlier read
            // supplies permission for later native dispatch or publication.
            if !self.files[..index]
                .iter()
                .any(|earlier| Rc::ptr_eq(earlier, files))
            {
                files.current()?;
            }
        }
        Ok(())
    }

    fn evidence_current(&self) -> Result<(), EvidenceError> {
        self.read_current().map_err(external)
    }
}

impl AdmissionEvidence for InstalledPacketWorldGraphPolicy {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.evidence_current()?;
        if let Some(original) = self.content.get(reference) {
            if original.len() > maximum {
                return Err(denied());
            }
            reference.verify(original).map_err(|error| EvidenceError {
                message: error.to_string(),
            })?;
            return super::current_files::current_answer(original.clone(), || {
                self.evidence_current()
            });
        }
        let member = self
            .measurements
            .iter()
            .position(|measurement| &measurement.peer.content == reference)
            .ok_or_else(denied)?;
        let bytes = self.files[member]
            .peer_content(reference, maximum)
            .map_err(|error| EvidenceError {
                message: error.to_string(),
            })?;
        self.evidence_current()?;
        Ok(bytes)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.evidence_current()?;
        if !self
            .sources
            .iter()
            .any(|source| &source.installation().provider.implementation == implementation)
        {
            return Err(denied());
        }
        self.evidence_current()
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.evidence_current()?;
        if !self
            .sources
            .iter()
            .any(|source| &source.installation().binding == binding)
        {
            return Err(denied());
        }
        self.evidence_current()
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.evidence_current()?;
        if !self.schemas.contains(schema) {
            return Err(denied());
        }
        self.evidence_current()
    }

    fn qualify_capability(
        &self,
        _: &WorldBinding,
        _: &NodeBinding,
        _: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        Err(denied())
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.evidence_current()?;
        let world_hash = self.world.identity().map_err(|error| EvidenceError {
            message: error.to_string(),
        })?;
        let matching = match claim {
            QualificationClaim::Scenario {
                world_binding_hash,
                scenario_ref,
                requirements_hash,
            } => {
                world_binding_hash == &world_hash
                    && scenario_ref == &self.world.scenario_ref
                    && requirements_hash == &self.requirements
            }
            QualificationClaim::CompleteInventory {
                world_binding_hash,
                ownership_ref,
                proof_ref,
            } => {
                world_binding_hash == &world_hash
                    && ownership_ref == &self.world.ownership_ref
                    && proof_ref == &self.proof
            }
            QualificationClaim::Coordinator {
                world_binding_hash,
                policy_ref,
            } => {
                // The claim names the complete installed policy. Its internal
                // proof fields were independently interpreted before Child.
                world_binding_hash == &world_hash
                    && policy_ref == &self.world.coordinator_contract_ref
            }
            QualificationClaim::Port {
                node_id,
                binding_hash,
                port_id,
                policy_ref,
            } => self.sources.iter().any(|source| {
                let selected = source.installation();
                node_id == &selected.descriptor.id
                    && selected
                        .binding
                        .compatibility
                        .identity()
                        .as_ref()
                        .is_ok_and(|hash| hash == binding_hash)
                    && port_id == &selected.descriptor.ports[0].id
                    && policy_ref == &selected.descriptor.ports[0].configuration_ref
            }),
            QualificationClaim::Capture {
                world_binding_hash,
                capture_owner_id,
                procedure_ref,
            } => {
                world_binding_hash == &world_hash
                    && procedure_ref == &self.proof
                    && self
                        .sources
                        .iter()
                        .any(|source| capture_owner_id == &source.installation().owner.owner.id)
            }
            _ => false,
        };
        if !matching {
            return Err(denied());
        }
        // Capture matches only each independently interpreted all-false limitation.
        // No arbitrary callback follows this direct source-owned revision read.
        self.evidence_current()
    }
}

fn refused() -> QualificationError {
    QualificationError::Refused("original three-owner packet graph policy unavailable")
}

fn external(error: QualificationError) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}

fn denied() -> EvidenceError {
    external(refused())
}
