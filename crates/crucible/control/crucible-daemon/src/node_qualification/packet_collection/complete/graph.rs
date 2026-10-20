//! Owns immutable compiled graph interpretations for one native-three/host-one packet world.
//!
//! This installer interprets original source, schema, program and inventory
//! objects itself. It accepts no arbitrary evidence callback and copies no
//! successful answers into permission. Its non-clone original owner controls
//! the same revision retained by every graph-policy view. Native owners and
//! Refused behavioral collection remain separate mandatory conjunctions.

mod host_setup17;
mod retained;

use std::{cell::Cell, collections::BTreeMap, rc::Rc};

use crucible_engine::node_admission::{
    AdmissionEvidence, EvidenceError, NodeCapabilityRequirement, QualificationClaim,
    ScenarioRequirements,
};
use crucible_node_format::{
    ContentRef, HashRef, Id, ImplementationIdentity, NodeBinding, SchemaRef, WorldBinding,
};
use crucible_node_transport::reference_packet::coordinator::PacketNative5CoordinatorInstallation;

use super::super::{PacketFixtureMeasurements, fixture::current_files::CurrentFiles};
use super::{PacketCompleteRoster, QualificationError, refused};
use crucible_engine::node_adapters::cnp::CnpSemanticSource;
use crucible_engine::node_contract::HostSchedulingSource;

use super::records;

/// Borrows the complete original native and host policy before file or native effects.
pub struct PacketCompleteGraphRequest<'a> {
    /// Retains three exact world-scoped semantic sources in coordinator order.
    pub roster: PacketCompleteRoster,
    /// Retains the same original host scheduling factory source.
    pub host: Rc<HostSchedulingSource>,
    /// Pins the actual host and independently selected peer/source roles per owner.
    pub measurements: [&'a PacketFixtureMeasurements; 3],
    /// Borrows one complete world, never three independent singleton worlds.
    pub world: &'a WorldBinding,
    /// Borrows the same complete source-authored scenario requirements.
    pub requirements: &'a ScenarioRequirements,
    /// Borrows every original program, policy and schema body used by the issuer.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
    /// Borrows the full static installation, with no predicted Ready rows.
    pub coordinator: &'a PacketNative5CoordinatorInstallation,
}

/// Owns the live original revision of the installed four-owner structural policy.
///
/// Drop revokes retained policy views. It neither drops native custody nor issues
/// Node qualification; callers retain it alongside the complete collecting actor.
#[must_use = "retain the original world issuer until all collecting work is contained"]
pub struct PacketCompleteGraphOwner {
    policy: Rc<InstalledPacketCompleteGraphPolicy>,
}

impl PacketCompleteGraphOwner {
    /// Interprets and measures the complete four-owner scope before native launch.
    ///
    /// # Errors
    /// Refuses foreign or incomplete rosters, changed measurements, unsupported
    /// policy/schema/program semantics, preservation demands or finite ceilings.
    pub fn install(request: PacketCompleteGraphRequest<'_>) -> Result<Self, QualificationError> {
        let validated = records::validate(&request)?;
        // Share only the complete equal role/path/pin tuple. Distinct path
        // selection or future measurement fields remain separate originals.
        let first = Rc::new(CurrentFiles::install_complete_bytes(
            request.measurements[0],
        )?);
        let second = if request.measurements[1] == request.measurements[0] {
            Rc::clone(&first)
        } else {
            Rc::new(CurrentFiles::install_complete_bytes(
                request.measurements[1],
            )?)
        };
        let third = if request.measurements[2] == request.measurements[0] {
            Rc::clone(&first)
        } else if request.measurements[2] == request.measurements[1] {
            Rc::clone(&second)
        } else {
            Rc::new(CurrentFiles::install_complete_bytes(
                request.measurements[2],
            )?)
        };
        let files = [first, second, third];
        let policy = Rc::new(InstalledPacketCompleteGraphPolicy {
            roster: request.roster,
            host: request.host,
            process: std::process::id(),
            thread: std::thread::current().id(),
            world: request.world.clone(),
            requirements: validated.requirements,
            content: request.content.clone(),
            schemas: validated.schemas,
            proof: validated.proof,
            interpretation: validated.interpretation,
            connections: validated.connections,
            closures: validated.closures,
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
    pub fn graph_policy(
        &self,
    ) -> Result<Rc<InstalledPacketCompleteGraphPolicy>, QualificationError> {
        self.policy.read_current()?;
        Ok(Rc::clone(&self.policy))
    }

    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_original_report_policy_data(
        &self,
        policy: &Rc<InstalledPacketCompleteGraphPolicy>,
    ) -> Result<(), QualificationError> {
        self.policy.authenticate_retained_origin_data()?;
        if !self.policy.revision.get() || !Rc::ptr_eq(&self.policy, policy) {
            return Err(refused());
        }
        Ok(())
    }

    /// Revokes every retained view of this same original full-world policy.
    pub fn revoke(&mut self) {
        self.policy.revision.set(false);
    }
}

impl Drop for PacketCompleteGraphOwner {
    fn drop(&mut self) {
        self.policy.revision.set(false);
    }
}

/// Retains source-owned graph predicates for the exact full four-owner world.
///
/// Only the compiled issuer constructs this policy. It has no deserializer or
/// public permission constructor. Every query and terminal read checks the same
/// original revision and measured file descriptors. Ordinary Node, extension,
/// and capture qualification remain refused. Declared direct connections and
/// finite same-time closure are interpreted only for this collecting scene.
pub struct InstalledPacketCompleteGraphPolicy {
    roster: PacketCompleteRoster,
    host: Rc<HostSchedulingSource>,
    process: u32,
    thread: std::thread::ThreadId,
    world: WorldBinding,
    requirements: HashRef,
    content: BTreeMap<ContentRef, Vec<u8>>,
    schemas: Vec<SchemaRef>,
    proof: ContentRef,
    interpretation: ContentRef,
    connections: Vec<(Id, ContentRef)>,
    closures: Vec<Id>,
    files: [Rc<CurrentFiles>; 3],
    measurements: [PacketFixtureMeasurements; 3],
    revision: Cell<bool>,
}

impl InstalledPacketCompleteGraphPolicy {
    pub(super) fn authenticate_scope(
        &self,
        roster: &PacketCompleteRoster,
        host: &Rc<HostSchedulingSource>,
        world: &WorldBinding,
        requirements: &HashRef,
    ) -> Result<(), QualificationError> {
        self.read_current()?;
        self.authenticate_scope_roster_data(roster, host, world, requirements)?;
        self.read_current()
    }

    pub(super) fn authenticate_content(
        &self,
        content: &BTreeMap<ContentRef, Vec<u8>>,
    ) -> Result<(), QualificationError> {
        self.read_current()?;
        if content != &self.content {
            return Err(refused());
        }
        self.read_current()
    }

    pub(super) fn capture_static_references(&self) -> (&ContentRef, &ContentRef) {
        (&self.proof, &self.interpretation)
    }

    pub(super) fn measurements(&self) -> &[PacketFixtureMeasurements; 3] {
        &self.measurements
    }

    /// Quotes the same member's complete retained-file validation phase.
    ///
    /// # Errors
    /// Refuses foreign/revoked policy, another member or unresolved file backing.
    pub(in crate::node_qualification::packet_collection::complete) fn original_native_launch_currentness_storage_data(
        &self,
        member: usize,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        self.authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !self.revision.get() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.files
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?
            .original_native_startup_currentness_storage_data()
    }

    /// Checks every original member file before the selected Child effect.
    ///
    /// # Errors
    /// Refuses inadequate credit, changed complete bytes, namespace or revision.
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_original_native_launch_currentness(
        &self,
        member: usize,
        maximum: usize,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        self.original_native_launch_currentness_storage_data(member)?;
        self.files
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?
            .authenticate_original_native_startup_currentness(maximum)?;
        if !self.revision.get() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn read_current(&self) -> Result<(), QualificationError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !self.revision.get()
        {
            return Err(refused());
        }
        self.roster.current_scope()?;
        self.host
            .authenticate_dispatch_source()
            .map_err(|error| QualificationError::Evidence(error.reason))?;
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

    /// Authenticates all original native participants and the attached Host2 source.
    ///
    /// # Errors
    /// Refuses unavailable or foreign native custody, stale files or host attachment.
    pub fn authenticate_original_participants(&self) -> Result<(), QualificationError> {
        self.read_current()?;
        self.roster
            .current_native()
            .map_err(|error| QualificationError::Evidence(error.reason))?;
        self.host
            .authenticate_current()
            .map_err(|error| QualificationError::Evidence(error.reason))?;
        self.read_current()?;
        self.roster
            .current_native()
            .map_err(|error| QualificationError::Evidence(error.reason))?;
        self.host
            .authenticate_current()
            .map_err(|error| QualificationError::Evidence(error.reason))
    }

    // The caller brackets this closed, allocation-free membership pass with
    // full actual-plan currency checks. No file result or active token is kept.
    pub(super) fn authenticate_schema_roster_data(
        &self,
        binding: &NodeBinding,
        schemas: &[SchemaRef],
    ) -> Result<(), EvidenceError> {
        self.authenticate_retained_origin_data().map_err(external)?;
        if !self.revision.get()
            || schemas != binding.compatibility.implementation.formats.as_slice()
            || (!self
                .roster
                .sources
                .iter()
                .any(|source| &source.installation().binding == binding)
                && &self.host.selection().binding != binding)
            || schemas.iter().any(|schema| !self.schemas.contains(schema))
        {
            return Err(denied());
        }
        Ok(())
    }

    fn evidence_current(&self) -> Result<(), EvidenceError> {
        self.read_current().map_err(external)
    }
}

impl AdmissionEvidence for InstalledPacketCompleteGraphPolicy {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.evidence_current()?;
        if let Some(original) = self.content.get(reference) {
            if original.len() > maximum {
                return Err(denied());
            }
            reference.verify(original).map_err(|error| EvidenceError {
                message: error.to_string(),
            })?;
            return super::super::fixture::current_files::current_answer(original.clone(), || {
                self.evidence_current()
            });
        }
        let original = if reference == &self.measurements[0].host {
            self.files[0].host_content(reference, maximum)
        } else if let Some(member) = self.measurements.iter().position(|measurement| {
            measurement
                .sources
                .iter()
                .any(|source| &source.content == reference)
        }) {
            self.files[member].source_content(reference, maximum)
        } else {
            let member = self
                .measurements
                .iter()
                .position(|measurement| &measurement.peer.content == reference)
                .ok_or_else(denied)?;
            self.files[member].peer_content(reference, maximum)
        };
        let bytes = original.map_err(|error| EvidenceError {
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
            .roster
            .sources
            .iter()
            .any(|source| &source.installation().provider.implementation == implementation)
            && &self.host.selection().binding.compatibility.implementation != implementation
        {
            return Err(denied());
        }
        self.evidence_current()
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.evidence_current()?;
        if !self
            .roster
            .sources
            .iter()
            .any(|source| &source.installation().binding == binding)
            && &self.host.selection().binding != binding
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
        let matching =
            match claim {
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
                } => self.roster.sources.iter().any(|source| {
                    let selected = source.installation();
                    node_id == &selected.descriptor.id
                        && selected
                            .binding
                            .compatibility
                            .identity()
                            .as_ref()
                            .is_ok_and(|hash| hash == binding_hash)
                        && selected.descriptor.ports.iter().any(|port| {
                            port_id == &port.id && policy_ref == &port.configuration_ref
                        })
                }),
                QualificationClaim::Connection {
                    world_binding_hash,
                    connection_id,
                    proof_ref,
                } => {
                    world_binding_hash == &world_hash
                        && self
                            .connections
                            .iter()
                            .any(|(id, proof)| connection_id == id && proof_ref == proof)
                }
                QualificationClaim::SameTimeClosure {
                    world_binding_hash,
                    execution_owner_id,
                    proof_ref,
                } => {
                    world_binding_hash == &world_hash
                        && proof_ref == &self.proof
                        && self.closures.contains(execution_owner_id)
                }
                // Bootstrap declarations do not qualify capture. A later
                // source-owned installed factory must authenticate the live
                // native/host allocation and complete selected geometry.
                QualificationClaim::Capture { .. } => false,
                _ => false,
            };
        if !matching {
            return Err(denied());
        }
        // Bootstrap never supplies a Capture qualification.
        // No arbitrary callback follows this direct source-owned revision read.
        self.evidence_current()
    }
}

fn external(error: QualificationError) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}

fn denied() -> EvidenceError {
    external(refused())
}

impl InstalledPacketCompleteGraphPolicy {
    // Both callback representations retain the same complete original scope.
    fn authenticate_scope_roster_data(
        &self,
        roster: &PacketCompleteRoster,
        host: &Rc<HostSchedulingSource>,
        world: &WorldBinding,
        requirements: &HashRef,
    ) -> Result<(), QualificationError> {
        if world != &self.world
            || requirements != &self.requirements
            || !self.roster.same_original(roster)
            || !Rc::ptr_eq(&self.host, host)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Quotes the largest actual sequential complete-file currentness phase.
    ///
    /// # Errors
    /// Refuses foreign or revoked origin, unsupported file ownership or count overflow.
    pub(in crate::node_qualification::packet_collection::complete) fn original_initial_callback_currentness_storage_data(
        &self,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        self.authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !self.revision.get() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.files.iter().try_fold(0usize, |maximum, files| {
            Ok(maximum.max(files.original_native_startup_currentness_storage_data()?))
        })
    }

    /// Checks the same original scope without reading its measured files.
    ///
    /// This is an identity comparison only. The closed Authority currentness
    /// interval separately retains its complete entry and exit file reads.
    ///
    /// # Errors
    /// Refuses another original roster, Host, world or requirements identity.
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_original_initial_callback_scope_roster_data(
        &self,
        roster: &PacketCompleteRoster,
        host: &Rc<HostSchedulingSource>,
        world: &WorldBinding,
        requirements: &HashRef,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.authenticate_scope_roster_data(roster, host, world, requirements)
            .map_err(|_| crucible_engine::node_contract::RuntimeError::ForeignAuthority)
    }

    /// Checks the original Source and Host guards without measuring files.
    ///
    /// This does not establish file currency or authorize an effect. It keeps
    /// the interior guards of the closed Authority interval in their original
    /// order between the two complete file measurements.
    ///
    /// # Errors
    /// Refuses foreign origin, revoked graph, changed Source scope or Host custody.
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_original_initial_callback_parents_data(
        &self,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        self.authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !self.revision.get() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.roster
            .current_scope()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.host
            .authenticate_dispatch_source()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    /// Reads complete original file currency after the concrete parent guards.
    ///
    /// # Errors
    /// Refuses foreign or revoked parents, changed file bytes or path identity.
    pub(in crate::node_qualification::packet_collection::complete) fn read_original_initial_callback_data(
        &self,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.authenticate_original_initial_callback_parents_data()?;
        for (index, files) in self.files.iter().enumerate() {
            if !self.files[..index]
                .iter()
                .any(|earlier| Rc::ptr_eq(earlier, files))
            {
                let row = files.original_native_startup_currentness_storage_data()?;
                files.authenticate_original_native_startup_currentness(row)?;
            }
        }
        Ok(())
    }
}

impl InstalledPacketCompleteGraphPolicy {
    /// Counts retained file descriptor views without liveness callbacks or I/O.
    ///
    /// Shared CurrentFiles views are conservatively repeated; no matching path,
    /// inode or content hash discounts a physical descriptor owner.
    ///
    /// # Errors
    /// Refuses foreign origin, unsupported file owners or arithmetic overflow.
    pub(in crate::node_qualification::packet_collection::complete) fn original_initial_retained_descriptors_data(
        &self,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        self.authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.files.iter().try_fold(0usize, |total, files| {
            total
                .checked_add(files.retained_descriptor_count_data()?)
                .ok_or(RuntimeError::ResourceLimit)
        })
    }
}

impl InstalledPacketCompleteGraphPolicy {
    pub(in crate::node_qualification::packet_collection::complete) fn original_runtime_content_data(
        &self,
    ) -> &std::collections::BTreeMap<ContentRef, Vec<u8>> {
        &self.content
    }
}
