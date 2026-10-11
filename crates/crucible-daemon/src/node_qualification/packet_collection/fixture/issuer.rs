//! Owns the independent installed predicates for one finite collecting source.
//!
//! The issuer verifies actual measured files and complete typed policy objects
//! itself. It accepts no arbitrary AdmissionEvidence and caches no successful
//! callback answer. Its original owner keeps the installed revision live; owner
//! revocation or Drop invalidates every previously issued wrapper. This supplies
//! structural collection policy only, never Node acceptance or native custody.

use std::{cell::Cell, collections::BTreeMap, rc::Rc};

use crucible::{
    node_adapters::cnp::{CnpSemanticSource, PacketSemanticSource},
    node_admission::{
        AdmissionEvidence, EvidenceError, NodeCapabilityRequirement, QualificationClaim,
        ScenarioRequirements,
    },
};
use crucible_node_contract::{
    ContentRef, HashRef, ImplementationIdentity, NodeBinding, SchemaRef, WorldBinding,
};

use super::{
    PacketFixtureMeasurements, QualificationError,
    current_files::CurrentFiles,
    graph_policy::{
        InstalledPacketGraphPolicy, PacketGraphCurrentScope, PacketGraphEvidence,
        PacketGraphPolicyTable, PacketGraphPredicate,
    },
};

#[path = "issuer/records.rs"]
mod records;

pub use records::packet_independent_graph_contract;

#[cfg(test)]
#[path = "issuer/tests.rs"]
mod tests;

/// Borrows independently selected original objects for the closed packet policy.
///
/// Complete bytes are interpreted by this issuer's actual compiled validators.
/// Neither a hash nor supplied data constitutes an independent qualification.
pub struct PacketIndependentGraphRequest<'a> {
    /// Retains the already selected finite output-only semantic implementation.
    pub source: Rc<PacketSemanticSource>,
    /// Pins the actual peer, current host ELF and complete source role roster.
    pub measurements: &'a PacketFixtureMeasurements,
    /// Borrows the complete singleton world selected before Child.
    pub world: &'a WorldBinding,
    /// Borrows explicit acceptance of this source's unsupported guarantees.
    pub requirements: &'a ScenarioRequirements,
    /// Borrows complete original public bodies used by the fixed policy.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
}

/// Owns the original installed graph revision independently of issued evidence.
///
/// Keeping an evidence Rc alive cannot extend this owner's authorization. Drop
/// revokes the original revision without releasing any native process custody.
/// This type cannot be cloned, decoded or reconstructed from an audit record.
#[must_use = "retain this original policy owner until collecting work is contained"]
pub struct PacketIndependentGraphOwner {
    evidence: Rc<OriginalGraphEvidence>,
}

impl PacketIndependentGraphOwner {
    /// Installs the compiled singleton interpretations after bounded measurement.
    ///
    /// No Child, transport, native callback, class certificate or execution
    /// occurs here. The exact source-owned validators interpret complete original
    /// program, schema, port, inventory and coordinator objects before issuance.
    ///
    /// # Errors
    /// Refuses changed file pins, foreign source/world, unsupported schemas or
    /// policy semantics, omitted bodies, widened guarantees and finite limits.
    pub fn install(request: PacketIndependentGraphRequest<'_>) -> Result<Self, QualificationError> {
        let installed = records::validate(&request)?;
        let files = CurrentFiles::install(request.measurements)?;
        let evidence = Rc::new(OriginalGraphEvidence {
            source: request.source,
            world: request.world.clone(),
            requirements: installed.requirements,
            content: request.content.clone(),
            schemas: installed.schemas,
            predicates: installed.predicates,
            files,
            revision: Cell::new(true),
        });
        evidence.current().map_err(external)?;
        Ok(Self { evidence })
    }

    /// Builds the default-refusing wrapper around this SAME original policy.
    ///
    /// The wrapper retains exact original evidence identity and complete query
    /// data; its final read returns to this owner's original installed revision.
    ///
    /// # Errors
    /// Refuses revoked policy or measured file drift and bounded wrapper failures.
    pub fn graph_policy(&self) -> Result<Rc<InstalledPacketGraphPolicy>, QualificationError> {
        self.evidence.current().map_err(external)?;
        InstalledPacketGraphPolicy::install(
            Rc::clone(&self.evidence.source),
            &self.evidence.world,
            &self.evidence.original_requirements()?,
            PacketGraphPolicyTable {
                content: &self.evidence.content,
                schemas: &self.evidence.schemas,
                capabilities: &[],
                predicates: &self.evidence.predicates,
            },
            self.evidence.clone(),
        )
    }

    /// Revokes the actual original policy without issuing replacement permission.
    ///
    /// Every previously issued policy immediately refuses its next direct read.
    pub fn revoke(&mut self) {
        self.evidence.revision.set(false);
    }
}

impl Drop for PacketIndependentGraphOwner {
    fn drop(&mut self) {
        self.evidence.revision.set(false);
    }
}

struct OriginalGraphEvidence {
    source: Rc<PacketSemanticSource>,
    world: WorldBinding,
    requirements: HashRef,
    content: BTreeMap<ContentRef, Vec<u8>>,
    schemas: Vec<SchemaRef>,
    predicates: Vec<PacketGraphPredicate>,
    files: CurrentFiles,
    revision: Cell<bool>,
}

impl OriginalGraphEvidence {
    fn current(&self) -> Result<(), EvidenceError> {
        // This is the actual owner's immutable installed objects/revision, not
        // another vendor callback or a gate over previously returned answers.
        if !self.revision.get() {
            return Err(refused());
        }
        self.files.current().map_err(|error| EvidenceError {
            message: error.to_string(),
        })
    }

    fn original_requirements(&self) -> Result<ScenarioRequirements, QualificationError> {
        records::decode(&self.content, &self.world.scenario_ref)
    }
}

impl AdmissionEvidence for OriginalGraphEvidence {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.current()?;
        let original = self.content.get(reference).ok_or_else(refused)?;
        if original.len() > maximum {
            return Err(refused());
        }
        reference.verify(original).map_err(|error| EvidenceError {
            message: error.to_string(),
        })?;
        Ok(original.clone())
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.current()?;
        if implementation != &self.source.installation().provider.implementation {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.current()?;
        if binding != &self.source.installation().binding {
            return Err(refused());
        }
        // This authenticates only the exact source-installed prelaunch binding.
        // Original native realization/registrar/kernel checks remain outside it.
        Ok(())
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.current()?;
        if !self.schemas.contains(schema) {
            return Err(refused());
        }
        Ok(())
    }

    fn qualify_capability(
        &self,
        _: &WorldBinding,
        _: &NodeBinding,
        _: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        Err(refused())
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.current()?;
        for predicate in &self.predicates {
            if predicate.matches(&claim, &self.world, &self.requirements, &self.source)? {
                return Ok(());
            }
        }
        // Node, Connection and SameTimeClosure claims remain refused. The exact
        // Capture claim here authenticates only the all-false preservation limitation.
        Err(refused())
    }
}

impl PacketGraphEvidence for OriginalGraphEvidence {
    fn authenticate_current_packet_graph_scope(
        &self,
        scope: PacketGraphCurrentScope<'_>,
    ) -> Result<(), EvidenceError> {
        if !std::ptr::eq(scope.selection, self.source.installation())
            || scope.world != &self.world
            || scope.requirements_hash != &self.requirements
            || scope.content != &self.content
            || scope.schemas != self.schemas.as_slice()
            || !scope.capabilities.is_empty()
            || scope.predicates != self.predicates.as_slice()
        {
            return Err(refused());
        }
        // No installed/vendor callback follows the actual original policy read.
        self.current()
    }
}

fn refused() -> EvidenceError {
    EvidenceError {
        message: "original finite packet graph policy is revoked or unsupported".into(),
    }
}

fn external(error: EvidenceError) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}
