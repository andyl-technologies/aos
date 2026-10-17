//! Requires independently installed owning policy before typed source preparation.
//!
//! This catalog prepares immutable metadata and a source-policy instance. It does
//! not reserve a world, launch a child or install a node. Those effectful stages
//! must consume their own original custody reservation and authenticated graph.

use std::{path::PathBuf, rc::Rc};

use crucible::node_adapters::cnp::LineageReferenceQualification;
use crucible::node_admission::{
    AdmittedGraph, InstalledExtensionPeerPolicy, InstalledExtensionRegistry,
};
use crucible_node_contract::{ContentRef, Id, U64, Validate};
use crucible_node_provider::reference_service::ReferenceProfile;

use super::super::{NodeObservedError, refused};
use super::InstalledTypedReaderPackage;

/// Supplies independently installed owning qualification for this exact source.
///
/// This interface belongs to host configuration. Package descriptors, namespace
/// labels, parsed class claims and successful peer negotiation cannot install it.
/// An implementation authenticates the measured package and regenerated profile
/// against its own behavioral premises before reserving its finite policy state.
/// It can retain the same immutable package with an allocation-free `Rc` clone.
pub trait InstalledTypedReaderCatalogPolicy {
    /// Checks complete prelaunch premises and reserves one original source policy.
    ///
    /// The returned policy remains responsible for actual process enrollment,
    /// realization, graph-selected extensions and every original input window.
    /// This callback cannot issue common readiness or an operation grant.
    ///
    /// # Errors
    /// Refuses by default. Installed implementations refuse changed package,
    /// unsupported profile/interpretation, incomplete behavioral applicability
    /// or unavailable finite policy custody. A refusal supplies no native work.
    fn prepare_original_policy(
        &self,
        _package: &Rc<InstalledTypedReaderPackage>,
        _profile: &ReferenceProfile,
        _peer: &InstalledExtensionPeerPolicy,
        _admitted: Option<(&AdmittedGraph, &Id)>,
        _maximum_operations: usize,
    ) -> Result<Box<dyn LineageReferenceQualification>, NodeObservedError> {
        Err(refused("installed typed reader owning policy unavailable"))
    }
}

/// Binds one finite source-owned metadata preparation request.
///
/// This in-memory request is not a portable selector or an execution grant.
pub struct InstalledTypedReaderConfiguration {
    /// Names the independently admitted logical node.
    pub node: Id,
    /// Names its independently admitted logical owner.
    pub owner: Id,
    /// Selects the positive fixed source window in picoseconds.
    pub quantum_ps: U64,
    /// Selects the finite physical source budget in nanoseconds.
    pub host_budget_ns: U64,
    /// Selects the source-owned ingress convention.
    pub closed_ingress: bool,
    /// Bounds retained original operations; this catalog supports at most 64.
    pub maximum_operations: usize,
}

/// Retains explicit host installation while leaving missing policy unsupported.
///
/// This separate catalog has no ordinary node selector. Its prepared metadata
/// does not carry a class certificate or reserve outer world capacity.
pub struct InstalledTypedReaderCatalog {
    descriptor: PathBuf,
    original: ContentRef,
    registry: Rc<InstalledExtensionRegistry>,
    policy: Option<Rc<dyn InstalledTypedReaderCatalogPolicy>>,
}

impl InstalledTypedReaderCatalog {
    /// Records independent host configuration without opening files or children.
    ///
    /// A missing policy is retained as an explicit unsupported installation.
    /// Preparation refuses it before package measurement or source callbacks.
    ///
    /// # Errors
    /// Refuses a relative descriptor path or malformed original identity.
    pub fn new(
        descriptor: PathBuf,
        original: ContentRef,
        registry: Rc<InstalledExtensionRegistry>,
        policy: Option<Rc<dyn InstalledTypedReaderCatalogPolicy>>,
    ) -> Result<Self, NodeObservedError> {
        original.validate()?;
        if !descriptor.is_absolute() {
            return Err(refused("typed reader descriptor path is relative"));
        }
        Ok(Self {
            descriptor,
            original,
            registry,
            policy,
        })
    }

    /// Remeasures the complete source before invoking installed owning policy.
    ///
    /// Peer projection requires the exact independently installed declaration,
    /// handler and all eight semantic contracts. Native preparation must later
    /// reserve its original whole runtime capsule before either process exists.
    ///
    /// # Errors
    /// Refuses absent policy, an unsupported finite operation count, changed
    /// package/profile/registry, exhausted metadata credit or callback refusal
    /// or unwind. No child, runtime or graph admission is created here.
    pub fn prepare(
        &self,
        configuration: InstalledTypedReaderConfiguration,
    ) -> Result<InstalledTypedReaderPreparation, NodeObservedError> {
        self.prepare_checked(configuration, None)
    }

    /// Rechecks measured metadata against an actually admitted original graph.
    ///
    /// The installed policy additionally authenticates complete selected node
    /// and application scope. Matching metadata cannot issue native permission.
    ///
    /// # Errors
    /// Refuses the same unsupported installation and credits as [`Self::prepare`],
    /// a changed admitted descriptor or absent exact extension, or installed
    /// policy refusal of the actual graph and original node.
    pub fn prepare_admitted(
        &self,
        configuration: InstalledTypedReaderConfiguration,
        graph: &AdmittedGraph,
    ) -> Result<InstalledTypedReaderPreparation, NodeObservedError> {
        self.prepare_checked(configuration, Some(graph))
    }

    fn prepare_checked(
        &self,
        configuration: InstalledTypedReaderConfiguration,
        graph: Option<&AdmittedGraph>,
    ) -> Result<InstalledTypedReaderPreparation, NodeObservedError> {
        let policy = self
            .policy
            .as_ref()
            .ok_or_else(|| refused("installed typed reader owning policy unavailable"))?;
        let maximum_operations = configuration.maximum_operations;
        if !(1..=64).contains(&maximum_operations) {
            return Err(refused("typed reader finite operation credit unsupported"));
        }

        let package = InstalledTypedReaderPackage::load(&self.descriptor, &self.original)?;
        let profile = package.profile(
            configuration.node,
            configuration.owner,
            configuration.quantum_ps,
            configuration.host_budget_ns,
            configuration.closed_ingress,
        )?;
        let peer = package.peer_policy(Rc::clone(&self.registry))?;
        if let Some(graph) = graph {
            let (_, handler, semantics) = peer
                .contract(package.definition().selection())
                .map_err(|error| NodeObservedError::Native(error.to_string()))?;
            let selected = graph
                .selected_extensions()
                .definitions()
                .find(|definition| definition.selection() == package.definition().selection());
            if graph.descriptor(&profile.descriptor.id) != Some(&profile.descriptor)
                || selected.is_none_or(|definition| {
                    definition.handler_identity() != handler
                        || definition.semantic_contract() != semantics
                })
            {
                return Err(refused(
                    "admitted typed reader descriptor or interpretation differs",
                ));
            }
        }
        let qualification = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            policy.prepare_original_policy(
                &package,
                &profile,
                &peer,
                graph.map(|graph| (graph, &profile.descriptor.id)),
                maximum_operations,
            )
        }))
        .map_err(|_| refused("installed typed reader prelaunch policy unwound"))??;

        Ok(InstalledTypedReaderPreparation {
            parts: InstalledTypedReaderPreparedParts {
                package,
                profile,
                peer,
                qualification,
                maximum_operations,
            },
        })
    }
}

#[cfg(test)]
// Inert prelaunch controls construct no original runtime or native issuer.
mod catalog_tests;

/// Owns measured metadata and the independently reserved original policy.
///
/// This object carries no runtime activation. A later owning adapter must check
/// the surviving registrar and actual original realization through this policy.
pub struct InstalledTypedReaderPreparation {
    parts: InstalledTypedReaderPreparedParts,
}

/// Transfers the same prelaunch metadata and independently reserved source policy.
///
/// No member supplies a runtime custody slot, activation or native grant.
pub struct InstalledTypedReaderPreparedParts {
    /// Retains the original measured package and source-role bodies.
    pub package: Rc<InstalledTypedReaderPackage>,
    /// Retains the exact regenerated source profile.
    pub profile: ReferenceProfile,
    /// Retains the exact independently installed peer interpretation.
    pub peer: InstalledExtensionPeerPolicy,
    /// Owns the policy instance for later actual registrar/realization/input checks.
    pub qualification: Box<dyn LineageReferenceQualification>,
    /// Retains the original finite operation credit.
    pub maximum_operations: usize,
}

impl InstalledTypedReaderPreparation {
    /// Borrows the complete source-regenerated profile without issuing admission.
    pub fn profile(&self) -> &ReferenceProfile {
        &self.parts.profile
    }

    /// Borrows the exact original measured package and source interpretation.
    pub fn package(&self) -> &InstalledTypedReaderPackage {
        &self.parts.package
    }

    /// Transfers the same metadata and policy into later reserved owning preparation.
    ///
    /// Consuming this data object cannot supply a runtime slot or bypass actual
    /// registrar, realization, graph, input and owner-readiness checks.
    pub fn into_parts(self) -> InstalledTypedReaderPreparedParts {
        self.parts
    }
}
