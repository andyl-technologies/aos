//! Retains independently issued private source authority for one finite collection.
//!
//! These originals are configured by the host before Child, never reconstructed
//! from common completion reports. Namespace/handler installation and collecting
//! graph authority remain independent conjunctions. No Accepted class is issued.

use std::{cell::RefCell, rc::Rc};

use super::{InstalledTypedReaderPackage, TypedReaderProgramme, kernel};
use crate::node_qualification::{QualificationError, QualificationUnit, WitnessPlan};
use crucible_node_contract::{
    BindingCompatibility, ContentRef, HashRef, Id, ResourceLimits, Validate,
};
use crucible_node_provider::{
    ProviderError,
    reference_service::{ReferenceNegotiatedLineageReaderLaunchBootstrap, ReferenceProfile},
};

#[path = "source_fixture/collection.rs"]
mod collection;
#[path = "source_fixture/current_native.rs"]
mod current_native;
#[path = "source_fixture/handshake.rs"]
mod handshake;
#[path = "source_fixture/launch.rs"]
pub(super) mod launch;
#[path = "source_fixture/limitations.rs"]
mod limitations;
#[path = "source_fixture/originals.rs"]
mod originals;
#[path = "source_fixture/staging.rs"]
mod staging;

pub use handshake::TypedReaderSourceHandshake;

pub(super) struct Source {
    pub(super) profile: ReferenceProfile,
    binding: BindingCompatibility,
    launch: ReferenceNegotiatedLineageReaderLaunchBootstrap,
    enrollment: RefCell<Option<(u32, u32, kernel::Enrollment)>>,
    pub(super) features: RefCell<Option<crucible_node_contract::IdSet>>,
    read_handle:
        RefCell<Option<crucible_node_provider::reference_lineage::LineageSourceReadHandle>>,
}

/// Retains one host-configured source installation without behavioral acceptance.
///
/// The constructor receives independently issued private launch originals and
/// an independently selected package identity. Loading package metadata cannot
/// construct this object. Private capabilities have no Debug/Serialize/export
/// API and never enter a public content hash. Three holders are reserved before
/// any native launch; actual process enrollment is required before windows.
pub struct InstalledTypedReaderSourceFixture {
    package: Rc<InstalledTypedReaderPackage>,
    programme: Rc<TypedReaderProgramme>,
    plan: WitnessPlan,
    reference: ContentRef,
    resources: ResourceLimits,
    world: HashRef,
    definition: super::TypedReaderCollectionWorld,
    sources: [Source; 3],
    staging: staging::StageOracles,
}

impl InstalledTypedReaderSourceFixture {
    /// Retains three original private launches after complete source preflight.
    ///
    /// Independent host configuration supplies the expected package, complete
    /// plan, world and private authority. The caller retains every launch on
    /// refusal because validation borrows them before bounded copies.
    ///
    /// # Errors
    /// Refuses changed package/source roles, world, profile, private launch scope,
    /// plan/whole source credit or current host environment/harness measurements.
    pub fn install(
        expected_package: &ContentRef,
        package: &Rc<InstalledTypedReaderPackage>,
        programme: &Rc<TypedReaderProgramme>,
        plan: &WitnessPlan,
        reference: &ContentRef,
        resources: ResourceLimits,
        launches: &[ReferenceNegotiatedLineageReaderLaunchBootstrap; 3],
    ) -> Result<Self, ProviderError> {
        expected_package.validate()?;
        resources.validate()?;
        if package.identity() != expected_package
            || programme.package() != expected_package
            || resources.processes.get() != 2
            || !(1..=64).contains(&resources.maximum_operations.get())
        {
            return Err(invalid());
        }
        super::programme::count(&(plan, reference), 1024 * 1024)?;
        let expected_plan = programme.witness_plan(plan.unit.clone(), plan.limitations.clone())?;
        if expected_plan != *plan {
            return Err(invalid());
        }
        let bytes = launch::encode(plan, 1024 * 1024)?;
        reference.verify(&bytes)?;
        if Self::qualification_unit(package, programme, &resources)? != plan.unit {
            return Err(invalid());
        }
        // All three configured originals must retain the exact public limitation
        // body before any launch/source clone. A reference alone is insufficient.
        limitations::originals(launches, &plan.limitations)?;
        let world = launches[0].bootstrap.world_binding_hash.clone();
        let mut sources = Vec::new();
        sources.try_reserve_exact(3).map_err(|_| invalid())?;
        for (index, original) in launches.iter().enumerate() {
            sources.push(launch::prepare(
                package, programme, reference, &resources, &world, index, original,
            )?);
        }
        if sources.iter().enumerate().any(|(index, source)| {
            sources[..index].iter().any(|prior| {
                prior.launch.bootstrap.admission_token == source.launch.bootstrap.admission_token
                    || prior.launch.bootstrap.authority.session_id
                        == source.launch.bootstrap.authority.session_id
                    || prior.launch.bootstrap.authority.realization_id
                        == source.launch.bootstrap.authority.realization_id
            })
        }) {
            return Err(invalid());
        }
        if launches
            .iter()
            .any(|launch| launch.qualification_refs != launches[0].qualification_refs)
        {
            return Err(invalid());
        }
        let definition = super::TypedReaderCollectionWorld::prepare(
            package,
            programme,
            &launches[0].qualification_refs,
        )?;
        if definition.world.identity()? != world {
            return Err(invalid());
        }
        let sources = sources.try_into().map_err(|_| invalid())?;
        Ok(Self {
            package: Rc::clone(package),
            programme: Rc::clone(programme),
            plan: plan.clone(),
            reference: reference.clone(),
            resources,
            world,
            definition,
            sources,
            staging: staging::StageOracles::new()?,
        })
    }

    /// Computes the complete three-source fixture unit from current host facts.
    ///
    /// This data projection measures the actual host executable and kernel and
    /// regenerates complete profiles. It does not install a class, namespace or
    /// launch authority; the configured host independently chooses this scope.
    ///
    /// # Errors
    /// Refuses inaccessible/changed measurements, unsupported source geometry or
    /// bounded projection failures before constructing the unit.
    pub fn qualification_unit(
        package: &InstalledTypedReaderPackage,
        programme: &TypedReaderProgramme,
        resources: &ResourceLimits,
    ) -> Result<QualificationUnit, ProviderError> {
        launch::unit(package, programme, resources)
    }

    /// Rechecks configured finite source scope before package reads or Child.
    ///
    /// # Errors
    /// Refuses substituted package/resources or changed complete current plan.
    pub fn authenticate_fixture_plan(
        &self,
        package: &ContentRef,
        resources: &ResourceLimits,
    ) -> Result<ContentRef, ProviderError> {
        if package != self.package.identity() || resources != &self.resources {
            return Err(invalid());
        }
        let bytes = launch::encode(&self.plan, 1024 * 1024)?;
        self.authenticate_plan(&self.reference, &bytes, &self.plan)
            .map_err(|_| invalid())?;
        Ok(self.reference.clone())
    }

    /// Authenticates unchanged complete plan bytes under original installation.
    ///
    /// # Errors
    /// Refuses changed applicability, source/host measurements or noncanonical
    /// bytes. The method cannot authenticate an accepted claim or report.
    pub fn authenticate_plan(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        reference.verify(bytes)?;
        if reference != &self.reference
            || plan != &self.plan
            || bytes != launch::encode(plan, 1024 * 1024).map_err(qualification)?
            || Self::qualification_unit(&self.package, &self.programme, &self.resources)
                .map_err(qualification)?
                != self.plan.unit
        {
            return Err(QualificationError::Refused(
                "typed installed source plan changed",
            ));
        }
        Ok(())
    }

    /// Borrows the exact binding regenerated from original private launch authority.
    ///
    /// # Errors
    /// Refuses unknown nodes or changed measured source configuration.
    pub fn binding(&self, node: &Id) -> Result<&BindingCompatibility, ProviderError> {
        let source = self.source(node)?;
        self.authenticate_source(
            &self.reference,
            &self.package,
            &source.profile,
            &self.resources,
        )?;
        Ok(&source.binding)
    }

    /// Reopens the complete actual host/source qualification unit for this node.
    ///
    /// # Errors
    /// Refuses an unknown node or changed whole source/environment measurements.
    pub fn current_unit(&self, node: &Id) -> Result<QualificationUnit, ProviderError> {
        self.binding(node)?;
        let unit = Self::qualification_unit(&self.package, &self.programme, &self.resources)?;
        if unit != self.plan.unit {
            return Err(invalid());
        }
        Ok(unit)
    }

    /// Returns a fresh verifier borrowing this installation's private authority.
    ///
    /// # Errors
    /// Refuses unknown nodes or changed source metadata before opening a socket.
    pub fn handshake(
        self: &Rc<Self>,
        node: &Id,
    ) -> Result<TypedReaderSourceHandshake, ProviderError> {
        self.binding(node)?;
        Ok(TypedReaderSourceHandshake {
            source: Rc::clone(self),
            node: node.clone(),
        })
    }

    /// Borrows fixed collection data without exposing an ordinary graph seal.
    pub fn collection_world(&self) -> &super::TypedReaderCollectionWorld {
        &self.definition
    }

    pub(super) fn package(&self) -> &InstalledTypedReaderPackage {
        &self.package
    }

    pub(super) fn source(&self, node: &Id) -> Result<&Source, ProviderError> {
        self.sources
            .iter()
            .find(|source| source.profile.descriptor.id == *node)
            .ok_or_else(invalid)
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("independently installed typed source scope differs")
}

fn qualification(error: ProviderError) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}

#[cfg(test)]
// Inert controls use typed errors and never launch native processes.
#[path = "source_fixture/tests.rs"]
mod tests;
