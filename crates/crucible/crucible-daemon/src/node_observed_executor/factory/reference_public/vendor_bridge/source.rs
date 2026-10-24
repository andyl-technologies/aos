//! Binds reference registry planning to the same installed world and native peer.
//!
//! Independent complete-world inspection remains a required installed owner.
//! This concrete bridge adds the compiled package/profile, exact singleton plan
//! and actual native enrollment conjunction. It cannot turn a copied graph or
//! a checksum report into ordinary source or behavioral acceptance.

use std::{cell::RefCell, rc::Rc};

use crucible_engine::{
    node_admission::{
        AdmissionEvidence, AdmissionLimits, AdmissionRequest, AdmittedGraph, EvidenceError,
        QualificationClaim, admit_graph,
    },
    node_contract::{
        InstalledProviderSource, PreparedRealization, ProviderAuthorityKind,
        ProviderAuthorizationLease, ProviderAuthorizationScope, ProviderPlanningRequest,
        ProviderPreparationPlan,
    },
};
use crucible_node_format::{
    ContentRef, ImplementationIdentity, NodeBinding, ProviderManifest, SchemaRef,
};
use crucible_node_transport::reference_service::ReferenceProfile;

use super::super::{native::NativePublicEnrollment, package::InstalledPublicReferencePackage};

pub(super) struct ReferenceVendorSource {
    pub(super) package: Rc<InstalledPublicReferencePackage>,
    pub(super) profile: ReferenceProfile,
    pub(super) graph: Rc<AdmittedGraph>,
    pub(super) scenario: crate::node_scenario::NodeScenario,
    pub(super) independent: Rc<dyn InstalledProviderSource>,
    pub(super) native: Rc<RefCell<Option<NativePublicEnrollment>>>,
    pub(super) resources: crucible_node_format::ResourceLimits,
    pub(super) quantum_ps: crucible_node_format::U64,
    pub(super) host_budget_ns: crucible_node_format::U64,
    pub(super) scope: ProviderAuthorizationScope,
}

impl ReferenceVendorSource {
    fn current_source(&self) -> Result<(), EvidenceError> {
        let current = self
            .package
            .profile(
                self.profile.descriptor.id.clone(),
                self.profile.owner.id.clone(),
                self.quantum_ps,
                self.host_budget_ns,
                true,
            )
            .map_err(error)?;
        if current.descriptor != self.profile.descriptor
            || current.provider_manifest != self.profile.provider_manifest
            || current.implementation != self.profile.implementation
            || current.configuration_ref != self.profile.configuration_ref
            || current.contents != self.profile.contents
            || self.graph.node_ids().count() != 1
            || self.graph.owners().count() != 1
            || !self.graph.world().connections.is_empty()
            || self.graph.descriptor(&current.descriptor.id) != Some(&current.descriptor)
        {
            return Err(refused("installed reference complete source changed"));
        }
        self.independent
            .authenticate_implementation(&current.implementation)?;
        drop(self.scenario.canonical_bytes().map_err(error)?);
        let binding = self
            .graph
            .binding(&self.profile.descriptor.id)
            .ok_or_else(|| refused("original source binding absent"))?;
        // Reopen the complete original graph against the independently installed
        // source, including ownership, connections, coordinator and demands.
        // A copied admitted graph or standalone checksum identity is insufficient.
        let verified = admit_graph(
            AdmissionRequest {
                world: &self.scenario.world,
                descriptors: &self.scenario.descriptors,
                bindings: std::slice::from_ref(binding),
                owners: &self.scenario.owners,
                requirements: &self.scenario.requirements,
            },
            self.independent.as_ref(),
            AdmissionLimits::default(),
        )
        .map_err(error)?;
        if verified.world_binding_hash() != self.graph.world_binding_hash()
            || verified.binding(&current.descriptor.id) != Some(binding)
            || verified.owners().ne(self.graph.owners())
        {
            return Err(refused("complete installed reference source scope changed"));
        }
        Ok(())
    }

    fn current_native(&self) -> Result<(), EvidenceError> {
        let native = self
            .native
            .try_borrow()
            .map_err(|_| refused("original reference native proof borrowed"))?;
        native
            .as_ref()
            .ok_or_else(|| refused("original reference native enrollment absent"))?
            .authenticate(&self.package, &self.resources)
            .map_err(error)
    }
}

impl AdmissionEvidence for ReferenceVendorSource {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.independent.content(reference, maximum_bytes)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.current_source()?;
        if implementation != &self.profile.implementation {
            return Err(refused("foreign reference implementation"));
        }
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.current_native()?;
        if self.graph.binding(&self.profile.descriptor.id) != Some(binding) {
            return Err(refused("foreign original reference authority"));
        }
        self.independent.authenticate_authority(binding)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        if !self.profile.implementation.formats.contains(schema) {
            return Err(refused("unsupported reference schema"));
        }
        self.independent.authenticate_schema(schema)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.current_source()?;
        if let QualificationClaim::Node {
            binding,
            binding_hash,
            qualification_refs,
        } = &claim
        {
            let original = self
                .graph
                .binding(&self.profile.descriptor.id)
                .ok_or_else(|| refused("installed reference binding absent"))?;
            if *binding != &original.compatibility
                || *binding_hash != &original.compatibility.identity().map_err(error)?
                || *qualification_refs != original.compatibility.qualification_refs.as_slice()
            {
                return Err(refused("foreign complete reference qualification scope"));
            }
        }
        self.independent.qualify(claim)
    }

    fn qualify_capability(
        &self,
        world: &crucible_node_format::WorldBinding,
        binding: &NodeBinding,
        requirement: &crucible_engine::node_admission::NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.current_source()?;
        if world != self.graph.world()
            || self.graph.binding(&self.profile.descriptor.id) != Some(binding)
        {
            return Err(refused("foreign reference capability world"));
        }
        // The independently installed closed subset owns each operation meaning.
        // Absent Compute/preservation support stays its actual default refusal.
        self.independent
            .qualify_capability(world, binding, requirement)
    }
}

impl InstalledProviderSource for ReferenceVendorSource {
    fn authenticate_provider(&self, manifest: &ProviderManifest) -> Result<(), EvidenceError> {
        self.current_source()?;
        self.independent.authenticate_provider(manifest)?;
        if manifest != &self.profile.provider_manifest {
            return Err(refused("foreign reference provider manifest"));
        }
        Ok(())
    }

    fn current_source_revision(
        &self,
        scope: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        self.current_source()?;
        if scope != &self.scope {
            return Err(refused("foreign reference revision scope"));
        }
        let lease = self.independent.current_source_revision(scope)?;
        lease.authenticate(scope, ProviderAuthorityKind::Source)?;
        Ok(lease)
    }

    fn authenticate_plan(
        &self,
        manifest: &ProviderManifest,
        selection: ProviderPlanningRequest<'_>,
        plan: &ProviderPreparationPlan,
    ) -> Result<(), EvidenceError> {
        self.authenticate_provider(manifest)?;
        self.independent
            .authenticate_plan(manifest, selection, plan)?;
        if ProviderAuthorizationScope::from_plan(selection, plan)? != self.scope
            || plan.descriptors.as_slice() != std::slice::from_ref(&self.profile.descriptor)
            || plan.bindings.as_slice()
                != std::slice::from_ref(
                    &self
                        .graph
                        .binding(&self.profile.descriptor.id)
                        .ok_or_else(|| refused("original source binding absent"))?
                        .compatibility,
                )
        {
            return Err(refused("foreign complete reference preparation plan"));
        }
        for binding in &plan.bindings {
            self.qualify(QualificationClaim::Node {
                binding,
                binding_hash: &binding.identity().map_err(error)?,
                qualification_refs: &binding.qualification_refs,
            })?;
        }
        Ok(())
    }

    fn authenticate_prepared(
        &self,
        manifest: &ProviderManifest,
        plan: &ProviderPreparationPlan,
        prepared: &PreparedRealization,
    ) -> Result<(), EvidenceError> {
        self.authenticate_provider(manifest)?;
        self.current_native()?;
        self.independent
            .authenticate_prepared(manifest, plan, prepared)?;
        if prepared.activation_record().world_binding_hash != *self.graph.world_binding_hash()
            || prepared.participants().len() != 1
            || plan.descriptors.len() != 1
            || plan.bindings.len() != 1
        {
            return Err(refused("foreign original reference prepared world"));
        }
        let actual = prepared
            .participants()
            .next()
            .ok_or_else(|| refused("original prepared peer absent"))?;
        if actual.descriptor() != &plan.descriptors[0]
            || actual.binding().compatibility != plan.bindings[0]
            || self.graph.binding(&self.profile.descriptor.id) != Some(actual.binding())
        {
            return Err(refused("changed original reference prepared peer"));
        }
        self.authenticate_authority(actual.binding())
    }
}

fn error(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}

fn refused(message: &str) -> EvidenceError {
    EvidenceError {
        message: message.into(),
    }
}
