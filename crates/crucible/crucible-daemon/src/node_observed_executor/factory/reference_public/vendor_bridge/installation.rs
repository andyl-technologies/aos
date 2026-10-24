//! Joins a trusted complete reference world with its original ordinary authorities.
//!
//! The constructor performs source and full normal-class inspection without
//! allocating a Child. The registry retains those same owners and rechecks them
//! before and after the original inactive realization. No portable selection
//! or revision owner can manufacture acceptance.

#[path = "budget.rs"]
mod budget;

use std::{cell::RefCell, path::PathBuf, rc::Rc};

use crucible_campaign::ExecutionId;
use crucible_engine::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, InstalledProviderBehavioral, InstalledProviderRegistry,
        InstalledProviderSource, ProviderAuthorityKind, ProviderAuthorizationScope,
        ProviderPlanningRequest, ProviderPreparationPlan, ProviderRegistryLimits, RuntimeLimits,
    },
};
use crucible_node_format::{Bytes, ContentRef, Id, ResourceLimits};
use crucible_node_transport::reference_service::ReferenceServiceBootstrap;

use crate::{
    node_observed_executor::{
        NodeObservedError,
        factory::{
            InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, refused,
            vendor_selection::InstalledVendorWorld,
        },
    },
    node_qualification::{AcceptanceLimits, CnpBehavioralAcceptance, InstalledAcceptancePolicy},
    node_scenario::NodeScenario,
};

use super::{
    super::{
        custody::PublicReferenceCustodyQueue, installation::SourcePublicReferenceInstallation,
    },
    PublicReferenceVendorSelection,
    behavioral::ReferenceVendorBehavioral,
    ordinary_launch::OrdinaryReferenceLaunch,
    provider::ReferenceVendorProvider,
    source::ReferenceVendorSource,
};

/// Supplies trusted actor-local installation, independently of public configuration.
///
/// These original authorities are constructed by operator source installation.
/// This type has no deserializer. The normal policy must already own a genuine
/// complete Accepted report, required classes and their current revision.
pub struct ReferenceVendorInstallationRequest {
    /// Names the compiled source profile and bounded original window credit.
    pub selection: PublicReferenceVendorSelection,
    /// Retains the exact complete independently authored scenario.
    pub scenario: NodeScenario,
    /// Retains its independently authenticated ordinary graph.
    pub graph: Rc<AdmittedGraph>,
    /// Owns independent complete-world source and policy inspection.
    pub source: Rc<dyn InstalledProviderSource>,
    /// Retains the independently installed original behavioral revision owner.
    pub behavioral_source: Rc<dyn InstalledProviderBehavioral>,
    /// Owns the same normal class report used by provider and catalog.
    pub behavioral: Rc<dyn InstalledAcceptancePolicy>,
    /// Narrows independent normal acceptance limits.
    pub acceptance_limits: AcceptanceLimits,
    /// Retains source-authenticated private launch data for this incarnation.
    pub bootstrap: ReferenceServiceBootstrap,
    /// Retains full original source/class roots installed in the private bootstrap.
    pub qualifications: Vec<ContentRef>,
    /// Binds the once-only original observed execution.
    pub execution: ExecutionId,
    /// Binds the same original all-owner activation.
    pub activation: ActivationRecord,
    /// Selects an unused absolute private directory for the original peer.
    pub directory: PathBuf,
    /// Retains the original Hello request identity.
    pub hello_id: Id,
    /// Retains the original connection identity.
    pub connection_id: Id,
    /// Retains the independently generated original nonce.
    pub controller_nonce: Bytes,
    /// Narrows complete-world runtime accounting; it does not add node capabilities.
    pub runtime_limits: RuntimeLimits,
}

/// Owns one source-installed ordinary reference registry and complete world definition.
pub struct ReferenceVendorInstallation {
    registry: InstalledProviderRegistry,
    policy: Rc<dyn InstalledAcceptancePolicy>,
    limits: AcceptanceLimits,
    provider: Id,
    world: InstalledVendorWorld,
}

impl ReferenceVendorInstallation {
    /// Authenticates a complete source installation without native effects.
    ///
    /// # Errors
    /// Refuses foreign package, graph or bootstrap, missing complete source or
    /// normal Accepted classes, absent original revisions, unsupported mixed
    /// ownership, or exhausted metadata/window credit.
    ///
    /// # Panics
    /// Independently installed source and policy callbacks may unwind. No Child
    /// or native capsule has been allocated by this constructor.
    pub fn new(request: ReferenceVendorInstallationRequest) -> Result<Self, NodeObservedError> {
        budget::authenticate_window_credit(
            request.selection.maximum_windows,
            request.bootstrap.resource_limits.maximum_operations,
            request.bootstrap.limits.journal_entries,
        )?;
        drop(request.scenario.canonical_bytes()?);
        let (package, profile) = request.selection.describe()?;
        let actual_requirements = serde_json::to_value(&request.scenario.requirements)?;
        let expected_requirements = serde_json::to_value(request.graph.requirements())?;
        let binding = request
            .graph
            .binding(&request.selection.node)
            .ok_or_else(|| refused("original vendor graph binding absent"))?;
        let owner = request
            .activation
            .owners
            .first()
            .ok_or_else(|| refused("original vendor activation owner absent"))?;
        if request.graph.node_ids().count() != 1
            || request.graph.owners().count() != 1
            || !request.graph.world().connections.is_empty()
            || request.scenario.world != *request.graph.world()
            || request.scenario.descriptors.as_slice() != std::slice::from_ref(&profile.descriptor)
            || request.scenario.compatibility.as_slice()
                != std::slice::from_ref(&binding.compatibility)
            || request.scenario.owners.len() != 1
            || request.graph.owner(&request.selection.owner) != request.scenario.owners.first()
            || actual_requirements != expected_requirements
            || request.activation.world_binding_hash != *request.graph.world_binding_hash()
            || request.activation.owners.len() != 1
            || owner.owner != request.selection.owner
            || request.bootstrap.node_id != request.selection.node
            || request.bootstrap.owner_id != request.selection.owner
            || request.bootstrap.quantum_ps != request.selection.quantum_ps
            || request.bootstrap.host_budget_ns != request.selection.host_budget_ns
            || request.runtime_limits.maximum_nodes != 1
            || request.runtime_limits.maximum_owners != 1
            || request.runtime_limits.maximum_operations < request.selection.maximum_windows
            || request.runtime_limits.maximum_operations > 256
            || request.runtime_limits.maximum_retained_outputs == 0
            || request.runtime_limits.maximum_retained_outputs > 256
        {
            return Err(refused(
                "original reference complete source/world scope differs",
            ));
        }
        super::geometry::bounded(
            &(
                &request.scenario,
                &request.bootstrap,
                &request.qualifications,
            ),
            ProviderRegistryLimits::default().metadata_bytes,
        )
        .map_err(super::super::super::native)?;
        let installed = SourcePublicReferenceInstallation::new(
            package.clone(),
            profile.clone(),
            request.bootstrap.clone(),
            request.qualifications.clone(),
            true,
        )
        .map_err(super::super::super::native)?;
        let (original_binding, original_owner) = profile
            .bind_qualified(request.bootstrap.authority.clone(), &request.qualifications)
            .map_err(super::super::super::native)?;
        if &original_binding != binding
            || request.graph.owner(&request.selection.owner) != Some(&original_owner)
        {
            return Err(refused(
                "original reference authority and owner differ from source graph",
            ));
        }
        CnpBehavioralAcceptance::new(request.behavioral.as_ref(), request.acceptance_limits)
            .authenticate_prelaunch(&profile, &request.bootstrap.resource_limits)
            .map_err(super::super::super::native)?;
        let plan = ProviderPreparationPlan {
            descriptors: vec![profile.descriptor.clone()],
            bindings: vec![binding.compatibility.clone()],
        };
        let nodes = [request.selection.node.clone()];
        let selection = ProviderPlanningRequest {
            profile: &profile.node_manifest.profile_id,
            configuration: &profile.configuration_ref,
            nodes: &nodes,
            resources: &request.bootstrap.resource_limits,
            limits: ProviderRegistryLimits::default(),
        };
        let scope = ProviderAuthorizationScope::from_plan(selection, &plan)
            .map_err(super::super::super::native)?;
        request
            .behavioral
            .provider_revision(&scope)
            .map_err(super::super::super::native)?
            .authenticate(&scope, ProviderAuthorityKind::CatalogClass)
            .map_err(super::super::super::native)?;
        let owner = owner.clone();
        let native = Rc::new(RefCell::new(None));
        let birth_authorities = super::currency::OriginalBirthAuthorities {
            source: request.source.clone(),
            behavioral: request.behavioral_source.clone(),
            class: request.behavioral.clone(),
            scope: scope.clone(),
        };
        let source = Rc::new(ReferenceVendorSource {
            package,
            profile: profile.clone(),
            graph: request.graph.clone(),
            scenario: request.scenario.clone(),
            independent: request.source,
            native: native.clone(),
            resources: request.bootstrap.resource_limits.clone(),
            quantum_ps: request.selection.quantum_ps,
            host_budget_ns: request.selection.host_budget_ns,
            scope: scope.clone(),
        });
        let behavioral = Rc::new(ReferenceVendorBehavioral {
            source: source.clone(),
            policy: request.behavioral.clone(),
            limits: request.acceptance_limits,
            independent: request.behavioral_source,
        });
        let provider_id = profile.provider_manifest.provider_id.clone();
        let selector = InstalledNodeSelection {
            node: request.selection.node,
            owner: request.selection.owner,
            kind: InstalledNodeKind::InstalledVendor {
                provider: provider_id.clone(),
                profile: profile.node_manifest.profile_id.clone(),
                configuration: profile.configuration_ref.clone(),
            },
        };
        let resources: ResourceLimits = request.bootstrap.resource_limits;
        let queue = PublicReferenceCustodyQueue::new(1).map_err(super::super::super::native)?;
        let provider = ReferenceVendorProvider {
            installed,
            birth_authorities,
            graph: request.graph,
            queue: queue.clone(),
            policy: request.behavioral.clone(),
            acceptance_limits: request.acceptance_limits,
            maximum_operations: request.selection.maximum_windows,
            native,
            original_launch: Some(OrdinaryReferenceLaunch {
                directory: request.directory,
                birth_currency: None,
                activation: request.activation.clone(),
                owner: owner.clone(),
                source_roots: request.qualifications,
                hello_id: request.hello_id,
                connection_id: request.connection_id,
                controller_nonce: request.controller_nonce,
            }),
        };
        let mut registry = InstalledProviderRegistry::new(ProviderRegistryLimits::default())
            .map_err(super::super::super::native)?;
        registry
            .install(
                &profile.provider_manifest,
                Box::new(provider),
                source,
                behavioral,
            )
            .map_err(super::super::super::native)?;
        Ok(Self {
            registry,
            policy: request.behavioral,
            limits: request.acceptance_limits,
            provider: provider_id,
            world: InstalledVendorWorld {
                execution: request.execution,
                selection: selector,
                scenario: request.scenario,
                activation: request.activation,
                resources,
                runtime_limits: request.runtime_limits,
                cleanup: ReferenceVendorCleanup(queue),
            },
        })
    }

    /// Installs the same registry, policy and world definition on the owning service actor.
    ///
    /// # Errors
    /// Refuses replacement or any prior catalog native custody. No Child is
    /// allocated, and no portable request can invoke this installation operation.
    pub fn install(self, catalog: &mut InstalledNodeCatalog) -> Result<(), NodeObservedError> {
        if catalog.vendor_providers.is_some()
            || catalog.behavioral_acceptance.is_some()
            || !catalog.vendor_worlds.is_empty()
            || catalog.custody.reserved_worlds() != 0
        {
            return Err(refused(
                "ordinary vendor installation cannot replace original catalog scope",
            ));
        }
        catalog.install_shared_behavioral_acceptance(self.policy, self.limits)?;
        catalog.install_vendor_providers(self.registry)?;
        catalog.vendor_worlds.insert(self.provider, self.world);
        Ok(())
    }
}

// The original peer queue remains installation-owned after kernel reclamation.
// Polling does not discard private journals or claim durable semantic release.
pub(in crate::node_observed_executor::factory) struct ReferenceVendorCleanup(
    PublicReferenceCustodyQueue,
);

impl ReferenceVendorCleanup {
    pub(in crate::node_observed_executor::factory) fn publisher(
        &self,
        stored: crate::node_observed_executor::StoredWorldActivationPublisher,
    ) -> Box<dyn crucible_engine::node_contract::ActivationPublisher> {
        Box::new(
            super::super::custody_publication::PublicReferenceCustodyPublisher::new(
                stored,
                self.0.clone(),
            ),
        )
    }

    pub(in crate::node_observed_executor::factory) fn poll(
        &self,
    ) -> Result<bool, crucible_node_transport::ProviderError> {
        self.0.poll_reclamation()?;
        self.0.resolve_ordinary_reclaimed()
    }

    pub(in crate::node_observed_executor::factory) fn retained(&self) -> usize {
        self.0.outstanding()
    }
}
