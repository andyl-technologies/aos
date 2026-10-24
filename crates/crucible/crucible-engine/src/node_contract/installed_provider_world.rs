//! One source-authenticated preparation and graph view for mixed implementations.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
};

use crucible_node_format::{ContentRef, Id, ImplementationIdentity, NodeBinding, SchemaRef};

use crate::node_admission::{AdmissionEvidence, EvidenceError, QualificationClaim};

use super::{
    InstalledProviderRegistry, ProviderEvidence, ProviderPlanningRequest, ProviderPreparationPlan,
    credit, error, refused, validate_plan, validate_selection,
};
use crate::node_contract::{
    ActivationRecord, InstalledProviderClassAdmission, InstalledProviderWorldSource,
    PreparedRealization, ProviderAuthorizationScope, ProviderWorldAuthorizationScope,
    ProviderWorldPreparation, RealizationFailure, RuntimeCustodySlot, RuntimeLimits,
};

/// Names an existing source-installed contributor and its exact local plan.
#[derive(Clone, Copy)]
pub struct ProviderWorldSelection<'a> {
    /// Original installed provider identity; this cannot install an authority.
    pub provider: &'a Id,
    /// Original bounded profile, configuration and local node roster.
    pub selection: ProviderPlanningRequest<'a>,
    /// Exact expected source-regenerated local descriptor/binding plan.
    pub plan: &'a ProviderPreparationPlan,
}

/// Borrows an accepted local contribution and the complete global preparation.
#[derive(Clone, Copy)]
pub struct ProviderContributionRequest<'a> {
    /// Original local selected profile and resource ceilings.
    pub selection: ProviderPlanningRequest<'a>,
    /// Independently authenticated local planning metadata.
    pub plan: &'a ProviderPreparationPlan,
    /// Complete global plan, including every other contributor.
    pub world_plan: &'a ProviderPreparationPlan,
    /// Complete original activation and owner roster shared by all contributors.
    pub activation: &'a ActivationRecord,
    /// Same admitted runtime limits; no additional world slot is supplied.
    pub runtime_limits: RuntimeLimits,
}

/// Transfers exactly one preowned global slot into mixed inactive preparation.
pub struct ProviderMixedWorldRequest<'a> {
    /// Complete disjoint partition ordered by installed provider and selected profile.
    pub contributions: &'a [ProviderWorldSelection<'a>],
    /// Complete descriptors/bindings in globally increasing node order.
    pub plan: &'a ProviderPreparationPlan,
    /// Same original global incarnation and full owner roster.
    pub activation: &'a ActivationRecord,
    /// Whole-world host routing and operation ceilings.
    pub runtime_limits: RuntimeLimits,
    /// Pre-reserved global custody, never split into contributor world slots.
    pub custody_slot: Box<dyn RuntimeCustodySlot>,
}

impl InstalledProviderRegistry {
    /// Installs a complete-world source owner independently of provider profiles.
    ///
    /// Local provider or class evidence cannot replace this original coordinator,
    /// connection and cross-owner source authority. Existing ownership cannot be
    /// replaced while original worlds or cleanup obligations can remain.
    ///
    /// # Errors
    /// Refuses replacement of an already installed complete-world source.
    pub fn install_world_source(
        &mut self,
        source: Rc<dyn InstalledProviderWorldSource>,
    ) -> Result<(), EvidenceError> {
        if self.world_source.is_some() {
            return Err(refused("original mixed-world source already installed"));
        }
        self.world_source = Some(source);
        Ok(())
    }

    /// Contributes independently qualified providers beneath one global capsule.
    ///
    /// Every local plan and the complete world source are authenticated before
    /// native birth. All original source/behavior/class/world leases remain with
    /// the actual capsule across contribution, semantic and graph callbacks.
    /// Participants remain inactive until complete ordinary graph admission and
    /// the existing common all-owner readiness/publication barrier.
    ///
    /// # Errors
    /// Refuses missing world source, incomplete/overlapping partitions, changed
    /// plans, absent classes or unsupported contributors. Every adopted original
    /// and the same global slot remain in the returned whole-world failure.
    ///
    /// # Panics
    /// Contributor/source/policy unwinds are caught with this complete builder
    /// outside the callback. Provider-local birth and negotiation must enter its
    /// own preowned guard before a possible unwind, as NodeProvider requires.
    pub fn prepare_mixed_original(
        &mut self,
        request: ProviderMixedWorldRequest<'_>,
        class: &dyn InstalledProviderClassAdmission,
    ) -> Result<PreparedRealization, RealizationFailure> {
        let mut world = ProviderWorldPreparation::for_world(
            request.plan,
            request.activation,
            request.runtime_limits,
            self.limits,
            request.custody_slot,
        )?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.contribute_world(
                request.contributions,
                request.plan,
                request.activation,
                request.runtime_limits,
                class,
                &mut world,
            )
        }));
        match result {
            Ok(Ok(())) => world.finish(),
            Ok(Err(error)) => Err(world.fail(&error.message)),
            Err(_) => {
                Err(world.fail("installed mixed-provider callback unwound; originals retained"))
            }
        }
    }

    fn contribute_world(
        &mut self,
        contributions: &[ProviderWorldSelection<'_>],
        world_plan: &ProviderPreparationPlan,
        activation: &ActivationRecord,
        runtime_limits: RuntimeLimits,
        class: &dyn InstalledProviderClassAdmission,
        world: &mut ProviderWorldPreparation<'_>,
    ) -> Result<(), EvidenceError> {
        self.validate_partition(contributions, world_plan)?;
        let source = Rc::clone(
            self.world_source
                .as_ref()
                .ok_or_else(|| refused("complete mixed-world source not installed"))?,
        );
        let mut scopes = Vec::new();
        let mut authorizations = Vec::new();
        scopes
            .try_reserve_exact(contributions.len())
            .map_err(|_| refused("world scope storage unavailable"))?;
        authorizations
            .try_reserve_exact(contributions.len())
            .map_err(|_| refused("world revision storage unavailable"))?;
        for contribution in contributions {
            let installed = self
                .providers
                .get(contribution.provider)
                .ok_or_else(|| refused("mixed contributor not installed"))?;
            let selection = ProviderPlanningRequest {
                limits: self.limits,
                ..contribution.selection
            };
            if installed.provider.describe() != &installed.manifest {
                return Err(refused("mixed contributor manifest changed"));
            }
            installed
                .source
                .authenticate_provider(&installed.manifest)?;
            let actual = installed
                .provider
                .plan(selection)
                .map_err(|failure| refused(&failure.reason))?;
            validate_plan(&installed.manifest, selection, &actual)?;
            if &actual != contribution.plan {
                return Err(refused(
                    "mixed contributor changed original source planning",
                ));
            }
            installed
                .source
                .authenticate_plan(&installed.manifest, selection, &actual)?;
            for binding in &actual.bindings {
                let hash = binding.identity().map_err(error)?;
                let claim = || QualificationClaim::Node {
                    binding,
                    binding_hash: &hash,
                    qualification_refs: &binding.qualification_refs,
                };
                installed.source.qualify(claim())?;
                installed.behavioral.qualify(claim())?;
                class.qualify(claim())?;
            }
            let scope = ProviderAuthorizationScope::from_plan(selection, &actual)?;
            let source_revision = installed.source.current_source_revision(&scope)?;
            let behavioral_revision = installed.behavioral.current_behavioral_revision(&scope)?;
            let class_revision = class.current_class_revision(&scope)?;
            scopes.push((contribution.provider.clone(), scope.clone()));
            authorizations.push(
                crate::node_contract::provider_revision::ProviderPreparationAuthorization::new(
                    scope,
                    source_revision,
                    behavioral_revision,
                    Some(class_revision),
                ),
            );
        }
        let scope =
            ProviderWorldAuthorizationScope::new(world_plan, scopes, activation, self.limits)?;
        source.authenticate_world_plan(&scope, world_plan)?;
        for contribution in contributions {
            let installed = self
                .providers
                .get(contribution.provider)
                .ok_or_else(|| refused("mixed contributor disappeared"))?;
            installed.source.authenticate_contribution_plan(
                &installed.manifest,
                ProviderPlanningRequest {
                    limits: self.limits,
                    ..contribution.selection
                },
                contribution.plan,
                &scope,
                world_plan,
            )?;
            if installed.provider.describe() != &installed.manifest {
                return Err(refused(
                    "mixed contributor changed after world authentication",
                ));
            }
        }
        let world_revision = source.current_world_revision(&scope)?;
        let Some(first) = authorizations.pop() else {
            return Err(refused("mixed-world authorization is empty"));
        };
        let authorization = first.combine(authorizations, scope.clone(), world_revision);
        authorization.authenticate(true)?;
        // Install the entire terminal conjunction before any native contributor.
        world.original.provider_authorization = Some(authorization);
        for contribution in contributions {
            world.original.authenticate_provider_authorization()?;
            let before = world.original.nodes.len();
            let installed = self
                .providers
                .get_mut(contribution.provider)
                .ok_or_else(|| refused("mixed contributor disappeared"))?;
            let mut contribution_view =
                crate::node_contract::ProviderWorldContribution::new(world, contribution.plan);
            installed
                .provider
                .prepare_original_into(
                    ProviderContributionRequest {
                        selection: ProviderPlanningRequest {
                            limits: self.limits,
                            ..contribution.selection
                        },
                        plan: contribution.plan,
                        world_plan,
                        activation,
                        runtime_limits,
                    },
                    &mut contribution_view,
                )
                .map_err(|failure| refused(&failure.reason))?;
            if world.original.nodes.len() - before != contribution.plan.descriptors.len()
                || world.original.nodes[before..]
                    .iter()
                    .zip(&contribution.plan.descriptors)
                    .zip(&contribution.plan.bindings)
                    .any(|((node, descriptor), binding)| {
                        node.descriptor() != descriptor || &node.binding().compatibility != binding
                    })
            {
                return Err(refused(
                    "mixed contributor omits or changes its original partition",
                ));
            }
            installed.source.authenticate_contribution_prepared(
                &installed.manifest,
                contribution.plan,
                &scope,
                &world.original,
            )?;
            world.original.authenticate_provider_authorization()?;
        }
        source.authenticate_world_prepared(&scope, &world.original)?;
        self.authenticate_mixed_prepared(&world.original)
    }

    /// Checks every original selected description, then all retained revisions.
    ///
    /// The roster comes from the actual prepared world's authenticated scope,
    /// never a caller-selected subset. Run this after the final graph callbacks;
    /// no callback-bearing validation may follow its direct currency check.
    ///
    /// # Errors
    /// Refuses missing mixed scope, changed provider manifests, absent original
    /// registrations or withdrawn source, behavior, class or world revisions.
    ///
    /// # Panics
    /// Provider description callbacks may unwind. The caller keeps the same
    /// complete prepared capsule outside these callbacks and its unwind boundary.
    pub fn authenticate_mixed_prepared(
        &self,
        prepared: &PreparedRealization,
    ) -> Result<(), EvidenceError> {
        let scope = prepared
            .provider_authorization
            .as_ref()
            .and_then(|authorization| authorization.world_scope())
            .ok_or_else(|| refused("original mixed-world authorization scope absent"))?;
        for (provider, _) in scope.contributions() {
            let installed = self
                .providers
                .get(provider)
                .ok_or_else(|| refused("original mixed contributor no longer installed"))?;
            if installed.provider.describe() != &installed.manifest {
                return Err(refused(
                    "mixed provider changed its original installed manifest",
                ));
            }
        }
        // Description callbacks may withdraw any role. This complete original
        // revision conjunction is deliberately the last, callback-free read.
        prepared.authenticate_provider_authorization()
    }

    fn validate_partition(
        &self,
        contributions: &[ProviderWorldSelection<'_>],
        plan: &ProviderPreparationPlan,
    ) -> Result<(), EvidenceError> {
        if contributions.is_empty()
            || contributions.len() > self.limits.nodes
            || contributions.windows(2).any(|pair| {
                (pair[0].provider, pair[0].selection.profile)
                    >= (pair[1].provider, pair[1].selection.profile)
            })
        {
            return Err(refused(
                "mixed world requires a finite unique installed partition",
            ));
        }
        if plan.descriptors.is_empty()
            || plan.descriptors.len() > self.limits.nodes
            || plan.descriptors.len() != plan.bindings.len()
            || plan
                .descriptors
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(refused("mixed world planning is incomplete or unordered"));
        }
        credit(plan, self.limits.metadata_bytes)?;
        let mut total = 0usize;
        for contribution in contributions {
            let installed = self
                .providers
                .get(contribution.provider)
                .ok_or_else(|| refused("mixed contributor not installed"))?;
            let selection = ProviderPlanningRequest {
                limits: self.limits,
                ..contribution.selection
            };
            validate_selection(&installed.manifest, selection)?;
            validate_plan(&installed.manifest, selection, contribution.plan)?;
            total = total
                .checked_add(selection.nodes.len())
                .ok_or_else(|| refused("mixed node count overflow"))?;
            for (descriptor, binding) in contribution
                .plan
                .descriptors
                .iter()
                .zip(&contribution.plan.bindings)
            {
                let index = plan
                    .descriptors
                    .binary_search_by(|actual| actual.id.cmp(&descriptor.id))
                    .map_err(|_| refused("contribution names a foreign global node"))?;
                if &plan.descriptors[index] != descriptor || &plan.bindings[index] != binding {
                    return Err(refused(
                        "contribution differs from complete global planning",
                    ));
                }
            }
        }
        if total != plan.descriptors.len()
            || plan.descriptors.iter().any(|descriptor| {
                contributions
                    .iter()
                    .filter(|part| part.selection.nodes.binary_search(&descriptor.id).is_ok())
                    .count()
                    != 1
            })
        {
            return Err(refused(
                "mixed world partitions overlap or omit an original node",
            ));
        }
        // Credit every occurrence before retaining scopes, plans or routing rows.
        for contribution in contributions {
            credit(
                &(
                    contribution.provider,
                    contribution.selection.profile,
                    contribution.selection.configuration,
                    contribution.selection.resources,
                    contribution.selection.nodes,
                    contribution.plan,
                ),
                self.limits.metadata_bytes / contributions.len(),
            )?;
        }
        Ok(())
    }

    /// Borrows explicit node routing and the installed complete-world evidence.
    ///
    /// Implementations are selected by the declared disjoint partition, never by
    /// trying authorities until one accepts. Global content/schema/coordinator
    /// claims use the separately installed complete-world source.
    ///
    /// # Errors
    /// Refuses incomplete partitions, missing world source or stale registrations.
    ///
    /// # Panics
    /// Installed source callbacks may unwind. Callers keep the same preparation
    /// outside this evidence construction and all subsequent graph callbacks.
    pub fn mixed_admission_evidence(
        &self,
        contributions: &[ProviderWorldSelection<'_>],
        plan: &ProviderPreparationPlan,
    ) -> Result<impl AdmissionEvidence + use<>, EvidenceError> {
        self.validate_partition(contributions, plan)?;
        let world = Rc::clone(
            self.world_source
                .as_ref()
                .ok_or_else(|| refused("mixed world source not installed"))?,
        );
        let mut providers = Vec::new();
        let mut routes = Vec::new();
        providers
            .try_reserve_exact(contributions.len())
            .map_err(|_| refused("world evidence storage unavailable"))?;
        routes
            .try_reserve_exact(plan.descriptors.len())
            .map_err(|_| refused("world route storage unavailable"))?;
        for contribution in contributions {
            let installed = self
                .providers
                .get(contribution.provider)
                .ok_or_else(|| refused("mixed provider absent"))?;
            installed
                .source
                .authenticate_provider(&installed.manifest)?;
            let index = providers.len();
            providers.push((
                installed.manifest.implementation.clone(),
                ProviderEvidence {
                    source: Rc::clone(&installed.source),
                    behavioral: Rc::clone(&installed.behavioral),
                },
            ));
            for node in contribution.selection.nodes {
                routes.push((node.clone(), index));
            }
        }
        Ok(MixedEvidence {
            world,
            providers,
            routes,
        })
    }
}

struct MixedEvidence {
    world: Rc<dyn InstalledProviderWorldSource>,
    providers: Vec<(ImplementationIdentity, ProviderEvidence)>,
    routes: Vec<(Id, usize)>,
}

impl MixedEvidence {
    fn node(&self, node: &Id) -> Result<&ProviderEvidence, EvidenceError> {
        let index = self
            .routes
            .iter()
            .find(|(actual, _)| actual == node)
            .map(|(_, index)| *index)
            .ok_or_else(|| refused("node absent from original mixed partition"))?;
        self.providers
            .get(index)
            .map(|(_, evidence)| evidence)
            .ok_or_else(|| refused("original mixed provider route absent"))
    }
}

impl AdmissionEvidence for MixedEvidence {
    fn extension_registry(&self) -> Option<&crate::node_admission::InstalledExtensionRegistry> {
        self.world.extension_registry()
    }

    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.world.content(reference, maximum)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        let mut found = false;
        for (actual, provider) in &self.providers {
            if actual == implementation {
                provider.authenticate_implementation(implementation)?;
                found = true;
            }
        }
        if !found {
            return Err(refused("foreign mixed-world implementation"));
        }
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.node(&binding.compatibility.node_id)?
            .authenticate_authority(binding)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.world.authenticate_schema(schema)
    }

    fn qualify_capability(
        &self,
        world: &crucible_node_format::WorldBinding,
        binding: &NodeBinding,
        requirement: &crate::node_admission::NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.node(&binding.compatibility.node_id)?
            .qualify_capability(world, binding, requirement)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        match &claim {
            QualificationClaim::Node { binding, .. } => self.node(&binding.node_id)?.qualify(claim),
            QualificationClaim::Port { node_id, .. } => self.node(node_id)?.qualify(claim),
            _ => self.world.qualify(claim),
        }
    }
}
