//! Contributes one ordinary accepted reference peer to the common world capsule.
//!
//! The installation owns a complete independently admitted singleton graph,
//! source bootstrap and normal class policy. Portable selection only names that
//! installation. Foreign graphs and mixed partitions are refused before birth;
//! no per-node checksum result widens the installed whole-world source scope.

use std::{cell::RefCell, rc::Rc};

use crucible_engine::{
    node_admission::AdmittedGraph,
    node_contract::{
        EffectKnowledge, NodeProvider, OperationFailure, OriginalRealizationRequest,
        PreparedRealization, ProviderContributionRequest, ProviderPlanningRequest,
        ProviderPreparationPlan, ProviderWorldContribution, ProviderWorldPreparation,
        RealizationFailure, RealizationRequest, SimulationNode,
    },
};
use crucible_node_format::ProviderManifest;

use crate::node_qualification::{
    AcceptanceLimits, CnpBehavioralAcceptance, InstalledAcceptancePolicy,
};

use super::{
    super::{
        custody::PublicReferenceCustodyQueue, installation::SourcePublicReferenceInstallation,
    },
    ordinary_launch::{OrdinaryReferenceLaunch, prepare},
};

/// Retains one source-installed original, with no retry or replacement launch.
pub(super) struct ReferenceVendorProvider {
    pub(super) installed: SourcePublicReferenceInstallation,
    pub(super) birth_authorities: super::currency::OriginalBirthAuthorities,
    pub(super) graph: Rc<AdmittedGraph>,
    pub(super) queue: PublicReferenceCustodyQueue,
    pub(super) policy: Rc<dyn InstalledAcceptancePolicy>,
    pub(super) acceptance_limits: AcceptanceLimits,
    pub(super) maximum_operations: usize,
    pub(super) original_launch: Option<OrdinaryReferenceLaunch>,
    pub(super) native: Rc<RefCell<Option<super::super::native::NativePublicEnrollment>>>,
}

impl ReferenceVendorProvider {
    fn retain_birth_currency(
        &mut self,
        selection: ProviderPlanningRequest<'_>,
        plan: &ProviderPreparationPlan,
    ) -> Result<(), OperationFailure> {
        let actual_scope =
            crucible_engine::node_contract::ProviderAuthorizationScope::from_plan(selection, plan)
                .map_err(|error| refused(&error.message))?;
        if actual_scope != self.birth_authorities.scope {
            return Err(refused("ordinary reference original birth scope differs"));
        }
        let original = self
            .original_launch
            .as_mut()
            .ok_or_else(|| refused("ordinary reference original launch absent"))?;
        if original.birth_currency.is_some() {
            return Err(refused(
                "ordinary reference original birth fences already retained",
            ));
        }
        original.birth_currency = Some(
            self.birth_authorities
                .retain_original()
                .map_err(|error| refused(&error.message))?,
        );
        Ok(())
    }

    fn plan_original(
        &self,
        selection: ProviderPlanningRequest<'_>,
    ) -> Result<ProviderPreparationPlan, OperationFailure> {
        let maximum = crucible_engine::node_contract::ProviderRegistryLimits::default();
        if selection.limits.metadata_bytes == 0
            || selection.limits.metadata_bytes > maximum.metadata_bytes
        {
            return Err(refused(
                "ordinary reference planning metadata ceiling differs",
            ));
        }
        let node = &self.installed.profile.descriptor.id;
        let profile = &self.installed.profile.node_manifest.profile_id;
        let expected = self
            .graph
            .binding(node)
            .ok_or_else(|| refused("installed reference binding absent"))?;
        if selection.nodes != std::slice::from_ref(node)
            || selection.profile != profile
            || selection.configuration != &self.installed.profile.configuration_ref
            || selection.resources != &self.installed.bootstrap.resource_limits
            || self.graph.node_ids().count() != 1
            || self.graph.owners().count() != 1
            || !self.graph.world().connections.is_empty()
            || self.graph.world_binding_hash() != &self.installed.bootstrap.world_binding_hash
            || self.graph.descriptor(node) != Some(&self.installed.profile.descriptor)
            || self.maximum_operations == 0
            || self.maximum_operations > 256
        {
            return Err(refused(
                "ordinary reference complete source selection differs",
            ));
        }
        super::geometry::bounded(
            &(
                &self.installed.profile.descriptor,
                &expected.compatibility,
                self.graph.owner(&self.installed.profile.owner.id),
            ),
            selection.limits.metadata_bytes,
        )
        .map_err(|error| refused(&error.to_string()))?;
        let (binding, owner) = self
            .installed
            .profile
            .bind_qualified(
                self.installed.bootstrap.authority.clone(),
                &self.installed.qualifications,
            )
            .map_err(|error| refused(&error.to_string()))?;
        if expected != &binding || self.graph.owner(&owner.owner.id) != Some(&owner) {
            return Err(refused(
                "ordinary reference graph is not its original source roster",
            ));
        }
        CnpBehavioralAcceptance::new(self.policy.as_ref(), self.acceptance_limits)
            .authenticate_prelaunch(&self.installed.profile, selection.resources)
            .map_err(|error| refused(&error.to_string()))?;
        super::geometry::bounded(
            &(&self.installed.profile.descriptor, &binding.compatibility),
            selection.limits.metadata_bytes,
        )
        .map_err(|error| refused(&error.to_string()))?;
        Ok(ProviderPreparationPlan {
            descriptors: vec![self.installed.profile.descriptor.clone()],
            bindings: vec![binding.compatibility],
        })
    }

    fn realize(&mut self) -> Result<Box<dyn SimulationNode>, OperationFailure> {
        let request = self
            .original_launch
            .take()
            .ok_or_else(|| refused("ordinary reference launch original was already spent"))?;
        let prepared = prepare(
            &mut self.installed,
            &self.queue,
            request,
            self.policy.as_ref(),
            self.acceptance_limits,
        )
        .map_err(|error| OperationFailure {
            effects: EffectKnowledge::Unknown,
            reason: error.to_string(),
        })?;
        let enrollment = self
            .installed
            .enrollment()
            .map_err(|error| OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: error.to_string(),
            })?;
        enrollment
            .authenticate(
                &self.installed.package,
                &self.installed.bootstrap.resource_limits,
            )
            .map_err(|error| OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: error.to_string(),
            })?;
        *self.native.try_borrow_mut().map_err(|_| OperationFailure {
            effects: EffectKnowledge::Unknown,
            reason: "original native proof holder borrowed".into(),
        })? = Some(enrollment);
        let acceptance = CnpBehavioralAcceptance::new(self.policy.as_ref(), self.acceptance_limits);
        let node = prepared.into_node(
            &self.graph,
            &self.installed.profile.descriptor.id,
            &self.installed,
            &acceptance,
            self.maximum_operations,
        )?;
        Ok(Box::new(node))
    }
}

impl NodeProvider for ReferenceVendorProvider {
    fn describe(&self) -> &ProviderManifest {
        &self.installed.profile.provider_manifest
    }

    fn plan(
        &self,
        request: ProviderPlanningRequest<'_>,
    ) -> Result<ProviderPreparationPlan, RealizationFailure> {
        self.plan_original(request)
            .map_err(|error| RealizationFailure {
                reason: error.reason,
                retained: None,
            })
    }

    fn prepare_original(
        &mut self,
        request: OriginalRealizationRequest<'_>,
    ) -> Result<PreparedRealization, RealizationFailure> {
        self.retain_birth_currency(request.selection, request.plan)
            .map_err(|error| RealizationFailure {
                reason: error.reason,
                retained: None,
            })?;
        let plan = self.plan(request.selection)?;
        if request.plan != &plan
            || request.activation.world_binding_hash != *self.graph.world_binding_hash()
            || self
                .original_launch
                .as_ref()
                .is_none_or(|original| &original.activation != request.activation)
        {
            return Err(RealizationFailure {
                reason: "ordinary reference whole-world original differs".into(),
                retained: None,
            });
        }
        let world = ProviderWorldPreparation::new(request)?;
        match self.realize() {
            Ok(node) => world.append(node)?.finish(),
            Err(error) => Err(fail_world(world, error.reason)),
        }
    }

    fn prepare_original_into(
        &mut self,
        request: ProviderContributionRequest<'_>,
        world: &mut ProviderWorldContribution<'_, '_>,
    ) -> Result<(), OperationFailure> {
        self.retain_birth_currency(request.selection, request.plan)?;
        let plan = self.plan_original(request.selection)?;
        if request.plan != &plan
            || request.world_plan != &plan
            || request.activation != world.activation_record()
            || request.activation.world_binding_hash != *self.graph.world_binding_hash()
            || self
                .original_launch
                .as_ref()
                .is_none_or(|original| &original.activation != request.activation)
        {
            return Err(refused(
                "ordinary reference foreign mixed world is unsupported",
            ));
        }
        let mut original = Some(self.realize()?);
        world
            .append_original(&mut original)
            .map_err(|error| OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: error.message,
            })?;
        Ok(())
    }

    fn prepare(
        &mut self,
        request: RealizationRequest<'_>,
    ) -> Result<PreparedRealization, RealizationFailure> {
        // The registry's original planning/source/class route is mandatory.
        // An already admitted graph alone cannot spend this installation's birth.
        drop(request);
        Err(RealizationFailure {
            reason: "use original installed reference preparation".into(),
            retained: None,
        })
    }
}

fn refused(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

fn fail_world(world: ProviderWorldPreparation<'_>, reason: String) -> RealizationFailure {
    match world.finish() {
        Ok(original) => RealizationFailure {
            reason,
            retained: Some(Box::new(original)),
        },
        Err(mut failure) => {
            failure.reason = reason;
            failure
        }
    }
}
