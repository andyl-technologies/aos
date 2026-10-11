//! Source-installed vendor profiles beneath the ordinary owning node catalog.
//!
//! Portable selections name an existing installation. Both source inspection
//! and independent ordinary behavioral admission remain mandatory before native
//! preparation. The same catalog world slot owns every preparation refusal.

use crate::node_qualification::BehavioralAdmissionEvidence;
use crucible::node_admission::{
    AdmissionEvidence, AdmissionLimits, AdmissionRequest, QualificationClaim, admit_graph,
};
use crucible::node_contract::{
    ActivationRecord, InstalledProviderRegistry, OriginalRealizationRequest,
    ProviderPlanningRequest, ProviderPreparationPlan, RuntimeCustodySupervisor, RuntimeLimits,
};
use crucible_node_contract::Id;

use super::{InstalledNodeCatalog, InstalledPreparedWorld, NodeObservedError, native, refused};
use crate::node_scenario::NodeScenario;

impl InstalledNodeCatalog {
    /// Installs a separately configured source and behavioral provider registry.
    ///
    /// Registration creates no native participant. An existing registry cannot
    /// be replaced while its original worlds or supervision obligations exist.
    ///
    /// # Errors
    /// Refuses replacement of the original installed registry.
    pub fn install_vendor_providers(
        &mut self,
        registry: InstalledProviderRegistry,
    ) -> Result<(), NodeObservedError> {
        if self.vendor_providers.is_some() {
            return Err(refused("vendor provider registry is already installed"));
        }
        self.vendor_providers = Some(registry);
        Ok(())
    }

    /// Borrows an installed vendor manifest through the normal catalog facade.
    ///
    /// Capability discovery creates no native participant and never promotes a
    /// manifest's declarations to ordinary behavioral acceptance or readiness.
    pub fn vendor_manifest(
        &self,
        provider: &Id,
    ) -> Option<&crucible_node_contract::ProviderManifest> {
        self.vendor_providers.as_ref()?.manifest(provider)
    }

    /// Prepares an independently qualified vendor world under original custody.
    ///
    /// The provider's source-regenerated plan must equal the whole authored
    /// descriptors and compatibility records before any Child allocation. The
    /// actual participants then undergo complete ordinary graph admission and
    /// the unchanged common readiness/publication barrier.
    ///
    /// # Errors
    /// Refuses absent installation, unsupported profile/configuration, changed
    /// source plan, behavioral qualification, resource credit or graph admission.
    /// Providers must retain partial native preparation beneath the original
    /// reserved world slot before returning or invoking another callback.
    ///
    /// # Panics
    /// Installed provider or policy callbacks may unwind. Complete returned
    /// preparation transfers through its preowned whole-world supervision slot.
    /// Before return, partial birth or negotiation requires the provider's own
    /// guarded preparation; the catalog cannot retain provider-local resources.
    pub fn prepare_vendor_world(
        &mut self,
        provider: &Id,
        selection: ProviderPlanningRequest<'_>,
        scenario: NodeScenario,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<InstalledPreparedWorld, NodeObservedError> {
        drop(scenario.canonical_bytes()?);
        // The portable complete scenario is already bounded before these copies.
        // It conveys configuration data; only registry source/class gates can
        // authenticate the resulting plan and native realization.
        let expected = ProviderPreparationPlan {
            descriptors: scenario.descriptors.clone(),
            bindings: scenario.compatibility.clone(),
        };
        let installed = self.behavioral_acceptance.as_ref().ok_or_else(|| {
            refused("vendor preparation requires normal installed behavioral acceptance")
        })?;
        let selected =
            super::acceptance::SourceBindingPolicy::new(installed.policy.as_ref(), &scenario);
        let registry = self
            .vendor_providers
            .as_mut()
            .ok_or_else(|| refused("vendor provider registry is not installed"))?;
        {
            let source = registry.admission_evidence(provider).map_err(native)?;
            let evidence = BehavioralAdmissionEvidence::new(&source, &selected, installed.limits);
            for binding in &scenario.compatibility {
                evidence
                    .qualify(QualificationClaim::Node {
                        binding,
                        binding_hash: &binding.identity()?,
                        qualification_refs: &binding.qualification_refs,
                    })
                    .map_err(native)?;
            }
        }
        let slot = self
            .custody
            .reserve_world(activation, limits)
            .map_err(native)?;
        let source = registry.admission_evidence(provider).map_err(native)?;
        let final_evidence = BehavioralAdmissionEvidence::new(&source, &selected, installed.limits);
        let prepared = registry
            .prepare_original_with_admission(
                provider,
                OriginalRealizationRequest {
                    selection,
                    plan: &expected,
                    activation,
                    runtime_limits: limits,
                    custody_slot: slot,
                },
                &final_evidence,
            )
            .map_err(|failure| {
                // The retained original is transferred by PreparedRealization's
                // existing owning drop, never extracted into standalone nodes.
                let reason = failure.reason.clone();
                drop(failure);
                native(reason)
            })?;
        let bindings: Vec<_> = prepared
            .participants()
            .map(|node| node.binding().clone())
            .collect();
        let source = registry.admission_evidence(provider).map_err(native)?;
        let evidence = BehavioralAdmissionEvidence::new(&source, &selected, installed.limits);
        let graph = admit_graph(
            AdmissionRequest {
                world: &scenario.world,
                descriptors: &scenario.descriptors,
                bindings: &bindings,
                owners: &scenario.owners,
                requirements: &scenario.requirements,
            },
            &evidence,
            AdmissionLimits::default(),
        )
        .map_err(native)?;
        // Graph admission invokes installed source and ordinary class callbacks.
        // Recheck the SAME original fences after every such callback; nothing
        // external follows this direct conjunction before owning world return.
        prepared
            .authenticate_provider_authorization()
            .map_err(native)?;
        Ok(InstalledPreparedWorld {
            scenario,
            graph,
            realization: prepared,
        })
    }
}
