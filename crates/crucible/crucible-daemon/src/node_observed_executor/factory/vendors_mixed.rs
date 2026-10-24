//! Mixed installed contributors beneath the catalog's one owning world barrier.

use std::rc::Rc;

use crucible_engine::node_admission::{AdmissionLimits, AdmissionRequest, admit_graph};
use crucible_engine::node_contract::{
    ActivationRecord, InstalledProviderWorldSource, ProviderMixedWorldRequest,
    ProviderPreparationPlan, ProviderWorldSelection, RuntimeCustodySupervisor, RuntimeLimits,
};

use crate::{node_qualification::BehavioralAdmissionEvidence, node_scenario::NodeScenario};

use super::{InstalledNodeCatalog, InstalledPreparedWorld, NodeObservedError, native, refused};

impl InstalledNodeCatalog {
    /// Installs original complete-world source semantics in the provider registry.
    ///
    /// This operator configuration creates no native resource. The authority must
    /// authenticate cross-provider coordination independently of the local
    /// profiles and the catalog's normal accepted-report/class policy.
    ///
    /// # Errors
    /// Refuses missing registry or replacement of its retained source owner.
    pub fn install_vendor_world_source(
        &mut self,
        source: Rc<dyn InstalledProviderWorldSource>,
    ) -> Result<(), NodeObservedError> {
        self.vendor_providers
            .as_mut()
            .ok_or_else(|| refused("vendor provider registry not installed"))?
            .install_world_source(source)
            .map_err(native)
    }

    /// Prepares one ordinary world from an exact source-installed provider partition.
    ///
    /// One global activation, slot and participant builder precede native birth.
    /// Providers contribute their original inactive nodes without extraction,
    /// respawn or separate world slots. Every owner still passes the common
    /// readiness and complete durable publication barrier after graph admission.
    /// Unsupported QEMU/Gem5 or vendor contribution defaults remain refusal.
    ///
    /// # Errors
    /// Refuses absent complete-world source or ordinary class acceptance, foreign
    /// partitions, changed planning, unsupported contributors or graph semantics.
    /// The same global slot retains every adopted original on any failure.
    ///
    /// # Panics
    /// Installed evidence and metadata callbacks may unwind. Returned or appended
    /// originals remain in the global capsule; provider-local birth requires its
    /// own guarded preparation before callbacks, as NodeProvider requires.
    pub fn prepare_mixed_vendor_world(
        &mut self,
        contributions: &[ProviderWorldSelection<'_>],
        scenario: NodeScenario,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<InstalledPreparedWorld, NodeObservedError> {
        drop(scenario.canonical_bytes()?);
        if activation.world_binding_hash != scenario.world.identity()? {
            return Err(refused(
                "mixed activation differs from original scenario world",
            ));
        }
        let expected = ProviderPreparationPlan {
            descriptors: scenario.descriptors.clone(),
            bindings: scenario.compatibility.clone(),
        };
        let installed = self
            .behavioral_acceptance
            .as_ref()
            .ok_or_else(|| refused("mixed vendor world requires normal behavioral acceptance"))?;
        let selected =
            super::acceptance::SourceBindingPolicy::new(installed.policy.as_ref(), &scenario);
        let registry = self
            .vendor_providers
            .as_mut()
            .ok_or_else(|| refused("vendor provider registry not installed"))?;
        // Construct the complete deterministic evidence route before first Child.
        let source = registry
            .mixed_admission_evidence(contributions, &expected)
            .map_err(native)?;
        let evidence = BehavioralAdmissionEvidence::new(&source, &selected, installed.limits);
        let slot = self
            .custody
            .reserve_world(activation, limits)
            .map_err(native)?;
        let mut bindings = Vec::new();
        bindings
            .try_reserve_exact(expected.bindings.len())
            .map_err(|_| refused("mixed actual binding storage unavailable"))?;
        let prepared = registry
            .prepare_mixed_original(
                ProviderMixedWorldRequest {
                    contributions,
                    plan: &expected,
                    activation,
                    runtime_limits: limits,
                    custody_slot: slot,
                },
                &evidence,
            )
            .map_err(|failure| {
                let reason = failure.reason.clone();
                drop(failure);
                native(reason)
            })?;
        let mut remaining = AdmissionLimits::default().maximum_total_core_bytes;
        for node in prepared.participants() {
            let binding = node.binding();
            let mut counter = BindingCredit(remaining);
            serde_json::to_writer(&mut counter, binding).map_err(native)?;
            remaining = counter.0;
            bindings.push(binding.clone());
        }
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
        // Nothing callback-bearing follows this same-original terminal read.
        registry
            .authenticate_mixed_prepared(&prepared)
            .map_err(native)?;
        Ok(InstalledPreparedWorld {
            scenario,
            graph,
            realization: prepared,
        })
    }
}

// Bound every borrowed actual binding body before creating the retained copy.
struct BindingCredit(usize);

impl std::io::Write for BindingCredit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("mixed actual binding credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
