//! Owned inactive provider preparation and admitted whole-world realization.

use crucible_node_contract::ProviderManifest;

use super::{
    ActivationRecord, NodeRuntime, RuntimeCustodySlot, RuntimeError, RuntimeLimits,
    RuntimePreparationFailure, SimulationNode,
};

/// Supplies immutable admitted planning and a bounded inactive realization request.
pub struct RealizationRequest<'a> {
    /// Complete sealed graph, without native execution permission.
    pub graph: &'a crate::node_admission::AdmittedGraph,
    /// Original initial or preserved cut and fresh complete owner roster.
    pub activation: &'a ActivationRecord,
    /// Exact admitted host routing and operation resource ceilings.
    pub limits: RuntimeLimits,
    /// Reserves whole-world custody before the provider allocates native resources.
    pub custody_slot: Box<dyn RuntimeCustodySlot>,
}

/// Retains prepared native handles with ordinary semantic execution withheld.
#[must_use = "admit inactive handles or retain their supervised cleanup custody"]
pub struct PreparedRealization {
    pub(super) nodes: Vec<Box<dyn SimulationNode>>,
    pub(super) activation: ActivationRecord,
    pub(super) limits: RuntimeLimits,
    pub(super) custody_slot: Option<Box<dyn RuntimeCustodySlot>>,
    pub(super) provider_authorization:
        Option<super::provider_revision::ProviderPreparationAuthorization>,
}

impl PreparedRealization {
    /// Takes custody of inactive native handles without creating ready authority.
    ///
    /// This constructor does not qualify a profile or validate a realization.
    /// Native resources must already be contained and supervised by their
    /// adapters. [`Self::admit`] checks the exact complete admitted realization.
    pub fn new(
        nodes: Vec<Box<dyn SimulationNode>>,
        activation: ActivationRecord,
        limits: RuntimeLimits,
        custody_slot: Box<dyn RuntimeCustodySlot>,
    ) -> Self {
        Self {
            nodes,
            activation,
            limits,
            custody_slot: Some(custody_slot),
            provider_authorization: None,
        }
    }

    /// Borrows the exact original inactive world record under this owned realization.
    ///
    /// This read-only data grants no readiness, publication or execution authority.
    /// The caller may bind authentic coordinator publication to this original
    /// record; actual owner preparation and the runtime barrier remain mandatory.
    pub fn activation_record(&self) -> &ActivationRecord {
        &self.activation
    }

    /// Borrows actual inactive participants for pre-admission graph construction.
    ///
    /// Metadata inspection grants no execution or mutation authority. The owning
    /// capsule and its reserved supervision slot remain intact across callbacks.
    pub fn participants(&self) -> impl ExactSizeIterator<Item = &dyn SimulationNode> {
        self.nodes.iter().map(|node| node.as_ref())
    }

    /// Checks retained original vendor source, evidence and normal class currency.
    ///
    /// This direct read invokes no provider, codec, source or policy callback.
    /// The catalog uses it after complete graph admission, with the same original
    /// revision leases installed by the registry before realization validation.
    /// It grants no graph, readiness, operation or acceptance authority itself.
    ///
    /// # Errors
    /// Refuses absent registry authorization, absent ordinary class currency,
    /// foreign scope or any withdrawn original authority.
    pub fn authenticate_provider_authorization(
        &self,
    ) -> Result<(), crate::node_admission::EvidenceError> {
        self.provider_authorization
            .as_ref()
            .ok_or_else(|| crate::node_admission::EvidenceError {
                message: "original installed vendor authorization absent".into(),
            })?
            .authenticate(true)
    }

    /// Admits prepared native handles into an inactive whole-world runtime.
    ///
    /// # Errors
    /// Returns the original owned handles on incompatible descriptors, bindings,
    /// routes, generations or resource ceilings. Success still requires complete
    /// authentic readiness and durable world activation before execution.
    pub fn admit(
        mut self,
        graph: &crate::node_admission::AdmittedGraph,
    ) -> Result<NodeRuntime, Box<RuntimePreparationFailure>> {
        let Some(custody_slot) = self.custody_slot.take() else {
            // This branch cannot follow public construction; leave handles in
            // this guard rather than returning them without a retention slot.
            return Err(RuntimePreparationFailure::without_resources(
                RuntimeError::OutstandingObligations,
                self.activation.clone(),
                self.limits,
            ));
        };
        NodeRuntime::new(
            graph,
            std::mem::take(&mut self.nodes),
            self.activation.clone(),
            self.limits,
            custody_slot,
        )
    }
}

impl Drop for PreparedRealization {
    fn drop(&mut self) {
        if let Some(slot) = self.custody_slot.take() {
            slot.retain(super::WholeRuntimeCustody::from_prepared(
                std::mem::take(&mut self.nodes),
                self.activation.clone(),
                self.limits,
            ));
        }
    }
}

/// Retains failed preparation's native resources with its diagnostic.
pub struct RealizationFailure {
    /// Unmet preparation precondition or actual native failure.
    pub reason: String,
    /// Prepared resources requiring cleanup, absent only if none were allocated.
    pub retained: Option<Box<PreparedRealization>>,
}

/// Realizes node profiles under owned inactive preparation and host admission.
///
/// Providers do not acquire a second scheduler or activation authority. Optional
/// support is explicit in the verified manifest and realized node binding.
pub trait NodeProvider {
    /// Returns the immutable provider implementation and profile manifest.
    fn describe(&self) -> &ProviderManifest;

    /// Regenerates exact immutable planning metadata before native allocation.
    ///
    /// Implementations enforce the borrowed host limits before constructing the
    /// plan. The registry subsequently authenticates source and behavioral scope.
    /// This callback must not create autonomous resources or native effects.
    ///
    /// # Errors
    /// Defaults to no-effect refusal for providers without installed planning.
    fn plan(
        &self,
        _request: super::ProviderPlanningRequest<'_>,
    ) -> Result<super::ProviderPreparationPlan, RealizationFailure> {
        Err(RealizationFailure {
            reason: "original installed provider planning is unsupported".into(),
            retained: None,
        })
    }

    /// Prepares original inactive nodes before their complete graph can be sealed.
    ///
    /// This consumes the pre-reserved custody slot. Every partial allocation must
    /// enter that same owning capsule before another callback or possible failure.
    /// Ordinary readiness and all-owner durable activation remain separate.
    ///
    /// # Errors
    /// Defaults to refusal before allocation. Implementations return all native
    /// resources in `retained` on any possibly effectful preparation failure.
    fn prepare_original(
        &mut self,
        _request: super::OriginalRealizationRequest<'_>,
    ) -> Result<PreparedRealization, RealizationFailure> {
        Err(RealizationFailure {
            reason: "original pre-admission provider realization is unsupported".into(),
            retained: None,
        })
    }

    /// Prepares requested nodes while withholding all semantic execution.
    ///
    /// # Errors
    /// Returns unsupported profiles, incompatible complete ownership or resource
    /// failures together with custody of any native resources already allocated.
    fn prepare(
        &mut self,
        request: RealizationRequest<'_>,
    ) -> Result<PreparedRealization, RealizationFailure>;
}
