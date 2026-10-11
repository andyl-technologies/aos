//! Provides an actual source-installed inactive native realization to common admission.

use crucible_node_contract::ProviderManifest;

use crate::node_contract::{
    ActivationRecord, NodeProvider, OperationFailure, PreparedRealization, RealizationFailure,
    RealizationRequest, SimulationNode,
};

use super::{CnpSemanticNode, refused};

/// Retains the actual original inactive node when provider construction refuses.
pub struct CnpSemanticProviderFailure {
    /// Records a current native/source or complete-world precondition failure.
    pub error: OperationFailure,
    /// Owns every original process, request and semantic association.
    pub node: Box<CnpSemanticNode>,
}

/// Supplies one actual source-qualified CNP realization through the common provider API.
///
/// Construction consumes an already graph-admitted, inactive original node. It
/// does not spawn another native instance or derive readiness from descriptions.
/// The first scope requires a complete singleton graph; heterogeneous orchestration
/// must gather actual capsules explicitly rather than omitting another participant.
#[must_use = "retain or consume the actual inactive native provider custody"]
pub struct CnpSemanticProvider {
    node: Option<CnpSemanticNode>,
    source: std::rc::Rc<dyn super::CnpSemanticSource>,
    activation: ActivationRecord,
}

impl CnpSemanticProvider {
    /// Retains the actual original node beneath its complete initial world proposal.
    ///
    /// # Errors
    /// Returns the owned node on used or quarantined custody, foreign world or
    /// owner roster, or failed current native/acceptance validation.
    pub fn new(
        node: CnpSemanticNode,
        activation: ActivationRecord,
    ) -> Result<Self, CnpSemanticProviderFailure> {
        if node
            .preparation
            .guard
            .custody
            .as_ref()
            .is_some_and(|native| native.conformance.is_some())
        {
            return Err(CnpSemanticProviderFailure {
                error: refused("ordinary provider refuses conformance-only custody"),
                node: Box::new(node),
            });
        }
        Self::new_installed(node, activation)
    }

    pub(super) fn new_installed(
        node: CnpSemanticNode,
        activation: ActivationRecord,
    ) -> Result<Self, CnpSemanticProviderFailure> {
        let result = (|| {
            node.current()?;
            let source = node.source()?;
            if activation.world_binding_hash != source.installation().world_binding_hash
                || activation.owners != node.route.owners
                || node.state()?.arm_attempt.is_some()
                || node.state()?.activation_attempt.is_some()
                || !node.state()?.operations.is_empty()
                || !node.state()?.inputs.is_empty()
            {
                return Err(refused(
                    "generic provider changed complete original inactive world",
                ));
            }
            Ok(source)
        })();
        match result {
            Ok(source) => Ok(Self {
                node: Some(node),
                source,
                activation,
            }),
            Err(error) => Err(CnpSemanticProviderFailure {
                error,
                node: Box::new(node),
            }),
        }
    }

    pub(super) fn prepare_collection(
        &mut self,
        graph: crate::node_admission::ConformanceGraph,
        limits: crate::node_contract::RuntimeLimits,
        custody_slot: Box<dyn crate::node_contract::RuntimeCustodySlot>,
    ) -> Result<
        crate::node_contract::ConformanceRuntime,
        crate::node_contract::ConformanceRuntimeFailure,
    > {
        let Some(node) = self.node.take() else {
            return Err(crate::node_contract::ConformanceRuntimeFailure::retained(
                "original collecting node was already transferred",
                PreparedRealization::new(Vec::new(), self.activation.clone(), limits, custody_slot),
            ));
        };
        let validated = (|| {
            graph.reauthenticate().map_err(super::unknown)?;
            node.current()?;
            node.preparation
                .guard
                .custody()
                .map_err(super::unknown)?
                .conformance
                .as_ref()
                .ok_or_else(|| refused("collecting provider has no fixture authority"))?
                .authenticate_graph(node.scope()?, &graph)
        })();
        let retained = PreparedRealization::new(
            vec![Box::new(node)],
            self.activation.clone(),
            limits,
            custody_slot,
        );
        if let Err(error) = validated {
            return Err(crate::node_contract::ConformanceRuntimeFailure::retained(
                error.reason,
                retained,
            ));
        }
        crate::node_contract::ConformanceRuntime::from_prepared(graph, retained)
    }
}

impl NodeProvider for CnpSemanticProvider {
    fn describe(&self) -> &ProviderManifest {
        &self.source.installation().provider
    }

    fn prepare(
        &mut self,
        request: RealizationRequest<'_>,
    ) -> Result<PreparedRealization, RealizationFailure> {
        let Some(node) = self.node.take() else {
            return Err(RealizationFailure {
                reason: "generic original inactive realization was already transferred".into(),
                retained: None,
            });
        };
        let validation = (|| {
            node.current()?;
            if request.graph.collecting || node.collection_scope().is_some() {
                return Err(refused(
                    "ordinary provider transfer refuses collecting purpose",
                ));
            }
            let install = self.source.installation();
            if request.graph.node_ids().count() != 1
                || request.graph.descriptor(&install.descriptor.id) != Some(&install.descriptor)
                || request.graph.binding(&install.descriptor.id) != Some(&install.binding)
                || request.graph.owner(&install.owner.owner.id) != Some(&install.owner)
                || request.graph.world_binding_hash() != &install.world_binding_hash
                || request.activation != &self.activation
                || request.limits.maximum_nodes == 0
                || request.limits.maximum_owners == 0
                || request.limits.maximum_operations == 0
                || request.limits.maximum_operations > install.maximum_operations
            {
                return Err(refused(
                    "generic provider request differs from installed complete native scope",
                ));
            }
            Ok(())
        })();
        // The real runtime slot owns the native node even when request validation
        // fails. Failure never discards a allocated original or creates a substitute.
        let retained = PreparedRealization::new(
            vec![Box::new(node)],
            self.activation.clone(),
            request.limits,
            request.custody_slot,
        );
        match validation {
            Ok(()) => Ok(retained),
            Err(error) => Err(RealizationFailure {
                reason: error.reason,
                retained: Some(Box::new(retained)),
            }),
        }
    }
}
