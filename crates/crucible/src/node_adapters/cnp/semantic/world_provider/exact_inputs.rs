//! Retains native-three and one genuine common scheduling owner in the original capsule.
//!
//! This route neither widens the old three-peer provider nor accepts a generic
//! host proxy. Every transfer uses the same original graph and custody slot.

use super::*;
use crate::node_contract::{HostSchedulingSource, PreparedHostSchedulingNode};
use std::rc::Rc;

/// Retains the complete callback-free exact-input world reservation request.
pub struct CnpSemanticExactWorldReservation {
    /// Retains three actual original collecting CNP peers.
    pub nodes: Vec<CnpSemanticConformanceNode>,
    /// Retains an empty native pointer vector with capacity for all four nodes.
    pub native: Vec<Box<dyn SimulationNode>>,
    /// Retains the genuine source-created common scheduling node.
    pub host: PreparedHostSchedulingNode,
    /// Retains the same original source view without renewing its permission.
    pub source: Rc<HostSchedulingSource>,
    /// Retains the complete four-owner activation proposal.
    pub activation: ActivationRecord,
    /// Retains the original complete opaque collection graph.
    pub graph: ConformanceGraph,
    /// Retains the original pre-Child whole-runtime custody reservation.
    pub runtime_custody: Box<dyn RuntimeCustodySlot>,
}

/// Retains the complete exact-input provider on callback-free reservation refusal.
pub struct CnpSemanticExactWorldReservationFailure {
    /// Describes the original finite-roster refusal.
    pub error: OperationFailure,
    /// Keeps every original peer, host node, graph and native custody slot.
    pub original: Box<CnpSemanticExactConformanceWorldProvider>,
}

/// Owns one exact-input collecting capsule with native-three and a genuine host owner.
#[must_use = "retain the original four-owner capsule until transfer or containment"]
pub struct CnpSemanticExactConformanceWorldProvider {
    original: CnpSemanticConformanceWorldProvider,
    host: Option<PreparedHostSchedulingNode>,
    source: Rc<HostSchedulingSource>,
}

impl CnpSemanticConformanceWorldProvider {
    /// Reserves all four original owners without invoking any source callback.
    ///
    /// # Errors
    /// Returns the complete original capsule on a changed finite roster,
    /// nonempty native vector or insufficient pre-Child pointer capacity.
    pub fn reserve_exact_inputs(
        request: CnpSemanticExactWorldReservation,
    ) -> Result<CnpSemanticExactConformanceWorldProvider, CnpSemanticExactWorldReservationFailure>
    {
        let original = Box::new(CnpSemanticExactConformanceWorldProvider {
            original: Self {
                nodes: Some(request.nodes),
                native: request.native,
                retirement: None,
                activation: request.activation,
                original_graph: Some(request.graph),
                runtime_custody: Some(request.runtime_custody),
            },
            host: Some(request.host),
            source: request.source,
        });
        if original
            .original
            .nodes
            .as_ref()
            .is_none_or(|nodes| nodes.len() != PARTICIPANTS)
            || original.original.activation.owners.len() != PARTICIPANTS + 1
            || !original.original.native.is_empty()
            || original.original.native.capacity() < PARTICIPANTS + 1
        {
            return Err(CnpSemanticExactWorldReservationFailure {
                error: refused(
                    "exact collecting world requires native-three and one genuine host owner",
                ),
                original,
            });
        }
        Ok(*original)
    }
}

impl CnpSemanticExactConformanceWorldProvider {
    /// Authenticates and transfers this same capsule through the exact-input constructor.
    ///
    /// # Errors
    /// Holds every original on foreign source, changed graph/native custody,
    /// missing host or exhausted pointer capacity. Runtime failure retains all transfers.
    ///
    /// # Panics
    /// Source callbacks may unwind; keep this capsule outside the unwind boundary.
    pub fn prepare_conformance_exact_inputs(
        &mut self,
        limits: RuntimeLimits,
        source: Rc<HostSchedulingSource>,
    ) -> Result<ConformanceRuntime, CnpSemanticWorldPreparationFailure> {
        if !Rc::ptr_eq(&source, &self.source) {
            return Err(CnpSemanticWorldPreparationFailure::Held(refused(
                "foreign original host source",
            )));
        }
        self.validate(limits)
            .map_err(CnpSemanticWorldPreparationFailure::Held)?;
        let graph = self.original.original_graph.as_ref().ok_or_else(|| {
            CnpSemanticWorldPreparationFailure::Held(refused("original exact graph absent"))
        })?;
        graph
            .authenticate_exact_input_scope(&self.source)
            .map_err(|error| CnpSemanticWorldPreparationFailure::Held(unknown(error)))?;
        let nodes = self.original.nodes.take().ok_or_else(|| {
            CnpSemanticWorldPreparationFailure::Held(refused("original exact peers transferred"))
        })?;
        let host = self.host.take().ok_or_else(|| {
            CnpSemanticWorldPreparationFailure::Held(refused("original exact host transferred"))
        })?;
        // Adopt the same concrete host and peers into the pre-reserved vector.
        // No source callback occurs between removal and adoption.
        self.original.native.push(Box::new(host));
        for node in nodes {
            self.original.native.push(Box::new(node.0));
        }
        let graph = self.original.original_graph.take().ok_or_else(|| {
            CnpSemanticWorldPreparationFailure::Held(refused("original exact graph absent"))
        })?;
        let slot = self.original.runtime_custody.take().ok_or_else(|| {
            CnpSemanticWorldPreparationFailure::Held(refused("original exact custody absent"))
        })?;
        let prepared = PreparedRealization::new(
            std::mem::take(&mut self.original.native),
            self.original.activation.clone(),
            limits,
            slot,
        );
        ConformanceRuntime::from_prepared_exact_inputs(graph, prepared, Rc::clone(&self.source))
            .map_err(CnpSemanticWorldPreparationFailure::Runtime)
    }

    /// Transfers all held original participants through their same native reservation.
    ///
    /// # Errors
    /// Keeps original custody on unavailable slot or unsupported native cleanup.
    ///
    /// # Panics
    /// Cleanup callbacks may unwind; keep this entire capsule outside the unwind boundary.
    pub fn retire_original(&mut self, limits: RuntimeLimits) -> Result<(), RuntimeError> {
        if self.original.retirement.is_none() && self.original.nodes.is_some() {
            let needed = self
                .original
                .native
                .len()
                .checked_add(self.original.nodes.as_ref().map_or(0, Vec::len))
                .and_then(|count| count.checked_add(usize::from(self.host.is_some())))
                .ok_or(RuntimeError::ResourceLimit)?;
            if self.original.runtime_custody.is_none()
                || self.original.native.capacity() < needed.max(PARTICIPANTS + 1)
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            if let Some(host) = self.host.take() {
                self.original.native.push(Box::new(host));
            }
        }
        self.original.retire_original(limits)
    }

    fn validate(&self, limits: RuntimeLimits) -> Result<(), OperationFailure> {
        self.source.authenticate_dispatch_source()?;
        let graph = self
            .original
            .original_graph
            .as_ref()
            .ok_or_else(|| refused("original exact graph absent"))?;
        let nodes = self
            .original
            .nodes
            .as_ref()
            .ok_or_else(|| refused("original exact peers transferred"))?;
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("original exact host transferred"))?;
        if limits.maximum_nodes < PARTICIPANTS + 1
            || limits.maximum_owners < PARTICIPANTS + 1
            || graph.graph.node_ids().count() != PARTICIPANTS + 1
            || graph.graph.world_binding_hash() != &self.original.activation.world_binding_hash
            || self.original.runtime_custody.is_none()
            || !self.original.native.is_empty()
            || self.original.native.capacity() < PARTICIPANTS + 1
        {
            return Err(refused("exact original graph/custody roster differs"));
        }
        host.authenticate_original_source(&self.source, &self.original.activation)?;
        host.validate_collection_scope(graph.plan())?;
        if graph.graph.descriptor(&host.descriptor().id) != Some(host.descriptor())
            || graph.graph.binding(&host.descriptor().id) != Some(host.binding())
            || graph.graph.owner(&self.source.selection().owner.owner.id)
                != Some(&self.source.selection().owner)
            || host.route().owners.len() != 1
        {
            return Err(refused("exact original host tuple differs"));
        }
        super::super::budget::serialized_size(
            &(
                self.original.activation.generation,
                &self.original.activation.activation_id,
                &self.original.activation.world_binding_hash,
                &self.original.activation.owners,
                self.original.activation.boundary,
            ),
            ACTIVATION_BYTES,
        )?;
        graph.reauthenticate().map_err(unknown)?;
        let mut participants = BTreeSet::new();
        let mut owners = BTreeSet::new();
        for node in nodes {
            let node = &node.0;
            node.current()?;
            let source = node.source()?;
            let installed = source.installation();
            if installed.world_binding_hash != self.original.activation.world_binding_hash
                || graph.graph.descriptor(&installed.descriptor.id) != Some(&installed.descriptor)
                || graph.graph.binding(&installed.descriptor.id) != Some(&installed.binding)
                || graph.graph.owner(&installed.owner.owner.id) != Some(&installed.owner)
                || !participants.insert(installed.descriptor.id.clone())
                || node.route.owners.len() != 1
                || !owners.insert(node.route.owners[0].clone())
                || node.state()?.arm_attempt.is_some()
                || node.state()?.activation_attempt.is_some()
                || !node.state()?.operations.is_empty()
                || !node.state()?.inputs.is_empty()
            {
                return Err(refused(
                    "combined original source, route or inactive state differs",
                ));
            }
            node.preparation
                .guard
                .custody()
                .map_err(unknown)?
                .conformance
                .as_ref()
                .ok_or_else(|| refused("combined peer lacks original fixture authority"))?
                .authenticate_graph(node.scope()?, graph)?;
        }

        if !participants.insert(host.descriptor().id.clone())
            || !owners.insert(host.route().owners[0].clone())
            || owners.len() != PARTICIPANTS + 1
            || self
                .original
                .activation
                .owners
                .iter()
                .any(|owner| !owners.contains(owner))
        {
            return Err(refused(
                "exact activation omits or duplicates an original owner",
            ));
        }
        self.source.authenticate_dispatch_source()?;
        graph.authenticate_current_scope().map_err(unknown)
    }
}
