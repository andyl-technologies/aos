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

impl CnpSemanticExactConformanceWorldProvider {
    /// Observes held inactive original provider owners without callbacks or transfer.
    ///
    /// # Errors
    /// Refuses entered retirement, unknown native backing or checked excess.
    pub fn original_retained_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.retained_storage_selected_precredit_data(maximum, None)
    }

    fn retained_storage_selected_precredit_data(
        &self,
        maximum: usize,
        initial_sources: Option<&[Rc<crate::node_adapters::cnp::PacketCompleteSemanticSource>; 3]>,
    ) -> Result<usize, RuntimeError> {
        use crate::node_adapters::cnp::CnpSemanticSource;
        use crate::node_contract::{NodeRuntime, RuntimeOwnedStorage};
        if self.original.retirement.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(self.original.activation.owned_storage()?)
            .ok_or(RuntimeError::ResourceLimit)?;
        if let Some(graph) = &self.original.original_graph {
            bytes = bytes
                .checked_add(graph.original_retained_storage_precredit_data(maximum)?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        let scratch = crate::node_adapters::cnp::CnpPreparationStorageScratch::new(
            crate::node_adapters::cnp::CnpPreparationStorageScratch::requested_bytes(),
        )?;
        if let Some(nodes) = &self.original.nodes {
            bytes = bytes
                .checked_add(
                    nodes
                        .capacity()
                        .checked_mul(std::mem::size_of::<CnpSemanticConformanceNode>())
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
            for node in nodes {
                let requested = match initial_sources {
                    Some(sources) => {
                        let source = sources
                            .iter()
                            .find(|source| {
                                source.installation().descriptor.id
                                    == node.original_conformance_route_data().node
                            })
                            .ok_or(RuntimeError::ForeignAuthority)?;
                        node.retained_original_initial_requested_storage_precredit_data(
                            source, &scratch, maximum,
                        )?
                        .complete_requested_bytes_precredit_data()?
                    }
                    None => node
                        .retained_requested_storage_precredit_data(&scratch, None, None, maximum)?
                        .complete_requested_bytes_precredit_data()?,
                };
                bytes = bytes
                    .checked_add(requested)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        if let Some(host) = &self.host {
            bytes = bytes
                .checked_add(std::mem::size_of_val(host))
                .and_then(|n| {
                    n.checked_add(
                        host.retained_requested_storage_precredit_data(maximum)
                            .ok()??,
                    )
                })
                .ok_or(RuntimeError::UnsupportedFacet)?;
        }
        bytes = bytes
            .checked_add(
                self.original
                    .native
                    .capacity()
                    .checked_mul(std::mem::size_of::<Box<dyn SimulationNode>>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        for node in &self.original.native {
            bytes = bytes
                .checked_add(std::mem::size_of_val(node.as_ref()))
                .and_then(|n| {
                    n.checked_add(
                        node.retained_requested_storage_precredit_data(maximum)
                            .ok()??,
                    )
                })
                .ok_or(RuntimeError::UnsupportedFacet)?;
        }
        if let Some(slot) = &self.original.runtime_custody {
            bytes = bytes
                .checked_add(std::mem::size_of_val(slot.as_ref()))
                .and_then(|n| n.checked_add(slot.retained_requested_storage_data(maximum).ok()??))
                .ok_or(RuntimeError::UnsupportedFacet)?;
        }
        bytes = bytes
            .checked_add(NodeRuntime::capture_shared_allocation_storage::<
                HostSchedulingSource,
            >())
            .and_then(|n| {
                n.checked_add(
                    self.source
                        .retained_original_metadata_bytes_excluding_runtime_precredit_data(maximum)
                        .ok()?,
                )
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
}

impl CnpSemanticExactConformanceWorldProvider {
    /// Observes actual retained descriptor views before the exact runtime transfer.
    ///
    /// # Errors
    /// Refuses entered retirement, unknown concrete nodes/slot or checked excess.
    pub fn original_retained_descriptor_views_precredit_data(&self) -> Result<usize, RuntimeError> {
        if self.original.retirement.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut total = 0usize;
        if let Some(nodes) = &self.original.nodes {
            for node in nodes {
                total = total
                    .checked_add(node.retained_descriptor_views_precredit_data()?)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        for node in &self.original.native {
            total = total
                .checked_add(
                    node.retained_descriptor_views_precredit_data()?
                        .ok_or(RuntimeError::UnsupportedFacet)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(slot) = &self.original.runtime_custody {
            total = total
                .checked_add(
                    slot.retained_descriptor_views_precredit_data()?
                        .ok_or(RuntimeError::UnsupportedFacet)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(total)
    }
}

impl CnpSemanticExactConformanceWorldProvider {
    /// Counts fixed views for the exact-input provider quote and construction.
    ///
    /// The installed action admits this static row before invoking the quote,
    /// including its borrowed saved-activation serializer view. The returned
    /// prospective construction row includes these headers independently.
    /// Compiler frames, nested serializer work and existing owners stay separate.
    ///
    /// # Errors
    /// Refuses checked header-layout addition overflow.
    pub fn original_construction_counter_scratch_data() -> Result<usize, RuntimeError> {
        use std::mem::size_of;

        [
            size_of::<crate::node_contract::RetirementActivation<'static>>(),
            size_of::<CnpSemanticExactWorldReservation>(),
            size_of::<Self>(),
            size_of::<PreparedRealization>(),
            size_of::<CnpSemanticWorldPreparationFailure>(),
            size_of::<CnpSemanticExactWorldReservationFailure>(),
            size_of::<BTreeSet<crucible_node_format::Id>>(),
            size_of::<BTreeSet<crate::node_contract::OwnerIdentity>>(),
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Quotes additional exact-input provider construction and transfer owners.
    ///
    /// Existing graph/node/slot backing and runtime maps are independently
    /// counted. This row names the new pointer banks, concrete node Boxes,
    /// graph Rc, activation copies and provider validation collections.
    ///
    /// # Errors
    /// Refuses a non-four-owner proposal, overflow or the requested ceiling.
    pub fn original_construction_storage_data(
        graph: &ConformanceGraph,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        use crate::node_contract::{NodeRuntime, RuntimeOwnedStorage};
        use std::mem::{align_of, size_of};
        if activation.owners.len() != 4 {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let add = |a: usize, b: usize| {
            a.checked_add(b)
                .filter(|n| *n <= maximum)
                .ok_or(RuntimeError::ResourceLimit)
        };
        let mut retained = size_of::<Self>(); // Box retained on reservation failure.
        for bytes in [
            3 * size_of::<CnpSemanticConformanceNode>(),
            4 * size_of::<Box<dyn SimulationNode>>(),
            3 * size_of::<super::super::CnpSemanticNode>(),
            size_of::<PreparedHostSchedulingNode>(),
            NodeRuntime::capture_shared_allocation_storage::<ConformanceGraph>(),
            size_of::<crate::node_contract::NodeRuntime>(),
        ] {
            retained = add(retained, bytes)?;
        }
        // Provider, PreparedRealization and RuntimePreparationFailure may each
        // retain an independent proposal clone across a failed transfer.
        for _ in 0..3 {
            retained = add(retained, activation.owned_storage()?)?;
        }
        let mut transient = NodeRuntime::capture_serialization_storage(
            &crate::node_contract::RetirementActivation::from(activation),
            maximum,
        )?;
        transient = add(
            transient,
            NodeRuntime::capture_protocol_tree_storage(
                1,
                4,
                size_of::<crucible_node_format::Id>(),
                align_of::<crucible_node_format::Id>(),
                maximum,
            )?,
        )?;
        transient = add(
            transient,
            NodeRuntime::capture_protocol_tree_storage(
                1,
                4,
                size_of::<crate::node_contract::OwnerIdentity>(),
                align_of::<crate::node_contract::OwnerIdentity>(),
                maximum,
            )?,
        )?;
        for owner in &activation.owners {
            transient = add(transient, owner.owned_storage()?)?;
        }
        for node in graph.graph.node_ids() {
            transient = add(transient, node.owned_storage()?)?;
        }
        let scratch = add(0, Self::original_construction_counter_scratch_data()?)?;
        Ok((retained, transient, scratch))
    }
}

#[path = "exact_inputs/initial_preparation.rs"]
mod initial_preparation;
