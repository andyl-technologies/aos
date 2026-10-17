//! Keeps three original collecting peers beneath one common world activation.
//!
//! Reservation is callback-free and grants no readiness or execution authority.
//! Preparation reauthenticates every original node and the full installed world,
//! then transfers all three into the SAME preowned runtime custody slot. The
//! legacy singleton provider and every ordinary provider path remain separate.

use std::collections::BTreeSet;

use crate::{
    node_admission::ConformanceGraph,
    node_contract::{
        ActivationRecord, ConformanceRuntime, ConformanceRuntimeFailure, OperationFailure,
        PreparedRealization, RuntimeCustodySlot, RuntimeError, RuntimeLimits, SimulationNode,
    },
};

use super::{CnpSemanticConformanceNode, refused, unknown};

mod exact_inputs;
mod restoration_inputs;

pub use exact_inputs::{
    CnpSemanticExactConformanceWorldProvider, CnpSemanticExactWorldReservation,
    CnpSemanticExactWorldReservationFailure,
};

const PARTICIPANTS: usize = 3;
const ACTIVATION_BYTES: usize = 65_536;

/// Retains all original inactive nodes when callback-free reservation refuses.
pub struct CnpSemanticWorldReservationFailure {
    /// Describes an invalid finite roster or activation proposal.
    pub error: OperationFailure,
    /// Keeps every original participant, full graph and the same runtime slot.
    pub original: Box<CnpSemanticConformanceWorldProvider>,
}

/// Distinguishes an original held provider from a transferred runtime failure.
pub enum CnpSemanticWorldPreparationFailure {
    /// Leaves every original node in the same provider for honest containment.
    Held(OperationFailure),
    /// Retains every transferred native node under the same runtime reservation.
    Runtime(ConformanceRuntimeFailure),
}

/// Reserves a distinct three-peer collecting world without ordinary qualification.
///
/// The caller keeps this complete capsule outside callback unwind. No public
/// node, graph or runtime getter is provided. Reservation alone cannot establish
/// that the three sources or their whole-world coordinator are authenticated.
#[must_use = "keep the original whole-world capsule until transfer or containment"]
pub struct CnpSemanticConformanceWorldProvider {
    nodes: Option<Vec<CnpSemanticConformanceNode>>,
    native: Vec<Box<dyn SimulationNode>>,
    retirement: Option<PreparedRealization>,
    activation: ActivationRecord,
    original_graph: Option<ConformanceGraph>,
    runtime_custody: Option<Box<dyn RuntimeCustodySlot>>,
}

impl CnpSemanticConformanceWorldProvider {
    /// Retains exactly three original nodes before invoking any source callback.
    ///
    /// # Errors
    /// Returns the complete original nodes and activation for a different finite
    /// roster or missing pre-Child native pointer capacity. The supplied empty
    /// native Vec must already reserve three pointers. Full source, ownership
    /// and world authentication occurs separately.
    pub fn reserve(
        nodes: Vec<CnpSemanticConformanceNode>,
        native: Vec<Box<dyn SimulationNode>>,
        activation: ActivationRecord,
        graph: ConformanceGraph,
        runtime_custody: Box<dyn RuntimeCustodySlot>,
    ) -> Result<Self, CnpSemanticWorldReservationFailure> {
        let original = Box::new(Self {
            nodes: Some(nodes),
            native,
            retirement: None,
            activation,
            original_graph: Some(graph),
            runtime_custody: Some(runtime_custody),
        });
        if original
            .nodes
            .as_ref()
            .is_none_or(|nodes| nodes.len() != PARTICIPANTS)
            || original.activation.owners.len() != PARTICIPANTS
            || !original.native.is_empty()
            || original.native.capacity() < PARTICIPANTS
        {
            return Err(CnpSemanticWorldReservationFailure {
                error: refused("combined collecting world requires three original participants"),
                original,
            });
        }
        Ok(*original)
    }

    /// Authenticates and transfers the complete roster into one collecting runtime.
    ///
    /// Every source authenticates the SAME opaque graph and retained original
    /// plan. All peers must remain inactive; their distinct owner routes must
    /// equal the complete original activation roster. The common runtime then
    /// performs its unchanged structural and all-owner preparation checks.
    ///
    /// # Errors
    /// Leaves original nodes in this provider on failed current/source/graph
    /// checks, missing or duplicate owners, changed bindings or exhausted credit.
    /// A runtime construction failure retains the transferred whole world.
    ///
    /// # Panics
    /// Installed source callbacks may unwind. The caller must keep this provider
    /// outside the unwind boundary, and keep the original runtime reservation
    /// under its independent supervisor. Allocator failure is outside this finite
    /// callback contract; no reclamation is inferred from transport destruction.
    pub fn prepare_conformance(
        &mut self,
        limits: RuntimeLimits,
    ) -> Result<ConformanceRuntime, CnpSemanticWorldPreparationFailure> {
        // Reservation placed complete upper metadata and the original runtime
        // slot in this holder before any source callback. Refusal/unwind keeps
        // those SAME objects, with no replacement graph or reservation.
        let graph = self.original_graph.as_ref().ok_or_else(|| {
            CnpSemanticWorldPreparationFailure::Held(refused("original graph absent"))
        })?;
        self.validate(graph, limits)
            .map_err(CnpSemanticWorldPreparationFailure::Held)?;
        if self.original_graph.is_none() || self.runtime_custody.is_none() {
            return Err(CnpSemanticWorldPreparationFailure::Held(refused(
                "combined original graph or custody slot absent",
            )));
        }
        let Some(nodes) = self.nodes.take() else {
            return Err(CnpSemanticWorldPreparationFailure::Held(refused(
                "combined original nodes were already transferred",
            )));
        };
        // This exact pointer Vec was reserved by the upper caller before Child.
        // Adopt each participant before the next iteration. Box allocator
        // exhaustion retains the separately stated Rust process-level limit;
        // no arbitrary callback runs between removal and adoption.
        for node in nodes {
            self.native.push(Box::new(node.0));
        }
        let native = std::mem::take(&mut self.native);
        let graph = self.original_graph.take().ok_or_else(|| {
            CnpSemanticWorldPreparationFailure::Held(refused("original graph absent"))
        })?;
        let custody_slot = self.runtime_custody.take().ok_or_else(|| {
            CnpSemanticWorldPreparationFailure::Held(refused("original custody slot absent"))
        })?;
        let prepared =
            PreparedRealization::new(native, self.activation.clone(), limits, custody_slot);
        ConformanceRuntime::from_prepared(graph, prepared)
            .map_err(CnpSemanticWorldPreparationFailure::Runtime)
    }

    /// Transfers retained inactive participants while keeping the original provider.
    ///
    /// Cleanup is independent of current collection permission. The same prepared
    /// capsule enters its original supervisor before any cleanup callback; all
    /// upper graph and activation metadata remain held in this provider.
    ///
    /// # Errors
    /// Refuses a missing original slot or unresolved borrowed cleanup obligation.
    ///
    /// # Panics
    /// Installed cleanup callbacks may unwind. Keep this provider outside the
    /// unwind boundary; its prepared retirement capsule remains owned here.
    pub fn retire_original(&mut self, limits: RuntimeLimits) -> Result<(), RuntimeError> {
        if self.retirement.is_none() && self.nodes.is_some() {
            if self.runtime_custody.is_none() || self.native.capacity() < PARTICIPANTS {
                return Err(RuntimeError::ForeignAuthority);
            }
            if let Some(nodes) = self.nodes.take() {
                for node in nodes {
                    self.native.push(Box::new(node.0));
                }
            }
            let slot = self
                .runtime_custody
                .take()
                .ok_or(RuntimeError::ForeignAuthority)?;
            self.retirement = Some(PreparedRealization::new(
                std::mem::take(&mut self.native),
                self.activation.clone(),
                limits,
                slot,
            ));
        }
        if let Some(original) = self.retirement.as_mut() {
            original.retire_original()?;
        }
        Ok(())
    }

    fn validate(
        &self,
        graph: &ConformanceGraph,
        limits: RuntimeLimits,
    ) -> Result<(), OperationFailure> {
        let nodes = self
            .nodes
            .as_ref()
            .ok_or_else(|| refused("combined original nodes were already transferred"))?;
        if limits.maximum_nodes < PARTICIPANTS
            || limits.maximum_owners < PARTICIPANTS
            || graph.graph.node_ids().count() != PARTICIPANTS
            || graph.graph.world_binding_hash() != &self.activation.world_binding_hash
        {
            return Err(refused("combined graph or runtime roster differs"));
        }
        super::budget::serialized_size(
            &(
                self.activation.generation,
                &self.activation.activation_id,
                &self.activation.world_binding_hash,
                &self.activation.owners,
                self.activation.boundary,
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
            if installed.world_binding_hash != self.activation.world_binding_hash
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
        if owners.len() != PARTICIPANTS
            || self
                .activation
                .owners
                .iter()
                .any(|owner| !owners.contains(owner))
        {
            return Err(refused(
                "combined activation omits or duplicates an original owner",
            ));
        }
        // This direct installed read follows the last source callback; selected
        // authority must cover all three original live native-owner revisions.
        graph.authenticate_current_scope().map_err(unknown)
    }
}
