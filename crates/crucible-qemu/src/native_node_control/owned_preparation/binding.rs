//! Matches a complete admitted binding before any QEMU initial allocation.

// SPDX-License-Identifier: Apache-2.0

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{ActivationRecord, NodeRoute, OperationFailure, OwnerIdentity},
};
use crucible_node_contract::{HashRef, Id, NodeBinding, NodeDescriptor};
use crucible_protocol::node_control::NativePrefixPreparation;

/// Supplies the factory's installation check before initial custody allocation.
///
/// The implementation belongs to the installed factory and checks the full
/// emulator/plugin/source/ABI/guest/policy closure selected by the graph. This
/// checks installation only; it cannot certify live native root closure or mint
/// common readiness from portable facts or a diagnostic executable identity.
/// Implementing this open trait provides no source authority: this adapter owns
/// inactive custody only, and readiness still requires the genuine native issuer.
pub trait QemuInitialInstallationQualification {
    /// Checks the exact installed tuple and every admitted constructor identity.
    ///
    /// # Errors
    /// Refuses substituted artifacts, unsupported policy or unavailable actual
    /// installation evidence before a native child or file is allocated.
    fn authenticate_installation(
        &self,
        graph: &AdmittedGraph,
        node: &Id,
        preparation: &NativePrefixPreparation,
    ) -> Result<(), OperationFailure>;
}

pub(super) struct Binding {
    pub(super) descriptor: NodeDescriptor,
    pub(super) node: NodeBinding,
    pub(super) route: NodeRoute,
    pub(super) world: HashRef,
    pub(super) preparation: NativePrefixPreparation,
}

pub(super) fn validate(
    graph: &AdmittedGraph,
    node: &Id,
    activation: &ActivationRecord,
    preparation: &NativePrefixPreparation,
    installation: &dyn QemuInitialInstallationQualification,
) -> Result<Binding, OperationFailure> {
    preparation
        .validate()
        .map_err(|error| super::refusal(error.to_string()))?;
    let descriptor = graph
        .descriptor(node)
        .ok_or_else(|| super::refusal("QEMU descriptor is absent"))?;
    let binding = graph
        .binding(node)
        .ok_or_else(|| super::refusal("QEMU binding is absent"))?;
    let original = &preparation
        .original_effect
        .original_root
        .administration
        .phase
        .initialization;
    let scope = &original.preparation.scope;
    let owner = graph
        .owner(&scope.owner)
        .ok_or_else(|| super::refusal("QEMU owner is absent"))?;
    let owner_identity = OwnerIdentity {
        owner: scope.owner.clone(),
        incarnation: scope.incarnation.clone(),
        generation: scope.owner_generation,
    };
    let binding_identity = binding
        .identity()
        .map_err(|error| super::refusal(error.to_string()))?;
    let owner_binding = owner
        .identity()
        .map_err(|error| super::refusal(error.to_string()))?;
    let compatibility = &binding.compatibility;
    // Common initial bindings are uncommitted (None/0). The native constructor
    // separately pins the proposed activation, which remains unpublished here.

    if compatibility.implementation.implementation_id.as_str() != super::QEMU_PREFIX_IMPLEMENTATION
        || compatibility.execution_owner != compatibility.capture_owner
        || compatibility.execution_owner != owner.owner
        || compatibility.execution_owner.participant_ids.as_slice() != std::slice::from_ref(node)
        || owner.node_bindings.len() != 1
        || owner.node_bindings[0].node_id != *node
        || owner.node_bindings[0].binding_hash != binding_identity
        || scope.node != *node
        || scope.owner_binding != owner_binding
        || scope.session != binding.authority.session_id
        || scope.incarnation != binding.authority.incarnation_id
        || scope.owner_generation != binding.authority.owner_generation
        || binding.authority.world_generation.get() != 0
        || binding.authority.activation_id.is_some()
        || scope.activation != activation.activation_id
        || scope.world_generation != activation.generation
        || scope.world_binding != *graph.world_binding_hash()
        || activation.world_binding_hash != *graph.world_binding_hash()
        || !activation.owners.contains(&owner_identity)
        || original.preparation.boundary != activation.boundary
        || activation.boundary.time_ps.get() != 0
        || activation.boundary.microstep.get() != 0
        || activation.boundary.phase != crucible_node_contract::Phase::BoundaryControl
    {
        return Err(super::refusal(
            "QEMU complete initial owner, binding or world differs",
        ));
    }
    installation.authenticate_installation(graph, node, preparation)?;
    Ok(Binding {
        descriptor: descriptor.clone(),
        node: binding.clone(),
        route: NodeRoute {
            node: node.clone(),
            owners: vec![owner_identity],
        },
        world: graph.world_binding_hash().clone(),
        preparation: preparation.clone(),
    })
}
