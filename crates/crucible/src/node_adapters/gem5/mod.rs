//! Genuine native gem5 preparation beneath the common node admission boundary.
//!
//! Preparation retains the actual stopped native owner and its original graph
//! identity. A private pre-event boundary or process image cannot establish
//! public input closure, guest-output birth, same-time phases or world readiness.
//! Qualified conversion consumes a sealed independently audited live authority.
//! Closed exact execution and backend-bound native capture retain original
//! receipts. Fresh continuation requires independently authenticated original
//! journals and genuine fresh native authority; unavailable input remains refused.

use crucible_node_contract::{HashRef, Id, NodeBinding, NodeDescriptor};
use crucible_node_provider::gem5::{Gem5Boundary, Gem5NativeProcess};

use crate::{
    node_admission::AdmittedGraph,
    node_contract::{EffectKnowledge, NodeRoute, OperationFailure, OwnerIdentity, SimulationNode},
};

mod capture;
mod continuation;
mod execution;
mod ledger;
mod node;
mod observations;
mod positions;
mod preparation_mapping;
mod public_continuation;
mod reconciliation;
mod restore;
mod retirement;
mod supplementary;

pub use capture::{
    GEM5_NATIVE_CONTINUATION_SPECIFICATION, Gem5ArchiveInstallation, Gem5NativeContinuation,
    gem5_native_continuation_schema,
};
pub use continuation::{
    Gem5AuthenticatedContinuation, Gem5ContinuationRecord, authenticate_gem5_continuation,
    decode_gem5_continuation,
};
pub use node::{Gem5NodeResources, Gem5QualifiedNodeFailure, QualifiedGem5Node};
pub use preparation_mapping::{
    GEM5_PUBLIC_PREPARATION_SPECIFICATION, Gem5PublicPreparationFailure,
    gem5_public_preparation_schema,
};
pub use public_continuation::{
    GEM5_PUBLIC_CONTINUATION_SPECIFICATION, GEM5_PUBLIC_EPOCH_CONTINUATION_PROFILE,
    gem5_public_continuation_schema, gem5_public_epoch_continuation_schema,
};

/// Names the installed no-ingress O3/stdout full-position execution profile.
///
/// The identity alone grants no capability. Promotion requires actual native
/// profile qualification, original whole-process custody, and clock mediation.
pub const GEM5_CLOSED_EXACT_PROFILE: &str = "gem5/freestanding-o3-exact-v1";

/// Names the installed complete opaque native process preservation profile.
///
/// Partial typed state diagnostics do not qualify this profile. Its authority
/// comes from independently authenticated native image and resource closure.
pub const GEM5_OPAQUE_PRESERVATION_PROFILE: &str = "gem5/opaque-process-preservation-v1";

/// Authenticates the actual prepared native process against installed host facts.
///
/// Implementations must inspect live custody and the complete source/model/device
/// configuration selected by the admitted graph. Portable hashes, guest ISA or a
/// diagnostic observer's `complete` field are insufficient. This preparation
/// check does not authorize native execution or issue a readiness attestation.
pub trait Gem5PreparationQualification {
    /// Authenticates original native lineage and its exact admitted installation.
    ///
    /// # Errors
    /// Rejects foreign peers, unavailable installed source/ABI qualification,
    /// changed models or resources, and missing whole-owner custody.
    fn authenticate_preparation(
        &self,
        native: &Gem5NativeProcess,
        graph: &AdmittedGraph,
        node: &Id,
    ) -> Result<(), OperationFailure>;
}

/// Preserves native custody when preparation or runtime qualification is refused.
pub struct Gem5PreparationFailure {
    /// Explains the no-effect refusal without claiming native reclamation.
    pub error: OperationFailure,
    /// Retains the actual native process under its already allocated supervisor.
    pub native: Gem5NativeProcess,
}

/// Retains a genuinely prepared gem5 owner without granting modeled execution.
///
/// The value exposes no run, input, ACK or capture path. Dropping it transfers
/// actual handles and pending native obligations through the process's mandatory
/// supervisor; it does not claim the owner has been reaped.
pub struct Gem5NodePreparation {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    route: NodeRoute,
    world_binding_hash: HashRef,
    native: Gem5NativeProcess,
}

impl Gem5NodePreparation {
    /// Takes custody of a real native owner matched to the original admitted graph.
    ///
    /// Every modeled implementation artifact is checked against the immutable
    /// native launch, and installed host authentication remains mandatory. The
    /// native boundary is retained verbatim; public positions are not converted
    /// into private grants or inferred from a diagnostic event ordinal.
    ///
    /// # Errors
    /// Returns both the refusal and actual native resources for missing graph
    /// identities, mismatched artifacts/owners, or failed installed authentication.
    pub fn from_prepared(
        graph: &AdmittedGraph,
        node: &Id,
        native: Gem5NativeProcess,
        qualification: &dyn Gem5PreparationQualification,
    ) -> Result<Self, Box<Gem5PreparationFailure>> {
        let validate = || -> Result<(NodeDescriptor, NodeBinding, NodeRoute), OperationFailure> {
            let descriptor = graph
                .descriptor(node)
                .ok_or_else(|| refusal("gem5 node absent from admitted graph"))?;
            let binding = graph
                .binding(node)
                .ok_or_else(|| refusal("gem5 binding absent from admitted graph"))?;
            let launch = native.launch();
            let compatibility = &binding.compatibility;
            if compatibility.implementation.implementation_id.as_str() != "gem5/native-process-v1"
                || compatibility.execution_owner != compatibility.capture_owner
                || launch.owner != compatibility.execution_owner.id
                || launch.incarnation != binding.authority.incarnation_id
                || launch.generation != binding.authority.owner_generation
                || graph.owner(&launch.owner).is_none()
                || !compatibility.execution_owner.participant_ids.contains(node)
            {
                return Err(refusal(
                    "gem5 prepared native owner or implementation differs",
                ));
            }
            for (id, role, content) in [
                ("gem5", "emulator", &launch.executable.content),
                ("guest", "guest-image", &launch.guest.content),
                ("model", "model-definition", &launch.model_script.content),
                ("owner", "native-controller", &launch.owner_script.content),
            ] {
                if !compatibility
                    .implementation
                    .artifacts
                    .iter()
                    .any(|artifact| {
                        artifact.id.as_str() == id
                            && artifact.role.as_str() == role
                            && &artifact.content == content
                            && artifact.extensions.is_empty()
                    })
                {
                    return Err(refusal(
                        "gem5 native modeled artifact differs from admitted implementation",
                    ));
                }
            }
            if let Some(images) = &launch.process_images {
                for (id, content) in [
                    ("image-launcher", &images.launcher.content),
                    ("image-restarter", &images.restarter.content),
                    ("image-runtime", &images.reconstruction_executable.content),
                    ("resource-helper", &images.resource_helper.content),
                ] {
                    if !compatibility
                        .implementation
                        .artifacts
                        .iter()
                        .any(|artifact| {
                            artifact.id.as_str() == id
                                && artifact.role.as_str() == id
                                && &artifact.content == content
                                && artifact.extensions.is_empty()
                        })
                    {
                        return Err(refusal(
                            "gem5 native image tool differs from admitted implementation",
                        ));
                    }
                }
            } else if compatibility
                .implementation
                .artifacts
                .iter()
                .any(|artifact| {
                    matches!(
                        artifact.id.as_str(),
                        "image-launcher" | "image-restarter" | "image-runtime" | "resource-helper"
                    )
                })
            {
                return Err(refusal(
                    "admitted gem5 image tools are absent from actual native resources",
                ));
            }
            qualification.authenticate_preparation(&native, graph, node)?;
            let route = NodeRoute {
                node: node.clone(),
                owners: vec![OwnerIdentity {
                    owner: launch.owner.clone(),
                    incarnation: launch.incarnation.clone(),
                    generation: launch.generation,
                }],
            };
            Ok((descriptor.clone(), binding.clone(), route))
        };

        match validate() {
            Ok((descriptor, binding, route)) => Ok(Self {
                descriptor,
                binding,
                route,
                world_binding_hash: graph.world_binding_hash().clone(),
                native,
            }),
            Err(error) => Err(Box::new(Gem5PreparationFailure { error, native })),
        }
    }

    /// Returns the original admitted descriptor without native mutation.
    pub fn descriptor(&self) -> &NodeDescriptor {
        &self.descriptor
    }

    /// Returns the original compatibility and authenticated live binding.
    pub fn binding(&self) -> &NodeBinding {
        &self.binding
    }

    /// Returns the complete native owner route used by this public alias.
    pub fn route(&self) -> &NodeRoute {
        &self.route
    }

    /// Returns the original whole-world compatibility commitment.
    pub fn world_binding_hash(&self) -> &HashRef {
        &self.world_binding_hash
    }

    /// Returns the retained private event boundary without asserting public readiness.
    pub fn native_boundary(&self) -> &Gem5Boundary {
        self.native.boundary()
    }

    /// Refuses runtime promotion while preserving the actual preparation.
    ///
    /// Public exact activation requires genuine input-epoch and same-time phase
    /// mediation, native guest-write birth/publication custody, and coordinated
    /// all-owner continuation. Neither a stopped scalar tick nor an opaque image
    /// independently satisfies those contracts. No common runtime node is minted
    /// until the installed native mapper supplies that complete evidence.
    ///
    /// # Errors
    /// Always returns an ownership-preserving unqualified-runtime refusal.
    pub fn into_simulation_node(self) -> Result<Box<dyn SimulationNode>, Box<Gem5RuntimeRefusal>> {
        Err(Box::new(Gem5RuntimeRefusal {
            error: refusal("gem5 public phase/input/publication/world contract is not qualified"),
            preparation: self,
        }))
    }

    /// Installs a sealed native exact authority without widening its closed profile.
    ///
    /// The authority must name this actual live incarnation. The sealed graph
    /// must select the implemented exact facet and original stdout octet schema.
    /// Input and preservation support require separately installed bridges.
    ///
    /// # Errors
    /// Returns the original native preparation and authority when graph policy,
    /// finite custody limits or actual live native qualification differ.
    pub fn into_qualified_simulation_node(
        self,
        graph: &AdmittedGraph,
        authority: crucible_node_provider::gem5::Gem5ExactAuthority,
        resources: Gem5NodeResources,
    ) -> Result<QualifiedGem5Node, Box<Gem5QualifiedNodeFailure>> {
        QualifiedGem5Node::from_qualified(self, graph, authority, resources, None, None)
    }

    /// Installs independently qualified complete native capture alongside exact execution.
    ///
    /// This edition exposes unchanged-cut capture only. Fresh common runtime
    /// continuation, durable restart and branch isolation remain separately
    /// gated until the installed native archive restoration bridge supports them.
    ///
    /// # Errors
    /// Retains actual preparation and live authority on unsupported graph claims,
    /// stale native qualification, incomplete archive installation or invalid limits.
    pub fn into_qualified_capturing_simulation_node(
        self,
        graph: &AdmittedGraph,
        authority: crucible_node_provider::gem5::Gem5ExactAuthority,
        resources: Gem5NodeResources,
        archive: Gem5ArchiveInstallation,
    ) -> Result<QualifiedGem5Node, Box<Gem5QualifiedNodeFailure>> {
        QualifiedGem5Node::from_qualified(self, graph, authority, resources, Some(archive), None)
    }

    /// Reattaches an authenticated unchanged source to a genuinely qualified fresh peer.
    ///
    /// The installed capsule must first restore the historical image without
    /// execution and qualify this actual fresh peer independently. Original
    /// common permissions are installed only by the runtime's opaque restore hook.
    ///
    /// # Errors
    /// Retains actual native custody when fresh identity, complete original
    /// ledger, signed source, installed profile or admitted model differs.
    pub fn into_qualified_restored_simulation_node(
        self,
        graph: &AdmittedGraph,
        authority: crucible_node_provider::gem5::Gem5ExactAuthority,
        resources: Gem5NodeResources,
        archive: Gem5ArchiveInstallation,
        restored: Gem5AuthenticatedContinuation,
    ) -> Result<QualifiedGem5Node, Box<Gem5QualifiedNodeFailure>> {
        QualifiedGem5Node::from_qualified(
            self,
            graph,
            authority,
            resources,
            Some(archive),
            Some(restored),
        )
    }
}

/// Retains the exact original preparation after unsupported runtime promotion.
pub struct Gem5RuntimeRefusal {
    /// Describes the no-effect qualification refusal.
    pub error: OperationFailure,
    /// Keeps actual native handles and their original admitted graph binding.
    pub preparation: Gem5NodePreparation,
}

fn refusal(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.to_owned(),
    }
}
