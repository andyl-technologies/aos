//! Retains a genuine source-installed x86 root owner beneath graph admission.
//!
//! The preparation owns the stopped native process and its independently
//! measured model closure. It cannot run callbacks, expose public readiness or
//! treat a reconstructed session as an original preparation. Those operations
//! require the separate current opaque native authority and common mapping.

use crucible_node_format::{HashRef, Id, NodeBinding, NodeDescriptor};
use crucible_node_transport::gem5::X86RootNativeProcess;

use crate::{
    node_admission::AdmittedGraph,
    node_contract::{NodeRoute, OperationFailure, OwnerIdentity},
};

use super::refusal;

/// Authenticates an actual x86 root process against installed common-node policy.
///
/// The implementation belongs to an installed factory. It must authenticate the
/// complete source-owned model, asset/configuration closure and actual retained
/// native custody. Portable profile identities and diagnostic completeness
/// fields do not create this qualification or a current execution authority.
pub trait X86RootPreparationQualification {
    /// Authenticates the retained native owner and its exact admitted identity.
    ///
    /// # Errors
    /// Refuses foreign installed assets, unsupported common-node policy,
    /// changed owner bindings or unavailable actual native custody.
    fn authenticate_preparation(
        &self,
        native: &X86RootNativeProcess,
        graph: &AdmittedGraph,
        node: &Id,
    ) -> Result<(), OperationFailure>;
}

/// Retains the original process when common x86 preparation is refused.
pub struct X86RootPreparationFailure {
    /// Describes the local no-effect conversion refusal.
    pub error: OperationFailure,
    /// Owns the actual child, control history and already reserved supervisor.
    pub native: X86RootNativeProcess,
}

/// Owns one authentic parked x86 root process without granting common execution.
///
/// Dropping this preparation transfers the complete original native/control
/// custody to its preallocated supervisor. It never certifies reclamation or
/// acknowledges held Serial output.
pub struct X86RootNodePreparation {
    pub(super) descriptor: NodeDescriptor,
    pub(super) binding: NodeBinding,
    pub(super) route: NodeRoute,
    pub(super) world_binding_hash: HashRef,
    pub(super) native: X86RootNativeProcess,
}

impl X86RootNodePreparation {
    /// Takes custody of an actual native owner matched to its admitted graph.
    ///
    /// Every selected launch role is matched by full content identity. The x86
    /// model and Serial dialect remain distinct from SE guest/stdout fields.
    /// The installed qualification still authenticates the native installation.
    ///
    /// # Errors
    /// Returns the refusal and complete original process for missing graph
    /// entries, substituted model/asset/owner identities or failed qualification.
    pub fn from_prepared(
        graph: &AdmittedGraph,
        node: &Id,
        native: X86RootNativeProcess,
        qualification: &dyn X86RootPreparationQualification,
    ) -> Result<Self, Box<X86RootPreparationFailure>> {
        let validate = || -> Result<(NodeDescriptor, NodeBinding, NodeRoute), OperationFailure> {
            let descriptor = graph
                .descriptor(node)
                .ok_or_else(|| refusal("x86 root descriptor is absent from the admitted graph"))?;
            let binding = graph
                .binding(node)
                .ok_or_else(|| refusal("x86 root binding is absent from the admitted graph"))?;
            let launch = native
                .launch()
                .map_err(|error| refusal(&error.to_string()))?;
            let compatibility = &binding.compatibility;
            if compatibility.implementation.implementation_id.as_str()
                != super::X86_ROOT_IMPLEMENTATION
                || compatibility.execution_owner != compatibility.capture_owner
                || compatibility.execution_owner.participant_ids.as_slice()
                    != std::slice::from_ref(node)
                || launch.owner() != &compatibility.execution_owner.id
                || launch.incarnation() != &binding.authority.incarnation_id
                || launch.generation() != binding.authority.owner_generation
                || graph.owner(launch.owner()).is_none()
                || launch.model_id() != super::X86_ROOT_MODEL
                || launch.native_dialect() != super::X86_ROOT_DIALECT
            {
                return Err(refusal(
                    "x86 root native model, indivisible owner or incarnation differs",
                ));
            }

            // The provider's installed constructor retains all seventeen roles.
            // The common graph binds that complete roster, not a guest-shaped
            // subset that would omit board configuration or native audit code.
            let bindings = launch.bindings();
            if bindings.len() != 17 || compatibility.implementation.artifacts.len() != 18 {
                return Err(refusal("x86 root installed launch role roster differs"));
            }
            for (role, content) in bindings {
                let id = format!("x86-root/{role}");
                let matches = compatibility
                    .implementation
                    .artifacts
                    .iter()
                    .filter(|artifact| {
                        artifact.id.as_str() == id
                            && artifact.role.as_str() == role
                            && &artifact.content == content
                            && artifact.extensions.is_empty()
                    })
                    .count();
                if matches != 1 {
                    return Err(refusal(
                        "x86 root modeled artifact is missing, duplicated or substituted",
                    ));
                }
            }
            let profile_matches = compatibility
                .implementation
                .artifacts
                .iter()
                .filter(|artifact| {
                    artifact.id.as_str() == "x86-root/profile"
                        && artifact.role.as_str() == "installed-profile"
                        && &artifact.content == launch.profile()
                        && artifact.extensions.is_empty()
                })
                .count();
            if profile_matches != 1 {
                return Err(refusal("x86 root transitive installed profile differs"));
            }
            qualification.authenticate_preparation(&native, graph, node)?;

            let owner = OwnerIdentity {
                owner: launch.owner().clone(),
                incarnation: launch.incarnation().clone(),
                generation: launch.generation(),
            };
            let route = NodeRoute {
                node: node.clone(),
                owners: vec![owner],
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
            Err(error) => Err(Box::new(X86RootPreparationFailure { error, native })),
        }
    }

    /// Borrows the exact admitted immutable descriptor.
    pub fn descriptor(&self) -> &NodeDescriptor {
        &self.descriptor
    }

    /// Borrows the authentic current native owner binding.
    pub fn binding(&self) -> &NodeBinding {
        &self.binding
    }

    /// Borrows the retained indivisible participant/owner route.
    pub fn route(&self) -> &NodeRoute {
        &self.route
    }

    /// Borrows the exact immutable world admitted for this native preparation.
    pub fn world_binding_hash(&self) -> &HashRef {
        &self.world_binding_hash
    }

    /// Borrows the actual retained native boundary without servicing a callback.
    pub fn native_boundary(&self) -> &crucible_node_transport::gem5::Gem5Boundary {
        self.native.boundary()
    }

    /// Returns the same retained native owner when inactive conversion is abandoned.
    ///
    /// The caller keeps the pre-reserved supervisor and every original native
    /// journal. This ownership transfer issues no common execution or readiness
    /// authority and performs no native control operation.
    pub fn into_native(self) -> X86RootNativeProcess {
        self.native
    }
}
