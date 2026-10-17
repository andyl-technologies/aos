//! Common node preparation backed by original native KVM resource custody.
//!
//! The adapter retains actual process and command ownership beneath a closed
//! execution gate. Component receipts cannot satisfy whole-domain readiness,
//! quantized input/output closure or exact continuation. Those hooks refuse
//! until an installed source-owned native preparation issuer exists.

use std::{
    task::{Context, Poll},
    thread::ThreadId,
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, CancelStatus, EffectKnowledge, FacetKind, Lifecycle,
        NativeReclamationReceipt, NodeFacet, NodeRoute, NodeStatus, OperationAdmission,
        OperationFailure, OperationOutcome, OperationToken, OwnerIdentity, PhysicalState,
        ReadyAttestation, Refusal, SimulationNode, Submission, ThreadAffinity,
    },
};
use crucible_node_contract::{
    CaptureScope, Continuation, Id, NodeBinding, NodeDescriptor, OperatingMode, Repeatability,
};

use super::KvmOwnedComponents;

/// Names the quantized KVM implementation family without claiming qualification.
pub const KVM_NODE_IMPLEMENTATION_ID: &str = "crucible.qemu-kvm.quantized-v1";

/// Retains original custody after a common adapter preparation is refused.
pub struct KvmNodePreparationFailure {
    /// Describes the failed no-effect common mapping.
    pub error: OperationFailure,
    /// Retains the same original child, peer, journal and supervisory reservation.
    pub custody: KvmOwnedComponents,
}

/// Retains an original prepared native owner under the common node interface.
///
/// This edition cannot pass `arm` and supplies no executable facets. An admitted
/// graph, OS-authenticated peer and source component receipts are insufficient
/// to mint complete native readiness. Preservation and replay retain their
/// unsupported trait defaults. Consuming the component owner closes its separate command surface; the
/// common node exposes no alternate mutation path. Its actual child, byte
/// ancestry and original journals remain in the same reserved capsule.
pub struct KvmPreparedNode {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    route: NodeRoute,
    custody: Option<KvmOwnedComponents>,
    thread: ThreadId,
    quarantined: bool,
}

impl KvmPreparedNode {
    /// Maps admitted metadata onto the same actual prepared original resources.
    ///
    /// The original capsule pins independently measured native files. It does
    /// not certify kernel/source linkage or whole-domain native preparation.
    /// Requiring all its artifacts in the binding prevents this mapping from
    /// quietly replacing an admitted implementation while withholding execution.
    ///
    /// # Errors
    /// Returns the original custody if the graph, single owner, implementation
    /// inventory, process or authenticated channel differs from preparation.
    pub fn from_prepared(
        graph: &AdmittedGraph,
        node: &Id,
        custody: KvmOwnedComponents,
    ) -> Result<Self, Box<KvmNodePreparationFailure>> {
        let validate = || -> Result<(NodeDescriptor, NodeBinding, NodeRoute), OperationFailure> {
            let descriptor = graph
                .descriptor(node)
                .ok_or_else(|| refusal("native KVM node is absent from the admitted graph"))?;
            let binding = graph
                .binding(node)
                .ok_or_else(|| refusal("native KVM binding is absent from the admitted graph"))?;
            if binding
                .compatibility
                .implementation
                .implementation_id
                .as_str()
                != KVM_NODE_IMPLEMENTATION_ID
            {
                return Err(refusal(
                    "admitted implementation is not the native KVM node family",
                ));
            }
            let world = custody.allocation();
            let execution = &binding.compatibility.execution_owner;
            let capture = &binding.compatibility.capture_owner;
            if world.world_binding_hash != *graph.world_binding_hash()
                || world.owners.len() != 1
                || execution.participant_ids.as_slice() != std::slice::from_ref(node)
                || capture.participant_ids.as_slice() != std::slice::from_ref(node)
                || execution.id != world.owners[0].owner
                || capture.id != world.owners[0].owner
                || binding.authority.incarnation_id != world.owners[0].incarnation
                || binding.authority.owner_generation != world.owners[0].generation
            {
                return Err(refusal(
                    "native KVM original owner or complete world scope differs",
                ));
            }
            let guarantees = graph
                .guarantees(node)
                .ok_or_else(|| refusal("native KVM guarantee profile is unavailable"))?;
            if binding.compatibility.operating_contract.mode != OperatingMode::Quantized
                || !binding.compatibility.operating_contract.facets.is_empty()
                || guarantees.repeatability != Repeatability::Nondeterministic
                || guarantees.capture_scope != CaptureScope::None
                || guarantees.continuation != Continuation::Unsupported
                || guarantees.durable_restart
                || guarantees.isolated_fork
                || guarantees.conditional_replay
            {
                return Err(refusal(
                    "native KVM preparation cannot advertise executable or preservation guarantees",
                ));
            }
            custody
                .validate_admitted_installation(&binding.compatibility.implementation.artifacts)
                .map_err(|error| {
                    refusal(&format!(
                        "native KVM installed peer binding failed: {error}"
                    ))
                })?;
            Ok((
                descriptor.clone(),
                binding.clone(),
                NodeRoute {
                    node: node.clone(),
                    owners: world.owners.clone(),
                },
            ))
        };
        let (descriptor, binding, route) = match validate() {
            Ok(parts) => parts,
            Err(error) => return Err(Box::new(KvmNodePreparationFailure { error, custody })),
        };
        Ok(Self {
            descriptor,
            binding,
            route,
            custody: Some(custody),
            thread: std::thread::current().id(),
            quarantined: false,
        })
    }
}

impl SimulationNode for KvmPreparedNode {
    fn descriptor(&self) -> &NodeDescriptor {
        &self.descriptor
    }

    fn binding(&self) -> &NodeBinding {
        &self.binding
    }

    fn route(&self) -> &NodeRoute {
        &self.route
    }

    fn thread_affinity(&self) -> ThreadAffinity {
        ThreadAffinity::OwnerThread(self.thread)
    }

    fn facets(&self) -> &[FacetKind] {
        &[]
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        if std::thread::current().id() != self.thread {
            return Err(refusal(
                "native KVM observation is not on the owning thread",
            ));
        }
        if let Some(custody) = &mut self.custody
            && custody
                .observe_process_exit()
                .map_err(|error| {
                    unknown(&format!(
                        "original native process observation failed: {error}"
                    ))
                })?
                .is_some()
        {
            self.quarantined = true;
        }
        Ok(NodeStatus {
            lifecycle: if self.quarantined {
                Lifecycle::Quarantined
            } else {
                Lifecycle::Prepared
            },
            physical: PhysicalState::Unknown,
            boundary: None,
        })
    }

    fn arm(&mut self, _: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        Err(refusal(
            "native KVM complete original preparation and device closure are unqualified",
        ))
    }

    fn validate_readiness(
        &self,
        _: &ActivationRecord,
        _: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        Err(refusal(
            "native KVM has no source-owned complete readiness issuer",
        ))
    }

    fn begin_operation(&mut self, _: &OperationAdmission) -> Submission {
        Submission::Refused(Refusal {
            reason: "native KVM atomic input/grant/whole-owner closure is unsupported".into(),
        })
    }

    fn poll_operation(
        &mut self,
        _: &OperationToken,
        _: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        Poll::Ready(Err(refusal("native KVM no common operation was admitted")))
    }

    fn validate_outcome(
        &self,
        _: &OperationAdmission,
        _: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        Err(refusal(
            "native KVM complete outcome authentication is unsupported",
        ))
    }

    fn request_cancel(&mut self, _: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        Err(refusal("native KVM no common cancellation scope exists"))
    }

    fn close_quantum(&mut self, _: &OperationAdmission) -> Submission {
        Submission::Refused(Refusal {
            reason: "native KVM genuine whole-domain quantum closure is unsupported".into(),
        })
    }

    fn acknowledge_publication(
        &mut self,
        _: &OperationToken,
        _: &[Id],
    ) -> Result<(), OperationFailure> {
        Err(refusal(
            "native KVM no common publication custody was issued",
        ))
    }

    fn facet(&mut self, _: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        Err(Refusal {
            reason: "native KVM executable facets remain unqualified".into(),
        })
    }

    fn quarantine_resources(&mut self) {
        self.quarantined = true;
        // The actual pre-reserved capsule moves to mandatory common supervision.
        // Process death is not device closure or a successful modeled outcome.
        drop(self.custody.take());
    }

    fn poll_reclamation(
        &mut self,
        _: &OwnerIdentity,
        _: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        Poll::Ready(Err(refusal(
            "native KVM whole-domain reclamation issuer is unsupported; resources remain supervised",
        )))
    }

    fn validate_reclamation(&self, _: &NativeReclamationReceipt) -> Result<(), OperationFailure> {
        Err(refusal(
            "native KVM process-group cleanup cannot authenticate whole-device reclamation",
        ))
    }
}

fn refusal(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

fn unknown(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;
