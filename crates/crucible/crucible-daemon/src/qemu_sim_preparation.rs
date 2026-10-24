//! Original QEMU-SIM preparation beneath the common inactive world capsule.
//!
//! A boxed participant and its shared custody are reserved before child transfer.
//! The source supervisor and participant retain one QemuNode, its existing
//! resource guard, and whole legacy continuations. The mixed-provider builder
//! adopts that participant before invoking getters. This preparation edition
//! exposes no execution facet or alternate mutable legacy backend.

use std::{
    cell::{RefCell, RefMut},
    rc::Rc,
    task::{Context, Poll},
    thread::ThreadId,
};

use crucible_engine::{
    Configuration, SingleSchedulerCheckpoint,
    node_contract::{
        ActivationRecord, CancelStatus, EffectKnowledge, FacetKind, Lifecycle,
        NativeReclamationReceipt, NodeFacet, NodeRoute, NodeStatus, OperationAdmission,
        OperationFailure, OperationOutcome, OperationToken, OwnerIdentity, PhysicalState,
        ReadyAttestation, Refusal, SimulationNode, Submission, ThreadAffinity,
    },
};
use crucible_node_format::{Id, NodeBinding, NodeDescriptor, OperatingMode};
use crucible_qemu_host::{
    ProductionFaultRuntimeCheckpoint, QemuNode, QemuProcessIdentity, QemuVmSnapshot,
};

use crate::QemuAttemptProcessResourceGuard;

mod clock;
pub use clock::QemuSimClockLattice;

#[cfg(test)]
mod tests;

/// Names the inactive QEMU-SIM preparation edition without qualifying execution.
pub const QEMU_SIM_PREPARATION_IMPLEMENTATION: &str = "crucible.qemu-sim.preparation-v1";

/// Retains complete inert legacy state without translating its checkpoint codec.
///
/// Version-nine VMState/host-I/O and the complete legacy scheduler and fault
/// continuations remain paired data. They are not a Runtime7 capture and cannot
/// satisfy common preservation, replay, fresh restoration, or source admission.
pub struct QemuSimLegacyContinuation {
    /// Retains the full legacy configuration used to check scheduler identity.
    pub configuration: Configuration,
    /// Retains every legacy scheduler queue, decision, event log and time mapping.
    pub scheduler: SingleSchedulerCheckpoint,
    /// Retains the complete host, network, device and fault-command continuation.
    pub fault: ProductionFaultRuntimeCheckpoint,
    /// Retains the original VMState/host-I/O pair when preparation follows capture.
    pub vm_state: Option<QemuVmSnapshot>,
}

struct OriginalResources<G: QemuAttemptProcessResourceGuard> {
    guard: G,
    legacy: Option<QemuSimLegacyContinuation>,
    node: Option<QemuNode>,
    process: Option<QemuProcessIdentity>,
    clock: Option<QemuSimClockLattice>,
    attempted: bool,
    bound: bool,
    guard_matched: bool,
    quarantined: bool,
    released: bool,
}

struct OriginalCustody<G: QemuAttemptProcessResourceGuard> {
    creator_pid: u32,
    thread: ThreadId,
    resources: RefCell<Option<Box<OriginalResources<G>>>>,
}

impl<G: QemuAttemptProcessResourceGuard> OriginalCustody<G> {
    fn origin(&self) -> Result<(), OperationFailure> {
        // The raw process check precedes TLS/thread identity and any RefCell loan.
        if std::process::id() != self.creator_pid {
            return Err(refusal(
                "QEMU preparation belongs to another creator process",
            ));
        }
        if std::thread::current().id() != self.thread {
            return Err(refusal("QEMU preparation belongs to another owning thread"));
        }
        Ok(())
    }

    fn loan(&self) -> Result<RefMut<'_, Option<Box<OriginalResources<G>>>>, OperationFailure> {
        self.origin()?;
        self.resources
            .try_borrow_mut()
            .map_err(|_| refusal("QEMU original preparation is already borrowed"))
    }
}

impl<G: QemuAttemptProcessResourceGuard> Drop for OriginalCustody<G> {
    fn drop(&mut self) {
        let Some(resources) = self.resources.get_mut().take() else {
            return;
        };
        if resources.released {
            return;
        }

        // An abandoned original has no authentic release. Preserve the already
        // allocated whole capsule, including legacy history, before quarantine.
        // The ordinary world slot normally retains it instead of reaching here.
        // No new allocation, child extraction, wait handle, or cleanup retry is
        // created by this final fallback. Foreign fork copies invoke no guard.
        let retained = Box::leak(resources);
        if std::process::id() == self.creator_pid {
            retained.guard.quarantine();
        }
    }
}

/// Owns the source-side alias of one preallocated original QEMU preparation.
///
/// The alias grants no semantic operation or readiness. It can transfer one
/// actual legacy node into the shared capsule and mechanically contain that
/// same child on refusal. There is no raw mutable QemuNode or guard getter.
pub struct QemuSimPreparationSupervisor<G: QemuAttemptProcessResourceGuard> {
    original: Rc<OriginalCustody<G>>,
}

/// Retains genuine legacy resources as one inactive common participant.
///
/// Source/class/provider qualification remains mandatory outside this wrapper.
/// `arm`, operations and preservation refuse until an independently installed
/// QEMU common native issuer supplies full-phase stop and output closure.
pub struct PreparedQemuSimNode<G: QemuAttemptProcessResourceGuard> {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    route: NodeRoute,
    original: Rc<OriginalCustody<G>>,
}

impl<G: QemuAttemptProcessResourceGuard + 'static> PreparedQemuSimNode<G> {
    /// Reserves participant storage and one whole custody slot before native transfer.
    ///
    /// All metadata and legacy continuations move unchanged. This creates no
    /// child and does not qualify a profile. The caller retains the supervisor
    /// outside birth/enrollment unwind boundaries. Actual source-installed
    /// metadata and original resource ceilings must already be admitted.
    pub fn reserve(
        descriptor: NodeDescriptor,
        binding: NodeBinding,
        route: NodeRoute,
        guard: G,
        legacy: QemuSimLegacyContinuation,
    ) -> (Box<Self>, QemuSimPreparationSupervisor<G>) {
        Self::reserve_storage(descriptor, binding, route, guard, Some(legacy))
    }

    fn reserve_storage(
        descriptor: NodeDescriptor,
        binding: NodeBinding,
        route: NodeRoute,
        guard: G,
        legacy: Option<QemuSimLegacyContinuation>,
    ) -> (Box<Self>, QemuSimPreparationSupervisor<G>) {
        let original = Rc::new(OriginalCustody {
            creator_pid: std::process::id(),
            thread: std::thread::current().id(),
            resources: RefCell::new(Some(Box::new(OriginalResources {
                guard,
                legacy,
                node: None,
                process: None,
                clock: None,
                attempted: false,
                bound: false,
                guard_matched: false,
                quarantined: false,
                released: false,
            }))),
        });

        (
            Box::new(Self {
                descriptor,
                binding,
                route,
                original: Rc::clone(&original),
            }),
            QemuSimPreparationSupervisor { original },
        )
    }

    /// Moves the original box into a caller-owned common contribution slot.
    ///
    /// Unsizing allocates nothing. The installed provider subsequently lends
    /// this slot to ProviderWorldContribution::append_original, which adopts it
    /// into the SAME preowned global world before inspecting any metadata.
    pub fn into_participant(self: Box<Self>) -> Box<dyn SimulationNode> {
        self
    }
}

impl<G: QemuAttemptProcessResourceGuard> QemuSimPreparationSupervisor<G> {
    /// Transfers one actual node before any guard or native observation callback.
    ///
    /// # Errors
    /// Refuses foreign origin/thread, a repeated attempt, missing original,
    /// absent legacy continuation, changed configuration/frontier, invalid
    /// calibration, or failed original resource/process observation. Once taken,
    /// the SAME node remains in this capsule on every error; retry is forbidden.
    pub fn install_original(
        &mut self,
        incoming: &mut Option<QemuNode>,
    ) -> Result<(), OperationFailure> {
        let mut loan = self.original.loan()?;
        let resources = loan
            .as_mut()
            .ok_or_else(|| refusal("QEMU original preparation storage is unavailable"))?;
        if resources.attempted || resources.released {
            return Err(refusal("QEMU original preparation cannot be renewed"));
        }
        resources.attempted = true;
        resources.node = incoming.take();
        resources.quarantined = true;
        let node = resources
            .node
            .as_mut()
            .ok_or_else(|| refusal("QEMU original participant is absent"))?;

        resources
            .guard
            .check_operational_boundary()
            .map_err(|error| unknown(&format!("QEMU original resource check: {error}")))?;
        let contract = resources.guard.child_process_contract().map_err(|error| {
            refusal(&format!(
                "QEMU original process contract is unavailable: {error}"
            ))
        })?;
        node.authenticate_original_launch_contract(contract)
            .map_err(|error| refusal(&format!("QEMU original guard/node association: {error}")))?;
        resources.guard_matched = true;

        let process = node
            .process_identity()
            .map_err(|error| unknown(&format!("QEMU original process observation: {error}")))?;
        let calibration = node
            .logical_time_calibration()
            .map_err(|error| unknown(&format!("QEMU original clock observation: {error}")))?;
        let clock = QemuSimClockLattice::from_calibration(calibration)?;
        let legacy = resources
            .legacy
            .as_ref()
            .ok_or_else(|| refusal("QEMU complete legacy continuation is unavailable"))?;
        let recovered = legacy
            .scheduler
            .configuration_for(&legacy.configuration.def)
            .map_err(|_| refusal("QEMU legacy scheduler continuation differs"))?;
        if recovered.id() != legacy.configuration.id()
            || legacy.scheduler.frontier().ticks != calibration.logical_icount
            || node.process_identity().map_err(|error| {
                unknown(&format!("QEMU original process post-observation: {error}"))
            })? != process
        {
            return Err(refusal(
                "QEMU preparation changes its original configuration or cut",
            ));
        }
        if let Some(snapshot) = &legacy.vm_state {
            let checkpoint = snapshot.checkpoint();
            if checkpoint.configuration != legacy.configuration.id()
                || checkpoint.scenario_ref != legacy.configuration.def.id()
                || checkpoint.virtual_time != legacy.scheduler.frontier()
                || snapshot.host_io().execution_binding() != checkpoint.id
                || snapshot.node_continuation().execution_binding() != checkpoint.id
                || snapshot.node_continuation().logical_time_calibration() != calibration
            {
                return Err(refusal("QEMU legacy VMState and host continuations differ"));
            }
        }

        resources.process = Some(process);
        resources.clock = Some(clock);
        resources.bound = true;
        resources.quarantined = false;
        Ok(())
    }

    /// Returns the retained original reported clock without issuing a quantum.
    ///
    /// # Errors
    /// Refuses foreign origin/thread, borrow contention, absent preparation or
    /// a failed/withdrawn original binding. The returned data grants no cut permit.
    pub fn clock(&self) -> Result<QemuSimClockLattice, OperationFailure> {
        let loan = self.original.loan()?;
        let resources = loan
            .as_ref()
            .ok_or_else(|| refusal("QEMU original preparation storage is unavailable"))?;
        if !resources.bound || resources.quarantined || resources.released {
            return Err(refusal("QEMU original preparation is not current"));
        }
        resources
            .clock
            .ok_or_else(|| refusal("QEMU original clock was not retained"))
    }

    /// Force-contains and reaps this SAME original before releasing its guard.
    ///
    /// This preparation cleanup invokes the unchanged legacy containment path.
    /// It issues no polite guest/QMP operation, common grant or preservation
    /// receipt. Complete legacy history stays retained until custody is dropped.
    ///
    /// # Errors
    /// Refuses foreign origin/thread or a conflicting loan. A failed kill/reap
    /// keeps the same node, whole history and quarantined guard. Guard finish is
    /// called only after actual child_reaped or an original never transferred.
    pub fn reclaim_preparation(&mut self) -> Result<(), OperationFailure> {
        let mut loan = self.original.loan()?;
        let resources = loan
            .as_mut()
            .ok_or_else(|| refusal("QEMU original preparation storage is unavailable"))?;
        if resources.released {
            return Ok(());
        }
        resources.quarantined = true;
        if let Some(node) = resources.node.as_mut() {
            if let Err(error) = node.force_quarantine_and_reap() {
                resources.guard.quarantine();
                return Err(unknown(&format!(
                    "QEMU original containment remains held: {error}"
                )));
            }
            if !node.child_reaped() {
                resources.guard.quarantine();
                return Err(unknown("QEMU original child has no completed reap"));
            }
        }
        if resources.node.is_some() && !resources.guard_matched {
            resources.guard.quarantine();
            return Err(unknown(
                "QEMU child was contained but its unmatched guard cannot be released",
            ));
        }
        let result = resources.guard.finish();
        // The existing guard contract completes its release ladder even when
        // finish returns a cleanup diagnostic. A panic leaves released=false.
        resources.released = true;
        result.map_err(|error| unknown(&format!("QEMU guard cleanup diagnostic: {error}")))
    }
}

impl<G: QemuAttemptProcessResourceGuard + 'static> SimulationNode for PreparedQemuSimNode<G> {
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
        ThreadAffinity::OwnerThread(self.original.thread)
    }

    fn facets(&self) -> &[FacetKind] {
        &[]
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        let mut loan = self.original.loan()?;
        let resources = loan
            .as_mut()
            .ok_or_else(|| refusal("QEMU original custody is absent"))?;
        if let (Some(node), Some(expected)) = (&resources.node, &resources.process)
            && node
                .process_identity()
                .map_err(|error| unknown(&error.to_string()))?
                != *expected
        {
            resources.quarantined = true;
            return Err(unknown("QEMU original process generation changed"));
        }
        Ok(NodeStatus {
            lifecycle: if resources.quarantined {
                Lifecycle::Quarantined
            } else {
                Lifecycle::Prepared
            },
            physical: PhysicalState::Unknown,
            boundary: None,
        })
    }

    fn arm(&mut self, _: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        self.original.origin()?;
        if self
            .binding
            .compatibility
            .implementation
            .implementation_id
            .as_str()
            != QEMU_SIM_PREPARATION_IMPLEMENTATION
            || self.binding.compatibility.operating_contract.mode != OperatingMode::Exact
            || !self
                .binding
                .compatibility
                .operating_contract
                .facets
                .is_empty()
        {
            return Err(refusal(
                "QEMU inactive preparation cannot advertise an executable profile",
            ));
        }
        Err(refusal(
            "QEMU common full-phase stop, source and output closure are unqualified",
        ))
    }

    fn validate_readiness(
        &self,
        _: &ActivationRecord,
        _: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        Err(refusal(
            "QEMU preparation has no common native readiness issuer",
        ))
    }

    fn begin_operation(&mut self, _: &OperationAdmission) -> Submission {
        Submission::Refused(Refusal {
            reason: "QEMU common operation closure is unqualified".into(),
        })
    }

    fn poll_operation(
        &mut self,
        _: &OperationToken,
        _: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        Poll::Ready(Err(refusal(
            "QEMU preparation admitted no common operation",
        )))
    }

    fn validate_outcome(
        &self,
        _: &OperationAdmission,
        _: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        Err(refusal(
            "QEMU preparation has no common native outcome issuer",
        ))
    }

    fn request_cancel(&mut self, _: &OperationToken) -> Result<CancelStatus, OperationFailure> {
        Err(refusal("QEMU preparation has no common cancellation scope"))
    }

    fn close_quantum(&mut self, _: &OperationAdmission) -> Submission {
        Submission::Refused(Refusal {
            reason: "QEMU preparation has no common quantum".into(),
        })
    }

    fn acknowledge_publication(
        &mut self,
        _: &OperationToken,
        _: &[Id],
    ) -> Result<(), OperationFailure> {
        Err(refusal(
            "QEMU preparation has no common publication custody",
        ))
    }

    fn facet(&mut self, _: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        Err(Refusal {
            reason: "QEMU preparation advertises no common facet".into(),
        })
    }

    fn quarantine_resources(&mut self) {
        if let Ok(mut loan) = self.original.loan()
            && let Some(resources) = loan.as_mut()
            && !resources.released
        {
            resources.quarantined = true;
            resources.guard.quarantine();
        }
    }

    fn poll_reclamation(
        &mut self,
        _: &OwnerIdentity,
        _: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        Poll::Ready(Err(refusal(
            "QEMU mechanical reap is not a common source reclamation receipt",
        )))
    }

    fn validate_reclamation(&self, _: &NativeReclamationReceipt) -> Result<(), OperationFailure> {
        Err(refusal(
            "QEMU preparation cannot authenticate a common reclamation receipt",
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
