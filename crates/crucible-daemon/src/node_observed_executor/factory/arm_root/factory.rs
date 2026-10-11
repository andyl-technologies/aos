//! Selects installed native codecs and consumes reserved cold-world preparations.
//!
//! Native source validation is separate from actual fresh peer qualification.
//! Empty restoration capsules transfer their already reserved original image
//! lease before any child or helper can be allocated.

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use crucible::{
    node_adapters::arm_root::authenticate_arm_root_continuation,
    node_admission::AdmittedGraph,
    node_contract::{ActivationRecord, RuntimeSnapshot},
    node_scheduling::SchedulingSnapshot,
    node_state::{
        AuthenticatedNativeSource, NativeArchiveLimits, NativeArchiveRecord, NativeRestoreStaging,
        NativeWorldFactory, RestoreReservations, StateError, StateErrorCode, VerifiedStateContent,
    },
};
use crucible_node_contract::CapturedOwner;

use super::{
    custody::RootCustodyQueue,
    evidence::{RootEvidence, RootImmutableEvidence},
    installed::{RootColdPlan, RootLiveWorld, host_resources},
    profile::RootWorldProfile,
    staging::RootStaging,
};

/// Retains immutable installed policy and at most one genuinely reserved cold lease.
pub(super) struct RootNativeFactory {
    profile: Rc<RootWorldProfile>,
    evidence: Rc<RootEvidence>,
    queue: RootCustodyQueue,
    cold: RefCell<Option<RootColdPlan>>,
}

impl RootNativeFactory {
    pub(super) fn for_live(world: &RootLiveWorld, queue: RootCustodyQueue) -> Self {
        Self {
            profile: world.profile.clone(),
            evidence: world.evidence.clone(),
            queue,
            cold: RefCell::new(None),
        }
    }

    pub(super) fn for_cold(plan: RootColdPlan, queue: RootCustodyQueue) -> Self {
        Self {
            profile: plan.profile.clone(),
            evidence: plan.evidence.clone(),
            queue,
            cold: RefCell::new(Some(plan)),
        }
    }

    // Consumes only the original lease that has not entered empty_staging.
    // Keeping it in retirement disables every future staging caller, including
    // callers that still hold another Rc to this installed factory.
    pub(super) fn take_unstarted(
        &self,
        target: &ActivationRecord,
        archive: &NativeArchiveRecord,
        namespace: &std::path::Path,
    ) -> Result<RootColdPlan, super::super::NodeObservedError> {
        let mut pending = self
            .cold
            .try_borrow_mut()
            .map_err(|_| super::super::refused("Root original cold lease is currently borrowed"))?;
        let plan = pending.as_ref().ok_or_else(|| {
            super::super::refused("Root original cold lease has already entered staging")
        })?;
        if &plan.target != target
            || plan.namespace != namespace
            || plan.archive.artifact() != archive.artifact()
            || plan.archive.manifest() != archive.manifest()
            || plan.archive.owners() != archive.owners()
        {
            return Err(super::super::refused(
                "Root unstarted retirement names another original reserved lease",
            ));
        }
        let owner = target
            .owners
            .iter()
            .find(|owner| owner.owner.as_str() == "owner/root")
            .ok_or_else(|| super::super::refused("Root original reserved owner absent"))?;
        self.queue.verify_reserved(target, owner, archive)?;
        // All fallible validation precedes this move. The same slot, image
        // handles and signed backing stay owned until namespace release.
        pending
            .take()
            .ok_or_else(|| super::super::refused("Root original cold lease is unavailable"))
    }

    pub(super) fn native_queue(&self) -> RootCustodyQueue {
        self.queue.clone()
    }

    pub(super) fn immutable(&self) -> RootImmutableEvidence {
        RootImmutableEvidence::new(self.evidence.clone())
    }

    /// Authenticates this factory's exact immutable owner roster and profiles.
    ///
    /// # Errors
    /// Refuses a foreign world, descriptor or selected compatibility binding.
    pub(super) fn check_graph(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        if graph.world() != &self.profile.scenario.world || graph.node_ids().count() != 2 {
            return Err(refusal(
                "Root source world differs from installed frozen policy",
            ));
        }
        for descriptor in &self.profile.scenario.descriptors {
            let compatibility = self
                .profile
                .scenario
                .compatibility
                .iter()
                .find(|binding| binding.node_id == descriptor.id)
                .ok_or_else(|| refusal("Root installed binding absent"))?;
            if graph.descriptor(&descriptor.id) != Some(descriptor)
                || graph
                    .binding(&descriptor.id)
                    .is_none_or(|binding| &binding.compatibility != compatibility)
            {
                return Err(refusal(
                    "Root installed descriptor, native model or backend differs",
                ));
            }
        }
        Ok(())
    }
}

impl NativeWorldFactory for RootNativeFactory {
    fn authenticate_source(
        &self,
        graph: &AdmittedGraph,
        owner: &CapturedOwner,
        source: &AuthenticatedNativeSource<'_>,
    ) -> Result<(), StateError> {
        self.check_graph(graph)?;
        if owner.participant_ids.len() != 1
            || source.owner().owner != owner.capture_owner_id
            || source.owner().participants != owner.participant_ids
            || source.owner().cut != source.runtime().capture_cut
        {
            return Err(refusal("Root original native owner or cut differs"));
        }
        let node = &owner.participant_ids[0];
        match node.as_str() {
            "clock" => {
                let inventory = crucible::node_adapters::validate_public_clock_continuation(
                    source,
                    graph,
                    node,
                    host_resources(),
                )
                .map_err(|error| refusal(error.reason))?;
                if inventory.native_model.bytes
                    != crucible::node_adapters::host_clock_initial_bytes(
                        source.runtime().capture_cut.time_ps.get(),
                    )
                    || source
                        .runtime()
                        .inputs
                        .iter()
                        .any(|input| input.node == *node)
                {
                    return Err(refusal(
                        "Root original clock native state or ingress differs",
                    ));
                }
            }
            "root" => {
                let continuation = authenticate_arm_root_continuation(source, node)
                    .map_err(|failure| refusal(failure.reason))?;
                super::archive::check_selection(graph, &continuation, &self.profile)?;
            }
            _ => return Err(refusal("Root owner codec is not installed")),
        }
        Ok(())
    }

    fn authenticate_coordinator(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        self.check_graph(graph)?;
        self.evidence
            .authenticate_coordinator(graph, runtime, scheduler, content)
    }

    fn reservation(
        &self,
        graph: &AdmittedGraph,
        owner: &CapturedOwner,
        source: &AuthenticatedNativeSource<'_>,
        limits: NativeArchiveLimits,
    ) -> Result<RestoreReservations, StateError> {
        self.authenticate_source(graph, owner, source)?;
        let reservation = match owner.participant_ids[0].as_str() {
            "clock" => RestoreReservations {
                memory_bytes: source.owner().state.length.get(),
                writable_bytes: 0,
                processes: 0,
                descriptors: 0,
            },
            "root" => {
                let mut extent = 0_u64;
                for artifact in &source.owner().artifacts {
                    extent = extent
                        .checked_add(artifact.content.length.get())
                        .ok_or_else(|| refusal("Root original native image extent overflow"))?;
                }
                if extent > 4 * 1024 * 1024 * 1024 || source.owner().artifacts.len() > 8192 {
                    return Err(refusal(
                        "Root complete native image extent exceeds installed edition",
                    ));
                }
                // Four simultaneous image generations cover original backing,
                // reconstruction, independent fresh audit and future capture.
                RestoreReservations {
                    memory_bytes: 8 * 1024 * 1024 * 1024,
                    writable_bytes: extent
                        .checked_mul(4)
                        .ok_or_else(|| refusal("Root native writable reservation overflow"))?,
                    processes: 4096,
                    descriptors: 32768,
                }
            }
            _ => return Err(refusal("Root reservation owner unsupported")),
        };
        if reservation.memory_bytes > limits.state.maximum_native_memory_bytes
            || reservation.writable_bytes > limits.state.maximum_native_writable_bytes
            || reservation.processes > limits.state.maximum_native_processes
            || reservation.descriptors > limits.state.maximum_native_descriptors
        {
            return Err(refusal(
                "Root native peak reservation exceeds enforced whole-world ceiling",
            ));
        }
        Ok(reservation)
    }

    fn empty_staging(
        &self,
        graph: Rc<AdmittedGraph>,
        archive: NativeArchiveRecord,
        target: &ActivationRecord,
        reservations: RestoreReservations,
        _limits: NativeArchiveLimits,
    ) -> Result<Box<dyn NativeRestoreStaging>, StateError> {
        self.check_graph(&graph)?;
        let mut pending = self
            .cold
            .try_borrow_mut()
            .map_err(|_| refusal("Root native lease is already being installed"))?;
        let plan = pending
            .as_ref()
            .ok_or_else(|| refusal("Root factory has no reserved original-image preparation"))?;
        if plan.target != *target
            || plan.archive.artifact() != archive.artifact()
            || graph
                .node_ids()
                .any(|node| graph.binding(node) != plan.graph.binding(node))
        {
            return Err(refusal(
                "Root original reserved lease, fresh target or binding differs",
            ));
        }
        let root = target
            .owners
            .iter()
            .find(|owner| owner.owner.as_str() == "owner/root")
            .ok_or_else(|| refusal("Root reserved Root owner absent"))?;
        self.queue
            .verify_reserved(target, root, &archive)
            .map_err(|error| refusal(error.to_string()))?;
        let plan = pending
            .take()
            .ok_or_else(|| refusal("Root original reserved preparation unavailable"))?;
        Ok(Box::new(RootStaging {
            graph,
            archive,
            profile: plan.profile,
            evidence: plan.evidence,
            target: target.clone(),
            reservations,
            queue: self.queue.clone(),
            slot: Some(plan.slot),
            namespace: plan.namespace,
            imported: None,
            native: None,
            failed_authority: None,
            nodes: BTreeMap::new(),
            proofs: BTreeMap::new(),
            owners: BTreeMap::new(),
            coordinator: None,
            quarantined: false,
            transferred: false,
        }))
    }
}

fn refusal(reason: impl Into<String>) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed Root native factory",
        reason,
    )
}
