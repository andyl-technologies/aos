//! Preserves one source-qualified disconnected four-owner native composition.
//!
//! Complete signed source authentication is separate from the reserved fresh
//! CPU lease, actual native reconstruction and the common all-owner barrier.
//! This factory never projects the archive to the legacy two-owner policy.

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use crucible::{
    node_adapters::{HostModelNode, gem5::authenticate_gem5_continuation},
    node_admission::AdmittedGraph,
    node_contract::{ActivationRecord, RuntimeSnapshot},
    node_scheduling::SchedulingSnapshot,
    node_state::{
        AuthenticatedNativeSource, NativeArchiveLimits, NativeArchiveRecord, NativeRestoreStaging,
        NativeWorldFactory, RestoreReservations, StateError, VerifiedStateContent,
    },
};
use crucible_node_contract::CapturedOwner;

use super::super::installed::host_group::IndependentLiveWorld;
use super::super::{
    custody::Gem5CustodyQueue,
    installed::{IndependentColdWorld, host_resources},
    staging::{GroupContinuation, MixedStaging},
};
use super::{
    evidence::IndependentGroupEvidence,
    immutable::GroupImmutableEvidence,
    profile::IndependentGroupProfile,
    source::{self, error},
};

pub(in crate::node_observed_executor::factory::native_state) struct IndependentNativeFactory {
    profile: Rc<IndependentGroupProfile>,
    evidence: Rc<IndependentGroupEvidence>,
    queue: Gem5CustodyQueue,
    cold: RefCell<Option<IndependentColdWorld>>,
}

impl IndependentNativeFactory {
    pub(in crate::node_observed_executor::factory::native_state) fn authenticate_failure_retirement(
        &self,
        original: &super::failure_retirement::FailureRetirementPreparation,
    ) -> Result<(), super::super::super::NodeObservedError> {
        original.authenticate(&self.profile)
    }

    pub(in crate::node_observed_executor::factory::native_state) fn failed_queue(
        &self,
    ) -> &Gem5CustodyQueue {
        &self.queue
    }

    pub(in crate::node_observed_executor::factory::native_state) fn authenticate_capture_credit(
        &self,
        reference: &crucible_node_contract::ContentRef,
    ) -> Result<(), crate::node_observed_executor::NodeObservedError> {
        let metadata = self
            .evidence
            .metadata()
            .map_err(|error| super::super::super::refused(&error.message))?;
        if metadata.credit()?.reference() != reference {
            return Err(super::super::super::refused(
                "actual installed archive credit differs from prebirth source selection",
            ));
        }
        Ok(())
    }

    pub(in crate::node_observed_executor::factory::native_state) fn authenticate_supervision(
        &self,
        graph: &AdmittedGraph,
        archive: NativeArchiveRecord,
        requirements: crucible::node_state::StateRequirements,
    ) -> Result<
        super::super::custody::AuthenticatedSupervision,
        crate::node_observed_executor::NodeObservedError,
    > {
        self.check_graph(graph)
            .map_err(|error| super::super::super::refused(&error.to_string()))?;
        super::super::custody::AuthenticatedSupervision::authenticate(
            archive,
            graph,
            self,
            requirements,
            self.profile.native.installed.maximum_microsteps(),
        )
        .map_err(|error| super::super::super::refused(&error.to_string()))
    }

    pub(in crate::node_observed_executor::factory::native_state) fn supervise_original(
        &self,
        target: &ActivationRecord,
        source: &mut Option<super::super::custody::AuthenticatedSupervision>,
    ) -> Result<(), crate::node_observed_executor::NodeObservedError> {
        self.queue
            .supervise_original(target, source)
            .map_err(|error| super::super::super::refused(&error.to_string()))
    }

    pub(in crate::node_observed_executor::factory::native_state) fn release_supervised(
        &self,
        target: &ActivationRecord,
        reopened: &super::super::custody::AuthenticatedSupervision,
    ) -> Result<(), crate::node_observed_executor::NodeObservedError> {
        self.queue
            .release_supervised(target, reopened)
            .map_err(|error| super::super::super::refused(&error.to_string()))
    }

    pub(in crate::node_observed_executor::factory::native_state) fn retirement(
        &self,
        target: &ActivationRecord,
    ) -> Result<
        Option<(crucible_node_contract::ContentRef, Vec<u8>)>,
        crate::node_observed_executor::NodeObservedError,
    > {
        self.queue
            .original_group_retirement(target)
            .map_err(|error| super::super::super::refused(&error.to_string()))
    }

    pub(in crate::node_observed_executor::factory::native_state) fn initial_publisher(
        &self,
        stored: crate::node_observed_executor::StoredWorldActivationPublisher,
    ) -> super::super::publication::NativeCustodyPublisher {
        super::super::publication::NativeCustodyPublisher {
            stored,
            queue: self.queue.clone(),
            restored: None,
        }
    }

    pub(in crate::node_observed_executor::factory::native_state) fn reclaimed(
        &self,
        target: &ActivationRecord,
    ) -> Result<bool, crate::node_observed_executor::NodeObservedError> {
        self.queue
            .original_group_reclaimed(target)
            .map_err(|error| super::super::super::refused(&error.to_string()))
    }

    pub(in crate::node_observed_executor::factory::native_state) fn for_live(
        world: &IndependentLiveWorld,
        queue: Gem5CustodyQueue,
    ) -> Self {
        Self {
            profile: world.profile.clone(),
            evidence: world.evidence.clone(),
            queue,
            cold: RefCell::new(None),
        }
    }

    pub(in crate::node_observed_executor::factory::native_state) fn for_cold(
        plan: IndependentColdWorld,
        queue: Gem5CustodyQueue,
    ) -> Self {
        Self {
            profile: plan.profile.clone(),
            evidence: plan.evidence.clone(),
            queue,
            cold: RefCell::new(Some(plan)),
        }
    }

    pub(in crate::node_observed_executor::factory::native_state) fn immutable(
        &self,
    ) -> GroupImmutableEvidence {
        GroupImmutableEvidence {
            evidence: self.evidence.clone(),
        }
    }

    pub(in crate::node_observed_executor::factory::native_state) fn restored_publisher(
        &self,
        stored: crate::node_observed_executor::StoredWorldActivationPublisher,
        source: &NativeArchiveRecord,
        target: &ActivationRecord,
    ) -> Result<
        super::super::publication::NativeCustodyPublisher,
        crate::node_observed_executor::NodeObservedError,
    > {
        if !self.profile.preserving
            || source.manifest().world_binding_hash != self.profile.scenario.world.identity()?
            || target.world_binding_hash != source.manifest().world_binding_hash
        {
            return Err(super::super::super::refused(
                "restored group publisher selects another installed source world",
            ));
        }
        super::super::publication::NativeCustodyPublisher::for_public_group_restore(
            stored,
            self.queue.clone(),
            source,
            target,
        )
    }

    fn check_graph(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        if !self.profile.preserving
            || graph.world() != &self.profile.scenario.world
            || graph.node_ids().count() != 4
        {
            return Err(error(
                "independent preserving graph differs from installed source",
            ));
        }
        for descriptor in &self.profile.scenario.descriptors {
            if graph.descriptor(&descriptor.id) != Some(descriptor)
                || graph.binding(&descriptor.id).is_none_or(|binding| {
                    !self
                        .profile
                        .scenario
                        .compatibility
                        .contains(&binding.compatibility)
                })
            {
                return Err(error(
                    "independent preserving original descriptor or codec differs",
                ));
            }
        }
        Ok(())
    }
}

impl NativeWorldFactory for IndependentNativeFactory {
    fn native_capture_record_ceiling(
        &self,
        graph: &AdmittedGraph,
        scheduler: &SchedulingSnapshot,
    ) -> Result<Option<usize>, StateError> {
        self.check_graph(graph)?;
        if graph.capability_selection().is_none() {
            return Ok(None);
        }
        let queued_payload_bytes = scheduler
            .payload_objects
            .iter()
            .try_fold(0usize, |total, payload| {
                total.checked_add(payload.bytes.len())
            })
            .ok_or_else(|| error("actual queued payload credit overflows this host"))?;
        Ok(Some(
            self.evidence
                .metadata()
                .map_err(error)?
                .credit()
                .map_err(error)?
                .native_record_ceiling(queued_payload_bytes)
                .map_err(error)?,
        ))
    }

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
            || source.runtime().schema_version != 1
            || source.runtime().terminal.is_some()
            || source.runtime().condition_stop.is_some()
        {
            return Err(error(
                "independent original owner or coordinator edition differs",
            ));
        }
        let node = &owner.participant_ids[0];
        if node.as_str() == "cpu" {
            let original = authenticate_gem5_continuation(
                source,
                node,
                self.profile.native.installed.maximum_microsteps(),
            )
            .map_err(|failure| error(failure.reason))?;
            if original.record().guest_isa() != "x86_64"
                || source
                    .runtime()
                    .inputs
                    .iter()
                    .any(|input| input.node == *node)
            {
                return Err(error(
                    "independent original CPU claimed another ISA or public input",
                ));
            }
            super::super::archive::check_installed_binding(
                graph,
                source,
                node,
                self.profile.native.installed.as_ref(),
                "x86_64",
            )?;
        } else if node.as_str() == "clock" {
            let inventory = crucible::node_adapters::validate_public_clock_continuation(
                source,
                graph,
                node,
                host_resources(),
            )
            .map_err(|failure| error(failure.reason))?;
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
                return Err(error(
                    "independent original Clock model or public inputs differ",
                ));
            }
        } else {
            crucible::node_adapters::validate_public_owned_model_continuation(
                source,
                graph,
                node,
                host_resources(),
            )
            .map_err(|failure| error(failure.reason))?;
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
        source::authenticate(&self.profile, graph, runtime, scheduler, content)
    }

    fn reservation(
        &self,
        graph: &AdmittedGraph,
        owner: &CapturedOwner,
        source: &AuthenticatedNativeSource<'_>,
        limits: NativeArchiveLimits,
    ) -> Result<RestoreReservations, StateError> {
        self.authenticate_source(graph, owner, source)?;
        let node = &owner.participant_ids[0];
        let reservation = if node.as_str() == "cpu" {
            let extent = source
                .owner()
                .artifacts
                .iter()
                .try_fold(0_u64, |extent, artifact| {
                    extent.checked_add(artifact.content.length.get())
                })
                .ok_or_else(|| error("independent original CPU image extent overflow"))?;
            if extent > 4 * 1024 * 1024 * 1024 || source.owner().artifacts.len() > 8192 {
                return Err(error(
                    "independent CPU image exceeds unchanged installed geometry",
                ));
            }
            RestoreReservations {
                memory_bytes: 8 * 1024 * 1024 * 1024,
                writable_bytes: extent
                    .checked_mul(4)
                    .ok_or_else(|| error("native peak extent overflow"))?,
                processes: 4096,
                descriptors: 32768,
            }
        } else {
            let mut extent = source.owner().state.length.get();
            for body in &source.owner().evidence {
                extent = extent
                    .checked_add(body.length.get())
                    .ok_or_else(|| error("independent original Host evidence extent overflow"))?;
            }
            let memory_bytes = extent
                .checked_add(4 * 1024 * 1024)
                .and_then(|extent| extent.checked_mul(32))
                .and_then(|extent| extent.checked_add(64 * 1024))
                .ok_or_else(|| error("independent original Host expanded reservation overflow"))?;
            RestoreReservations {
                memory_bytes,
                ..Default::default()
            }
        };
        if reservation.memory_bytes > limits.state.maximum_native_memory_bytes
            || reservation.writable_bytes > limits.state.maximum_native_writable_bytes
            || reservation.processes > limits.state.maximum_native_processes
            || reservation.descriptors > limits.state.maximum_native_descriptors
        {
            return Err(error(
                "independent native reservation exceeds authored whole-world credit",
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
        _: NativeArchiveLimits,
    ) -> Result<Box<dyn NativeRestoreStaging>, StateError> {
        self.check_graph(&graph)?;
        let mut cold = self
            .cold
            .try_borrow_mut()
            .map_err(|_| error("independent original cold lease is already being installed"))?;
        let plan = cold
            .as_ref()
            .ok_or_else(|| error("independent factory has no inactive original lease"))?;
        if &plan.target != target
            || plan.archive.artifact() != archive.artifact()
            || graph
                .node_ids()
                .any(|node| graph.binding(node) != plan.graph.binding(node))
        {
            return Err(error(
                "independent original lease, bindings or fresh target differs",
            ));
        }
        let cpu = target
            .owners
            .iter()
            .find(|owner| owner.owner.as_str() == "owner/cpu")
            .ok_or_else(|| error("independent original fresh CPU is absent"))?;
        self.queue
            .verify_reserved_restore(target, cpu, &archive)
            .map_err(error)?;
        let plan = cold
            .take()
            .ok_or_else(|| error("independent original cold lease disappeared"))?;
        let mut nodes = BTreeMap::new();
        // Construct every original fresh Host model/node before CPU child birth.
        // These nodes remain in the installed capsule on all later refusals.
        for (node, model) in plan.models {
            let actual = HostModelNode::new(
                &graph,
                &node,
                model,
                plan.evidence.as_ref(),
                host_resources(),
            )
            .map_err(|failure| error(failure.reason))?;
            nodes.insert(node, actual);
        }
        if nodes.len() != 2 {
            return Err(error(
                "independent original inactive Host roster is incomplete",
            ));
        }
        Ok(Box::new(MixedStaging {
            graph,
            archive,
            profile: plan.profile.native.clone(),
            evidence: plan.native_evidence,
            group: Some(GroupContinuation {
                evidence: plan.evidence,
                nodes,
            }),
            target: target.clone(),
            reservations,
            queue: self.queue.clone(),
            slot: Some(plan.slot),
            namespace: plan.namespace,
            imported: None,
            native: None,
            nodes: BTreeMap::new(),
            proofs: BTreeMap::new(),
            owners: BTreeMap::new(),
            coordinator: None,
            quarantined: false,
            transferred: false,
        }))
    }
}
