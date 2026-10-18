//! Borrows a real Main-held Source node for private native observations.
//!
//! Launch and cleanup use the same selected guard, Source issuer, directory,
//! generation lease and Original as the normal lifecycle. This module does not
//! admit a Main, issue a Source or turn an observation into resource authority.

use crate::NativeObservationError;

use super::*;
use crucible_engine::{
    BackendEffect, BackendError, BackendSnapshot, FingerprintSample, SimulationBackend,
    StepObservation, VirtualTime,
};

impl<G, F> QemuAttemptProductionVmNodeLauncher<G, F>
where
    G: QemuAttemptProcessResourceGuard + Send,
    F: Send,
{
    /// Starts one authored observation profile inside this actual Source.
    ///
    /// Diskless profiles pass their actual absent image to the same production
    /// helper. No disk is added to make a fixture conform to the normal profile.
    pub(crate) fn launch_native_observation(
        &mut self,
        node: &crucible_engine::NodeId,
        profile: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        router: &str,
        crash_detector: &str,
    ) -> Result<(), crate::QemuAttemptProductionVmLifecycleError> {
        if self.retained_node.is_some() {
            return Err(crate::QemuAttemptProductionVmLifecycleError::Lifecycle(
                launcher_message("same Source already retains a node or Park phase"),
            ));
        }
        #[cfg(feature = "private-measurement-domain")]
        if self.parent_park_phase.is_some() {
            return Err(crate::QemuAttemptProductionVmLifecycleError::Lifecycle(
                launcher_message("same Source still retains its Park phase"),
            ));
        }
        let observation = self.native_observation_config.as_ref().ok_or_else(|| {
            crate::QemuAttemptProductionVmLifecycleError::Lifecycle(launcher_message(
                "same observation Source lost its configured registration owner",
            ))
        })?;
        let original = observation
            .host_operation_supervisor()
            .cloned()
            .ok_or(crate::QemuAttemptProductionVmLifecycleError::HostWatchdogExpired)?;
        let registration = observation
            .host_ram_registration_factory()
            .ok_or_else(|| {
                crate::QemuAttemptProductionVmLifecycleError::HostRamAdmission(
                    crucible_control_api::host_operational::HostRamAdmissionError::contract(
                        "same Source registration is absent",
                    ),
                )
            })?
            .prepare(
                &node.name,
                profile.process_generation(),
                profile.resource_requirements().guest_memory_bytes(),
                profile.resource_requirements().virtual_cpus(),
            )
            .map_err(crate::QemuAttemptProductionVmLifecycleError::HostRamAdmission)?;
        self.launch_registered_observation(
            node,
            profile,
            router,
            crash_detector,
            registration,
            original,
        )
        .map_err(crate::QemuAttemptProductionVmLifecycleError::Lifecycle)
    }

    fn launch_registered_observation(
        &mut self,
        node: &crucible_engine::NodeId,
        profile: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        router: &str,
        crash_detector: &str,
        registration: crucible_qemu_host::ram_control::RamControlRegistration,
        original: crucible_host_resources::host_supervision::HostOperationSupervisor,
    ) -> Result<(), LifecycleApiError> {
        let generation =
            ProductionVmNodeGeneration::new(node.clone(), profile.process_generation())?;
        let lease = self.owner.register_generation(generation.clone())?;
        let directories = Arc::clone(&self.run_directories);
        let mut directories = match directories.lock() {
            Ok(directories) => directories,
            Err(_) => {
                return Err(abort_unspawned_generation(
                    lease,
                    launcher_message("observation directory registry is poisoned"),
                ));
            }
        };
        if directories.contains_key(&generation) {
            return Err(abort_unspawned_generation(
                lease,
                launcher_message("observation generation already retains its directory"),
            ));
        }
        let fresh = self.prepare_fresh_generation(
            profile,
            node,
            QemuLiveNodeIdentity::new(&node.name, router, crash_detector),
            profile.qemu_executable(),
            profile.root_image(),
            Some((registration, original)),
            lease,
        )?;
        // Both consumers use the same recording cut. The observer keeps its
        // actual lease INLINE in the already priced containing launcher.
        let (node, lease, directory) = self.record_launched_parts(
            profile.qemu_executable(),
            fresh.lease,
            fresh.directory,
            fresh.node,
            fresh.contract,
            &mut directories,
        );
        self.retained_node = Some(RetainedNodeLaunch::observed(node, lease, directory));
        Ok(())
    }

    /// Lends operations while retaining the complete node/lease in this launcher.
    pub(crate) fn borrow_native_observation<'a>(
        &'a mut self,
        context: &'a crate::AttemptExecutionContext,
    ) -> Result<ObservedNativeNode<'a>, LifecycleApiError> {
        let retained = self
            .retained_node
            .as_mut()
            .ok_or_else(|| launcher_message("same Source has no retained observation node"))?;
        let node = retained.node_mut()?;
        Ok(ObservedNativeNode {
            node,
            owner: &mut self.owner,
            context,
        })
    }

    /// Reads the pinned post-reap trace through a borrowed buffered reader.
    ///
    /// # Errors
    ///
    /// Returns directory validation, trace-read or inspection refusal.
    pub(crate) fn inspect_native_observation_trace(
        &self,
        node: &crucible_engine::NodeId,
        generation: u64,
        maximum_bytes: u64,
        inspect: &mut dyn FnMut(&mut dyn std::io::BufRead) -> Result<(), NativeObservationError>,
    ) -> Result<(), NativeObservationError> {
        self.with_native_observation_directory(node, generation, |directory| {
            directory.inspect_runtime_determinism_trace_after_reap(maximum_bytes, inspect)
        })
    }

    /// Copies the bounded liveness tail from the same pinned post-reap trace.
    ///
    /// # Errors
    ///
    /// Returns directory validation or the actual trace-read refusal.
    pub(crate) fn native_observation_liveness_tail(
        &self,
        node: &crucible_engine::NodeId,
        generation: u64,
    ) -> Result<String, NativeObservationError> {
        self.with_native_observation_directory(node, generation, |directory| {
            Ok(directory.retain_runtime_liveness_trace_tail_after_reap()?)
        })
    }

    /// Keeps directory access private to the two bounded read operations.
    fn with_native_observation_directory<T, E>(
        &self,
        node: &crucible_engine::NodeId,
        generation: u64,
        inspect: impl FnOnce(&QemuPreparedRunDirectory) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<LifecycleApiError>,
    {
        let identity =
            ProductionVmNodeGeneration::new(node.clone(), generation).map_err(E::from)?;
        let directories = self.run_directories.lock().map_err(|_| {
            E::from(launcher_message(
                "observation directory registry is poisoned",
            ))
        })?;
        let directory = directories
            .get(&identity)
            .ok_or_else(|| E::from(launcher_message("same observation directory is absent")))?;
        inspect(directory)
    }
}

/// Borrows only operations; moving or dropping it cannot return Source custody.
pub(crate) struct ObservedNativeNode<'a> {
    node: &'a mut QemuNode,
    owner: &'a mut dyn NativeQuantumCharge,
    context: &'a crate::AttemptExecutionContext,
}

impl ObservedNativeNode<'_> {
    /// Charges the accepted execution and its same retained native generation.
    fn charge_quantum(&mut self) -> Result<(), BackendError> {
        self.context
            .charge_execution_quantum()
            .map_err(|first| BackendError::Rejected {
                message: first.to_string(),
            })?;
        self.owner
            .charge_native_quantum()
            .map_err(|first| BackendError::Rejected {
                message: first.to_string(),
            })
    }

    /// Installs the existing single-use host preemption evidence claim.
    pub(crate) fn enable_bounded_scheduler_preemption(
        &mut self,
        evidence: crucible_qemu_host::BoundedSchedulerPreemptionEvidenceClaim,
    ) {
        self.node.enable_bounded_scheduler_preemption(evidence);
    }

    /// Advances to authenticated idle under one accepted/native quantum charge.
    ///
    /// # Errors
    ///
    /// Returns the actual charge or node advance refusal before further work.
    pub(crate) fn advance_to_next_idle(
        &mut self,
        ceiling: crucible_engine::Icount,
    ) -> Result<crucible_engine::AdvanceOutcome, BackendError> {
        // The driver does not charge separately: both advance entry points
        // charge exactly once, before asking this same node to execute.
        self.charge_quantum()?;
        self.node
            .advance_to_next_idle(ceiling)
            .map_err(BackendError::from)
    }

    /// Reads the exact current fingerprint through this retained node.
    ///
    /// # Errors
    ///
    /// Returns the node's actual fingerprint capture refusal.
    pub(crate) fn execution_fingerprint(
        &mut self,
    ) -> Result<crucible_engine::ExecutionFingerprint, crucible_qemu_host::QemuNodeError> {
        self.node.execution_fingerprint()
    }

    /// Reads the current plain-value fingerprint sample.
    ///
    /// # Errors
    ///
    /// Returns the node's actual sample validation refusal.
    pub(crate) fn fingerprint_sample(
        &mut self,
    ) -> Result<crucible_qemu_shmem::FingerprintSample, crucible_qemu_host::QemuNodeError> {
        self.node.fingerprint_sample()
    }

    /// Reads the current plain-value logical/raw clock calibration.
    ///
    /// # Errors
    ///
    /// Returns the node's actual calibration validation refusal.
    pub(crate) fn logical_time_calibration(
        &mut self,
    ) -> Result<crucible_qemu_host::QemuLogicalTimeCalibration, crucible_qemu_host::QemuNodeError>
    {
        self.node.logical_time_calibration()
    }

    /// Reads the current plain-value idle state.
    ///
    /// # Errors
    ///
    /// Returns the node's actual idle-state validation refusal.
    pub(crate) fn idle_state(
        &mut self,
    ) -> Result<crucible_qemu_host::QemuNodeIdleState, crucible_qemu_host::QemuNodeError> {
        self.node.idle_state()
    }

    /// Reads the most recent plain-value timer callback witness.
    ///
    /// # Errors
    ///
    /// Returns the node's actual shared-memory read refusal.
    pub(crate) fn virtual_timer_fire_witness(
        &mut self,
    ) -> Result<
        Option<crucible_qemu_host::QemuVirtualTimerFireWitness>,
        crucible_qemu_host::QemuNodeError,
    > {
        self.node.virtual_timer_fire_witness()
    }

    /// Drains process-neutral selectable request records from this node.
    ///
    /// # Errors
    ///
    /// Returns the node's actual request validation refusal.
    pub(crate) fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<
        Vec<crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanPendingRequest>,
        crucible_qemu_host::QemuNodeError,
    > {
        self.node.drain_pending_selectable_requests()
    }

    /// Enqueues the reply for the same node's authenticated pending request.
    ///
    /// # Errors
    ///
    /// Returns the node's actual stopped-state or request/reply refusal.
    pub(crate) fn enqueue_selectable_reply(
        &mut self,
        pending: &crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
        reply: &crucible_qemu_protocol::SelectionReply,
    ) -> Result<(), crucible_qemu_host::QemuNodeError> {
        self.node.enqueue_selectable_reply(pending, reply)
    }

    /// Observes whether this node has consumed its queued selectable reply.
    pub(crate) fn selectable_reply_is_checkpoint_quiescent(&self) -> bool {
        self.node.selectable_reply_is_checkpoint_quiescent()
    }

    /// Pauses this retained node at its exact checkpoint boundary.
    ///
    /// # Errors
    ///
    /// Returns the node's actual pause refusal.
    pub(crate) fn pause_at_exact_checkpoint_boundary(
        &mut self,
    ) -> Result<(), crucible_qemu_host::QemuNodeError> {
        self.node.pause_at_exact_checkpoint_boundary()
    }

    /// Advances the existing template transaction and returns its factual state.
    ///
    /// # Errors
    ///
    /// Returns the node's actual transaction refusal.
    pub(crate) fn prepare_hot_fork_template(
        &mut self,
        bindings: &[crucible_qemu_host::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crucible_qemu_host::QmpHotForkTemplateState, crucible_qemu_host::QemuNodeChannelError>
    {
        self.node.prepare_hot_fork_template(bindings)
    }

    /// Acquires the same template's barriers and returns their factual state.
    ///
    /// # Errors
    ///
    /// Returns the node's actual barrier refusal.
    pub(crate) fn prepare_hot_fork_template_barriers(
        &mut self,
        bindings: &[crucible_qemu_host::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crucible_qemu_host::QmpHotForkTemplateState, crucible_qemu_host::QemuNodeChannelError>
    {
        self.node.prepare_hot_fork_template_barriers(bindings)
    }

    /// Prepares node-retained child resources and returns only their evidence.
    ///
    /// Every descriptor, mapping and endpoint remains in the actual node. The
    /// returned records contain names, identities and scalar protocol facts.
    ///
    /// # Errors
    ///
    /// Returns the node's actual resource-preparation refusal.
    pub(crate) fn prepare_hot_fork_child_resources(
        &mut self,
        maximum_ring_image_bytes: usize,
    ) -> Result<
        crucible_qemu_host::QemuHotForkPreparedChildResources,
        crucible_qemu_host::QemuHotForkChildResourcePreparationError,
    > {
        self.node
            .prepare_hot_fork_child_resources(maximum_ring_image_bytes)
    }

    /// Applies the requested mutations without lending the owning block handle.
    ///
    /// Absence remains distinct from a present device's mutation refusal. The
    /// temporary handle is dropped inside this call on every path.
    ///
    /// # Errors
    ///
    /// Returns the actual block-service refusal for a present device.
    pub(crate) fn apply_storage_boundary_mutations(
        &mut self,
        volatile_sequences: &[u64],
        transitions: &[(
            crucible_device::block::ResolvedBlockControllerTransition,
            u64,
        )],
    ) -> Option<Result<(), crucible_qemu_host::QemuLiveBlockIoServicerError>> {
        self.node
            .shared_block_device()
            .map(|device| device.apply_storage_boundary_mutations(volatile_sequences, transitions))
    }

    /// Copies visible bytes without lending the owning block handle.
    ///
    /// # Errors
    ///
    /// Returns the actual block-service refusal for a present device; absence
    /// remains a separate `None`.
    pub(crate) fn inspect_storage_visible(
        &self,
        offset: u64,
        count: u32,
    ) -> Option<Result<Vec<u8>, crucible_qemu_host::QemuLiveBlockIoServicerError>> {
        self.node
            .shared_block_device()
            .map(|device| device.inspect_storage_visible(offset, count))
    }

    /// Copies the accumulated plain-value block diagnostics.
    pub(crate) fn block_io_diagnostics(
        &self,
    ) -> Option<crucible_qemu_host::BlockIoDiagnosticsSnapshot> {
        self.node.block_io_diagnostics()
    }

    /// Attempts actual child shutdown while retaining this Source's ownership.
    ///
    /// # Errors
    ///
    /// Returns the node's actual shutdown refusal. Even success leaves the
    /// node, generation lease and Source owner in their existing launcher.
    pub(crate) fn shutdown_child(
        &mut self,
    ) -> Result<crucible_qemu_host::QemuShutdownReport, crucible_qemu_host::QemuNodeError> {
        self.node.shutdown_child()
    }
}

impl SimulationBackend for ObservedNativeNode<'_> {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        self.charge_quantum()?;
        self.node.step_to(ceiling)
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        self.node.apply(effect, at)
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        self.node.snapshot()
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        self.node.restore(snapshot)
    }

    fn now(&self) -> VirtualTime {
        self.node.now()
    }

    fn fingerprint(
        &mut self,
        node: crucible_engine::NodeId,
    ) -> Result<FingerprintSample, BackendError> {
        SimulationBackend::fingerprint(self.node, node)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.node.shutdown()
    }

    fn drain_observable_events(
        &mut self,
    ) -> Result<Vec<crucible_engine::ObservableEvent>, BackendError> {
        self.node.drain_observable_events()
    }

    fn drain_rng_evidence(
        &mut self,
    ) -> Result<Vec<crucible_engine::BackendRngEvidence>, BackendError> {
        self.node.drain_rng_evidence()
    }

    fn drain_network_outputs(
        &mut self,
    ) -> Result<Vec<crucible_engine::BackendNetworkOutput>, BackendError> {
        self.node.drain_network_outputs()
    }
}

/// Borrows the real generation charge method without moving its guard.
trait NativeQuantumCharge {
    fn charge_native_quantum(&mut self) -> Result<(), LifecycleApiError>;
}

impl<G: QemuAttemptProcessResourceGuard> NativeQuantumCharge
    for QemuAttemptGenerationResourceOwner<G>
{
    fn charge_native_quantum(&mut self) -> Result<(), LifecycleApiError> {
        self.charge_execution_quantum()
    }
}
