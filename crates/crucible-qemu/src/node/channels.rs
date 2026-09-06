//! Typed plugin IPC, shared-memory, and QMP channel contracts for one QEMU node.
//!
//! The contracts separate setup and teardown control from per-quantum data and
//! machine operations. Pending quantum tokens retain their publication fence.

use super::*;

/// Plugin IPC control channel for setup and teardown only.
pub trait QemuPluginIpcControlChannel: Send {
    /// Sends the plugin IPC `Quit` control message.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the control channel cannot accept
    /// the teardown request.
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError>;
}

/// Shared-memory hot-path channel for per-quantum data.
pub trait QemuShmemHotPathChannel: Send {
    /// Returns the retained setup-region backing identity.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when this channel has no mapped setup
    /// region whose descriptor identity can be authenticated.
    #[cfg(unix)]
    fn hot_fork_setup_region_identity(
        &mut self,
    ) -> Result<crucible_shmem::SetupRegionBackingIdentity, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query hot-fork setup-region identity",
            "hot-fork ring imaging is unavailable on this channel",
        ))
    }

    /// Observes both hot-fork admission endpoints for every mapped ring.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when this channel has no mapped setup
    /// region or its retained ABI geometry no longer validates.
    #[cfg(unix)]
    fn hot_fork_ring_io_snapshot(
        &mut self,
    ) -> Result<crucible_shmem::MappedRingIoBarrierSnapshot, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query hot-fork ring I/O barrier",
            "hot-fork ring imaging is unavailable on this channel",
        ))
    }

    /// Captures one bounded canonical image of every held ring-backed range.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when this channel has no mapped setup
    /// region, either endpoint is open or active, or the exact image exceeds
    /// `maximum_bytes`.
    #[cfg(unix)]
    fn capture_hot_fork_ring_image(
        &mut self,
        _maximum_bytes: usize,
    ) -> Result<crucible_shmem::HotForkRingImage, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "capture hot-fork ring image",
            "hot-fork ring imaging is unavailable on this channel",
        ))
    }

    /// Clones the scheduler-owned continuation onto one private ring mapping.
    ///
    /// Implementations must preserve every host-only cursor, pending value,
    /// coverage continuation, selectable continuation, and send authorizer while
    /// leaving the source channel unchanged. The supplied mapping has already
    /// passed the source/destination ring-image proof.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when this channel cannot clone its
    /// complete continuation or the private mapping no longer matches it.
    #[cfg(target_os = "linux")]
    fn clone_hot_fork_host_continuation(
        &self,
        _mapping: &QemuHotForkPrivateRingMapping,
    ) -> Result<Box<dyn QemuShmemHotPathChannel>, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "clone hot-fork shared-memory host continuation",
            "this shared-memory channel does not implement hot-fork continuation cloning",
        ))
    }

    /// Arms a hot-fork child's inherited instruction counter as its ceiling.
    ///
    /// A child's private ring carries the source's queue contents but a fresh
    /// node slot, so its scheduler ceiling starts at zero while the plugin
    /// still stands at the source's counter; the first control boundary would
    /// publish that counter past the ceiling and abort. Arming the inherited
    /// counter before any host request, without a wake, lets the child
    /// publish exactly where the source stopped.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when this channel cannot arm a ceiling
    /// or the counter is behind the slot's published counter.
    #[cfg(target_os = "linux")]
    fn arm_hot_fork_child_ceiling(
        &mut self,
        _inherited_icount: u64,
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "arm hot-fork child ceiling",
            "this shared-memory channel does not implement hot-fork child arming",
        ))
    }

    /// Captures both directed network rings and the host injection cursor.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when either quiesced ring cannot be
    /// snapshotted exactly.
    fn checkpoint_network_transport(
        &mut self,
    ) -> Result<crate::QemuNetworkTransportCheckpoint, QemuNodeChannelError>;

    /// Restores both directed network rings and the host injection cursor.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the checkpoint is malformed or
    /// cannot be restored atomically into the mapped rings.
    fn restore_network_transport(
        &mut self,
        checkpoint: &crate::QemuNetworkTransportCheckpoint,
    ) -> Result<(), QemuNodeChannelError>;

    /// Enqueues one guest-agent request through the public shared-memory ABI.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when guest introspection is unavailable
    /// or the request queue cannot accept the record.
    fn send_guest_introspection(
        &mut self,
        _record: GuestIntrospectionRecord,
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "send guest introspection",
            "guest introspection is unavailable on this channel",
        ))
    }

    /// Dequeues one guest-agent response, if one is currently available.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when guest introspection is unavailable
    /// or the response queue is malformed.
    fn receive_guest_introspection(
        &mut self,
    ) -> Result<Option<GuestIntrospectionRecord>, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "receive guest introspection",
            "guest introspection is unavailable on this channel",
        ))
    }

    /// Returns whether this channel owns a plugin-to-host coverage queue.
    ///
    /// The registration-time value is immutable. Direct node APIs use it to
    /// reject an advance before guest execution when no unified-log owner was
    /// supplied.
    fn coverage_enabled(&self) -> bool {
        false
    }

    /// Reads the node's current retired-instruction count.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory state cannot be
    /// observed.
    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError>;

    /// Reads the coherent plugin logical/raw time calibration.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory state cannot be
    /// observed or carries an impossible raw/logical relationship.
    fn logical_time_calibration(
        &mut self,
    ) -> Result<QemuLogicalTimeCalibration, QemuNodeChannelError>;

    /// Starts a split quantum by publishing `horizon` through shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory hot path cannot
    /// publish the scheduler ceiling or wake the plugin.
    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError>;

    /// Polls a split quantum without consuming its pending token.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory completion report
    /// cannot be read or is not yet visible.
    fn poll_quantum(
        &mut self,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError>;

    /// Finishes a split quantum after the bounded host-I/O runtime completes.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory completion report
    /// cannot be read.
    fn finish_quantum(
        &mut self,
        mut pending: QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        self.poll_quantum(&mut pending)
    }

    /// Publishes one scheduler-commanded preemption before its bounded RUN.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the command is invalid or a prior
    /// command remains unconsumed.
    fn publish_preemption_command(
        &mut self,
        command: SchedulerPreemptionCommand,
    ) -> Result<(), QemuNodeChannelError>;

    /// Publishes one authenticated fault command at a scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the fault transport is absent,
    /// full, corrupt, or rejects the command envelope.
    fn enqueue_fault_command(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<(), QemuNodeChannelError>;

    /// Removes one completed fault result from the lossless result transport.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the result transport is absent or
    /// corrupt.
    fn dequeue_fault_result(&mut self)
    -> Result<Option<DequeuedFaultResult>, QemuNodeChannelError>;

    /// Removes one authenticated installed-rule occurrence event.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the event transport is absent,
    /// corrupt, or fails evidence authentication.
    fn dequeue_fault_event(&mut self) -> Result<Option<DequeuedFaultEvent>, QemuNodeChannelError>;

    /// Reports whether an installed-rule event awaits boundary admission.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the event transport is invalid.
    fn fault_event_pending(&mut self) -> Result<bool, QemuNodeChannelError>;

    /// Returns the number of published installed-rule events without consuming them.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the event transport is invalid.
    fn fault_event_count(&mut self) -> Result<usize, QemuNodeChannelError>;

    /// Authenticates and copies installed-rule events without consuming them.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the transport is invalid,
    /// destination storage is insufficient, or evidence does not authenticate.
    fn snapshot_fault_events(
        &mut self,
        destination: &mut Vec<DequeuedFaultEvent>,
        canonical_payload_bytes: &mut usize,
        configured_payload_bytes: usize,
        configured_inline_payload_bytes: usize,
    ) -> Result<(), QemuNodeError>;
    /// Advances the node to `horizon` or until it pauses earlier.
    ///
    /// This helper is retained for direct channel tests and already-completed
    /// quanta. [`QemuNode`] uses the split methods through the bounded async
    /// driver.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory advance request
    /// cannot complete.
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, QemuNodeChannelError> {
        let pending = self.start_quantum(horizon)?;
        self.finish_quantum(pending)
            .map(|completion| completion.outcome)
    }

    /// Drains coverage observations at the current completed boundary.
    ///
    /// Implementations without an enabled coverage transport return an empty
    /// batch. The caller must append a non-empty batch to the unified event log
    /// before continuing or tearing down the node.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared coverage ring is corrupt
    /// or contains an observation after the published boundary.
    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, QemuNodeChannelError> {
        Ok(Vec::new())
    }

    /// Drains causal decisions completed by synchronous guest callbacks.
    ///
    /// Implementations without a white-box app-random transport return an empty
    /// batch. The authoritative scheduler must validate and append every
    /// returned decision before another quantum begins.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the causal transport is corrupt or
    /// contains an entry after the completed boundary.
    // crucible-lint: allow host-nondeterminism-state -- this boundary returns values without admitting them into engine state.
    fn drain_causal_decisions(&mut self) -> Result<Vec<Decision>, QemuNodeChannelError> {
        Ok(Vec::new())
    }

    /// Drains selectable requests retained at a plugin-requested VMStop.
    ///
    /// Implementations without the selectable transport return an empty batch.
    /// Every returned request retains its exact trap coordinate and guest
    /// virtual reply reservation; semantic choice authority remains host-side.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the marker transport is corrupt or
    /// contains an entry after the completed boundary.
    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<
        Vec<crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest>,
        QemuNodeChannelError,
    > {
        Ok(Vec::new())
    }

    /// Publishes one host-authorized reply for an exact paused selectable request.
    ///
    /// The plugin remains the sole owner of guest-memory mutation and verifies
    /// the request sequence and trap coordinate again before resuming guest
    /// execution.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the request is not at the current
    /// boundary, the reply sequence or reservation is incompatible, or the
    /// single-entry host-to-plugin ring is unavailable, corrupt, or full.
    fn enqueue_selectable_reply(
        &mut self,
        _pending: &crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "enqueue selectable reply",
            "selectable replies are unavailable on this channel",
        ))
    }

    /// Returns the exact host-mirrored selectable catalog plan, when enabled.
    #[must_use]
    fn selectable_catalog_plan(
        &self,
    ) -> Option<&crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan> {
        None
    }

    /// Reports whether no host-authorized reply awaits plugin consumption.
    #[must_use]
    fn selectable_reply_is_checkpoint_quiescent(&self) -> bool {
        true
    }

    /// Delivers a deterministic frame through the shared-memory input ring.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the frame cannot be delivered.
    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError>;

    /// Delivers a deterministic frame at its scheduler-resolved instruction count.
    ///
    /// Channels that do not expose timestamped injection may inherit the legacy
    /// boundary-relative delivery behavior. Production shared-memory channels
    /// override this method so the event-log timestamp reaches QEMU unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the frame cannot be delivered at
    /// `delivery_icount`.
    fn deliver_frame_at(
        &mut self,
        input: BackendInput,
        delivery_icount: Icount,
    ) -> Result<(), QemuNodeChannelError> {
        let _ = delivery_icount;
        self.deliver_frame(input)
    }

    /// Reads one emitted frame from the shared-memory output ring.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the output ring cannot be read.
    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError>;

    /// Reads the current idle state from shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the idle state cannot be observed.
    fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError>;

    /// Reads the current execution fingerprint from the shared-memory data path.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the fingerprint cannot be read.
    fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError>;

    /// Reads the complete plugin-published fingerprint sample.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the sample is absent or invalid.
    fn fingerprint_sample(&mut self) -> Result<QemuFingerprintSample, QemuNodeChannelError>;
}

/// Type-erased token returned after a shared-memory quantum is started.
pub struct QemuNodePendingQuantum {
    token: Box<dyn Any>,
    completion_fence: Option<QemuAdvanceCompletionFence>,
}

impl QemuNodePendingQuantum {
    /// Wraps a concrete pending-quantum token.
    #[must_use]
    pub fn new<T>(token: T) -> Self
    where
        T: Any,
    {
        Self {
            token: Box::new(token),
            completion_fence: None,
        }
    }

    /// Wraps a token whose scheduler input requires a fresh plugin publication.
    #[must_use]
    pub fn new_with_completion_fence<T>(token: T, fence: QemuAdvanceCompletionFence) -> Self
    where
        T: Any,
    {
        Self {
            token: Box::new(token),
            completion_fence: Some(fence),
        }
    }

    /// Returns the optional publication fence carried by this quantum.
    #[must_use]
    pub const fn completion_fence(&self) -> Option<QemuAdvanceCompletionFence> {
        self.completion_fence
    }

    /// Recovers the concrete token expected by the finishing channel.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the token came from a different
    /// shared-memory channel implementation.
    pub fn downcast_mut<T>(
        &mut self,
        operation: &'static str,
    ) -> Result<&mut T, QemuNodeChannelError>
    where
        T: Any,
    {
        self.token.downcast_mut().ok_or_else(|| {
            QemuNodeChannelError::new(operation, "pending quantum token type mismatch")
        })
    }
}

/// QMP machine-control channel for snapshot and quit commands.
pub trait QemuQmpMachineControlChannel: Send {
    /// Stops guest execution for a checkpoint transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot confirm the paused state.
    fn stop_for_checkpoint(&mut self) -> Result<(), QemuNodeChannelError>;

    /// Resumes guest execution after a checkpoint transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU does not acknowledge the
    /// running-state transition. The next bounded step proves execution.
    fn resume_after_checkpoint(&mut self) -> Result<(), QemuNodeChannelError>;

    /// Queries QEMU's exact hot-fork readiness proof report.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_readiness(
        &mut self,
    ) -> Result<crate::QmpHotForkReadiness, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_readiness",
            "hot-fork readiness is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact bounded active-thread registry.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_thread_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkThreadInventory, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_thread_inventory",
            "hot-fork thread inventory is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact bounded observational RCU inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_rcu_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkRcuInventory, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_rcu_inventory",
            "hot-fork RCU inventory is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact bounded observational AioContext inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_aio_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkAioInventory, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_aio_inventory",
            "hot-fork AIO inventory is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact bounded allocated-AIO-handler inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_aio_handler_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkAioHandlerInventory, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_aio_handler_inventory",
            "hot-fork AIO-handler inventory is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact bounded allocated-block-backend inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_block_backend_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkBlockBackendInventory, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_block_backend_inventory",
            "hot-fork block-backend inventory is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact sealed Crucible plugin-resource inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_plugin_resource_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkPluginResourceInventory, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_plugin_resource_inventory",
            "hot-fork plugin-resource inventory is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact registered fork-child runtime state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_child_runtime(
        &mut self,
    ) -> Result<crate::QmpHotForkChildRuntimeState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_child_runtime",
            "hot-fork child-runtime observation is not implemented by this QMP channel",
        ))
    }

    /// Queries the retained Crucible plugin callback/ring/worker barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<crate::QmpHotForkPluginBarrierState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_plugin_barrier",
            "hot-fork plugin barrier is not implemented by this QMP channel",
        ))
    }

    /// Starts or advances QEMU's retained hot-fork template transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation, subsystem
    /// barrier acquisition or rollback, or strict response validation fails.
    fn prepare_hot_fork_template(
        &mut self,
        _block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "prepare_hot_fork_template",
            "hot-fork template coordination is not implemented by this QMP channel",
        ))
    }

    /// Acquires all retained template barriers before child-resource staging.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when bounded preparation fails or the
    /// channel does not implement generation-bound acquisition.
    fn prepare_hot_fork_template_barriers(
        &mut self,
        _block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "prepare_hot_fork_template_barriers",
            "bounded hot-fork barrier acquisition is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's retained hot-fork template transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// response validation fails.
    fn query_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_template",
            "hot-fork template coordination is not implemented by this QMP channel",
        ))
    }

    /// Aborts QEMU's retained hot-fork template transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation, barrier
    /// rollback, or strict response validation fails.
    fn abort_hot_fork_template(
        &mut self,
    ) -> Result<crate::QmpHotForkTemplateState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "abort_hot_fork_template",
            "hot-fork template coordination is not implemented by this QMP channel",
        ))
    }

    /// Forks one exact retained template after all private child resources are sealed.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkCommandError::Rejected`] only when QEMU explicitly
    /// rejects the request before creating a child. Every other command error
    /// is [`QemuHotForkCommandError::Indeterminate`] because a child may exist.
    #[cfg(target_os = "linux")]
    fn hot_fork(
        &mut self,
        _request: crate::QmpHotForkRequest,
    ) -> Result<crate::QmpHotForkState, QemuHotForkCommandError> {
        Err(QemuHotForkCommandError::Rejected {
            source: QemuNodeChannelError::new(
                "fork retained hot-fork template",
                "hot-fork execution is not implemented by this QMP channel",
            ),
        })
    }

    /// Queries one exact source-QEMU child-process record through reap.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the generation is unknown, the
    /// exchange fails, or the response violates the retained-state contract.
    #[cfg(target_os = "linux")]
    fn query_hot_fork_child_process(
        &mut self,
        _generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query retained hot-fork child process",
            "hot-fork child-process observation is not implemented by this QMP channel",
        ))
    }

    /// Releases one exact source-QEMU child-process record after reap.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] while the child is running, when the
    /// generation is unknown, when the exchange fails, or when the released
    /// response violates the retained-state contract.
    #[cfg(target_os = "linux")]
    fn release_hot_fork_child_process(
        &mut self,
        _generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "release retained hot-fork child process",
            "hot-fork child-process release is not implemented by this QMP channel",
        ))
    }

    /// Imports and retains one target-attempt process contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when descriptor transfer fails, QEMU
    /// rejects either exact kernel identity, or the template generation differs.
    #[cfg(target_os = "linux")]
    fn install_hot_fork_child_process_contract(
        &mut self,
        _names: &crate::QmpHotForkChildProcessContractNames,
        _cgroup: BorrowedFd<'_>,
        _cgroup_procs: BorrowedFd<'_>,
        _cancellation: BorrowedFd<'_>,
        _identity: crate::QmpHotForkChildProcessContractIdentity,
        _template_generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "install hot-fork child process contract",
            "hot-fork child process contract transfer is not implemented by this QMP channel",
        ))
    }

    /// Releases one exact QEMU-owned target process contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the retained basis differs or the
    /// source QEMU cannot release both descriptors.
    #[cfg(target_os = "linux")]
    fn release_hot_fork_child_process_contract(
        &mut self,
        _names: &crate::QmpHotForkChildProcessContractNames,
        _identity: crate::QmpHotForkChildProcessContractIdentity,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "release hot-fork child process contract",
            "hot-fork child process contract release is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's retained target process contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O or strict response
    /// validation fails.
    fn query_hot_fork_child_process_contract(
        &mut self,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query hot-fork child process contract",
            "hot-fork child process contract query is not implemented by this QMP channel",
        ))
    }

    /// Imports every child-private destination and stages the one-shot plan.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when descriptor transfer fails, QEMU
    /// rejects a destination or root, or the template generation differs.
    #[cfg(target_os = "linux")]
    fn install_hot_fork_child_files(
        &mut self,
        _files: &[crate::QmpHotForkChildFile],
        _descriptors: &[BorrowedFd<'_>],
        _maximum_bytes: u64,
        _template_generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "install hot-fork child files",
            "hot-fork child file transfer is not implemented by this QMP channel",
        ))
    }

    /// Releases one exact QEMU-owned child-private file plan.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the generation differs or the
    /// source QEMU cannot release the plan.
    #[cfg(target_os = "linux")]
    fn release_hot_fork_child_files(
        &mut self,
        _generation: u64,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "release hot-fork child files",
            "hot-fork child file release is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's retained child-private file plan.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O or strict response
    /// validation fails.
    fn query_hot_fork_child_files(
        &mut self,
    ) -> Result<crate::QmpHotForkChildFilesState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query hot-fork child files",
            "hot-fork child file query is not implemented by this QMP channel",
        ))
    }

    /// Imports one held branch-private ring descriptor into the QEMU template.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when this channel cannot transfer Unix
    /// descriptors, standard QMP `getfd` does not acknowledge the exact name,
    /// or QEMU cannot duplicate and authenticate `identity`.
    #[cfg(target_os = "linux")]
    fn install_hot_fork_private_ring_descriptor(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _descriptor: BorrowedFd<'_>,
        _identity: crucible_shmem::SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "install hot-fork private ring descriptor",
            "hot-fork descriptor transfer is not implemented by this QMP channel",
        ))
    }

    /// Closes one branch-private ring descriptor retained by the QEMU template.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot release its retained
    /// duplicate under the exact identity, the channel cannot exchange
    /// standard QMP `closefd`, or the monitor no longer owns the exact name.
    #[cfg(target_os = "linux")]
    fn close_hot_fork_private_ring_descriptor(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _identity: crucible_shmem::SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "close hot-fork private ring descriptor",
            "hot-fork descriptor close is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact retained branch-private ring descriptor state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// response validation fails.
    fn query_hot_fork_private_rings(
        &mut self,
    ) -> Result<crate::QmpHotForkPrivateRingState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query hot-fork private rings",
            "hot-fork private-ring query is not implemented by this QMP channel",
        ))
    }

    /// Imports branch-private plugin control and wake endpoints into QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the channel cannot transfer both
    /// Unix descriptors or QEMU cannot authenticate the exact endpoint and
    /// private-ring basis.
    #[cfg(target_os = "linux")]
    fn install_hot_fork_plugin_endpoints(
        &mut self,
        _control_name: &crate::QmpDescriptorName,
        _control: BorrowedFd<'_>,
        _wake_name: &crate::QmpDescriptorName,
        _wake: BorrowedFd<'_>,
        _identity: crate::QmpHotForkPluginEndpointIdentity,
        _private_ring_generation: u64,
    ) -> Result<crate::QmpHotForkPluginEndpointState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "install hot-fork plugin endpoints",
            "hot-fork plugin endpoint transfer is not implemented by this QMP channel",
        ))
    }

    /// Closes plugin endpoints retained by the QEMU template and monitor.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot release the exact
    /// retained pair or either standard monitor name cannot be closed.
    #[cfg(target_os = "linux")]
    fn close_hot_fork_plugin_endpoints(
        &mut self,
        _control_name: &crate::QmpDescriptorName,
        _wake_name: &crate::QmpDescriptorName,
        _identity: crate::QmpHotForkPluginEndpointIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "close hot-fork plugin endpoints",
            "hot-fork plugin endpoint close is not implemented by this QMP channel",
        ))
    }

    /// Imports one branch-private child diagnostics stream into QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when this channel cannot transfer Unix
    /// descriptors or QEMU cannot authenticate the exact stream and template.
    #[cfg(target_os = "linux")]
    fn install_hot_fork_child_diagnostics(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _descriptor: BorrowedFd<'_>,
        _socket_cookie: u64,
        _template_generation: u64,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "install hot-fork child diagnostics",
            "hot-fork child diagnostics transfer is not implemented by this QMP channel",
        ))
    }

    /// Closes the exact child diagnostics stream retained by QEMU and monitor.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when either ownership layer cannot be
    /// released in exact order.
    #[cfg(target_os = "linux")]
    fn close_hot_fork_child_diagnostics(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "close hot-fork child diagnostics",
            "hot-fork child diagnostics close is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact retained child diagnostics state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the query or strict response
    /// validation fails.
    fn query_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query hot-fork child diagnostics",
            "hot-fork child diagnostics query is not implemented by this QMP channel",
        ))
    }

    /// Imports one branch-private child QMP stream into QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when this channel cannot transfer Unix
    /// descriptors or QEMU cannot authenticate the exact stream and template.
    #[cfg(target_os = "linux")]
    fn install_hot_fork_child_qmp(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _descriptor: BorrowedFd<'_>,
        _socket_cookie: u64,
        _template_generation: u64,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "install hot-fork child QMP",
            "hot-fork child QMP transfer is not implemented by this QMP channel",
        ))
    }

    /// Closes the exact child QMP stream retained by QEMU and monitor.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when either ownership layer cannot be
    /// released in exact order.
    #[cfg(target_os = "linux")]
    fn close_hot_fork_child_qmp(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "close hot-fork child QMP",
            "hot-fork child QMP close is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact retained child QMP state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the query or strict response
    /// validation fails.
    fn query_hot_fork_child_qmp(
        &mut self,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query hot-fork child QMP",
            "hot-fork child QMP query is not implemented by this QMP channel",
        ))
    }

    /// Imports one branch-private child console stream into QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when this channel cannot transfer Unix
    /// descriptors or QEMU cannot authenticate the exact console and template.
    #[cfg(target_os = "linux")]
    fn install_hot_fork_child_console(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _descriptor: BorrowedFd<'_>,
        _socket_cookie: u64,
        _template_generation: u64,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "install hot-fork child console",
            "hot-fork child console transfer is not implemented by this QMP channel",
        ))
    }

    /// Closes the exact child console retained by QEMU and monitor.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when either ownership layer cannot be
    /// released in exact order.
    #[cfg(target_os = "linux")]
    fn close_hot_fork_child_console(
        &mut self,
        _name: &crate::QmpDescriptorName,
        _socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "close hot-fork child console",
            "hot-fork child console close is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact retained child-console state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the query or strict response
    /// validation fails.
    fn query_hot_fork_child_console(
        &mut self,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query hot-fork child console",
            "hot-fork child console query is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact bounded allocated-bottom-half inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_bottom_half_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkBottomHalfInventory, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_bottom_half_inventory",
            "hot-fork bottom-half inventory is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact bounded observational mutex ownership inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_mutex_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkMutexInventory, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_mutex_inventory",
            "hot-fork mutex inventory is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact bounded observational live-timer inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_timer_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkTimerInventory, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_timer_inventory",
            "hot-fork timer inventory is not implemented by this QMP channel",
        ))
    }

    /// Queries QEMU's exact bounded monitor/parser inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the QMP operation or strict
    /// versioned response validation fails.
    fn query_hot_fork_monitor_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkMonitorInventory, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "query_hot_fork_monitor_inventory",
            "hot-fork monitor inventory is not implemented by this QMP channel",
        ))
    }

    /// Completes an authenticated terminal lifecycle transition without
    /// expecting QEMU to resume guest execution.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot acknowledge the
    /// terminal completion command.
    fn complete_terminal_lifecycle_exit(
        &mut self,
        action: crucible::ContentHash,
        evidence: crucible::ContentHash,
        process_generation: u64,
    ) -> Result<(), QemuNodeChannelError>;

    /// Saves VMState under the supplied checkpoint identity.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot complete the save job.
    fn save_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError>;

    /// Deletes VMState stored under the supplied checkpoint identity.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot complete the delete job.
    fn delete_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError>;

    /// Requests QEMU termination through QMP `quit`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot send the quit command.
    fn quit(&mut self) -> Result<(), QemuNodeChannelError>;

    /// Sends the fixed fork-time activation token to the dormant guest bootstrap.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the channel has no activation
    /// device or QMP rejects the bounded command.
    fn activate_debug_guest(&mut self) -> Result<(), QemuNodeChannelError>;
}
