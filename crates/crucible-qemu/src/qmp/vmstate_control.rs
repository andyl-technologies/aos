//! Checkpoint-tagged VMState control over typed QMP commands.

use std::io::Write;
use std::os::fd::BorrowedFd;
use std::os::unix::net::UnixStream;

use crucible::Checkpoint;
use crucible_shmem::SetupRegionBackingIdentity;

use super::{
    QmpClient, QmpCommandComplete, QmpDescriptorName, QmpError, QmpHotForkAioHandlerInventory,
    QmpHotForkAioInventory, QmpHotForkBhTimerBarrierState, QmpHotForkBlockBackendInventory,
    QmpHotForkBlockBarrierState, QmpHotForkBlockSnapshotBinding, QmpHotForkBottomHalfInventory,
    QmpHotForkChildProcessState, QmpHotForkChildRuntimeState, QmpHotForkMonitorInventory,
    QmpHotForkMutexInventory, QmpHotForkPluginBarrierState, QmpHotForkPluginResourceInventory,
    QmpHotForkRcuBarrierState, QmpHotForkRcuInventory, QmpHotForkReadiness, QmpHotForkRequest,
    QmpHotForkState, QmpHotForkTemplateState, QmpHotForkThreadInventory, QmpHotForkTimerInventory,
    QmpIoTimeoutPolicy, QmpJobPollPolicy, QmpRunStateKind, QmpSnapshotTag, QmpTimeoutStream,
};
#[cfg(target_os = "linux")]
use crate::QemuHotForkCommandError;
use crate::{
    QMP_DEBUG_GUEST_ACTIVATION_TOKEN, QemuLoadvmCommandAuthorization, QemuNodeChannelError,
};

/// Checkpoint-tagged VMState control surface over a typed QMP client.
///
/// This wrapper is intentionally narrower than
/// [`crate::QemuQmpMachineControlChannel`]: callers must supply the checkpoint
/// metadata they are saving or restoring, and restore requires an explicit
/// [`QemuLoadvmCommandAuthorization`] token. It therefore exposes the low-level
/// QMP VMState operations needed by a real realization executor without hiding
/// replay-oracle admission behind the generic backend restore API.
#[derive(Debug)]
pub struct QemuQmpVmStateControlChannel<S> {
    client: QmpClient<S>,
    debug_guest_activation_stream: Option<UnixStream>,
}

impl<S> QemuQmpVmStateControlChannel<S>
where
    S: QmpTimeoutStream,
{
    /// Builds a VMState control channel over an already-negotiated QMP client.
    #[must_use]
    pub const fn new(client: QmpClient<S>) -> Self {
        Self {
            client,
            debug_guest_activation_stream: None,
        }
    }

    /// Returns a channel with the pre-established guest activation stream.
    #[must_use]
    pub fn with_debug_guest_activation_stream(mut self, stream: UnixStream) -> Self {
        self.debug_guest_activation_stream = Some(stream);
        self
    }

    /// Returns a channel whose QEMU launch already has the inert endpoint.
    #[must_use]
    pub fn with_predeclared_debug_guest_endpoint(mut self) -> Self {
        self.client = self.client.with_predeclared_debug_guest_endpoint();
        self
    }

    /// Connects to an established QMP stream and negotiates capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QMP connection setup or capability negotiation
    /// fails.
    pub fn connect(stream: S) -> Result<Self, QmpError> {
        QmpClient::connect(stream).map(Self::new)
    }

    /// Connects with explicit snapshot-job and stream timeout policies.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QMP connection setup or capability negotiation
    /// fails.
    pub fn connect_with_policies(
        stream: S,
        job_poll_policy: QmpJobPollPolicy,
        io_timeout_policy: QmpIoTimeoutPolicy,
    ) -> Result<Self, QmpError> {
        QmpClient::connect_with_policies(stream, job_poll_policy, io_timeout_policy).map(Self::new)
    }

    /// Returns the wrapped typed QMP client.
    #[must_use]
    pub fn into_inner(self) -> QmpClient<S> {
        self.client
    }

    /// Stops guest execution for an exact checkpoint transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot enter and confirm the
    /// paused run state.
    pub fn stop_for_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        let state = self.client.query_status()?;
        if !state.running && state.status == crate::QmpRunStateKind::Paused {
            return Ok(());
        }
        self.client
            .stop()
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Resumes guest execution after an exact checkpoint transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU does not acknowledge the
    /// running-state transition. The first scheduler-authorized node step is
    /// the execution proof because an idle restored simulator can park before
    /// servicing a follow-up QMP status query.
    pub fn resume_after_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.client
            .cont_acknowledged()
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact versioned hot-fork readiness proof bitmap.
    ///
    /// This operation is observational. It does not prepare a template or
    /// infer readiness from ordinary paused state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed readiness schema.
    pub fn query_hot_fork_readiness(
        &mut self,
    ) -> Result<QmpHotForkReadiness, QemuNodeChannelError> {
        self.client
            .query_hot_fork_readiness()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact bounded active-thread registry.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed inventory schema and bounds.
    pub fn query_hot_fork_thread_inventory(
        &mut self,
    ) -> Result<QmpHotForkThreadInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_thread_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact bounded observational RCU inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed RCU inventory schema and bounds.
    pub fn query_hot_fork_rcu_inventory(
        &mut self,
    ) -> Result<QmpHotForkRcuInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_rcu_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact bounded observational AioContext inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed AIO inventory schema and bounds.
    pub fn query_hot_fork_aio_inventory(
        &mut self,
    ) -> Result<QmpHotForkAioInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_aio_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact bounded allocated-AIO-handler inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed AIO-handler inventory schema and bounds.
    pub fn query_hot_fork_aio_handler_inventory(
        &mut self,
    ) -> Result<QmpHotForkAioHandlerInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_aio_handler_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact bounded allocated-block-backend inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed block-backend inventory schema and bounds.
    pub fn query_hot_fork_block_backend_inventory(
        &mut self,
    ) -> Result<QmpHotForkBlockBackendInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_block_backend_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact sealed Crucible plugin-resource inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed plugin-resource schema and relationships.
    pub fn query_hot_fork_plugin_resource_inventory(
        &mut self,
    ) -> Result<QmpHotForkPluginResourceInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_plugin_resource_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact registered fork-child runtime state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed child-runtime schema and relationships.
    pub fn query_hot_fork_child_runtime(
        &mut self,
    ) -> Result<QmpHotForkChildRuntimeState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_child_runtime()
            .map_err(QemuNodeChannelError::from)
    }

    /// Holds the reversible plugin callback barrier without waiting for drain.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU is not at the exact paused
    /// boundary or the barrier exchange/postcondition fails.
    pub fn hold_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<QmpHotForkPluginBarrierState, QemuNodeChannelError> {
        self.client
            .hold_hot_fork_plugin_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries the reversible plugin callback barrier without changing it.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed barrier schema.
    pub fn query_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<QmpHotForkPluginBarrierState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_plugin_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Releases the reversible plugin callback barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or QEMU does not
    /// report the required released postcondition.
    pub fn release_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<QmpHotForkPluginBarrierState, QemuNodeChannelError> {
        self.client
            .release_hot_fork_plugin_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Holds the reversible RCU admission/drain barrier without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU is not at the exact paused
    /// boundary or the barrier exchange/postcondition fails.
    pub fn hold_hot_fork_rcu_barrier(
        &mut self,
    ) -> Result<QmpHotForkRcuBarrierState, QemuNodeChannelError> {
        self.client
            .hold_hot_fork_rcu_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries the reversible RCU admission/drain barrier without changing it.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed barrier schema.
    pub fn query_hot_fork_rcu_barrier(
        &mut self,
    ) -> Result<QmpHotForkRcuBarrierState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_rcu_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Releases the reversible RCU admission/drain barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or QEMU does not
    /// report the required released postcondition.
    pub fn release_hot_fork_rcu_barrier(
        &mut self,
    ) -> Result<QmpHotForkRcuBarrierState, QemuNodeChannelError> {
        self.client
            .release_hot_fork_rcu_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Holds the reversible bottom-half/timer source barrier without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU is not at the exact paused
    /// boundary or the barrier exchange/postcondition fails.
    pub fn hold_hot_fork_bh_timer_barrier(
        &mut self,
    ) -> Result<QmpHotForkBhTimerBarrierState, QemuNodeChannelError> {
        self.client
            .hold_hot_fork_bh_timer_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries the reversible bottom-half/timer source barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed barrier schema.
    pub fn query_hot_fork_bh_timer_barrier(
        &mut self,
    ) -> Result<QmpHotForkBhTimerBarrierState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_bh_timer_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Releases the reversible bottom-half/timer source barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or QEMU does not
    /// report the required released postcondition.
    pub fn release_hot_fork_bh_timer_barrier(
        &mut self,
    ) -> Result<QmpHotForkBhTimerBarrierState, QemuNodeChannelError> {
        self.client
            .release_hot_fork_bh_timer_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Holds QEMU's native all-block drain section.
    ///
    /// This is a reversible I/O-quiescence prerequisite. It does not create or
    /// authenticate an immutable external-snapshot root.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU is not at the exact paused
    /// boundary or the barrier exchange/postcondition fails.
    pub fn hold_hot_fork_block_barrier(
        &mut self,
    ) -> Result<QmpHotForkBlockBarrierState, QemuNodeChannelError> {
        self.client
            .hold_hot_fork_block_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's retained all-block drain section.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed barrier schema.
    pub fn query_hot_fork_block_barrier(
        &mut self,
    ) -> Result<QmpHotForkBlockBarrierState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_block_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Releases QEMU's retained all-block drain section.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or QEMU does not
    /// report the required released postcondition.
    pub fn release_hot_fork_block_barrier(
        &mut self,
    ) -> Result<QmpHotForkBlockBarrierState, QemuNodeChannelError> {
        self.client
            .release_hot_fork_block_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Starts or advances QEMU's retained hot-fork template transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails, a subsystem barrier
    /// cannot be acquired or rolled back, or QEMU violates the closed
    /// transaction schema.
    pub fn prepare_hot_fork_template(
        &mut self,
        block_snapshot_bindings: &[QmpHotForkBlockSnapshotBinding],
    ) -> Result<QmpHotForkTemplateState, QemuNodeChannelError> {
        self.client
            .prepare_hot_fork_template(block_snapshot_bindings)
            .map_err(QemuNodeChannelError::from)
    }

    /// Acquires all retained template barriers before child-resource staging.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O, generation validation,
    /// or bounded barrier acquisition fails.
    pub fn prepare_hot_fork_template_barriers(
        &mut self,
        block_snapshot_bindings: &[QmpHotForkBlockSnapshotBinding],
    ) -> Result<QmpHotForkTemplateState, QemuNodeChannelError> {
        self.client
            .prepare_hot_fork_template_barriers(block_snapshot_bindings)
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's retained hot-fork template transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails, coordinator
    /// ownership was lost, or the response violates the closed schema.
    pub fn query_hot_fork_template(
        &mut self,
    ) -> Result<QmpHotForkTemplateState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_template()
            .map_err(QemuNodeChannelError::from)
    }

    /// Aborts QEMU's retained hot-fork template transaction.
    ///
    /// A draining response requires another abort exchange while retaining the
    /// stopped source; only `rollback_complete()` permits releasing ownership.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot roll back an acquired
    /// barrier or the response violates the closed abort postcondition.
    pub fn abort_hot_fork_template(
        &mut self,
    ) -> Result<QmpHotForkTemplateState, QemuNodeChannelError> {
        self.client
            .abort_hot_fork_template()
            .map_err(QemuNodeChannelError::from)
    }

    /// Forks one exact prepared template with process-boundary error classification.
    ///
    /// An explicit QMP error for the hot-fork command is the protocol's only
    /// proof that no child was created. Transport, framing, response, and echo
    /// failures remain indeterminate; [`QmpClient`] has already poisoned the
    /// connection before this method returns them.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkCommandError::Rejected`] for an explicit pre-fork
    /// command rejection and [`QemuHotForkCommandError::Indeterminate`] for
    /// every other failure.
    #[cfg(target_os = "linux")]
    pub fn hot_fork(
        &mut self,
        request: QmpHotForkRequest,
    ) -> Result<QmpHotForkState, QemuHotForkCommandError> {
        match self.client.hot_fork(request) {
            Ok(state) => Ok(state),
            Err(
                error @ QmpError::Command {
                    command: super::QmpCommandKind::HotFork,
                    ..
                },
            ) => Err(QemuHotForkCommandError::Rejected {
                source: error.into(),
            }),
            Err(error) => Err(QemuHotForkCommandError::Indeterminate {
                source: error.into(),
            }),
        }
    }

    /// Queries one exact source-QEMU child-process record through reap.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the generation is unknown, the exchange
    /// fails, or the response does not match the exact retained-state schema.
    #[cfg(target_os = "linux")]
    pub fn query_hot_fork_child_process(
        &mut self,
        generation: u64,
    ) -> Result<QmpHotForkChildProcessState, QmpError> {
        self.client.query_hot_fork_child_process(generation)
    }

    /// Releases one exact source-QEMU child-process record after reap.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] while the child is running, when the generation is
    /// unknown, when the exchange fails, or when the response does not match
    /// the exact released-state schema.
    #[cfg(target_os = "linux")]
    pub fn release_hot_fork_child_process(
        &mut self,
        generation: u64,
    ) -> Result<QmpHotForkChildProcessState, QmpError> {
        self.client.release_hot_fork_child_process(generation)
    }

    /// Imports and stages one exact target-attempt process contract.
    ///
    /// Standard-QMP names are closed after QEMU has retained authenticated
    /// duplicates; the one-shot stage remains until explicit release.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when either transfer, stage, or monitor
    /// descriptor close fails.
    #[cfg(target_os = "linux")]
    pub fn install_hot_fork_child_process_contract(
        &mut self,
        cgroup_name: &QmpDescriptorName,
        cgroup: BorrowedFd<'_>,
        cancellation_name: &QmpDescriptorName,
        cancellation: BorrowedFd<'_>,
        identity: crate::QmpHotForkChildProcessContractIdentity,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        self.client
            .install_descriptor(cgroup_name, cgroup)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .install_descriptor(cancellation_name, cancellation)
            .map_err(QemuNodeChannelError::from)?;
        let state = self
            .client
            .stage_hot_fork_child_process_contract(cgroup_name, cancellation_name, identity)
            .map_err(QemuNodeChannelError::from)?;
        if state.template_generation() != template_generation {
            return Err(QemuNodeChannelError::new(
                "install hot-fork child process contract",
                "QEMU retained the process contract for another template",
            ));
        }
        self.client
            .close_descriptor(cancellation_name)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .close_descriptor(cgroup_name)
            .map_err(QemuNodeChannelError::from)?;
        Ok(state)
    }

    /// Releases QEMU's exact retained target process contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the retained descriptor basis
    /// differs or the QMP exchange fails.
    #[cfg(target_os = "linux")]
    pub fn release_hot_fork_child_process_contract(
        &mut self,
        cgroup_name: &QmpDescriptorName,
        cancellation_name: &QmpDescriptorName,
        identity: crate::QmpHotForkChildProcessContractIdentity,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        self.client
            .release_hot_fork_child_process_contract(cgroup_name, cancellation_name, identity)
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's target process-contract stage.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O or strict response
    /// validation fails.
    pub fn query_hot_fork_child_process_contract(
        &mut self,
    ) -> Result<crate::QmpHotForkChildProcessContractState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_child_process_contract()
            .map_err(QemuNodeChannelError::from)
    }

    /// Imports one held branch-private ring descriptor into the QEMU template.
    ///
    /// The caller retains its descriptor and mapping. This first imports a
    /// monitor-owned `getfd` copy, then makes QEMU independently duplicate and
    /// authenticate it against `identity`. A successful return does not
    /// authorize a fork, release a ring barrier, or prove child rebinding.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the descriptor-bearing QMP
    /// exchange fails or QEMU does not acknowledge the import. An ambiguous
    /// transfer poisons the underlying QMP client.
    pub fn install_hot_fork_private_ring_descriptor(
        &mut self,
        name: &QmpDescriptorName,
        descriptor: BorrowedFd<'_>,
        identity: SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.client
            .install_descriptor(name, descriptor)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .stage_hot_fork_private_rings(name, identity)
            .map(|_state| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Releases both QEMU-owned and monitor-owned private-ring descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the typed QMP client is poisoned,
    /// the close exchange fails, or QEMU no longer owns the exact name and
    /// backing identity.
    pub fn close_hot_fork_private_ring_descriptor(
        &mut self,
        name: &QmpDescriptorName,
        identity: SetupRegionBackingIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.client
            .release_hot_fork_private_rings(name, identity)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .close_descriptor(name)
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact retained private-ring descriptor state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response is
    /// outside the current closed contract.
    pub fn query_hot_fork_private_rings(
        &mut self,
    ) -> Result<super::QmpHotForkPrivateRingState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_private_rings()
            .map_err(QemuNodeChannelError::from)
    }

    /// Imports branch-private plugin control and wake endpoints into QEMU.
    ///
    /// The caller retains both endpoint pairs. This imports two monitor-owned
    /// `getfd` copies, then makes QEMU independently duplicate and authenticate
    /// them against `identity`. During an active template transaction, QEMU
    /// also captures the exact quiescent plugin-barrier generation and a plan
    /// that resumes every sealed worker class in the parent and reinitializes
    /// every class in a future child. A successful return does not apply the
    /// child plan, recreate a plugin worker, or acknowledge a hot-fork
    /// readiness proof.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when either descriptor-bearing exchange
    /// fails or QEMU does not acknowledge the exact pair. Any ambiguous
    /// transfer poisons the underlying QMP client.
    pub fn install_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &QmpDescriptorName,
        control: BorrowedFd<'_>,
        wake_name: &QmpDescriptorName,
        wake: BorrowedFd<'_>,
        identity: crate::QmpHotForkPluginEndpointIdentity,
        private_ring_generation: u64,
    ) -> Result<crate::QmpHotForkPluginEndpointState, QemuNodeChannelError> {
        self.client
            .install_descriptor(control_name, control)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .install_descriptor(wake_name, wake)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .stage_hot_fork_plugin_endpoints(
                control_name,
                wake_name,
                identity,
                private_ring_generation,
            )
            .map_err(QemuNodeChannelError::from)
    }

    /// Releases QEMU-owned and monitor-owned plugin endpoint descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the typed QMP client is poisoned,
    /// any close exchange fails, or QEMU no longer owns the exact names and
    /// kernel-object identities.
    pub fn close_hot_fork_plugin_endpoints(
        &mut self,
        control_name: &QmpDescriptorName,
        wake_name: &QmpDescriptorName,
        identity: crate::QmpHotForkPluginEndpointIdentity,
    ) -> Result<(), QemuNodeChannelError> {
        self.client
            .release_hot_fork_plugin_endpoints(control_name, wake_name, identity)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .close_descriptor(wake_name)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .close_descriptor(control_name)
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Imports one branch-private child diagnostics stream into QEMU.
    ///
    /// The caller retains both stream endpoints. This imports one monitor-owned
    /// `getfd` copy, then makes QEMU independently duplicate and authenticate
    /// the child endpoint. Complete plan composition remains a later operation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when descriptor transfer fails or QEMU
    /// does not acknowledge the exact stream and template basis.
    pub fn install_hot_fork_child_diagnostics(
        &mut self,
        name: &QmpDescriptorName,
        descriptor: BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        self.client
            .install_descriptor(name, descriptor)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .stage_hot_fork_child_diagnostics(name, socket_cookie, template_generation)
            .map_err(QemuNodeChannelError::from)
    }

    /// Releases QEMU-owned and monitor-owned child diagnostics descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when either exact ownership layer
    /// cannot be released in order.
    pub fn close_hot_fork_child_diagnostics(
        &mut self,
        name: &QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.client
            .release_hot_fork_child_diagnostics(name, socket_cookie)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .close_descriptor(name)
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact retained child diagnostics stream.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O or strict response
    /// validation fails.
    pub fn query_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<crate::QmpHotForkChildDiagnosticState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_child_diagnostics()
            .map_err(QemuNodeChannelError::from)
    }

    /// Imports one branch-private child QMP stream into QEMU.
    ///
    /// The caller retains both stream endpoints. This imports one monitor-owned
    /// `getfd` copy, then makes QEMU independently duplicate and authenticate
    /// the child endpoint. Monitor reconstruction remains a later operation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when descriptor transfer fails or QEMU
    /// does not acknowledge the exact stream and template basis.
    pub fn install_hot_fork_child_qmp(
        &mut self,
        name: &QmpDescriptorName,
        descriptor: BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        self.client
            .install_descriptor(name, descriptor)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .stage_hot_fork_child_qmp(name, socket_cookie, template_generation)
            .map_err(QemuNodeChannelError::from)
    }

    /// Releases QEMU-owned and monitor-owned child QMP descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when either exact ownership layer
    /// cannot be released in order.
    pub fn close_hot_fork_child_qmp(
        &mut self,
        name: &QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.client
            .release_hot_fork_child_qmp(name, socket_cookie)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .close_descriptor(name)
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact retained child QMP stream.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O or strict response
    /// validation fails.
    pub fn query_hot_fork_child_qmp(
        &mut self,
    ) -> Result<crate::QmpHotForkChildQmpState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_child_qmp()
            .map_err(QemuNodeChannelError::from)
    }

    /// Imports one branch-private child console stream into QEMU.
    ///
    /// The caller retains both stream endpoints. This imports one monitor-owned
    /// `getfd` copy, then makes QEMU independently duplicate and authenticate
    /// the child endpoint against the exact `crucible-console` source chardev.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when descriptor transfer fails or QEMU
    /// does not acknowledge the exact stream and template basis.
    pub fn install_hot_fork_child_console(
        &mut self,
        name: &QmpDescriptorName,
        descriptor: BorrowedFd<'_>,
        socket_cookie: u64,
        template_generation: u64,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        self.client
            .install_descriptor(name, descriptor)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .stage_hot_fork_child_console(name, socket_cookie, template_generation)
            .map_err(QemuNodeChannelError::from)
    }

    /// Releases QEMU-owned and monitor-owned child-console descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when either exact ownership layer
    /// cannot be released in order.
    pub fn close_hot_fork_child_console(
        &mut self,
        name: &QmpDescriptorName,
        socket_cookie: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.client
            .release_hot_fork_child_console(name, socket_cookie)
            .map_err(QemuNodeChannelError::from)?;
        self.client
            .close_descriptor(name)
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact retained child-console stream.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O or strict response
    /// validation fails.
    pub fn query_hot_fork_child_console(
        &mut self,
    ) -> Result<crate::QmpHotForkChildConsoleState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_child_console()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact bounded allocated-bottom-half inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed bottom-half inventory schema and bounds.
    pub fn query_hot_fork_bottom_half_inventory(
        &mut self,
    ) -> Result<QmpHotForkBottomHalfInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_bottom_half_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact bounded observational mutex ownership inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed mutex inventory schema and bounds.
    pub fn query_hot_fork_mutex_inventory(
        &mut self,
    ) -> Result<QmpHotForkMutexInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_mutex_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries QEMU's exact bounded observational live-timer inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed timer inventory schema and bounds.
    pub fn query_hot_fork_timer_inventory(
        &mut self,
    ) -> Result<QmpHotForkTimerInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_timer_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Returns QEMU's bounded monitor/parser inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP transport or strict response
    /// validation fails.
    pub fn query_hot_fork_monitor_inventory(
        &mut self,
    ) -> Result<QmpHotForkMonitorInventory, QemuNodeChannelError> {
        self.client
            .query_hot_fork_monitor_inventory()
            .map_err(QemuNodeChannelError::from)
    }

    /// Confirms that stopped-state post-restore calibration preserved the pause.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU cannot report its state or is
    /// not in the exact paused state required after calibration.
    pub(crate) fn confirm_restore_boundary_pause(&mut self) -> Result<(), QemuNodeChannelError> {
        let state = self.client.query_status()?;
        if !state.running && state.status == QmpRunStateKind::Paused {
            return Ok(());
        }
        Err(QmpError::UnexpectedRunState {
            command: super::QmpCommandKind::QueryStatus,
            status: state.status,
            running: state.running,
        }
        .into())
    }

    /// Acknowledges one authenticated terminal lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU does not acknowledge the
    /// terminal completion command before beginning process shutdown.
    pub fn complete_terminal_lifecycle_exit(
        &mut self,
        action: crucible::ContentHash,
        evidence: crucible::ContentHash,
        process_generation: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.client
            .complete_terminal_lifecycle_exit(action, evidence, process_generation)
            .map(|_complete| ())
            .map_err(QemuNodeChannelError::from)
    }

    /// Sends the fixed activation token to the dormant debug guest bootstrap.
    /// The channel retains the socket so QEMU cannot discard queued bytes while
    /// the scheduler still has the guest paused.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when endpoint preparation fails or the
    /// activation stream cannot deliver the fixed token.
    pub fn activate_debug_guest(&mut self) -> Result<(), QemuNodeChannelError> {
        self.client
            .confirm_predeclared_debug_guest_endpoint()
            .map_err(QemuNodeChannelError::from)?;
        let activation = self.debug_guest_activation_stream.as_mut().ok_or_else(|| {
            QemuNodeChannelError::new(
                "activate debug guest",
                "fork-time guest activation stream is not configured",
            )
        })?;
        activation
            .write_all(QMP_DEBUG_GUEST_ACTIVATION_TOKEN.as_bytes())
            .map_err(|error| {
                QemuNodeChannelError::new("write debug guest activation token", error.to_string())
            })?;
        Ok(())
    }

    /// Saves the QEMU VMState under a tag derived from `checkpoint`.
    ///
    /// This operation persists only the QEMU VMState half. The caller remains
    /// responsible for storing the Crucible checkpoint metadata and node blobs.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot save the checkpoint's
    /// VMState snapshot.
    pub fn save_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<QmpCommandComplete, QemuNodeChannelError> {
        let tag = QmpSnapshotTag::from_checkpoint(checkpoint);
        self.client.savevm(&tag).map_err(QemuNodeChannelError::from)
    }

    /// Restores the QEMU VMState tagged by `checkpoint`.
    ///
    /// The authorization token must be issued by the exact snapshot policy for either
    /// replay-oracle probing or admitted runtime realization.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot load the checkpoint's
    /// VMState snapshot.
    pub fn restore_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
        authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<QmpCommandComplete, QemuNodeChannelError> {
        if authorization.purpose() != crate::QemuLoadvmCommandPurpose::ReplayOracleProbe {
            return Err(QemuNodeChannelError::new(
                "qmp",
                "public VMState restore only admits replay-oracle probes",
            ));
        }
        self.restore_checkpoint_vmstate_authorized(checkpoint)
    }

    pub(crate) fn restore_checkpoint_vmstate_authorized(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<QmpCommandComplete, QemuNodeChannelError> {
        let tag = QmpSnapshotTag::from_checkpoint(checkpoint);
        self.client
            .loadvm_authorized(&tag)
            .map_err(QemuNodeChannelError::from)
    }

    /// Deletes the QEMU VMState artifact tagged by `checkpoint`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot complete deletion.
    pub fn delete_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<QmpCommandComplete, QemuNodeChannelError> {
        let tag = QmpSnapshotTag::from_checkpoint(checkpoint);
        self.client
            .delete_snapshot(&tag)
            .map_err(QemuNodeChannelError::from)
    }

    /// Requests graceful QEMU termination through QMP.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP cannot send the quit command.
    pub fn quit(&mut self) -> Result<QmpCommandComplete, QemuNodeChannelError> {
        self.client.quit().map_err(QemuNodeChannelError::from)
    }
}
