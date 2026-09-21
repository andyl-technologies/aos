//! Hot-fork coordinator surface of the typed QMP client.
//!
//! These methods drive QEMU's retained-template coordinator through its
//! aggregate preparation transaction, reversible barriers, fork operation,
//! and child-process records. They share the client's private command
//! execution with the general-purpose surface in the parent module.
use super::*;

impl<S> QmpClient<S>
where
    S: QmpTimeoutStream,
{
    /// Returns QEMU's exact sealed inventory of Crucible plugin resources.
    ///
    /// The OOB query binds the plugin/process identity, shared-memory backing,
    /// descriptors, feature resources, and plugin/QEMU callback masks. It is
    /// observational and cannot acknowledge hot-fork proof bit 6.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, masks, identities, descriptor
    /// relationships, feature derivations, or completeness rule.
    pub fn query_hot_fork_plugin_resource_inventory(
        &mut self,
    ) -> Result<QmpHotForkPluginResourceInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkPluginResourceInventory)?;
        parse_hot_fork_plugin_resource_inventory(&response.value)
    }

    /// Returns QEMU's exact registered fork-child runtime state.
    ///
    /// The OOB query invokes only the runtime's observational action and binds
    /// it to the complete plugin resource manifest and current process
    /// generation. It neither initializes nor releases a child and cannot
    /// acknowledge hot-fork proof bit 8.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails or the response violates
    /// the closed schema, registration/manifest relationship, process-
    /// generation succession, worker masks, phase flags, or inert-template
    /// shape.
    pub fn query_hot_fork_child_runtime(
        &mut self,
    ) -> Result<QmpHotForkChildRuntimeState, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkChildRuntime)?;
        parse_hot_fork_child_runtime_state(&response.value)
    }

    /// Holds the reversible Crucible plugin callback barrier.
    ///
    /// The command returns immediately after rejecting new covered callbacks;
    /// callers query again until [`QmpHotForkPluginBarrierState::quiescent`]
    /// becomes true. This does not freeze host-side ring producers or authorize
    /// a process fork.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QEMU is not at its exact paused boundary, the
    /// plugin did not register the barrier, or the response violates the closed
    /// schema or hold postcondition.
    pub fn hold_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<QmpHotForkPluginBarrierState, QmpError> {
        self.hot_fork_plugin_barrier(HotForkPluginBarrierAction::Hold)
    }

    /// Observes the reversible Crucible plugin callback barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the QMP exchange fails or the response violates
    /// the closed barrier schema and derived quiescence relationship.
    pub fn query_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<QmpHotForkPluginBarrierState, QmpError> {
        self.hot_fork_plugin_barrier(HotForkPluginBarrierAction::Query)
    }

    /// Releases the reversible Crucible plugin callback barrier.
    ///
    /// Permanent teardown closure is never reopened by this operation.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the QMP exchange fails, the plugin did not
    /// register the barrier, or the response violates the closed schema or
    /// release postcondition.
    pub fn release_hot_fork_plugin_barrier(
        &mut self,
    ) -> Result<QmpHotForkPluginBarrierState, QmpError> {
        self.hot_fork_plugin_barrier(HotForkPluginBarrierAction::Release)
    }

    /// Holds QEMU's reversible RCU admission and drain barrier.
    ///
    /// New outer read-side entries and callback submissions are parked
    /// immediately. Already-admitted work drains asynchronously, so callers
    /// query again until [`QmpHotForkRcuBarrierState::quiescent`] is true.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QEMU is not at the exact paused boundary, the
    /// QMP exchange fails, or the response violates the closed barrier schema
    /// or hold postcondition.
    pub fn hold_hot_fork_rcu_barrier(&mut self) -> Result<QmpHotForkRcuBarrierState, QmpError> {
        self.hot_fork_rcu_barrier(HotForkRcuBarrierAction::Hold)
    }

    /// Observes QEMU's reversible RCU admission and drain barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the QMP exchange fails or the response
    /// violates the closed barrier schema.
    pub fn query_hot_fork_rcu_barrier(&mut self) -> Result<QmpHotForkRcuBarrierState, QmpError> {
        self.hot_fork_rcu_barrier(HotForkRcuBarrierAction::Query)
    }

    /// Releases QEMU's reversible RCU admission and drain barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the QMP exchange fails or the response
    /// violates the closed barrier schema or release postcondition.
    pub fn release_hot_fork_rcu_barrier(&mut self) -> Result<QmpHotForkRcuBarrierState, QmpError> {
        self.hot_fork_rcu_barrier(HotForkRcuBarrierAction::Release)
    }

    /// Holds QEMU's reversible asynchronous-worker barrier.
    ///
    /// New producers are parked and new callback dispatch is skipped while
    /// already-admitted operations finish. AioContext polling and GLib
    /// dispatch, AioHandler lifecycle and callbacks, coroutine scheduling,
    /// bottom halves, and timers share the retained admission gate. Pending
    /// work remains queued for release or an eventual child reinitializer.
    /// The retained template coordinator acknowledges AIO proof bit 3 only
    /// while this complete held barrier is quiescent.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QEMU is not at the exact paused boundary, the
    /// exchange fails, or the response violates the closed barrier schema or
    /// hold postcondition.
    pub fn hold_hot_fork_async_worker_barrier(
        &mut self,
    ) -> Result<QmpHotForkAsyncWorkerBarrierState, QmpError> {
        self.hot_fork_async_worker_barrier(HotForkAsyncWorkerBarrierAction::Hold)
    }

    /// Observes QEMU's reversible asynchronous-worker barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails or the response violates
    /// the closed barrier schema.
    pub fn query_hot_fork_async_worker_barrier(
        &mut self,
    ) -> Result<QmpHotForkAsyncWorkerBarrierState, QmpError> {
        self.hot_fork_async_worker_barrier(HotForkAsyncWorkerBarrierAction::Query)
    }

    /// Releases QEMU's reversible asynchronous-worker barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails or the response violates
    /// the closed barrier schema or release postcondition.
    pub fn release_hot_fork_async_worker_barrier(
        &mut self,
    ) -> Result<QmpHotForkAsyncWorkerBarrierState, QmpError> {
        self.hot_fork_async_worker_barrier(HotForkAsyncWorkerBarrierAction::Release)
    }

    /// Holds QEMU's native all-block drain section.
    ///
    /// New external block clients are quiesced immediately while already-issued
    /// I/O finishes asynchronously. This barrier does not create or authenticate
    /// an immutable external snapshot and therefore cannot acknowledge hot-fork
    /// proof bit 5 by itself.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QEMU is not at the exact paused boundary, the
    /// current replay/AioContext mode cannot retain the native drain section,
    /// or the response violates the closed barrier schema or hold postcondition.
    pub fn hold_hot_fork_block_barrier(&mut self) -> Result<QmpHotForkBlockBarrierState, QmpError> {
        self.hot_fork_block_barrier(HotForkBlockBarrierAction::Hold)
    }

    /// Observes QEMU's retained all-block drain section.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails or the response violates
    /// the closed barrier schema.
    pub fn query_hot_fork_block_barrier(
        &mut self,
    ) -> Result<QmpHotForkBlockBarrierState, QmpError> {
        self.hot_fork_block_barrier(HotForkBlockBarrierAction::Query)
    }

    /// Releases QEMU's retained all-block drain section.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails or the response violates
    /// the closed barrier schema or release postcondition.
    pub fn release_hot_fork_block_barrier(
        &mut self,
    ) -> Result<QmpHotForkBlockBarrierState, QmpError> {
        self.hot_fork_block_barrier(HotForkBlockBarrierAction::Release)
    }

    /// Starts or advances QEMU's retained hot-fork template transaction.
    ///
    /// QEMU acquires every currently implemented subsystem barrier. A draining
    /// response retains those barriers for another poll or for exact
    /// branch-private resource staging. Once the implemented barriers drain,
    /// an incomplete readiness bitmap remains retained until the caller
    /// advances preparation or explicitly aborts the transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QEMU is not at the exact paused boundary, a
    /// subsystem barrier cannot be acquired or rolled back, another owner holds
    /// the plugin barrier, or the response violates the closed transaction
    /// schema and state relationships.
    pub fn prepare_hot_fork_template(
        &mut self,
        block_snapshot_bindings: &[QmpHotForkBlockSnapshotBinding],
    ) -> Result<QmpHotForkTemplateState, QmpError> {
        self.hot_fork_template(
            HotForkTemplateAction::Prepare,
            Some(block_snapshot_bindings),
        )
    }

    /// Observes QEMU's retained hot-fork template transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails, coordinator ownership was
    /// lost, or the response violates the closed transaction schema.
    pub fn query_hot_fork_template(&mut self) -> Result<QmpHotForkTemplateState, QmpError> {
        self.hot_fork_template(HotForkTemplateAction::Query, None)
    }

    /// Re-adopts one reconstructed immediate child as a fresh template source.
    ///
    /// This transaction consumes the inherited child resource plan. It does
    /// not prepare a descendant: callers must subsequently run the complete
    /// template-barrier preparation before staging any child resources.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the process is not an active reconstructed
    /// child at an exact paused boundary or QEMU cannot detach its immediate
    /// parent contract.
    pub fn adopt_hot_fork_child_as_template_source(
        &mut self,
    ) -> Result<QmpHotForkTemplateState, QmpError> {
        self.hot_fork_template(HotForkTemplateAction::AdoptChild, None)
    }

    /// Aborts QEMU's retained hot-fork template transaction.
    ///
    /// A draining reply retains ownership while main-loop barrier release or
    /// native source restoration is pending. The caller must keep the source
    /// stopped and retry abort until `rollback_complete()` is true.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QEMU cannot roll back an acquired barrier or
    /// the response violates the closed transaction schema and abort
    /// postcondition.
    pub fn abort_hot_fork_template(&mut self) -> Result<QmpHotForkTemplateState, QmpError> {
        self.hot_fork_template(HotForkTemplateAction::Abort, None)
    }

    /// Forks one exact retained hot-fork template on QEMU's main-loop thread.
    ///
    /// A successful response proves that the positive direct child exists and
    /// echoes every generation in `request`. The caller must still retain and
    /// authenticate that direct child through its branch-private QMP endpoint
    /// before admitting guest execution.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when QEMU rejects the pre-fork basis, the exchange
    /// becomes indeterminate, or the result does not echo the exact request.
    /// Explicit QMP command rejection creates no child and leaves the client
    /// usable. Every other error poisons the connection because child creation
    /// may already have occurred.
    pub fn hot_fork(&mut self, request: QmpHotForkRequest) -> Result<QmpHotForkState, QmpError> {
        let result = self
            .send_command_return(QmpCommand::HotFork { request })
            .and_then(|response| parse_hot_fork_state(&response.value, request));
        let pre_fork_rejection = matches!(
            &result,
            Err(QmpError::Command {
                command: QmpCommandKind::HotFork,
                ..
            })
        );
        if result.is_err() && !pre_fork_rejection {
            self.poisoned = true;
            self.stream.get_mut().poison_qmp_stream();
        }
        result
    }

    /// Queries the source QEMU's retained wait status for one fork child.
    ///
    /// The exact child-process generation remains reserved while the child is
    /// running and after QEMU reaps it. This query never releases that record.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the generation is zero or unknown, the
    /// exchange fails, or the response violates the exact generation and
    /// retained-state contract. An explicit QMP command rejection leaves the
    /// connection usable; any transport or response-contract failure poisons
    /// it.
    pub fn query_hot_fork_child_process(
        &mut self,
        generation: u64,
    ) -> Result<QmpHotForkChildProcessState, QmpError> {
        self.hot_fork_child_process(HotForkChildProcessAction::Query, generation)
    }

    /// Releases one reaped child-process record from the source QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] while the child is still running, when the
    /// generation is zero or unknown, when the exchange fails, or when the
    /// response violates the exact released-state contract. An explicit QMP
    /// command rejection leaves the connection usable; any transport or
    /// response-contract failure poisons it.
    pub fn release_hot_fork_child_process(
        &mut self,
        generation: u64,
    ) -> Result<QmpHotForkChildProcessState, QmpError> {
        self.hot_fork_child_process(HotForkChildProcessAction::Release, generation)
    }
}
