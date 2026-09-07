//! Hot-fork coordinator surface of the typed QMP client.
//!
//! These methods observe and drive QEMU's retained-template coordinator:
//! readiness and bounded subsystem inventories, the reversible barriers,
//! template preparation and abort, the fork itself, and the source's
//! child-process records. They share the client's private command
//! execution with the general-purpose surface in the parent module.
use super::*;

impl<S> QmpClient<S>
where
    S: QmpTimeoutStream,
{
    /// Returns QEMU's exact versioned hot-fork readiness proof bitmap.
    ///
    /// This query is observational. It does not pause, prepare, or fork QEMU.
    /// A caller may treat hot fork as available only when
    /// [`QmpHotForkReadiness::ready`] is true; ordinary paused state is
    /// deliberately insufficient.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when QEMU
    /// reports an unknown schema, changes the required proof set, acknowledges
    /// an unknown proof, or contradicts the relationship between its bitmap and
    /// readiness flag.
    pub fn query_hot_fork_readiness(&mut self) -> Result<QmpHotForkReadiness, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkReadiness)?;
        parse_hot_fork_readiness(&response.value)
    }

    /// Returns QEMU's exact bounded active-thread registry.
    ///
    /// The query is audit-only. A structurally complete registry may still
    /// contain unclassified threads and cannot authorize a fork.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, count/name bounds, sorted unique
    /// thread IDs, disposition vocabulary, or derived completeness fields.
    pub fn query_hot_fork_thread_inventory(
        &mut self,
    ) -> Result<QmpHotForkThreadInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkThreadInventory)?;
        parse_hot_fork_thread_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded observational RCU inventory.
    ///
    /// This query does not drain callbacks, hold readers quiescent, or
    /// acknowledge the RCU hot-fork proof.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, reader bound, sorted unique
    /// identifiers, declared counts, or derived completeness relationship.
    pub fn query_hot_fork_rcu_inventory(&mut self) -> Result<QmpHotForkRcuInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkRcuInventory)?;
        parse_hot_fork_rcu_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded observational AioContext inventory.
    ///
    /// This query does not drain or park AIO, bottom halves, handlers, or
    /// timers and does not acknowledge the AIO hot-fork proof.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, context bound, sorted unique
    /// identifiers, home-thread profile, declared aggregates, or derived
    /// completeness relationship.
    pub fn query_hot_fork_aio_inventory(&mut self) -> Result<QmpHotForkAioInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkAioInventory)?;
        parse_hot_fork_aio_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded inventory of every allocated AIO handler.
    ///
    /// The query includes handlers awaiting deferred deletion, their exact
    /// AioContext and descriptor binding, installed callback classes, and
    /// active callback count. It does not drain or park callbacks and cannot
    /// acknowledge hot-fork proof bit 3.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, bound, identifier ordering,
    /// descriptor profile, declared aggregates, or completeness rule.
    pub fn query_hot_fork_aio_handler_inventory(
        &mut self,
    ) -> Result<QmpHotForkAioHandlerInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkAioHandlerInventory)?;
        parse_hot_fork_aio_handler_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded inventory of every allocated block backend.
    ///
    /// The OOB query observes stable backend/AioContext identities, monitor
    /// visibility, root/device attachment, permissions, quiesce depth, queue
    /// policy, and in-flight I/O. It neither traverses nor drains the block
    /// graph and cannot acknowledge hot-fork proof bit 5.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, bound, identifier ordering,
    /// monitor-name profile, declared aggregates, or completeness rule.
    pub fn query_hot_fork_block_backend_inventory(
        &mut self,
    ) -> Result<QmpHotForkBlockBackendInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkBlockBackendInventory)?;
        parse_hot_fork_block_backend_inventory(&response.value)
    }

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

    /// Holds QEMU's reversible asynchronous-source barrier.
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
    pub fn hold_hot_fork_bh_timer_barrier(
        &mut self,
    ) -> Result<QmpHotForkBhTimerBarrierState, QmpError> {
        self.hot_fork_bh_timer_barrier(HotForkBhTimerBarrierAction::Hold)
    }

    /// Observes QEMU's reversible asynchronous-source barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails or the response violates
    /// the closed barrier schema.
    pub fn query_hot_fork_bh_timer_barrier(
        &mut self,
    ) -> Result<QmpHotForkBhTimerBarrierState, QmpError> {
        self.hot_fork_bh_timer_barrier(HotForkBhTimerBarrierAction::Query)
    }

    /// Releases QEMU's reversible asynchronous-source barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the exchange fails or the response violates
    /// the closed barrier schema or release postcondition.
    pub fn release_hot_fork_bh_timer_barrier(
        &mut self,
    ) -> Result<QmpHotForkBhTimerBarrierState, QmpError> {
        self.hot_fork_bh_timer_barrier(HotForkBhTimerBarrierAction::Release)
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

    /// Returns QEMU's exact bounded inventory of every allocated bottom half.
    ///
    /// This query observes inert, pending, active, canceled, and deferred-free
    /// bottom halves. It does not drain or park them and cannot acknowledge
    /// hot-fork proof bit 3.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, bounds, identifier ordering,
    /// state relationships, declared aggregates, or completeness rule.
    pub fn query_hot_fork_bottom_half_inventory(
        &mut self,
    ) -> Result<QmpHotForkBottomHalfInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkBottomHalfInventory)?;
        parse_hot_fork_bottom_half_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded observational mutex ownership inventory.
    ///
    /// This query does not hold a lock barrier across another operation and
    /// does not acknowledge the child-reinitialization hot-fork proof.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, mutex bound, sorted identifiers,
    /// owner/depth relationship, declared aggregates, or completeness rule.
    pub fn query_hot_fork_mutex_inventory(&mut self) -> Result<QmpHotForkMutexInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkMutexInventory)?;
        parse_hot_fork_mutex_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded observational live-timer inventory.
    ///
    /// Initialized but inert timers are absent. This query does not drain or
    /// park pending timers or callbacks and cannot acknowledge hot-fork proof
    /// bit 3.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, timer bound, sorted identifiers,
    /// pending/expiry relationship, declared aggregates, or completeness rule.
    pub fn query_hot_fork_timer_inventory(&mut self) -> Result<QmpHotForkTimerInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkTimerInventory)?;
        parse_hot_fork_timer_inventory(&response.value)
    }

    /// Returns QEMU's exact bounded observational monitor/parser inventory.
    ///
    /// This query neither rebuilds child monitor state nor acknowledges the
    /// child-runtime hot-fork proof.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError`] when the request or response fails, or when the
    /// response violates the closed schema, monitor bound, aggregate
    /// relationships, or completeness rule.
    pub fn query_hot_fork_monitor_inventory(
        &mut self,
    ) -> Result<QmpHotForkMonitorInventory, QmpError> {
        let response = self.send_command_return(QmpCommand::QueryHotForkMonitorInventory)?;
        parse_hot_fork_monitor_inventory(&response.value)
    }
}
