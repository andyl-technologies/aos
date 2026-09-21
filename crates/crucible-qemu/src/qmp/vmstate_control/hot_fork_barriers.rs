//! Hot-fork readiness, inventory, barrier, and template QMP operations.

use super::*;

impl<S> QemuQmpVmStateControlChannel<S>
where
    S: QmpTimeoutStream,
{
    /// Queries QEMU's exact versioned hot-fork readiness proof bitmap.
    ///
    /// This operation is observational. It does not prepare a template or
    /// infer readiness from ordinary paused state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// Queries QEMU's exact bounded active-thread registry.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// Queries QEMU's exact bounded observational RCU inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// Queries QEMU's exact bounded observational AioContext inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// Queries QEMU's exact bounded allocated-AIO-handler inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// Queries QEMU's exact bounded allocated-block-backend inventory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
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

    /// Holds the reversible asynchronous-worker barrier without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QEMU is not at the exact paused
    /// boundary or the barrier exchange/postcondition fails.
    pub fn hold_hot_fork_async_worker_barrier(
        &mut self,
    ) -> Result<QmpHotForkAsyncWorkerBarrierState, QemuNodeChannelError> {
        self.client
            .hold_hot_fork_async_worker_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Queries the reversible asynchronous-worker barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or the response does
    /// not satisfy the closed barrier schema.
    pub fn query_hot_fork_async_worker_barrier(
        &mut self,
    ) -> Result<QmpHotForkAsyncWorkerBarrierState, QemuNodeChannelError> {
        self.client
            .query_hot_fork_async_worker_barrier()
            .map_err(QemuNodeChannelError::from)
    }

    /// Releases the reversible asynchronous-worker barrier.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when QMP I/O fails or QEMU does not
    /// report the required released postcondition.
    pub fn release_hot_fork_async_worker_barrier(
        &mut self,
    ) -> Result<QmpHotForkAsyncWorkerBarrierState, QemuNodeChannelError> {
        self.client
            .release_hot_fork_async_worker_barrier()
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
}
