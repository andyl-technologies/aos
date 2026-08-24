//! Host-I/O runtime contract for the bounded QEMU driver.

use super::*;

/// Host-I/O runtime used by the bounded async driver.
pub trait QemuHostIoRuntime: Send {
    /// Sets the aggregate number of fault events this runtime may stage.
    ///
    /// Production runtimes apply the plan-authored remaining event-record
    /// budget to every control callback. Runtimes without a live event ring may
    /// ignore the limit.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when already-staged events exceed
    /// the new ceiling.
    fn set_fault_event_staging_limit(
        &mut self,
        _maximum_event_records: usize,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    /// Arms the publication fence for the next advance-completion wait.
    ///
    /// Live runtimes retain the supplied pre-wake generation until the plugin
    /// publishes the scheduler input that invalidated its prior idle report.
    /// Runtimes without a live shared-memory executor ignore the fence.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot arm the
    /// requested completion fence.
    fn arm_advance_completion_fence(
        &mut self,
        _fence: Option<QemuAdvanceCompletionFence>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    /// Reports whether QEMU owns no in-flight device coroutine at this boundary.
    ///
    /// Runtimes without a live external executor are always quiescent. A live
    /// runtime overrides this method with an acquire snapshot of its shared
    /// node slot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the live node slot cannot be
    /// inspected consistently.
    fn checkpoint_device_io_is_quiescent(&mut self) -> Result<bool, QemuAsyncDriverRuntimeError> {
        Ok(true)
    }

    /// Probes QEMU's main-loop device boundary without requesting a pause.
    ///
    /// Live runtimes use this to expose device work queued behind an otherwise
    /// quiescent slot before the caller commits to an exact checkpoint
    /// coordinate. Runtimes without an external executor remain ready.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the probe cannot be
    /// acknowledged or serviced within `timeout`.
    fn probe_checkpoint_device_io(
        &mut self,
        _timeout: Duration,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        self.checkpoint_device_io_is_quiescent()
    }

    /// Publishes the current exact execution fingerprint at a control boundary.
    ///
    /// The runtime must wake the external executor and wait until the plugin has
    /// release-acknowledged a synchronous fingerprint sample. This is required
    /// after an all-halted idle advance because no vCPU callback owns a later
    /// sample at that otherwise quiescent boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the control request cannot be
    /// published, woken, or acknowledged within `timeout`.
    fn publish_current_execution_fingerprint(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError>;

    /// Requests a coordinated shared-memory pause and waits for quiescence.
    ///
    /// Runtimes without a live external executor have nothing to pause. A live
    /// runtime overrides this method and must fail closed when the pause is not
    /// acknowledged within `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the pause cannot be
    /// requested, acknowledged, or serviced within the supplied bound.
    fn quiesce_for_checkpoint(
        &mut self,
        _timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    /// Clears a coordinated plugin pause while QEMU is already stopped.
    ///
    /// This operation must not wake the plugin's scheduler futex or main-loop
    /// doorbell. A vCPU-idle callback owns QEMU's big lock while it waits on
    /// that futex; waking it while QMP deliberately holds the VM stopped can
    /// strand the following VMState command behind that lock.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the live executor cannot
    /// clear the checkpoint barrier without making it runnable.
    fn clear_checkpoint_pause_while_stopped(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    /// Aborts a plugin checkpoint pause while QEMU may still be running.
    ///
    /// Unlike [`Self::clear_checkpoint_pause_while_stopped`], rollback must
    /// wake both plugin wait mechanisms so a failed pre-stop transaction cannot
    /// leave the process stranded behind a cleared flag.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the live executor cannot
    /// clear and actively release the failed checkpoint barrier.
    fn abort_checkpoint_pause(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    /// Reports whether host-device work crosses the current scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when live block queues or device
    /// continuation state cannot be inspected consistently.
    #[cfg(target_os = "linux")]
    fn has_pending_device_io(&mut self) -> Result<bool, QemuAsyncDriverRuntimeError> {
        Ok(false)
    }

    /// Captures the complete host-I/O continuation paired with QEMU VMState.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the guest is not quiescent
    /// or an attached device or shared-memory ring cannot be snapshotted.
    fn checkpoint_host_io(
        &mut self,
        execution_binding: crucible::model::ContentHash,
    ) -> Result<crate::QemuHostIoCheckpoint, QemuAsyncDriverRuntimeError> {
        Ok(crate::QemuHostIoCheckpoint::without_devices(
            execution_binding,
        ))
    }

    /// Prevalidates a paired host-I/O restore without changing live state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the checkpoint identity or
    /// live device topology differs. The default runtime accepts only the
    /// explicit no-block topology.
    fn validate_host_io_checkpoint(
        &mut self,
        execution_binding: crucible::model::ContentHash,
        checkpoint: &crate::QemuHostIoCheckpoint,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if checkpoint.execution_binding() == execution_binding
            && checkpoint.block().is_none()
            && checkpoint.ninep().is_none()
        {
            Ok(())
        } else {
            Err(QemuAsyncDriverRuntimeError::new(
                "validate host-I/O checkpoint",
                "checkpoint identity or device topology does not match this runtime",
            ))
        }
    }

    /// Commits a previously validated host-I/O continuation restore.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] under the same conditions as
    /// [`Self::validate_host_io_checkpoint`].
    fn restore_host_io_checkpoint(
        &mut self,
        execution_binding: crucible::model::ContentHash,
        checkpoint: &crate::QemuHostIoCheckpoint,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.validate_host_io_checkpoint(execution_binding, checkpoint)
    }

    /// Captures the block state needed to roll back one scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when a runtime with an attached
    /// block device cannot capture its complete fault continuation.
    #[cfg(target_os = "linux")]
    fn checkpoint_block_boundary_state(
        &self,
    ) -> Result<Option<crucible_device::block::BlockFaultState>, QemuAsyncDriverRuntimeError> {
        Ok(None)
    }

    /// Returns the authoritative live block-device handle, when configured.
    #[cfg(target_os = "linux")]
    fn shared_block_device(&self) -> Option<crate::QemuSharedBlockDevice> {
        None
    }

    /// Restores block state captured before an uncommitted scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when this runtime cannot restore
    /// the supplied state exactly.
    #[cfg(target_os = "linux")]
    fn restore_block_boundary_state(
        &mut self,
        state: Option<crucible_device::block::BlockFaultState>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if state.is_none() {
            Ok(())
        } else {
            Err(QemuAsyncDriverRuntimeError::new(
                "restore block boundary state",
                "host-I/O runtime does not implement block transaction rollback",
            ))
        }
    }

    /// Applies storage-targeted actions at one exact scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when an attached block runtime
    /// cannot apply its matching actions atomically.
    #[cfg(target_os = "linux")]
    fn apply_block_boundary_actions(
        &mut self,
        _coordinate: crucible::model::FaultCoordinate,
        _evaluation_sequence: u64,
        actions: &[crucible::model::ResolvedBindingAction],
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if actions.is_empty() {
            Ok(())
        } else {
            Err(QemuAsyncDriverRuntimeError::new(
                "apply block boundary actions",
                "host-I/O runtime does not implement signal-driven block boundary mutations",
            ))
        }
    }

    /// Installs the signal-driven coordinator for an attached live block device.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when this runtime has no live block
    /// device. A new coordinator atomically replaces the previous binding so a
    /// restored or relaunched node cannot retain a stale continuation owner.
    #[cfg(target_os = "linux")]
    fn install_block_fault_coordinator(
        &mut self,
        _coordinator: Box<dyn crate::supervision::QemuBlockFaultCoordinator>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Err(QemuAsyncDriverRuntimeError::new(
            "install block fault coordinator",
            "host-I/O runtime does not own a live block device",
        ))
    }

    /// Installs the signal-driven coordinator for an attached live 9p device.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when this runtime has no live 9p
    /// device or already has a continuation owner.
    #[cfg(target_os = "linux")]
    fn install_ninep_fault_coordinator(
        &mut self,
        _coordinator: Box<dyn crate::supervision::QemuNinepFaultCoordinator>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Err(QemuAsyncDriverRuntimeError::new(
            "install 9p fault coordinator",
            "host-I/O runtime does not own a live 9p device",
        ))
    }

    /// Yields once so control-plane work can run between quanta.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot yield.
    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError>;

    /// Waits for one child event using `timeout` as a bounded budget.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot execute
    /// the await operation.
    fn await_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError>;

    /// Polls an already-signaled child event again under the original budget.
    ///
    /// The runtime must retain the deadline established by
    /// [`Self::await_child`] and return [`QemuAsyncWaitOutcome::TimedOut`] when
    /// that original `timeout` budget expires. A repeated poll must not repeat
    /// one-shot side effects such as waking the plugin.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot execute
    /// the repeated poll operation.
    fn repoll_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError>;

    /// Wakes QEMU and waits for one lossless fault-command result.
    ///
    /// Implementations must use `timeout` only as a host-liveness bound. The
    /// returned result carries the QEMU-observed virtual coordinate and is the
    /// sole mutation evidence used by the scheduler.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot wake
    /// QEMU, the result transport is corrupt, or the bounded wait expires.
    fn await_fault_result(
        &mut self,
        _timeout: Duration,
        _payload_buffer: Vec<u8>,
        _maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        Err(QemuAsyncDriverRuntimeError::new(
            "await fault result",
            "host-I/O runtime does not own a QEMU fault-result transport",
        ))
    }

    /// Wakes QEMU and obtains one non-mutating PREPARE result with exact storage.
    ///
    /// Implementations may inspect the published result length and reserve
    /// exactly that storage because PREPARE cannot make architectural state
    /// visible. APPLY must continue to use [`Self::await_fault_result`] with
    /// caller-owned storage reserved before publication.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot wake
    /// QEMU, inspect or allocate the result, or complete within `timeout`.
    fn await_fault_preparation_result(
        &mut self,
        _timeout: Duration,
        _maximum_payload_bytes: usize,
        _maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        Err(QemuAsyncDriverRuntimeError::new(
            "await fault preparation result",
            "host-I/O runtime does not own a QEMU fault-result transport",
        ))
    }

    /// Moves events consumed while completing a fault-command publication fence.
    ///
    /// The live runtime may have to consume the plugin-to-host ring while a
    /// control request remains outstanding so event backpressure cannot
    /// deadlock the lossless result fence. The scheduler-facing node remains
    /// the canonical sequence validator and observation owner.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when staged event ownership is
    /// corrupt or cannot be transferred.
    fn take_staged_fault_events(
        &mut self,
    ) -> Result<Vec<DequeuedFaultEvent>, QemuAsyncDriverRuntimeError> {
        Ok(Vec::new())
    }

    /// Reports whether a fault-result fence has physically consumed events
    /// that the scheduler has not admitted yet.
    #[must_use]
    fn staged_fault_events_pending(&self) -> bool {
        false
    }

    /// Returns the number of scheduler-owned events staged by this runtime.
    #[must_use]
    fn staged_fault_event_count(&self) -> usize {
        0
    }
}
