//! Exact VMState and host-continuation capture at completed boundaries.

use super::*;
use std::sync::Arc;

impl QemuNode {
    /// Captures QEMU VMState and the Apache host-I/O continuation as one pair.
    ///
    /// The caller supplies the already materialized scheduler checkpoint whose
    /// content identity names the VMState artifact. Host-I/O state is captured
    /// first at the completed quantum boundary; QMP then saves guest state under
    /// the same identity. A failed save leaves any pre-existing artifact intact;
    /// the typed QMP client dismisses every concluded snapshot job.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the node is not at the checkpoint's
    /// virtual-time boundary, host-I/O capture fails, or QMP save fails.
    pub fn capture_exact_snapshot(
        &mut self,
        node: &NodeId,
        checkpoint: Checkpoint,
    ) -> Result<crate::QemuVmSnapshot, QemuNodeError> {
        self.capture_exact_snapshot_inner(node, Arc::new(checkpoint), true, false)
    }

    /// Captures an exact snapshot while preserving an intentional QEMU pause.
    ///
    /// This is the savepoint operation for a lifecycle node whose service state
    /// is powered off. It records the same VMState and host-I/O continuation as
    /// [`Self::capture_exact_snapshot`], but does not issue `cont` after capture.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] under the same conditions as
    /// [`Self::capture_exact_snapshot`].
    pub fn capture_exact_snapshot_paused(
        &mut self,
        node: &NodeId,
        checkpoint: Checkpoint,
    ) -> Result<crate::QemuVmSnapshot, QemuNodeError> {
        self.capture_exact_snapshot_inner(node, Arc::new(checkpoint), false, false)
    }

    /// Captures the post-mutation restart state for a terminal lifecycle fault.
    ///
    /// QEMU remains paused after a successful capture. The caller must next
    /// authorize terminal completion and supervise the exact child exit; it
    /// must never issue an ordinary resume to this process generation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] under the same conditions as
    /// [`Self::capture_exact_snapshot`]. A failed terminal capture deliberately
    /// leaves QEMU paused because `cont` is already bound to process exit.
    pub fn capture_terminal_lifecycle_snapshot(
        &mut self,
        node: &NodeId,
        checkpoint: Checkpoint,
    ) -> Result<crate::QemuVmSnapshot, QemuNodeError> {
        self.capture_terminal_lifecycle_snapshot_shared(node, Arc::new(checkpoint))
    }

    pub(crate) fn capture_terminal_lifecycle_snapshot_shared(
        &mut self,
        node: &NodeId,
        checkpoint: Arc<Checkpoint>,
    ) -> Result<crate::QemuVmSnapshot, QemuNodeError> {
        self.capture_exact_snapshot_inner(node, checkpoint, false, true)
    }

    /// Prevalidates terminal snapshot identity and boundary prerequisites.
    ///
    /// This read-only check lets a multi-node lifecycle transaction reject all
    /// known configuration and boundary failures before pausing its first VM.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the node is not running at the exact
    /// checkpoint boundary or cannot safely enter checkpoint capture.
    pub fn prevalidate_terminal_lifecycle_snapshot(
        &mut self,
        node: &NodeId,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeError> {
        self.validate_exact_snapshot_boundary(node, checkpoint)
    }

    fn validate_exact_snapshot_boundary(
        &mut self,
        node: &NodeId,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeError> {
        if self.lifecycle_state != QemuNodeLifecycleState::Running {
            return Err(QemuNodeError::checkpoint(
                "exact snapshot capture requires a running QEMU node",
            ));
        }
        if self.active_gdbstub.is_some() {
            return Err(QemuNodeError::checkpoint(
                "exact snapshot capture is forbidden while a debugger proxy is active",
            ));
        }
        if let Some(message) = &self.fault_event_terminal_failure {
            return Err(QemuNodeError::checkpoint(format!(
                "fault-event transport is terminally invalid: {message}"
            )));
        }
        if self.fault_event_pending()? {
            return Err(QemuNodeError::checkpoint(
                "exact snapshot capture requires an empty fault-event continuation",
            ));
        }
        let expected_icount = checkpoint.node_icounts.get(node).ok_or_else(|| {
            QemuNodeError::checkpoint(format!(
                "checkpoint has no instruction counter for QEMU node `{}`",
                node.name
            ))
        })?;
        if expected_icount.retired != self.last_observed_time.ticks {
            return Err(QemuNodeError::checkpoint(format!(
                "checkpoint icount {} for `{}` does not match QEMU boundary {}",
                expected_icount.retired, node.name, self.last_observed_time.ticks
            )));
        }
        let observed_icount = self.current_icount()?;
        if observed_icount.retired != self.last_observed_time.ticks {
            return Err(QemuNodeError::checkpoint(format!(
                "shared-memory icount {} does not match completed QEMU boundary {}",
                observed_icount.retired, self.last_observed_time.ticks
            )));
        }
        Ok(())
    }

    fn capture_exact_snapshot_inner(
        &mut self,
        node: &NodeId,
        checkpoint: Arc<Checkpoint>,
        resume_after_capture: bool,
        terminal_lifecycle_stop: bool,
    ) -> Result<crate::QemuVmSnapshot, QemuNodeError> {
        self.validate_exact_snapshot_boundary(node, &checkpoint)?;
        if terminal_lifecycle_stop {
            // A terminal QEMU mutation installs its RR stop fence before its
            // typed result becomes visible to the host. Requesting a second
            // plugin pause can therefore strand behind the already-stopped
            // main loop. Confirm that native stopped state first, then require
            // the exact boundary's device marker to be quiescent.
            if let Err(source) = self.channels.qmp_machine_control.stop_for_checkpoint() {
                return self.handle_qmp_channel_error(source);
            }
            if !self
                .host_io_runtime
                .checkpoint_device_io_is_quiescent()
                .map_err(|source| {
                    QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
                })?
            {
                return Err(QemuNodeError::checkpoint(
                    "terminal lifecycle stopped with active QEMU device I/O",
                ));
            }
        } else {
            self.host_io_runtime
                .quiesce_for_checkpoint(self.async_policy.qmp_command_timeout)
                .map_err(|source| {
                    QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
                })?;
            let pending_fault_event = match self.fault_event_pending() {
                Ok(pending) => pending,
                Err(source) => {
                    self.host_io_runtime
                        .abort_checkpoint_pause()
                        .map_err(|cleanup| {
                            QemuNodeError::checkpoint(format!(
                                "fault-event inspection failed while quiescing exact snapshot ({source}); aborting the plugin pause also failed ({cleanup})"
                            ))
                        })?;
                    return Err(source);
                }
            };
            if pending_fault_event {
                self.host_io_runtime
                    .abort_checkpoint_pause()
                    .map_err(|cleanup| {
                        QemuNodeError::checkpoint(format!(
                            "fault events appeared while quiescing exact snapshot; aborting the plugin pause failed ({cleanup})"
                        ))
                    })?;
                return Err(QemuNodeError::checkpoint(
                    "fault events appeared while quiescing exact snapshot",
                ));
            }
            if let Err(source) = self.channels.qmp_machine_control.stop_for_checkpoint() {
                self.host_io_runtime
                    .abort_checkpoint_pause()
                    .map_err(|cleanup| {
                        QemuNodeError::checkpoint(format!(
                            "QMP stop failed ({source}); aborting the plugin pause also failed ({cleanup})"
                        ))
                    })?;
                return self.handle_qmp_channel_error(source);
            }
            if let Err(source) = self.host_io_runtime.clear_checkpoint_pause_while_stopped() {
                let resume = self.channels.qmp_machine_control.resume_after_checkpoint();
                return match resume {
                    Ok(()) => Err(QemuNodeError::from_async_driver(
                        crate::QemuAsyncDriverError::Runtime(source),
                    )),
                    Err(qmp) => Err(QemuNodeError::checkpoint(format!(
                        "clearing the stopped plugin checkpoint pause failed ({source}); resuming QEMU also failed ({qmp})"
                    ))),
                };
            }
        }
        let capture_result = (|| {
            let paused_icount = self.current_icount()?;
            if paused_icount.retired != self.last_observed_time.ticks {
                return Err(QemuNodeError::checkpoint(format!(
                    "checkpoint pause moved shared-memory icount from {} to {}",
                    self.last_observed_time.ticks, paused_icount.retired
                )));
            }
            let host_io = self
                .host_io_runtime
                .checkpoint_host_io(checkpoint.id)
                .map_err(|source| {
                    QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
                })?;
            let logical_time_calibration = self
                .channels
                .shmem_hot_path
                .logical_time_calibration()
                .map_err(|source| {
                    QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
                })?;
            if logical_time_calibration.logical_icount != self.last_observed_time.ticks {
                return Err(QemuNodeError::checkpoint(format!(
                    "checkpoint logical-time calibration {} differs from scheduler boundary {}",
                    logical_time_calibration.logical_icount, self.last_observed_time.ticks
                )));
            }
            let _logical_time_offset = logical_time_calibration.offset().map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
            let mut network_transport = self
                .channels
                .shmem_hot_path
                .checkpoint_network_transport()
                .map_err(|source| {
                    QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
                })?;
            network_transport
                .bind_outbound_sequence(self.next_network_output_sequence)
                .map_err(|error| QemuNodeError::checkpoint(error.to_string()))?;
            let node = crate::QemuNodeContinuationCheckpoint {
                execution_binding: checkpoint.id,
                last_observed_time: self.last_observed_time,
                logical_time_calibration,
                console_observation_boundary: self.console_observation_boundary,
                pending_preemption: self.pending_preemption.clone(),
                pending_network_outputs: self.pending_network_outputs.clone(),
                network_transport,
                next_fault_command_sequence: self.next_fault_command_sequence,
                next_fault_event_sequence: self.next_fault_event_sequence,
            };
            crate::QemuVmSnapshot::from_live_capture(
                Arc::clone(&checkpoint),
                host_io,
                node,
                crate::QemuReplayOracleValidation::NotRun,
            )
            .map_err(|error| QemuNodeError::checkpoint(error.to_string()))
        })();
        let snapshot = match capture_result {
            Ok(snapshot) => snapshot,
            Err(error) if !resume_after_capture => return Err(error),
            Err(error) => {
                let resume = self.channels.qmp_machine_control.resume_after_checkpoint();
                return match resume {
                    Ok(()) => Err(error),
                    Err(resume_error) => Err(QemuNodeError::checkpoint(format!(
                        "checkpoint capture failed ({error}); resuming QEMU also failed ({resume_error})"
                    ))),
                };
            }
        };
        if let Err(save_error) = self
            .channels
            .qmp_machine_control
            .save_checkpoint_vmstate(&checkpoint)
        {
            // Once snapshot-save has been written, a transport, decode, poll,
            // dismiss, or timeout failure can leave an asynchronous job active.
            // Never issue `cont` into that indeterminate state. Terminate and
            // reap the owned process through the full shutdown ladder instead.
            return match self.shutdown_child_after_coverage_drain() {
                Ok(shutdown) => Err(QemuNodeError::checkpoint(format!(
                    "saving QEMU VMState failed ({save_error}); the indeterminate checkpoint process was terminated and reaped: {shutdown:?}"
                ))),
                Err(shutdown) => Err(QemuNodeError::checkpoint(format!(
                    "saving QEMU VMState failed ({save_error}); terminating the indeterminate checkpoint process also failed ({shutdown})"
                ))),
            };
        }
        if resume_after_capture
            && let Err(source) = self.channels.qmp_machine_control.resume_after_checkpoint()
        {
            return self.handle_qmp_channel_error(source);
        }
        Ok(snapshot)
    }
}
