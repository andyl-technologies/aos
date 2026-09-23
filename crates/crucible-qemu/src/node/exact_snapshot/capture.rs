//! QEMU exact-checkpoint capture, commit, abort, and resume operations.

use super::*;

impl QemuNode {
    #[cfg(target_os = "linux")]
    pub(crate) fn install_checkpoint_cancellation(&mut self, cancellation: OwnedFd) {
        self.checkpoint_cancellation = Some(cancellation);
    }

    /// Captures native VMState for a retained hot-fork source and keeps QEMU paused.
    ///
    /// This crate-private operation exists only for the native hot-fork
    /// transaction. Campaign checkpoints use descriptor-backed v9 capture.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the node is not at the checkpoint boundary,
    /// host-I/O capture fails, or native VMState capture fails.
    pub(crate) fn capture_native_hot_fork_vmstate_paused(
        &mut self,
        node: &NodeId,
        checkpoint: Checkpoint,
    ) -> Result<crate::QemuVmSnapshot, QemuNodeError> {
        self.capture_exact_snapshot_inner(
            node,
            Arc::new(checkpoint),
            false,
            false,
            false,
            SnapshotCapture::native_vmstate(),
        )
        .map(|(snapshot, _)| snapshot)
    }

    /// Captures an admitted direct or parent-relative exact checkpoint.
    ///
    /// QEMU consumes all three imported descriptor names. Success leaves the
    /// node paused and the candidate uncommitted so the caller can durably
    /// publish its closure before advancing QEMU's dirty epoch. This layer
    /// verifies the request's checkpoint component against the captured host
    /// continuation. The production caller must derive the target and frontier
    /// components from the same authenticated v9 manifest it publishes.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when boundary validation, host continuation
    /// capture, descriptor transfer, or QEMU capture fails. A failure after
    /// descriptor transfer terminates and reaps the indeterminate process.
    #[cfg(target_os = "linux")]
    fn capture_admitted_exact_checkpoint(
        &mut self,
        node: &NodeId,
        checkpoint: Checkpoint,
        admission: QemuExactCheckpointCaptureAdmission,
        cancellation: BorrowedFd<'_>,
        resume_after_pre_save_failure: bool,
    ) -> Result<QemuExactCheckpointCaptureResult, QemuNodeError> {
        validate_capture_admission_binding(
            admission.checkpoint,
            &admission.node,
            checkpoint.id,
            node,
        )?;
        let QemuExactCheckpointCaptureAdmission {
            request,
            ram,
            device,
            ..
        } = admission;
        let parent = request.parent();
        let (snapshot, qemu) = self.capture_exact_snapshot_inner(
            node,
            Arc::new(checkpoint),
            false,
            resume_after_pre_save_failure,
            false,
            SnapshotCapture::ExactRam(ExactRamCapture {
                request: &request,
                descriptors: QemuExactCheckpointCaptureDescriptors::new(
                    ram.as_fd(),
                    device.as_fd(),
                    cancellation,
                ),
            }),
        )?;
        let qemu = qemu.ok_or_else(|| {
            QemuNodeError::checkpoint("exact RAM capture returned no QEMU report")
        })?;
        Ok(QemuExactCheckpointCaptureResult {
            snapshot,
            qemu,
            parent,
            ram,
            device,
        })
    }

    /// Captures an exact candidate using this node's sticky attempt cancellation.
    ///
    /// This is the guarded production capture path. The cancellation event was
    /// cloned from the same process contract before spawn and remains readable
    /// when concurrent attempt retirement wins during the QMP operation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when this node lacks guarded cancellation or
    /// when admitted capture, descriptor transfer, or QEMU capture fails.
    #[cfg(target_os = "linux")]
    pub(crate) fn capture_exact_checkpoint_for_publication_guarded(
        &mut self,
        node: &NodeId,
        checkpoint: Checkpoint,
        admission: QemuExactCheckpointCaptureAdmission,
    ) -> Result<QemuExactCheckpointCaptureResult, QemuNodeError> {
        let cancellation = self
            .checkpoint_cancellation
            .as_ref()
            .ok_or_else(|| {
                QemuNodeError::checkpoint(
                    "guarded exact checkpoint capture has no sticky cancellation event",
                )
            })?
            .try_clone()
            .map_err(|error| {
                QemuNodeError::checkpoint(format!(
                    "duplicate guarded exact checkpoint cancellation event: {error}"
                ))
            })?;
        self.capture_admitted_exact_checkpoint(
            node,
            checkpoint,
            admission,
            cancellation.as_fd(),
            true,
        )
    }

    /// Captures a paused exact candidate with sticky attempt cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] under the same conditions as
    /// [`Self::capture_exact_checkpoint_for_publication_guarded`].
    #[cfg(target_os = "linux")]
    pub(crate) fn capture_exact_checkpoint_paused_guarded(
        &mut self,
        node: &NodeId,
        checkpoint: Checkpoint,
        admission: QemuExactCheckpointCaptureAdmission,
    ) -> Result<QemuExactCheckpointCaptureResult, QemuNodeError> {
        let cancellation = self
            .checkpoint_cancellation
            .as_ref()
            .ok_or_else(|| {
                QemuNodeError::checkpoint(
                    "guarded exact checkpoint capture has no sticky cancellation event",
                )
            })?
            .try_clone()
            .map_err(|error| {
                QemuNodeError::checkpoint(format!(
                    "duplicate guarded exact checkpoint cancellation event: {error}"
                ))
            })?;
        self.capture_admitted_exact_checkpoint(
            node,
            checkpoint,
            admission,
            cancellation.as_fd(),
            false,
        )
    }

    /// Commits a durably published exact checkpoint candidate.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when QEMU cannot authenticate and commit the
    /// exact candidate identity.
    pub(crate) fn commit_exact_checkpoint(
        &mut self,
        identity: crate::QmpCheckpointIdentity,
    ) -> Result<crate::QmpCheckpointEpochState, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .commit_exact_checkpoint(identity)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    /// Aborts an unpublished exact checkpoint candidate.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when QEMU cannot discard the candidate while
    /// retaining the expected committed parent.
    pub(crate) fn abort_exact_checkpoint(
        &mut self,
        identity: crate::QmpCheckpointIdentity,
        expected_committed: Option<crate::QmpCheckpointIdentity>,
    ) -> Result<crate::QmpCheckpointEpochState, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .abort_exact_checkpoint(identity, expected_committed)
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    /// Returns QEMU's exact committed and candidate epoch state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when QEMU cannot provide a valid epoch report.
    pub(crate) fn query_exact_checkpoint_epoch(
        &mut self,
    ) -> Result<crate::QmpCheckpointEpochState, QemuNodeError> {
        self.channels
            .qmp_machine_control
            .query_exact_checkpoint_epoch()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, source)
            })
    }

    /// Resumes a running node after its paused exact artifacts are durable.
    ///
    /// The lifecycle owner calls this only after it has streamed every
    /// checkpoint artifact from the stopped process generation into durable
    /// content storage. Powered-off nodes deliberately remain paused and must
    /// not use this operation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when QMP cannot confirm the running-state
    /// transition.
    pub fn resume_after_exact_snapshot(&mut self) -> Result<(), QemuNodeError> {
        self.resume_after_restore()
    }

    pub(crate) fn capture_terminal_lifecycle_snapshot_shared(
        &mut self,
        node: &NodeId,
        checkpoint: Arc<Checkpoint>,
    ) -> Result<crate::QemuVmSnapshot, QemuNodeError> {
        self.capture_exact_snapshot_inner(
            node,
            checkpoint,
            false,
            false,
            true,
            SnapshotCapture::native_vmstate(),
        )
        .map(|(snapshot, _)| snapshot)
    }

    /// Pauses QEMU at the current exact scheduler boundary.
    ///
    /// This performs the production checkpoint handoff without capturing
    /// VMState: it quiesces the plugin and host device paths, asks QMP to stop
    /// the VM, and clears the plugin pause while QEMU remains stopped. The
    /// stopped process can then be used by operations such as retained
    /// hot-fork template preparation that require QEMU's exact native pause.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the node is not running at its completed
    /// scheduler boundary, fault events are pending, the plugin cannot
    /// quiesce, QMP cannot stop the VM, or the stopped boundary moves.
    pub fn pause_at_exact_checkpoint_boundary(&mut self) -> Result<(), QemuNodeError> {
        self.validate_exact_pause_boundary()?;
        self.pause_at_exact_checkpoint_boundary_after_validation()
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
    pub(crate) fn prevalidate_terminal_lifecycle_snapshot(
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
        self.validate_exact_pause_boundary()?;

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
        Ok(())
    }

    fn validate_exact_pause_boundary(&mut self) -> Result<(), QemuNodeError> {
        if self.lifecycle_state != QemuNodeLifecycleState::Running {
            return Err(QemuNodeError::checkpoint(
                "exact checkpoint pause requires a running QEMU node",
            ));
        }
        if let Some(message) = &self.fault_event_terminal_failure {
            return Err(QemuNodeError::checkpoint(format!(
                "fault-event transport is terminally invalid: {message}"
            )));
        }
        if self.fault_event_pending()? {
            return Err(QemuNodeError::checkpoint(
                "exact checkpoint pause requires an empty fault-event continuation",
            ));
        }
        if !self.pending_priming_observations.is_empty() {
            return Err(QemuNodeError::checkpoint(
                "checkpoint requested before setup-time observations reached the scheduler event log",
            ));
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

    fn pause_at_exact_checkpoint_boundary_after_validation(&mut self) -> Result<(), QemuNodeError> {
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

        let paused_icount = self.current_icount()?;
        if paused_icount.retired != self.last_observed_time.ticks {
            return Err(QemuNodeError::checkpoint(format!(
                "checkpoint pause moved shared-memory icount from {} to {}",
                self.last_observed_time.ticks, paused_icount.retired
            )));
        }
        Ok(())
    }

    fn capture_exact_snapshot_inner(
        &mut self,
        node: &NodeId,
        checkpoint: Arc<Checkpoint>,
        resume_after_capture: bool,
        resume_after_pre_save_failure: bool,
        terminal_lifecycle_stop: bool,
        capture: SnapshotCapture<'_>,
    ) -> Result<(crate::QemuVmSnapshot, Option<crate::QmpCheckpointCapture>), QemuNodeError> {
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
            self.pause_at_exact_checkpoint_boundary_after_validation()?;
        }
        let capture_result = (|| {
            if terminal_lifecycle_stop {
                let paused_icount = self.current_icount()?;
                if paused_icount.retired != self.last_observed_time.ticks {
                    return Err(QemuNodeError::checkpoint(format!(
                        "checkpoint pause moved shared-memory icount from {} to {}",
                        self.last_observed_time.ticks, paused_icount.retired
                    )));
                }
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
            crate::QemuVmSnapshot::from_live_capture(Arc::clone(&checkpoint), host_io, node)
                .map_err(|error| QemuNodeError::checkpoint(error.to_string()))
        })();
        let snapshot = match capture_result {
            Ok(snapshot) => snapshot,
            Err(error) if !resume_after_pre_save_failure => return Err(error),
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
        let qemu_capture = match capture {
            #[cfg(target_os = "linux")]
            SnapshotCapture::ExactRam(exact_ram) => {
                let installed = (|| {
                    self.channels
                        .qmp_machine_control
                        .install_exact_checkpoint_descriptor(
                            exact_ram.request.ram_descriptor(),
                            exact_ram.descriptors.ram,
                        )?;
                    self.channels
                        .qmp_machine_control
                        .install_exact_checkpoint_descriptor(
                            exact_ram.request.device_descriptor(),
                            exact_ram.descriptors.device,
                        )?;
                    self.channels
                        .qmp_machine_control
                        .install_exact_checkpoint_descriptor(
                            exact_ram.request.cancellation_descriptor(),
                            exact_ram.descriptors.cancellation,
                        )?;
                    self.channels
                        .qmp_machine_control
                        .capture_exact_checkpoint(exact_ram.request)
                })();
                match installed {
                    Ok(capture) => Some(capture),
                    Err(save_error) => {
                        return self.fail_indeterminate_checkpoint_capture(save_error);
                    }
                }
            }
            SnapshotCapture::NativeVmState(_) => {
                if let Err(save_error) = self
                    .channels
                    .qmp_machine_control
                    .save_checkpoint_vmstate(&checkpoint)
                {
                    // Once snapshot-save has been written, a transport, decode,
                    // poll, dismiss, or timeout failure can leave an asynchronous
                    // job active. Never resume that indeterminate process.
                    return self.fail_indeterminate_checkpoint_capture(save_error);
                }
                None
            }
        };
        if resume_after_capture
            && let Err(source) = self.channels.qmp_machine_control.resume_after_checkpoint()
        {
            return self.handle_qmp_channel_error(source);
        }
        Ok((snapshot, qemu_capture))
    }

    fn fail_indeterminate_checkpoint_capture<T>(
        &mut self,
        save_error: QemuNodeChannelError,
    ) -> Result<T, QemuNodeError> {
        match self.shutdown_child_after_coverage_drain() {
            Ok(shutdown) => Err(QemuNodeError::checkpoint(format!(
                "saving QEMU checkpoint state failed ({save_error}); the indeterminate checkpoint process was terminated and reaped: {shutdown:?}"
            ))),
            Err(shutdown) => Err(QemuNodeError::checkpoint(format!(
                "saving QEMU checkpoint state failed ({save_error}); terminating the indeterminate checkpoint process also failed ({shutdown})"
            ))),
        }
    }
}
