//! Erased scheduler-channel integration for the QEMU quantum hot path.

use super::*;

impl QemuShmemHotPathChannel for QemuQuantumShmemHotPath<'_> {
    fn checkpoint_network_transport(
        &mut self,
    ) -> Result<crate::QemuNetworkTransportCheckpoint, QemuNodeChannelError> {
        let inbound = self
            .view
            .inbound_ring
            .snapshot(self.view.inbound_entries)
            .map_err(|error| {
                QemuNodeChannelError::new("checkpoint network inbound ring", error.to_string())
            })?;
        let outbound = self
            .view
            .outbound_ring
            .snapshot(self.view.outbound_entries)
            .map_err(|error| {
                QemuNodeChannelError::new("checkpoint network outbound ring", error.to_string())
            })?;
        Ok(crate::QemuNetworkTransportCheckpoint {
            inbound,
            outbound,
            queue_capacity: self.view.inbound_entries.len() as u32,
            router_slot: self.config.router_slot,
            next_router_inbound_sequence: self.next_router_inbound_sequence,
            next_host_outbound_sequence: 0,
            next_plugin_outbound_sequence: 0,
        })
    }

    fn restore_network_transport(
        &mut self,
        checkpoint: &crate::QemuNetworkTransportCheckpoint,
    ) -> Result<(), QemuNodeChannelError> {
        if checkpoint.queue_capacity as usize != self.view.inbound_entries.len()
            || checkpoint.queue_capacity as usize != self.view.outbound_entries.len()
            || checkpoint.router_slot != self.config.router_slot
        {
            return Err(QemuNodeChannelError::new(
                "restore network transport",
                "checkpoint network ring shape does not match mapped runtime",
            ));
        }
        let prior_inbound = self
            .view
            .inbound_ring
            .snapshot(self.view.inbound_entries)
            .map_err(|error| {
                QemuNodeChannelError::new("snapshot prior network inbound ring", error.to_string())
            })?;
        self.view
            .inbound_ring
            .restore(self.view.inbound_entries, &checkpoint.inbound)
            .map_err(|error| {
                QemuNodeChannelError::new("restore network inbound ring", error.to_string())
            })?;
        if let Err(error) = self
            .view
            .outbound_ring
            .restore(self.view.outbound_entries, &checkpoint.outbound)
        {
            self.view
                .inbound_ring
                .restore(self.view.inbound_entries, &prior_inbound)
                .map_err(|rollback| {
                    QemuNodeChannelError::new(
                        "roll back network inbound ring",
                        rollback.to_string(),
                    )
                })?;
            return Err(QemuNodeChannelError::new(
                "restore network outbound ring",
                error.to_string(),
            ));
        }
        self.next_router_inbound_sequence = checkpoint.next_router_inbound_sequence;
        *self.inbound_delivery_ledger.get_mut() = checkpoint
            .inbound
            .frames
            .iter()
            .map(crucible_shmem::FrameEntry::delivery_key)
            .collect();
        Ok(())
    }

    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        Ok(self.current_icount_from_slot())
    }

    fn logical_time_calibration(
        &mut self,
    ) -> Result<crate::QemuLogicalTimeCalibration, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        let snapshot = self.node_snapshot();
        let calibration = crate::QemuLogicalTimeCalibration {
            logical_icount: snapshot.current_icount,
            raw_icount: snapshot.logical_time_raw_icount,
        };
        let _offset = calibration.offset()?;
        Ok(calibration)
    }

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError> {
        QemuQuantumShmemHotPath::start_quantum(self, horizon)
            .map(QemuNodePendingQuantum::new)
            .map_err(QemuNodeChannelError::from)
    }

    fn poll_quantum(
        &mut self,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        let pending = pending.downcast_mut::<QemuPendingQuantum>("finish_quantum")?;
        QemuQuantumShmemHotPath::poll_quantum(self, pending)
            .map(QemuAsyncQuantumCompletion::from)
            .map_err(QemuNodeChannelError::from)
    }

    fn publish_preemption_command(
        &mut self,
        command: crucible_shmem::SchedulerPreemptionCommand,
    ) -> Result<(), QemuNodeChannelError> {
        self.view
            .node_slot
            .publish_preemption_command(command)
            .map(|_| ())
            .map_err(|source| {
                QemuNodeChannelError::new("publish_preemption_command", source.to_string())
            })
    }

    fn enqueue_fault_command(
        &mut self,
        _header: crucible_shmem::FaultCommandHeaderV1,
        _payload: &[u8],
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "enqueue_fault_command",
            "the borrowed quantum view does not own the mapped fault transport",
        ))
    }

    fn dequeue_fault_result(
        &mut self,
    ) -> Result<Option<crucible_shmem::DequeuedFaultResult>, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "dequeue_fault_result",
            "the borrowed quantum view does not own the mapped fault transport",
        ))
    }

    fn dequeue_fault_event(
        &mut self,
    ) -> Result<Option<crucible_shmem::DequeuedFaultEvent>, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "dequeue_fault_event",
            "the borrowed quantum view does not own the mapped fault transport",
        ))
    }

    fn fault_event_pending(&mut self) -> Result<bool, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "fault_event_pending",
            "the borrowed quantum view does not own the mapped fault transport",
        ))
    }

    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
        let delivery_icount = Icount {
            retired: self.current_icount_from_slot().retired.saturating_add(1),
        };
        self.deliver_frame_at(input, delivery_icount)
    }

    fn deliver_frame_at(
        &mut self,
        // crucible-lint: allow host-nondeterminism-state -- the erased channel preserves the scheduler-owned input and exact delivery point.
        input: BackendInput,
        delivery_icount: Icount,
    ) -> Result<(), QemuNodeChannelError> {
        let sequence = self
            .next_router_inbound_sequence()
            .map_err(QemuNodeChannelError::from)?;
        let entry = self
            .inbound_entry_from_frame(QemuInboundFrame {
                delivery_icount,
                src_node: self.config.router_slot,
                sequence,
                payload: input.payload,
            })
            .map_err(QemuNodeChannelError::from)?;
        self.publish_inbound_entry_and_wake(&entry)
            .map_err(QemuNodeChannelError::from)?;
        self.inbound_delivery_ledger
            .get_mut()
            .push_back(entry.delivery_key());
        self.commit_router_inbound_sequence()
            .map_err(QemuNodeChannelError::from)
    }

    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
        self.dequeue_authorized_emitted_outbound()
            .map_err(QemuNodeChannelError::from)
    }

    fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        Ok(idle_state_from_snapshot(self.view.node_slot.snapshot()))
    }

    fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        let snapshot = self.view.node_slot.snapshot();
        let material = format!(
            "node={}\ncurrent_icount={}\ncurrent_ns={}\nmax_advance_icount={}\nidle_wake_icount={}\nstatus={}\ndevice_io_active={}\ninbound_read_idx={}\ninbound_write_idx={}\noutbound_read_idx={}\noutbound_write_idx={}\n",
            self.config.node.name,
            snapshot.current_icount,
            snapshot.current_ns,
            snapshot.max_advance_icount,
            snapshot.idle_wake_icount,
            snapshot.status,
            snapshot.device_io_active,
            self.view.inbound_ring.read_index(),
            self.view.inbound_ring.write_index(),
            self.view.outbound_ring.read_index(),
            self.view.outbound_ring.write_index(),
        );
        Ok(ExecutionFingerprint {
            hash: ContentHash::from_canonical_material(QUANTUM_FINGERPRINT_DOMAIN, &material),
        })
    }

    fn fingerprint_sample(&mut self) -> Result<FingerprintSample, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        self.view.fingerprint_sample.snapshot().ok_or_else(|| {
            QemuNodeChannelError::retryable(
                "fingerprint_sample",
                "the plugin has not published a black-box fingerprint sample",
            )
        })
    }
}

impl From<QemuQuantumError> for QemuNodeChannelError {
    fn from(error: QemuQuantumError) -> Self {
        if matches!(error, QemuQuantumError::PluginReportNotPublished { .. }) {
            Self::retryable("qemu_quantum_shmem_hot_path", error.to_string())
        } else {
            Self::new("qemu_quantum_shmem_hot_path", error.to_string())
        }
    }
}
