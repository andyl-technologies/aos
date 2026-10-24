//! Scheduler backend adapters and deterministic preemption coordinates for a QEMU node.

use super::*;

impl Backend for QemuNode {
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError> {
        self.advance_to_ceiling(horizon.icount)
            .map_err(BackendError::from)
    }

    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
        self.execution_fingerprint().map_err(BackendError::from)
    }

    // crucible-lint: allow host-nondeterminism-state -- this adapter forwards an untrusted input to the validated shared-memory channel.
    fn deliver_input(&mut self, input: BackendInput) -> Result<(), BackendError> {
        self.deliver_frame(input).map_err(BackendError::from)
    }

    fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
        Err(BackendError::Rejected {
            message: String::from(
                "QEMU snapshots require capture_exact_snapshot with scheduler checkpoint metadata",
            ),
        })
    }

    fn restore(&mut self, _checkpoint: &Checkpoint) -> Result<(), BackendError> {
        Err(BackendError::Rejected {
            message: String::from("QEMU restore requires paired VMState and host-I/O realization"),
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.shutdown_child()
            .map(|_| ())
            .map_err(BackendError::from)
    }
}

impl SimulationBackend for QemuNode {
    fn step_node_with_admission(
        &mut self,
        admission: &crucible_engine::PreparedRunAdmission,
    ) -> Result<crucible_engine::BackendRunResult, BackendError> {
        #[cfg(any(test, feature = "test-support"))]
        {
            self.validate_scripted_run_admission_for_test(admission)?;
            self.step_to(VirtualTime {
                ticks: admission.dispatch_horizon().icount.retired,
            })
            .map(crucible_engine::BackendRunResult::Completed)
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let _ = admission;
            Err(BackendError::Unsupported {
                capability: "step_node_with_admission",
            })
        }
    }

    fn observe_node_io_inventory(
        &mut self,
        node: &NodeId,
    ) -> Result<crucible_engine::BackendIoInventory, BackendError> {
        #[cfg(any(test, feature = "test-support"))]
        {
            self.observe_scripted_io_inventory_for_test(node)
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let _ = node;
            Err(BackendError::Unsupported {
                capability: "observe_node_io_inventory",
            })
        }
    }

    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        let icount_ceiling = Icount {
            retired: ceiling.ticks,
        };
        if let Some(decision) = self.pending_preemption.as_ref() {
            let command = scheduler_preemption_command(
                decision,
                self.last_observed_time.ticks,
                icount_ceiling.retired,
            )?;
            self.channels
                .shmem_hot_path
                .publish_preemption_command(command)
                .map_err(|source| {
                    QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
                })?;
            self.pending_preemption = None;
        }
        let report = self
            .advance_to_ceiling_report(icount_ceiling)
            .map_err(BackendError::from)?;
        let emitted_network_output = !report.emitted_frames.is_empty();
        let outcome = self
            .finish_advance_report(icount_ceiling, report)
            .map_err(BackendError::from)?;
        let mut observation = StepObservation::from_advance_outcome(ceiling, outcome);
        if emitted_network_output {
            observation.physical_stop = BackendPhysicalStop::NetworkOutput;
        }
        self.console_observation_boundary = observation.reached;
        Ok(observation)
    }

    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, BackendError> {
        let mut events = self
            .drain_scheduler_observable_events()
            .map_err(BackendError::from)?;
        if let Some(console) = self.console_observation.as_mut() {
            let bytes = console
                .spool
                .take()
                .map_err(|error| BackendError::Rejected {
                    message: format!("take staged QEMU console output: {error}"),
                })?;
            if !bytes.is_empty() {
                events.push(ObservableEvent::console_output(
                    self.console_observation_boundary,
                    console.node.clone(),
                    bytes,
                ));
            }
        }
        Ok(events)
    }

    // crucible-lint: allow host-nondeterminism-state -- the scheduler validates every returned conjecture before append.
    fn drain_rng_evidence(&mut self) -> Result<Vec<BackendRngEvidence>, BackendError> {
        self.channels
            .shmem_hot_path
            .drain_rng_evidence()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source).into()
            })
    }

    fn drain_network_outputs(&mut self) -> Result<Vec<BackendNetworkOutput>, BackendError> {
        let mut outputs = Vec::new();
        for frame in self.pending_network_outputs.drain(..) {
            outputs.push(BackendNetworkOutput {
                source: frame.source,
                destination: frame.destination,
                emit_icount: frame.emit_icount,
                sequence: frame.sequence,
                payload: frame.payload,
                route: None,
                fault_continuation: Default::default(),
            });
        }
        while let Some(frame) = self.emit_frame().map_err(BackendError::from)? {
            self.observe_network_output_sequence(&frame)
                .map_err(BackendError::from)?;
            outputs.push(BackendNetworkOutput {
                source: frame.source,
                destination: frame.destination,
                emit_icount: frame.emit_icount,
                sequence: frame.sequence,
                payload: frame.payload,
                route: None,
                fault_continuation: Default::default(),
            });
        }
        Ok(outputs)
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        match effect {
            BackendEffect::DeliverInput(input) => {
                if at < self.last_observed_time {
                    return Err(BackendError::Rejected {
                        message: format!(
                            "qemu backend input at {} is behind physical node time {}",
                            at.ticks, self.last_observed_time.ticks
                        ),
                    });
                }
                self.deliver_frame_at(input.clone(), at)
                    .map_err(BackendError::from)
            }
            BackendEffect::Noop | BackendEffect::Preemption(_) | BackendEffect::Shutdown
                if at != self.last_observed_time =>
            {
                Err(BackendError::Rejected {
                    message: format!(
                        "qemu backend effect at {} does not match physical node time {}",
                        at.ticks, self.last_observed_time.ticks
                    ),
                })
            }
            BackendEffect::Noop => Ok(()),
            BackendEffect::Preemption(decision) => {
                if self.pending_preemption.is_some() {
                    return Err(BackendError::Rejected {
                        message: String::from(
                            "qemu backend already has a pending scheduler preemption",
                        ),
                    });
                }
                self.pending_preemption = Some(decision.clone());
                Ok(())
            }
            BackendEffect::Shutdown => self
                .shutdown_child()
                .map(|_| ())
                .map_err(BackendError::from),
        }
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        Err(BackendError::Rejected {
            message: String::from(
                "QEMU snapshots require capture_exact_snapshot with scheduler checkpoint metadata",
            ),
        })
    }

    fn restore(&mut self, _snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        Err(BackendError::Rejected {
            message: String::from("QEMU restore requires paired VMState and host-I/O realization"),
        })
    }

    fn now(&self) -> VirtualTime {
        self.last_observed_time
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        Ok(FingerprintSample {
            node,
            at: self.last_observed_time,
            fingerprint: self.execution_fingerprint().map_err(BackendError::from)?,
        })
    }

    fn send_guest_introspection(
        &mut self,
        _node: &NodeId,
        record: GuestIntrospectionRecord,
    ) -> Result<(), BackendError> {
        QemuNode::send_guest_introspection(self, record).map_err(BackendError::from)
    }

    fn receive_guest_introspection(
        &mut self,
        _node: &NodeId,
    ) -> Result<Option<GuestIntrospectionRecord>, BackendError> {
        QemuNode::receive_guest_introspection(self).map_err(BackendError::from)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        // `BackendQuantumLoop` owns the simulation-backend path and drains
        // every observation into the unified log before invoking this hook.
        // Bypass the public coverage guard here so coverage-enabled nodes can
        // complete teardown after that canonical handoff.
        self.shutdown_child_after_coverage_drain()
            .map(|_| ())
            .map_err(BackendError::from)
    }
}

pub(super) fn scheduler_preemption_command(
    decision: &crucible_engine::PreemptionDecision,
    deadline_tick: u64,
    ceiling_tick: u64,
) -> Result<SchedulerPreemptionCommand, BackendError> {
    if decision.at.ticks < deadline_tick || decision.at.ticks > ceiling_tick {
        return Err(BackendError::Rejected {
            message: format!(
                "scheduler preemption at {} is outside backend RUN window [{deadline_tick}, {ceiling_tick}]",
                decision.at.ticks
            ),
        });
    }
    let kind = match decision.kind {
        crucible_engine::PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
            ShmemSchedulerPreemptionKind::VcpuSwitch {
                from_vcpu: from_vcpu.index,
                to_vcpu: to_vcpu.index,
            }
        }
        crucible_engine::PreemptionKind::InterruptAt { target_vcpu, irq } => {
            ShmemSchedulerPreemptionKind::InterruptAt {
                target_vcpu: target_vcpu.index,
                irq: irq.vector,
            }
        }
    };
    Ok(SchedulerPreemptionCommand {
        at_tick: decision.at.ticks,
        deadline_tick,
        ceiling_tick,
        kind,
    })
}

pub(super) const fn virtual_time_from_advance_outcome(
    ceiling: Icount,
    outcome: AdvanceOutcome,
) -> VirtualTime {
    match outcome {
        AdvanceOutcome::ReachedHorizon => VirtualTime {
            ticks: ceiling.retired,
        },
        AdvanceOutcome::Paused { at } => VirtualTime { ticks: at.retired },
    }
}
