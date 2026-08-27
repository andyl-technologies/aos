//! Tests for live QEMU node lifecycle and fault transport.

use std::collections::VecDeque;
use std::error::Error;
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crucible::{
    CheckpointKind, ContentHash, EventLogCoverageObservation, ExecutionHorizon, GdbListen, NodeId,
    event_log_coverage_projection,
};
use crucible_shmem::{
    FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR, FAULT_COMMAND_SEMANTIC_VERSION,
    FaultBoundaryPhase, FaultCapabilityScope, FaultCommandKind, FaultEventHeaderV1,
    FaultEventOutcomeV1, FaultResultHeaderV1,
};

use crate::{
    QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome, QemuNodeSet,
    QemuQuantumOperation,
};

use super::*;

#[path = "node/tests/child_exit.rs"]
mod child_exit;
#[path = "node/tests/fault_command.rs"]
mod fault_command;
#[path = "node/tests/host_io_runtime.rs"]
pub(crate) mod host_io_runtime;
#[path = "node/tests/sequence_restore.rs"]
mod sequence_restore;
#[path = "node/tests/shutdown_and_preemption.rs"]
mod shutdown_and_preemption;

type SharedLog = Arc<Mutex<Vec<ChannelCall>>>;
type SharedFaultCommands = Arc<Mutex<Vec<(FaultCommandHeaderV1, Vec<u8>)>>>;
type SharedFaultEvents = Arc<Mutex<VecDeque<DequeuedFaultEvent>>>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum ChannelCall {
    ShmemCurrentIcount,
    HostYield,
    HostAwait {
        wait: QemuAsyncWait,
        timeout: Duration,
        outcome: QemuAsyncWaitOutcome,
    },
    ShmemStart(u64),
    ShmemFinish(u64),
    ShmemPreemption(SchedulerPreemptionCommand),
    ShmemDeliver {
        node: String,
        payload: Vec<u8>,
    },
    ShmemEmit,
    ShmemIdle,
    ShmemFingerprint,
    ShmemSelectableReply(u64),
    HostFingerprintBoundary,
    HostCheckpointClearWhileStopped,
    HostCheckpointAbort,
    HostFaultEventLimit {
        maximum_local_records: usize,
        canonical_current_offset: usize,
        configured_event_records: usize,
    },
    QmpStop,
    QmpContinue,
    QmpHotForkReadiness,
    QmpHotForkThreadInventory,
    QmpHotForkRcuInventory,
    QmpHotForkAioInventory,
    QmpHotForkBottomHalfInventory,
    QmpHotForkMutexInventory,
    QmpHotForkTimerInventory,
    QmpTerminalLifecycle {
        action: ContentHash,
        evidence: ContentHash,
        process_generation: u64,
    },
    QmpExactSave(ContentHash),
    QmpExactDelete(ContentHash),
    QmpActivateDebugGuest,
    PluginQuit,
    QmpQuit,
}

#[derive(Clone)]
struct ScriptedPluginControl {
    log: SharedLog,
    fail_quit: bool,
}

#[derive(Clone)]
struct ScriptedShmemHotPath {
    log: SharedLog,
    fail_advance: bool,
    coverage_enabled: bool,
    quantum_coverage: Arc<Mutex<VecDeque<Vec<ObservableEvent>>>>,
    teardown_coverage: Arc<Mutex<Vec<ObservableEvent>>>,
    fault_commands: SharedFaultCommands,
    stale_fault_results: Arc<Mutex<VecDeque<DequeuedFaultResult>>>,
    fault_events: SharedFaultEvents,
    fingerprint_retry_countdown: Arc<Mutex<u8>>,
}

#[derive(Clone)]
struct ScriptedHostIoRuntime {
    log: SharedLog,
    outcomes: VecDeque<QemuAsyncWaitOutcome>,
    fault_results: VecDeque<DequeuedFaultResult>,
    staged_fault_events: Vec<DequeuedFaultEvent>,
    fingerprint_fault_events: VecDeque<DequeuedFaultEvent>,
}

#[derive(Clone)]
struct ScriptedQmpMachineControl {
    log: SharedLog,
    process_id: u32,
    fail_stop: bool,
    fail_snapshot: bool,
    timeout_snapshot: bool,
}

impl QemuPluginIpcControlChannel for ScriptedPluginControl {
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::PluginQuit);
        if self.fail_quit {
            return Err(QemuNodeChannelError::new("send_quit", "control closed"));
        }
        Ok(())
    }
}

impl QemuShmemHotPathChannel for ScriptedShmemHotPath {
    fn checkpoint_network_transport(
        &mut self,
    ) -> Result<crate::QemuNetworkTransportCheckpoint, QemuNodeChannelError> {
        Ok(crate::QemuNetworkTransportCheckpoint {
            inbound: crucible_shmem::SpscRingSnapshot { frames: Vec::new() },
            outbound: crucible_shmem::SpscRingSnapshot { frames: Vec::new() },
            queue_capacity: crucible_shmem::DEFAULT_QUEUE_CAPACITY,
            router_slot: crucible_shmem::SLOT_NET_ROUTER as u32,
            next_router_inbound_sequence: 0,
            next_host_outbound_sequence: 0,
            next_plugin_outbound_sequence: 0,
        })
    }

    fn restore_network_transport(
        &mut self,
        _checkpoint: &crate::QemuNetworkTransportCheckpoint,
    ) -> Result<(), QemuNodeChannelError> {
        Ok(())
    }

    fn coverage_enabled(&self) -> bool {
        self.coverage_enabled
    }

    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemCurrentIcount);
        Ok(Icount { retired: 11 })
    }

    fn logical_time_calibration(
        &mut self,
    ) -> Result<QemuLogicalTimeCalibration, QemuNodeChannelError> {
        Ok(QemuLogicalTimeCalibration {
            logical_icount: 11,
            raw_icount: 11,
        })
    }

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemStart(horizon.icount.retired));
        if self.fail_advance {
            return Err(QemuNodeChannelError::new(
                "advance_to_horizon",
                "futex wake failed",
            ));
        }
        Ok(QemuNodePendingQuantum::new(horizon.icount.retired))
    }

    fn poll_quantum(
        &mut self,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        let horizon = *pending.downcast_mut::<u64>("finish_quantum")?;
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemFinish(horizon));
        if let Some(events) = self.quantum_coverage.lock().unwrap().pop_front() {
            self.teardown_coverage.lock().unwrap().extend(events);
        }
        Ok(QemuAsyncQuantumCompletion {
            ceiling: Icount { retired: horizon },
            outcome: AdvanceOutcome::ReachedHorizon,
            final_state: QemuNodeIdleState {
                current_icount: Icount { retired: horizon },
                next_deadline: None,
            },
            inbound_frames_consumed: 0,
            emitted_frames: Vec::new(),
            operations: vec![
                QemuQuantumOperation::StoreSchedulerCeiling,
                QemuQuantumOperation::FutexWake,
                QemuQuantumOperation::ObservePluginReport,
            ],
        })
    }

    fn publish_preemption_command(
        &mut self,
        command: SchedulerPreemptionCommand,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemPreemption(command));
        Ok(())
    }

    fn enqueue_selectable_reply(
        &mut self,
        _pending: &crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::ShmemSelectableReply(reply.sequence()));
        Ok(())
    }

    fn enqueue_fault_command(
        &mut self,
        header: FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<(), QemuNodeChannelError> {
        self.fault_commands
            .lock()
            .unwrap()
            .push((header, payload.to_vec()));
        Ok(())
    }

    fn dequeue_fault_result(
        &mut self,
    ) -> Result<Option<DequeuedFaultResult>, QemuNodeChannelError> {
        Ok(self.stale_fault_results.lock().unwrap().pop_front())
    }

    fn dequeue_fault_event(&mut self) -> Result<Option<DequeuedFaultEvent>, QemuNodeChannelError> {
        Ok(self.fault_events.lock().unwrap().pop_front())
    }

    fn fault_event_pending(&mut self) -> Result<bool, QemuNodeChannelError> {
        Ok(!self.fault_events.lock().unwrap().is_empty())
    }

    fn fault_event_count(&mut self) -> Result<usize, QemuNodeChannelError> {
        Ok(self.fault_events.lock().unwrap().len())
    }

    fn snapshot_fault_events(
        &mut self,
        destination: &mut Vec<DequeuedFaultEvent>,
        canonical_payload_bytes: &mut usize,
        configured_payload_bytes: usize,
        configured_inline_payload_bytes: usize,
    ) -> Result<(), QemuNodeError> {
        let events = self.fault_events.lock().unwrap();
        fault_event_budget::snapshot_scripted_fault_events(
            &events,
            destination,
            canonical_payload_bytes,
            configured_payload_bytes,
            configured_inline_payload_bytes,
        )
    }

    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, QemuNodeChannelError> {
        Ok(std::mem::take(&mut *self.teardown_coverage.lock().unwrap()))
    }

    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::ShmemDeliver {
            node: input.node.name,
            payload: input.payload,
        });
        Ok(())
    }

    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::ShmemEmit);
        Ok(Some(QemuNodeEmittedFrame {
            source: node_id("vm-a"),
            destination: node_id("vm-b"),
            emit_icount: Icount { retired: 17 },
            sequence: 7,
            payload: vec![8, 9],
        }))
    }

    fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::ShmemIdle);
        Ok(QemuNodeIdleState {
            current_icount: Icount { retired: 13 },
            next_deadline: Some(Icount { retired: 21 }),
        })
    }

    fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::ShmemFingerprint);
        let mut retry_countdown = self.fingerprint_retry_countdown.lock().unwrap();
        if *retry_countdown > 0 {
            *retry_countdown -= 1;
            return Err(QemuNodeChannelError::retryable(
                "execution_fingerprint",
                "scripted sample is stale",
            ));
        }
        Ok(ExecutionFingerprint {
            hash: content_hash("fingerprint", "vm-a"),
        })
    }

    fn fingerprint_sample(&mut self) -> Result<QemuFingerprintSample, QemuNodeChannelError> {
        let mut sample = QemuFingerprintSample {
            sample_icount: 11,
            vcpu_count: 1,
            rr_switch_quantum: 4_096,
            ..QemuFingerprintSample::default()
        };
        sample.vcpus[0].register_file_bytes = 1;
        Ok(sample)
    }
}

impl QemuQmpMachineControlChannel for ScriptedQmpMachineControl {
    fn stop_for_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpStop);
        if self.fail_stop {
            return Err(QemuNodeChannelError::new(
                "stop_for_checkpoint",
                "injected QMP stop failure",
            ));
        }
        Ok(())
    }

    fn resume_after_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpContinue);
        Ok(())
    }

    fn query_hot_fork_readiness(
        &mut self,
    ) -> Result<crate::QmpHotForkReadiness, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkReadiness);
        crate::QmpHotForkReadiness::from_acknowledged_proofs(7).ok_or_else(|| {
            QemuNodeChannelError::new(
                "query_hot_fork_readiness",
                "scripted readiness bitmap is invalid",
            )
        })
    }

    fn query_hot_fork_thread_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkThreadInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkThreadInventory);
        Ok(crate::QmpHotForkThreadInventory::one_coordinator(
            self.process_id,
        ))
    }

    fn query_hot_fork_rcu_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkRcuInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkRcuInventory);
        Ok(crate::QmpHotForkRcuInventory::from_reader_ids(&[
            self.process_id
        ]))
    }

    fn query_hot_fork_aio_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkAioInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkAioInventory);
        Ok(crate::QmpHotForkAioInventory::one_idle(1, self.process_id))
    }

    fn query_hot_fork_bottom_half_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkBottomHalfInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkBottomHalfInventory);
        Ok(crate::QmpHotForkBottomHalfInventory::one_idle(1, 1))
    }

    fn query_hot_fork_mutex_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkMutexInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkMutexInventory);
        Ok(crate::QmpHotForkMutexInventory::one_owned(
            1,
            self.process_id,
        ))
    }

    fn query_hot_fork_timer_inventory(
        &mut self,
    ) -> Result<crate::QmpHotForkTimerInventory, QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpHotForkTimerInventory);
        Ok(crate::QmpHotForkTimerInventory::empty())
    }

    fn complete_terminal_lifecycle_exit(
        &mut self,
        action: ContentHash,
        evidence: ContentHash,
        process_generation: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpTerminalLifecycle {
                action,
                evidence,
                process_generation,
            });
        Ok(())
    }

    fn save_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpExactSave(checkpoint.id));
        if self.timeout_snapshot {
            return Err(QemuNodeChannelError::bounded_await_timeout(
                "save_checkpoint_vmstate",
                "QMP command timed out",
                Duration::from_millis(2),
            ));
        }
        if self.fail_snapshot {
            return Err(QemuNodeChannelError::new(
                "save_checkpoint_vmstate",
                "QMP error",
            ));
        }
        Ok(())
    }

    fn delete_checkpoint_vmstate(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpExactDelete(checkpoint.id));
        Ok(())
    }

    fn quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpQuit);
        Ok(())
    }

    fn activate_debug_guest(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::QmpActivateDebugGuest);
        Ok(())
    }
}

impl QemuHostIoRuntime for ScriptedHostIoRuntime {
    fn set_fault_event_staging_limit(
        &mut self,
        maximum_local_records: usize,
        canonical_current_offset: usize,
        configured_event_records: usize,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if self.staged_fault_events.len() > maximum_local_records {
            return Err(QemuAsyncDriverRuntimeError::fault_event_storage(
                canonical_current_offset.saturating_add(self.staged_fault_events.len()),
                0,
                configured_event_records,
            ));
        }
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::HostFaultEventLimit {
                maximum_local_records,
                canonical_current_offset,
                configured_event_records,
            });
        Ok(())
    }

    fn publish_current_execution_fingerprint(
        &mut self,
        _timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::HostFingerprintBoundary);
        if let Some(event) = self.fingerprint_fault_events.pop_front() {
            self.staged_fault_events.push(event);
        }
        Ok(())
    }

    fn clear_checkpoint_pause_while_stopped(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::HostCheckpointClearWhileStopped);
        Ok(())
    }

    fn abort_checkpoint_pause(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.log
            .lock()
            .unwrap()
            .push(ChannelCall::HostCheckpointAbort);
        Ok(())
    }

    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.log.lock().unwrap().push(ChannelCall::HostYield);
        Ok(())
    }

    fn await_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        let outcome = self.outcomes.pop_front().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new("await child", "no scripted outcome")
        })?;
        self.log.lock().unwrap().push(ChannelCall::HostAwait {
            wait,
            timeout,
            outcome,
        });
        Ok(outcome)
    }

    fn repoll_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        self.await_child(wait, timeout)
    }
    fn await_fault_result(
        &mut self,
        _timeout: Duration,
        payload_buffer: Vec<u8>,
        _maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        let result = self.fault_results.pop_front().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new("await fault result", "no scripted fault result")
        })?;
        let required = match &result {
            DequeuedFaultResult::Valid { payload, .. } => payload.len(),
            DequeuedFaultResult::Invalid { .. } => 0,
        };
        if payload_buffer.capacity() < required {
            return Err(QemuAsyncDriverRuntimeError::new(
                "await fault result",
                format!(
                    "scripted result buffer capacity {} is smaller than {required}",
                    payload_buffer.capacity()
                ),
            ));
        }
        Ok(result)
    }

    fn await_fault_preparation_result(
        &mut self,
        _timeout: Duration,
        maximum_payload_bytes: usize,
        _maximum_event_records: usize,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        let result = self.fault_results.front().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "await fault preparation result",
                "no scripted fault result",
            )
        })?;
        let required = match result {
            DequeuedFaultResult::Valid { payload, .. } => payload.len(),
            DequeuedFaultResult::Invalid { .. } => 0,
        };
        if required > maximum_payload_bytes {
            return Err(QemuAsyncDriverRuntimeError::fault_result_storage(
                required,
                maximum_payload_bytes,
            ));
        }
        self.fault_results.pop_front().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "await fault preparation result",
                "scripted fault result disappeared after admission",
            )
        })
    }

    fn take_staged_fault_events(
        &mut self,
    ) -> Result<Vec<DequeuedFaultEvent>, QemuAsyncDriverRuntimeError> {
        Ok(std::mem::take(&mut self.staged_fault_events))
    }

    fn staged_fault_events(&self) -> &[DequeuedFaultEvent] {
        &self.staged_fault_events
    }

    fn staged_fault_events_pending(&self) -> bool {
        !self.staged_fault_events.is_empty()
    }

    fn staged_fault_event_count(&self) -> usize {
        self.staged_fault_events.len()
    }
}

#[test]
fn qemu_node_owns_one_child_and_exactly_three_channel_roles() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

    assert_eq!(
        node.channel_roles(),
        [
            QemuNodeChannelPlane::PluginIpcControl,
            QemuNodeChannelPlane::ShmemHotPath,
            QemuNodeChannelPlane::QmpMachineControl,
        ]
    );
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);
    assert!(!node.child_reaped());
    assert!(recorded(&log).is_empty());

    let report = node.shutdown_child()?;
    assert!(report.reaped);
    assert!(node.child_reaped());
    assert_eq!(
        report
            .attempts
            .iter()
            .map(|attempt| attempt.rung)
            .collect::<Vec<_>>(),
        [
            QemuShutdownRung::ControlQuit,
            QemuShutdownRung::QmpQuit,
            QemuShutdownRung::Sigterm,
        ]
    );
    assert_eq!(
        node.lifecycle_state(),
        QemuNodeLifecycleState::ShutdownRequested
    );

    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn hot_fork_audit_brackets_one_exact_child_process_inventory() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let process_id = node.child.process_id();

    // `spawn` confirms `exec`, not completion of the child's loader/runtime
    // setup. Entering nanosleep gives the procfs fixed-point assertion a
    // deterministic fixture rather than racing startup mappings.
    let status_path = format!("/proc/{process_id}/status");
    let mut sleeping = false;
    for _ in 0..500 {
        let status = std::fs::read_to_string(&status_path)?;
        if status.lines().any(|line| line.starts_with("State:\tS")) {
            sleeping = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !sleeping {
        return Err(format!("scripted child {process_id} did not enter sleeping state").into());
    }

    let audit = node.audit_hot_fork_process()?;
    assert_eq!(audit.readiness().acknowledged_proofs(), 7);
    assert_eq!(audit.process().process().process_id, process_id);
    assert!(!audit.process().threads().is_empty());
    assert!(!audit.process().mappings().is_empty());
    assert_eq!(audit.qemu_threads().threads().len(), 1);
    assert_eq!(audit.qemu_threads().threads()[0].thread_id(), process_id);
    assert_eq!(audit.qemu_rcu().readers().len(), 1);
    assert_eq!(audit.qemu_rcu().readers()[0].thread_id(), process_id);
    assert_eq!(audit.qemu_aio().contexts().len(), 1);
    assert_eq!(
        audit.qemu_aio().contexts()[0].home_thread_id(),
        Some(process_id)
    );
    assert_eq!(audit.qemu_bottom_halves().bottom_halves().len(), 1);
    assert_eq!(
        audit.qemu_bottom_halves().bottom_halves()[0].context_id(),
        1
    );
    assert_eq!(audit.qemu_mutexes().mutexes().len(), 1);
    assert_eq!(
        audit.qemu_mutexes().mutexes()[0].owner_thread_id(),
        Some(process_id)
    );
    assert!(audit.qemu_timers().timers().is_empty());
    assert!(audit.externally_created_thread_ids().is_empty());
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::QmpHotForkReadiness,
            ChannelCall::QmpHotForkThreadInventory,
            ChannelCall::QmpHotForkRcuInventory,
            ChannelCall::QmpHotForkAioInventory,
            ChannelCall::QmpHotForkBottomHalfInventory,
            ChannelCall::QmpHotForkMutexInventory,
            ChannelCall::QmpHotForkTimerInventory,
            ChannelCall::QmpHotForkTimerInventory,
            ChannelCall::QmpHotForkMutexInventory,
            ChannelCall::QmpHotForkBottomHalfInventory,
            ChannelCall::QmpHotForkAioInventory,
            ChannelCall::QmpHotForkRcuInventory,
            ChannelCall::QmpHotForkThreadInventory,
            ChannelCall::QmpHotForkReadiness,
        ]
    );

    node.shutdown_child()?;
    Ok(())
}

#[test]
fn failed_node_surrenders_its_direct_child_wait_authority() -> Result<(), Box<dyn Error>> {
    let node = scripted_node(shared_log(), false, false, false)?;
    let process_id = node.child.process_id();

    let mut child = node.into_direct_child_for_quarantine();

    assert_eq!(child.process_id(), process_id);
    assert!(!child.reaped());
    child.force_kill_and_reap_failed_realization()?;
    assert!(child.reaped());
    Ok(())
}

#[test]
fn live_fault_sequences_continue_after_capability_admission() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

    assert_eq!(node.reserve_fault_command_sequence()?, 2);
    assert_eq!(node.reserve_fault_command_sequence()?, 3);

    Ok(())
}

#[test]
fn qemu_node_routes_scheduler_operations_over_strict_channels() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

    assert_eq!(node.current_icount()?, Icount { retired: 11 });
    assert_eq!(
        Backend::advance_to_horizon(
            &mut node,
            ExecutionHorizon {
                icount: Icount { retired: 19 },
            },
        )?,
        AdvanceOutcome::ReachedHorizon
    );
    Backend::deliver_input(
        &mut node,
        BackendInput {
            node: node_id("vm-a"),
            payload: vec![1, 2, 3],
        },
    )?;
    assert_eq!(
        node.emit_frame()?,
        Some(QemuNodeEmittedFrame {
            source: node_id("vm-a"),
            destination: node_id("vm-b"),
            emit_icount: Icount { retired: 17 },
            sequence: 7,
            payload: vec![8, 9],
        })
    );
    assert_eq!(
        node.idle_state()?,
        QemuNodeIdleState {
            current_icount: Icount { retired: 13 },
            next_deadline: Some(Icount { retired: 21 }),
        }
    );
    assert_eq!(
        Backend::fingerprint(&mut node)?,
        ExecutionFingerprint {
            hash: content_hash("fingerprint", "vm-a"),
        }
    );

    assert!(matches!(
        Backend::snapshot(&mut node),
        Err(BackendError::Rejected { message })
            if message.contains("capture_exact_snapshot")
    ));
    let report = node.shutdown_child()?;

    assert!(report.reaped);
    assert_eq!(
        node.lifecycle_state(),
        QemuNodeLifecycleState::ShutdownRequested
    );
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::HostYield,
            ChannelCall::ShmemStart(19),
            ChannelCall::HostAwait {
                wait: QemuAsyncWait::AdvanceCompletion,
                timeout: Duration::from_millis(4),
                outcome: QemuAsyncWaitOutcome::Completed,
            },
            ChannelCall::ShmemFinish(19),
            ChannelCall::HostYield,
            ChannelCall::ShmemDeliver {
                node: String::from("vm-a"),
                payload: vec![1, 2, 3],
            },
            ChannelCall::ShmemEmit,
            ChannelCall::ShmemIdle,
            ChannelCall::ShmemFingerprint,
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );

    Ok(())
}

#[test]
fn selectable_reply_is_published_before_qemu_resumes() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let request = crucible_protocol::SelectionRequest::new(
        7,
        "product.test.selectable",
        "instance-a",
        None,
        128,
    )?;
    let pending = crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest::new(
        request, 41, 0, 0x1000,
    );
    let reply = crucible_protocol::SelectionReply::rejected(
        7,
        crucible_protocol::SelectionReplyStatus::Unavailable,
        [0; 32],
        [0; 32],
    )?;

    node.enqueue_selectable_reply(&pending, &reply)?;

    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemSelectableReply(7),
            ChannelCall::QmpContinue,
        ]
    );
    node.shutdown_child()?;
    Ok(())
}

#[path = "node_tests/exact_lifecycle_tests.rs"]
mod exact_lifecycle;
#[path = "node_tests/fault_event_budget.rs"]
mod fault_event_budget;
#[path = "node_tests/fingerprint.rs"]
mod fingerprint;

fn scripted_node(
    log: SharedLog,
    fail_plugin_quit: bool,
    fail_shmem_advance: bool,
    fail_qmp_snapshot: bool,
) -> Result<QemuNode, Box<dyn Error>> {
    scripted_node_with_runtime(
        log,
        fail_plugin_quit,
        fail_shmem_advance,
        fail_qmp_snapshot,
        [QemuAsyncWaitOutcome::Completed],
    )
}

fn scripted_node_with_runtime(
    log: SharedLog,
    fail_plugin_quit: bool,
    fail_shmem_advance: bool,
    fail_qmp_snapshot: bool,
    runtime_outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>,
) -> Result<QemuNode, Box<dyn Error>> {
    scripted_node_with_options(
        log,
        ScriptedNodeOptions {
            fail_plugin_quit,
            fail_shmem_advance,
            fail_qmp_stop: false,
            fail_qmp_snapshot,
            qmp_snapshot_timeout: false,
            fingerprint_retry_countdown: 0,
            fingerprint_fault_event_count: 0,
        },
        runtime_outcomes,
    )
}

#[derive(Clone, Copy, Debug, Default)]
struct ScriptedNodeOptions {
    fail_plugin_quit: bool,
    fail_shmem_advance: bool,
    fail_qmp_stop: bool,
    fail_qmp_snapshot: bool,
    qmp_snapshot_timeout: bool,
    fingerprint_retry_countdown: u8,
    fingerprint_fault_event_count: u8,
}

fn scripted_node_with_options(
    log: SharedLog,
    options: ScriptedNodeOptions,
    runtime_outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>,
) -> Result<QemuNode, Box<dyn Error>> {
    scripted_node_with_coverage(
        log,
        options,
        runtime_outcomes,
        std::iter::empty(),
        std::iter::empty(),
    )
}

fn scripted_node_with_fault_events(
    log: SharedLog,
    events: impl IntoIterator<Item = DequeuedFaultEvent>,
) -> Result<QemuNode, Box<dyn Error>> {
    let mut events = events.into_iter();
    let staged_fault_events = events.next().into_iter().collect();
    let child = Command::new("sleep").arg("60").spawn()?;
    let process_id = child.id();
    let channels = QemuNodeChannels::new(
        ScriptedPluginControl {
            log: Arc::clone(&log),
            fail_quit: false,
        },
        ScriptedShmemHotPath {
            log: Arc::clone(&log),
            fail_advance: false,
            coverage_enabled: false,
            quantum_coverage: Arc::new(Mutex::new(VecDeque::new())),
            teardown_coverage: Arc::new(Mutex::new(Vec::new())),
            fault_commands: Arc::new(Mutex::new(Vec::new())),
            stale_fault_results: Arc::new(Mutex::new(VecDeque::new())),
            fault_events: Arc::new(Mutex::new(events.collect())),
            fingerprint_retry_countdown: Arc::new(Mutex::new(0)),
        },
        ScriptedQmpMachineControl {
            log: Arc::clone(&log),
            process_id,
            fail_stop: false,
            fail_snapshot: false,
            timeout_snapshot: false,
        },
    );
    Ok(QemuNode::new(
        QemuNodeChild::new(child),
        channels,
        node_shutdown_policy(),
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new("vm-a"),
        ScriptedHostIoRuntime {
            log,
            outcomes: VecDeque::new(),
            fault_results: VecDeque::new(),
            staged_fault_events,
            fingerprint_fault_events: VecDeque::new(),
        },
        2,
    ))
}

fn fault_event_with_sequence(event_sequence: u64) -> DequeuedFaultEvent {
    let payload = Vec::new();
    DequeuedFaultEvent {
        header: FaultEventHeaderV1 {
            command_kind: FaultCommandKind::CpuService,
            outcome: FaultEventOutcomeV1::Applied,
            event_sequence,
            rule_command_sequence: 1,
            observed_icount: 1,
            model_phase: 1,
            target_kind: 1,
            generation: 1,
            binding_hash: [1; 32],
            opportunity_hash: [2; 32],
            action_hash: [3; 32],
            target_hash: [4; 32],
            before_hash: [5; 32],
            after_hash: [6; 32],
            evidence_hash: [7; 32],
            payload_hash: *blake3::hash(&payload).as_bytes(),
            payload_offset: 0,
            payload_length: 0,
        },
        payload,
    }
}

fn scripted_node_with_coverage(
    log: SharedLog,
    options: ScriptedNodeOptions,
    runtime_outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>,
    quantum_coverage: impl IntoIterator<Item = Vec<ObservableEvent>>,
    teardown_coverage: impl IntoIterator<Item = ObservableEvent>,
) -> Result<QemuNode, Box<dyn Error>> {
    let quantum_coverage = quantum_coverage.into_iter().collect::<VecDeque<_>>();
    let teardown_coverage = teardown_coverage.into_iter().collect::<Vec<_>>();
    let coverage_enabled = !quantum_coverage.is_empty() || !teardown_coverage.is_empty();
    let child = Command::new("sleep").arg("60").spawn()?;
    let process_id = child.id();
    let channels = QemuNodeChannels::new(
        ScriptedPluginControl {
            log: Arc::clone(&log),
            fail_quit: options.fail_plugin_quit,
        },
        ScriptedShmemHotPath {
            log: Arc::clone(&log),
            fail_advance: options.fail_shmem_advance,
            coverage_enabled,
            quantum_coverage: Arc::new(Mutex::new(quantum_coverage)),
            teardown_coverage: Arc::new(Mutex::new(teardown_coverage)),
            fault_commands: Arc::new(Mutex::new(Vec::new())),
            stale_fault_results: Arc::new(Mutex::new(VecDeque::new())),
            fault_events: Arc::new(Mutex::new(VecDeque::new())),
            fingerprint_retry_countdown: Arc::new(Mutex::new(options.fingerprint_retry_countdown)),
        },
        ScriptedQmpMachineControl {
            log: Arc::clone(&log),
            process_id,
            fail_stop: options.fail_qmp_stop,
            fail_snapshot: options.fail_qmp_snapshot,
            timeout_snapshot: options.qmp_snapshot_timeout,
        },
    );
    Ok(QemuNode::new(
        QemuNodeChild::new(child),
        channels,
        node_shutdown_policy(),
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new("vm-a"),
        ScriptedHostIoRuntime {
            log,
            outcomes: runtime_outcomes.into_iter().collect(),
            fault_results: VecDeque::new(),
            staged_fault_events: Vec::new(),
            fingerprint_fault_events: (1..=options.fingerprint_fault_event_count)
                .map(|sequence| fault_event_with_sequence(u64::from(sequence)))
                .collect(),
        },
        2,
    ))
}

fn node_shutdown_policy() -> QemuShutdownPolicy {
    let mut policy = QemuShutdownPolicy::fast_test();
    policy.sigterm_wait = Duration::from_secs(2);
    policy.sigkill_wait = Duration::from_secs(1);
    policy.reap_wait = Duration::from_secs(1);
    policy
}

fn shared_log() -> SharedLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn recorded(log: &SharedLog) -> Vec<ChannelCall> {
    log.lock().unwrap().clone()
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn checkpoint(name: &str) -> Checkpoint {
    Checkpoint::new(
        content_hash("checkpoint", name),
        content_hash("configuration", name),
        CheckpointKind::Fat,
    )
}

fn content_hash(domain: &str, material: &str) -> ContentHash {
    ContentHash::from_canonical_material(domain, material)
}
