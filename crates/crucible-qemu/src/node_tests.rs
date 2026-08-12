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
    QemuAsyncDriverRuntimeError, QemuAsyncWait, QemuAsyncWaitOutcome, QemuQuantumOperation,
};

use super::*;

#[path = "node/tests/shutdown_and_preemption.rs"]
mod shutdown_and_preemption;

type SharedLog = Arc<Mutex<Vec<ChannelCall>>>;
type SharedFaultCommands = Arc<Mutex<Vec<(FaultCommandHeaderV1, Vec<u8>)>>>;
type SharedFaultEvents = Arc<Mutex<VecDeque<DequeuedFaultEvent>>>;

#[cfg(target_os = "linux")]
#[test]
fn orphan_quarantine_ignores_a_reused_process_identity() -> Result<(), Box<dyn Error>> {
    let current = linux_process_identity(std::process::id())?
        .ok_or("test process should have a Linux process identity")?;
    let mismatched = QemuProcessIdentity {
        start_time_ticks: current
            .start_time_ticks
            .checked_add(1)
            .ok_or("test start-time tick should increment")?,
        ..current
    };

    quarantine_orphaned_qemu_process(&mismatched, Duration::from_millis(10))?;
    assert!(linux_process_identity(std::process::id())?.is_some());
    Ok(())
}

#[test]
fn child_poll_preserves_clean_exit_status_and_disarms_drop_cleanup() -> Result<(), Box<dyn Error>> {
    let child = Command::new("true").spawn()?;
    let mut child = QemuNodeChild::new(child);
    wait_for_test_child_exit_pending(&child)?;
    let status = child
        .try_wait_natural_exit()?
        .ok_or("child remained live after closing its output pipe")?;

    assert!(status.success());
    assert!(child.reaped());
    drop(child);
    Ok(())
}

#[cfg(unix)]
#[test]
fn child_poll_preserves_signal_termination_as_unclean() -> Result<(), Box<dyn Error>> {
    use std::os::unix::process::ExitStatusExt as _;

    let child = Command::new("sleep").arg("60").spawn()?;
    let mut child = QemuNodeChild::new(child);
    signal_child(
        child.child.id(),
        libc::SIGTERM,
        "terminate child test fixture",
    )?;
    wait_for_test_child_exit_pending(&child)?;
    let status = child
        .try_wait_natural_exit()?
        .ok_or("signaled child remained live after closing its output pipe")?;

    assert!(!status.success());
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    assert!(child.reaped());
    Ok(())
}

fn wait_for_test_child_exit_pending(child: &QemuNodeChild) -> Result<(), Box<dyn Error>> {
    use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

    let pid = Pid::from_child(&child.child);
    waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
    )?
    .ok_or("waitid returned no status for a blocking child-exit wait")?;
    Ok(())
}

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
    QmpStop,
    QmpContinue,
    QmpExactSave(ContentHash),
    QmpExactDelete(ContentHash),
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
}

#[derive(Clone)]
struct ScriptedHostIoRuntime {
    log: SharedLog,
    outcomes: VecDeque<QemuAsyncWaitOutcome>,
    fault_results: VecDeque<DequeuedFaultResult>,
}

#[derive(Clone)]
struct ScriptedQmpMachineControl {
    log: SharedLog,
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
            outcome: AdvanceOutcome::ReachedHorizon,
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
        Ok(ExecutionFingerprint {
            hash: content_hash("fingerprint", "vm-a"),
        })
    }
}

impl QemuQmpMachineControlChannel for ScriptedQmpMachineControl {
    fn stop_for_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpStop);
        Ok(())
    }

    fn resume_after_checkpoint(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.lock().unwrap().push(ChannelCall::QmpContinue);
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
}

impl QemuHostIoRuntime for ScriptedHostIoRuntime {
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
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        self.fault_results.pop_front().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new("await fault result", "no scripted fault result")
        })
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

#[test]
fn live_fault_sequences_continue_after_capability_admission() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

    assert_eq!(node.reserve_fault_command_sequence()?, 2);
    assert_eq!(node.reserve_fault_command_sequence()?, 3);

    Ok(())
}

#[test]
fn invalid_fault_event_sequence_is_terminal_across_retries() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_fault_events(
        Arc::clone(&log),
        [fault_event_with_sequence(1), fault_event_with_sequence(3)],
    )?;
    let mut retained = Vec::new();

    let first_error = node
        .drain_fault_events(&mut retained)
        .expect_err("a sequence gap must fail closed");
    assert_eq!(retained.len(), 2);
    let second_error = node
        .drain_fault_events(&mut retained)
        .expect_err("retry must preserve the terminal sequence failure");
    assert_eq!(retained.len(), 2);
    assert_eq!(first_error.to_string(), second_error.to_string());
    assert!(first_error.to_string().contains("expected 2, observed 3"));
    let pending_error = node
        .fault_event_pending()
        .expect_err("checkpoint admission must observe the terminal failure");
    assert_eq!(first_error.to_string(), pending_error.to_string());

    node.shutdown_child()?;
    Ok(())
}

#[test]
fn fault_command_applies_at_exact_current_boundary_without_guest_progress()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let fault_commands = Arc::new(Mutex::new(Vec::new()));
    let payload = vec![1_u8, 2, 3, 4];
    let command = FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::MemoryMutation,
        command_flags: 0,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 7,
        target_node_hash: [1; 32],
        target_icount: 11,
        authorization_ceiling_icount: 11,
        binding_hash: [2; 32],
        opportunity_hash: [3; 32],
        expected_precondition_hash: [4; 32],
        payload_hash: *blake3::hash(&payload).as_bytes(),
        payload_offset: 0,
        payload_length: u32::try_from(payload.len())?,
    };
    let result = DequeuedFaultResult::Valid {
        header: FaultResultHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::MemoryMutation as u16,
            status: FaultResultStatus::Applied,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence: 7,
            observed_icount: 11,
            applied_icount: 11,
            capability_version: 1,
            phase: FaultBoundaryPhase::NodeBoundary,
            before_hash: [4; 32],
            after_hash: [5; 32],
            evidence_hash: [6; 32],
            result_payload_hash: *blake3::hash(&[]).as_bytes(),
            result_offset: 0,
            result_length: 0,
        },
        payload: Vec::new(),
    };
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
            fault_commands: Arc::clone(&fault_commands),
            stale_fault_results: Arc::new(Mutex::new(VecDeque::new())),
            fault_events: Arc::new(Mutex::new(VecDeque::new())),
        },
        ScriptedQmpMachineControl {
            log: Arc::clone(&log),
            fail_snapshot: false,
            timeout_snapshot: false,
        },
    );
    let child = Command::new("sleep").arg("60").spawn()?;
    let mut node = QemuNode::new(
        QemuNodeChild::new(child),
        channels,
        node_shutdown_policy(),
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new("vm-a"),
        ScriptedHostIoRuntime {
            log,
            outcomes: VecDeque::new(),
            fault_results: VecDeque::from([result.clone()]),
        },
    )
    .with_fault_capabilities(vec![FaultCapabilityRowV1 {
        command_kind: FaultCommandKind::MemoryMutation,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        scope: FaultCapabilityScope::All,
        phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
        maximum_payload_bytes: 64,
        maximum_pending_commands: 1,
        required_feature_bits: 0,
        capability_hash: [7; 32],
    }]);

    assert_eq!(
        node.apply_fault_command_at_current_boundary(command.clone(), &payload)?,
        result
    );
    assert_eq!(*fault_commands.lock().unwrap(), vec![(command, payload)]);
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
fn qemu_node_captures_one_identity_bound_vmstate_and_host_io_pair() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let mut checkpoint = checkpoint("paired-exact");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );

    let snapshot = node.capture_exact_snapshot(&node_identity, checkpoint.clone())?;

    assert_eq!(snapshot.checkpoint(), &checkpoint);
    assert_eq!(
        snapshot.host_io().execution_binding(),
        snapshot.checkpoint().id
    );
    assert_eq!(
        snapshot.replay_oracle_validation(),
        crate::QemuReplayOracleValidation::NotRun
    );
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpStop,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpExactSave(snapshot.checkpoint().id),
            ChannelCall::QmpContinue,
        ]
    );
    Ok(())
}

#[test]
fn qemu_node_terminates_after_failed_exact_capture() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, true)?;
    let mut checkpoint = checkpoint("failed-exact");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );

    let error = node
        .capture_exact_snapshot(&node_identity, checkpoint.clone())
        .expect_err("failed QMP save must reject the paired checkpoint");

    assert!(error.to_string().contains("save_checkpoint_vmstate"));
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpStop,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpExactSave(checkpoint.id),
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );
    assert!(node.child_reaped());
    Ok(())
}

#[test]
fn qemu_node_appends_quantum_coverage_to_the_unified_event_log() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let event = ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
    let mut node = scripted_node_with_coverage(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        [QemuAsyncWaitOutcome::Completed],
        [vec![event]],
        std::iter::empty(),
    )?;
    let mut event_log = EventLog::new();

    let (outcome, append) =
        node.advance_to_ceiling_with_event_log(Icount { retired: 19 }, &mut event_log)?;

    assert_eq!(outcome, AdvanceOutcome::ReachedHorizon);
    assert_eq!(append.entries.len(), 1);
    let projection = event_log_coverage_projection(&append.entries);
    assert_eq!(projection.len(), 1);
    assert_eq!(projection.entries()[0].at.icount, Icount { retired: 17 });
    assert_eq!(
        projection.entries()[0].observation,
        EventLogCoverageObservation::BasicBlock {
            node: node_id("vm-a"),
            guest_pc: 0x4010,
            block_len: 4,
        }
    );
    let (shutdown, _final_append) = node.shutdown_child_with_event_log(&mut event_log)?;
    assert!(shutdown.reaped);
    Ok(())
}

#[test]
fn qemu_node_rejects_a_coverage_quantum_without_an_event_log() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let event = ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
    let mut node = scripted_node_with_coverage(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        [QemuAsyncWaitOutcome::Completed],
        [vec![event]],
        std::iter::empty(),
    )?;

    assert_eq!(
        node.advance_to_ceiling(Icount { retired: 19 }),
        Err(QemuNodeError::CoverageEventLogRequired)
    );
    let mut event_log = EventLog::new();
    let (shutdown, append) = node.shutdown_child_with_event_log(&mut event_log)?;
    assert!(shutdown.reaped);
    assert!(append.entries.is_empty());
    Ok(())
}

#[test]
fn qemu_node_generic_backend_drains_coverage_without_a_local_side_record()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let event = ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
    let mut node = scripted_node_with_coverage(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        [QemuAsyncWaitOutcome::Completed],
        [vec![event]],
        std::iter::empty(),
    )?;

    let step = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 19 })?;
    assert_eq!(step.reached, VirtualTime { ticks: 19 });
    let observations = SimulationBackend::drain_observable_events(&mut node)?;
    assert_eq!(observations.len(), 1);
    assert!(SimulationBackend::drain_observable_events(&mut node)?.is_empty());

    let mut event_log = EventLog::new();
    let append = event_log.append_observable_events(observations)?;
    assert_eq!(event_log_coverage_projection(&append.entries).len(), 1);
    SimulationBackend::shutdown(&mut node)?;
    assert!(node.child_reaped());
    SimulationBackend::shutdown(&mut node)?;
    assert!(node.child_reaped());
    Ok(())
}

#[test]
fn qemu_node_stamps_polled_console_at_the_scheduler_boundary() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let spool = QemuConsoleObservationSpool::new();
    spool.append(b"guest output")?;
    let mut node = scripted_node_with_options(
        log,
        ScriptedNodeOptions::default(),
        [QemuAsyncWaitOutcome::Completed],
    )?
    .with_console_observation(node_id("vm-a"), spool);

    let boundary = VirtualTime { ticks: 97 };
    SimulationBackend::step_to(&mut node, boundary)?;
    node.last_observed_time = VirtualTime { ticks: 3 };
    let observations = SimulationBackend::drain_observable_events(&mut node)?;

    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].at(), boundary);
    SimulationBackend::shutdown(&mut node)?;
    Ok(())
}

#[test]
fn qemu_node_drains_final_coverage_before_teardown() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let event = ObservableEvent::coverage_block(Icount { retired: 17 }, node_id("vm-a"), 0x4010, 4);
    let mut node = scripted_node_with_coverage(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        std::iter::empty(),
        std::iter::empty(),
        [event],
    )?;
    let mut event_log = EventLog::new();

    let (report, append) = node.shutdown_child_with_event_log(&mut event_log)?;

    assert!(report.reaped);
    assert!(node.child_reaped());
    let projection = event_log_coverage_projection(&append.entries);
    assert_eq!(projection.len(), 1);
    assert_eq!(projection.entries()[0].at.icount, Icount { retired: 17 });
    Ok(())
}

#[test]
fn qemu_node_satisfies_simulation_backend_trait() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_runtime(
        Arc::clone(&log),
        false,
        false,
        false,
        [
            QemuAsyncWaitOutcome::Completed,
            QemuAsyncWaitOutcome::Completed,
        ],
    )?;

    let observation = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 23 })?;
    assert_eq!(observation.reached, VirtualTime { ticks: 23 });
    assert_eq!(SimulationBackend::now(&node), VirtualTime { ticks: 23 });

    assert!(matches!(
        SimulationBackend::apply(
            &mut node,
            &BackendEffect::Noop,
            VirtualTime { ticks: 22 },
        ),
        Err(BackendError::Rejected { message })
            if message.contains("does not match physical node time")
    ));
    SimulationBackend::apply(
        &mut node,
        &BackendEffect::DeliverInput(BackendInput {
            node: node_id("vm-a"),
            payload: vec![3, 2, 1],
        }),
        VirtualTime { ticks: 23 },
    )?;
    let sample = SimulationBackend::fingerprint(&mut node, node_id("vm-a"))?;
    assert_eq!(sample.node, node_id("vm-a"));
    assert_eq!(sample.at, VirtualTime { ticks: 23 });
    assert_eq!(
        sample.fingerprint,
        ExecutionFingerprint {
            hash: content_hash("fingerprint", "vm-a"),
        }
    );

    assert!(matches!(
        SimulationBackend::snapshot(&mut node),
        Err(BackendError::Rejected { message })
            if message.contains("capture_exact_snapshot")
    ));
    let later = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 29 })?;
    assert_eq!(later.reached, VirtualTime { ticks: 29 });
    assert_eq!(SimulationBackend::now(&node), VirtualTime { ticks: 29 });
    SimulationBackend::shutdown(&mut node)?;

    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::HostYield,
            ChannelCall::ShmemStart(23),
            ChannelCall::HostAwait {
                wait: QemuAsyncWait::AdvanceCompletion,
                timeout: Duration::from_millis(4),
                outcome: QemuAsyncWaitOutcome::Completed,
            },
            ChannelCall::ShmemFinish(23),
            ChannelCall::HostYield,
            ChannelCall::ShmemDeliver {
                node: String::from("vm-a"),
                payload: vec![3, 2, 1],
            },
            ChannelCall::ShmemFingerprint,
            ChannelCall::HostYield,
            ChannelCall::ShmemStart(29),
            ChannelCall::HostAwait {
                wait: QemuAsyncWait::AdvanceCompletion,
                timeout: Duration::from_millis(4),
                outcome: QemuAsyncWaitOutcome::Completed,
            },
            ChannelCall::ShmemFinish(29),
            ChannelCall::HostYield,
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );

    Ok(())
}

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
            fail_qmp_snapshot,
            qmp_snapshot_timeout: false,
        },
        runtime_outcomes,
    )
}

#[derive(Clone, Copy, Debug, Default)]
struct ScriptedNodeOptions {
    fail_plugin_quit: bool,
    fail_shmem_advance: bool,
    fail_qmp_snapshot: bool,
    qmp_snapshot_timeout: bool,
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
            fault_events: Arc::new(Mutex::new(events.into_iter().collect())),
        },
        ScriptedQmpMachineControl {
            log: Arc::clone(&log),
            fail_snapshot: false,
            timeout_snapshot: false,
        },
    );
    let child = Command::new("sleep").arg("60").spawn()?;
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
        },
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
        },
        ScriptedQmpMachineControl {
            log: Arc::clone(&log),
            fail_snapshot: options.fail_qmp_snapshot,
            timeout_snapshot: options.qmp_snapshot_timeout,
        },
    );
    let child = Command::new("sleep").arg("60").spawn()?;
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
        },
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
