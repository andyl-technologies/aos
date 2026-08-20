//! Tests for the asynchronous QEMU driver.

use super::*;

use std::collections::VecDeque;

use crate::{
    QemuCrashCause, QemuNodeIdleState, QemuQuantumOperation, QemuShutdownAttempt, QemuShutdownRung,
};
use crucible::Icount;

#[test]
fn async_driver_completes_one_quantum_with_bounded_wait_and_yields() {
    let policy = QemuAsyncDriverPolicy::fast_test();
    let mut target = ScriptedTarget::completed();
    let mut runtime = ScriptedRuntime::new([QemuAsyncWaitOutcome::Completed]);
    let crash_detector = QemuCrashDetector::new("vm-a");

    let report = match run_bounded_qemu_node_step(
        &mut target,
        &mut runtime,
        policy,
        &crash_detector,
        horizon(12),
    ) {
        Ok(report) => report,
        Err(error) => panic!("bounded node-step should complete: {error}"),
    };

    assert_eq!(
        report.outcome,
        QemuAsyncNodeStepOutcome::Completed {
            advance: AdvanceOutcome::ReachedHorizon,
        }
    );
    assert!(report.yielded_before_quantum);
    assert!(report.yielded_after_quantum);
    assert_eq!(
        report.hot_path_operations,
        vec![
            QemuQuantumOperation::StoreSchedulerCeiling,
            QemuQuantumOperation::FutexWake,
            QemuQuantumOperation::ObservePluginReport,
        ]
    );
    assert_eq!(
        report.async_operations,
        vec![
            QemuAsyncDriverOperation::YieldToControlPlane,
            QemuAsyncDriverOperation::AwaitChild {
                wait: QemuAsyncWait::AdvanceCompletion,
                timeout: Duration::from_millis(4),
                outcome: QemuAsyncWaitOutcome::Completed,
            },
            QemuAsyncDriverOperation::YieldToControlPlane,
        ]
    );
    assert_eq!(target.started, vec![12]);
    assert_eq!(target.finished, 1);
    assert_eq!(target.shutdowns, 0);
    assert_eq!(runtime.yields, 2);
}

#[test]
fn async_driver_preserves_consumed_inbound_boundary_progress() {
    let policy = QemuAsyncDriverPolicy::fast_test();
    let mut target = ScriptedTarget::completed();
    target.completion.inbound_frames_consumed = 2;
    let mut runtime = ScriptedRuntime::new([QemuAsyncWaitOutcome::Completed]);
    let crash_detector = QemuCrashDetector::new("vm-a");

    let report = run_bounded_qemu_node_step(
        &mut target,
        &mut runtime,
        policy,
        &crash_detector,
        horizon(12),
    )
    .unwrap_or_else(|error| panic!("inbound boundary should complete: {error}"));

    assert_eq!(report.inbound_frames_consumed, 2);
}

#[test]
fn async_driver_repolls_a_transient_shared_memory_report() {
    let policy = QemuAsyncDriverPolicy::fast_test();
    let mut target = ScriptedTarget::pending_once();
    let mut runtime = ScriptedRuntime::new([
        QemuAsyncWaitOutcome::Completed,
        QemuAsyncWaitOutcome::Completed,
    ]);
    let crash_detector = QemuCrashDetector::new("vm-a");

    let report = run_bounded_qemu_node_step(
        &mut target,
        &mut runtime,
        policy,
        &crash_detector,
        horizon(12),
    )
    .unwrap_or_else(|error| panic!("transient report should be repolled: {error}"));

    assert_eq!(
        report.outcome,
        QemuAsyncNodeStepOutcome::Completed {
            advance: AdvanceOutcome::ReachedHorizon,
        }
    );
    assert_eq!(target.finished, 2);
    assert_eq!(
        report
            .async_operations
            .iter()
            .filter(|operation| matches!(
                operation,
                QemuAsyncDriverOperation::AwaitChild {
                    wait: QemuAsyncWait::AdvanceCompletion,
                    outcome: QemuAsyncWaitOutcome::Completed,
                    ..
                }
            ))
            .count(),
        2
    );
    assert_eq!(target.shutdowns, 0);
    assert_eq!(runtime.awaits, 1);
    assert_eq!(runtime.repolls, 1);
}

#[test]
fn async_driver_timeout_surfaces_crash_and_escalates_shutdown() {
    let policy = QemuAsyncDriverPolicy::fast_test();
    let mut target = ScriptedTarget::completed();
    let mut runtime = ScriptedRuntime::new([QemuAsyncWaitOutcome::TimedOut]);
    let crash_detector = QemuCrashDetector::new("vm-a");

    let report = match run_bounded_qemu_node_step(
        &mut target,
        &mut runtime,
        policy,
        &crash_detector,
        horizon(20),
    ) {
        Ok(report) => report,
        Err(error) => panic!("timeout should return crashed-node report: {error}"),
    };

    match report.outcome {
        QemuAsyncNodeStepOutcome::Crashed { status, shutdown } => {
            assert!(status.is_infrastructure_crash());
            match status {
                QemuNodeRunStatus::Crashed(crash) => {
                    assert_eq!(crash.node_id, "vm-a");
                    assert_eq!(
                        crash.cause,
                        QemuCrashCause::BoundedAwaitTimeout(crate::QemuBoundedAwaitTimeout::new(
                            "advance completion",
                            Duration::from_millis(4),
                        ),)
                    );
                    assert!(!crash.handling.retry_on_determinism_gate());
                }
                _ => panic!("timeout should produce crashed-node status"),
            }
            assert!(shutdown.reaped);
        }
        QemuAsyncNodeStepOutcome::Completed { .. } => {
            panic!("timeout should not complete the quantum")
        }
    }
    assert!(report.yielded_before_quantum);
    assert!(!report.yielded_after_quantum);
    assert_eq!(target.started, vec![20]);
    assert_eq!(target.finished, 0);
    assert_eq!(target.shutdowns, 1);
}

#[test]
fn async_driver_rejects_zero_timeout_policy() {
    let policy = QemuAsyncDriverPolicy::new(
        Duration::ZERO,
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::from_millis(1),
    );
    let mut target = ScriptedTarget::completed();
    let mut runtime = ScriptedRuntime::new([QemuAsyncWaitOutcome::Completed]);
    let crash_detector = QemuCrashDetector::new("vm-a");

    assert_eq!(
        run_bounded_qemu_node_step(
            &mut target,
            &mut runtime,
            policy,
            &crash_detector,
            horizon(1),
        ),
        Err(QemuAsyncDriverError::UnboundedAwait {
            wait: QemuAsyncWait::Handshake,
        })
    );
    assert!(target.started.is_empty());
    assert_eq!(runtime.yields, 0);
}

#[test]
fn async_driver_rejects_qmp_or_plugin_ipc_in_quantum_hot_path() {
    let policy = QemuAsyncDriverPolicy::fast_test();
    let mut target = ScriptedTarget {
        completion: QemuAsyncQuantumCompletion {
            outcome: AdvanceOutcome::ReachedHorizon,
            final_state: QemuNodeIdleState {
                current_icount: Icount { retired: 0 },
                next_deadline: None,
            },
            inbound_frames_consumed: 0,
            emitted_frames: Vec::new(),
            operations: vec![QemuQuantumOperation::QmpCommand {
                command: "query-status",
            }],
        },
        ..ScriptedTarget::completed()
    };
    let mut runtime = ScriptedRuntime::new([QemuAsyncWaitOutcome::Completed]);
    let crash_detector = QemuCrashDetector::new("vm-a");

    assert_eq!(
        run_bounded_qemu_node_step(
            &mut target,
            &mut runtime,
            policy,
            &crash_detector,
            horizon(1),
        ),
        Err(QemuAsyncDriverError::ForbiddenHotPathOperation {
            plane: QemuQuantumOperationPlane::QmpMachineControl,
        })
    );

    target.completion.operations = vec![QemuQuantumOperation::PluginIpcControlFrame {
        operation: "advance",
    }];
    runtime = ScriptedRuntime::new([QemuAsyncWaitOutcome::Completed]);
    assert_eq!(
        run_bounded_qemu_node_step(
            &mut target,
            &mut runtime,
            policy,
            &crash_detector,
            horizon(1),
        ),
        Err(QemuAsyncDriverError::ForbiddenHotPathOperation {
            plane: QemuQuantumOperationPlane::PluginIpcControl,
        })
    );
}

#[test]
fn async_driver_lifecycle_awaits_use_policy_timeouts() {
    let policy = QemuAsyncDriverPolicy::fast_test();
    let mut target = ScriptedTarget::completed();
    let mut runtime = ScriptedRuntime::new([QemuAsyncWaitOutcome::Completed]);
    let crash_detector = QemuCrashDetector::new("vm-a");

    assert_eq!(
        await_bounded_lifecycle_event(
            &mut target,
            &mut runtime,
            policy,
            &crash_detector,
            QemuAsyncWait::Handshake,
        ),
        Ok(QemuAsyncLifecycleAwaitReport {
            wait: QemuAsyncWait::Handshake,
            outcome: QemuAsyncLifecycleAwaitOutcome::Completed,
            async_operations: vec![QemuAsyncDriverOperation::AwaitChild {
                wait: QemuAsyncWait::Handshake,
                timeout: Duration::from_millis(1),
                outcome: QemuAsyncWaitOutcome::Completed,
            }],
        })
    );
    assert_eq!(target.shutdowns, 0);
    assert_eq!(
        await_bounded_lifecycle_event(
            &mut target,
            &mut runtime,
            policy,
            &crash_detector,
            QemuAsyncWait::AdvanceCompletion,
        ),
        Err(QemuAsyncDriverError::LifecycleAdvanceWait)
    );
}

#[test]
fn async_driver_lifecycle_timeouts_crash_and_shutdown_for_each_wait_class() {
    for (wait, timeout) in [
        (QemuAsyncWait::Handshake, Duration::from_millis(1)),
        (QemuAsyncWait::QmpCommand, Duration::from_millis(2)),
        (QemuAsyncWait::ProcessEvent, Duration::from_millis(3)),
    ] {
        let policy = QemuAsyncDriverPolicy::fast_test();
        let mut target = ScriptedTarget::completed();
        let mut runtime = ScriptedRuntime::new([QemuAsyncWaitOutcome::TimedOut]);
        let crash_detector = QemuCrashDetector::new("vm-a");

        let report = match await_bounded_lifecycle_event(
            &mut target,
            &mut runtime,
            policy,
            &crash_detector,
            wait,
        ) {
            Ok(report) => report,
            Err(error) => panic!("lifecycle timeout should return crash report: {error}"),
        };

        match report.outcome {
            QemuAsyncLifecycleAwaitOutcome::Crashed { status, shutdown } => {
                assert!(status.is_infrastructure_crash());
                match status {
                    QemuNodeRunStatus::Crashed(crash) => {
                        assert_eq!(crash.node_id, "vm-a");
                        assert_eq!(
                            crash.cause,
                            QemuCrashCause::BoundedAwaitTimeout(
                                crate::QemuBoundedAwaitTimeout::new(wait.operation(), timeout),
                            )
                        );
                    }
                    _ => panic!("timeout should produce crashed-node status"),
                }
                assert!(shutdown.reaped);
            }
            QemuAsyncLifecycleAwaitOutcome::Completed => {
                panic!("lifecycle timeout should not complete")
            }
        }
        assert_eq!(
            report.async_operations,
            vec![
                QemuAsyncDriverOperation::AwaitChild {
                    wait,
                    timeout,
                    outcome: QemuAsyncWaitOutcome::TimedOut,
                },
                QemuAsyncDriverOperation::ShutdownAfterCrash,
            ]
        );
        assert_eq!(target.shutdowns, 1);
    }
}

#[derive(Debug)]
struct ScriptedRuntime {
    outcomes: VecDeque<QemuAsyncWaitOutcome>,
    yields: usize,
    awaits: usize,
    repolls: usize,
}

impl ScriptedRuntime {
    fn new(outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
            yields: 0,
            awaits: 0,
            repolls: 0,
        }
    }
}

impl QemuHostIoRuntime for ScriptedRuntime {
    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.yields += 1;
        Ok(())
    }

    fn await_child(
        &mut self,
        _wait: QemuAsyncWait,
        _timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        self.awaits += 1;
        self.outcomes
            .pop_front()
            .ok_or_else(|| QemuAsyncDriverRuntimeError::new("await child", "no outcome"))
    }

    fn repoll_child(
        &mut self,
        _wait: QemuAsyncWait,
        _timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        self.repolls += 1;
        self.outcomes
            .pop_front()
            .ok_or_else(|| QemuAsyncDriverRuntimeError::new("repoll child", "no outcome"))
    }
}

#[derive(Debug)]
struct ScriptedTarget {
    completion: QemuAsyncQuantumCompletion,
    pending_finishes: usize,
    started: Vec<u64>,
    finished: usize,
    shutdowns: usize,
}

impl ScriptedTarget {
    fn completed() -> Self {
        Self {
            completion: QemuAsyncQuantumCompletion {
                outcome: AdvanceOutcome::ReachedHorizon,
                final_state: QemuNodeIdleState {
                    current_icount: Icount { retired: 0 },
                    next_deadline: None,
                },
                inbound_frames_consumed: 0,
                emitted_frames: Vec::new(),
                operations: vec![
                    QemuQuantumOperation::StoreSchedulerCeiling,
                    QemuQuantumOperation::FutexWake,
                    QemuQuantumOperation::ObservePluginReport,
                ],
            },
            pending_finishes: 0,
            started: Vec::new(),
            finished: 0,
            shutdowns: 0,
        }
    }

    fn pending_once() -> Self {
        Self {
            pending_finishes: 1,
            ..Self::completed()
        }
    }
}

impl QemuAsyncCrashEscalationTarget for ScriptedTarget {
    fn shutdown_after_crash(&mut self) -> Result<QemuShutdownReport, QemuAsyncDriverTargetError> {
        self.shutdowns += 1;
        Ok(QemuShutdownReport {
            attempts: vec![QemuShutdownAttempt {
                rung: QemuShutdownRung::Sigkill,
                wait: Duration::from_millis(1),
                child: crate::QemuChildWait::Exited,
            }],
            failures: Vec::new(),
            reaped: true,
            leaked: false,
        })
    }
}

impl QemuAsyncNodeStepTarget for ScriptedTarget {
    type PendingQuantum = u64;

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<Self::PendingQuantum, QemuNodeChannelError> {
        self.started.push(horizon.icount.retired);
        Ok(horizon.icount.retired)
    }

    fn finish_quantum(
        &mut self,
        _pending: &mut Self::PendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        self.finished += 1;
        if self.pending_finishes > 0 {
            self.pending_finishes -= 1;
            return Err(QemuNodeChannelError::retryable(
                "finish quantum",
                "plugin report is still in flight",
            ));
        }
        Ok(self.completion.clone())
    }
}

fn horizon(retired: u64) -> ExecutionHorizon {
    ExecutionHorizon {
        icount: Icount { retired },
    }
}
