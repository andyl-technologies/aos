//! Tests for the asynchronous QEMU driver.

use super::*;

use std::collections::VecDeque;
use std::os::unix::process::ExitStatusExt;

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
    assert_eq!(runtime.armed_fences, vec![None]);
}

#[test]
fn async_driver_arms_the_pending_scheduler_input_fence_before_waiting() {
    let policy = QemuAsyncDriverPolicy::fast_test();
    let mut target = ScriptedTarget::completed();
    target.completion_fence = Some(QemuAdvanceCompletionFence {
        initial_publish_generation: 17,
        stop_condition: crate::QemuQuantumStopCondition::Ceiling,
    });
    let mut runtime = ScriptedRuntime::new([QemuAsyncWaitOutcome::Completed]);
    let crash_detector = QemuCrashDetector::new("vm-a");

    run_bounded_qemu_node_step(
        &mut target,
        &mut runtime,
        policy,
        &crash_detector,
        horizon(12),
    )
    .unwrap_or_else(|error| panic!("fenced node-step should complete: {error}"));

    assert_eq!(runtime.armed_fences, vec![target.completion_fence]);
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
fn campaign_advance_can_outlive_multiple_host_poll_slices() {
    let policy = QemuAsyncDriverPolicy::fast_test().with_unbounded_advance_completion();
    let mut target = ScriptedTarget::completed();
    target.completion_fence = Some(QemuAdvanceCompletionFence {
        initial_publish_generation: 17,
        stop_condition: crate::QemuQuantumStopCondition::Ceiling,
    });
    let mut runtime = ScriptedRuntime::new([
        QemuAsyncWaitOutcome::TimedOut,
        QemuAsyncWaitOutcome::TimedOut,
        QemuAsyncWaitOutcome::Completed,
    ]);
    let crash_detector = QemuCrashDetector::new("vm-a");

    let report = match run_bounded_qemu_node_step(
        &mut target,
        &mut runtime,
        policy,
        &crash_detector,
        horizon(20),
    ) {
        Ok(report) => report,
        Err(error) => panic!("a host polling slice is not a campaign stop outcome: {error}"),
    };

    assert!(matches!(
        report.outcome,
        QemuAsyncNodeStepOutcome::Completed { .. }
    ));
    assert_eq!(target.started, vec![20]);
    assert_eq!(target.shutdowns, 0);
    assert_eq!(runtime.awaits, 1);
    assert_eq!(runtime.repolls, 2);
    assert_eq!(runtime.renewals, 2);
    assert_eq!(runtime.poll_slices, vec![None]);
    assert_eq!(runtime.armed_fences, vec![target.completion_fence]);
    assert_eq!(policy.handshake_timeout, Duration::from_millis(1));
    assert_eq!(policy.qmp_command_timeout, Duration::from_millis(2));
    assert_eq!(policy.process_event_timeout, Duration::from_millis(3));
}

#[test]
fn campaign_advance_detects_child_exit_within_one_host_poll_slice() {
    let policy = QemuAsyncDriverPolicy::new(
        Duration::from_secs(300),
        Duration::from_secs(300),
        Duration::from_secs(300),
        Duration::from_secs(300),
    )
    .with_unbounded_advance_completion();
    let mut target = ScriptedTarget {
        child_exit_status: Some(std::process::ExitStatus::from_raw(1 << 8)),
        ..ScriptedTarget::completed()
    };
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
        Err(error) => panic!("an exited child is reported as an infrastructure crash: {error}"),
    };

    assert!(matches!(
        report.outcome,
        QemuAsyncNodeStepOutcome::Crashed { .. }
    ));
    assert!(report.async_operations.iter().any(|operation| matches!(
        operation,
        QemuAsyncDriverOperation::AwaitChild {
            wait: QemuAsyncWait::AdvanceCompletion,
            timeout,
            outcome: QemuAsyncWaitOutcome::TimedOut,
        } if *timeout == Duration::from_secs(1)
    )));
    assert_eq!(runtime.renewals, 0);
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
            completed_boundary: None,
            ceiling: Icount { retired: 0 },
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

#[test]
fn bounded_pending_poll_does_not_finish_or_renew_the_quantum() {
    let mut target = ScriptedTarget::completed();
    let mut runtime = ScriptedRuntime::new([
        QemuAsyncWaitOutcome::Pending,
        QemuAsyncWaitOutcome::Pending,
        QemuAsyncWaitOutcome::Completed,
    ]);
    let policy = QemuAsyncDriverPolicy::fast_test();
    let report = run_bounded_qemu_node_step(
        &mut target,
        &mut runtime,
        policy,
        &QemuCrashDetector::new("vm-a"),
        horizon(20),
    )
    .unwrap_or_else(|error| panic!("pending host polls must retain the original quantum: {error}"));

    assert!(matches!(
        report.outcome,
        QemuAsyncNodeStepOutcome::Completed { .. }
    ));
    assert_eq!(target.started, vec![20]);
    assert_eq!(target.finished, 1);
    assert_eq!(runtime.awaits, 1);
    assert_eq!(runtime.repolls, 2);
    assert_eq!(runtime.renewals, 0);
    assert_eq!(runtime.poll_slices, vec![Some(Duration::from_secs(1))]);
}

#[test]
fn lifecycle_wait_refuses_a_pending_advance_poll_outcome() {
    let mut target = ScriptedTarget::completed();
    let mut runtime = ScriptedRuntime::new([QemuAsyncWaitOutcome::Pending]);
    let error = match await_bounded_lifecycle_event(
        &mut target,
        &mut runtime,
        QemuAsyncDriverPolicy::fast_test(),
        &QemuCrashDetector::new("vm-a"),
        QemuAsyncWait::Handshake,
    ) {
        Err(error) => error,
        Ok(_) => panic!("a host poll yield cannot complete a lifecycle operation"),
    };

    assert!(matches!(error, QemuAsyncDriverError::Runtime(_)));
    assert_eq!(target.shutdowns, 0);
    assert_eq!(target.finished, 0);
}

#[cfg(target_os = "linux")]
mod owned_child {
    use super::*;
    use crucible_shmem::MappedSetupRegion;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::process::{Command, Stdio};

    struct OwnedTarget {
        child: crate::QemuNodeChild,
        region: MappedSetupRegion,
        started: usize,
        finished: usize,
        exit_checks: usize,
    }

    impl QemuAsyncCrashEscalationTarget for OwnedTarget {
        fn shutdown_after_crash(
            &mut self,
        ) -> Result<QemuShutdownReport, QemuAsyncDriverTargetError> {
            self.child
                .force_kill_and_reap_failed_helper(Duration::from_secs(1))
                .map_err(|error| {
                    QemuAsyncDriverTargetError::new("reap owned fixture", error.to_string())
                })?;
            Ok(QemuShutdownReport {
                attempts: Vec::new(),
                failures: Vec::new(),
                reaped: self.child.reaped(),
                leaked: !self.child.reaped(),
            })
        }
    }

    impl QemuAsyncNodeStepTarget for OwnedTarget {
        type PendingQuantum = ();

        fn child_exit_status(
            &mut self,
        ) -> Result<Option<std::process::ExitStatus>, QemuAsyncDriverTargetError> {
            self.exit_checks += 1;
            self.child.try_wait_natural_exit().map_err(|error| {
                QemuAsyncDriverTargetError::new("poll owned fixture", error.to_string())
            })
        }

        fn start_quantum(&mut self, horizon: ExecutionHorizon) -> Result<(), QemuNodeChannelError> {
            self.started += 1;
            let ceiling =
                crucible_shmem::authorize_advance_ceiling(0, horizon.icount.retired, None)
                    .map_err(|error| {
                        QemuNodeChannelError::new("authorize fixture advance", error.to_string())
                    })?;
            self.region
                .node_slot(0)
                .map_err(|error| QemuNodeChannelError::new("fixture slot", error.to_string()))?
                .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
                .map(|_wake| ())
                .map_err(|error| QemuNodeChannelError::new("fixture advance", error.to_string()))
        }

        fn finish_quantum(
            &mut self,
            _pending: &mut (),
        ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
            self.finished += 1;
            Err(QemuNodeChannelError::new(
                "finish fixture",
                "pending mapped slot has no completion",
            ))
        }
    }

    // The AOS-built Bash child uses only builtins and has no subprocess that
    // could inherit a pipe or survive cleanup. A ready byte authenticates that
    // the uniquely owned process is running before its release or watchdog.
    fn fixture() -> Result<
        (
            OwnedTarget,
            crate::QemuLiveHostIoRuntime,
            std::process::ChildStdin,
        ),
        Box<dyn std::error::Error>,
    > {
        let mut child = Command::new("bash")
            .args(["-c", "printf R; IFS= read -r release; exit 1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take().ok_or("fixture stdin missing")?;
        let mut output = child.stdout.take().ok_or("fixture stdout missing")?;
        let child = crate::QemuNodeChild::new(child);
        let mut ready = [0_u8];
        output.read_exact(&mut ready)?;
        if ready != *b"R" {
            return Err("fixture ready byte differs".into());
        }

        let allocation =
            crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
        let layout = allocation.layout();
        let mut shmem = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
        shmem.write_all(&allocation.setup_region_bytes()?)?;
        let region = crucible_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        region.node_slot(0)?.publish_reached_icount(0)?;
        let wake = tempfile::tempfile()?;
        let runtime = crate::QemuLiveHostIoRuntime::from_shmem_fd(
            shmem.as_fd(),
            wake.as_fd(),
            layout.region_size,
            0,
        )?;
        Ok((
            OwnedTarget {
                child,
                region,
                started: 0,
                finished: 0,
                exit_checks: 0,
            },
            runtime,
            input,
        ))
    }

    // crucible-lint: allow clippy-disallowed-method -- elapsed host time only checks owned-process liveness; it does not enter virtual state.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn early_owned_child_exit_is_observed_during_bounded_advance()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut target, mut runtime, mut release) = fixture()?;
        release.write_all(b"exit\n")?;
        let budget = Duration::from_secs(5);
        let policy = QemuAsyncDriverPolicy::new(budget, budget, budget, budget);
        let started = std::time::Instant::now();
        let report = run_bounded_qemu_node_step(
            &mut target,
            &mut runtime,
            policy,
            &QemuCrashDetector::new("owned"),
            horizon(100),
        )?;

        assert!(started.elapsed() < budget);
        let QemuAsyncNodeStepOutcome::Crashed {
            status: QemuNodeRunStatus::Crashed(status),
            shutdown,
        } = report.outcome
        else {
            panic!("owned exit must be a genuine crash");
        };
        let QemuCrashCause::UnexpectedChildExit(exit) = status.cause else {
            panic!("owned exit must not be a watchdog timeout");
        };
        assert_eq!(exit.code, Some(1));
        assert_eq!(exit.signal, None);
        assert!(!exit.success);
        assert!(shutdown.reaped && !shutdown.leaked);
        assert!(target.child.reaped());
        assert_eq!(target.started, 1);
        assert_eq!(target.finished, 0);
        assert!(report.completed_boundary.is_none());
        assert!(report.final_state.is_none());
        Ok(())
    }

    // crucible-lint: allow clippy-disallowed-method -- elapsed host time checks the original watchdog only, never virtual time or replay evidence.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn live_owned_child_pending_advance_keeps_original_watchdog()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut target, mut runtime, _hold_open) = fixture()?;
        let budget = Duration::from_millis(2250);
        let policy = QemuAsyncDriverPolicy::new(budget, budget, budget, budget);
        let started = std::time::Instant::now();
        let report = run_bounded_qemu_node_step(
            &mut target,
            &mut runtime,
            policy,
            &QemuCrashDetector::new("owned"),
            horizon(100),
        )?;

        assert!(started.elapsed() >= budget);
        let QemuAsyncNodeStepOutcome::Crashed {
            status: QemuNodeRunStatus::Crashed(status),
            shutdown,
        } = report.outcome
        else {
            panic!("live pending child must expire its original watchdog");
        };
        assert_eq!(
            status.cause,
            QemuCrashCause::BoundedAwaitTimeout(crate::QemuBoundedAwaitTimeout::new(
                "advance completion",
                budget
            ))
        );
        assert!(target.exit_checks >= 3);
        assert_eq!(target.finished, 0);
        assert!(shutdown.reaped && !shutdown.leaked);
        assert!(target.child.reaped());
        assert!(report.completed_boundary.is_none());
        let pending_poll_count = report
            .async_operations
            .iter()
            .filter(|operation| {
                matches!(
                    operation,
                    QemuAsyncDriverOperation::AwaitChild {
                        outcome: QemuAsyncWaitOutcome::Pending,
                        timeout,
                        ..
                    } if *timeout == budget
                )
            })
            .count();
        assert!(pending_poll_count >= 2);
        Ok(())
    }
}

#[derive(Debug)]
struct ScriptedRuntime {
    outcomes: VecDeque<QemuAsyncWaitOutcome>,
    yields: usize,
    awaits: usize,
    repolls: usize,
    renewals: usize,
    armed_fences: Vec<Option<QemuAdvanceCompletionFence>>,
    poll_slices: Vec<Option<Duration>>,
}

impl ScriptedRuntime {
    fn new(outcomes: impl IntoIterator<Item = QemuAsyncWaitOutcome>) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
            yields: 0,
            awaits: 0,
            repolls: 0,
            renewals: 0,
            armed_fences: Vec::new(),
            poll_slices: Vec::new(),
        }
    }
}

impl QemuHostIoRuntime for ScriptedRuntime {
    fn set_advance_completion_poll_slice(
        &mut self,
        slice: Option<Duration>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.poll_slices.push(slice);
        Ok(())
    }

    fn renew_advance_completion_poll(
        &mut self,
        _timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.renewals += 1;
        Ok(())
    }

    fn publish_current_execution_fingerprint(
        &mut self,
        _timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    fn arm_advance_completion_fence(
        &mut self,
        fence: Option<QemuAdvanceCompletionFence>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.armed_fences.push(fence);
        Ok(())
    }

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
    completion_fence: Option<QemuAdvanceCompletionFence>,
    child_exit_status: Option<std::process::ExitStatus>,
}

impl ScriptedTarget {
    fn completed() -> Self {
        Self {
            completion: QemuAsyncQuantumCompletion {
                completed_boundary: None,
                ceiling: Icount { retired: 0 },
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
            completion_fence: None,
            child_exit_status: None,
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

    fn child_exit_status(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, QemuAsyncDriverTargetError> {
        Ok(self.child_exit_status)
    }

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<Self::PendingQuantum, QemuNodeChannelError> {
        self.started.push(horizon.icount.retired);
        Ok(horizon.icount.retired)
    }

    fn advance_completion_fence(
        &self,
        _pending: &Self::PendingQuantum,
    ) -> Option<QemuAdvanceCompletionFence> {
        self.completion_fence
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
