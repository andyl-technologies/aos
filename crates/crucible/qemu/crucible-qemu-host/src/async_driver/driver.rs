//! Bounded per-quantum and lifecycle wait drivers.

use super::*;
use crucible_host_resources::host_supervision::{HostOperationClass, HostSupervisionError};

fn supervision_error(source: HostSupervisionError) -> QemuAsyncDriverError {
    QemuAsyncDriverError::Runtime(QemuAsyncDriverRuntimeError::operational_supervision(
        "host operation supervision",
        source,
    ))
}

/// Runs one scheduler quantum through a bounded host-I/O bridge.
///
/// # Errors
///
/// Returns [`QemuAsyncDriverError`] when timeout policy validation fails, the
/// runtime cannot yield or await, the shared-memory hot path fails, shutdown
/// escalation cannot run after a timeout, or forbidden QMP/plugin-IPC operations
/// appear in the quantum hot path.
pub fn run_bounded_qemu_node_step<T, R>(
    target: &mut T,
    runtime: &mut R,
    policy: QemuAsyncDriverPolicy,
    crash_detector: &QemuCrashDetector,
    horizon: ExecutionHorizon,
) -> Result<QemuAsyncNodeStepReport, QemuAsyncDriverError>
where
    T: QemuAsyncNodeStepTarget,
    R: QemuHostIoRuntime + ?Sized,
{
    run_bounded_qemu_node_step_with_start_hook(
        target,
        runtime,
        policy,
        crash_detector,
        horizon,
        |_target, _pending| Ok(()),
    )
}

/// Runs one scheduler quantum and invokes a gate hook after publication.
///
/// The hook exists for bounded scheduler-preemption gates: they must not
/// release their signal controller until `start_quantum` has published a real
/// QEMU horizon. Production callers use [`run_bounded_qemu_node_step`].
///
/// # Errors
///
/// Returns [`QemuAsyncDriverError`] under the same conditions as
/// [`run_bounded_qemu_node_step`], including a typed channel error when the
/// post-publication hook rejects the pending quantum.
pub(crate) fn run_bounded_qemu_node_step_with_start_hook<T, R, F>(
    target: &mut T,
    runtime: &mut R,
    policy: QemuAsyncDriverPolicy,
    crash_detector: &QemuCrashDetector,
    horizon: ExecutionHorizon,
    after_start: F,
) -> Result<QemuAsyncNodeStepReport, QemuAsyncDriverError>
where
    T: QemuAsyncNodeStepTarget,
    R: QemuHostIoRuntime + ?Sized,
    F: FnOnce(&mut T, &mut T::PendingQuantum) -> Result<(), QemuNodeChannelError>,
{
    run_node_step_with_operation(
        target,
        runtime,
        policy,
        crash_detector,
        horizon,
        after_start,
        None,
    )
}

/// Borrows the original operation through publication, resume and every wait.
#[cfg(any(test, feature = "test-support", feature = "private-measurement-domain"))]
pub(crate) fn run_qemu_node_step_under_original<T, R, F>(
    target: &mut T,
    runtime: &mut R,
    policy: QemuAsyncDriverPolicy,
    crash_detector: &QemuCrashDetector,
    horizon: ExecutionHorizon,
    after_start: F,
    original: &crucible_host_resources::host_supervision::HostOperationGuard,
) -> Result<QemuAsyncNodeStepReport, QemuAsyncDriverError>
where
    T: QemuAsyncNodeStepTarget,
    R: QemuHostIoRuntime + ?Sized,
    F: FnOnce(&mut T, &mut T::PendingQuantum) -> Result<(), QemuNodeChannelError>,
{
    run_node_step_with_operation(
        target,
        runtime,
        policy,
        crash_detector,
        horizon,
        after_start,
        Some(original),
    )
}

fn check_original(
    original: Option<&crucible_host_resources::host_supervision::HostOperationGuard>,
) -> Result<(), QemuAsyncDriverError> {
    if let Some(original) = original {
        original.wait_slice().map_err(supervision_error)?;
    }
    Ok(())
}

/// Observes the same entered operation after every actual runtime return,
/// including an adapter refusal. The initiating error owns its typed post
/// observation inline; neither formatting nor a replacement operation is needed.
fn observe_runtime_return<T>(
    result: Result<T, QemuAsyncDriverRuntimeError>,
    original: Option<&crucible_host_resources::host_supervision::HostOperationGuard>,
) -> Result<T, QemuAsyncDriverError> {
    let post = original.and_then(|operation| operation.wait_slice().err());

    match (result, post) {
        (Ok(value), None) => Ok(value),
        (Ok(_), Some(source)) => Err(supervision_error(source)),
        (Err(first), None) => Err(QemuAsyncDriverError::Runtime(first)),
        (Err(first), Some(source)) => Err(QemuAsyncDriverError::Runtime(
            first.with_operational_supervision_post(source),
        )),
    }
}

fn run_node_step_with_operation<T, R, F>(
    target: &mut T,
    runtime: &mut R,
    policy: QemuAsyncDriverPolicy,
    crash_detector: &QemuCrashDetector,
    horizon: ExecutionHorizon,
    after_start: F,
    original: Option<&crucible_host_resources::host_supervision::HostOperationGuard>,
) -> Result<QemuAsyncNodeStepReport, QemuAsyncDriverError>
where
    T: QemuAsyncNodeStepTarget,
    R: QemuHostIoRuntime + ?Sized,
    F: FnOnce(&mut T, &mut T::PendingQuantum) -> Result<(), QemuNodeChannelError>,
{
    policy.validate()?;

    check_original(original)?;
    let host_operation = if original.is_some() {
        None
    } else {
        runtime
            .host_operation_supervisor()
            .map(|supervisor| supervisor.begin(HostOperationClass::Quantum))
            .transpose()
            .map_err(supervision_error)?
    };

    // Publication and every later cut borrow this same entered operation.
    // A driver-issued Quantum needs the same cancellation checks as a loan.
    let active_operation = original.or(host_operation.as_ref());

    target
        .operational_health()
        .map_err(QemuAsyncDriverError::OperationalHealth)?;

    let mut async_operations = Vec::new();
    observe_runtime_return(runtime.yield_to_control_plane(), active_operation)?;
    async_operations.push(QemuAsyncDriverOperation::YieldToControlPlane);

    check_original(active_operation)?;
    let mut pending = target
        .start_quantum(horizon)
        .map_err(QemuAsyncDriverError::Channel)?;
    check_original(active_operation)?;
    after_start(target, &mut pending).map_err(QemuAsyncDriverError::Channel)?;
    check_original(active_operation)?;
    observe_runtime_return(
        runtime.arm_advance_completion_fence(target.advance_completion_fence(&pending)),
        active_operation,
    )?;
    // Renewal is a liveness poll, not an attempt deadline. A short slice
    // observes child exit and an authored watchdog cancellation promptly.
    let initial_wait_timeout = if policy.unbounded_advance_completion {
        policy
            .timeout_for(QemuAsyncWait::AdvanceCompletion)
            .min(Duration::from_secs(1))
    } else {
        policy.timeout_for(QemuAsyncWait::AdvanceCompletion)
    };
    let mut first_wait = true;
    let completion = loop {
        let wait_timeout = match active_operation {
            Some(operation) => match operation.wait_slice() {
                Ok(slice) => slice,
                Err(source) => {
                    if original.is_none() {
                        target
                            .shutdown_after_crash()
                            .map_err(QemuAsyncDriverError::Target)?;
                    }
                    return Err(supervision_error(source));
                }
            },
            None => initial_wait_timeout,
        };
        let is_initial_wait = first_wait;
        if is_initial_wait {
            first_wait = false;
        }
        let wait_result = if let Some(original) = original {
            if is_initial_wait {
                runtime.await_child_under_original(QemuAsyncWait::AdvanceCompletion, original)
            } else {
                runtime.repoll_child_under_original(QemuAsyncWait::AdvanceCompletion, original)
            }
        } else if is_initial_wait {
            runtime.await_child(QemuAsyncWait::AdvanceCompletion, wait_timeout)
        } else {
            runtime.repoll_child(QemuAsyncWait::AdvanceCompletion, wait_timeout)
        };
        // Observe the same Original even after refusal. A borrowed Original's
        // adapter cause precedes later health observations. For ordinary
        // Quantum waits, retain the existing Source-health priority over a
        // transport failure caused by that Source closing its socket.
        let wait_result = observe_runtime_return(wait_result, active_operation);
        let wait_result = if original.is_some() {
            Ok(wait_result?)
        } else {
            wait_result
        };
        // Source failure closes only operational continuation. The actual
        // process and pending buffers remain owned for explicit containment;
        // this path never turns a blocked memory access into a guest crash.
        target
            .operational_health()
            .map_err(QemuAsyncDriverError::OperationalHealth)?;
        let wait_outcome = wait_result?;
        check_original(active_operation)?;
        let observed_wait = QemuAsyncDriverOperation::AwaitChild {
            wait: QemuAsyncWait::AdvanceCompletion,
            timeout: wait_timeout,
            outcome: wait_outcome,
        };
        // Poll traffic is operational evidence, not an unbounded history buffer.
        if async_operations.len() < 64 {
            async_operations.push(observed_wait);
        } else if let Some(last) = async_operations.last_mut() {
            *last = observed_wait;
        }
        if wait_outcome == QemuAsyncWaitOutcome::TimedOut {
            if original.is_none()
                && host_operation.is_none()
                && !policy.unbounded_advance_completion
            {
                break None;
            }
            if let Some(exit_status) = target
                .child_exit_status()
                .map_err(QemuAsyncDriverError::Target)?
            {
                if original.is_some() {
                    return Err(QemuAsyncDriverError::Target(
                        QemuAsyncDriverTargetError::new(
                            "original reset quantum child exit",
                            format!("owned child exited: {exit_status}"),
                        ),
                    ));
                }
                async_operations.push(QemuAsyncDriverOperation::ShutdownAfterCrash);
                let status = crash_detector.unexpected_child_exit(exit_status);
                let shutdown = target
                    .shutdown_after_crash()
                    .map_err(QemuAsyncDriverError::Target)?;
                return Ok(QemuAsyncNodeStepReport {
                    ceiling: None,
                    outcome: QemuAsyncNodeStepOutcome::Crashed { status, shutdown },
                    final_state: None,
                    inbound_frames_consumed: 0,
                    emitted_frames: Vec::new(),
                    yielded_before_quantum: true,
                    yielded_after_quantum: false,
                    hot_path_operations: Vec::new(),
                    async_operations,
                });
            }
            if original.is_none() {
                observe_runtime_return(
                    runtime.renew_advance_completion_poll(wait_timeout),
                    active_operation,
                )?;
            }
            continue;
        }
        check_original(active_operation)?;
        match target.finish_quantum(&mut pending) {
            Ok(completion) => {
                target
                    .operational_health()
                    .map_err(QemuAsyncDriverError::OperationalHealth)?;
                check_original(active_operation)?;
                break Some(completion);
            }
            Err(error) => {
                target
                    .operational_health()
                    .map_err(QemuAsyncDriverError::OperationalHealth)?;
                if error.is_retryable() {
                    continue;
                }
                return Err(QemuAsyncDriverError::Channel(error));
            }
        }
    };
    let Some(completion) = completion else {
        async_operations.push(QemuAsyncDriverOperation::ShutdownAfterCrash);
        let status = crash_detector.bounded_await_timeout(
            QemuAsyncWait::AdvanceCompletion.operation(),
            initial_wait_timeout,
        );
        let shutdown = target
            .shutdown_after_crash()
            .map_err(QemuAsyncDriverError::Target)?;
        return Ok(QemuAsyncNodeStepReport {
            ceiling: None,
            outcome: QemuAsyncNodeStepOutcome::Crashed { status, shutdown },
            final_state: None,
            inbound_frames_consumed: 0,
            emitted_frames: Vec::new(),
            yielded_before_quantum: true,
            yielded_after_quantum: false,
            hot_path_operations: Vec::new(),
            async_operations,
        });
    };
    check_original(active_operation)?;
    assert_async_driver_quantum_hot_path_is_shmem_only(&completion.operations)?;

    observe_runtime_return(runtime.yield_to_control_plane(), active_operation)?;
    async_operations.push(QemuAsyncDriverOperation::YieldToControlPlane);

    check_original(active_operation)?;
    if let Some(operation) = host_operation {
        operation.complete().map_err(supervision_error)?;
    }
    Ok(QemuAsyncNodeStepReport {
        ceiling: Some(completion.ceiling),
        outcome: QemuAsyncNodeStepOutcome::Completed {
            advance: completion.outcome,
        },
        final_state: Some(completion.final_state),
        inbound_frames_consumed: completion.inbound_frames_consumed,
        emitted_frames: completion.emitted_frames,
        yielded_before_quantum: true,
        yielded_after_quantum: true,
        hot_path_operations: completion.operations,
        async_operations,
    })
}

/// Awaits a lifecycle child event with the policy timeout for that wait class.
///
/// # Errors
///
/// Returns [`QemuAsyncDriverError`] when the policy is invalid, `wait` names the
/// per-quantum advance-completion wait, the runtime await fails, or shutdown
/// escalation fails after a timeout.
pub fn await_bounded_lifecycle_event<T, R>(
    target: &mut T,
    runtime: &mut R,
    policy: QemuAsyncDriverPolicy,
    crash_detector: &QemuCrashDetector,
    wait: QemuAsyncWait,
) -> Result<QemuAsyncLifecycleAwaitReport, QemuAsyncDriverError>
where
    T: QemuAsyncCrashEscalationTarget,
    R: QemuHostIoRuntime + ?Sized,
{
    policy.validate()?;
    if wait == QemuAsyncWait::AdvanceCompletion {
        return Err(QemuAsyncDriverError::LifecycleAdvanceWait);
    }
    let timeout = policy.timeout_for(wait);
    let class = match wait {
        QemuAsyncWait::Handshake => HostOperationClass::Setup,
        QemuAsyncWait::QmpCommand => HostOperationClass::Preparation,
        QemuAsyncWait::ProcessEvent => HostOperationClass::Cleanup,
        QemuAsyncWait::AdvanceCompletion => HostOperationClass::Quantum,
    };
    let operation = runtime
        .host_operation_supervisor()
        .map(|supervisor| supervisor.begin(class))
        .transpose()
        .map_err(supervision_error)?;
    let mut first = true;
    let outcome = loop {
        let slice = match &operation {
            Some(operation) => operation.wait_slice().map_err(supervision_error)?,
            None => timeout,
        };
        let result = if first {
            first = false;
            runtime.await_child(wait, slice)
        } else {
            runtime.repoll_child(wait, slice)
        };
        let outcome = observe_runtime_return(result, operation.as_ref())?;
        if outcome == QemuAsyncWaitOutcome::Completed || operation.is_none() {
            break outcome;
        }
    };
    if outcome == QemuAsyncWaitOutcome::Completed
        && let Some(operation) = operation
    {
        operation.complete().map_err(supervision_error)?;
    }
    let mut async_operations = vec![QemuAsyncDriverOperation::AwaitChild {
        wait,
        timeout,
        outcome,
    }];
    if outcome == QemuAsyncWaitOutcome::TimedOut {
        async_operations.push(QemuAsyncDriverOperation::ShutdownAfterCrash);
        let status = crash_detector.bounded_await_timeout(wait.operation(), timeout);
        let shutdown = target
            .shutdown_after_crash()
            .map_err(QemuAsyncDriverError::Target)?;
        return Ok(QemuAsyncLifecycleAwaitReport {
            wait,
            outcome: QemuAsyncLifecycleAwaitOutcome::Crashed { status, shutdown },
            async_operations,
        });
    }
    Ok(QemuAsyncLifecycleAwaitReport {
        wait,
        outcome: QemuAsyncLifecycleAwaitOutcome::Completed,
        async_operations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
    use crucible_host_resources::test_support::TestAllocationObserver;

    #[test]
    fn actual_original_runtime_post_retains_first_without_allocating()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Quantum)?;
        supervisor.cancel()?;
        let expected = original
            .wait_slice()
            .expect_err("actual Original is canceled");

        let (result, counts) = TestAllocationObserver::count(|| {
            observe_runtime_return::<()>(
                Err(QemuAsyncDriverRuntimeError::new(
                    "adapter",
                    "initiating refusal",
                )),
                Some(&original),
            )
        });

        let QemuAsyncDriverError::Runtime(error) = result.expect_err("adapter refuses") else {
            panic!("initiating adapter must remain the first typed error");
        };
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert_eq!(error.operation, "adapter");
        assert_eq!(error.message, "initiating refusal");
        assert_eq!(error.operational_supervision_post(), Some(expected));
        assert!(original.wait_slice().is_err());
        Ok(())
    }
}
