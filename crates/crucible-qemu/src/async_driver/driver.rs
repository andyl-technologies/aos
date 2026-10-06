//! Bounded per-quantum and lifecycle wait drivers.

use super::*;
use crucible_linux_resource::host_supervision::{HostOperationClass, HostSupervisionError};

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
    policy.validate()?;

    let host_operation = runtime
        .host_operation_supervisor()
        .map(|supervisor| supervisor.begin(HostOperationClass::Quantum))
        .transpose()
        .map_err(supervision_error)?;

    let mut async_operations = Vec::new();
    runtime
        .yield_to_control_plane()
        .map_err(QemuAsyncDriverError::Runtime)?;
    async_operations.push(QemuAsyncDriverOperation::YieldToControlPlane);

    let mut pending = target
        .start_quantum(horizon)
        .map_err(QemuAsyncDriverError::Channel)?;
    after_start(target, &mut pending).map_err(QemuAsyncDriverError::Channel)?;
    runtime
        .arm_advance_completion_fence(target.advance_completion_fence(&pending))
        .map_err(QemuAsyncDriverError::Runtime)?;
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
        let wait_timeout = match &host_operation {
            Some(operation) => match operation.wait_slice() {
                Ok(slice) => slice,
                Err(source) => {
                    target
                        .shutdown_after_crash()
                        .map_err(QemuAsyncDriverError::Target)?;
                    return Err(supervision_error(source));
                }
            },
            None => initial_wait_timeout,
        };
        let is_initial_wait = first_wait;
        if is_initial_wait {
            first_wait = false;
        }
        let wait_outcome = if is_initial_wait {
            runtime.await_child(QemuAsyncWait::AdvanceCompletion, wait_timeout)
        } else {
            runtime.repoll_child(QemuAsyncWait::AdvanceCompletion, wait_timeout)
        }
        .map_err(QemuAsyncDriverError::Runtime)?;
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
            if host_operation.is_none() && !policy.unbounded_advance_completion {
                break None;
            }
            if let Some(exit_status) = target
                .child_exit_status()
                .map_err(QemuAsyncDriverError::Target)?
            {
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
            runtime
                .renew_advance_completion_poll(wait_timeout)
                .map_err(QemuAsyncDriverError::Runtime)?;
            continue;
        }
        match target.finish_quantum(&mut pending) {
            Ok(completion) => {
                break Some(completion);
            }
            Err(error) if error.is_retryable() => continue,
            Err(error) => return Err(QemuAsyncDriverError::Channel(error)),
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
    if let Some(operation) = host_operation {
        operation.complete().map_err(supervision_error)?;
    }
    assert_async_driver_quantum_hot_path_is_shmem_only(&completion.operations)?;

    runtime
        .yield_to_control_plane()
        .map_err(QemuAsyncDriverError::Runtime)?;
    async_operations.push(QemuAsyncDriverOperation::YieldToControlPlane);

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
        let outcome = if first {
            first = false;
            runtime.await_child(wait, slice)
        } else {
            runtime.repoll_child(wait, slice)
        }
        .map_err(QemuAsyncDriverError::Runtime)?;
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
