//! Bounded per-quantum and lifecycle wait drivers.

use super::*;

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
        || Ok(()),
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
    F: FnOnce() -> Result<(), QemuNodeChannelError>,
{
    policy.validate()?;

    let mut async_operations = Vec::new();
    runtime
        .yield_to_control_plane()
        .map_err(QemuAsyncDriverError::Runtime)?;
    async_operations.push(QemuAsyncDriverOperation::YieldToControlPlane);

    let mut pending = target
        .start_quantum(horizon)
        .map_err(QemuAsyncDriverError::Channel)?;
    after_start().map_err(QemuAsyncDriverError::Channel)?;
    runtime
        .arm_advance_completion_fence(target.advance_completion_fence(&pending))
        .map_err(QemuAsyncDriverError::Runtime)?;
    let wait_timeout = policy.timeout_for(QemuAsyncWait::AdvanceCompletion);
    let mut first_wait = true;
    let completion = loop {
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
        async_operations.push(QemuAsyncDriverOperation::AwaitChild {
            wait: QemuAsyncWait::AdvanceCompletion,
            timeout: wait_timeout,
            outcome: wait_outcome,
        });
        if wait_outcome == QemuAsyncWaitOutcome::TimedOut {
            break None;
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
        let status = crash_detector
            .bounded_await_timeout(QemuAsyncWait::AdvanceCompletion.operation(), wait_timeout);
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
    let outcome = runtime
        .await_child(wait, timeout)
        .map_err(QemuAsyncDriverError::Runtime)?;
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
