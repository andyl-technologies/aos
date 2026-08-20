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
    policy.validate()?;

    let mut async_operations = Vec::new();
    runtime
        .yield_to_control_plane()
        .map_err(QemuAsyncDriverError::Runtime)?;
    async_operations.push(QemuAsyncDriverOperation::YieldToControlPlane);

    let mut pending = target
        .start_quantum(horizon)
        .map_err(QemuAsyncDriverError::Channel)?;
    let wait_timeout = policy.timeout_for(QemuAsyncWait::AdvanceCompletion);
    let mut first_wait = true;
    let completion = loop {
        // Starting a quantum can discover that its boundary was already
        // published (for example, an idle node whose current icount equals the
        // new ceiling). Poll before blocking so that state cannot deadlock with
        // the child waiting for a strictly later authorization.
        match target.finish_quantum(&mut pending) {
            Ok(completion) => break Some(completion),
            Err(error) if error.is_retryable() => {}
            Err(error) => return Err(QemuAsyncDriverError::Channel(error)),
        }

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
    };
    let Some(completion) = completion else {
        async_operations.push(QemuAsyncDriverOperation::ShutdownAfterCrash);
        let status = crash_detector
            .bounded_await_timeout(QemuAsyncWait::AdvanceCompletion.operation(), wait_timeout);
        let shutdown = target
            .shutdown_after_crash()
            .map_err(QemuAsyncDriverError::Target)?;
        return Ok(QemuAsyncNodeStepReport {
            outcome: QemuAsyncNodeStepOutcome::Crashed { status, shutdown },
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
        outcome: QemuAsyncNodeStepOutcome::Completed {
            advance: completion.outcome,
        },
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
