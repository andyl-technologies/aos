//! Effect-free coherent-source acquisition under the original advance budget.

use super::*;

pub(super) enum Acquisition<P> {
    Published(P),
    Crashed(Box<QemuAsyncNodeStepReport>),
}

/// Retries only a typed publication-unavailable refusal before any RUN exists.
pub(super) fn acquire_quantum<T, R>(
    target: &mut T,
    runtime: &mut R,
    policy: QemuAsyncDriverPolicy,
    crash_detector: &QemuCrashDetector,
    horizon: ExecutionHorizon,
    timeout: Duration,
) -> Result<Acquisition<T::PendingQuantum>, QemuAsyncDriverError>
where
    T: QemuAsyncNodeStepTarget,
    R: QemuHostIoRuntime + ?Sized,
{
    loop {
        match target.start_quantum(horizon) {
            Ok(pending) => return Ok(Acquisition::Published(pending)),
            Err(error) if error.is_publication_unavailable() => {}
            Err(error) => return Err(QemuAsyncDriverError::Channel(error)),
        }
        let outcome = runtime
            .await_node_publication(timeout)
            .map_err(QemuAsyncDriverError::Runtime)?;
        if outcome == QemuAsyncWaitOutcome::Completed {
            continue;
        }

        let exit = target
            .child_exit_status()
            .map_err(QemuAsyncDriverError::Target)?;
        let cause =
            match exit {
                Some(exit) => Some(crash_detector.unexpected_child_exit(exit)),
                None if outcome == QemuAsyncWaitOutcome::TimedOut
                    && !policy.unbounded_advance_completion =>
                {
                    Some(crash_detector.bounded_await_timeout(
                        QemuAsyncWait::AdvanceCompletion.operation(),
                        timeout,
                    ))
                }
                None => None,
            };
        if let Some(status) = cause {
            let shutdown = target
                .shutdown_after_crash()
                .map_err(QemuAsyncDriverError::Target)?;
            return Ok(Acquisition::Crashed(Box::new(QemuAsyncNodeStepReport {
                ceiling: None,
                outcome: QemuAsyncNodeStepOutcome::Crashed { status, shutdown },
                final_state: None,
                completed_boundary: None,
                inbound_frames_consumed: 0,
                emitted_frames: Vec::new(),
                yielded_before_quantum: true,
                yielded_after_quantum: false,
                hot_path_operations: Vec::new(),
                async_operations: vec![
                    QemuAsyncDriverOperation::YieldToControlPlane,
                    QemuAsyncDriverOperation::ShutdownAfterCrash,
                ],
            })));
        }
        if outcome == QemuAsyncWaitOutcome::TimedOut {
            runtime
                .renew_advance_completion_poll(timeout)
                .map_err(QemuAsyncDriverError::Runtime)?;
        }
    }
}
