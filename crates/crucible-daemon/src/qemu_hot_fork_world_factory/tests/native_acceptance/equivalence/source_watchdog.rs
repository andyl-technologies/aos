//! Host panic fallback for the initial single-node equivalence source stage.
//!
//! This opt-in qualification bound can reject a legitimately slow run. It is
//! not guest time, a campaign timeout outcome, or evidence of a runtime repair.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use crate::AttemptExecutionContext;
use crate::supervision::AssignmentHostWatchdogGuard;

pub(super) const SOURCE_STAGE_HOST_WATCHDOG_MS: u64 = 300_000;

/// Retains the original context and cancellation incarnation across the stage.
pub(super) fn run_source_stage<T>(
    context: AttemptExecutionContext,
    milliseconds: u64,
    stage: impl FnOnce(&AttemptExecutionContext) -> T,
) -> (AttemptExecutionContext, T) {
    let mut watchdog =
        AssignmentHostWatchdogGuard::start(milliseconds, context.cancellation().clone())
            .expect("start native fixture source-stage watchdog");
    let context = context.with_host_watchdog(watchdog.state.clone());
    let result = catch_unwind(AssertUnwindSafe(|| stage(&context)));
    let expired = watchdog.stop();

    match result {
        Ok(value) => {
            assert!(
                !expired,
                "native fixture source-stage host watchdog expired after {milliseconds} ms"
            );
            (context, value)
        }
        Err(payload) => {
            if expired {
                eprintln!(
                    "native fixture source-stage host watchdog expired after {milliseconds} ms; retaining original panic"
                );
            }
            // Unwinding the stage already ran the original ownership cleanup.
            resume_unwind(payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use crucible_campaign::{AttemptResourceLimits, ExecutionRetentionIntent};

    use super::*;
    use crate::executor_supervisor::ExecutionCancellationHook;
    use crate::{ExecutionCancellation, ExecutionCheckpointRequest};

    fn context() -> AttemptExecutionContext {
        AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1024, 2048, 2).expect("test resources"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
            crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
        )
    }

    #[test]
    fn source_stage_authors_finite_advance_and_disarms_the_same_incarnation() {
        let context = context();
        let cancellation = context.cancellation().clone();
        let template = crucible_api::ProductionVmLifecycleConfig::new(
            "qemu", "plugin", "kernel", "root", "run",
        );
        let baseline = crate::qemu_campaign_lifecycle::config_for_assignment_host_watchdog(
            template.clone(),
            &context,
        )
        .expect("original fixture configuration");
        assert!(baseline.unbounded_advance_completion());

        let (context, value) = run_source_stage(context, 5000, |context| {
            assert!(context.cancellation().same_incarnation(&cancellation));
            let configured = crate::qemu_campaign_lifecycle::config_for_assignment_host_watchdog(
                template.clone(),
                context,
            )
            .expect("authored watchdog configuration");
            assert!(!configured.unbounded_advance_completion());
            assert!(configured.completion_timeout() <= Duration::from_secs(5));
            assert!(!configured.completion_timeout().is_zero());
            17
        });

        assert_eq!(value, 17);
        assert!(context.cancellation().same_incarnation(&cancellation));
        assert!(!cancellation.is_canceled());
    }

    #[test]
    fn source_stage_preserves_the_original_panic_and_disarms_cancellation() {
        let context = context();
        let cancellation = context.cancellation().clone();

        let failure = catch_unwind(AssertUnwindSafe(|| {
            run_source_stage::<()>(context, 5000, |_| panic!("original source-stage failure"))
        }))
        .expect_err("original stage panic remains a failure");

        assert_eq!(
            failure.downcast_ref::<&str>(),
            Some(&"original source-stage failure")
        );
        assert!(!cancellation.is_canceled());
    }

    #[derive(Debug)]
    struct CancellationNotice(mpsc::Sender<()>);

    impl ExecutionCancellationHook for CancellationNotice {
        fn signal(&self) {
            let _ = self.0.send(());
        }
    }

    #[test]
    fn source_stage_cancels_the_same_incarnation_and_refuses_an_expired_candidate() {
        let context = context();
        let cancellation = context.cancellation().clone();
        let (notice, observed) = mpsc::channel();
        let hook: Arc<dyn ExecutionCancellationHook> = Arc::new(CancellationNotice(notice));
        let _registration = cancellation.register_hook(hook).expect("cancellation hook");

        let failure = catch_unwind(AssertUnwindSafe(|| {
            run_source_stage(context, 1, |context| {
                assert!(context.cancellation().same_incarnation(&cancellation));
                observed
                    .recv_timeout(Duration::from_secs(5))
                    .expect("original watchdog published cancellation");
                17
            })
        }))
        .expect_err("deadline wins over the returned candidate");

        assert!(cancellation.is_canceled());
        let message = failure.downcast_ref::<String>().expect("expiry panic text");
        assert!(message.contains("source-stage host watchdog expired after 1 ms"));
    }
}
