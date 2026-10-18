//! Bounds raw Pending member retirement with its once-entered World Cleanup.
//!
//! Physical body completion and the independent post observation are distinct.
//! A later retry observes an already closed body without repeating effects or
//! entering another Cleanup clock.

use super::*;
use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};

type CleanupError = crate::ProductionVmConstructionCleanupError;

impl<F> PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
{
    pub(super) fn finish_under_world_cleanup(&mut self) -> Result<(), CleanupError> {
        let world = self.world.as_ref().ok_or(CleanupError::Retained(
            "entered World has no delivered cleanup loan",
        ))?;
        let cleanup = match world.retained_cleanup() {
            Ok(cleanup) => cleanup,
            Err(first) => {
                self.history.cleanup_first.get_or_insert(first);
                return Err(CleanupError::Retained("same World Cleanup is unavailable"));
            }
        };
        let (attempt, first, post) =
            observe_saved_world_cleanup(&cleanup, || self.finish_native_members());
        if let Some(first) = first {
            self.history.cleanup_first.get_or_insert(first.into());
        }
        if let Err(post) = post {
            self.history.cleanup_post.get_or_insert(post);
        }
        attempt
    }

    fn finish_native_members(&mut self) -> Result<(), CleanupError> {
        let factory =
            self.factory
                .as_mut()
                .ok_or(crate::ProductionVmConstructionCleanupError::Retained(
                    "pending Source lost its actual factory",
                ))?;
        let members = if self.members_closed {
            Ok(())
        } else {
            let world = self.world.as_ref().ok_or(
                crate::ProductionVmConstructionCleanupError::Retained(
                    "entered World has no delivered cleanup loan",
                ),
            )?;
            factory.retry_native_world_construction(world)
        };
        match members {
            Ok(()) => {
                self.members_closed = true;
                if let Some(guard) = self.returned_guard.as_mut() {
                    guard.finish()?;
                }
                self.returned_guard = None;
                self.generation_storage = None;
                self.body_cleanup_complete = true;
                Ok(())
            }
            Err(first) => {
                self.record_first(first);
                Err(crate::ProductionVmConstructionCleanupError::Retained(
                    "same World construction member cleanup remains retained",
                ))
            }
        }
    }
}

fn observe_saved_world_cleanup<T>(
    cleanup: &HostOperationGuard,
    attempt: impl FnOnce() -> Result<T, CleanupError>,
) -> (
    Result<T, CleanupError>,
    Option<HostSupervisionError>,
    Result<(), HostSupervisionError>,
) {
    let (result, first) = match cleanup.wait_slice() {
        Ok(_) => (attempt(), None),
        Err(first) => (
            Err(CleanupError::Retained(
                "same World Cleanup refused retirement effects",
            )),
            Some(first),
        ),
    };
    let post = cleanup.wait_slice().map(|_| ());
    (result, first, post)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
    };

    #[test]
    fn saved_cleanup_observes_independent_post_after_same_initiating_error() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let cleanup = original.begin_original_cleanup_control().unwrap();
        let initiating = CleanupError::Authority(LifecycleApiError::LoopFactory {
            message: String::from("actual typed initiating cause"),
        });
        let CleanupError::Authority(LifecycleApiError::LoopFactory { message }) = &initiating
        else {
            panic!("unexpected fixture variant");
        };
        let pointer = message.as_ptr();

        let (attempt, first, post) = observe_saved_world_cleanup(&cleanup, || {
            cleanup.complete().unwrap();
            Err::<(), _>(initiating)
        });

        let CleanupError::Authority(LifecycleApiError::LoopFactory { message }) =
            attempt.unwrap_err()
        else {
            panic!("initiating cause was replaced");
        };
        assert_eq!(message.as_ptr(), pointer);
        assert!(first.is_none());
        assert_eq!(
            post,
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Completed
            })
        );
    }

    #[test]
    fn terminal_saved_cleanup_refuses_effects_and_keeps_independent_post() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let cleanup = original.begin_original_cleanup_control().unwrap();
        cleanup.complete().unwrap();
        let mut effects = 0;

        let (attempt, first, post) = observe_saved_world_cleanup(&cleanup, || {
            effects += 1;
            Ok(())
        });

        assert!(attempt.is_err());
        assert_eq!(effects, 0);
        assert_eq!(
            first,
            Some(HostSupervisionError::Terminal {
                state: HostOperationState::Completed
            })
        );
        assert_eq!(
            post,
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Completed
            })
        );
    }
}
