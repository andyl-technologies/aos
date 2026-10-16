//! Retires the actual unserved packaged owner under its external original.
//!
//! Worker completion precedes materializer shutdown so accepted checkpoint
//! messages drain through their existing receiver. This path creates no owner
//! thread or response channel. The enclosing actor keeps the entire executor
//! on every refusal, including a cause returned by an already joined thread.

use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};

use super::*;
use crate::executor_pool::original_retirement::OriginalPoolRetirementError;
use exact_pin_materializer::original_retirement::OriginalMaterializerRetirementError;

/// Retains the genuine packaged retirement cause without a late carrier birth.
#[derive(Debug, thiserror::Error)]
pub enum OriginalPackagedRetirementError {
    /// This same owner previously refused retirement and remains contained.
    #[error("original packaged retirement is terminal and retained")]
    Terminal,
    /// The same external original refused before further retirement work.
    #[error("original packaged retirement refused: {0}")]
    Original(#[from] HostSupervisionError),
    /// A source owner needs a separately implemented physical retirement path.
    #[error("packaged source owner still requires physical retirement")]
    SourceOwner,
    /// The existing worker pool remains occupied or failed.
    #[error("original worker retirement refused: {0}")]
    Workers(#[source] OriginalPoolRetirementError),
    /// The same exact-pin materializer returned its initiating cause.
    #[error("original exact-pin retirement refused: {0}")]
    Materializer(#[source] OriginalMaterializerRetirementError),
    /// The actual Main dispatcher remains physically retained by this owner.
    #[error("original Main Target dispatcher retirement refused: {0}")]
    TargetDispatcher(#[source] QemuVmRealizationError),
    /// The permanent same Main queue retains physical lifecycle custody.
    #[error("original lifecycle cleanup refused: {0}")]
    LifecycleCleanup(#[source] crucible_api::LifecycleApiError),
    /// Independent component reports retained before dispatcher retirement.
    #[error(
        "packaged cleanup: Source retained={source_owner}; Source refusal={source_failure:?}; workers={workers:?}; materializer={materializer:?}; controls={controls:?}; lifecycle={lifecycle:?}; post={post:?}"
    )]
    Components {
        /// The actual Source owner remains present.
        source_owner: bool,
        /// Exact retained hot-fork owner refused its own real shutdown route.
        source_failure: Option<PackagedQemuHotForkSourceShutdownError>,
        /// The service or pool's initiating refusal.
        workers: Option<OriginalPoolRetirementError>,
        /// The materializer's independently observed refusal.
        materializer: Option<OriginalMaterializerRetirementError>,
        /// Worker hooks and the subsequent lifecycle drain.
        controls: Option<crate::campaign_process::ExecutorControlRetirementError>,
        /// The same owner's final lifecycle-queue observation.
        lifecycle: Option<crucible_api::LifecycleApiError>,
        /// The same external Original postcut.
        post: Option<HostSupervisionError>,
        /// Actual final worker, materializer, queue and dispatcher cuts completed.
        physically_closed: bool,
    },
    /// Native roster custody refused after the executor body was freed.
    #[error("original native roster retirement refused: {0}")]
    Accounts(#[from] crucible_qemu::OriginalActorAccountError),
}

impl PackagedQemuExecutor {
    pub(crate) fn physically_retired(&self) -> bool {
        self.original_physically_retired
    }

    /// Prepares this actual owner for physical destruction under its original.
    ///
    /// # Errors
    /// Refuses a retained hot-fork source, unfinished or failed workers, the
    /// real materializer, actual Main dispatcher or saved original. Refusal
    /// leaves this body owned.
    pub(crate) fn try_retire_original(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), OriginalPackagedRetirementError> {
        original.wait_slice()?;
        let mut source_failure = None;
        let workers = self.service.try_retire_original(original).err();
        // The materializer must keep serving accepted checkpoint work while
        // service worker bodies still exist, even after a semantic pool report.
        let mut materializer = None;
        let controls = self
            .guarded_state
            .config
            .normal_executor
            .as_ref()
            .and_then(|main| {
                crate::campaign_process::try_retire_executor_controls(main, original).err()
            });
        let service_retry = if self.service.physically_retired() {
            None
        } else {
            self.service.try_retire_original(original).err()
        };
        let workers = workers.or(service_retry);
        if self.service.physically_retired() {
            if !self.source_physically_retired {
                let source = self
                    .hot_fork_owner
                    .as_ref()
                    .map(|owner| owner.orderly_shutdown())
                    .unwrap_or(Ok(()));
                if source.is_ok() {
                    self.source_physically_retired = true;
                }
                source_failure = source.err();
            }
            materializer = self
                .exact_pin_materializer
                .try_retire_original(original)
                .err();
        }
        let final_controls = self
            .guarded_state
            .config
            .normal_executor
            .as_ref()
            .and_then(|main| {
                crate::campaign_process::try_retire_executor_controls(main, original).err()
            });
        let controls_closed = final_controls
            .as_ref()
            .is_none_or(|error| error.physically_closed());
        let controls = controls.or(final_controls);
        let lifecycle = self
            .guarded_state
            .lifecycle_cleanup
            .as_ref()
            .and_then(|queue| {
                let work = queue.retry_pending();
                let empty = queue.verify_empty();
                work.and(empty).err()
            });
        let source_owner = !self.source_physically_retired;
        let prerequisites_closed = !source_owner
            && self.service.physically_retired()
            && self.exact_pin_materializer.physically_retired()
            && controls_closed
            && lifecycle.is_none();
        let dispatcher = if prerequisites_closed {
            original.wait_slice()?;
            self.guarded_state
                .host
                .as_ref()
                .ok_or_else(|| QemuVmRealizationError::ExecutorUnavailable {
                    operation: "retire original Main Target dispatcher",
                    message: String::from("actual saved Linux host factory is absent"),
                })
                .and_then(SharedQemuAttemptHostResourceFactory::finish_target_dispatcher)
        } else {
            return Err(OriginalPackagedRetirementError::Components {
                source_owner,
                source_failure,
                workers,
                materializer,
                controls,
                lifecycle,
                post: original.wait_slice().err(),
                physically_closed: false,
            });
        };
        let post = original.wait_slice().err();
        let physically_closed = dispatcher.is_ok();
        self.original_physically_retired |= physically_closed;
        if let Err(source) = dispatcher {
            return Err(OriginalPackagedRetirementError::TargetDispatcher(source));
        }
        if workers.is_some()
            || materializer.is_some()
            || source_failure.is_some()
            || controls.is_some()
            || lifecycle.is_some()
            || post.is_some()
        {
            return Err(OriginalPackagedRetirementError::Components {
                source_owner,
                source_failure,
                workers,
                materializer,
                controls,
                lifecycle,
                post,
                physically_closed,
            });
        }
        Ok(())
    }
}

impl OriginalPackagedRetirementError {
    pub(crate) fn physically_closed(&self) -> bool {
        matches!(
            self,
            Self::Components {
                physically_closed: true,
                ..
            }
        )
    }
}
