//! Bounds the existing watcher join by its retained original Cleanup guard.
//!
//! This path starts no worker, clock owner or cancellation event. Its local
//! timeout preserves the ordinary finish ceiling; every poll also observes the
//! same original absolute end. A refusal returns the actual watcher separately
//! from its first typed cause so the process owner can restore custody.

use std::time::Instant;

use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};

use super::{LinuxQemuCgroupWatcher, WATCHER_WAIT_POLL_INTERVAL, signal_terminal};

impl super::LinuxQemuCgroupCleanupAuthority {
    /// Removes an unconfigured child that has never exposed a spawn contract.
    pub(crate) fn remove_under_original(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), crate::QemuVmRealizationError> {
        original.wait_slice().map_err(original_error)?;
        if self.original_removed {
            return Ok(());
        }
        let pinned = self.pin_directory();
        check_group_result(original, pinned)?;

        original.wait_slice().map_err(original_error)?;
        let verified = match self.directory.as_ref() {
            Some(directory) => super::verify_directory_identity(
                &self.parent_directory,
                &self.name,
                directory,
                &self.path,
            ),
            None => Err(super::LinuxQemuCgroupError::DirectoryIdentity {
                path: self.path.clone(),
            }),
        };
        check_group_result(original, verified)?;

        original.wait_slice().map_err(original_error)?;
        let removed = super::unlinkat(
            &self.parent_directory,
            self.name.as_str(),
            super::AtFlags::REMOVEDIR,
        )
        .map_err(|source| super::LinuxQemuCgroupError::Io {
            operation: "remove unconfigured original QEMU cgroup",
            path: self.path.clone(),
            source: source.into(),
        });
        if removed.is_ok() {
            self.original_removed = true;
        }
        check_group_result(original, removed)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("partial original cgroup cleanup failed: {source}; original: {original_after:?}")]
struct OriginalGroupRefusal {
    #[source]
    source: super::LinuxQemuCgroupError,
    original_after: Option<HostSupervisionError>,
}

fn original_error(source: HostSupervisionError) -> crate::QemuVmRealizationError {
    crate::QemuVmRealizationError::ModelCopy {
        source: Box::new(source),
    }
}

fn check_group_result(
    original: &HostOperationGuard,
    result: Result<(), super::LinuxQemuCgroupError>,
) -> Result<(), crate::QemuVmRealizationError> {
    let checked = original.wait_slice();
    match result {
        Ok(()) => checked.map(|_| ()).map_err(original_error),
        Err(source) => Err(crate::QemuVmRealizationError::ModelCopy {
            source: Box::new(OriginalGroupRefusal {
                source,
                original_after: checked.err(),
            }),
        }),
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum OriginalWatcherCause {
    #[error("original watcher cleanup refused: {0}")]
    Original(#[source] HostSupervisionError),
    #[error("existing watcher terminal signal failed: {0}")]
    Signal(#[source] std::io::Error),
    #[error("existing watcher finish timeout expired")]
    Timeout,
    #[error("watcher terminated outside its guarded body")]
    ThreadPanicked,
}

#[derive(Debug, thiserror::Error)]
#[error("{cause}; original postcheck: {original_after:?}")]
pub(crate) struct OriginalWatcherRefusal {
    #[source]
    cause: OriginalWatcherCause,
    original_after: Option<HostSupervisionError>,
}

impl LinuxQemuCgroupWatcher {
    // crucible-lint: allow clippy-disallowed-method -- the existing host-only join timeout is retained alongside the original guard, never substituted for its absolute end.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn finish_under_original(
        mut self,
        timeout: std::time::Duration,
        original: &HostOperationGuard,
    ) -> Result<(), (Option<Self>, OriginalWatcherRefusal)> {
        if let Err(source) = original.wait_slice() {
            return Err((
                Some(self),
                refusal(OriginalWatcherCause::Original(source), None),
            ));
        }
        let signal = signal_terminal(&self.watcher_state, self.cancellation_event.as_raw_fd());
        let after = original.wait_slice();
        if let Err(source) = signal {
            return Err((
                Some(self),
                refusal(OriginalWatcherCause::Signal(source), after.err()),
            ));
        }
        if let Err(source) = after {
            return Err((
                Some(self),
                refusal(OriginalWatcherCause::Original(source), None),
            ));
        }

        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return Err((Some(self), refusal(OriginalWatcherCause::Timeout, None)));
        };
        loop {
            let slice = match original.wait_slice() {
                Ok(slice) => slice,
                Err(source) => {
                    return Err((
                        Some(self),
                        refusal(OriginalWatcherCause::Original(source), None),
                    ));
                }
            };
            let Some(join) = self.join.as_ref() else {
                return Err((None, refusal(OriginalWatcherCause::ThreadPanicked, None)));
            };
            if join.is_finished() {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err((Some(self), refusal(OriginalWatcherCause::Timeout, None)));
            }
            std::thread::sleep(
                slice
                    .min(WATCHER_WAIT_POLL_INTERVAL)
                    .min(deadline.duration_since(now)),
            );
        }

        if let Err(source) = original.wait_slice() {
            return Err((
                Some(self),
                refusal(OriginalWatcherCause::Original(source), None),
            ));
        }
        let Some(join) = self.join.take() else {
            return Err((None, refusal(OriginalWatcherCause::ThreadPanicked, None)));
        };
        let joined = join.join();
        // A successful join owns the actual watcher control; close it before
        // recording the original postcheck, including a failed postcheck.
        let panicked = joined.is_err();
        drop(joined);
        let after = original.wait_slice();
        if panicked {
            return Err((
                None,
                refusal(OriginalWatcherCause::ThreadPanicked, after.err()),
            ));
        }
        if let Err(source) = after {
            return Err((None, refusal(OriginalWatcherCause::Original(source), None)));
        }
        Ok(())
    }
}

fn refusal(
    cause: OriginalWatcherCause,
    original_after: Option<HostSupervisionError>,
) -> OriginalWatcherRefusal {
    OriginalWatcherRefusal {
        cause,
        original_after,
    }
}

use std::os::fd::AsRawFd as _;
