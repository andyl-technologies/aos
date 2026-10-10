//! Attempt-lifetime ownership for one guarded QEMU cgroup.
//!
//! This state machine keeps the configured cgroup, its one watcher, the sealed
//! launch contract, and every direct-child wait handle under one owner. Normal
//! completion closes and joins the watcher before removing the cgroup. Failed
//! realization transfers the complete state to the nondroppable quarantine
//! worker. Dropping an unfinished owner performs that transfer instead of
//! invoking bounded child destructors or releasing cgroup authority.

use std::collections::VecDeque;
use std::time::Duration;

#[cfg(feature = "private-measurement-domain")]
use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};

use thiserror::Error;

use super::quarantine::{
    LinuxQemuAttemptProcessQuarantine, LinuxQemuAttemptProcessQuarantineStatus,
};
use super::{
    LinuxQemuCgroup, LinuxQemuCgroupCancellationSignal, LinuxQemuCgroupError,
    LinuxQemuCgroupWatcher, QemuChildProcessContract, QemuNodeChild, QemuProcessIdentity,
    WATCHER_RUNNING,
};

/// Result of one attempt-process owner cleanup observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxQemuAttemptProcessOwnerStatus {
    /// The watcher joined and the authenticated empty cgroup was removed.
    ReapedAndReleased,
    /// Detached quarantine still owns cleanup authority.
    QuarantineRunning,
    /// Detached quarantine parked after one caught invariant panic.
    QuarantineParked,
}

/// Failure while starting or advancing one attempt-process owner.
#[derive(Debug, Error)]
pub(crate) enum LinuxQemuAttemptProcessOwnerError {
    /// A cgroup operation failed while the owner retained its authority.
    #[error(transparent)]
    Cgroup(#[from] LinuxQemuCgroupError),
    /// A watcher operation failed while the owner retained its authority.
    #[error("QEMU cgroup watcher cleanup failed: {message}")]
    Watcher {
        /// Stable diagnostic from the retained watcher error.
        message: String,
    },
    /// The nondroppable quarantine worker could not accept ownership.
    #[error("QEMU process quarantine startup failed: {message}")]
    Quarantine {
        /// Stable diagnostic from the retained startup error.
        message: String,
    },
    /// The original Parent permanently retains the complete watcher failure.
    #[cfg(feature = "private-measurement-domain")]
    #[error("original Parent retains its originating watcher cleanup failure")]
    OriginalParentWatcherRetained,
    /// The original Parent permanently retains the complete group failure.
    #[cfg(feature = "private-measurement-domain")]
    #[error("original Parent retains its originating group removal failure")]
    OriginalParentGroupRetained,
    /// An impossible internal state omitted required authority.
    #[error("QEMU attempt process owner lost {authority} authority")]
    MissingAuthority {
        /// Missing state-machine component.
        authority: &'static str,
    },
}

#[cfg(feature = "private-measurement-domain")]
#[derive(Debug, Error)]
pub(crate) enum OriginalProcessFinishError {
    #[error("original process cleanup refused: {0}")]
    Original(#[source] HostSupervisionError),
    #[error("original watcher cleanup failed: {0}")]
    Watcher(#[source] super::original_finish::OriginalWatcherRefusal),
    #[error("physical process cleanup failed: {source}; original: {original_after:?}")]
    Physical {
        #[source]
        source: LinuxQemuAttemptProcessOwnerError,
        original_after: Option<HostSupervisionError>,
    },
}

/// Failed owner startup with every created cgroup authority retained.
#[derive(Debug, Error)]
#[error("failed to start QEMU attempt process owner: {source}")]
#[must_use = "recover the cgroup authority or leak it fail-closed"]
pub(crate) struct LinuxQemuAttemptProcessOwnerStartError {
    source: LinuxQemuAttemptProcessOwnerError,
    authority: Option<Box<LinuxQemuAttemptProcessOwnerStartAuthority>>,
}

#[derive(Debug)]
struct LinuxQemuAttemptProcessOwnerStartAuthority {
    _group: LinuxQemuCgroup,
    _watcher: Option<LinuxQemuCgroupWatcher>,
}

impl LinuxQemuAttemptProcessOwnerStartError {
    /// Returns the startup diagnostic without consuming retained authority.
    #[must_use]
    pub(crate) const fn source_error(&self) -> &LinuxQemuAttemptProcessOwnerError {
        &self.source
    }

    /// Recovers the same partial owner for original-aware physical cleanup.
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn into_original_owner(mut self) -> Option<LinuxQemuAttemptProcessOwner> {
        self.authority.take().map(|authority| {
            let authority = *authority;
            LinuxQemuAttemptProcessOwner {
                group: Some(authority._group),
                watcher: authority._watcher,
                process_contract: None,
                failed_children: VecDeque::new(),
                quarantine: None,
            }
        })
    }
}

impl Drop for LinuxQemuAttemptProcessOwnerStartError {
    fn drop(&mut self) {
        if let Some(authority) = self.authority.take() {
            // An ignored startup error must not release a configured cgroup or
            // detach a live watcher. The future daemon owner recovers this
            // authority; leaking is the fail-closed fallback.
            let _leaked = Box::leak(authority);
        }
    }
}

/// Complete process authority for one guarded QEMU attempt.
#[derive(Debug)]
#[must_use = "finish the attempt owner or transfer it to quarantine"]
pub(crate) struct LinuxQemuAttemptProcessOwner {
    group: Option<LinuxQemuCgroup>,
    watcher: Option<LinuxQemuCgroupWatcher>,
    process_contract: Option<QemuChildProcessContract>,
    failed_children: VecDeque<QemuNodeChild>,
    quarantine: Option<LinuxQemuAttemptProcessQuarantine>,
}

impl LinuxQemuAttemptProcessOwner {
    /// Retains a configured group before watcher or contract publication.
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn retain_created(group: LinuxQemuCgroup) -> Self {
        Self {
            group: Some(group),
            watcher: None,
            process_contract: None,
            failed_children: VecDeque::new(),
            quarantine: None,
        }
    }

    /// Publishes the existing watcher before the caller's original postcheck.
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn start_saved_watcher(&mut self) -> Result<(), LinuxQemuAttemptProcessOwnerError> {
        let group =
            self.group
                .as_mut()
                .ok_or(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                    authority: "created Parent group",
                })?;
        self.watcher = Some(group.start_watcher()?);
        Ok(())
    }

    /// Stores the sealed contract while the original caller retains this owner.
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn seal_saved_contract(
        &mut self,
        limits: crate::spawn::QemuChildFileLimits,
        user: u32,
        group_id: u32,
    ) -> Result<(), LinuxQemuAttemptProcessOwnerError> {
        let group =
            self.group
                .as_ref()
                .ok_or(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                    authority: "created Parent group",
                })?;
        self.process_contract = Some(group.child_process_contract(
            limits.writable_bytes,
            limits.descriptors,
            limits.locked_bytes,
            user,
            group_id,
            None,
        )?);
        Ok(())
    }

    /// Starts the one watcher and seals the exact child launch contract.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptProcessOwnerStartError`] with the configured
    /// group and any started watcher when descriptor setup or contract
    /// validation fails.
    pub(crate) fn start(
        mut group: LinuxQemuCgroup,
        maximum_writable_bytes: u64,
        maximum_file_descriptors: u64,
        maximum_locked_bytes: u64,
        child_user_id: libc::uid_t,
        child_group_id: libc::gid_t,
        exact_checkpoint_root: Option<crucible::ContentHash>,
    ) -> Result<Self, LinuxQemuAttemptProcessOwnerStartError> {
        let watcher = match group.start_watcher() {
            Ok(watcher) => watcher,
            Err(source) => {
                return Err(LinuxQemuAttemptProcessOwnerStartError {
                    source: source.into(),
                    authority: Some(Box::new(LinuxQemuAttemptProcessOwnerStartAuthority {
                        _group: group,
                        _watcher: None,
                    })),
                });
            }
        };
        let process_contract = match group.child_process_contract(
            maximum_writable_bytes,
            maximum_file_descriptors,
            maximum_locked_bytes,
            child_user_id,
            child_group_id,
            exact_checkpoint_root,
        ) {
            Ok(contract) => contract,
            Err(source) => {
                return Err(LinuxQemuAttemptProcessOwnerStartError {
                    source: source.into(),
                    authority: Some(Box::new(LinuxQemuAttemptProcessOwnerStartAuthority {
                        _group: group,
                        _watcher: Some(watcher),
                    })),
                });
            }
        };
        Ok(Self {
            group: Some(group),
            watcher: Some(watcher),
            process_contract: Some(process_contract),
            failed_children: VecDeque::new(),
            quarantine: None,
        })
    }

    pub(crate) fn memory_control(
        &self,
    ) -> Result<super::LinuxQemuCgroupMemoryControl, LinuxQemuAttemptProcessOwnerError> {
        self.process_contract()?;
        self.group
            .as_ref()
            .ok_or(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                authority: "configured cgroup",
            })?
            .control
            .memory_control()
            .map_err(Into::into)
    }

    /// Returns the sealed child-process contract while this owner is active.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptProcessOwnerError::MissingAuthority`] after
    /// terminal cleanup or quarantine transfer has begun.
    pub(crate) fn process_contract(
        &self,
    ) -> Result<&QemuChildProcessContract, LinuxQemuAttemptProcessOwnerError> {
        if let Some(group) = self.group.as_ref()
            && group
                .control
                .watcher_state
                .load(std::sync::atomic::Ordering::Acquire)
                != WATCHER_RUNNING
        {
            return Err(LinuxQemuCgroupError::WatcherNotRunning {
                path: group.path.clone(),
            }
            .into());
        }
        self.process_contract
            .as_ref()
            .ok_or(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                authority: "child-process contract",
            })
    }

    /// Duplicates the narrow sticky-cancellation signal for a daemon relay.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptProcessOwnerError`] after terminal cleanup or
    /// when the event descriptor cannot be duplicated.
    pub(crate) fn cancellation_signal(
        &self,
    ) -> Result<LinuxQemuCgroupCancellationSignal, LinuxQemuAttemptProcessOwnerError> {
        let group =
            self.group
                .as_ref()
                .ok_or(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                    authority: "configured cgroup",
                })?;
        group.control.cancellation_signal().map_err(Into::into)
    }

    /// Authenticates one externally forked process as a live group member.
    ///
    /// This path is used for a hot-fork child whose direct `waitpid` authority
    /// remains with the source QEMU process. The daemon separately retains a
    /// pidfd before calling this method, so the returned identity can be bound
    /// to that exact live kernel process generation.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptProcessOwnerError`] after terminal cleanup or
    /// when the PID identity and bounded cgroup-membership proof fail.
    pub(crate) fn authenticate_hot_fork_child_process(
        &mut self,
        process_id: u32,
    ) -> Result<QemuProcessIdentity, LinuxQemuAttemptProcessOwnerError> {
        let group =
            self.group
                .as_mut()
                .ok_or(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                    authority: "configured cgroup",
                })?;
        if group
            .control
            .watcher_state
            .load(std::sync::atomic::Ordering::Acquire)
            != WATCHER_RUNNING
        {
            return Err(LinuxQemuCgroupError::WatcherNotRunning {
                path: group.path.clone(),
            }
            .into());
        }
        if self.process_contract.is_none() {
            return Err(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                authority: "child-process contract",
            });
        }
        group
            .authenticate_process_id(process_id)
            .map_err(Into::into)
    }

    /// Retains a direct child that synchronous realization cleanup could not reap.
    ///
    /// The retained handles are bounded by the cgroup's exact task ceiling.
    /// Exceeding that trusted invariant leaks the excess handle deliberately so
    /// a bounded destructor cannot abandon an unreaped process generation.
    pub(crate) fn retain_failed_child(&mut self, child: QemuNodeChild) {
        let maximum_children = self
            .group
            .as_ref()
            .map_or(0, |group| group.limits.maximum_tasks as usize);
        if self.failed_children.len() >= maximum_children
            || self.failed_children.try_reserve(1).is_err()
        {
            let _leaked = Box::leak(Box::new(child));
            return;
        }
        self.failed_children.push_back(child);
    }

    /// Transfers every unfinished authority to the nondroppable worker.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptProcessOwnerError`] when the worker cannot
    /// start. When startup returns the authorities, this owner restores them so
    /// a caller can retry. If startup cannot recover them, its error leaks them
    /// fail-closed.
    pub(crate) fn quarantine(
        &mut self,
    ) -> Result<LinuxQemuAttemptProcessOwnerStatus, LinuxQemuAttemptProcessOwnerError> {
        if let Some(quarantine) = self.quarantine.as_ref() {
            return Ok(owner_quarantine_status(quarantine.status()));
        }
        let group =
            self.group
                .take()
                .ok_or(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                    authority: "configured cgroup",
                })?;
        let watcher = self.watcher.take();
        let children = std::mem::take(&mut self.failed_children);
        self.process_contract = None;
        match LinuxQemuAttemptProcessQuarantine::start_retained(group, watcher, children) {
            Ok(quarantine) => {
                let status = owner_quarantine_status(quarantine.status());
                self.quarantine = Some(quarantine);
                Ok(status)
            }
            Err(error) => {
                let message = error.to_string();
                if let Some((group, watcher, children)) = error.into_owner_parts() {
                    self.group = Some(group);
                    self.watcher = watcher;
                    self.failed_children = children;
                }
                Err(LinuxQemuAttemptProcessOwnerError::Quarantine { message })
            }
        }
    }

    /// Retains the direct Parent owner while joining under its original end.
    ///
    /// # Errors
    /// Refuses failed-child/quarantine aliases or unfinished authority without
    /// starting an ordinary quarantine worker.
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn finish_under_original_parent(
        &mut self,
        original: &crucible_linux_resource::host_services::process_birth::OriginalParentAttempt,
        setup: &mut crate::linux_attempt_host::OriginalParentSetup,
    ) -> Result<LinuxQemuAttemptProcessOwnerStatus, LinuxQemuAttemptProcessOwnerError> {
        check_parent_cleanup_slot(setup)?;
        if self.quarantine.is_some() || !self.failed_children.is_empty() {
            return Err(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                authority: "original Parent requires retained direct-child retirement",
            });
        }
        if self.group.is_none() {
            return Ok(LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased);
        }
        self.process_contract = None;
        if let Some(watcher) = self.watcher.take() {
            let completed = watcher.finish_under_original_parent(original);
            let retained = retain_parent_watcher_outcome(setup, completed);
            let post = original.check_original();
            if let Err(error) = post {
                setup.cleanup_original_post = Some(error);
            }
            // The real work error stays primary even if the original end also
            // refused. Its complete owner precedes both checks and reporting.
            retained?;
            if let Some(error) = &setup.cleanup_original_post {
                return Err(LinuxQemuAttemptProcessOwnerError::Watcher {
                    message: error.to_string(),
                });
            }
        }
        original
            .check_original()
            .map_err(|error| LinuxQemuAttemptProcessOwnerError::Watcher {
                message: error.to_string(),
            })?;
        let group =
            self.group
                .take()
                .ok_or(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                    authority: "configured original Parent cgroup",
                })?;
        let removed = group.remove_if_empty();
        let retained = retain_parent_group_outcome(setup, removed);
        let post = original.check_original();
        if let Err(error) = post {
            setup.cleanup_original_post = Some(error);
        }
        retained?;
        if let Some(error) = &setup.cleanup_original_post {
            return Err(LinuxQemuAttemptProcessOwnerError::Watcher {
                message: error.to_string(),
            });
        }
        Ok(LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased)
    }

    /// Completes normal watcher and cgroup cleanup within `timeout`.
    ///
    /// A retained failed child changes this operation into quarantine transfer;
    /// the direct child is never reaped on the caller's thread. Watcher timeout
    /// and cgroup removal failures leave this owner retryable in place.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptProcessOwnerError`] while retaining every
    /// recoverable authority needed for another call or quarantine.
    pub(crate) fn finish(
        &mut self,
        timeout: Duration,
    ) -> Result<LinuxQemuAttemptProcessOwnerStatus, LinuxQemuAttemptProcessOwnerError> {
        if self.quarantine.is_some() || !self.failed_children.is_empty() {
            return self.quarantine();
        }
        if self.group.is_none() {
            return Ok(LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased);
        }
        self.process_contract = None;
        if let Some(watcher) = self.watcher.take()
            && let Err(error) = watcher.finish_and_wait(timeout)
        {
            let message = error.to_string();
            self.watcher = error.into_watcher();
            return Err(LinuxQemuAttemptProcessOwnerError::Watcher { message });
        }
        let group =
            self.group
                .take()
                .ok_or(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                    authority: "configured cgroup",
                })?;
        match group.remove_if_empty() {
            Ok(()) => Ok(LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased),
            Err(error) => {
                let message = error.to_string();
                self.group = Some(error.into_group());
                Err(LinuxQemuAttemptProcessOwnerError::Quarantine { message })
            }
        }
    }

    /// Keeps actual watcher and cgroup cleanup within the same original end.
    #[cfg(feature = "private-measurement-domain")]
    pub(crate) fn finish_under_original(
        &mut self,
        timeout: Duration,
        original: &HostOperationGuard,
    ) -> Result<LinuxQemuAttemptProcessOwnerStatus, OriginalProcessFinishError> {
        original
            .wait_slice()
            .map_err(OriginalProcessFinishError::Original)?;
        if self.quarantine.is_some() || !self.failed_children.is_empty() {
            return Err(OriginalProcessFinishError::Physical {
                source: LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                    authority: "direct original cleanup instead of quarantine custody",
                },
                original_after: original.wait_slice().err(),
            });
        }
        if self.group.is_none() {
            return Ok(LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased);
        }
        self.process_contract = None;
        if let Some(watcher) = self.watcher.take()
            && let Err((watcher, source)) = watcher.finish_under_original(timeout, original)
        {
            self.watcher = watcher;
            return Err(OriginalProcessFinishError::Watcher(source));
        }

        original
            .wait_slice()
            .map_err(OriginalProcessFinishError::Original)?;
        let Some(group) = self.group.take() else {
            return Err(OriginalProcessFinishError::Physical {
                source: LinuxQemuAttemptProcessOwnerError::MissingAuthority {
                    authority: "configured cgroup",
                },
                original_after: original.wait_slice().err(),
            });
        };
        let removed = group.remove_if_empty();
        // Preserve the physical fact or recover the actual group before the
        // independent original postcheck can refuse. No path is reacquired.
        let source = match removed {
            Ok(()) => None,
            Err(error) => {
                self.group = Some(*error.group);
                Some(LinuxQemuAttemptProcessOwnerError::Cgroup(error.source))
            }
        };
        let after = original.wait_slice();
        if let Some(source) = source {
            return Err(OriginalProcessFinishError::Physical {
                source,
                original_after: after.err(),
            });
        }
        after.map_err(OriginalProcessFinishError::Original)?;
        Ok(LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased)
    }
}

impl Drop for LinuxQemuAttemptProcessOwner {
    fn drop(&mut self) {
        let Some(group) = self.group.take() else {
            return;
        };
        let watcher = self.watcher.take();
        let children = std::mem::take(&mut self.failed_children);
        self.process_contract = None;
        match LinuxQemuAttemptProcessQuarantine::start_retained(group, watcher, children) {
            Ok(quarantine) => drop(quarantine),
            Err(error) => drop(error),
        }
    }
}

#[cfg(feature = "private-measurement-domain")]
fn check_parent_cleanup_slot(
    setup: &crate::linux_attempt_host::OriginalParentSetup,
) -> Result<(), LinuxQemuAttemptProcessOwnerError> {
    if setup.has_retained_cleanup() {
        return Err(LinuxQemuAttemptProcessOwnerError::MissingAuthority {
            authority: "unoccupied original Parent cleanup slot",
        });
    }
    Ok(())
}

#[cfg(feature = "private-measurement-domain")]
fn retain_parent_watcher_outcome(
    setup: &mut crate::linux_attempt_host::OriginalParentSetup,
    completed: Result<(), super::LinuxQemuCgroupWatcherWaitError>,
) -> Result<(), LinuxQemuAttemptProcessOwnerError> {
    match completed {
        Ok(()) => Ok(()),
        Err(error) => {
            setup.watcher_cleanup_failure = Some(error);
            Err(LinuxQemuAttemptProcessOwnerError::OriginalParentWatcherRetained)
        }
    }
}

#[cfg(feature = "private-measurement-domain")]
fn retain_parent_group_outcome(
    setup: &mut crate::linux_attempt_host::OriginalParentSetup,
    completed: Result<(), super::LinuxQemuCgroupReleaseError>,
) -> Result<(), LinuxQemuAttemptProcessOwnerError> {
    match completed {
        Ok(()) => Ok(()),
        Err(error) => {
            setup.group_cleanup_failure = Some(error);
            Err(LinuxQemuAttemptProcessOwnerError::OriginalParentGroupRetained)
        }
    }
}

fn owner_quarantine_status(
    status: LinuxQemuAttemptProcessQuarantineStatus,
) -> LinuxQemuAttemptProcessOwnerStatus {
    match status {
        LinuxQemuAttemptProcessQuarantineStatus::Running => {
            LinuxQemuAttemptProcessOwnerStatus::QuarantineRunning
        }
        LinuxQemuAttemptProcessQuarantineStatus::ReapedAndReleased => {
            LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased
        }
        LinuxQemuAttemptProcessQuarantineStatus::ParkedWithAuthority => {
            LinuxQemuAttemptProcessOwnerStatus::QuarantineParked
        }
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
    // crucible-lint: allow clippy-disallowed-method -- bounded host polling localizes background failures.
    #![allow(clippy::expect_used, clippy::disallowed_methods)]

    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU8;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::linux_process_identity;
    use crate::spawn::QemuChildProcessContract;

    use super::super::{
        ControlAccess, LinuxQemuCgroupControl, LinuxQemuCgroupLimits, WATCHER_NOT_STARTED,
        create_cancellation_eventfd, duplicate_fd, open_control, open_directory,
    };

    fn group_fixture() -> Result<(tempfile::TempDir, LinuxQemuCgroup), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let name = "attempt";
        let path = root.path().join(name);
        fs::create_dir(&path)?;
        fs::write(path.join("cgroup.kill"), b"xx")?;
        fs::write(path.join("cgroup.events"), b"populated 0\n")?;
        fs::write(path.join("cgroup.procs"), b"")?;

        let parent_directory = open_directory(root.path(), "open attempt-owner parent fixture")?;
        let directory = open_directory(&path, "open attempt-owner cgroup fixture")?;
        let cgroup_kill = open_control(&directory, &path, "cgroup.kill", ControlAccess::Write)?;
        let cgroup_events = open_control(&directory, &path, "cgroup.events", ControlAccess::Read)?;
        let cancellation_event = create_cancellation_eventfd(&path)?;
        let control = LinuxQemuCgroupControl {
            parent_directory: duplicate_fd(
                parent_directory.as_raw_fd(),
                "retain attempt-owner parent fixture",
                &path,
            )?,
            name: String::from(name),
            directory,
            cancellation_event,
            cgroup_kill,
            cgroup_events,
            path: path.clone(),
            watcher_state: Arc::new(AtomicU8::new(WATCHER_NOT_STARTED)),
        };
        Ok((
            root,
            LinuxQemuCgroup {
                path,
                parent_directory,
                name: String::from(name),
                limits: LinuxQemuCgroupLimits::new(1, 4096, 4)?,
                control,
            },
        ))
    }

    fn test_process_contract() -> QemuChildProcessContract {
        let (_cgroup_reader, cgroup_writer) =
            UnixStream::pair().expect("attempt-owner cgroup descriptors");
        let (cancellation_reader, _cancellation_writer) =
            UnixStream::pair().expect("attempt-owner cancellation descriptors");
        QemuChildProcessContract::from_unvalidated_test_descriptors(
            cgroup_writer.into(),
            cancellation_reader.into(),
            1,
            4096,
            4096,
        )
    }

    fn owner_fixture()
    -> Result<(tempfile::TempDir, LinuxQemuAttemptProcessOwner), Box<dyn std::error::Error>> {
        let (root, mut group) = group_fixture()?;
        let watcher = group.start_watcher()?;
        Ok((
            root,
            LinuxQemuAttemptProcessOwner {
                group: Some(group),
                watcher: Some(watcher),
                process_contract: Some(test_process_contract()),
                failed_children: VecDeque::new(),
                quarantine: None,
            },
        ))
    }

    fn unlink_virtual_controls(path: &std::path::Path) -> Result<(), std::io::Error> {
        fs::remove_file(path.join("cgroup.kill"))?;
        fs::remove_file(path.join("cgroup.events"))?;
        fs::remove_file(path.join("cgroup.procs"))
    }

    fn wait_for_cleanup(
        path: &std::path::Path,
        process_id: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(1);
        while (path.exists() || linux_process_identity(process_id)?.is_some())
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        if path.exists() || linux_process_identity(process_id)?.is_some() {
            return Err(std::io::Error::other(
                "attempt-owner quarantine did not reap and remove before deadline",
            )
            .into());
        }
        Ok(())
    }

    #[cfg(feature = "private-measurement-domain")]
    #[test]
    fn parent_saved_process_keeps_watcher_on_contract_refusal_and_unwind()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, group) = group_fixture()?;
        let mut saved = Some(LinuxQemuAttemptProcessOwner::retain_created(group));
        saved
            .as_mut()
            .expect("published process")
            .start_saved_watcher()?;
        let result = saved
            .as_mut()
            .expect("published process")
            .seal_saved_contract(
                crate::spawn::QemuChildFileLimits {
                    writable_bytes: 4096,
                    descriptors: 1024,
                    locked_bytes: 0,
                },
                65_533,
                65_532,
            );
        assert!(
            result.is_err(),
            "regular filesystem cannot seal a cgroup contract"
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                panic!("original postcheck after contract refusal");
            }))
            .is_err()
        );

        let owner = saved
            .as_mut()
            .expect("same published process survives unwind");
        assert!(owner.group.is_some());
        assert!(owner.watcher.is_some());
        assert!(owner.process_contract.is_none());
        assert!(
            owner.quarantine.is_none(),
            "no ordinary worker owns this failure"
        );
        let watcher = owner.watcher.take().expect("same actual started watcher");
        watcher.finish_and_wait(Duration::from_secs(1))?;
        // Synthetic control files do not prove kernel enforcement. The test
        // closes its own joined watcher without invoking the ordinary Drop.
        drop(owner.group.take());
        assert!(root.path().join("attempt").is_dir());
        Ok(())
    }

    #[cfg(feature = "private-measurement-domain")]
    #[test]
    fn parent_cleanup_retains_actual_signal_io_and_watcher_before_postcheck_panic()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("read-only-wake");
        fs::write(&path, b"wake")?;
        let read_only = fs::File::open(&path)?;
        let identity = rustix::fs::fstat(&read_only)?;
        let watcher = LinuxQemuCgroupWatcher {
            cancellation_event: read_only.into(),
            watcher_state: Arc::new(AtomicU8::new(WATCHER_RUNNING)),
            join: None,
            path,
        };
        let mut saved = crate::linux_attempt_host::OriginalParentSetup::empty();

        // The real write fails on a read-only descriptor. No cgroup, issuer or
        // original grant is synthesized by this local error-custody fixture.
        let completed = watcher.finish_and_wait(Duration::from_secs(1));
        let primary = retain_parent_watcher_outcome(&mut saved, completed);
        assert!(matches!(
            primary,
            Err(LinuxQemuAttemptProcessOwnerError::OriginalParentWatcherRetained)
        ));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                panic!("caller postcheck after actual failed signal");
            }))
            .is_err()
        );

        let error = saved
            .watcher_cleanup_failure
            .as_ref()
            .expect("whole signal error");
        let super::super::LinuxQemuCgroupWatcherWaitError::Signal { watcher, source } = error
        else {
            panic!("actual signal failure was replaced: {error}");
        };
        assert_eq!(source.raw_os_error(), Some(libc::EBADF));
        let retained = rustix::fs::fstat(&watcher.cancellation_event)?;
        assert_eq!(
            (retained.st_dev, retained.st_ino),
            (identity.st_dev, identity.st_ino)
        );
        assert!(
            check_parent_cleanup_slot(&saved).is_err(),
            "no later cleanup can overwrite the actual error"
        );
        Ok(())
    }

    #[cfg(feature = "private-measurement-domain")]
    #[test]
    fn parent_cleanup_retains_actual_removal_io_and_pinned_group_on_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, group) = group_fixture()?;
        let identity = rustix::fs::fstat(&group.control.directory)?;
        let mut saved = crate::linux_attempt_host::OriginalParentSetup::empty();

        // Ordinary fixture files make the real rmdir fail with ENOTEMPTY.
        let completed = group.remove_if_empty();
        let primary = retain_parent_group_outcome(&mut saved, completed);
        assert!(matches!(
            primary,
            Err(LinuxQemuAttemptProcessOwnerError::OriginalParentGroupRetained)
        ));
        let actual = root.path().join("attempt");
        let moved = root.path().join("retained-original");
        fs::rename(&actual, &moved)?;
        fs::create_dir(&actual)?;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                panic!("late caller refusal after actual removal failure");
            }))
            .is_err()
        );

        let error = saved
            .group_cleanup_failure
            .as_ref()
            .expect("whole release error");
        assert!(matches!(&error.source,
            LinuxQemuCgroupError::Io { source, .. } if source.raw_os_error() == Some(libc::ENOTEMPTY)
        ));
        let retained = rustix::fs::fstat(&error.group.control.directory)?;
        assert_eq!(
            (retained.st_dev, retained.st_ino),
            (identity.st_dev, identity.st_ino)
        );
        let replacement = open_directory(&actual, "inspect replacement fixture")?;
        assert_ne!(rustix::fs::fstat(&replacement)?.st_ino, retained.st_ino);
        assert!(check_parent_cleanup_slot(&saved).is_err());
        assert!(moved.is_dir());
        assert!(actual.is_dir());
        Ok(())
    }

    #[test]
    fn start_failure_returns_group_and_started_watcher() -> Result<(), Box<dyn std::error::Error>> {
        let (_root, group) = group_fixture()?;
        let mut error =
            LinuxQemuAttemptProcessOwner::start(group, 4096, 1024, 0, 65_533, 65_532, None)
                .expect_err("ordinary filesystem must fail cgroup provenance validation");
        assert!(matches!(
            error.source_error(),
            LinuxQemuAttemptProcessOwnerError::Cgroup(LinuxQemuCgroupError::Io { .. })
        ));
        let authority = error
            .authority
            .take()
            .ok_or_else(|| std::io::Error::other("owner startup lost cgroup authority"))?;
        let LinuxQemuAttemptProcessOwnerStartAuthority {
            _group,
            _watcher: watcher,
        } = *authority;
        let watcher = watcher
            .ok_or_else(|| std::io::Error::other("owner startup lost its started watcher"))?;
        watcher.finish_and_wait(Duration::from_secs(1))?;
        Ok(())
    }

    #[test]
    fn normal_finish_joins_watcher_and_removes_the_exact_group()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, mut owner) = owner_fixture()?;
        let path = owner.group.as_ref().expect("configured group").path.clone();
        assert!(owner.process_contract().is_ok());
        unlink_virtual_controls(&path)?;

        assert_eq!(
            owner.finish(Duration::from_secs(1))?,
            LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased
        );
        assert!(!path.exists());
        assert!(owner.process_contract().is_err());
        Ok(())
    }

    #[test]
    fn narrow_signal_closes_minting_and_drives_normal_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, mut owner) = owner_fixture()?;
        let path = owner.group.as_ref().expect("configured group").path.clone();
        let signal = owner.cancellation_signal()?;

        signal.signal()?;
        assert!(matches!(
            owner.process_contract(),
            Err(LinuxQemuAttemptProcessOwnerError::Cgroup(
                LinuxQemuCgroupError::WatcherNotRunning { .. }
            ))
        ));
        unlink_virtual_controls(&path)?;
        assert_eq!(
            owner.finish(Duration::from_secs(1))?,
            LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased
        );
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn unverified_failed_child_is_reaped_under_the_exact_owner_lifecycle()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, mut owner) = owner_fixture()?;
        let path = owner.group.as_ref().expect("configured group").path.clone();
        let child = QemuNodeChild::new(Command::new("sleep").arg("60").spawn()?);
        let process_id = child.process_id();
        owner.retain_failed_child(child);
        unlink_virtual_controls(&path)?;

        assert_ne!(
            owner.quarantine()?,
            LinuxQemuAttemptProcessOwnerStatus::QuarantineParked
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        while owner
            .quarantine
            .as_ref()
            .map(|quarantine| owner_quarantine_status(quarantine.status()))
            != Some(LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased)
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            owner
                .quarantine
                .as_ref()
                .map(|quarantine| owner_quarantine_status(quarantine.status())),
            Some(LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased)
        );
        assert!(linux_process_identity(process_id)?.is_none());
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn dropping_unfinished_owner_transfers_child_and_cgroup_to_quarantine()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_root, mut owner) = owner_fixture()?;
        let path = owner.group.as_ref().expect("configured group").path.clone();
        let child = QemuNodeChild::new(Command::new("sleep").arg("60").spawn()?);
        let process_id = child.process_id();
        owner.retain_failed_child(child);
        unlink_virtual_controls(&path)?;

        drop(owner);
        wait_for_cleanup(&path, process_id)
    }
}
