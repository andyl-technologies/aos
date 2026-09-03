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
    /// An impossible internal state omitted required authority.
    #[error("QEMU attempt process owner lost {authority} authority")]
    MissingAuthority {
        /// Missing state-machine component.
        authority: &'static str,
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
    group: LinuxQemuCgroup,
    watcher: Option<LinuxQemuCgroupWatcher>,
}

impl LinuxQemuAttemptProcessOwnerStartError {
    /// Returns the startup diagnostic without consuming retained authority.
    #[must_use]
    pub(crate) const fn source_error(&self) -> &LinuxQemuAttemptProcessOwnerError {
        &self.source
    }

    /// Recovers the configured cgroup and optional started watcher.
    #[must_use]
    pub(crate) fn into_parts(
        mut self,
    ) -> Option<(LinuxQemuCgroup, Option<LinuxQemuCgroupWatcher>)> {
        let authority = *self.authority.take()?;
        Some((authority.group, authority.watcher))
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
        child_user_id: libc::uid_t,
        child_group_id: libc::gid_t,
    ) -> Result<Self, LinuxQemuAttemptProcessOwnerStartError> {
        let watcher = match group.start_watcher() {
            Ok(watcher) => watcher,
            Err(source) => {
                return Err(LinuxQemuAttemptProcessOwnerStartError {
                    source: source.into(),
                    authority: Some(Box::new(LinuxQemuAttemptProcessOwnerStartAuthority {
                        group,
                        watcher: None,
                    })),
                });
            }
        };
        let process_contract = match group.child_process_contract(
            maximum_writable_bytes,
            child_user_id,
            child_group_id,
        ) {
            Ok(contract) => contract,
            Err(source) => {
                return Err(LinuxQemuAttemptProcessOwnerStartError {
                    source: source.into(),
                    authority: Some(Box::new(LinuxQemuAttemptProcessOwnerStartAuthority {
                        group,
                        watcher: Some(watcher),
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

    /// Returns the latest detached-quarantine state, when transfer occurred.
    #[must_use]
    pub(crate) fn status(&self) -> Option<LinuxQemuAttemptProcessOwnerStatus> {
        self.quarantine
            .as_ref()
            .map(|quarantine| owner_quarantine_status(quarantine.status()))
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

    #[test]
    fn start_failure_returns_group_and_started_watcher() -> Result<(), Box<dyn std::error::Error>> {
        let (_root, group) = group_fixture()?;
        let error = LinuxQemuAttemptProcessOwner::start(group, 4096, 65_533, 65_532)
            .expect_err("ordinary filesystem must fail cgroup provenance validation");
        assert!(matches!(
            error.source_error(),
            LinuxQemuAttemptProcessOwnerError::Cgroup(LinuxQemuCgroupError::Io { .. })
        ));
        let (_group, watcher) = error
            .into_parts()
            .ok_or_else(|| std::io::Error::other("owner startup lost cgroup authority"))?;
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
        while owner.status() != Some(LinuxQemuAttemptProcessOwnerStatus::ReapedAndReleased)
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            owner.status(),
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
