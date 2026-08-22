//! Linux cgroup-v2 authority for attempt-contained QEMU processes.
//!
//! This module owns the privileged host boundary that turns an operator-
//! delegated cgroup directory into the sealed pre-exec contract consumed by
//! [`crate::spawn_prepared_qemu_child_with_fds_in_directory_guarded`]. It does
//! so through pinned parent/child directory descriptors rather than trusting a
//! mutable path after creation. Every production child contract also requires
//! a non-root user and group distinct from every supervisor credential; the
//! pre-exec path clears supplementary groups and installs those IDs after
//! cgroup attachment. One attempt owner now composes normal watcher completion,
//! direct-child retention, and nondroppable quarantine transfer. The authority
//! remains crate-internal until aggregate quota, quantum charging, and daemon
//! guard/session composition land. It does not own campaign semantics,
//! VMState, or QEMU/plugin code.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, flock, fstat, fstatfs, mkdirat, open, openat, unlinkat,
};
use thiserror::Error;

use crate::spawn::{QemuChildCredentials, QemuChildProcessContract};
use crate::{QemuNode, QemuNodeChild, QemuProcessIdentity, linux_process_identity};

mod attempt_owner;
mod quarantine;

const CPU_PERIOD_MICROS: u64 = 100_000;
const MAX_CGROUP_CONTROL_BYTES: u64 = 4096;
const CGROUP_KILL_INTERVAL: Duration = Duration::from_millis(10);
const WATCHER_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const WATCHER_NOT_STARTED: u8 = 0;
const WATCHER_RUNNING: u8 = 1;
const WATCHER_TERMINAL: u8 = 2;
const REQUIRED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

/// Maximum task count accepted by the local QEMU cgroup authority.
pub const MAX_LINUX_QEMU_CGROUP_TASKS: u32 = 65_536;

/// Exact cgroup-v2 ceilings installed for one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxQemuCgroupLimits {
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_tasks: u32,
}

impl LinuxQemuCgroupLimits {
    /// Builds nonzero CPU-rate, resident-memory, and task ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError::InvalidLimit`] when any ceiling is zero
    /// or the cgroup CPU quota cannot be represented.
    pub fn new(
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_tasks: u32,
    ) -> Result<Self, LinuxQemuCgroupError> {
        if maximum_vcpus == 0
            || maximum_resident_bytes == 0
            || maximum_tasks == 0
            || maximum_tasks > MAX_LINUX_QEMU_CGROUP_TASKS
        {
            return Err(LinuxQemuCgroupError::InvalidLimit);
        }
        u64::from(maximum_vcpus)
            .checked_mul(CPU_PERIOD_MICROS)
            .ok_or(LinuxQemuCgroupError::InvalidLimit)?;
        Ok(Self {
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_tasks,
        })
    }

    /// Returns the vCPU ceiling used to derive the aggregate CPU-time rate.
    #[must_use]
    pub const fn maximum_vcpus(self) -> u32 {
        self.maximum_vcpus
    }

    /// Returns the admitted resident-memory ceiling.
    #[must_use]
    pub const fn maximum_resident_bytes(self) -> u64 {
        self.maximum_resident_bytes
    }

    /// Returns the defensive cgroup task-count ceiling.
    #[must_use]
    pub const fn maximum_tasks(self) -> u32 {
        self.maximum_tasks
    }

    fn cpu_max(self) -> Result<String, LinuxQemuCgroupError> {
        let quota = u64::from(self.maximum_vcpus)
            .checked_mul(CPU_PERIOD_MICROS)
            .ok_or(LinuxQemuCgroupError::InvalidLimit)?;
        Ok(format!("{quota} {CPU_PERIOD_MICROS}\n"))
    }
}

/// Failure while constructing or operating one QEMU attempt cgroup.
#[derive(Debug, Error)]
pub enum LinuxQemuCgroupError {
    /// A limit was zero or outside the supported checked range.
    #[error("QEMU cgroup limits must be nonzero and representable")]
    InvalidLimit,
    /// The cgroup name was empty, reserved, or path-like.
    #[error("QEMU cgroup name is not a stable single path component: {name}")]
    InvalidName {
        /// Rejected operator-provided name.
        name: String,
    },
    /// The delegated parent does not expose every required controller.
    #[error("delegated cgroup is missing required controller `{controller}`")]
    MissingController {
        /// Missing cgroup-v2 controller name.
        controller: &'static str,
    },
    /// The delegated directory is not on the unified cgroup-v2 filesystem.
    #[error("delegated QEMU cgroup root is not cgroup v2: {path}")]
    NotCgroupV2 {
        /// Rejected delegated root.
        path: PathBuf,
    },
    /// Another supervisor already owns the delegated cgroup namespace.
    #[error("delegated QEMU cgroup root is already locked: {path}")]
    NamespaceLocked {
        /// Contended delegated root.
        path: PathBuf,
    },
    /// A cgroup-v2 filesystem operation failed.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Affected cgroup path.
        path: PathBuf,
        /// Underlying host error.
        source: io::Error,
    },
    /// The exact process generation is absent from this cgroup.
    #[error("QEMU process generation is not an exact member of {path}")]
    ProcessMembership {
        /// Attempt cgroup path.
        path: PathBuf,
    },
    /// The named child no longer identifies the pinned cgroup directory.
    #[error("QEMU cgroup path no longer names the pinned directory: {path}")]
    DirectoryIdentity {
        /// Attempt cgroup path.
        path: PathBuf,
    },
    /// Sticky cancellation already closed this attempt to new children.
    #[error("QEMU cgroup is already canceled: {path}")]
    Canceled {
        /// Closed attempt cgroup path.
        path: PathBuf,
    },
    /// This attempt already created its one persistent watcher.
    #[error("QEMU cgroup watcher is already started: {path}")]
    WatcherAlreadyStarted {
        /// Attempt cgroup path.
        path: PathBuf,
    },
    /// This attempt has no live watcher or has already entered terminal closure.
    #[error("QEMU cgroup watcher is not running: {path}")]
    WatcherNotRunning {
        /// Attempt cgroup path.
        path: PathBuf,
    },
    /// A controller did not retain the exact installed value.
    #[error("QEMU cgroup control {path} retained `{actual}` instead of `{expected}`")]
    ControlValue {
        /// Affected cgroup control file.
        path: PathBuf,
        /// Exact value requested by the authority.
        expected: String,
        /// Value read back from the kernel.
        actual: String,
    },
    /// The cgroup event file was not canonical or complete.
    #[error("QEMU cgroup events are invalid for {path}: {message}")]
    InvalidEvents {
        /// Attempt cgroup path.
        path: PathBuf,
        /// Stable parse diagnostic.
        message: String,
    },
}

/// Failed cgroup creation with optional ownership of the incomplete child.
#[derive(Debug, Error)]
#[error("failed to create QEMU cgroup: {source}")]
#[must_use = "recover and release any incomplete cgroup authority"]
pub struct LinuxQemuCgroupCreateError {
    source: LinuxQemuCgroupError,
    cleanup: Option<Box<LinuxQemuCgroupCleanupAuthority>>,
}

impl LinuxQemuCgroupCreateError {
    fn without_cleanup(source: LinuxQemuCgroupError) -> Self {
        Self {
            source,
            cleanup: None,
        }
    }

    fn with_cleanup(
        source: LinuxQemuCgroupError,
        cleanup: LinuxQemuCgroupCleanupAuthority,
    ) -> Self {
        Self {
            source,
            cleanup: Some(Box::new(cleanup)),
        }
    }

    /// Returns the setup failure without consuming retained cleanup authority.
    #[must_use]
    pub const fn source_error(&self) -> &LinuxQemuCgroupError {
        &self.source
    }

    /// Recovers ownership of the incomplete child when creation reached mkdir.
    #[must_use]
    pub fn into_cleanup_authority(self) -> Option<LinuxQemuCgroupCleanupAuthority> {
        self.cleanup.map(|cleanup| *cleanup)
    }
}

/// Exclusive cleanup authority for a created but incompletely configured child.
#[derive(Debug)]
#[must_use = "the incomplete cgroup must be removed or transferred to quarantine"]
pub struct LinuxQemuCgroupCleanupAuthority {
    path: PathBuf,
    parent_directory: OwnedFd,
    name: String,
    directory: Option<OwnedFd>,
}

impl LinuxQemuCgroupCleanupAuthority {
    /// Returns the incomplete cgroup path for diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Kills every process unexpectedly moved into the incomplete child.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError`] when the pinned child or `cgroup.kill`
    /// cannot be opened or the kill request fails.
    pub fn kill_members(&mut self) -> Result<(), LinuxQemuCgroupError> {
        let path = self.path.clone();
        self.pin_directory()?;
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| LinuxQemuCgroupError::DirectoryIdentity { path: path.clone() })?;
        let mut kill = open_control(directory, &path, "cgroup.kill", ControlAccess::Write)?;
        write_kill(&mut kill, &path)
    }

    /// Returns whether the incomplete child contains a process.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError`] when the child or `cgroup.events`
    /// cannot be authenticated and read within the control-size bound.
    pub fn is_populated(&mut self) -> Result<bool, LinuxQemuCgroupError> {
        let path = self.path.clone();
        self.pin_directory()?;
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| LinuxQemuCgroupError::DirectoryIdentity { path: path.clone() })?;
        let mut events = open_control(directory, &path, "cgroup.events", ControlAccess::Read)?;
        read_populated(&mut events, &path)
    }

    /// Removes the incomplete child after proving it is empty and still named.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupCleanupReleaseError`] with this complete
    /// authority when validation or removal fails.
    pub fn remove_if_empty(mut self) -> Result<(), LinuxQemuCgroupCleanupReleaseError> {
        let populated = match self.is_populated() {
            Ok(populated) => populated,
            Err(source) => {
                return Err(LinuxQemuCgroupCleanupReleaseError {
                    authority: Box::new(self),
                    source,
                });
            }
        };
        if populated {
            let source = LinuxQemuCgroupError::InvalidEvents {
                path: self.path.clone(),
                message: String::from("incomplete cgroup remained populated at release"),
            };
            return Err(LinuxQemuCgroupCleanupReleaseError {
                authority: Box::new(self),
                source,
            });
        }
        if let Err(source) = self.pin_directory() {
            return Err(LinuxQemuCgroupCleanupReleaseError {
                authority: Box::new(self),
                source,
            });
        }
        let identity = self
            .directory
            .as_ref()
            .ok_or_else(|| LinuxQemuCgroupError::DirectoryIdentity {
                path: self.path.clone(),
            })
            .and_then(|directory| {
                verify_directory_identity(&self.parent_directory, &self.name, directory, &self.path)
            });
        if let Err(source) = identity {
            return Err(LinuxQemuCgroupCleanupReleaseError {
                authority: Box::new(self),
                source,
            });
        }
        if let Err(source) = unlinkat(
            &self.parent_directory,
            self.name.as_str(),
            AtFlags::REMOVEDIR,
        ) {
            let source = LinuxQemuCgroupError::Io {
                operation: "remove incomplete QEMU attempt cgroup",
                path: self.path.clone(),
                source: source.into(),
            };
            return Err(LinuxQemuCgroupCleanupReleaseError {
                authority: Box::new(self),
                source,
            });
        }
        Ok(())
    }

    fn pin_directory(&mut self) -> Result<(), LinuxQemuCgroupError> {
        if self.directory.is_none() {
            self.directory = Some(open_directory_at(
                &self.parent_directory,
                &self.name,
                &self.path,
            )?);
        }
        Ok(())
    }
}

/// Failed incomplete-child removal that retains the cleanup authority.
#[derive(Debug, Error)]
#[error("failed to release incomplete QEMU cgroup: {source}")]
pub struct LinuxQemuCgroupCleanupReleaseError {
    authority: Box<LinuxQemuCgroupCleanupAuthority>,
    source: LinuxQemuCgroupError,
}

impl LinuxQemuCgroupCleanupReleaseError {
    /// Returns the removal failure without consuming retained authority.
    #[must_use]
    pub const fn source_error(&self) -> &LinuxQemuCgroupError {
        &self.source
    }

    /// Recovers cleanup authority for kill, quarantine, or retry.
    pub fn into_authority(self) -> LinuxQemuCgroupCleanupAuthority {
        *self.authority
    }
}

/// Failed cgroup removal that retains the complete supervision authority.
#[derive(Debug, Error)]
#[error("failed to release QEMU cgroup: {source}")]
pub struct LinuxQemuCgroupReleaseError {
    group: Box<LinuxQemuCgroup>,
    source: LinuxQemuCgroupError,
}

/// Authenticated direct-child wait authority retained for reap or quarantine.
#[derive(Debug)]
#[must_use = "the direct child must be reaped or transferred to quarantine"]
pub struct LinuxQemuDirectChild {
    identity: QemuProcessIdentity,
    child: QemuNodeChild,
    cgroup_path: PathBuf,
    attempt_lifecycle: Arc<AtomicU8>,
}

impl LinuxQemuDirectChild {
    /// Returns the exact process-generation identity authenticated at handoff.
    #[must_use]
    pub const fn identity(&self) -> &QemuProcessIdentity {
        &self.identity
    }

    /// Returns whether this direct-child authority observed `waitpid` success.
    #[must_use]
    pub const fn is_reaped(&self) -> bool {
        self.child.reaped()
    }

    /// Force-kills and reaps the exact retained direct child.
    ///
    /// The caller must run this blocking wait on its dedicated supervision or
    /// quarantine worker. The authority remains owned by `self` on every
    /// error, so a failed wait cannot discard the only direct-child handle.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError::ProcessMembership`] if a still-running
    /// child no longer has the authenticated process identity. Returns
    /// [`LinuxQemuCgroupError::Io`] when polling, killing, or reaping the direct
    /// child fails.
    pub fn kill_and_reap_blocking(&mut self) -> Result<(), LinuxQemuCgroupError> {
        if self.child.reaped() {
            return Ok(());
        }
        if self
            .child
            .try_wait_natural_exit()
            .map_err(|source| LinuxQemuCgroupError::Io {
                operation: "poll retained QEMU direct child",
                path: self.cgroup_path.clone(),
                source: io::Error::other(source),
            })?
            .is_some()
        {
            return Ok(());
        }
        if linux_process_identity(self.identity.process_id)
            .map_err(|source| LinuxQemuCgroupError::Io {
                operation: "authenticate retained QEMU direct child",
                path: self.cgroup_path.clone(),
                source: io::Error::other(source),
            })?
            .as_ref()
            != Some(&self.identity)
        {
            return Err(LinuxQemuCgroupError::ProcessMembership {
                path: self.cgroup_path.clone(),
            });
        }
        self.child
            .force_kill_and_reap_failed_realization()
            .map_err(|source| LinuxQemuCgroupError::Io {
                operation: "kill and reap retained QEMU direct child",
                path: self.cgroup_path.clone(),
                source: io::Error::other(source),
            })
    }
}

/// Failed direct-child authentication with the wait authority retained.
#[derive(Debug, Error)]
#[error("failed to authenticate QEMU direct child: {source}")]
#[must_use = "recover the direct child for reap or quarantine"]
pub struct LinuxQemuDirectChildAuthenticationError {
    source: LinuxQemuCgroupError,
    child: Box<QemuNodeChild>,
}

impl LinuxQemuDirectChildAuthenticationError {
    /// Returns the authentication failure without consuming the child handle.
    #[must_use]
    pub const fn source_error(&self) -> &LinuxQemuCgroupError {
        &self.source
    }

    /// Recovers the exact direct-child wait authority after failed handoff.
    #[must_use]
    pub fn into_child(self) -> QemuNodeChild {
        *self.child
    }
}

impl LinuxQemuCgroupReleaseError {
    /// Returns the removal failure without consuming the retained authority.
    #[must_use]
    pub const fn source_error(&self) -> &LinuxQemuCgroupError {
        &self.source
    }

    /// Recovers the complete cgroup authority for kill, reap, or retry.
    pub fn into_group(self) -> LinuxQemuCgroup {
        *self.group
    }
}

/// Shared cancellation and kill authority for one attempt cgroup.
#[derive(Debug)]
pub struct LinuxQemuCgroupControl {
    parent_directory: OwnedFd,
    name: String,
    directory: OwnedFd,
    cancellation_event: OwnedFd,
    cgroup_kill: File,
    cgroup_events: File,
    path: PathBuf,
    watcher_state: Arc<AtomicU8>,
}

/// Narrow sticky-cancellation authority for one attempt process group.
///
/// This capability can close child minting and wake the persistent cgroup
/// watcher, but cannot alter resource controls, inspect membership, or release
/// namespace ownership.
#[derive(Debug)]
pub(crate) struct LinuxQemuCgroupCancellationSignal {
    cancellation_event: OwnedFd,
    watcher_state: Arc<AtomicU8>,
    path: PathBuf,
}

impl LinuxQemuCgroupCancellationSignal {
    /// Makes cancellation permanently visible to existing and future children.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError::Io`] when the sticky event cannot be
    /// published. Future child minting remains closed even on that error.
    pub(crate) fn signal(&self) -> Result<(), LinuxQemuCgroupError> {
        signal_terminal(&self.watcher_state, self.cancellation_event.as_raw_fd()).map_err(
            |source| LinuxQemuCgroupError::Io {
                operation: "signal QEMU cancellation eventfd",
                path: self.path.clone(),
                source,
            },
        )
    }
}

impl LinuxQemuCgroupControl {
    /// Duplicates this authority for a persistent cancellation watcher.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError::Io`] when either descriptor cannot be
    /// duplicated.
    pub fn try_clone(&self) -> Result<Self, LinuxQemuCgroupError> {
        let directory = duplicate_fd(
            self.directory.as_raw_fd(),
            "duplicate QEMU cgroup directory",
            &self.path,
        )?;
        Ok(Self {
            parent_directory: duplicate_fd(
                self.parent_directory.as_raw_fd(),
                "retain QEMU cgroup namespace lock",
                &self.path,
            )?,
            name: self.name.clone(),
            cgroup_kill: open_control(&directory, &self.path, "cgroup.kill", ControlAccess::Write)?,
            cgroup_events: open_control(
                &directory,
                &self.path,
                "cgroup.events",
                ControlAccess::Read,
            )?,
            directory,
            cancellation_event: duplicate_fd(
                self.cancellation_event.as_raw_fd(),
                "duplicate QEMU cancellation eventfd",
                &self.path,
            )?,
            path: self.path.clone(),
            watcher_state: Arc::clone(&self.watcher_state),
        })
    }

    fn cancellation_signal(
        &self,
    ) -> Result<LinuxQemuCgroupCancellationSignal, LinuxQemuCgroupError> {
        Ok(LinuxQemuCgroupCancellationSignal {
            cancellation_event: duplicate_fd(
                self.cancellation_event.as_raw_fd(),
                "duplicate QEMU cancellation signal",
                &self.path,
            )?,
            watcher_state: Arc::clone(&self.watcher_state),
            path: self.path.clone(),
        })
    }

    /// Makes cancellation permanently visible to every future child contract.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError::Io`] when the eventfd write fails.
    pub fn signal_cancellation(&mut self) -> Result<(), LinuxQemuCgroupError> {
        signal_terminal(&self.watcher_state, self.cancellation_event.as_raw_fd()).map_err(
            |source| LinuxQemuCgroupError::Io {
                operation: "signal QEMU cancellation eventfd",
                path: self.path.clone(),
                source,
            },
        )?;
        Ok(())
    }

    /// Kills every current cgroup member without disarming future cancellation.
    ///
    /// Persistent cancellation watchers call this repeatedly until the cgroup
    /// is empty so a child racing with the first kill cannot escape.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError::Io`] when `cgroup.kill` rejects the
    /// request.
    pub fn kill_members(&mut self) -> Result<(), LinuxQemuCgroupError> {
        write_kill(&mut self.cgroup_kill, &self.path)
    }

    /// Signals sticky cancellation and kills every current member.
    ///
    /// # Errors
    ///
    /// Returns the first cancellation or kill failure.
    pub fn cancel(&mut self) -> Result<(), LinuxQemuCgroupError> {
        self.signal_cancellation()?;
        self.kill_members()
    }

    /// Returns whether this cgroup currently contains a live process.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError`] when `cgroup.events` cannot be read or
    /// contains a noncanonical `populated` field.
    pub fn is_populated(&mut self) -> Result<bool, LinuxQemuCgroupError> {
        read_populated(&mut self.cgroup_events, &self.path)
    }
}

/// Terminal outcome of one persistent cgroup cancellation watcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxQemuCgroupWatcherOutcome {
    /// Terminal closure was latched and the cgroup became empty.
    ClosedAndEmpty,
}

/// Persistent cancellation and kill owner for one attempt cgroup.
#[derive(Debug)]
#[must_use = "the watcher must be joined or transferred to quarantine"]
pub struct LinuxQemuCgroupWatcher {
    cancellation_event: OwnedFd,
    watcher_state: Arc<AtomicU8>,
    join: Option<JoinHandle<LinuxQemuCgroupWatcherThreadResult>>,
    path: PathBuf,
}

#[derive(Debug)]
struct LinuxQemuCgroupWatcherThreadResult {
    outcome: LinuxQemuCgroupWatcherOutcome,
    authority: LinuxQemuCgroupControl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxQemuCgroupWatcherAttempt {
    Closed(LinuxQemuCgroupWatcherOutcome),
    Retry,
    Panicked,
}

impl LinuxQemuCgroupWatcher {
    fn start(mut control: LinuxQemuCgroupControl) -> Result<Self, LinuxQemuCgroupError> {
        let path = control.path.clone();
        control
            .watcher_state
            .compare_exchange(
                WATCHER_NOT_STARTED,
                WATCHER_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| LinuxQemuCgroupError::WatcherAlreadyStarted { path: path.clone() })?;
        let watcher_state = Arc::clone(&control.watcher_state);
        let cancellation_event = duplicate_fd(
            control.cancellation_event.as_raw_fd(),
            "retain QEMU watcher cancellation eventfd",
            &path,
        )
        .inspect_err(|_| {
            let _ = watcher_state.compare_exchange(
                WATCHER_RUNNING,
                WATCHER_NOT_STARTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        })?;
        let thread_state = Arc::clone(&watcher_state);
        let thread_event = duplicate_fd(
            control.cancellation_event.as_raw_fd(),
            "retain QEMU watcher exit eventfd",
            &path,
        )
        .inspect_err(|_| {
            let _ = watcher_state.compare_exchange(
                WATCHER_RUNNING,
                WATCHER_NOT_STARTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        })?;
        let join = match thread::Builder::new()
            .name(String::from("crucible-qemu-cgroup"))
            .spawn(move || {
                let outcome = loop {
                    match run_cgroup_watcher_attempt(|| cgroup_watcher_loop(&mut control)) {
                        LinuxQemuCgroupWatcherAttempt::Closed(outcome) => break outcome,
                        LinuxQemuCgroupWatcherAttempt::Retry => {
                            let _ = signal_terminal(&thread_state, thread_event.as_raw_fd());
                            thread::sleep(CGROUP_KILL_INTERVAL);
                        }
                        LinuxQemuCgroupWatcherAttempt::Panicked => {
                            let _ = signal_terminal(&thread_state, thread_event.as_raw_fd());
                            // Unwinding invalidates the worker's local
                            // invariants. Retain every authority descriptor in
                            // a parked quarantine instead of re-entering the
                            // panicked body or detaching populated ownership.
                            loop {
                                thread::park();
                            }
                        }
                    }
                };
                let _ = signal_terminal(&thread_state, thread_event.as_raw_fd());
                LinuxQemuCgroupWatcherThreadResult {
                    outcome,
                    authority: control,
                }
            }) {
            Ok(join) => join,
            Err(source) => {
                let _ = watcher_state.compare_exchange(
                    WATCHER_RUNNING,
                    WATCHER_NOT_STARTED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                return Err(LinuxQemuCgroupError::Io {
                    operation: "spawn QEMU cgroup cancellation watcher",
                    path,
                    source,
                });
            }
        };
        Ok(Self {
            cancellation_event,
            watcher_state,
            join: Some(join),
            path,
        })
    }

    /// Signals sticky cancellation and waits for an empty cgroup attestation.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupWatcherWaitError`] with the live watcher on a
    /// timeout, or a terminal watcher error after its thread exits.
    pub fn cancel_and_wait(
        self,
        timeout: Duration,
    ) -> Result<LinuxQemuCgroupWatcherOutcome, LinuxQemuCgroupWatcherWaitError> {
        self.close_and_wait(timeout)
    }

    /// Closes the watcher after the caller has independently reaped QEMU.
    ///
    /// Ordinary finalization deliberately latches the same sticky event as
    /// cancellation. That closes child minting and makes any already-minted
    /// pre-exec contract fail before QEMU code, so no stop race can disarm the
    /// watcher. Killing an already-empty cgroup is harmless.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupWatcherWaitError`] with the live watcher on a
    /// signal failure or timeout, or a terminal watcher error after exit.
    pub fn finish_and_wait(
        self,
        timeout: Duration,
    ) -> Result<LinuxQemuCgroupWatcherOutcome, LinuxQemuCgroupWatcherWaitError> {
        self.close_and_wait(timeout)
    }

    fn close_and_wait(
        self,
        timeout: Duration,
    ) -> Result<LinuxQemuCgroupWatcherOutcome, LinuxQemuCgroupWatcherWaitError> {
        if let Err(source) =
            signal_terminal(&self.watcher_state, self.cancellation_event.as_raw_fd())
        {
            return Err(LinuxQemuCgroupWatcherWaitError::Signal {
                watcher: Box::new(self),
                source,
            });
        }
        self.wait(timeout)
    }

    /// Waits for a previously requested terminal watcher outcome.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupWatcherWaitError::Timeout`] with this watcher
    /// when the deadline expires, or a terminal watcher/thread failure.
    // This clock bounds a host-only join. It never enters modeled or canonical
    // Crucible state.
    #[allow(clippy::disallowed_methods)]
    pub fn wait(
        mut self,
        timeout: Duration,
    ) -> Result<LinuxQemuCgroupWatcherOutcome, LinuxQemuCgroupWatcherWaitError> {
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return Err(LinuxQemuCgroupWatcherWaitError::Timeout {
                watcher: Box::new(self),
            });
        };
        loop {
            let Some(join) = self.join.as_ref() else {
                return Err(LinuxQemuCgroupWatcherWaitError::DetachedThreadPanicked {
                    path: self.path.clone(),
                });
            };
            if join.is_finished() {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(LinuxQemuCgroupWatcherWaitError::Timeout {
                    watcher: Box::new(self),
                });
            }
            thread::sleep(WATCHER_WAIT_POLL_INTERVAL.min(deadline.duration_since(now)));
        }
        let Some(join) = self.join.take() else {
            return Err(LinuxQemuCgroupWatcherWaitError::DetachedThreadPanicked {
                path: self.path.clone(),
            });
        };
        match join.join() {
            Ok(result) => {
                drop(result.authority);
                Ok(result.outcome)
            }
            Err(_) => Err(LinuxQemuCgroupWatcherWaitError::DetachedThreadPanicked {
                path: self.path.clone(),
            }),
        }
    }

    /// Joins a terminal watcher without surrendering the caller's cgroup authority.
    ///
    /// This blocking operation is reserved for the dedicated process-quarantine
    /// worker after sticky cancellation is visible and the direct child has
    /// been reaped. A caught watcher-body panic deliberately never returns: its
    /// thread parks while retaining the duplicated control authority.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError::Io`] when the watcher thread terminates
    /// through an unguarded panic. The caller still owns the configured cgroup
    /// and can continue kill and empty-group validation.
    fn join_terminal_blocking(&mut self) -> Result<(), LinuxQemuCgroupError> {
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        join.join()
            .map(|_| ())
            .map_err(|_| LinuxQemuCgroupError::Io {
                operation: "join QEMU cgroup cancellation watcher",
                path: self.path.clone(),
                source: io::Error::other("watcher thread panicked outside its guarded body"),
            })
    }
}

impl Drop for LinuxQemuCgroupWatcher {
    fn drop(&mut self) {
        if self.join.is_some() {
            let _ = signal_terminal(&self.watcher_state, self.cancellation_event.as_raw_fd());
        }
    }
}

/// Failed watcher signaling or bounded completion.
#[derive(Debug, Error)]
pub enum LinuxQemuCgroupWatcherWaitError {
    /// A wake event failed while the watcher still owns its thread.
    #[error("failed to signal QEMU cgroup watcher: {source}")]
    Signal {
        /// Watcher retained for retry or quarantine.
        watcher: Box<LinuxQemuCgroupWatcher>,
        /// Underlying eventfd failure.
        source: io::Error,
    },
    /// The bounded wait expired while the watcher remained live.
    #[error("timed out waiting for QEMU cgroup watcher")]
    Timeout {
        /// Watcher retained for retry or quarantine.
        watcher: Box<LinuxQemuCgroupWatcher>,
    },
    /// The worker panicked outside the guarded worker body.
    #[error("QEMU cgroup watcher thread detached during panic for {path}")]
    DetachedThreadPanicked {
        /// Affected cgroup path.
        path: PathBuf,
    },
}

impl LinuxQemuCgroupWatcherWaitError {
    /// Recovers the still-running watcher after a signal failure or timeout.
    #[must_use]
    pub fn into_watcher(self) -> Option<LinuxQemuCgroupWatcher> {
        match self {
            Self::Signal { watcher, .. } | Self::Timeout { watcher } => Some(*watcher),
            Self::DetachedThreadPanicked { .. } => None,
        }
    }
}

fn cgroup_watcher_loop(
    control: &mut LinuxQemuCgroupControl,
) -> Result<LinuxQemuCgroupWatcherOutcome, LinuxQemuCgroupError> {
    wait_for_cgroup_watcher_signal(control.cancellation_event.as_raw_fd(), &control.path)?;
    loop {
        control.kill_members()?;
        if !control.is_populated()? {
            return Ok(LinuxQemuCgroupWatcherOutcome::ClosedAndEmpty);
        }
        thread::sleep(CGROUP_KILL_INTERVAL);
    }
}

fn run_cgroup_watcher_attempt(
    attempt: impl FnOnce() -> Result<LinuxQemuCgroupWatcherOutcome, LinuxQemuCgroupError>,
) -> LinuxQemuCgroupWatcherAttempt {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(attempt)) {
        Ok(Ok(outcome)) => LinuxQemuCgroupWatcherAttempt::Closed(outcome),
        Ok(Err(_)) => LinuxQemuCgroupWatcherAttempt::Retry,
        Err(_) => LinuxQemuCgroupWatcherAttempt::Panicked,
    }
}

fn wait_for_cgroup_watcher_signal(
    cancellation_event: RawFd,
    path: &Path,
) -> Result<(), LinuxQemuCgroupError> {
    let mut signal = libc::pollfd {
        fd: cancellation_event,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ready = unsafe {
            // SAFETY: `signal` is one initialized pollfd value.
            libc::poll(&mut signal, 1, -1)
        };
        if ready < 0 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(LinuxQemuCgroupError::Io {
                operation: "wait for QEMU cgroup watcher signal",
                path: path.to_owned(),
                source,
            });
        }
        if signal.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(LinuxQemuCgroupError::Io {
                operation: "wait for QEMU cgroup watcher signal",
                path: path.to_owned(),
                source: io::Error::from_raw_os_error(libc::EBADF),
            });
        }
        if signal.revents & libc::POLLIN != 0 {
            return Ok(());
        }
    }
}

/// Exclusive authority over one operator-delegated cgroup-v2 namespace.
#[derive(Debug)]
#[must_use = "the namespace lock must outlive every attempt cgroup"]
pub struct LinuxQemuCgroupRoot {
    path: PathBuf,
    directory: OwnedFd,
}

impl LinuxQemuCgroupRoot {
    /// Opens, validates, and exclusively locks a delegated cgroup-v2 root.
    ///
    /// Every conforming supervisor that can mutate the delegated namespace
    /// must acquire this advisory lock. The operator must not grant a separate
    /// non-cooperating writer access to the same root.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError`] when the directory is not unified
    /// cgroup v2, required controllers are not delegated, or another owner
    /// already holds the namespace lock.
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, LinuxQemuCgroupError> {
        let path = path.as_ref();
        let directory = open_directory(path, "open delegated cgroup root")?;
        validate_cgroup_v2(&directory, path)?;
        validate_delegated_controllers(&directory, path)?;
        lock_namespace(&directory, path)?;
        Ok(Self {
            path: path.to_owned(),
            directory,
        })
    }

    /// Returns the configured delegated-root path for diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates and configures one attempt child below this exclusive root.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupCreateError`] when the name is unsafe, the child
    /// already exists, or any limit/control file cannot be installed exactly.
    /// Once the child directory exists, the error retains cleanup authority so
    /// the caller can kill, quarantine, or remove the incomplete cgroup.
    pub fn create(
        &mut self,
        name: impl Into<String>,
        limits: LinuxQemuCgroupLimits,
    ) -> Result<LinuxQemuCgroup, LinuxQemuCgroupCreateError> {
        let name = name.into();
        validate_cgroup_name(&name).map_err(LinuxQemuCgroupCreateError::without_cleanup)?;
        let path = self.path.join(&name);
        let parent_directory = duplicate_fd(
            self.directory.as_raw_fd(),
            "retain delegated cgroup namespace lock",
            &path,
        )
        .map_err(LinuxQemuCgroupCreateError::without_cleanup)?;
        mkdirat(
            &self.directory,
            name.as_str(),
            Mode::from_bits_truncate(0o700),
        )
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create QEMU attempt cgroup",
            path: path.clone(),
            source: source.into(),
        })
        .map_err(LinuxQemuCgroupCreateError::without_cleanup)?;

        let mut cleanup = LinuxQemuCgroupCleanupAuthority {
            path: path.clone(),
            parent_directory,
            name,
            directory: None,
        };
        let directory =
            match open_directory_at(&cleanup.parent_directory, &cleanup.name, &cleanup.path) {
                Ok(directory) => directory,
                Err(source) => {
                    return Err(LinuxQemuCgroupCreateError::with_cleanup(source, cleanup));
                }
            };
        cleanup.directory = Some(directory);
        match LinuxQemuCgroup::open_configured(cleanup, limits) {
            Ok(group) => Ok(group),
            Err((source, cleanup)) => {
                Err(LinuxQemuCgroupCreateError::with_cleanup(source, *cleanup))
            }
        }
    }
}

/// One configured, operator-delegated cgroup for a QEMU attempt.
#[derive(Debug)]
#[must_use = "the cgroup authority must be released or transferred to quarantine"]
pub struct LinuxQemuCgroup {
    path: PathBuf,
    parent_directory: OwnedFd,
    name: String,
    limits: LinuxQemuCgroupLimits,
    control: LinuxQemuCgroupControl,
}

impl LinuxQemuCgroup {
    fn open_configured(
        mut cleanup: LinuxQemuCgroupCleanupAuthority,
        limits: LinuxQemuCgroupLimits,
    ) -> Result<Self, (LinuxQemuCgroupError, Box<LinuxQemuCgroupCleanupAuthority>)> {
        if let Err(source) = cleanup.pin_directory() {
            return Err((source, Box::new(cleanup)));
        }
        let path = cleanup.path.clone();
        let configured = (|| {
            let directory = cleanup
                .directory
                .as_ref()
                .ok_or_else(|| LinuxQemuCgroupError::DirectoryIdentity { path: path.clone() })?;
            write_control(directory, &path, "cpu.max", limits.cpu_max()?.as_bytes())?;
            write_control(
                directory,
                &path,
                "memory.max",
                format!("{}\n", limits.maximum_resident_bytes).as_bytes(),
            )?;
            write_control(directory, &path, "memory.swap.max", b"0\n")?;
            write_control(
                directory,
                &path,
                "pids.max",
                format!("{}\n", limits.maximum_tasks).as_bytes(),
            )?;
            let cgroup_events =
                open_control(directory, &path, "cgroup.events", ControlAccess::Read)?;
            let cgroup_kill = open_control(directory, &path, "cgroup.kill", ControlAccess::Write)?;
            let cancellation_event = create_cancellation_eventfd(&path)?;
            let control_parent_directory = duplicate_fd(
                cleanup.parent_directory.as_raw_fd(),
                "retain QEMU cgroup namespace lock for control",
                &path,
            )?;
            Ok((
                cgroup_events,
                cgroup_kill,
                cancellation_event,
                control_parent_directory,
            ))
        })();
        let (cgroup_events, cgroup_kill, cancellation_event, control_parent_directory) =
            match configured {
                Ok(configured) => configured,
                Err(source) => return Err((source, Box::new(cleanup))),
            };
        let directory = match cleanup.directory.take() {
            Some(directory) => directory,
            None => {
                return Err((
                    LinuxQemuCgroupError::DirectoryIdentity {
                        path: cleanup.path.clone(),
                    },
                    Box::new(cleanup),
                ));
            }
        };
        let name = cleanup.name;
        Ok(Self {
            path: cleanup.path.clone(),
            parent_directory: cleanup.parent_directory,
            name: name.clone(),
            limits,
            control: LinuxQemuCgroupControl {
                parent_directory: control_parent_directory,
                name,
                directory,
                cancellation_event,
                cgroup_kill,
                cgroup_events,
                path: cleanup.path,
                watcher_state: Arc::new(AtomicU8::new(WATCHER_NOT_STARTED)),
            },
        })
    }

    /// Returns the configured cgroup path for diagnostics.
    ///
    /// Pinned directory descriptors, not this potentially stale path, remain
    /// authoritative for control-file access and removal.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Duplicates cancellation/kill authority for the supervisor watcher.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError`] when descriptors cannot be duplicated.
    pub fn control(&self) -> Result<LinuxQemuCgroupControl, LinuxQemuCgroupError> {
        self.control.try_clone()
    }

    /// Starts the one persistent cancellation watcher over duplicated authority.
    ///
    /// Child contracts can be minted only while this watcher is running. Its
    /// worker retries ordinary control failures at the fixed 10 ms kill cadence
    /// and parks without re-entry after a caught invariant panic.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError::WatcherAlreadyStarted`] after the one
    /// attempt-owned watcher has been created. Descriptor duplication or worker
    /// startup failures leave the one-shot capability available for retry.
    pub fn start_watcher(&mut self) -> Result<LinuxQemuCgroupWatcher, LinuxQemuCgroupError> {
        LinuxQemuCgroupWatcher::start(self.control()?)
    }

    /// Mints one unforgeable child-side containment contract.
    ///
    /// `maximum_writable_bytes` is both the admitted aggregate writable-byte
    /// ceiling checked against the launch profile and a conservative per-file
    /// `RLIMIT_FSIZE` backstop. The concrete attempt store must still enforce
    /// that aggregate filesystem quota across every writable artifact.
    /// `child_user_id` and `child_group_id` must be non-root and distinct from
    /// every real, effective, saved, or supplementary supervisor identity.
    /// Guarded pre-exec clears supplementary groups and switches all real,
    /// effective, and saved IDs after cgroup attachment.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError`] when the watcher is not running, the
    /// child credentials overlap the supervisor, descriptors cannot be
    /// duplicated, or the sealed contract rejects their provenance.
    pub fn child_process_contract(
        &self,
        maximum_writable_bytes: u64,
        child_user_id: libc::uid_t,
        child_group_id: libc::gid_t,
    ) -> Result<QemuChildProcessContract, LinuxQemuCgroupError> {
        if self.control.watcher_state.load(Ordering::Acquire) != WATCHER_RUNNING {
            return Err(LinuxQemuCgroupError::WatcherNotRunning {
                path: self.path.clone(),
            });
        }
        let cgroup_procs = open_control(
            &self.control.directory,
            &self.path,
            "cgroup.procs",
            ControlAccess::Write,
        )?
        .into();
        let cancellation_event = duplicate_fd(
            self.control.cancellation_event.as_raw_fd(),
            "duplicate QEMU cancellation eventfd",
            &self.path,
        )?;
        let credentials =
            QemuChildCredentials::new(child_user_id, child_group_id).map_err(|source| {
                LinuxQemuCgroupError::Io {
                    operation: "validate QEMU child credentials",
                    path: self.path.clone(),
                    source: io::Error::new(io::ErrorKind::InvalidInput, source),
                }
            })?;
        if self.control.watcher_state.load(Ordering::Acquire) != WATCHER_RUNNING {
            return Err(LinuxQemuCgroupError::WatcherNotRunning {
                path: self.path.clone(),
            });
        }
        QemuChildProcessContract::new(
            cgroup_procs,
            cancellation_event,
            self.limits.maximum_vcpus,
            self.limits.maximum_resident_bytes,
            maximum_writable_bytes,
            credentials,
        )
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation: "seal QEMU child process contract",
            path: self.path.clone(),
            source: io::Error::new(io::ErrorKind::InvalidInput, source),
        })
    }

    /// Proves that `process` is live and is an exact member of this cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError`] when process identity changed or its PID
    /// is absent from the authoritative `cgroup.procs` membership set.
    pub fn verify_process_member(
        &mut self,
        process: &QemuProcessIdentity,
    ) -> Result<(), LinuxQemuCgroupError> {
        if !process_identity_matches(process, &self.path)? {
            return Err(LinuxQemuCgroupError::ProcessMembership {
                path: self.path.clone(),
            });
        }
        let mut cgroup_procs = open_control(
            &self.control.directory,
            &self.path,
            "cgroup.procs",
            ControlAccess::Read,
        )?;
        if !contains_member_pid(
            &mut cgroup_procs,
            &self.path,
            process.process_id,
            self.limits.maximum_tasks,
        )? {
            return Err(LinuxQemuCgroupError::ProcessMembership {
                path: self.path.clone(),
            });
        }
        if !process_identity_matches(process, &self.path)? {
            return Err(LinuxQemuCgroupError::ProcessMembership {
                path: self.path.clone(),
            });
        }
        Ok(())
    }

    /// Authenticates the exact process generation owned by `child` as a member.
    ///
    /// The returned identity binds the direct-child PID, Linux start-time
    /// ticks, and canonical executable. Membership validation brackets its
    /// bounded `cgroup.procs` scan with that same complete identity.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError::ProcessMembership`] when the direct child
    /// no longer has a readable identity or is not an exact member of this
    /// cgroup, and returns [`LinuxQemuCgroupError::Io`] on `/proc` or cgroup
    /// validation failure.
    pub fn authenticate_child(
        &mut self,
        child: &QemuNodeChild,
    ) -> Result<QemuProcessIdentity, LinuxQemuCgroupError> {
        self.authenticate_process_id(child.process_id())
    }

    /// Retains the authenticated direct-child wait handle for reap or quarantine.
    ///
    /// Authentication derives the PID/start-time/executable identity from the
    /// owned child and brackets the bounded membership scan with that identity.
    /// The returned authority must remain co-owned with this cgroup and its
    /// watcher until direct-child reap and cgroup emptiness are both attested.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuDirectChildAuthenticationError`] with the original
    /// child handle when process identity or cgroup membership cannot be
    /// authenticated.
    pub fn retain_child(
        &mut self,
        child: QemuNodeChild,
    ) -> Result<LinuxQemuDirectChild, LinuxQemuDirectChildAuthenticationError> {
        match self.authenticate_child(&child) {
            Ok(identity) => Ok(LinuxQemuDirectChild {
                identity,
                child,
                cgroup_path: self.path.clone(),
                attempt_lifecycle: Arc::clone(&self.control.watcher_state),
            }),
            Err(source) => Err(LinuxQemuDirectChildAuthenticationError {
                source,
                child: Box::new(child),
            }),
        }
    }

    /// Extracts and authenticates the direct child from a failed live node.
    ///
    /// Consuming the node drops its modeled channels and backend capabilities;
    /// only the nonduplicable direct-child wait handle crosses into the cgroup
    /// reap authority.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuDirectChildAuthenticationError`] with the extracted
    /// child when its exact process generation is no longer a member of this
    /// cgroup.
    pub fn retain_failed_node(
        &mut self,
        node: QemuNode,
    ) -> Result<LinuxQemuDirectChild, LinuxQemuDirectChildAuthenticationError> {
        self.retain_child(node.into_direct_child_for_quarantine())
    }

    /// Transfers this group, its watcher, and one retained child to quarantine.
    ///
    /// The detached owner retries direct-child reap, terminal watcher join, and
    /// authenticated cgroup removal without depending on the returned
    /// observation handle. All three inputs must carry the same unforgeable
    /// watcher-lifecycle token.
    ///
    /// # Errors
    ///
    /// Returns [`quarantine::LinuxQemuAttemptProcessQuarantineStartError`] with
    /// every authority retained when the lifecycle basis differs or the worker
    /// cannot start. Ignoring that error leaks the authorities fail-closed.
    pub fn quarantine_process(
        self,
        watcher: LinuxQemuCgroupWatcher,
        child: LinuxQemuDirectChild,
    ) -> Result<
        quarantine::LinuxQemuAttemptProcessQuarantine,
        quarantine::LinuxQemuAttemptProcessQuarantineStartError,
    > {
        quarantine::LinuxQemuAttemptProcessQuarantine::start(self, watcher, child)
    }

    fn owns_child_authority(&self, child: &LinuxQemuDirectChild) -> bool {
        self.path == child.cgroup_path
            && Arc::ptr_eq(&self.control.watcher_state, &child.attempt_lifecycle)
    }

    fn authenticate_process_id(
        &mut self,
        process_id: u32,
    ) -> Result<QemuProcessIdentity, LinuxQemuCgroupError> {
        let process = linux_process_identity(process_id)
            .map_err(|source| LinuxQemuCgroupError::Io {
                operation: "derive QEMU direct-child identity",
                path: self.path.clone(),
                source: io::Error::other(source),
            })?
            .ok_or_else(|| LinuxQemuCgroupError::ProcessMembership {
                path: self.path.clone(),
            })?;
        self.verify_process_member(&process)?;
        Ok(process)
    }

    /// Returns whether this cgroup currently contains a live process.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupError`] when `cgroup.events` cannot be read or
    /// contains a noncanonical `populated` field.
    pub fn is_populated(&mut self) -> Result<bool, LinuxQemuCgroupError> {
        self.control.is_populated()
    }

    /// Removes this cgroup after proving that it is empty.
    ///
    /// The supervisor must first rejoin every watcher or otherwise ensure no
    /// independently cloned control authority will be used after removal.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuCgroupReleaseError`] with the complete authority when
    /// members remain, event validation fails, or removal fails. The caller can
    /// recover the group and continue kill/reap supervision without losing the
    /// cgroup descriptors.
    pub fn remove_if_empty(mut self) -> Result<(), LinuxQemuCgroupReleaseError> {
        if let Err(source) = self.remove_if_empty_in_place() {
            return Err(LinuxQemuCgroupReleaseError {
                group: Box::new(self),
                source,
            });
        }
        Ok(())
    }

    /// Removes the named cgroup while retaining this authority until success.
    ///
    /// The dedicated quarantine state machine uses this borrowed form so an
    /// unwind cannot drop the namespace authority between validation and an
    /// unsuccessful removal. After success the pinned descriptors may be
    /// dropped because the authenticated named directory no longer exists.
    fn remove_if_empty_in_place(&mut self) -> Result<(), LinuxQemuCgroupError> {
        if self.is_populated()? {
            return Err(LinuxQemuCgroupError::InvalidEvents {
                path: self.path.clone(),
                message: String::from("cgroup remained populated at release"),
            });
        }
        self.verify_named_directory()?;
        unlinkat(
            &self.parent_directory,
            self.name.as_str(),
            AtFlags::REMOVEDIR,
        )
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation: "remove empty QEMU attempt cgroup",
            path: self.path.clone(),
            source: source.into(),
        })?;
        Ok(())
    }

    fn verify_named_directory(&self) -> Result<(), LinuxQemuCgroupError> {
        verify_directory_identity(
            &self.parent_directory,
            &self.name,
            &self.control.directory,
            &self.path,
        )
    }
}

fn process_identity_matches(
    expected: &QemuProcessIdentity,
    path: &Path,
) -> Result<bool, LinuxQemuCgroupError> {
    Ok(linux_process_identity(expected.process_id)
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation: "authenticate QEMU process identity",
            path: path.to_owned(),
            source: io::Error::other(source),
        })?
        .as_ref()
        == Some(expected))
}

fn verify_directory_identity(
    parent: &OwnedFd,
    name: &str,
    expected: &OwnedFd,
    path: &Path,
) -> Result<(), LinuxQemuCgroupError> {
    let named = open_directory_at(parent, name, path)?;
    let expected = fstat(expected).map_err(|source| LinuxQemuCgroupError::Io {
        operation: "identify pinned QEMU attempt cgroup",
        path: path.to_owned(),
        source: source.into(),
    })?;
    let actual = fstat(&named).map_err(|source| LinuxQemuCgroupError::Io {
        operation: "identify named QEMU attempt cgroup",
        path: path.to_owned(),
        source: source.into(),
    })?;
    if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
        return Err(LinuxQemuCgroupError::DirectoryIdentity {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn validate_cgroup_name(name: &str) -> Result<(), LinuxQemuCgroupError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(LinuxQemuCgroupError::InvalidName {
            name: name.to_owned(),
        });
    }
    Ok(())
}

fn validate_delegated_controllers(
    directory: &OwnedFd,
    path: &Path,
) -> Result<(), LinuxQemuCgroupError> {
    let controllers = read_words(directory, path, "cgroup.controllers")?;
    let delegated = read_words(directory, path, "cgroup.subtree_control")?;
    for controller in REQUIRED_CONTROLLERS {
        if !controllers.contains(controller) || !delegated.contains(controller) {
            return Err(LinuxQemuCgroupError::MissingController { controller });
        }
    }
    Ok(())
}

fn validate_cgroup_v2(directory: &OwnedFd, path: &Path) -> Result<(), LinuxQemuCgroupError> {
    let filesystem = fstatfs(directory).map_err(|source| LinuxQemuCgroupError::Io {
        operation: "identify delegated cgroup filesystem",
        path: path.to_owned(),
        source: source.into(),
    })?;
    if filesystem.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(LinuxQemuCgroupError::NotCgroupV2 {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn lock_namespace(directory: &OwnedFd, path: &Path) -> Result<(), LinuxQemuCgroupError> {
    flock(directory, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
        if source == rustix::io::Errno::WOULDBLOCK {
            LinuxQemuCgroupError::NamespaceLocked {
                path: path.to_owned(),
            }
        } else {
            LinuxQemuCgroupError::Io {
                operation: "lock delegated cgroup namespace",
                path: path.to_owned(),
                source: source.into(),
            }
        }
    })
}

fn read_words(
    directory: &OwnedFd,
    root: &Path,
    file_name: &'static str,
) -> Result<BTreeSet<String>, LinuxQemuCgroupError> {
    let path = root.join(file_name);
    let mut file = open_control(directory, root, file_name, ControlAccess::Read)?;
    let text = read_control(
        &mut file,
        &path,
        "read delegated cgroup controllers",
        MAX_CGROUP_CONTROL_BYTES,
    )?;
    Ok(text.split_ascii_whitespace().map(str::to_owned).collect())
}

fn write_control(
    directory: &OwnedFd,
    root: &Path,
    file_name: &'static str,
    value: &[u8],
) -> Result<(), LinuxQemuCgroupError> {
    let path = root.join(file_name);
    let mut file = open_control(directory, root, file_name, ControlAccess::Write)?;
    file.write_all(value)
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation: "write QEMU cgroup limit",
            path: path.clone(),
            source,
        })?;
    drop(file);

    let mut file = open_control(directory, root, file_name, ControlAccess::Read)?;
    let actual = read_control(
        &mut file,
        &path,
        "verify QEMU cgroup limit",
        MAX_CGROUP_CONTROL_BYTES,
    )?;
    let expected = String::from_utf8_lossy(value).trim_ascii_end().to_owned();
    let actual = actual.trim_ascii_end().to_owned();
    if actual != expected {
        return Err(LinuxQemuCgroupError::ControlValue {
            path,
            expected,
            actual,
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ControlAccess {
    Read,
    Write,
}

fn open_control(
    directory: &OwnedFd,
    root: &Path,
    file_name: &'static str,
    access: ControlAccess,
) -> Result<File, LinuxQemuCgroupError> {
    let path = root.join(file_name);
    let flags = OFlags::CLOEXEC
        | OFlags::NOFOLLOW
        | match access {
            ControlAccess::Read => OFlags::RDONLY,
            ControlAccess::Write => OFlags::WRONLY,
        };
    openat(directory, file_name, flags, Mode::empty())
        .map(File::from)
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation: "open QEMU cgroup control",
            path,
            source: source.into(),
        })
}

fn open_directory(path: &Path, operation: &'static str) -> Result<OwnedFd, LinuxQemuCgroupError> {
    open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| LinuxQemuCgroupError::Io {
        operation,
        path: path.to_owned(),
        source: source.into(),
    })
}

fn open_directory_at(
    parent: &OwnedFd,
    name: &str,
    path: &Path,
) -> Result<OwnedFd, LinuxQemuCgroupError> {
    openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| LinuxQemuCgroupError::Io {
        operation: "pin QEMU attempt cgroup directory",
        path: path.to_owned(),
        source: source.into(),
    })
}

fn create_cancellation_eventfd(path: &Path) -> Result<OwnedFd, LinuxQemuCgroupError> {
    let descriptor = unsafe {
        // SAFETY: eventfd has no pointer arguments and returns one new fd.
        libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK)
    };
    if descriptor < 0 {
        return Err(LinuxQemuCgroupError::Io {
            operation: "create QEMU cancellation eventfd",
            path: path.to_owned(),
            source: io::Error::last_os_error(),
        });
    }
    Ok(unsafe {
        // SAFETY: successful eventfd returned a uniquely owned descriptor.
        OwnedFd::from_raw_fd(descriptor)
    })
}

fn duplicate_fd(
    descriptor: i32,
    operation: &'static str,
    path: &Path,
) -> Result<OwnedFd, LinuxQemuCgroupError> {
    let duplicated = unsafe {
        // SAFETY: fcntl reads a live fd and returns a fresh descriptor.
        libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 0)
    };
    if duplicated < 0 {
        return Err(LinuxQemuCgroupError::Io {
            operation,
            path: path.to_owned(),
            source: io::Error::last_os_error(),
        });
    }
    Ok(unsafe {
        // SAFETY: successful F_DUPFD_CLOEXEC returned unique ownership.
        OwnedFd::from_raw_fd(duplicated)
    })
}

fn write_kill(file: &mut File, path: &Path) -> Result<(), LinuxQemuCgroupError> {
    file.rewind().map_err(|source| LinuxQemuCgroupError::Io {
        operation: "rewind cgroup.kill",
        path: path.to_owned(),
        source,
    })?;
    file.write_all(b"1\n")
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation: "kill QEMU cgroup members",
            path: path.to_owned(),
            source,
        })
}

fn write_eventfd(descriptor: i32, value: u64) -> io::Result<()> {
    loop {
        let written = unsafe {
            // SAFETY: `value` is a valid u64 input buffer for eventfd.
            libc::write(
                descriptor,
                (&value as *const u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if written == 8 {
            return Ok(());
        }
        if written >= 0 {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if source.kind() == io::ErrorKind::WouldBlock {
            // A saturated nonblocking eventfd is already readable, which is
            // the sticky wake postcondition required by pre-exec polling.
            return Ok(());
        }
        return Err(source);
    }
}

fn signal_terminal(watcher_state: &AtomicU8, cancellation_event: RawFd) -> io::Result<()> {
    signal_terminal_with(watcher_state, || write_eventfd(cancellation_event, 1))
}

fn signal_terminal_with(
    watcher_state: &AtomicU8,
    wake: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let result = wake();
    // A successful sticky wake precedes publication so an already-minted
    // child cannot observe a terminal transition without a readable event.
    // Failure still closes all future minting before control returns.
    watcher_state.store(WATCHER_TERMINAL, Ordering::Release);
    result
}

fn contains_member_pid(
    file: &mut File,
    path: &Path,
    target: u32,
    maximum_tasks: u32,
) -> Result<bool, LinuxQemuCgroupError> {
    file.rewind().map_err(|source| LinuxQemuCgroupError::Io {
        operation: "rewind QEMU cgroup membership",
        path: path.to_owned(),
        source,
    })?;
    let reader = BufReader::with_capacity(4096, file);
    let mut found = false;
    let mut tasks = 0_u32;
    let mut process_id = 0_u32;
    let mut digits = 0_u8;
    for byte in reader.bytes() {
        let byte = byte.map_err(|source| LinuxQemuCgroupError::Io {
            operation: "read QEMU cgroup membership",
            path: path.to_owned(),
            source,
        })?;
        if byte == b'\n' {
            if digits == 0 {
                return Err(LinuxQemuCgroupError::InvalidEvents {
                    path: path.to_owned(),
                    message: String::from("cgroup.procs contained an empty PID"),
                });
            }
            tasks = tasks
                .checked_add(1)
                .ok_or(LinuxQemuCgroupError::InvalidLimit)?;
            if tasks > maximum_tasks {
                return Err(LinuxQemuCgroupError::InvalidEvents {
                    path: path.to_owned(),
                    message: format!("cgroup.procs exceeded the {maximum_tasks}-task ceiling"),
                });
            }
            found |= process_id == target;
            process_id = 0;
            digits = 0;
            continue;
        }
        if !byte.is_ascii_digit() || digits == 10 {
            return Err(LinuxQemuCgroupError::InvalidEvents {
                path: path.to_owned(),
                message: String::from("cgroup.procs contained a noncanonical PID"),
            });
        }
        process_id = process_id
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
            .ok_or_else(|| LinuxQemuCgroupError::InvalidEvents {
                path: path.to_owned(),
                message: String::from("cgroup.procs PID exceeded u32"),
            })?;
        digits += 1;
    }
    if digits != 0 {
        return Err(LinuxQemuCgroupError::InvalidEvents {
            path: path.to_owned(),
            message: String::from("cgroup.procs contained an unterminated PID"),
        });
    }
    Ok(found)
}

fn read_populated(file: &mut File, path: &Path) -> Result<bool, LinuxQemuCgroupError> {
    let text = read_control(
        file,
        path,
        "read QEMU cgroup events",
        MAX_CGROUP_CONTROL_BYTES,
    )?;
    let mut populated = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            return Err(LinuxQemuCgroupError::InvalidEvents {
                path: path.to_owned(),
                message: format!("malformed cgroup.events line `{line}`"),
            });
        };
        if key == "populated" {
            if populated.is_some() {
                return Err(LinuxQemuCgroupError::InvalidEvents {
                    path: path.to_owned(),
                    message: String::from("duplicate populated field"),
                });
            }
            populated = match value {
                "0" => Some(false),
                "1" => Some(true),
                _ => {
                    return Err(LinuxQemuCgroupError::InvalidEvents {
                        path: path.to_owned(),
                        message: format!("invalid populated value `{value}`"),
                    });
                }
            };
        }
    }
    populated.ok_or_else(|| LinuxQemuCgroupError::InvalidEvents {
        path: path.to_owned(),
        message: String::from("missing populated field"),
    })
}

fn read_control(
    file: &mut File,
    path: &Path,
    operation: &'static str,
    maximum_bytes: u64,
) -> Result<String, LinuxQemuCgroupError> {
    file.rewind().map_err(|source| LinuxQemuCgroupError::Io {
        operation,
        path: path.to_owned(),
        source,
    })?;
    let mut text = String::new();
    file.take(maximum_bytes + 1)
        .read_to_string(&mut text)
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation,
            path: path.to_owned(),
            source,
        })?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > maximum_bytes {
        return Err(LinuxQemuCgroupError::InvalidEvents {
            path: path.to_owned(),
            message: format!("control exceeded the {maximum_bytes}-byte ceiling"),
        });
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;

    fn pipe_pair() -> io::Result<(OwnedFd, OwnedFd)> {
        let mut descriptors = [-1_i32; 2];
        let result = unsafe {
            // SAFETY: `descriptors` provides storage for exactly two fds.
            libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK)
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe {
            // SAFETY: successful pipe2 returned two distinct owned fds.
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        })
    }

    fn eventfd_value(descriptor: i32) -> io::Result<u64> {
        let mut value = 0_u64;
        let read = unsafe {
            // SAFETY: `value` is a valid writable u64 buffer for eventfd.
            libc::read(
                descriptor,
                (&mut value as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if read == 8 {
            Ok(value)
        } else if read < 0 {
            Err(io::Error::last_os_error())
        } else {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }

    fn watcher_control_fixture(
        path: &Path,
        populated: bool,
    ) -> Result<(LinuxQemuCgroupControl, OwnedFd), LinuxQemuCgroupError> {
        let kill_path = path.join("cgroup.kill");
        let events_path = path.join("cgroup.events");
        fs::write(&kill_path, b"xx").map_err(|source| LinuxQemuCgroupError::Io {
            operation: "write watcher kill fixture",
            path: kill_path,
            source,
        })?;
        fs::write(
            &events_path,
            if populated {
                b"populated 1\n".as_slice()
            } else {
                b"populated 0\n".as_slice()
            },
        )
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation: "write watcher events fixture",
            path: events_path,
            source,
        })?;
        let cancellation_event = create_cancellation_eventfd(path)?;
        let cancellation_reader = duplicate_fd(
            cancellation_event.as_raw_fd(),
            "duplicate watcher cancellation fixture",
            path,
        )?;
        let directory = open_directory(path, "open watcher cgroup fixture")?;
        let parent_directory = duplicate_fd(
            directory.as_raw_fd(),
            "retain watcher fixture namespace lock",
            path,
        )?;
        let cgroup_kill = open_control(&directory, path, "cgroup.kill", ControlAccess::Write)?;
        let cgroup_events = open_control(&directory, path, "cgroup.events", ControlAccess::Read)?;
        Ok((
            LinuxQemuCgroupControl {
                parent_directory,
                name: String::from("watcher-fixture"),
                directory,
                cancellation_event,
                cgroup_kill,
                cgroup_events,
                path: path.to_owned(),
                watcher_state: Arc::new(AtomicU8::new(WATCHER_NOT_STARTED)),
            },
            cancellation_reader,
        ))
    }

    #[test]
    fn cgroup_limits_render_exact_cpu_quota() -> Result<(), LinuxQemuCgroupError> {
        let limits = LinuxQemuCgroupLimits::new(4, 512 * 1024 * 1024, 16)?;
        assert_eq!(limits.cpu_max()?, "400000 100000\n");
        assert_eq!(limits.maximum_vcpus(), 4);
        assert_eq!(limits.maximum_resident_bytes(), 512 * 1024 * 1024);
        assert_eq!(limits.maximum_tasks(), 16);
        assert!(LinuxQemuCgroupLimits::new(0, 1, 1).is_err());
        assert!(LinuxQemuCgroupLimits::new(1, 0, 1).is_err());
        assert!(LinuxQemuCgroupLimits::new(1, 1, 0).is_err());
        assert!(LinuxQemuCgroupLimits::new(1, 1, MAX_LINUX_QEMU_CGROUP_TASKS + 1).is_err());
        Ok(())
    }

    #[test]
    fn namespace_lock_is_exclusive_across_open_descriptions() -> Result<(), LinuxQemuCgroupError> {
        let directory = tempfile::tempdir().map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create namespace-lock fixture",
            path: PathBuf::from("fixture"),
            source,
        })?;
        let first = open_directory(directory.path(), "open first namespace-lock fixture")?;
        let second = open_directory(directory.path(), "open second namespace-lock fixture")?;
        lock_namespace(&first, directory.path())?;
        assert!(matches!(
            lock_namespace(&second, directory.path()),
            Err(LinuxQemuCgroupError::NamespaceLocked { .. })
        ));
        Ok(())
    }

    #[test]
    fn failed_setup_retains_child_and_namespace_authority() -> Result<(), LinuxQemuCgroupError> {
        let directory = tempfile::tempdir().map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create setup-cleanup fixture",
            path: PathBuf::from("fixture"),
            source,
        })?;
        let root_directory = open_directory(directory.path(), "open setup-cleanup fixture")?;
        lock_namespace(&root_directory, directory.path())?;
        let mut root = LinuxQemuCgroupRoot {
            path: directory.path().to_owned(),
            directory: root_directory,
        };
        let limits = LinuxQemuCgroupLimits::new(1, 4096, 16)?;

        let error = match root.create("attempt", limits) {
            Ok(_) => panic!("regular directory unexpectedly exposed cgroup controls"),
            Err(error) => error,
        };
        let cleanup = match error.into_cleanup_authority() {
            Some(cleanup) => cleanup,
            None => panic!("created child did not retain cleanup authority"),
        };
        drop(root);
        let contender = open_directory(directory.path(), "open setup-cleanup contender")?;
        assert!(matches!(
            lock_namespace(&contender, directory.path()),
            Err(LinuxQemuCgroupError::NamespaceLocked { .. })
        ));
        drop(cleanup);
        lock_namespace(&contender, directory.path())?;
        assert!(directory.path().join("attempt").is_dir());
        Ok(())
    }

    #[test]
    fn control_writes_are_read_back_exactly() -> Result<(), LinuxQemuCgroupError> {
        let directory = tempfile::tempdir().map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create control-write fixture",
            path: PathBuf::from("fixture"),
            source,
        })?;
        fs::write(directory.path().join("cpu.max"), b"0\n").map_err(|source| {
            LinuxQemuCgroupError::Io {
                operation: "write initial control fixture",
                path: directory.path().to_owned(),
                source,
            }
        })?;
        let descriptor = open_directory(directory.path(), "open control-write fixture")?;
        write_control(&descriptor, directory.path(), "cpu.max", b"1\n")?;
        assert_eq!(
            fs::read(directory.path().join("cpu.max")).map_err(|source| {
                LinuxQemuCgroupError::Io {
                    operation: "read control-write fixture",
                    path: directory.path().to_owned(),
                    source,
                }
            })?,
            b"1\n"
        );
        Ok(())
    }

    #[test]
    fn cgroup_names_are_single_stable_components() {
        for rejected in ["", ".", "..", "a/b", "a.b", "a b"] {
            assert!(validate_cgroup_name(rejected).is_err());
        }
        assert!(validate_cgroup_name("attempt_42-epoch_7").is_ok());
    }

    #[test]
    fn non_cgroup_delegation_fails_before_child_creation() -> Result<(), LinuxQemuCgroupError> {
        let directory = tempfile::tempdir().map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create delegated-cgroup fixture",
            path: PathBuf::from("fixture"),
            source,
        })?;
        fs::write(directory.path().join("cgroup.controllers"), b"cpu memory\n").map_err(
            |source| LinuxQemuCgroupError::Io {
                operation: "write controller fixture",
                path: directory.path().to_owned(),
                source,
            },
        )?;
        fs::write(
            directory.path().join("cgroup.subtree_control"),
            b"cpu memory\n",
        )
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation: "write delegation fixture",
            path: directory.path().to_owned(),
            source,
        })?;

        assert!(matches!(
            LinuxQemuCgroupRoot::acquire(directory.path()),
            Err(LinuxQemuCgroupError::NotCgroupV2 { .. })
        ));
        assert!(!directory.path().join("attempt").exists());

        let descriptor = open_directory(directory.path(), "open delegation fixture")?;
        assert!(matches!(
            validate_delegated_controllers(&descriptor, directory.path()),
            Err(LinuxQemuCgroupError::MissingController { controller: "pids" })
        ));
        Ok(())
    }

    #[test]
    fn cancellation_is_sticky_across_control_clones() -> Result<(), LinuxQemuCgroupError> {
        let directory = tempfile::tempdir().map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create cgroup-control fixture",
            path: PathBuf::from("fixture"),
            source,
        })?;
        let kill_path = directory.path().join("cgroup.kill");
        let events_path = directory.path().join("cgroup.events");
        fs::write(&kill_path, b"xx").map_err(|source| LinuxQemuCgroupError::Io {
            operation: "write kill fixture",
            path: kill_path.clone(),
            source,
        })?;
        fs::write(&events_path, b"populated 0\n").map_err(|source| LinuxQemuCgroupError::Io {
            operation: "write events fixture",
            path: events_path.clone(),
            source,
        })?;
        let cancellation_event = create_cancellation_eventfd(directory.path())?;
        let cancellation_reader = duplicate_fd(
            cancellation_event.as_raw_fd(),
            "duplicate cancellation fixture",
            directory.path(),
        )?;
        let cgroup_directory = open_directory(directory.path(), "open cgroup-control fixture")?;
        let cgroup_kill = open_control(
            &cgroup_directory,
            directory.path(),
            "cgroup.kill",
            ControlAccess::Write,
        )?;
        let cgroup_events = open_control(
            &cgroup_directory,
            directory.path(),
            "cgroup.events",
            ControlAccess::Read,
        )?;
        let mut control = LinuxQemuCgroupControl {
            parent_directory: duplicate_fd(
                cgroup_directory.as_raw_fd(),
                "retain control fixture namespace lock",
                directory.path(),
            )?,
            name: String::from("control-fixture"),
            directory: cgroup_directory,
            cancellation_event,
            cgroup_kill,
            cgroup_events,
            path: directory.path().to_owned(),
            watcher_state: Arc::new(AtomicU8::new(WATCHER_NOT_STARTED)),
        };
        let mut clone = control.try_clone()?;

        control.signal_cancellation()?;
        clone.signal_cancellation()?;
        assert_eq!(
            eventfd_value(cancellation_reader.as_raw_fd()).map_err(|source| {
                LinuxQemuCgroupError::Io {
                    operation: "read cancellation fixture",
                    path: directory.path().to_owned(),
                    source,
                }
            })?,
            2
        );
        assert!(!clone.is_populated()?);
        control.kill_members()?;
        control.kill_members()?;
        assert_eq!(
            fs::read(&kill_path).map_err(|source| LinuxQemuCgroupError::Io {
                operation: "read kill fixture",
                path: kill_path,
                source,
            })?,
            b"1\n"
        );
        Ok(())
    }

    #[test]
    fn failed_cancellation_signal_still_latches_terminal_state() -> Result<(), LinuxQemuCgroupError>
    {
        let directory = tempfile::tempdir().map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create failed-signal fixture",
            path: PathBuf::from("fixture"),
            source,
        })?;
        let kill_path = directory.path().join("cgroup.kill");
        let events_path = directory.path().join("cgroup.events");
        fs::write(&kill_path, b"xx").map_err(|source| LinuxQemuCgroupError::Io {
            operation: "write failed-signal kill fixture",
            path: kill_path,
            source,
        })?;
        fs::write(&events_path, b"populated 0\n").map_err(|source| LinuxQemuCgroupError::Io {
            operation: "write failed-signal events fixture",
            path: events_path,
            source,
        })?;
        let (read_end, _write_end) = pipe_pair().map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create failed-signal pipe",
            path: directory.path().to_owned(),
            source,
        })?;
        let watcher_state = Arc::new(AtomicU8::new(WATCHER_RUNNING));
        let cgroup_directory = open_directory(directory.path(), "open failed-signal fixture")?;
        let cgroup_kill = open_control(
            &cgroup_directory,
            directory.path(),
            "cgroup.kill",
            ControlAccess::Write,
        )?;
        let cgroup_events = open_control(
            &cgroup_directory,
            directory.path(),
            "cgroup.events",
            ControlAccess::Read,
        )?;
        let mut control = LinuxQemuCgroupControl {
            parent_directory: duplicate_fd(
                cgroup_directory.as_raw_fd(),
                "retain failed-signal fixture namespace lock",
                directory.path(),
            )?,
            name: String::from("failed-signal-fixture"),
            directory: cgroup_directory,
            cancellation_event: read_end,
            cgroup_kill,
            cgroup_events,
            path: directory.path().to_owned(),
            watcher_state: Arc::clone(&watcher_state),
        };

        assert!(control.signal_cancellation().is_err());
        assert_eq!(watcher_state.load(Ordering::Acquire), WATCHER_TERMINAL);
        Ok(())
    }

    #[test]
    fn terminal_signal_orders_sticky_wake_before_successful_publication() {
        let successful_state = AtomicU8::new(WATCHER_RUNNING);
        let result = signal_terminal_with(&successful_state, || {
            assert_eq!(successful_state.load(Ordering::Acquire), WATCHER_RUNNING);
            Ok(())
        });
        assert!(result.is_ok());
        assert_eq!(successful_state.load(Ordering::Acquire), WATCHER_TERMINAL);

        let failed_state = AtomicU8::new(WATCHER_RUNNING);
        let result = signal_terminal_with(&failed_state, || {
            assert_eq!(failed_state.load(Ordering::Acquire), WATCHER_RUNNING);
            Err(io::Error::from_raw_os_error(libc::EBADF))
        });
        assert!(result.is_err());
        assert_eq!(failed_state.load(Ordering::Acquire), WATCHER_TERMINAL);
    }

    #[test]
    fn watcher_panic_is_classified_once_for_terminal_quarantine() {
        let calls = std::cell::Cell::new(0_u8);
        let outcome = run_cgroup_watcher_attempt(|| {
            calls.set(calls.get() + 1);
            panic!("forced watcher panic");
        });

        assert_eq!(outcome, LinuxQemuCgroupWatcherAttempt::Panicked);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn cancellation_watcher_kills_until_the_cgroup_is_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let (control, _cancellation_reader) = watcher_control_fixture(directory.path(), false)?;
        let watcher_state = Arc::clone(&control.watcher_state);
        let watcher = LinuxQemuCgroupWatcher::start(control)?;

        assert_eq!(
            watcher.cancel_and_wait(Duration::from_secs(1))?,
            LinuxQemuCgroupWatcherOutcome::ClosedAndEmpty
        );
        assert_eq!(watcher_state.load(Ordering::Acquire), WATCHER_TERMINAL);
        assert_eq!(fs::read(directory.path().join("cgroup.kill"))?, b"1\n");
        Ok(())
    }

    #[test]
    fn watcher_start_is_one_shot_and_required_for_child_minting()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let (control, _cancellation_reader) = watcher_control_fixture(directory.path(), false)?;
        let mut group = LinuxQemuCgroup {
            path: directory.path().to_owned(),
            parent_directory: open_directory(directory.path(), "open watcher parent fixture")?,
            name: String::from("watcher-fixture"),
            limits: LinuxQemuCgroupLimits::new(1, 4096, 1)?,
            control,
        };

        assert!(matches!(
            group.child_process_contract(4096, 65_533, 65_532),
            Err(LinuxQemuCgroupError::WatcherNotRunning { .. })
        ));
        let watcher = group.start_watcher()?;
        assert!(matches!(
            group.start_watcher(),
            Err(LinuxQemuCgroupError::WatcherAlreadyStarted { .. })
        ));
        assert_eq!(
            watcher.finish_and_wait(Duration::from_secs(1))?,
            LinuxQemuCgroupWatcherOutcome::ClosedAndEmpty
        );
        Ok(())
    }

    #[test]
    fn watcher_signal_failure_still_latches_terminal_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let (control, cancellation_event) = watcher_control_fixture(directory.path(), false)?;
        let watcher_state = Arc::clone(&control.watcher_state);
        let mut watcher = LinuxQemuCgroupWatcher::start(control)?;
        let (invalid_writer, _write_end) = pipe_pair()?;
        watcher.cancellation_event = invalid_writer;

        let error = match watcher.finish_and_wait(Duration::from_secs(1)) {
            Ok(_) => panic!("invalid watcher signal unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(watcher_state.load(Ordering::Acquire), WATCHER_TERMINAL);
        let watcher = match error.into_watcher() {
            Some(watcher) => watcher,
            None => panic!("signal failure did not retain the watcher"),
        };

        write_eventfd(cancellation_event.as_raw_fd(), 1)?;
        assert_eq!(
            watcher.wait(Duration::from_secs(1))?,
            LinuxQemuCgroupWatcherOutcome::ClosedAndEmpty
        );
        Ok(())
    }

    #[test]
    fn terminal_closure_rejects_new_child_contracts() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let (control, _cancellation_reader) = watcher_control_fixture(directory.path(), false)?;
        control
            .watcher_state
            .store(WATCHER_TERMINAL, Ordering::Release);
        let group = LinuxQemuCgroup {
            path: directory.path().to_owned(),
            parent_directory: open_directory(directory.path(), "open closed parent fixture")?,
            name: String::from("closed"),
            limits: LinuxQemuCgroupLimits::new(1, 4096, 1)?,
            control,
        };

        assert!(matches!(
            group.child_process_contract(4096, 65_533, 65_532),
            Err(LinuxQemuCgroupError::WatcherNotRunning { .. })
        ));
        Ok(())
    }

    #[test]
    fn watcher_timeout_retains_the_live_owner_for_retry() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let (control, _cancellation_reader) = watcher_control_fixture(directory.path(), true)?;
        let watcher = LinuxQemuCgroupWatcher::start(control)?;
        let error = match watcher.cancel_and_wait(Duration::from_millis(20)) {
            Ok(_) => panic!("populated watcher unexpectedly terminated"),
            Err(error) => error,
        };
        let watcher = match error.into_watcher() {
            Some(watcher) => watcher,
            None => panic!("watcher timeout dropped its live owner"),
        };

        fs::write(directory.path().join("cgroup.events"), b"populated 0\n")?;
        assert_eq!(
            watcher.wait(Duration::from_secs(1))?,
            LinuxQemuCgroupWatcherOutcome::ClosedAndEmpty
        );
        Ok(())
    }

    #[test]
    fn ordinary_finish_closes_child_minting_and_drop_cancels_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let stopped_directory = tempfile::tempdir()?;
        let (control, _cancellation_reader) =
            watcher_control_fixture(stopped_directory.path(), false)?;
        let finish_state = Arc::clone(&control.watcher_state);
        let watcher = LinuxQemuCgroupWatcher::start(control)?;
        assert_eq!(
            watcher.finish_and_wait(Duration::from_secs(1))?,
            LinuxQemuCgroupWatcherOutcome::ClosedAndEmpty
        );
        assert_eq!(finish_state.load(Ordering::Acquire), WATCHER_TERMINAL);
        assert_eq!(
            fs::read(stopped_directory.path().join("cgroup.kill"))?,
            b"1\n"
        );

        let dropped_directory = tempfile::tempdir()?;
        let (control, _cancellation_reader) =
            watcher_control_fixture(dropped_directory.path(), false)?;
        let drop_state = Arc::clone(&control.watcher_state);
        let watcher = LinuxQemuCgroupWatcher::start(control)?;
        drop(watcher);
        assert_eq!(drop_state.load(Ordering::Acquire), WATCHER_TERMINAL);
        Ok(())
    }

    #[test]
    fn release_retains_authority_and_rejects_path_replacement() -> Result<(), LinuxQemuCgroupError>
    {
        let directory = tempfile::tempdir().map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create retained-authority fixture",
            path: PathBuf::from("fixture"),
            source,
        })?;
        let cgroup_path = directory.path().join("attempt");
        fs::create_dir(&cgroup_path).map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create retained-authority cgroup",
            path: cgroup_path.clone(),
            source,
        })?;
        for (name, value) in [
            ("cgroup.procs", b"123\n".as_slice()),
            ("cgroup.events", b"populated 1\n".as_slice()),
            ("cgroup.kill", b"xx".as_slice()),
        ] {
            fs::write(cgroup_path.join(name), value).map_err(|source| {
                LinuxQemuCgroupError::Io {
                    operation: "write retained-authority fixture",
                    path: cgroup_path.join(name),
                    source,
                }
            })?;
        }
        let parent_directory = open_directory(directory.path(), "open retained-authority root")?;
        let child_directory = open_directory_at(&parent_directory, "attempt", &cgroup_path)?;
        let cgroup_kill = open_control(
            &child_directory,
            &cgroup_path,
            "cgroup.kill",
            ControlAccess::Write,
        )?;
        let cgroup_events = open_control(
            &child_directory,
            &cgroup_path,
            "cgroup.events",
            ControlAccess::Read,
        )?;
        let group = LinuxQemuCgroup {
            path: cgroup_path.clone(),
            parent_directory: duplicate_fd(
                parent_directory.as_raw_fd(),
                "retain release fixture namespace lock",
                &cgroup_path,
            )?,
            name: String::from("attempt"),
            limits: LinuxQemuCgroupLimits::new(1, 4096, 16)?,
            control: LinuxQemuCgroupControl {
                parent_directory,
                name: String::from("attempt"),
                directory: child_directory,
                cancellation_event: create_cancellation_eventfd(&cgroup_path)?,
                cgroup_kill,
                cgroup_events,
                path: cgroup_path.clone(),
                watcher_state: Arc::new(AtomicU8::new(WATCHER_NOT_STARTED)),
            },
        };

        let error = match group.remove_if_empty() {
            Ok(()) => panic!("populated cgroup was removed"),
            Err(error) => error,
        };
        assert!(matches!(
            error.source_error(),
            LinuxQemuCgroupError::InvalidEvents { .. }
        ));
        let mut group = error.into_group();
        group.control.kill_members()?;
        assert_eq!(
            fs::read(cgroup_path.join("cgroup.kill")).map_err(|source| {
                LinuxQemuCgroupError::Io {
                    operation: "read retained-authority kill fixture",
                    path: cgroup_path.clone(),
                    source,
                }
            })?,
            b"1\n"
        );

        fs::write(cgroup_path.join("cgroup.events"), b"populated 0\n").map_err(|source| {
            LinuxQemuCgroupError::Io {
                operation: "clear retained-authority fixture",
                path: cgroup_path.clone(),
                source,
            }
        })?;
        let moved_path = directory.path().join("moved-attempt");
        fs::rename(&cgroup_path, &moved_path).map_err(|source| LinuxQemuCgroupError::Io {
            operation: "rename retained-authority fixture",
            path: cgroup_path.clone(),
            source,
        })?;
        fs::create_dir(&cgroup_path).map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create replacement cgroup fixture",
            path: cgroup_path.clone(),
            source,
        })?;
        let mut cloned_control = group.control()?;
        assert!(!cloned_control.is_populated()?);

        let error = match group.remove_if_empty() {
            Ok(()) => panic!("replacement cgroup path was removed"),
            Err(error) => error,
        };
        assert!(matches!(
            error.source_error(),
            LinuxQemuCgroupError::DirectoryIdentity { .. }
        ));
        assert!(cgroup_path.exists());
        assert!(moved_path.exists());
        Ok(())
    }

    #[test]
    fn populated_parser_is_strict_and_complete() -> Result<(), LinuxQemuCgroupError> {
        let directory = tempfile::tempdir().map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create cgroup parser fixture",
            path: PathBuf::from("fixture"),
            source,
        })?;
        let path = directory.path().join("events");
        fs::write(&path, b"populated 1\nfrozen 0\n").map_err(|source| {
            LinuxQemuCgroupError::Io {
                operation: "write cgroup parser fixture",
                path: path.clone(),
                source,
            }
        })?;
        let mut file = File::open(&path).map_err(|source| LinuxQemuCgroupError::Io {
            operation: "open cgroup parser fixture",
            path: path.clone(),
            source,
        })?;
        assert!(read_populated(&mut file, &path)?);
        fs::write(&path, b"frozen 0\n").map_err(|source| LinuxQemuCgroupError::Io {
            operation: "rewrite cgroup parser fixture",
            path: path.clone(),
            source,
        })?;
        assert!(read_populated(&mut file, &path).is_err());
        fs::write(&path, b"populated 0\npopulated 1\n").map_err(|source| {
            LinuxQemuCgroupError::Io {
                operation: "write duplicate cgroup parser fixture",
                path: path.clone(),
                source,
            }
        })?;
        assert!(read_populated(&mut file, &path).is_err());
        Ok(())
    }

    #[test]
    fn membership_scan_is_chunk_independent_and_task_bounded() -> Result<(), LinuxQemuCgroupError> {
        let directory = tempfile::tempdir().map_err(|source| LinuxQemuCgroupError::Io {
            operation: "create membership fixture",
            path: PathBuf::from("fixture"),
            source,
        })?;
        let path = directory.path().join("cgroup.procs");
        let mut contents = String::new();
        for process_id in 1..=1500_u32 {
            contents.push_str(&format!("{process_id}\n"));
        }
        fs::write(&path, contents).map_err(|source| LinuxQemuCgroupError::Io {
            operation: "write membership fixture",
            path: path.clone(),
            source,
        })?;
        let mut file = File::open(&path).map_err(|source| LinuxQemuCgroupError::Io {
            operation: "open membership fixture",
            path: path.clone(),
            source,
        })?;
        assert!(contains_member_pid(&mut file, &path, 1499, 1500)?);
        assert!(contains_member_pid(&mut file, &path, 1501, 1499).is_err());
        Ok(())
    }

    #[test]
    fn direct_child_identity_is_authenticated_across_membership_scan()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let process_id = std::process::id();
        fs::write(
            directory.path().join("cgroup.procs"),
            format!("{process_id}\n"),
        )?;
        let (control, _cancellation_reader) = watcher_control_fixture(directory.path(), true)?;
        let mut group = LinuxQemuCgroup {
            path: directory.path().to_owned(),
            parent_directory: open_directory(
                directory.path(),
                "open direct-child identity parent fixture",
            )?,
            name: String::from("direct-child-identity"),
            limits: LinuxQemuCgroupLimits::new(1, 4096, 1)?,
            control,
        };

        let expected = linux_process_identity(process_id)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "test process disappeared"))?;
        assert_eq!(group.authenticate_process_id(process_id)?, expected);

        let other_process_id = if process_id == 1 { 2 } else { 1 };
        fs::write(
            directory.path().join("cgroup.procs"),
            format!("{other_process_id}\n"),
        )?;
        assert!(matches!(
            group.authenticate_process_id(process_id),
            Err(LinuxQemuCgroupError::ProcessMembership { .. })
        ));
        Ok(())
    }

    #[test]
    fn direct_child_wait_authority_survives_handoff_until_reap()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let child = QemuNodeChild::new(Command::new("sleep").arg("60").spawn()?);
        let process_id = child.process_id();
        fs::write(
            directory.path().join("cgroup.procs"),
            format!("{process_id}\n"),
        )?;
        let (control, _cancellation_reader) = watcher_control_fixture(directory.path(), true)?;
        let mut group = LinuxQemuCgroup {
            path: directory.path().to_owned(),
            parent_directory: open_directory(
                directory.path(),
                "open direct-child handoff parent fixture",
            )?,
            name: String::from("direct-child-handoff"),
            limits: LinuxQemuCgroupLimits::new(1, 4096, 1)?,
            control,
        };

        let mut retained = group
            .retain_child(child)
            .map_err(|error| io::Error::other(error.to_string()))?;
        assert_eq!(retained.identity().process_id, process_id);
        assert!(!retained.is_reaped());

        retained.kill_and_reap_blocking()?;
        assert!(retained.is_reaped());
        assert!(linux_process_identity(process_id)?.is_none());
        Ok(())
    }

    #[test]
    fn direct_child_authority_rejects_same_path_cgroup_reincarnation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let child = QemuNodeChild::new(Command::new("sleep").arg("60").spawn()?);
        let process_id = child.process_id();
        fs::write(
            directory.path().join("cgroup.procs"),
            format!("{process_id}\n"),
        )?;
        let (first_control, _first_reader) = watcher_control_fixture(directory.path(), true)?;
        let mut first = LinuxQemuCgroup {
            path: directory.path().to_owned(),
            parent_directory: open_directory(
                directory.path(),
                "open first lifecycle parent fixture",
            )?,
            name: String::from("same-path"),
            limits: LinuxQemuCgroupLimits::new(1, 4096, 1)?,
            control: first_control,
        };
        let child = first
            .retain_child(child)
            .map_err(|error| io::Error::other(error.to_string()))?;
        assert!(first.owns_child_authority(&child));

        let (second_control, _second_reader) = watcher_control_fixture(directory.path(), true)?;
        let second = LinuxQemuCgroup {
            path: directory.path().to_owned(),
            parent_directory: open_directory(
                directory.path(),
                "open second lifecycle parent fixture",
            )?,
            name: String::from("same-path"),
            limits: LinuxQemuCgroupLimits::new(1, 4096, 1)?,
            control: second_control,
        };
        assert!(!second.owns_child_authority(&child));

        let mut child = child;
        child.kill_and_reap_blocking()?;
        Ok(())
    }

    #[test]
    fn quarantine_start_error_retains_every_cross_incarnation_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let child = QemuNodeChild::new(Command::new("sleep").arg("60").spawn()?);
        let process_id = child.process_id();
        fs::write(
            directory.path().join("cgroup.procs"),
            format!("{process_id}\n"),
        )?;
        let (first_control, _first_reader) = watcher_control_fixture(directory.path(), false)?;
        let mut first = LinuxQemuCgroup {
            path: directory.path().to_owned(),
            parent_directory: open_directory(
                directory.path(),
                "open first quarantine-incarnation fixture",
            )?,
            name: String::from("same-path"),
            limits: LinuxQemuCgroupLimits::new(1, 4096, 1)?,
            control: first_control,
        };
        let child = first
            .retain_child(child)
            .map_err(|error| io::Error::other(error.to_string()))?;

        let (second_control, _second_reader) = watcher_control_fixture(directory.path(), false)?;
        let mut second = LinuxQemuCgroup {
            path: directory.path().to_owned(),
            parent_directory: open_directory(
                directory.path(),
                "open second quarantine-incarnation fixture",
            )?,
            name: String::from("same-path"),
            limits: LinuxQemuCgroupLimits::new(1, 4096, 1)?,
            control: second_control,
        };
        let watcher = second.start_watcher()?;
        let error = match second.quarantine_process(watcher, child) {
            Ok(_) => panic!("cross-incarnation quarantine unexpectedly started"),
            Err(error) => error,
        };
        assert!(matches!(
            error.source_error(),
            LinuxQemuCgroupError::ProcessMembership { .. }
        ));
        let (_second, watcher, mut child) = error
            .into_parts()
            .ok_or_else(|| io::Error::other("quarantine startup lost retained authority"))?;

        child.kill_and_reap_blocking()?;
        assert_eq!(
            watcher.finish_and_wait(Duration::from_secs(1))?,
            LinuxQemuCgroupWatcherOutcome::ClosedAndEmpty
        );
        assert!(linux_process_identity(process_id)?.is_none());
        Ok(())
    }
}
