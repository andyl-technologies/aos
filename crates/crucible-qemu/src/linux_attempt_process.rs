//! Sealed Linux process ownership for one QEMU attempt.
//!
//! This module is the public, process-only facade over the raw cgroup-v2 state
//! machine. It creates one uniquely named attempt cgroup, starts its persistent
//! cancellation watcher, lends only the sealed child-launch contract, retains
//! failed direct children, and completes or quarantines the entire process
//! authority. Raw cgroup controls remain crate-private. This facade deliberately
//! does not claim aggregate filesystem-quota ownership and therefore cannot by
//! itself satisfy a complete campaign attempt resource guard.

use std::io::Read as _;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

use crate::linux_cgroup::{
    LinuxQemuAttemptProcessOwner as CgroupAttemptProcessOwner,
    LinuxQemuAttemptProcessOwnerError as CgroupAttemptProcessOwnerError,
    LinuxQemuAttemptProcessOwnerStatus as CgroupAttemptProcessOwnerStatus, LinuxQemuCgroupError,
    LinuxQemuCgroupLimits, LinuxQemuCgroupRoot, MAX_LINUX_QEMU_CGROUP_TASKS,
};
use crate::{
    QemuChildProcessContract, QemuHotForkChildProcessBasis, QemuHotForkChildProcessOwner,
    QemuNodeChannelError, QemuNodeChild, QemuProcessIdentity, QemuVmRealizationError,
};

/// Minimum bounded wait accepted for normal process-owner cleanup.
pub const MIN_LINUX_QEMU_PROCESS_FINISH_TIMEOUT: Duration = Duration::from_millis(10);

/// Maximum bounded wait accepted for normal process-owner cleanup.
pub const MAX_LINUX_QEMU_PROCESS_FINISH_TIMEOUT: Duration = Duration::from_secs(60);

const ATTEMPT_COUNTER_HEX_BYTES: usize = 16;
const ATTEMPT_NAME_SEPARATOR_BYTES: usize = 1;
const MAX_CGROUP_NAME_BYTES: usize = 128;
const MAX_ATTEMPT_NAMESPACE_BYTES: usize =
    MAX_CGROUP_NAME_BYTES - ATTEMPT_NAME_SEPARATOR_BYTES - ATTEMPT_COUNTER_HEX_BYTES;

/// Validated configuration for one delegated Linux QEMU process namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxQemuAttemptProcessConfig {
    cgroup_root: PathBuf,
    attempt_namespace: String,
    child_user_id: u32,
    child_group_id: u32,
    maximum_tasks: u32,
    finish_timeout: Duration,
}

impl LinuxQemuAttemptProcessConfig {
    /// Validates one daemon-incarnation process namespace.
    ///
    /// `attempt_namespace` must be unique to the daemon incarnation. The
    /// factory appends a fixed-width process-local counter to derive each child
    /// name without using semantic campaign identity.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::Executor`] when the root is not an
    /// absolute path, the namespace is not a bounded cgroup name prefix, child
    /// credentials are root, the task ceiling is invalid, or the finish timeout
    /// is outside the reviewed bound.
    pub fn new(
        cgroup_root: impl Into<PathBuf>,
        attempt_namespace: impl Into<String>,
        child_user_id: u32,
        child_group_id: u32,
        maximum_tasks: u32,
        finish_timeout: Duration,
    ) -> Result<Self, QemuVmRealizationError> {
        let cgroup_root = cgroup_root.into();
        let attempt_namespace = attempt_namespace.into();
        if !cgroup_root.is_absolute() {
            return Err(invalid_config("delegated cgroup root must be absolute"));
        }
        if attempt_namespace.is_empty()
            || attempt_namespace.len() > MAX_ATTEMPT_NAMESPACE_BYTES
            || !attempt_namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid_config(
                "attempt namespace must be bounded ASCII alphanumeric, dash, or underscore",
            ));
        }
        if child_user_id == 0 || child_group_id == 0 {
            return Err(invalid_config(
                "QEMU child user and group identifiers must be non-root",
            ));
        }
        if maximum_tasks == 0 || maximum_tasks > MAX_LINUX_QEMU_CGROUP_TASKS {
            return Err(invalid_config(
                "QEMU task ceiling is outside the supported bound",
            ));
        }
        if !(MIN_LINUX_QEMU_PROCESS_FINISH_TIMEOUT..=MAX_LINUX_QEMU_PROCESS_FINISH_TIMEOUT)
            .contains(&finish_timeout)
        {
            return Err(invalid_config(
                "QEMU process finish timeout is outside the reviewed bound",
            ));
        }
        Ok(Self {
            cgroup_root,
            attempt_namespace,
            child_user_id,
            child_group_id,
            maximum_tasks,
            finish_timeout,
        })
    }

    /// Returns the delegated cgroup-v2 root path.
    #[must_use]
    pub fn cgroup_root(&self) -> &Path {
        &self.cgroup_root
    }

    /// Returns the daemon-incarnation child-name namespace.
    #[must_use]
    pub fn attempt_namespace(&self) -> &str {
        &self.attempt_namespace
    }

    /// Returns the unprivileged QEMU child user identifier.
    #[must_use]
    pub const fn child_user_id(&self) -> u32 {
        self.child_user_id
    }

    /// Returns the unprivileged QEMU child group identifier.
    #[must_use]
    pub const fn child_group_id(&self) -> u32 {
        self.child_group_id
    }

    /// Returns the defensive cgroup task ceiling.
    #[must_use]
    pub const fn maximum_tasks(&self) -> u32 {
        self.maximum_tasks
    }

    /// Returns the bounded normal-finish wait.
    #[must_use]
    pub const fn finish_timeout(&self) -> Duration {
        self.finish_timeout
    }
}

/// Exclusive allocator for one daemon-incarnation QEMU cgroup namespace.
#[derive(Debug)]
#[must_use = "the delegated namespace lock must outlive every attempt process owner"]
pub struct LinuxQemuAttemptProcessFactory {
    config: LinuxQemuAttemptProcessConfig,
    root: LinuxQemuCgroupRoot,
    next_attempt: u64,
    poisoned: bool,
}

impl LinuxQemuAttemptProcessFactory {
    /// Acquires and validates the configured delegated cgroup-v2 root.
    ///
    /// Configuration validation completes before any path access.
    ///
    /// # Errors
    ///
    /// Returns a stable executor error for invalid configuration or cgroup
    /// policy, and an availability error for host I/O or namespace contention.
    pub fn open(config: LinuxQemuAttemptProcessConfig) -> Result<Self, QemuVmRealizationError> {
        let root = LinuxQemuCgroupRoot::acquire(config.cgroup_root())
            .map_err(|error| map_cgroup_error("acquire delegated QEMU cgroup root", &error))?;
        Ok(Self {
            config,
            root,
            next_attempt: 0,
            poisoned: false,
        })
    }

    /// Returns the validated process-namespace configuration.
    #[must_use]
    pub const fn config(&self) -> &LinuxQemuAttemptProcessConfig {
        &self.config
    }

    /// Returns whether a retained setup failure closed this allocator.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Installs one attempt cgroup and sealed process owner.
    ///
    /// `maximum_writable_bytes` is the per-file launch backstop only. The
    /// caller must pair this process authority with the same attempt's hard
    /// aggregate filesystem quota before exposing it as a complete guard.
    ///
    /// # Errors
    ///
    /// Returns a stable or availability error when limits, cgroup creation,
    /// watcher startup, credentials, or contract sealing fail. A failure after
    /// cgroup creation poisons the allocator and deliberately retains or leaks
    /// cleanup authority fail-closed; another QEMU process cannot launch from
    /// this allocator until daemon restart.
    pub fn begin(
        &mut self,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
    ) -> Result<LinuxQemuAttemptProcessOwner, QemuVmRealizationError> {
        if self.poisoned {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "create QEMU attempt process owner",
                message: String::from("delegated process allocator is poisoned"),
            });
        }
        if maximum_writable_bytes == 0 {
            return Err(invalid_config("QEMU writable-byte ceiling must be nonzero"));
        }
        let limits = LinuxQemuCgroupLimits::new(
            maximum_vcpus,
            maximum_resident_bytes,
            self.config.maximum_tasks,
        )
        .map_err(|error| map_cgroup_error("validate QEMU cgroup limits", &error))?;
        let sequence = self.next_attempt;
        self.next_attempt = self.next_attempt.checked_add(1).ok_or_else(|| {
            QemuVmRealizationError::ExecutorUnavailable {
                operation: "allocate QEMU attempt process name",
                message: String::from("attempt process-name sequence is exhausted"),
            }
        })?;
        let name = attempt_name(&self.config.attempt_namespace, sequence);
        let group = match self.root.create(name, limits) {
            Ok(group) => group,
            Err(error) => {
                self.poisoned = true;
                let mapped = map_cgroup_error("create QEMU attempt cgroup", error.source_error());
                if let Some(authority) = error.into_cleanup_authority() {
                    let _retained = Box::leak(Box::new(authority));
                }
                return Err(mapped);
            }
        };
        let owner = match CgroupAttemptProcessOwner::start(
            group,
            maximum_writable_bytes,
            self.config.child_user_id,
            self.config.child_group_id,
        ) {
            Ok(owner) => owner,
            Err(error) => {
                self.poisoned = true;
                let mapped =
                    map_owner_error("start QEMU attempt process owner", error.source_error());
                drop(error);
                return Err(mapped);
            }
        };
        Ok(LinuxQemuAttemptProcessOwner {
            owner,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            finish_timeout: self.config.finish_timeout,
            hot_fork_child_retained: false,
        })
    }
}

/// Complete Linux process authority for one QEMU attempt.
#[derive(Debug)]
#[must_use = "finish the QEMU process owner or transfer it to quarantine"]
pub struct LinuxQemuAttemptProcessOwner {
    owner: CgroupAttemptProcessOwner,
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_writable_bytes: u64,
    finish_timeout: Duration,
    hot_fork_child_retained: bool,
}

impl LinuxQemuAttemptProcessOwner {
    /// Returns the exact CPU, memory, and writable-byte launch ceiling.
    #[must_use]
    pub const fn resource_ceiling(&self) -> (u32, u64, u64) {
        (
            self.maximum_vcpus,
            self.maximum_resident_bytes,
            self.maximum_writable_bytes,
        )
    }

    /// Returns the sealed child-process launch contract while active.
    ///
    /// # Errors
    ///
    /// Returns an operational error after cancellation or terminal cleanup has
    /// closed launch authority.
    pub fn process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.owner
            .process_contract()
            .map_err(|error| map_owner_error("lend QEMU child-process contract", &error))
    }

    /// Duplicates the narrow sticky-cancellation signal.
    ///
    /// # Errors
    ///
    /// Returns an operational error when signal authority cannot be duplicated
    /// or terminal cleanup has begun.
    pub fn cancellation_signal(
        &self,
    ) -> Result<LinuxQemuAttemptCancellationSignal, QemuVmRealizationError> {
        self.owner
            .cancellation_signal()
            .map(|signal| LinuxQemuAttemptCancellationSignal { signal })
            .map_err(|error| map_owner_error("duplicate QEMU cancellation signal", &error))
    }

    /// Retains a failed launch's exact direct-child wait handle.
    pub fn retain_failed_child(&mut self, child: QemuNodeChild) {
        self.owner.retain_failed_child(child);
    }

    /// Joins the watcher, proves the group empty, and releases the cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::ReapQuarantined`] when cleanup moved to
    /// the nondroppable worker, or an availability error while retryable owner
    /// authority remains installed.
    pub fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        match self.owner.finish(self.finish_timeout) {
            Ok(CgroupAttemptProcessOwnerStatus::ReapedAndReleased) => Ok(()),
            Ok(
                CgroupAttemptProcessOwnerStatus::QuarantineRunning
                | CgroupAttemptProcessOwnerStatus::QuarantineParked,
            ) => Err(QemuVmRealizationError::ReapQuarantined {
                operation: "finish QEMU attempt process owner",
                message: String::from("process cleanup remains under quarantine authority"),
            }),
            Err(error) => Err(map_owner_error("finish QEMU attempt process owner", &error)),
        }
    }

    /// Transfers every unfinished process authority to nondroppable quarantine.
    pub fn quarantine(&mut self) {
        let _ = self.owner.quarantine();
    }
}

/// Exact daemon-side kill and identity authority for one hot-fork child.
///
/// The source QEMU process remains the direct parent and owns `waitpid` status.
/// This authority instead pins the live kernel process generation with a pidfd
/// and records the identity authenticated inside the target attempt cgroup.
/// Callers must retain it with the source child-status record and the target
/// [`LinuxQemuAttemptProcessOwner`] until terminal reap and cgroup emptiness are
/// both attested.
#[derive(Debug)]
#[must_use = "retain the hot-fork child authority until source reap and cgroup cleanup"]
pub struct LinuxQemuHotForkChildProcessAuthority {
    basis: QemuHotForkChildProcessBasis,
    identity: QemuProcessIdentity,
    pidfd: OwnedFd,
}

impl LinuxQemuHotForkChildProcessAuthority {
    /// Returns the exact source, child, and fork-request basis.
    #[must_use]
    pub const fn basis(&self) -> QemuHotForkChildProcessBasis {
        self.basis
    }

    /// Returns the authenticated Linux process-generation identity.
    #[must_use]
    pub const fn identity(&self) -> &QemuProcessIdentity {
        &self.identity
    }

    /// Sends `SIGTERM` through the exact retained pidfd.
    ///
    /// # Errors
    ///
    /// Returns an executor-availability error when the kernel rejects the
    /// pidfd signal operation. The source-parent status and attempt cgroup must
    /// remain retained regardless of this result.
    pub fn terminate(&self) -> Result<(), QemuVmRealizationError> {
        pidfd_send_signal(&self.pidfd, Signal::TERM).map_err(|source| {
            QemuVmRealizationError::ExecutorUnavailable {
                operation: "terminate retained hot-fork child",
                message: source.to_string(),
            }
        })
    }

    /// Sends `SIGKILL` through the exact retained pidfd.
    ///
    /// # Errors
    ///
    /// Returns an executor-availability error when the kernel rejects the
    /// pidfd signal operation. The caller must keep the attempt cgroup watcher
    /// and source-QEMU reap authority active regardless of this result.
    pub fn kill(&self) -> Result<(), QemuVmRealizationError> {
        pidfd_send_signal(&self.pidfd, Signal::KILL).map_err(|source| {
            QemuVmRealizationError::ExecutorUnavailable {
                operation: "kill retained hot-fork child",
                message: source.to_string(),
            }
        })
    }
}

impl QemuHotForkChildProcessOwner for LinuxQemuAttemptProcessOwner {
    type Authority = LinuxQemuHotForkChildProcessAuthority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        if self.hot_fork_child_retained {
            return Err(QemuNodeChannelError::new(
                "retain forked child process",
                "attempt process owner already retained one hot-fork child",
            ));
        }
        let raw_process_id = i32::try_from(basis.child_process_id())
            .ok()
            .and_then(Pid::from_raw)
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "retain forked child process",
                    "hot-fork child PID is outside the supported Linux range",
                )
            })?;
        let pidfd = pidfd_open(raw_process_id, PidfdFlags::empty()).map_err(|source| {
            QemuNodeChannelError::new(
                "retain forked child process",
                format!("open pidfd for hot-fork child: {source}"),
            )
        })?;
        verify_pidfd_process_id(&pidfd, basis.child_process_id())?;
        let identity = self
            .owner
            .authenticate_hot_fork_child_process(basis.child_process_id())
            .map_err(|source| {
                QemuNodeChannelError::new(
                    "retain forked child process",
                    format!("authenticate hot-fork child in attempt cgroup: {source}"),
                )
            })?;
        verify_pidfd_process_id(&pidfd, basis.child_process_id())?;

        self.hot_fork_child_retained = true;
        Ok(LinuxQemuHotForkChildProcessAuthority {
            basis,
            identity,
            pidfd,
        })
    }
}

fn verify_pidfd_process_id(
    pidfd: &OwnedFd,
    expected_process_id: u32,
) -> Result<(), QemuNodeChannelError> {
    const MAX_PIDFD_INFO_BYTES: u64 = 4096;

    let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let file = std::fs::File::open(&path).map_err(|source| {
        QemuNodeChannelError::new(
            "retain forked child process",
            format!("open pidfd identity {path}: {source}"),
        )
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_PIDFD_INFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            QemuNodeChannelError::new(
                "retain forked child process",
                format!("read pidfd identity {path}: {source}"),
            )
        })?;
    if bytes.len() > MAX_PIDFD_INFO_BYTES as usize {
        return Err(QemuNodeChannelError::new(
            "retain forked child process",
            "pidfd identity exceeded the bounded Linux fdinfo size",
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|source| {
        QemuNodeChannelError::new(
            "retain forked child process",
            format!("decode pidfd identity: {source}"),
        )
    })?;
    let observed = text
        .lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .and_then(|value| value.parse::<u32>().ok());
    if observed != Some(expected_process_id) {
        return Err(QemuNodeChannelError::new(
            "retain forked child process",
            "pidfd no longer names the reported live hot-fork child",
        ));
    }
    Ok(())
}

/// Narrow sticky signal for one Linux QEMU attempt process group.
#[derive(Debug)]
pub struct LinuxQemuAttemptCancellationSignal {
    signal: crate::linux_cgroup::LinuxQemuCgroupCancellationSignal,
}

impl LinuxQemuAttemptCancellationSignal {
    /// Makes cancellation visible to existing and future child processes.
    ///
    /// # Errors
    ///
    /// Returns an availability error when the sticky event cannot be published.
    pub fn signal(&self) -> Result<(), QemuVmRealizationError> {
        self.signal
            .signal()
            .map_err(|error| map_cgroup_error("signal QEMU attempt cancellation", &error))
    }
}

fn attempt_name(namespace: &str, sequence: u64) -> String {
    format!("{namespace}-{sequence:016x}")
}

fn invalid_config(message: &'static str) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "configure Linux QEMU attempt process owner",
        message: String::from(message),
    }
}

fn map_cgroup_error(
    operation: &'static str,
    error: &LinuxQemuCgroupError,
) -> QemuVmRealizationError {
    match error {
        LinuxQemuCgroupError::Io { .. } | LinuxQemuCgroupError::NamespaceLocked { .. } => {
            QemuVmRealizationError::ExecutorUnavailable {
                operation,
                message: error.to_string(),
            }
        }
        _ => QemuVmRealizationError::Executor {
            operation,
            message: error.to_string(),
        },
    }
}

fn map_owner_error(
    operation: &'static str,
    error: &CgroupAttemptProcessOwnerError,
) -> QemuVmRealizationError {
    match error {
        CgroupAttemptProcessOwnerError::Cgroup(error) => map_cgroup_error(operation, error),
        CgroupAttemptProcessOwnerError::Watcher { .. }
        | CgroupAttemptProcessOwnerError::Quarantine { .. } => {
            QemuVmRealizationError::ExecutorUnavailable {
                operation,
                message: error.to_string(),
            }
        }
        CgroupAttemptProcessOwnerError::MissingAuthority { .. } => {
            QemuVmRealizationError::Executor {
                operation,
                message: error.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
    #![allow(clippy::expect_used)]

    use tempfile::tempdir;

    use super::*;

    fn config(
        root: impl Into<PathBuf>,
        namespace: &str,
    ) -> Result<LinuxQemuAttemptProcessConfig, QemuVmRealizationError> {
        LinuxQemuAttemptProcessConfig::new(
            root,
            namespace,
            65_533,
            65_532,
            64,
            Duration::from_secs(1),
        )
    }

    #[test]
    fn configuration_rejects_invalid_values_before_cgroup_access() {
        assert!(config("relative", "attempt").is_err());
        assert!(config("/does/not/exist", "").is_err());
        assert!(config("/does/not/exist", "bad/name").is_err());
        assert!(
            LinuxQemuAttemptProcessConfig::new(
                "/does/not/exist",
                "attempt",
                0,
                65_532,
                64,
                Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(
            LinuxQemuAttemptProcessConfig::new(
                "/does/not/exist",
                "attempt",
                65_533,
                65_532,
                MAX_LINUX_QEMU_CGROUP_TASKS + 1,
                Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(
            LinuxQemuAttemptProcessConfig::new(
                "/does/not/exist",
                "attempt",
                65_533,
                65_532,
                64,
                Duration::from_millis(1),
            )
            .is_err()
        );
    }

    #[test]
    fn child_names_are_bounded_unique_and_namespace_scoped() {
        let namespace = "d0123456789abcdef";
        let first = attempt_name(namespace, 0);
        let second = attempt_name(namespace, 1);
        assert_ne!(first, second);
        assert!(first.starts_with(namespace));
        assert!(first.len() <= MAX_CGROUP_NAME_BYTES);
        assert_eq!(first, "d0123456789abcdef-0000000000000000");
    }

    #[test]
    fn non_cgroup_root_fails_closed_without_creating_children() {
        let root = tempdir().expect("temporary cgroup root");
        let config = config(root.path(), "attempt").expect("process config");
        assert!(matches!(
            LinuxQemuAttemptProcessFactory::open(config),
            Err(QemuVmRealizationError::Executor { .. })
        ));
        assert_eq!(
            std::fs::read_dir(root.path())
                .expect("read temporary root")
                .count(),
            0
        );
    }

    #[test]
    fn pidfd_identity_rejects_a_reaped_process_generation() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut child = std::process::Command::new("sleep").arg("60").spawn()?;
        let process_id = child.id();
        let raw_process_id = i32::try_from(process_id)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or("test child PID is outside the supported Linux range")?;
        let pidfd = pidfd_open(raw_process_id, PidfdFlags::empty())?;

        verify_pidfd_process_id(&pidfd, process_id)?;
        child.kill()?;
        child.wait()?;
        assert!(verify_pidfd_process_id(&pidfd, process_id).is_err());
        Ok(())
    }
}
