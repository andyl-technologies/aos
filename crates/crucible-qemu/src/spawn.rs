//! Linux QEMU process spawning with fixed inherited descriptors.
//!
//! This module owns the Linux-only process boundary required by RFC-0010
//! T-QEMU-7. It creates the per-node control socket pair, shared-memory memfd,
//! and wake eventfd before `exec`, maps the child descriptors to the fixed
//! plugin fd numbers, clears the inherited host environment, and sets
//! `PR_SET_PDEATHSIG=SIGKILL` in the child.

use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write as _};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::supervision::HostSupervisionDeadline;

use rustix::fs::{FileType, OFlags, fcntl_getfl, fcntl_setfl, fstat, fstatfs};
use thiserror::Error;

use crate::{
    QEMU_PLUGIN_CONTROL_FD, QEMU_PLUGIN_SHMEM_FD, QEMU_PLUGIN_WAKE_FD, QemuLaunchCommand,
    QemuNodeChild,
};

mod materialization;
mod run_directory;

pub(crate) use materialization::QemuProductionExactRestoreSource;
pub(crate) use materialization::SealedAtomicExactRestoreInputs;
pub(crate) use materialization::{
    QemuExactDeviceStateBinding, QemuGuardedExactRamInput, require_exact_restore_not_canceled,
};
pub use run_directory::QemuPreparedRunDirectory;
use run_directory::{PinnedFileIdentity, open_prepared_root_overlay};

const QEMU_VMSTATE_LAUNCH_FD: RawFd = QEMU_PLUGIN_WAKE_FD + 1;
const QEMU_ROOT_OVERLAY_READ_LAUNCH_FD: RawFd = QEMU_VMSTATE_LAUNCH_FD + 1;
const QEMU_ROOT_OVERLAY_WRITE_LAUNCH_FD: RawFd = QEMU_ROOT_OVERLAY_READ_LAUNCH_FD + 1;
// Every inherited source is relocated above all fixed exec targets before dup2.
const CHILD_SOURCE_FD_MIN: RawFd = QEMU_ROOT_OVERLAY_WRITE_LAUNCH_FD + 1;
const CGROUP_ATTACH_SELF: &[u8] = b"0\n";
const MAX_SUPERVISOR_GROUPS: usize = 65_536;
const VMSTATE_FILE_NAME_C: &[u8] = b"crucible-vmstate.qcow2\0";
const GUARDED_IMAGE_TOOL_TIMEOUT: Duration = Duration::from_secs(60);
const GUARDED_IMAGE_TOOL_REAP_TIMEOUT: Duration = Duration::from_secs(5);
const GUARDED_IMAGE_TOOL_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Owned pre-exec contract for one attempt-contained child process.
///
/// The cgroup descriptors pin the attempt directory and its `cgroup.procs`
/// file. The cancellation descriptor is a nonblocking eventfd that becomes
/// readable once cancellation wins. All descriptors must be opened by the
/// supervising resource guard and remain owned by that guard independently of
/// this per-spawn duplicate. A production contract also carries validated non-root
/// child credentials; pre-exec clears supplementary groups, sets
/// `no_new_privs`, and switches every user/group identity after attaching the
/// child to the cgroup. The contract seals the exact admitted vCPU,
/// resident-memory, and aggregate writable-byte ceilings so guarded launch can
/// reject an incompatible command before touching the run directory or
/// allocating child descriptors. A private lifecycle token also binds every
/// prepared run-directory authority to this exact contract rather than merely
/// to another attempt with equal numeric limits.
#[derive(Debug)]
pub struct QemuChildProcessContract {
    cgroup_directory: Option<OwnedFd>,
    cgroup_procs: OwnedFd,
    cancellation_event: OwnedFd,
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_writable_bytes: u64,
    credentials: Option<QemuChildCredentials>,
    attempt_binding: Arc<AttemptResourceBinding>,
    exact_checkpoint_root: Option<crucible::ContentHash>,
}

#[derive(Debug)]
struct AttemptResourceBinding;

fn invalid_input(operation: &'static str, message: &'static str) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation,
        source: io::Error::new(io::ErrorKind::InvalidInput, message),
    }
}

/// Distinct unprivileged credentials installed in a guarded QEMU child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QemuChildCredentials {
    user_id: libc::uid_t,
    group_id: libc::gid_t,
}

struct SupervisorCredentials {
    user_ids: [libc::uid_t; 3],
    group_ids: [libc::gid_t; 3],
    supplementary_group_ids: Vec<libc::gid_t>,
}

impl QemuChildCredentials {
    /// Validates credentials that cannot retain the supervisor's identity.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError::InvalidChildCredentials`] when either ID is
    /// root, the user ID equals any real, effective, or saved daemon user, or
    /// the group ID equals any real, effective, saved, or supplementary daemon
    /// group. Returns
    /// [`QemuSpawnError::Io`] when the daemon group set cannot be inspected
    /// within its explicit bound.
    pub(crate) fn new(user_id: libc::uid_t, group_id: libc::gid_t) -> Result<Self, QemuSpawnError> {
        let supervisor = current_supervisor_credentials()?;
        if user_id == 0
            || group_id == 0
            || supervisor.user_ids.contains(&user_id)
            || supervisor.group_ids.contains(&group_id)
            || supervisor.supplementary_group_ids.contains(&group_id)
        {
            return Err(QemuSpawnError::InvalidChildCredentials { user_id, group_id });
        }
        Ok(Self { user_id, group_id })
    }
}

fn current_supervisor_credentials() -> Result<SupervisorCredentials, QemuSpawnError> {
    let mut real_user_id = 0;
    let mut effective_user_id = 0;
    let mut saved_user_id = 0;
    let users_read = unsafe {
        // SAFETY: all three pointers name writable uid_t values.
        libc::getresuid(
            &mut real_user_id,
            &mut effective_user_id,
            &mut saved_user_id,
        )
    };
    if users_read != 0 {
        return Err(last_io_error("inspect supervisor user credentials"));
    }
    let mut real_group_id = 0;
    let mut effective_group_id = 0;
    let mut saved_group_id = 0;
    let groups_read = unsafe {
        // SAFETY: all three pointers name writable gid_t values.
        libc::getresgid(
            &mut real_group_id,
            &mut effective_group_id,
            &mut saved_group_id,
        )
    };
    if groups_read != 0 {
        return Err(last_io_error("inspect supervisor group credentials"));
    }
    Ok(SupervisorCredentials {
        user_ids: [real_user_id, effective_user_id, saved_user_id],
        group_ids: [real_group_id, effective_group_id, saved_group_id],
        supplementary_group_ids: current_supplementary_groups()?,
    })
}

fn current_supplementary_groups() -> Result<Vec<libc::gid_t>, QemuSpawnError> {
    let count = unsafe {
        // SAFETY: a zero count permits a null list and returns its required size.
        libc::getgroups(0, std::ptr::null_mut())
    };
    if count < 0 {
        return Err(last_io_error("inspect supervisor supplementary groups"));
    }
    let count = usize::try_from(count).map_err(|source| QemuSpawnError::Io {
        operation: "bound supervisor supplementary groups",
        source: io::Error::new(io::ErrorKind::InvalidData, source),
    })?;
    if count > MAX_SUPERVISOR_GROUPS {
        return Err(QemuSpawnError::Io {
            operation: "bound supervisor supplementary groups",
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "supervisor supplementary groups exceed the supported bound",
            ),
        });
    }
    let mut groups = vec![0; count];
    if count == 0 {
        return Ok(groups);
    }
    let returned = unsafe {
        // SAFETY: `groups` contains exactly `count` writable gid_t elements.
        libc::getgroups(count as libc::c_int, groups.as_mut_ptr())
    };
    if returned < 0 {
        return Err(last_io_error("read supervisor supplementary groups"));
    }
    if usize::try_from(returned).ok() != Some(count) {
        return Err(QemuSpawnError::Io {
            operation: "read supervisor supplementary groups",
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "supervisor supplementary groups changed while inspected",
            ),
        });
    }
    Ok(groups)
}

impl QemuChildProcessContract {
    /// Duplicates the sticky cancellation event for one bounded QMP operation.
    ///
    /// The returned descriptor observes the same eventfd counter as the child
    /// process contract. An attempt cancellation therefore interrupts both a
    /// process blocked in setup and a descriptor-backed QMP capture or restore.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError::Io`] when the retained eventfd cannot be
    /// duplicated.
    pub fn try_clone_cancellation_event(&self) -> Result<OwnedFd, QemuSpawnError> {
        self.cancellation_event
            .try_clone()
            .map_err(|source| QemuSpawnError::Io {
                operation: "duplicate QMP cancellation eventfd",
                source,
            })
    }

    /// Duplicates this contract for another generation under the same attempt.
    ///
    /// The duplicated descriptors retain the same cgroup, cancellation event,
    /// credentials, resource ceilings, and private attempt binding. This is for
    /// a lifecycle launcher whose aggregate guard is shared through an ownership
    /// registry and therefore cannot lend a reference while that registry is
    /// unlocked.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError::Io`] when a retained descriptor cannot be
    /// duplicated.
    pub fn try_clone_for_attempt_generation(&self) -> Result<Self, QemuSpawnError> {
        let cgroup_directory = self
            .cgroup_directory
            .as_ref()
            .map(OwnedFd::try_clone)
            .transpose()
            .map_err(|source| QemuSpawnError::Io {
                operation: "duplicate generation cgroup directory",
                source,
            })?;
        let cgroup_procs = self
            .cgroup_procs
            .try_clone()
            .map_err(|source| QemuSpawnError::Io {
                operation: "duplicate generation cgroup.procs descriptor",
                source,
            })?;
        let cancellation_event =
            self.cancellation_event
                .try_clone()
                .map_err(|source| QemuSpawnError::Io {
                    operation: "duplicate generation cancellation eventfd",
                    source,
                })?;

        Ok(Self {
            cgroup_directory,
            cgroup_procs,
            cancellation_event,
            maximum_vcpus: self.maximum_vcpus,
            maximum_resident_bytes: self.maximum_resident_bytes,
            maximum_writable_bytes: self.maximum_writable_bytes,
            credentials: self.credentials,
            attempt_binding: Arc::clone(&self.attempt_binding),
            exact_checkpoint_root: self.exact_checkpoint_root,
        })
    }

    fn admitted_resource_ceiling(&self) -> (u32, u64, u64) {
        (
            self.maximum_vcpus,
            self.maximum_resident_bytes,
            self.maximum_writable_bytes,
        )
    }

    /// Builds one child-side containment and credential contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when either descriptor is invalid.
    pub(crate) fn new(
        cgroup_directory: OwnedFd,
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        cgroup_limits: crate::linux_cgroup::LinuxQemuCgroupLimits,
        maximum_writable_bytes: u64,
        credentials: QemuChildCredentials,
        exact_checkpoint_root: Option<crucible::ContentHash>,
    ) -> Result<Self, QemuSpawnError> {
        validate_cgroup_directory_fd(&cgroup_directory)?;
        validate_cgroup_procs_fd(&cgroup_procs)?;
        validate_cancellation_eventfd(cancellation_event.as_raw_fd())?;
        Ok(Self {
            cgroup_directory: Some(cgroup_directory),
            cgroup_procs,
            cancellation_event,
            maximum_vcpus: cgroup_limits.maximum_vcpus(),
            maximum_resident_bytes: cgroup_limits.maximum_resident_bytes(),
            maximum_writable_bytes,
            credentials: Some(credentials),
            attempt_binding: Arc::new(AttemptResourceBinding),
            exact_checkpoint_root,
        })
    }

    pub(crate) fn require_exact_checkpoint_root(
        &self,
        root: crucible::ContentHash,
    ) -> Result<(), QemuSpawnError> {
        if self.exact_checkpoint_root != Some(root) {
            return Err(invalid_input(
                "authenticate exact checkpoint root",
                "attempt process contract is not bound to this exact checkpoint root",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn for_test(
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_writable_bytes: u64,
    ) -> Self {
        Self::from_unvalidated_test_descriptors_with_root(
            cgroup_procs,
            cancellation_event,
            u32::MAX,
            u64::MAX,
            maximum_writable_bytes,
            None,
        )
    }

    #[cfg(test)]
    fn for_exact_checkpoint_test(
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_writable_bytes: u64,
        exact_checkpoint_root: crucible::ContentHash,
    ) -> Self {
        Self::from_unvalidated_test_descriptors_with_root(
            cgroup_procs,
            cancellation_event,
            u32::MAX,
            u64::MAX,
            maximum_writable_bytes,
            Some(exact_checkpoint_root),
        )
    }

    /// Builds an unvalidated process contract for cross-crate conformance tests.
    ///
    /// This constructor exists only with the `test-support` feature or while
    /// compiling this crate's unit tests. It must never be used as a production
    /// containment boundary.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn from_unvalidated_test_descriptors(
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
    ) -> Self {
        Self::from_unvalidated_test_descriptors_with_root(
            cgroup_procs,
            cancellation_event,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            None,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    fn from_unvalidated_test_descriptors_with_root(
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
        exact_checkpoint_root: Option<crucible::ContentHash>,
    ) -> Self {
        Self {
            cgroup_directory: None,
            cgroup_procs,
            cancellation_event,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            credentials: None,
            attempt_binding: Arc::new(AttemptResourceBinding),
            exact_checkpoint_root,
        }
    }

    /// Builds an unvalidated hot-fork process contract for cross-crate tests.
    ///
    /// Unlike [`Self::from_unvalidated_test_descriptors`], this value carries a
    /// directory descriptor so tests can exercise retained-template descriptor
    /// transfer. No descriptor provenance or credential policy is validated.
    /// It must never be used as a production containment boundary.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn from_unvalidated_hot_fork_test_descriptors(
        cgroup_directory: OwnedFd,
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
    ) -> Self {
        Self {
            cgroup_directory: Some(cgroup_directory),
            cgroup_procs,
            cancellation_event,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            credentials: None,
            attempt_binding: Arc::new(AttemptResourceBinding),
            exact_checkpoint_root: None,
        }
    }

    /// Duplicates the cgroup directory, its `cgroup.procs`, and the
    /// cancellation eventfd for one hot-fork contract stage, in that order.
    pub(crate) fn duplicate_hot_fork_descriptors(
        &self,
    ) -> Result<(OwnedFd, OwnedFd, OwnedFd), QemuSpawnError> {
        let cgroup_directory = self
            .cgroup_directory
            .as_ref()
            .ok_or_else(|| QemuSpawnError::Io {
                operation: "duplicate hot-fork cgroup directory",
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "test-only process contract has no cgroup directory",
                ),
            })?
            .try_clone()
            .map_err(|source| QemuSpawnError::Io {
                operation: "duplicate hot-fork cgroup directory",
                source,
            })?;
        let cgroup_procs = self
            .cgroup_procs
            .try_clone()
            .map_err(|source| QemuSpawnError::Io {
                operation: "duplicate hot-fork cgroup.procs descriptor",
                source,
            })?;
        let cancellation_event =
            self.cancellation_event
                .try_clone()
                .map_err(|source| QemuSpawnError::Io {
                    operation: "duplicate hot-fork cancellation eventfd",
                    source,
                })?;
        Ok((cgroup_directory, cgroup_procs, cancellation_event))
    }

    pub(crate) const fn maximum_writable_bytes(&self) -> u64 {
        self.maximum_writable_bytes
    }
}

/// Host-side descriptors retained after spawning a QEMU child.
#[derive(Debug)]
pub struct QemuSpawnHostResources {
    control_socket: OwnedFd,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
    region_len: u64,
    fault_node_hash: [u8; 32],
}

impl QemuSpawnHostResources {
    /// Returns the host end of the plugin IPC control socket.
    #[must_use]
    pub fn control_socket_fd(&self) -> RawFd {
        self.control_socket.as_raw_fd()
    }

    /// Returns the host shared-memory descriptor.
    #[must_use]
    pub fn shmem_fd(&self) -> RawFd {
        self.shmem_fd.as_raw_fd()
    }

    /// Returns the host wake event descriptor.
    #[must_use]
    pub fn wake_fd(&self) -> RawFd {
        self.wake_fd.as_raw_fd()
    }

    /// Returns the shared-memory region length used to size the memfd.
    #[must_use]
    pub const fn region_len(&self) -> u64 {
        self.region_len
    }

    /// Consumes retained host descriptors into setup-driver resources.
    #[must_use]
    pub fn into_setup_resources(self) -> QemuSpawnSetupResources {
        QemuSpawnSetupResources {
            control_socket: UnixStream::from(self.control_socket),
            shmem_fd: self.shmem_fd,
            wake_fd: self.wake_fd,
            region_len: self.region_len,
            fault_node_hash: self.fault_node_hash,
        }
    }
}

/// Host-side descriptors in the shape required by the setup protocol driver.
#[derive(Debug)]
pub struct QemuSpawnSetupResources {
    control_socket: UnixStream,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
    region_len: u64,
    fault_node_hash: [u8; 32],
}

impl QemuSpawnSetupResources {
    /// Returns the host end of the plugin IPC control socket.
    #[must_use]
    pub fn control_socket_fd(&self) -> RawFd {
        self.control_socket.as_raw_fd()
    }

    /// Returns the host shared-memory descriptor.
    #[must_use]
    pub fn shmem_fd(&self) -> RawFd {
        self.shmem_fd.as_raw_fd()
    }

    /// Returns the host wake event descriptor.
    #[must_use]
    pub fn wake_fd(&self) -> RawFd {
        self.wake_fd.as_raw_fd()
    }

    /// Returns the shared-memory region length used to size the memfd.
    #[must_use]
    pub const fn region_len(&self) -> u64 {
        self.region_len
    }

    /// Returns the node identity hash encoded in the spawned plugin argument.
    #[must_use]
    pub const fn fault_node_hash(&self) -> [u8; 32] {
        self.fault_node_hash
    }

    /// Consumes the setup resources into their owned parts.
    #[must_use]
    pub fn into_parts(self) -> (UnixStream, OwnedFd, OwnedFd, u64, [u8; 32]) {
        (
            self.control_socket,
            self.shmem_fd,
            self.wake_fd,
            self.region_len,
            self.fault_node_hash,
        )
    }
}

/// A spawned QEMU child plus the host descriptors retained for its node.
#[derive(Debug)]
pub struct QemuSpawnedChild {
    child: QemuNodeChild,
    resources: QemuSpawnHostResources,
}

/// Failed guarded image preparation with optional unreaped helper ownership.
///
/// Callers must transfer an unreaped helper into their attempt-wide process
/// owner before dropping the error. Errors without a child attest that no
/// helper was spawned or that every spawned helper was synchronously reaped.
#[derive(Debug, Error)]
#[error("{source}")]
pub struct QemuGuardedImagePreparationError {
    pub(super) source: QemuSpawnError,
    pub(super) child: Option<QemuNodeChild>,
}

impl QemuGuardedImagePreparationError {
    /// Takes the unique wait authority for an unreaped image-tool helper.
    #[must_use]
    pub fn take_unreaped_child(&mut self) -> Option<QemuNodeChild> {
        self.child.take()
    }
}

impl QemuSpawnedChild {
    /// Consumes the spawn result into its node child and retained host resources.
    #[must_use]
    pub fn into_parts(self) -> (QemuNodeChild, QemuSpawnHostResources) {
        (self.child, self.resources)
    }
}

/// Errors returned while preparing or spawning a QEMU child.
#[derive(Debug, Error)]
pub enum QemuSpawnError {
    /// The shared-memory region length was zero.
    #[error("shared-memory region length must be non-zero")]
    RegionLengthZero,
    /// The shared-memory region length cannot be represented by `ftruncate`.
    #[error("shared-memory region length {region_len} is too large for ftruncate")]
    RegionLengthTooLarge {
        /// Requested shared-memory region length.
        region_len: u64,
    },
    /// A Linux descriptor or process operation failed.
    #[error("{operation} failed: {source}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Underlying OS error.
        source: io::Error,
    },
    /// A guarded image-tool helper exited unsuccessfully.
    #[error("guarded qemu-img operation `{operation}` failed with {status}")]
    GuardedImageTool {
        /// Stable preparation operation.
        operation: &'static str,
        /// Rendered process exit status.
        status: String,
    },
    /// A guarded image-tool helper exceeded its absolute execution deadline.
    #[error("guarded qemu-img operation `{operation}` exceeded its execution deadline")]
    GuardedImageToolTimeout {
        /// Stable preparation operation.
        operation: &'static str,
    },
    /// A guarded QEMU setup probe exceeded its absolute execution deadline.
    #[error("guarded QEMU setup probe exceeded its execution deadline")]
    GuardedQemuProbeTimeout,
    /// A guarded QEMU setup probe exceeded its bounded diagnostic output.
    #[error("guarded QEMU setup probe exceeded its {maximum_bytes}-byte output limit")]
    GuardedQemuProbeOutputLimit {
        /// Maximum bytes retained independently for stdout and stderr.
        maximum_bytes: usize,
    },
    /// A fixed diagnostic trace had the wrong filesystem identity.
    #[error(
        "diagnostic trace `{file}` metadata is invalid: type={file_type_mode:o} links={links} owner={user_id}:{group_id} mode={mode:o}"
    )]
    DiagnosticTraceMetadata {
        /// Fixed trace file name.
        file: &'static str,
        /// Observed file-type mode bits.
        file_type_mode: u32,
        /// Observed hard-link count.
        links: u64,
        /// Observed owning user.
        user_id: libc::uid_t,
        /// Observed owning group.
        group_id: libc::gid_t,
        /// Observed permission and special-mode bits.
        mode: u32,
    },
    /// A fixed diagnostic trace was empty or exceeded its byte limit.
    #[error("diagnostic trace `{file}` length {actual} is outside maximum {maximum}")]
    DiagnosticTraceLength {
        /// Fixed trace file name.
        file: &'static str,
        /// Observed byte length.
        actual: u64,
        /// Fixed maximum byte length.
        maximum: u64,
    },
    /// A fixed diagnostic trace exceeded its line limit.
    #[error("diagnostic trace `{file}` line count {actual} is outside maximum {maximum}")]
    DiagnosticTraceLines {
        /// Fixed trace file name.
        file: &'static str,
        /// Observed newline count.
        actual: usize,
        /// Fixed maximum newline count.
        maximum: usize,
    },
    /// The fixed trace and launch artifacts exceeded aggregate storage admission.
    #[error(
        "diagnostic trace `{file}` uses {trace_bytes} bytes outside aggregate writable maximum {maximum}"
    )]
    DiagnosticTraceExceedsAdmission {
        /// Fixed trace file name.
        file: &'static str,
        /// Trace bytes counted with the other launch artifacts.
        trace_bytes: u64,
        /// Aggregate attempt ceiling.
        maximum: u64,
    },
    /// The fixed trace name or inode changed while being retained.
    #[error("diagnostic trace `{file}` changed during retention")]
    DiagnosticTraceChanged {
        /// Fixed trace file name.
        file: &'static str,
    },
    /// The fixed trace was not valid UTF-8 text.
    #[error("diagnostic trace `{file}` is not UTF-8: {source}")]
    DiagnosticTraceUtf8 {
        /// Fixed trace file name.
        file: &'static str,
        /// UTF-8 decoding failure.
        #[source]
        source: std::string::FromUtf8Error,
    },
    /// A disk-backed fresh launch omitted its immutable root image.
    #[error("fresh disk-backed QEMU preparation requires one root image")]
    FreshRootImageMissing,
    /// A diskless fresh launch was paired with an unexpected root image.
    #[error("diskless fresh QEMU preparation received an unexpected root image")]
    FreshRootImageUnexpected,
    /// Guarded fresh preparation requires a path immune to cwd changes.
    #[error("guarded qemu-img path must be absolute: {path}")]
    FreshImageToolPath {
        /// Rejected adjacent image-tool path.
        path: PathBuf,
    },
    /// The immutable root image has no bytes.
    #[error("fresh QEMU root image is empty: {path}")]
    FreshRootImageEmpty {
        /// Root-image path used only for diagnostics.
        path: PathBuf,
    },
    /// Fresh image-tool output has not been completely sealed.
    #[error("fresh QEMU generation artifacts are not ready: {path}")]
    FreshArtifactsNotReady {
        /// Descriptor-pinned generation path used only for diagnostics.
        path: PathBuf,
    },
    /// The guarded run directory lacks its pre-provisioned device-state container.
    #[error("guarded QEMU launch requires pre-provisioned device-state container {path}")]
    MissingPreparedDeviceState {
        /// Required device-state container path.
        path: PathBuf,
    },
    /// The retained run-directory descriptor no longer names its opened inode.
    #[error("prepared QEMU run-directory identity changed: {path}")]
    PreparedRunDirectoryChanged {
        /// Original diagnostic path of the pinned directory.
        path: PathBuf,
    },
    /// The device-state name no longer resolves to the retained regular file.
    #[error("prepared device-state identity changed: {path}")]
    PreparedDeviceStateChanged {
        /// Original diagnostic path of the device-state container.
        path: PathBuf,
    },
    /// The command, admitted ceiling, or attempt lifecycle differs from preparation.
    #[error("prepared QEMU run directory is bound to a different launch admission")]
    PreparedLaunchAdmissionChanged,
    /// A prepared writable artifact has an invalid length.
    #[error("prepared QEMU artifact is not ready: {path}")]
    PreparedArtifactNotReady {
        /// Descriptor-pinned artifact path used only for diagnostics.
        path: PathBuf,
    },
    /// The complete prepared artifact pair exceeds the aggregate quota.
    #[error(
        "prepared artifacts use {device_state_bytes} device-state bytes and {root_overlay_bytes} root-overlay bytes, above maximum {maximum}"
    )]
    PreparedArtifactsTooLarge {
        /// Logical device-state bytes.
        device_state_bytes: u64,
        /// Logical root-overlay bytes.
        root_overlay_bytes: u64,
        /// Admitted aggregate writable-byte ceiling.
        maximum: u64,
    },
    /// A declared exact restore exceeds the aggregate writable-byte admission.
    #[error(
        "exact checkpoint artifacts use {device_state_bytes} device-state bytes, {root_overlay_bytes} root-overlay bytes, and {ram_bytes} RAM bytes, above maximum {maximum}"
    )]
    PreparedExactCheckpointArtifactsTooLarge {
        /// Declared device-state bytes.
        device_state_bytes: u64,
        /// Declared root-overlay bytes.
        root_overlay_bytes: u64,
        /// Sum of every declared RAM layer.
        ram_bytes: u64,
        /// Admitted aggregate writable-byte ceiling.
        maximum: u64,
    },
    /// Exact-checkpoint admission metadata could not be allocated.
    #[error("exact checkpoint artifact-set admission allocation failed")]
    PreparedExactCheckpointAdmissionAllocation,
    /// An exact-checkpoint materialization set is incomplete.
    #[error("prepared exact-checkpoint materialization is not ready: {path}")]
    PreparedExactCheckpointNotReady {
        /// Pinned generation path used only for diagnostics.
        path: PathBuf,
    },
    /// The exact device-state input has an invalid declared byte length.
    #[error(
        "prepared exact device-state length {length} is outside the admitted maximum {maximum}"
    )]
    PreparedDeviceStateLength {
        /// Declared exact checkpoint bytes.
        length: u64,
        /// Admitted aggregate writable-byte ceiling.
        maximum: u64,
    },
    /// The exact device-state input is absent or incomplete.
    #[error("prepared sealed device-state input is absent or incomplete")]
    PreparedDeviceStateNotReady,
    /// A materialized exact descriptor input is shorter or longer than declared.
    #[error("prepared exact input is incomplete: expected {expected} bytes, found {actual}")]
    PreparedExactInputIncomplete {
        /// Declared complete checkpoint length.
        expected: u64,
        /// Bytes written or found in the pinned file.
        actual: u64,
    },
    /// The root-overlay name no longer resolves to the retained regular file.
    #[error("prepared root-overlay identity changed: {path}")]
    PreparedRootOverlayChanged {
        /// Original diagnostic path of the root overlay.
        path: PathBuf,
    },
    /// The exact root overlay has an invalid declared byte length.
    #[error(
        "prepared exact root-overlay length {length} is outside the admitted maximum {maximum}"
    )]
    PreparedRootOverlayLength {
        /// Declared exact checkpoint bytes.
        length: u64,
        /// Conservative aggregate writable-byte share.
        maximum: u64,
    },
    /// The exact root-overlay destination already exists.
    #[error("prepared exact root-overlay destination already exists: {path}")]
    PreparedRootOverlayAlreadyExists {
        /// Pinned root-overlay path used only for diagnostics.
        path: PathBuf,
    },
    /// The exact root overlay is absent or remains incomplete.
    #[error("prepared exact root-overlay materialization is not ready: {path}")]
    PreparedRootOverlayNotReady {
        /// Pinned root-overlay path used only for diagnostics.
        path: PathBuf,
    },
    /// The materialized root overlay is shorter or longer than declared.
    #[error("prepared exact root overlay is incomplete: expected {expected} bytes, found {actual}")]
    PreparedRootOverlayIncomplete {
        /// Declared complete checkpoint length.
        expected: u64,
        /// Bytes written or found in the pinned file.
        actual: u64,
    },
    /// The guarded child would retain root or a supervisor credential.
    #[error(
        "QEMU child credentials must be non-root and distinct from the supervisor: {user_id}:{group_id}"
    )]
    InvalidChildCredentials {
        /// Requested child user ID.
        user_id: libc::uid_t,
        /// Requested child group ID.
        group_id: libc::gid_t,
    },
    /// The validated launch command exceeds the attempt's admitted ceiling.
    #[error("QEMU launch exceeds admitted attempt resources: {source}")]
    LaunchResources {
        /// Exact launch-resource mismatch.
        source: crate::QemuLaunchResourceError,
    },
}
/// Spawns QEMU from an already-provisioned run directory under `contract`.
///
/// This fixed-FD operation never invokes `qemu-img` or creates the exact-VMState
/// container. The supervisor must provision and validate that container under
/// its own bounded service policy before admitting the attempt. Before
/// revalidating that authority, this path validates the command's fixed
/// resource baseline against the ceilings sealed into `contract`. The child
/// writes itself into the attempt cgroup and checks cancellation in `pre_exec`,
/// before QEMU executes.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when the launch exceeds its admitted resources,
/// the prepared container is absent or not a regular file, descriptor
/// preparation fails, the pre-exec containment contract rejects the child, or
/// QEMU cannot be spawned.
pub(crate) fn spawn_prepared_qemu_child_with_fds_in_directory_guarded(
    command: &QemuLaunchCommand,
    run_directory: &QemuPreparedRunDirectory,
    region_len: u64,
    contract: &QemuChildProcessContract,
) -> Result<QemuSpawnedChild, QemuSpawnError> {
    run_directory.validate_launch_basis(command, contract)?;
    run_directory.revalidate()?;
    let image_pins = GuardedLaunchImagePins::new(run_directory)?;
    let launch_args = guarded_launch_args(command.args(), image_pins.overlay.is_some())?;
    let (mut resources, child_resources) = create_spawn_resources(region_len)?;
    resources.fault_node_hash = command.plugin_fault_node_hash();
    let child = spawn_process_with_resources(
        command.executable(),
        &launch_args,
        run_directory,
        child_resources,
        &image_pins,
        &[],
        Some(contract),
    )?;
    Ok(QemuSpawnedChild {
        child: QemuNodeChild::new(child),
        resources,
    })
}

pub(crate) fn validate_guarded_launch_resources(
    command: &QemuLaunchCommand,
    contract: &QemuChildProcessContract,
) -> Result<(), QemuSpawnError> {
    validate_guarded_launch_requirements(command.resource_requirements(), contract)
}

pub(crate) fn validate_guarded_launch_requirements(
    requirements: crate::QemuLaunchResourceRequirements,
    contract: &QemuChildProcessContract,
) -> Result<(), QemuSpawnError> {
    requirements
        .validate_ceiling(
            contract.maximum_vcpus,
            contract.maximum_resident_bytes,
            contract.maximum_writable_bytes,
        )
        .map_err(|source| QemuSpawnError::LaunchResources { source })
}
#[derive(Debug)]
struct QemuSpawnChildResources {
    control_socket: OwnedFd,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
}

struct GuardedLaunchImagePins {
    vmstate: OwnedFd,
    overlay: Option<GuardedOverlayImagePins>,
}

struct GuardedOverlayImagePins {
    read: OwnedFd,
    write: OwnedFd,
}

impl GuardedLaunchImagePins {
    fn new(run_directory: &QemuPreparedRunDirectory) -> Result<Self, QemuSpawnError> {
        let vmstate = duplicate_cloexec_fd(
            run_directory.vmstate.as_raw_fd(),
            "pin guarded VMState launch descriptor",
        )?;
        let overlay = match run_directory.open_direct_root_overlay_for_launch()? {
            Some((read, write)) => Some(GuardedOverlayImagePins {
                read: duplicate_cloexec_fd(
                    read.as_raw_fd(),
                    "pin read-only guarded root-overlay launch descriptor",
                )?,
                write: duplicate_cloexec_fd(
                    write.as_raw_fd(),
                    "pin read-write guarded root-overlay launch descriptor",
                )?,
            }),
            None => None,
        };
        Ok(Self { vmstate, overlay })
    }
}

fn guarded_launch_args(args: &[String], has_overlay: bool) -> Result<Vec<String>, QemuSpawnError> {
    let vmstate_name = format!("file.filename={}", crate::DEFAULT_VMSTATE_FILE_NAME);
    let overlay_name = format!("file={}", crate::DEFAULT_ROOT_OVERLAY_FILE_NAME);
    let mut vmstate_count = 0;
    let mut overlay_count = 0;
    let mut rewritten = Vec::with_capacity(args.len() + 6);

    rewritten.extend([
        String::from("-add-fd"),
        format!("fd={QEMU_VMSTATE_LAUNCH_FD},set=1,opaque=crucible-vmstate"),
    ]);
    if has_overlay {
        rewritten.extend([
            String::from("-add-fd"),
            format!(
                "fd={QEMU_ROOT_OVERLAY_READ_LAUNCH_FD},set=2,opaque=crucible-root-overlay-read"
            ),
            String::from("-add-fd"),
            format!(
                "fd={QEMU_ROOT_OVERLAY_WRITE_LAUNCH_FD},set=2,opaque=crucible-root-overlay-write"
            ),
        ]);
    }

    for arg in args {
        let mut value = arg.clone();
        if value.contains(&vmstate_name) {
            vmstate_count += value.matches(&vmstate_name).count();
            value = value.replace(&vmstate_name, "file.filename=/dev/fdset/1");
        }
        if value.contains(&overlay_name) {
            overlay_count += value.matches(&overlay_name).count();
            value = value.replace(&overlay_name, "file=/dev/fdset/2");
        }
        rewritten.push(value);
    }

    if vmstate_count != 1 || overlay_count != usize::from(has_overlay) {
        return Err(invalid_input(
            "bind guarded QEMU block roots",
            "canonical VMState or root-overlay launch path is missing or duplicated",
        ));
    }
    Ok(rewritten)
}

fn create_spawn_resources(
    region_len: u64,
) -> Result<(QemuSpawnHostResources, QemuSpawnChildResources), QemuSpawnError> {
    if region_len == 0 {
        return Err(QemuSpawnError::RegionLengthZero);
    }

    let (host_control, child_control) = socket_pair()?;
    let child_control =
        duplicate_cloexec_fd(child_control.as_raw_fd(), "duplicate plugin control fd")?;
    let host_shmem = memfd_region(region_len)?;
    let child_shmem = duplicate_cloexec_fd(host_shmem.as_raw_fd(), "duplicate shmem fd")?;
    let host_wake = event_fd()?;
    let child_wake = duplicate_cloexec_fd(host_wake.as_raw_fd(), "duplicate wake fd")?;

    Ok((
        QemuSpawnHostResources {
            control_socket: host_control,
            shmem_fd: host_shmem,
            wake_fd: host_wake,
            region_len,
            fault_node_hash: [0; 32],
        },
        QemuSpawnChildResources {
            control_socket: child_control,
            shmem_fd: child_shmem,
            wake_fd: child_wake,
        },
    ))
}

#[cfg(test)]
/// Creates host setup resources and the child-side control socket for tests.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when descriptor setup fails or `region_len` is
/// zero.
pub(crate) fn create_test_spawn_resource_pair(
    region_len: u64,
) -> Result<(QemuSpawnHostResources, UnixStream), QemuSpawnError> {
    let (mut host_resources, child_resources) = create_spawn_resources(region_len)?;
    host_resources.fault_node_hash = crate::qemu_fault_target_hash("standalone-vm-slot-0");
    Ok((
        host_resources,
        UnixStream::from(child_resources.control_socket),
    ))
}

fn spawn_process_with_resources(
    executable: &str,
    args: &[String],
    run_directory: &QemuPreparedRunDirectory,
    child_resources: QemuSpawnChildResources,
    image_pins: &GuardedLaunchImagePins,
    envs: &[(&str, &str)],
    process_contract: Option<&QemuChildProcessContract>,
) -> Result<Child, QemuSpawnError> {
    let control_fd = child_resources.control_socket.as_raw_fd();
    let shmem_fd = child_resources.shmem_fd.as_raw_fd();
    let wake_fd = child_resources.wake_fd.as_raw_fd();
    let expected_parent_pid = unsafe {
        // SAFETY: `getpid` has no preconditions.
        libc::getpid()
    };
    let process_contract = process_contract.map(|contract| ChildProcessContractRaw {
        cgroup_procs: contract.cgroup_procs.as_raw_fd(),
        cancellation_event: contract.cancellation_event.as_raw_fd(),
        maximum_file_bytes: contract.maximum_writable_bytes,
        credentials: contract.credentials,
    });
    let pinned_run_directory = PreparedRunDirectoryRaw {
        directory: run_directory.directory.as_raw_fd(),
        vmstate_device: run_directory.vmstate_identity.device,
        vmstate_inode: run_directory.vmstate_identity.inode,
    };
    let vmstate_fd = image_pins.vmstate.as_raw_fd();
    let overlay_fds = image_pins
        .overlay
        .as_ref()
        .map(|overlay| (overlay.read.as_raw_fd(), overlay.write.as_raw_fd()));

    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (key, value) in envs {
        command.env(key, value);
    }

    // SAFETY: the closure only calls async-signal-safe syscalls between fork
    // and exec: `write`, `poll`, `setrlimit`, `openat`, `fstat`, `fchdir`, raw
    // credential syscalls, `prctl`, `getppid`, `dup2`, and `close`. It captures
    // only integers and raw descriptor numbers, not heap-owning Rust values.
    unsafe {
        command.pre_exec(move || {
            if let Some(contract) = process_contract {
                install_attempt_process_contract(contract)?;
            }
            install_prepared_run_directory(pinned_run_directory)?;
            if let Some(credentials) = process_contract.and_then(|contract| contract.credentials) {
                install_child_credentials(credentials)?;
            }
            install_child_process_contract(control_fd, shmem_fd, wake_fd, expected_parent_pid)?;
            install_guarded_launch_image_pins(vmstate_fd, overlay_fds)
        });
    }

    command.spawn().map_err(|source| QemuSpawnError::Io {
        operation: "spawn guarded QEMU child",
        source,
    })
}

/// Runs the stopped QEMU setup probe through an admitted attempt contract.
///
/// The probe uses the exact descriptor-pinned launch directory and child
/// credentials of the eventual VM. Its input, lifetime, and two diagnostic
/// streams are bounded. A helper that cannot be synchronously reaped remains
/// owned by the returned error for transfer to the attempt resource owner.
pub(crate) fn run_guarded_qemu_setup_probe(
    launch: &QemuLaunchCommand,
    args: &[String],
    input: &[u8],
    maximum_output_bytes: usize,
    timeout: Duration,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
) -> Result<Output, QemuGuardedImagePreparationError> {
    if let Err(source) = run_directory
        .validate_launch_basis(launch, process_contract)
        .and_then(|()| run_directory.revalidate())
    {
        return Err(QemuGuardedImagePreparationError {
            source,
            child: None,
        });
    }

    let deadline = HostSupervisionDeadline::start(timeout);
    let mut command = Command::new(launch.executable());
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    install_guarded_helper_authority(&mut command, run_directory, process_contract);

    let mut child = command
        .spawn()
        .map_err(|source| QemuGuardedImagePreparationError {
            source: QemuSpawnError::Io {
                operation: "spawn guarded QEMU setup probe",
                source,
            },
            child: None,
        })?;
    let child_stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            return Err(cleanup_missing_guarded_probe_pipe(
                child,
                "open guarded QEMU probe stdin",
            ));
        }
    };
    let child_stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return Err(cleanup_missing_guarded_probe_pipe(
                child,
                "open guarded QEMU probe stdout",
            ));
        }
    };
    let child_stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return Err(cleanup_missing_guarded_probe_pipe(
                child,
                "open guarded QEMU probe stderr",
            ));
        }
    };

    if let Err(source) = nonblocking_probe_pipe(&child_stdin)
        .and_then(|()| nonblocking_probe_pipe(&child_stdout))
        .and_then(|()| nonblocking_probe_pipe(&child_stderr))
    {
        return Err(cleanup_failed_image_tool(QemuNodeChild::new(child), source));
    }

    let mut stdin = (!input.is_empty()).then_some(child_stdin);
    let mut stdout = child_stdout;
    let mut stderr = child_stderr;
    let mut written = 0;
    let mut stdout_capture = ProbeCapture::new(maximum_output_bytes);
    let mut stderr_capture = ProbeCapture::new(maximum_output_bytes);
    let mut child = QemuNodeChild::new(child);
    let mut status = None;

    loop {
        if !deadline.has_time_remaining() {
            return Err(cleanup_failed_image_tool(
                child,
                QemuSpawnError::GuardedQemuProbeTimeout,
            ));
        }

        let mut progressed = false;
        if let Some(pipe) = stdin.as_mut() {
            match pipe.write(&input[written..]) {
                Ok(0) => {
                    return Err(cleanup_failed_image_tool(
                        child,
                        QemuSpawnError::Io {
                            operation: "write guarded QEMU setup probe input",
                            source: io::ErrorKind::WriteZero.into(),
                        },
                    ));
                }
                Ok(count) => {
                    written += count;
                    progressed = true;
                    if written == input.len() {
                        stdin = None;
                    }
                }
                Err(error) if retryable_probe_io(&error) => {}
                Err(source) => {
                    return Err(cleanup_failed_image_tool(
                        child,
                        QemuSpawnError::Io {
                            operation: "write guarded QEMU setup probe input",
                            source,
                        },
                    ));
                }
            }
        }

        match stdout_capture.read_once(&mut stdout) {
            Ok(read_progressed) => progressed |= read_progressed,
            Err(source) => {
                return Err(cleanup_failed_image_tool(
                    child,
                    QemuSpawnError::Io {
                        operation: "read guarded QEMU setup probe stdout",
                        source,
                    },
                ));
            }
        }
        match stderr_capture.read_once(&mut stderr) {
            Ok(read_progressed) => progressed |= read_progressed,
            Err(source) => {
                return Err(cleanup_failed_image_tool(
                    child,
                    QemuSpawnError::Io {
                        operation: "read guarded QEMU setup probe stderr",
                        source,
                    },
                ));
            }
        }
        if stdout_capture.exceeded || stderr_capture.exceeded {
            return Err(cleanup_failed_image_tool(
                child,
                QemuSpawnError::GuardedQemuProbeOutputLimit {
                    maximum_bytes: maximum_output_bytes,
                },
            ));
        }

        if status.is_none() {
            match child.try_wait_natural_exit() {
                Ok(observed) => status = observed,
                Err(error) => {
                    return Err(cleanup_failed_image_tool(
                        child,
                        QemuSpawnError::Io {
                            operation: "poll guarded QEMU setup probe",
                            source: io::Error::other(error.to_string()),
                        },
                    ));
                }
            }
        }
        if stdout_capture.eof
            && stderr_capture.eof
            && stdin.is_none()
            && let Some(status) = status
        {
            return Ok(Output {
                status,
                stdout: stdout_capture.bytes,
                stderr: stderr_capture.bytes,
            });
        }

        if !progressed {
            thread::sleep(GUARDED_IMAGE_TOOL_POLL_INTERVAL);
        }
    }
}

fn install_guarded_helper_authority(
    command: &mut Command,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
) {
    let expected_parent_pid = unsafe {
        // SAFETY: `getpid` has no preconditions.
        libc::getpid()
    };
    let contract = ChildProcessContractRaw {
        cgroup_procs: process_contract.cgroup_procs.as_raw_fd(),
        cancellation_event: process_contract.cancellation_event.as_raw_fd(),
        maximum_file_bytes: process_contract.maximum_writable_bytes,
        credentials: process_contract.credentials,
    };
    let directory = PreparedRunDirectoryRaw {
        directory: run_directory.directory.as_raw_fd(),
        vmstate_device: run_directory.vmstate_identity.device,
        vmstate_inode: run_directory.vmstate_identity.inode,
    };
    unsafe {
        // SAFETY: the closure uses only async-signal-safe scalar syscalls and
        // captures raw descriptor numbers plus copyable credentials.
        command.pre_exec(move || {
            install_attempt_process_contract(contract)?;
            install_prepared_run_directory(directory)?;
            if let Some(credentials) = contract.credentials {
                install_child_credentials(credentials)?;
            }
            set_parent_death_signal(expected_parent_pid)
        });
    }
}

fn cleanup_missing_guarded_probe_pipe(
    child: Child,
    operation: &'static str,
) -> QemuGuardedImagePreparationError {
    cleanup_failed_image_tool(
        QemuNodeChild::new(child),
        QemuSpawnError::Io {
            operation,
            source: io::Error::other("configured pipe was unavailable"),
        },
    )
}

struct ProbeCapture {
    bytes: Vec<u8>,
    maximum_bytes: usize,
    exceeded: bool,
    eof: bool,
}

impl ProbeCapture {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum_bytes.min(64 * 1024)),
            maximum_bytes,
            exceeded: false,
            eof: false,
        }
    }

    // One read per iteration prevents a flooding stream from starving the
    // deadline, the monitor request, or the other diagnostic stream.
    fn read_once(&mut self, reader: &mut impl Read) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let mut buffer = [0_u8; 16 * 1024];
        match reader.read(&mut buffer) {
            Ok(0) => {
                self.eof = true;
                Ok(true)
            }
            Ok(count) => {
                let retained = count.min(self.maximum_bytes.saturating_sub(self.bytes.len()));
                self.bytes.extend_from_slice(&buffer[..retained]);
                self.exceeded |= retained != count;
                Ok(true)
            }
            Err(error) if retryable_probe_io(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

fn nonblocking_probe_pipe(pipe: &impl AsFd) -> Result<(), QemuSpawnError> {
    fcntl_getfl(pipe)
        .and_then(|flags| fcntl_setfl(pipe, flags | OFlags::NONBLOCK))
        .map_err(|source| QemuSpawnError::Io {
            operation: "configure guarded QEMU probe pipe",
            source: source.into(),
        })
}

fn retryable_probe_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn run_guarded_image_tool(
    executable: &Path,
    args: &[std::ffi::OsString],
    operation: &'static str,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
) -> Result<(), QemuGuardedImagePreparationError> {
    if let Err(source) = run_directory.validate_helper_basis(process_contract) {
        return Err(QemuGuardedImagePreparationError {
            source,
            child: None,
        });
    }
    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    install_guarded_helper_authority(&mut command, run_directory, process_contract);
    let child = command
        .spawn()
        .map_err(|source| QemuGuardedImagePreparationError {
            source: QemuSpawnError::Io { operation, source },
            child: None,
        })?;
    let mut child = QemuNodeChild::new(child);
    let deadline = HostSupervisionDeadline::start(GUARDED_IMAGE_TOOL_TIMEOUT);
    loop {
        match child.try_wait_natural_exit() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(QemuGuardedImagePreparationError {
                    source: QemuSpawnError::GuardedImageTool {
                        operation,
                        status: status.to_string(),
                    },
                    child: None,
                });
            }
            Ok(None) if deadline.has_time_remaining() => {
                thread::sleep(GUARDED_IMAGE_TOOL_POLL_INTERVAL)
            }
            Ok(None) => {
                return Err(cleanup_failed_image_tool(
                    child,
                    QemuSpawnError::GuardedImageToolTimeout { operation },
                ));
            }
            Err(error) => {
                return Err(cleanup_failed_image_tool(
                    child,
                    QemuSpawnError::Io {
                        operation,
                        source: io::Error::other(error.to_string()),
                    },
                ));
            }
        }
    }
}

fn cleanup_failed_image_tool(
    mut child: QemuNodeChild,
    source: QemuSpawnError,
) -> QemuGuardedImagePreparationError {
    match child.force_kill_and_reap_failed_helper(GUARDED_IMAGE_TOOL_REAP_TIMEOUT) {
        Ok(()) => QemuGuardedImagePreparationError {
            source,
            child: None,
        },
        Err(_) => QemuGuardedImagePreparationError {
            source,
            child: Some(child),
        },
    }
}

#[derive(Clone, Copy)]
struct ChildProcessContractRaw {
    cgroup_procs: RawFd,
    cancellation_event: RawFd,
    maximum_file_bytes: u64,
    credentials: Option<QemuChildCredentials>,
}

#[derive(Clone, Copy)]
struct PreparedRunDirectoryRaw {
    directory: RawFd,
    vmstate_device: u128,
    vmstate_inode: u128,
}

fn install_prepared_run_directory(directory: PreparedRunDirectoryRaw) -> io::Result<()> {
    let changed = || io::Error::from_raw_os_error(libc::ESTALE);
    let changed_directory = unsafe {
        // SAFETY: `directory` is the live retained directory descriptor
        // captured by the parent. `fchdir` copies no Rust-owned memory.
        libc::fchdir(directory.directory)
    };
    if changed_directory != 0 {
        return Err(io::Error::last_os_error());
    }
    let vmstate = unsafe {
        // SAFETY: the static filename is NUL-terminated and `directory` names
        // the retained run directory. `openat` returns a new child-owned fd.
        libc::openat(
            directory.directory,
            VMSTATE_FILE_NAME_C.as_ptr().cast(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if vmstate < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let inspected = unsafe {
        // SAFETY: `metadata` points to writable storage for one stat and
        // `vmstate` is the live descriptor returned above.
        libc::fstat(vmstate, metadata.as_mut_ptr())
    };
    let inspect_error = (inspected != 0).then(io::Error::last_os_error);
    let close_result = unsafe {
        // SAFETY: `vmstate` is owned by this child-side function.
        libc::close(vmstate)
    };
    if let Some(error) = inspect_error {
        return Err(error);
    }
    if close_result != 0 {
        return Err(io::Error::last_os_error());
    }
    let metadata = unsafe {
        // SAFETY: successful fstat initialized the complete structure.
        metadata.assume_init()
    };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || u128::from(metadata.st_dev) != directory.vmstate_device
        || u128::from(metadata.st_ino) != directory.vmstate_inode
    {
        return Err(changed());
    }
    Ok(())
}

fn install_guarded_launch_image_pins(
    vmstate: RawFd,
    overlay: Option<(RawFd, RawFd)>,
) -> io::Result<()> {
    dup_to_fixed_child_fd(vmstate, QEMU_VMSTATE_LAUNCH_FD)?;
    if let Some((read, write)) = overlay {
        dup_to_fixed_child_fd(read, QEMU_ROOT_OVERLAY_READ_LAUNCH_FD)?;
        dup_to_fixed_child_fd(write, QEMU_ROOT_OVERLAY_WRITE_LAUNCH_FD)?;
    }
    close_child_source_fd(vmstate)?;
    if let Some((read, write)) = overlay {
        close_child_source_fd(read)?;
        close_child_source_fd(write)?;
    }
    Ok(())
}

fn install_attempt_process_contract(contract: ChildProcessContractRaw) -> io::Result<()> {
    let attached = unsafe {
        // SAFETY: `cgroup_procs` is a live descriptor supplied by the parent,
        // and the static two-byte buffer remains valid for the syscall.
        libc::write(
            contract.cgroup_procs,
            CGROUP_ATTACH_SELF.as_ptr().cast(),
            CGROUP_ATTACH_SELF.len(),
        )
    };
    if attached < 0 {
        return Err(io::Error::last_os_error());
    }
    if attached != 2 {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }

    let mut cancellation = libc::pollfd {
        fd: contract.cancellation_event,
        events: libc::POLLIN,
        revents: 0,
    };
    let canceled = unsafe {
        // SAFETY: `cancellation` points to one initialized pollfd. A zero
        // timeout performs a non-consuming readiness query.
        libc::poll(&mut cancellation, 1, 0)
    };
    if canceled > 0 && cancellation.revents & libc::POLLIN != 0 {
        return Err(io::Error::from_raw_os_error(libc::ECANCELED));
    }
    if canceled < 0 {
        return Err(io::Error::last_os_error());
    }
    if cancellation.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }

    let file_limit = libc::rlimit {
        rlim_cur: contract.maximum_file_bytes,
        rlim_max: contract.maximum_file_bytes,
    };
    let limited = unsafe {
        // SAFETY: `file_limit` is initialized and `setrlimit` copies it during
        // this async-signal-safe syscall.
        libc::setrlimit(libc::RLIMIT_FSIZE, &file_limit)
    };
    if limited != 0 {
        return Err(io::Error::last_os_error());
    }
    let no_new_privileges = unsafe {
        // SAFETY: PR_SET_NO_NEW_PRIVS takes scalar arguments and permanently
        // prevents this child from regaining privilege across exec.
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    };
    if no_new_privileges != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn install_child_credentials(credentials: QemuChildCredentials) -> io::Result<()> {
    let groups_cleared = unsafe {
        // SAFETY: the raw Linux syscall receives a zero count and null array,
        // so it removes every supplementary group without dereferencing data.
        libc::syscall(
            libc::SYS_setgroups,
            0_usize,
            std::ptr::null::<libc::gid_t>(),
        )
    };
    if groups_cleared != 0 {
        return Err(io::Error::last_os_error());
    }
    let group_changed = unsafe {
        // SAFETY: the raw Linux syscall takes three scalar group IDs.
        libc::syscall(
            libc::SYS_setresgid,
            credentials.group_id,
            credentials.group_id,
            credentials.group_id,
        )
    };
    if group_changed != 0 {
        return Err(io::Error::last_os_error());
    }
    let user_changed = unsafe {
        // SAFETY: the raw Linux syscall takes three scalar user IDs.
        libc::syscall(
            libc::SYS_setresuid,
            credentials.user_id,
            credentials.user_id,
            credentials.user_id,
        )
    };
    if user_changed != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn validate_cgroup_procs_fd(fd: &OwnedFd) -> Result<(), QemuSpawnError> {
    validate_live_fd(fd.as_raw_fd(), "validate child cgroup descriptor")?;
    let filesystem = fstatfs(fd).map_err(|source| QemuSpawnError::Io {
        operation: "inspect child cgroup filesystem",
        source: source.into(),
    })?;
    if filesystem.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(QemuSpawnError::Io {
            operation: "validate child cgroup filesystem",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "cgroup.procs descriptor is not on cgroup v2",
            ),
        });
    }
    let target = fs::read_link(PathBuf::from("/proc/self/fd").join(fd.as_raw_fd().to_string()))
        .map_err(|source| QemuSpawnError::Io {
            operation: "resolve child cgroup descriptor",
            source,
        })?;
    if target.file_name().and_then(|name| name.to_str()) != Some("cgroup.procs") {
        return Err(QemuSpawnError::Io {
            operation: "validate child cgroup descriptor target",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "child cgroup descriptor does not name cgroup.procs",
            ),
        });
    }
    Ok(())
}

fn validate_cgroup_directory_fd(fd: &OwnedFd) -> Result<(), QemuSpawnError> {
    validate_live_fd(fd.as_raw_fd(), "validate child cgroup directory")?;
    let filesystem = fstatfs(fd).map_err(|source| QemuSpawnError::Io {
        operation: "inspect child cgroup directory filesystem",
        source: source.into(),
    })?;
    let metadata = fstat(fd).map_err(|source| QemuSpawnError::Io {
        operation: "inspect child cgroup directory",
        source: source.into(),
    })?;
    if filesystem.f_type != libc::CGROUP2_SUPER_MAGIC
        || FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_dev == 0
        || metadata.st_ino == 0
    {
        return Err(QemuSpawnError::Io {
            operation: "validate child cgroup directory",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "child cgroup directory is not a cgroup-v2 directory",
            ),
        });
    }
    Ok(())
}

fn validate_cancellation_eventfd(fd: RawFd) -> Result<(), QemuSpawnError> {
    let flags = validate_live_fd(fd, "validate child cancellation descriptor")?;
    if flags & libc::O_NONBLOCK == 0 {
        return Err(QemuSpawnError::Io {
            operation: "validate child cancellation descriptor flags",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "child cancellation eventfd is blocking",
            ),
        });
    }
    let target =
        fs::read_link(PathBuf::from("/proc/self/fd").join(fd.to_string())).map_err(|source| {
            QemuSpawnError::Io {
                operation: "resolve child cancellation descriptor",
                source,
            }
        })?;
    if target.to_string_lossy() != "anon_inode:[eventfd]" {
        return Err(QemuSpawnError::Io {
            operation: "validate child cancellation descriptor target",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "child cancellation descriptor is not an eventfd",
            ),
        });
    }
    Ok(())
}

fn validate_live_fd(fd: RawFd, operation: &'static str) -> Result<i32, QemuSpawnError> {
    let flags = unsafe {
        // SAFETY: `fcntl(F_GETFL)` reads descriptor metadata without pointers.
        libc::fcntl(fd, libc::F_GETFL)
    };
    if flags < 0 {
        return Err(last_io_error(operation));
    }
    Ok(flags)
}

fn socket_pair() -> Result<(OwnedFd, OwnedFd), QemuSpawnError> {
    let mut fds = [-1; 2];
    let result = unsafe {
        // SAFETY: `fds` points to two writable RawFd slots for `socketpair`.
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(last_io_error("create plugin control socketpair"));
    }
    let host = owned_fd_from_raw(fds[0]);
    let child = owned_fd_from_raw(fds[1]);
    Ok((host, child))
}

/// Creates one writable, shrink-sealed setup-region memfd.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when the length is not representable or the
/// memfd cannot be created, sized, or sealed.
pub(crate) fn memfd_region(region_len: u64) -> Result<OwnedFd, QemuSpawnError> {
    let region_len = libc::off_t::try_from(region_len)
        .map_err(|_| QemuSpawnError::RegionLengthTooLarge { region_len })?;
    let name = CString::new("crucible-qemu-shmem").map_err(|source| QemuSpawnError::Io {
        operation: "build memfd name",
        source: io::Error::new(io::ErrorKind::InvalidInput, source),
    })?;
    let fd = unsafe {
        // SAFETY: `name` is a valid NUL-terminated C string.
        libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
    };
    if fd < 0 {
        return Err(last_io_error("create shmem memfd"));
    }
    let fd = owned_fd_from_raw(fd);
    let truncate = unsafe {
        // SAFETY: `fd` is a live memfd, and `region_len` was range-checked.
        libc::ftruncate(fd.as_raw_fd(), region_len)
    };
    if truncate != 0 {
        return Err(last_io_error("size shmem memfd"));
    }
    let seal = unsafe {
        // SAFETY: `fd` is a live sealable memfd. The shrink seal preserves the
        // mapping length while still permitting shared-memory writes.
        libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_SHRINK)
    };
    if seal != 0 {
        return Err(last_io_error("seal shmem memfd against shrink"));
    }
    Ok(fd)
}

fn event_fd() -> Result<OwnedFd, QemuSpawnError> {
    let fd = unsafe {
        // SAFETY: `eventfd` has no pointer arguments; flags request close-on-exec.
        libc::eventfd(0, libc::EFD_CLOEXEC)
    };
    if fd < 0 {
        return Err(last_io_error("create wake eventfd"));
    }
    Ok(owned_fd_from_raw(fd))
}

fn duplicate_cloexec_fd(fd: RawFd, operation: &'static str) -> Result<OwnedFd, QemuSpawnError> {
    let duplicated = unsafe {
        // SAFETY: `fcntl` reads a live fd and returns a new fd on success.
        libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, CHILD_SOURCE_FD_MIN)
    };
    if duplicated < 0 {
        return Err(last_io_error(operation));
    }
    Ok(owned_fd_from_raw(duplicated))
}

fn install_child_process_contract(
    control_fd: RawFd,
    shmem_fd: RawFd,
    wake_fd: RawFd,
    expected_parent_pid: libc::pid_t,
) -> io::Result<()> {
    set_parent_death_signal(expected_parent_pid)?;
    dup_to_fixed_child_fd(control_fd, QEMU_PLUGIN_CONTROL_FD)?;
    dup_to_fixed_child_fd(shmem_fd, QEMU_PLUGIN_SHMEM_FD)?;
    dup_to_fixed_child_fd(wake_fd, QEMU_PLUGIN_WAKE_FD)?;
    close_child_source_fd(control_fd)?;
    close_child_source_fd(shmem_fd)?;
    close_child_source_fd(wake_fd)
}

fn set_parent_death_signal(expected_parent_pid: libc::pid_t) -> io::Result<()> {
    let result = unsafe {
        // SAFETY: `prctl` is called with integer arguments only.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0)
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    let current_parent = unsafe {
        // SAFETY: `getppid` has no preconditions.
        libc::getppid()
    };
    if current_parent == expected_parent_pid {
        Ok(())
    } else {
        // Abort when the "parent changed before child exec" race is observed.
        Err(io::Error::from_raw_os_error(libc::ECHILD))
    }
}

fn dup_to_fixed_child_fd(source_fd: RawFd, target_fd: RawFd) -> io::Result<()> {
    let result = unsafe {
        // SAFETY: both arguments are descriptor numbers; `dup2` validates them.
        libc::dup2(source_fd, target_fd)
    };
    if result == target_fd {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn close_child_source_fd(fd: RawFd) -> io::Result<()> {
    let result = unsafe {
        // SAFETY: `fd` is a descriptor number owned by the post-fork child.
        libc::close(fd)
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn owned_fd_from_raw(fd: RawFd) -> OwnedFd {
    unsafe {
        // SAFETY: callers pass a newly returned descriptor that is uniquely owned.
        OwnedFd::from_raw_fd(fd)
    }
}

fn last_io_error(operation: &'static str) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation,
        source: io::Error::last_os_error(),
    }
}

#[cfg(test)]
#[path = "spawn_test.rs"]
mod tests;
