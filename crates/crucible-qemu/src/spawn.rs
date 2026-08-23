//! Linux QEMU process spawning with fixed inherited descriptors.
//!
//! This module owns the Linux-only process boundary required by RFC-0010
//! T-QEMU-7. It creates the per-node control socket pair, shared-memory memfd,
//! and wake eventfd before `exec`, maps the child descriptors to the fixed
//! plugin fd numbers, clears the inherited host environment, and sets
//! `PR_SET_PDEATHSIG=SIGKILL` in the child.

use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustix::fs::{FileType, Mode, OFlags, fstat, fsync, open, openat};
use thiserror::Error;

use crate::{
    QEMU_PLUGIN_CONTROL_FD, QEMU_PLUGIN_SHMEM_FD, QEMU_PLUGIN_WAKE_FD, QemuLaunchCommand,
    QemuNodeChild,
};

mod materialization;
use materialization::{PreparedRootOverlayMaterialization, PreparedVmStateMaterialization};
pub use materialization::{
    QemuRootOverlayMaterialization, QemuVmStateBinding, QemuVmStateMaterialization,
};

const CHILD_SOURCE_FD_MIN: RawFd = QEMU_PLUGIN_WAKE_FD + 1;
const CGROUP_ATTACH_SELF: &[u8] = b"0\n";
const MAX_SUPERVISOR_GROUPS: usize = 65_536;
const VMSTATE_FILE_NAME_C: &[u8] = b"crucible-vmstate.qcow2\0";
const GUARDED_IMAGE_TOOL_TIMEOUT: Duration = Duration::from_secs(60);
const GUARDED_IMAGE_TOOL_REAP_TIMEOUT: Duration = Duration::from_secs(5);
const GUARDED_IMAGE_TOOL_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Owned pre-exec contract for one attempt-contained child process.
///
/// The cgroup descriptor names the attempt's `cgroup.procs` file. The
/// cancellation descriptor is a nonblocking eventfd that becomes readable
/// once cancellation wins. Both descriptors must be opened by the supervising
/// resource guard and remain owned by that guard independently of this
/// per-spawn duplicate. A production contract also carries validated non-root
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
    cgroup_procs: OwnedFd,
    cancellation_event: OwnedFd,
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_writable_bytes: u64,
    credentials: Option<QemuChildCredentials>,
    attempt_binding: Arc<AttemptResourceBinding>,
}

/// Pinned authority over one pre-provisioned QEMU run directory.
///
/// The authority opens the directory without following a final symlink and
/// retains the exact regular VMState file and optional writable root overlay
/// named inside it. Guarded spawn uses the directory descriptor for `fchdir`
/// and reauthenticates every required named artifact immediately before
/// `exec`. It also retains the exact admitted command resource profile and
/// contract ceiling. Replacement of the diagnostic path, replacement of a
/// retained artifact before that boundary, or reuse under a different resource
/// admission or attempt lifecycle therefore fails closed.
/// This authority does not make the directory namespace immutable: the
/// production supervisor must exclude concurrent mutators until QEMU has
/// opened every relative launch artifact and must enforce the separate
/// aggregate quota.
#[derive(Debug)]
#[must_use = "guarded QEMU launch requires the pinned run-directory authority"]
pub struct QemuPreparedRunDirectory {
    path: PathBuf,
    directory: OwnedFd,
    directory_identity: PinnedFileIdentity,
    vmstate: OwnedFd,
    vmstate_identity: PinnedFileIdentity,
    root_overlay: Option<OwnedFd>,
    root_overlay_identity: Option<PinnedFileIdentity>,
    launch_resources: crate::QemuLaunchResourceRequirements,
    admitted_ceiling: (u32, u64, u64),
    child_credentials: Option<QemuChildCredentials>,
    attempt_binding: Arc<AttemptResourceBinding>,
    vmstate_materialization: PreparedVmStateMaterialization,
    root_overlay_materialization: PreparedRootOverlayMaterialization,
}

/// Reopen-independent read capability for one reaped QEMU VMState artifact.
///
/// The capability exposes bounded positional reads only. It carries no run-
/// directory, mutation, quota, or process authority and remains readable after
/// the attempt owner unlinks its private run-directory artifacts.
#[derive(Debug)]
pub struct QemuCapturedVmState {
    file: File,
    logical_length: u64,
}

impl QemuCapturedVmState {
    /// Builds an unvalidated captured source for cross-crate conformance tests.
    ///
    /// Production code can obtain this capability only from the post-reap
    /// realization executor.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn from_unvalidated_test_file(file: File, logical_length: u64) -> Self {
        Self {
            file,
            logical_length,
        }
    }

    /// Returns the exact stable byte length attested after process reap.
    #[must_use]
    pub const fn logical_length(&self) -> u64 {
        self.logical_length
    }

    /// Reads bytes at one absolute artifact offset without shared cursor state.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the retained inode cannot be read.
    pub fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        self.file.read_at(buffer, offset)
    }
}

#[derive(Debug)]
struct AttemptResourceBinding;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PinnedFileIdentity {
    device: u128,
    inode: u128,
}

impl PinnedFileIdentity {
    fn from_stat(metadata: &rustix::fs::Stat) -> Self {
        Self {
            device: u128::from(metadata.st_dev),
            inode: u128::from(metadata.st_ino),
        }
    }

    fn matches(self, metadata: &rustix::fs::Stat) -> bool {
        self == Self::from_stat(metadata)
    }
}

impl QemuPreparedRunDirectory {
    /// Admits and opens one pre-provisioned run directory for a launch profile.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] before path access when the command exceeds
    /// the contract's admitted resources. Otherwise returns an error when the
    /// path cannot be opened without following a final symlink, does not name
    /// a directory, or lacks the required regular non-symlink VMState file.
    pub fn open_for_launch(
        command: &QemuLaunchCommand,
        path: impl AsRef<Path>,
        contract: &QemuChildProcessContract,
    ) -> Result<Self, QemuSpawnError> {
        Self::open_for_requirements(command.resource_requirements(), path.as_ref(), contract)
    }

    pub(crate) fn open_for_requirements(
        requirements: crate::QemuLaunchResourceRequirements,
        path: &Path,
        contract: &QemuChildProcessContract,
    ) -> Result<Self, QemuSpawnError> {
        validate_guarded_launch_requirements(requirements, contract)?;
        let path = path.to_owned();
        let directory = open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "pin prepared QEMU run directory",
            source: source.into(),
        })?;
        let vmstate = open_prepared_vmstate(&directory, &path)?;
        Self::from_admitted_descriptors(requirements, &path, directory, vmstate, contract)
    }

    /// Constructs one prepared authority from already-pinned storage descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the launch profile exceeds the process
    /// contract or either descriptor has the wrong file type.
    pub(crate) fn from_admitted_descriptors(
        requirements: crate::QemuLaunchResourceRequirements,
        path: &Path,
        directory: OwnedFd,
        vmstate: OwnedFd,
        contract: &QemuChildProcessContract,
    ) -> Result<Self, QemuSpawnError> {
        validate_guarded_launch_requirements(requirements, contract)?;

        let directory_metadata = fstat(&directory).map_err(|source| QemuSpawnError::Io {
            operation: "inspect prepared QEMU run directory",
            source: source.into(),
        })?;
        if FileType::from_raw_mode(directory_metadata.st_mode) != FileType::Directory {
            return Err(invalid_input(
                "validate prepared QEMU run directory",
                "prepared QEMU run path is not a directory",
            ));
        }
        let vmstate_metadata = fstat(&vmstate).map_err(|source| QemuSpawnError::Io {
            operation: "inspect prepared exact-VMState container",
            source: source.into(),
        })?;
        if FileType::from_raw_mode(vmstate_metadata.st_mode) != FileType::RegularFile {
            return Err(invalid_input(
                "validate prepared exact-VMState container",
                "exact-VMState container path is not a regular file",
            ));
        }
        let root_overlay = open_optional_root_overlay(&directory)?;
        let root_overlay_metadata =
            root_overlay
                .as_ref()
                .map(fstat)
                .transpose()
                .map_err(|source| QemuSpawnError::Io {
                    operation: "inspect prepared root overlay",
                    source: source.into(),
                })?;
        if root_overlay_metadata.as_ref().is_some_and(|metadata| {
            FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        }) {
            return Err(invalid_input(
                "validate prepared root overlay",
                "prepared root overlay path is not a regular file",
            ));
        }
        let root_overlay_identity = root_overlay_metadata
            .as_ref()
            .map(PinnedFileIdentity::from_stat);

        Ok(Self {
            path: path.to_owned(),
            directory_identity: PinnedFileIdentity::from_stat(&directory_metadata),
            directory,
            vmstate_identity: PinnedFileIdentity::from_stat(&vmstate_metadata),
            vmstate,
            root_overlay_materialization: if root_overlay.is_some() {
                PreparedRootOverlayMaterialization::Provisioned
            } else {
                PreparedRootOverlayMaterialization::Absent
            },
            root_overlay,
            root_overlay_identity,
            launch_resources: requirements,
            admitted_ceiling: contract.admitted_resource_ceiling(),
            child_credentials: contract.credentials,
            attempt_binding: Arc::clone(&contract.attempt_binding),
            vmstate_materialization: PreparedVmStateMaterialization::Provisioned,
        })
    }

    /// Returns the original run-directory path for diagnostics only.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn revalidate(&self) -> Result<(), QemuSpawnError> {
        if self.vmstate_materialization == PreparedVmStateMaterialization::Updating {
            return Err(QemuSpawnError::PreparedVmStateNotReady {
                path: self.path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
            });
        }
        let retained_vmstate = self.revalidate_identity()?;
        if self.root_overlay_materialization == PreparedRootOverlayMaterialization::Updating {
            return Err(QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        if self.launch_resources.has_root_overlay()
            && self.root_overlay_materialization == PreparedRootOverlayMaterialization::Absent
        {
            return Err(QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        if let PreparedVmStateMaterialization::Exact { bytes, .. } = self.vmstate_materialization {
            let actual = u64::try_from(retained_vmstate.st_size).unwrap_or(u64::MAX);
            if actual != bytes {
                return Err(QemuSpawnError::PreparedVmStateIncomplete {
                    expected: bytes,
                    actual,
                });
            }
        }
        if let PreparedRootOverlayMaterialization::Exact { bytes, .. } =
            self.root_overlay_materialization
        {
            let retained = self.revalidate_root_overlay_identity()?;
            let actual = u64::try_from(retained.st_size).unwrap_or(u64::MAX);
            if actual != bytes {
                return Err(QemuSpawnError::PreparedRootOverlayIncomplete {
                    expected: bytes,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn revalidate_identity(&self) -> Result<rustix::fs::Stat, QemuSpawnError> {
        let directory_metadata = fstat(&self.directory).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect prepared QEMU run directory",
            source: source.into(),
        })?;
        if !self.directory_identity.matches(&directory_metadata) {
            return Err(QemuSpawnError::PreparedRunDirectoryChanged {
                path: self.path.clone(),
            });
        }
        let retained_vmstate = fstat(&self.vmstate).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect retained exact-VMState container",
            source: source.into(),
        })?;
        if !self.vmstate_identity.matches(&retained_vmstate) {
            return Err(QemuSpawnError::PreparedVmStateChanged {
                path: self.path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
            });
        }
        let named_vmstate = open_prepared_vmstate(&self.directory, &self.path)?;
        let named_metadata = fstat(&named_vmstate).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect named exact-VMState container",
            source: source.into(),
        })?;
        if !self.vmstate_identity.matches(&named_metadata) {
            return Err(QemuSpawnError::PreparedVmStateChanged {
                path: self.path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
            });
        }
        Ok(retained_vmstate)
    }

    fn revalidate_root_overlay_identity(&self) -> Result<rustix::fs::Stat, QemuSpawnError> {
        let retained = self.root_overlay.as_ref().ok_or_else(|| {
            QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            }
        })?;
        let identity = self.root_overlay_identity.ok_or_else(|| {
            QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            }
        })?;
        let retained_metadata = fstat(retained).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect retained root overlay",
            source: source.into(),
        })?;
        if !identity.matches(&retained_metadata) {
            return Err(QemuSpawnError::PreparedRootOverlayChanged {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        let named = open_prepared_root_overlay(&self.directory, &self.path)?;
        let named_metadata = fstat(&named).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect named root overlay",
            source: source.into(),
        })?;
        if !identity.matches(&named_metadata) {
            return Err(QemuSpawnError::PreparedRootOverlayChanged {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        Ok(retained_metadata)
    }

    /// Seals a positional read capability after the owning QEMU process is reaped.
    ///
    /// This method is crate-private so only the realization executor can invoke
    /// it after its active-node shutdown attestation. It intentionally accepts
    /// a file whose length changed through a completed QEMU `savevm` operation;
    /// ordinary launch revalidation continues to require the prior exact length.
    pub(crate) fn capture_vmstate_after_reap(&self) -> Result<QemuCapturedVmState, QemuSpawnError> {
        if self.vmstate_materialization == PreparedVmStateMaterialization::Updating {
            return Err(QemuSpawnError::PreparedVmStateNotReady {
                path: self.path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
            });
        }
        let before = self.revalidate_identity()?;
        let logical_length =
            u64::try_from(before.st_size).map_err(|_| QemuSpawnError::PreparedVmStateLength {
                length: u64::MAX,
                maximum: self.admitted_ceiling.2,
            })?;
        if logical_length == 0 || logical_length > self.admitted_ceiling.2 {
            return Err(QemuSpawnError::PreparedVmStateLength {
                length: logical_length,
                maximum: self.admitted_ceiling.2,
            });
        }
        fsync(&self.vmstate).map_err(|source| QemuSpawnError::Io {
            operation: "synchronize captured exact-VMState artifact",
            source: source.into(),
        })?;
        let file = File::from(
            self.vmstate
                .try_clone()
                .map_err(|source| QemuSpawnError::Io {
                    operation: "duplicate captured exact-VMState artifact",
                    source,
                })?,
        );
        let after = fstat(&file).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect captured exact-VMState artifact",
            source: source.into(),
        })?;
        if !self.vmstate_identity.matches(&after)
            || u64::try_from(after.st_size).ok() != Some(logical_length)
        {
            return Err(QemuSpawnError::PreparedVmStateChanged {
                path: self.path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
            });
        }
        Ok(QemuCapturedVmState {
            file,
            logical_length,
        })
    }

    fn validate_launch_basis(
        &self,
        command: &QemuLaunchCommand,
        contract: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError> {
        if self.launch_resources != command.resource_requirements()
            || self.admitted_ceiling != contract.admitted_resource_ceiling()
            || !Arc::ptr_eq(&self.attempt_binding, &contract.attempt_binding)
        {
            return Err(QemuSpawnError::PreparedLaunchAdmissionChanged);
        }
        validate_guarded_launch_resources(command, contract)
    }

    fn validate_helper_basis(
        &self,
        contract: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError> {
        if self.admitted_ceiling != contract.admitted_resource_ceiling()
            || !Arc::ptr_eq(&self.attempt_binding, &contract.attempt_binding)
            || self.vmstate_materialization != PreparedVmStateMaterialization::Provisioned
            || self.root_overlay_materialization != PreparedRootOverlayMaterialization::Absent
        {
            return Err(QemuSpawnError::PreparedLaunchAdmissionChanged);
        }
        validate_guarded_launch_requirements(self.launch_resources, contract)?;
        self.revalidate_identity().map(|_| ())
    }
}

fn open_prepared_vmstate(directory: &OwnedFd, path: &Path) -> Result<OwnedFd, QemuSpawnError> {
    openat(
        directory,
        crate::DEFAULT_VMSTATE_FILE_NAME,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        let source: io::Error = source.into();
        if source.kind() == io::ErrorKind::NotFound {
            QemuSpawnError::MissingPreparedVmState {
                path: path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
            }
        } else {
            QemuSpawnError::Io {
                operation: "open prepared exact-VMState container",
                source,
            }
        }
    })
}

fn open_optional_root_overlay(directory: &OwnedFd) -> Result<Option<OwnedFd>, QemuSpawnError> {
    match openat(
        directory,
        crate::DEFAULT_ROOT_OVERLAY_FILE_NAME,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => Ok(Some(file)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(source) => Err(QemuSpawnError::Io {
            operation: "open optional prepared root overlay",
            source: source.into(),
        }),
    }
}

fn open_prepared_root_overlay(directory: &OwnedFd, path: &Path) -> Result<OwnedFd, QemuSpawnError> {
    open_optional_root_overlay(directory)?.ok_or_else(|| {
        QemuSpawnError::PreparedRootOverlayNotReady {
            path: path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
        }
    })
}

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
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
        credentials: QemuChildCredentials,
    ) -> Result<Self, QemuSpawnError> {
        validate_cgroup_procs_fd(cgroup_procs.as_raw_fd())?;
        validate_cancellation_eventfd(cancellation_event.as_raw_fd())?;
        Ok(Self {
            cgroup_procs,
            cancellation_event,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            credentials: Some(credentials),
            attempt_binding: Arc::new(AttemptResourceBinding),
        })
    }

    #[cfg(test)]
    fn for_test(
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_writable_bytes: u64,
    ) -> Self {
        Self::from_unvalidated_test_descriptors(
            cgroup_procs,
            cancellation_event,
            u32::MAX,
            u64::MAX,
            maximum_writable_bytes,
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
        Self {
            cgroup_procs,
            cancellation_event,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            credentials: None,
            attempt_binding: Arc::new(AttemptResourceBinding),
        }
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
    /// The exact-VMState qcow2 container could not be created.
    #[error("qemu-img could not create exact-VMState container {path}: {status}: {stderr}")]
    VmStateImageTool {
        /// Intended qcow2 container path.
        path: PathBuf,
        /// Process exit status rendered without host-specific structure.
        status: String,
        /// Trimmed qemu-img diagnostic output.
        stderr: String,
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
    /// The guarded run directory does not contain its pre-provisioned VMState image.
    #[error("guarded QEMU launch requires pre-provisioned VMState container {path}")]
    MissingPreparedVmState {
        /// Required exact-VMState container path.
        path: PathBuf,
    },
    /// The retained run-directory descriptor no longer names its opened inode.
    #[error("prepared QEMU run-directory identity changed: {path}")]
    PreparedRunDirectoryChanged {
        /// Original diagnostic path of the pinned directory.
        path: PathBuf,
    },
    /// The VMState name no longer resolves to the retained regular file.
    #[error("prepared exact-VMState identity changed: {path}")]
    PreparedVmStateChanged {
        /// Original diagnostic path of the VMState container.
        path: PathBuf,
    },
    /// The command, admitted ceiling, or attempt lifecycle differs from preparation.
    #[error("prepared QEMU run directory is bound to a different launch admission")]
    PreparedLaunchAdmissionChanged,
    /// A replacement destination was already populated or partially updated.
    #[error("replacement QEMU generation destination is not empty: {path}")]
    ReplacementDestinationNotEmpty {
        /// Descriptor-pinned destination path used only for diagnostics.
        path: PathBuf,
    },
    /// A replacement source lacks a complete stable writable artifact.
    #[error("replacement QEMU generation source is not ready: {path}")]
    ReplacementSourceNotReady {
        /// Descriptor-pinned source path used only for diagnostics.
        path: PathBuf,
    },
    /// The complete replacement artifact pair exceeds the aggregate quota.
    #[error(
        "replacement artifacts use {vmstate_bytes} VMState bytes and {root_overlay_bytes} root-overlay bytes, above maximum {maximum}"
    )]
    ReplacementArtifactsTooLarge {
        /// Logical VMState bytes.
        vmstate_bytes: u64,
        /// Logical root-overlay bytes.
        root_overlay_bytes: u64,
        /// Admitted aggregate writable-byte ceiling.
        maximum: u64,
    },
    /// A retained replacement artifact changed during descriptor-bound cloning.
    #[error("replacement QEMU artifact changed during cloning: {path}")]
    ReplacementArtifactChanged {
        /// Descriptor-pinned generation path used only for diagnostics.
        path: PathBuf,
    },
    /// The exact VMState image has an invalid declared byte length.
    #[error("prepared exact-VMState length {length} is outside the admitted maximum {maximum}")]
    PreparedVmStateLength {
        /// Declared exact checkpoint bytes.
        length: u64,
        /// Admitted aggregate writable-byte ceiling.
        maximum: u64,
    },
    /// The exact VMState image is absent or a replacement remains incomplete.
    #[error("prepared exact-VMState materialization is not ready: {path}")]
    PreparedVmStateNotReady {
        /// Pinned VMState path used only for diagnostics.
        path: PathBuf,
    },
    /// The materialized exact VMState is shorter or longer than declared.
    #[error("prepared exact-VMState is incomplete: expected {expected} bytes, found {actual}")]
    PreparedVmStateIncomplete {
        /// Declared complete checkpoint length.
        expected: u64,
        /// Bytes written or found in the pinned file.
        actual: u64,
    },
    /// The committed VMState file belongs to another exact-checkpoint root.
    #[error("prepared exact-VMState binding mismatch: expected {expected:?}, found {actual:?}")]
    PreparedVmStateBindingMismatch {
        /// Root-derived binding requested by the exact restore.
        expected: QemuVmStateBinding,
        /// Root-derived binding whose authenticated bytes were committed.
        actual: QemuVmStateBinding,
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
    /// The committed root overlay belongs to another exact-checkpoint root.
    #[error(
        "prepared exact root-overlay binding mismatch: expected {expected:?}, found {actual:?}"
    )]
    PreparedRootOverlayBindingMismatch {
        /// Root-derived binding requested by exact restore.
        expected: QemuVmStateBinding,
        /// Root-derived binding whose authenticated bytes were committed.
        actual: QemuVmStateBinding,
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

/// Spawns a validated QEMU launch command in `run_directory`.
///
/// The spawn path first creates the exact-VMState qcow2 container with the
/// `qemu-img` adjacent to the selected QEMU executable. Relative launch
/// artifacts, including that container, the QMP socket filename, and root
/// overlay image, are then resolved by QEMU under this working directory
/// without embedding volatile host paths in the launch hash material.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when run-directory or VMState-container
/// preparation, descriptor creation, descriptor duplication, parent-death
/// signal setup, changing the child working directory, or process spawning
/// fails.
pub fn spawn_qemu_child_with_fds_in_directory(
    command: &QemuLaunchCommand,
    run_directory: impl AsRef<Path>,
    region_len: u64,
) -> Result<QemuSpawnedChild, QemuSpawnError> {
    let run_directory = run_directory.as_ref();
    prepare_vmstate_container(command, run_directory)?;
    let (mut resources, child_resources) = create_spawn_resources(region_len)?;
    resources.fault_node_hash = command.plugin_fault_node_hash();
    let child = spawn_process_with_resources(
        command.executable(),
        command.args(),
        QemuSpawnWorkingDirectory::Path(run_directory),
        child_resources,
        &[],
        "spawn QEMU child",
        None,
    )?;
    Ok(QemuSpawnedChild {
        child: QemuNodeChild::new(child),
        resources,
    })
}

/// Spawns QEMU from an already-provisioned run directory under `contract`.
///
/// Unlike [`spawn_qemu_child_with_fds_in_directory`], this operation never
/// invokes `qemu-img` or creates the exact-VMState container. The supervisor
/// must provision and validate that container under its own bounded service
/// policy before admitting the attempt. Before revalidating that authority,
/// this path validates the command's fixed resource baseline against the
/// ceilings sealed into `contract`. The child writes itself into the attempt
/// cgroup and checks cancellation in `pre_exec`, before QEMU executes.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when the launch exceeds its admitted resources,
/// the prepared container is absent or not a regular file, descriptor
/// preparation fails, the pre-exec containment contract rejects the child, or
/// QEMU cannot be spawned.
pub fn spawn_prepared_qemu_child_with_fds_in_directory_guarded(
    command: &QemuLaunchCommand,
    run_directory: &QemuPreparedRunDirectory,
    region_len: u64,
    contract: &QemuChildProcessContract,
) -> Result<QemuSpawnedChild, QemuSpawnError> {
    run_directory.validate_launch_basis(command, contract)?;
    run_directory.revalidate()?;
    let (mut resources, child_resources) = create_spawn_resources(region_len)?;
    resources.fault_node_hash = command.plugin_fault_node_hash();
    let child = spawn_process_with_resources(
        command.executable(),
        command.args(),
        QemuSpawnWorkingDirectory::Pinned(run_directory),
        child_resources,
        &[],
        "spawn guarded QEMU child",
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

/// Prepares the exact-VMState qcow2 required by a launch or stopped probe.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when the run directory, existing artifact,
/// adjacent `qemu-img`, durable staging write, or atomic publication fails.
pub(crate) fn prepare_vmstate_container(
    command: &QemuLaunchCommand,
    run_directory: &Path,
) -> Result<(), QemuSpawnError> {
    fs::create_dir_all(run_directory).map_err(|source| QemuSpawnError::Io {
        operation: "create QEMU run directory",
        source,
    })?;
    let path = run_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME);
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => return Ok(()),
        Ok(_) => {
            return Err(QemuSpawnError::Io {
                operation: "validate exact-VMState container path",
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "exact-VMState container path is not a regular file",
                ),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(QemuSpawnError::Io {
                operation: "inspect exact-VMState container",
                source,
            });
        }
    }

    let staging = tempfile::Builder::new()
        .prefix(".crucible-vmstate-")
        .suffix(".qcow2")
        .tempfile_in(run_directory)
        .map_err(|source| QemuSpawnError::Io {
            operation: "stage exact-VMState container",
            source,
        })?;
    let image_tool = Path::new(command.executable()).with_file_name("qemu-img");
    let output = Command::new(&image_tool)
        .arg("create")
        .arg("-q")
        .arg("-f")
        .arg("qcow2")
        .arg(staging.path())
        .arg(format!("{}M", command.vmstate_size_mib()))
        .output()
        .map_err(|source| QemuSpawnError::Io {
            operation: "execute qemu-img for exact-VMState container",
            source,
        })?;
    if !output.status.success() {
        return Err(QemuSpawnError::VmStateImageTool {
            path,
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    staging
        .as_file()
        .sync_all()
        .map_err(|source| QemuSpawnError::Io {
            operation: "flush exact-VMState container",
            source,
        })?;
    match staging.persist_noclobber(&path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::metadata(&path).map_err(|source| QemuSpawnError::Io {
                operation: "inspect concurrently created exact-VMState container",
                source,
            })?;
            if !metadata.is_file() {
                return Err(QemuSpawnError::Io {
                    operation: "validate concurrently created exact-VMState container",
                    source: io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "exact-VMState container path is not a regular file",
                    ),
                });
            }
        }
        Err(error) => {
            return Err(QemuSpawnError::Io {
                operation: "publish exact-VMState container",
                source: error.error,
            });
        }
    }
    File::open(run_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| QemuSpawnError::Io {
            operation: "flush QEMU run directory",
            source,
        })
}

#[derive(Debug)]
struct QemuSpawnChildResources {
    control_socket: OwnedFd,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
}

#[derive(Clone, Copy)]
enum QemuSpawnWorkingDirectory<'a> {
    #[cfg(test)]
    Inherit,
    Path(&'a Path),
    Pinned(&'a QemuPreparedRunDirectory),
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
    run_directory: QemuSpawnWorkingDirectory<'_>,
    child_resources: QemuSpawnChildResources,
    envs: &[(&str, &str)],
    operation: &'static str,
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
    let pinned_run_directory = match run_directory {
        QemuSpawnWorkingDirectory::Pinned(directory) => Some(PreparedRunDirectoryRaw {
            directory: directory.directory.as_raw_fd(),
            vmstate_device: directory.vmstate_identity.device,
            vmstate_inode: directory.vmstate_identity.inode,
        }),
        #[cfg(test)]
        QemuSpawnWorkingDirectory::Inherit => None,
        QemuSpawnWorkingDirectory::Path(_) => None,
    };

    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let QemuSpawnWorkingDirectory::Path(run_directory) = run_directory {
        command.current_dir(run_directory);
    }
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
            if let Some(directory) = pinned_run_directory {
                install_prepared_run_directory(directory)?;
            }
            if let Some(credentials) = process_contract.and_then(|contract| contract.credentials) {
                install_child_credentials(credentials)?;
            }
            install_child_process_contract(control_fd, shmem_fd, wake_fd, expected_parent_pid)
        });
    }

    command
        .spawn()
        .map_err(|source| QemuSpawnError::Io { operation, source })
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
    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
    let child = command
        .spawn()
        .map_err(|source| QemuGuardedImagePreparationError {
            source: QemuSpawnError::Io { operation, source },
            child: None,
        })?;
    let mut child = QemuNodeChild::new(child);
    let started = guarded_image_tool_started();
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
            Ok(None) if guarded_image_tool_elapsed(started) < GUARDED_IMAGE_TOOL_TIMEOUT => {
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

/// Starts a host-only image-helper deadline outside canonical state.
// crucible-lint: allow clippy-disallowed-method -- host time only bounds an operational helper and never enters modeled state.
#[allow(clippy::disallowed_methods)]
fn guarded_image_tool_started() -> Instant {
    Instant::now()
}

/// Measures a host-only image-helper deadline outside canonical state.
// crucible-lint: allow clippy-disallowed-method -- host time only bounds an operational helper and never enters modeled state.
#[allow(clippy::disallowed_methods)]
fn guarded_image_tool_elapsed(started: Instant) -> Duration {
    started.elapsed()
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

fn validate_cgroup_procs_fd(fd: RawFd) -> Result<(), QemuSpawnError> {
    validate_live_fd(fd, "validate child cgroup descriptor")?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let status = unsafe {
        // SAFETY: `filesystem` points to writable storage for one statfs.
        libc::fstatfs(fd, filesystem.as_mut_ptr())
    };
    if status != 0 {
        return Err(last_io_error("inspect child cgroup filesystem"));
    }
    let filesystem = unsafe {
        // SAFETY: successful fstatfs initialized the complete structure.
        filesystem.assume_init()
    };
    if filesystem.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(QemuSpawnError::Io {
            operation: "validate child cgroup filesystem",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "cgroup.procs descriptor is not on cgroup v2",
            ),
        });
    }
    let target =
        fs::read_link(PathBuf::from("/proc/self/fd").join(fd.to_string())).map_err(|source| {
            QemuSpawnError::Io {
                operation: "resolve child cgroup descriptor",
                source,
            }
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

fn memfd_region(region_len: u64) -> Result<OwnedFd, QemuSpawnError> {
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
