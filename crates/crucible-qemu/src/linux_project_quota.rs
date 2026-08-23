//! Linux ext4 project-quota enforcement for one QEMU run directory.
//!
//! This module owns the raw kernel transaction needed by the concrete attempt
//! resource guard. It accepts a freshly created, pinned directory on an ext4
//! filesystem with project quotas already enabled, installs hard block and
//! inode limits for one unused project ID, and only then marks the directory
//! with that ID and `FS_XFLAG_PROJINHERIT`. Every setting is read back and the
//! quota metadata is synchronized before the authority is returned.
//!
//! The transaction deliberately does not allocate project IDs, create directory
//! names, provision VMState, or decide when process reap permits release. Those
//! responsibilities belong to the combined daemon-incarnation owner, which
//! must serialize allocation and reuse of every project ID. Dropping this
//! low-level authority without an explicit release leaks its pinned file
//! descriptors while leaving the kernel quota active; that is the fail-closed
//! fallback until the nondroppable combined owner consumes this module.

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{FileType, Mode, OFlags, RawDir, fstat, fstatfs, fsync, openat};
use rustix::ioctl::{Getter, Setter, ioctl, opcode};
use thiserror::Error;

const EXT4_QUOTA_BLOCK_BYTES: u64 = 1 << 10;
const PROJECT_QUOTA_TYPE: u32 = 2;
const QUOTA_SUBCOMMAND_SHIFT: u32 = 8;
const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;
const MAX_QUOTACTL_PROJECT_ID: u32 = 0x7fff_ffff;
const MAX_PROJECT_QUOTA_INODES: u64 = 1 << 20;
const DIRECTORY_SCAN_BUFFER_BYTES: usize = 4096;

const FS_IOC_FSGETXATTR: rustix::ioctl::Opcode = opcode::read::<Fsxattr>(b'X', 31);
const FS_IOC_FSSETXATTR: rustix::ioctl::Opcode = opcode::write::<Fsxattr>(b'X', 32);

/// Exact hard aggregate limits installed for one ext4 project.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LinuxProjectQuotaLimits {
    requested_bytes: u64,
    quota_blocks: u64,
    maximum_inodes: u64,
}

impl LinuxProjectQuotaLimits {
    /// Converts a byte ceiling to the conservative ext4 quota-block boundary.
    ///
    /// The quota interface expresses hard space limits in 1,024-byte blocks.
    /// A non-aligned request is rounded down so the kernel-enforced maximum can
    /// never exceed the admitted byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProjectQuotaError::InvalidLimits`] when fewer than one
    /// quota block or inode is admitted, or the inode ceiling exceeds the
    /// fixed cleanup-work bound.
    pub(crate) fn new(
        maximum_writable_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Self, LinuxProjectQuotaError> {
        let quota_blocks = maximum_writable_bytes / EXT4_QUOTA_BLOCK_BYTES;
        if quota_blocks == 0 || maximum_inodes == 0 || maximum_inodes > MAX_PROJECT_QUOTA_INODES {
            return Err(LinuxProjectQuotaError::InvalidLimits);
        }
        Ok(Self {
            requested_bytes: maximum_writable_bytes,
            quota_blocks,
            maximum_inodes,
        })
    }

    /// Returns the caller's admitted aggregate writable-byte ceiling.
    #[must_use]
    pub(crate) const fn requested_bytes(self) -> u64 {
        self.requested_bytes
    }

    /// Returns the conservative byte ceiling enforced by ext4.
    #[must_use]
    pub(crate) const fn enforced_bytes(self) -> u64 {
        self.quota_blocks * EXT4_QUOTA_BLOCK_BYTES
    }

    /// Returns the hard inode ceiling, including the run directory itself.
    #[must_use]
    pub(crate) const fn maximum_inodes(self) -> u64 {
        self.maximum_inodes
    }
}

/// Installed project-quota and pinned-directory authority.
#[derive(Debug)]
#[must_use = "release the project quota after process reap or retain it in quarantine"]
pub(crate) struct LinuxProjectQuotaReservation {
    filesystem: Option<OwnedFd>,
    directory: Option<OwnedFd>,
    path: PathBuf,
    project_id: u32,
    limits: LinuxProjectQuotaLimits,
    original_attributes: Fsxattr,
    released: bool,
}

impl LinuxProjectQuotaReservation {
    /// Installs one hard project quota on a fresh pinned directory.
    ///
    /// `filesystem` and `directory` must refer to the same ext4 filesystem.
    /// The caller must hold exclusive allocation authority for the nonzero
    /// project ID, whose quota record must be completely unused. The directory
    /// must be empty and must not already carry a project ID or inheritance
    /// flag. Quotas must already be enabled by the operator.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProjectQuotaInstallError`] before exposing the directory
    /// when filesystem validation, quota installation, attribute assignment,
    /// synchronization, or read-back authentication fails. Once a kernel limit
    /// may have changed, the error retains a cleanup authority.
    pub(crate) fn install(
        filesystem: OwnedFd,
        directory: OwnedFd,
        path: impl Into<PathBuf>,
        project_id: u32,
        limits: LinuxProjectQuotaLimits,
    ) -> Result<Self, LinuxProjectQuotaInstallError> {
        let path = path.into();
        if !project_id_is_supported(project_id) {
            return Err(LinuxProjectQuotaInstallError::without_cleanup(
                LinuxProjectQuotaError::InvalidProjectId,
            ));
        }
        validate_ext4_filesystem(&filesystem, &directory, &path)
            .map_err(LinuxProjectQuotaInstallError::without_cleanup)?;
        validate_empty_directory(&directory, &path)
            .map_err(LinuxProjectQuotaInstallError::without_cleanup)?;
        project_quota_info(&filesystem, &path)
            .map_err(LinuxProjectQuotaInstallError::without_cleanup)?;
        let original_attributes = get_project_attributes(&directory, &path)
            .map_err(LinuxProjectQuotaInstallError::without_cleanup)?;
        if original_attributes.fsx_projid != 0
            || original_attributes.fsx_xflags & FS_XFLAG_PROJINHERIT != 0
        {
            return Err(LinuxProjectQuotaInstallError::without_cleanup(
                LinuxProjectQuotaError::DirectoryAlreadyAssigned { path },
            ));
        }
        let prior = get_project_quota(&filesystem, &path, project_id)
            .map_err(LinuxProjectQuotaInstallError::without_cleanup)?;
        if !project_quota_record_is_unused(prior) {
            return Err(LinuxProjectQuotaInstallError::without_cleanup(
                LinuxProjectQuotaError::ProjectInUse {
                    project_id,
                    bytes: prior.dqb_curspace,
                    inodes: prior.dqb_curinodes,
                },
            ));
        }

        let mut reservation = Self {
            filesystem: Some(filesystem),
            directory: Some(directory),
            path,
            project_id,
            limits,
            original_attributes,
            released: false,
        };
        if let Err(source) = reservation.install_limits_and_attributes() {
            return Err(LinuxProjectQuotaInstallError::with_cleanup(
                source,
                reservation,
            ));
        }
        Ok(reservation)
    }

    /// Returns the assigned project identifier.
    #[must_use]
    pub(crate) const fn project_id(&self) -> u32 {
        self.project_id
    }

    /// Returns the exact admitted and kernel-rounded limits.
    #[must_use]
    pub(crate) const fn limits(&self) -> LinuxProjectQuotaLimits {
        self.limits
    }

    /// Returns the pinned directory descriptor.
    ///
    /// The descriptor is lent only for descriptor-relative preparation. It
    /// does not grant quota release or project-ID reuse.
    pub(crate) fn directory(&self) -> Result<&OwnedFd, LinuxProjectQuotaError> {
        self.directory
            .as_ref()
            .ok_or_else(|| LinuxProjectQuotaError::MissingAuthority {
                path: self.path.clone(),
            })
    }

    /// Restores the directory attributes and clears the quota after reap.
    ///
    /// The caller must already own the exclusive run-directory namespace and
    /// attest that no process can create another entry. The directory must be
    /// empty; this low-level operation does not recursively delete artifacts.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProjectQuotaReleaseError`] with this complete authority
    /// when emptiness, attribute restoration, usage reconciliation, quota
    /// clearing, synchronization, or read-back validation fails.
    pub(crate) fn release(mut self) -> Result<(), LinuxProjectQuotaReleaseError> {
        if let Err(source) = self.release_in_place() {
            return Err(LinuxProjectQuotaReleaseError {
                reservation: Box::new(self),
                source,
            });
        }
        Ok(())
    }

    fn install_limits_and_attributes(&mut self) -> Result<(), LinuxProjectQuotaError> {
        let filesystem = self.filesystem()?;
        set_project_quota(filesystem, &self.path, self.project_id, self.limits)?;
        sync_project_quota(filesystem, &self.path)?;
        verify_project_quota(filesystem, &self.path, self.project_id, self.limits)?;

        let mut assigned = self.original_attributes;
        assigned.fsx_projid = self.project_id;
        assigned.fsx_xflags |= FS_XFLAG_PROJINHERIT;
        let directory = self.directory()?;
        set_project_attributes(directory, &self.path, assigned)?;
        fsync(directory).map_err(|source| LinuxProjectQuotaError::Io {
            operation: "synchronize project-quota directory",
            path: self.path.clone(),
            source: source.into(),
        })?;
        verify_project_attributes(directory, &self.path, assigned)?;
        verify_project_usage_within_limit(filesystem, &self.path, self.project_id, self.limits)
    }

    fn release_in_place(&mut self) -> Result<(), LinuxProjectQuotaError> {
        if self.released {
            return Ok(());
        }
        let directory = self.directory()?;
        validate_empty_directory(directory, &self.path)?;
        set_project_attributes(directory, &self.path, self.original_attributes)?;
        fsync(directory).map_err(|source| LinuxProjectQuotaError::Io {
            operation: "synchronize released project-quota directory",
            path: self.path.clone(),
            source: source.into(),
        })?;
        verify_project_attributes(directory, &self.path, self.original_attributes)?;

        let filesystem = self.filesystem()?;
        let usage = get_project_quota(filesystem, &self.path, self.project_id)?;
        if usage.dqb_curspace != 0 || usage.dqb_curinodes != 0 {
            return Err(LinuxProjectQuotaError::ProjectInUse {
                project_id: self.project_id,
                bytes: usage.dqb_curspace,
                inodes: usage.dqb_curinodes,
            });
        }
        clear_project_quota(filesystem, &self.path, self.project_id)?;
        sync_project_quota(filesystem, &self.path)?;
        verify_project_quota_cleared(filesystem, &self.path, self.project_id)?;
        self.released = true;
        self.directory = None;
        self.filesystem = None;
        Ok(())
    }

    fn filesystem(&self) -> Result<&OwnedFd, LinuxProjectQuotaError> {
        self.filesystem
            .as_ref()
            .ok_or_else(|| LinuxProjectQuotaError::MissingAuthority {
                path: self.path.clone(),
            })
    }
}

impl Drop for LinuxProjectQuotaReservation {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Some(directory) = self.directory.take() {
            std::mem::forget(directory);
        }
        if let Some(filesystem) = self.filesystem.take() {
            std::mem::forget(filesystem);
        }
    }
}

/// Failure installing a project quota with optional retained cleanup authority.
#[derive(Debug, Error)]
#[error("failed to install Linux project quota: {source}")]
#[must_use = "recover partial project-quota authority or leave it enforced fail-closed"]
pub(crate) struct LinuxProjectQuotaInstallError {
    source: LinuxProjectQuotaError,
    cleanup: Option<Box<LinuxProjectQuotaReservation>>,
}

impl LinuxProjectQuotaInstallError {
    fn without_cleanup(source: LinuxProjectQuotaError) -> Self {
        Self {
            source,
            cleanup: None,
        }
    }

    fn with_cleanup(source: LinuxProjectQuotaError, cleanup: LinuxProjectQuotaReservation) -> Self {
        Self {
            source,
            cleanup: Some(Box::new(cleanup)),
        }
    }

    /// Returns the installation diagnostic without consuming cleanup authority.
    #[must_use]
    pub(crate) const fn source_error(&self) -> &LinuxProjectQuotaError {
        &self.source
    }

    /// Recovers the partially installed kernel authority, when present.
    #[must_use = "retain partial project-quota authority for cleanup or quarantine"]
    pub(crate) fn into_cleanup(mut self) -> Option<LinuxProjectQuotaReservation> {
        self.cleanup.take().map(|cleanup| *cleanup)
    }
}

/// Failed release that retains the installed project quota.
#[derive(Debug, Error)]
#[error("failed to release Linux project quota: {source}")]
#[must_use = "retry release or transfer the project quota to quarantine"]
pub(crate) struct LinuxProjectQuotaReleaseError {
    reservation: Box<LinuxProjectQuotaReservation>,
    source: LinuxProjectQuotaError,
}

impl LinuxProjectQuotaReleaseError {
    /// Returns the release diagnostic without consuming the reservation.
    #[must_use]
    pub(crate) const fn source_error(&self) -> &LinuxProjectQuotaError {
        &self.source
    }

    /// Recovers the complete installed reservation for retry or quarantine.
    #[must_use = "retry release or transfer the project-quota authority to quarantine"]
    pub(crate) fn into_reservation(self) -> LinuxProjectQuotaReservation {
        *self.reservation
    }
}

/// Stable project-quota validation or kernel-operation failure.
#[derive(Debug, Error)]
pub(crate) enum LinuxProjectQuotaError {
    /// Aggregate bytes or inode bounds cannot be enforced safely.
    #[error("project-quota limits are outside the supported range")]
    InvalidLimits,
    /// Project ID is zero or cannot fit the signed `quotactl_fd` argument.
    #[error("project-quota identifier must fit the positive signed 32-bit range")]
    InvalidProjectId,
    /// The pinned run directory is not on the supported filesystem.
    #[error("project-quota run directory is not on ext4: {path}")]
    UnsupportedFilesystem {
        /// Diagnostic path for the pinned directory.
        path: PathBuf,
    },
    /// Filesystem and run-directory descriptors do not name one filesystem.
    #[error("project-quota descriptors do not name one filesystem: {path}")]
    FilesystemIdentity {
        /// Diagnostic path for the pinned directory.
        path: PathBuf,
    },
    /// The run directory is not fresh and empty.
    #[error("project-quota run directory is not empty: {path}")]
    DirectoryNotEmpty {
        /// Diagnostic path for the pinned directory.
        path: PathBuf,
    },
    /// The run directory already belongs to another project namespace.
    #[error("project-quota run directory is already assigned: {path}")]
    DirectoryAlreadyAssigned {
        /// Diagnostic path for the pinned directory.
        path: PathBuf,
    },
    /// The selected project ID already accounts filesystem content.
    #[error(
        "project-quota identifier {project_id} retains quota state ({bytes} bytes, {inodes} inodes)"
    )]
    ProjectInUse {
        /// Conflicting project identifier.
        project_id: u32,
        /// Existing accounted bytes.
        bytes: u64,
        /// Existing accounted inode count.
        inodes: u64,
    },
    /// Kernel directory attributes did not match the requested transaction.
    #[error("project-quota directory attributes did not verify: {path}")]
    AttributeMismatch {
        /// Diagnostic path for the pinned directory.
        path: PathBuf,
    },
    /// Kernel quota limits did not match the requested transaction.
    #[error("project-quota limits did not verify for identifier {project_id}: {path}")]
    QuotaMismatch {
        /// Diagnostic path for the pinned directory.
        path: PathBuf,
        /// Project identifier whose limits differed.
        project_id: u32,
    },
    /// Required pinned descriptors were already released.
    #[error("project-quota authority is unavailable: {path}")]
    MissingAuthority {
        /// Diagnostic path for the pinned directory.
        path: PathBuf,
    },
    /// One raw filesystem operation failed.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Diagnostic path for the pinned directory.
        path: PathBuf,
        /// Underlying operating-system failure.
        #[source]
        source: io::Error,
    },
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Fsxattr {
    fsx_xflags: u32,
    fsx_extsize: u32,
    fsx_nextents: u32,
    fsx_projid: u32,
    fsx_cowextsize: u32,
    fsx_pad: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IfDqblk {
    dqb_bhardlimit: u64,
    dqb_bsoftlimit: u64,
    dqb_curspace: u64,
    dqb_ihardlimit: u64,
    dqb_isoftlimit: u64,
    dqb_curinodes: u64,
    dqb_btime: u64,
    dqb_itime: u64,
    dqb_valid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IfDqinfo {
    dqi_bgrace: u64,
    dqi_igrace: u64,
    dqi_flags: u32,
    dqi_valid: u32,
}

fn validate_ext4_filesystem(
    filesystem: &OwnedFd,
    directory: &OwnedFd,
    path: &Path,
) -> Result<(), LinuxProjectQuotaError> {
    let filesystem_stat = fstat(filesystem).map_err(|source| LinuxProjectQuotaError::Io {
        operation: "inspect project-quota filesystem",
        path: path.to_owned(),
        source: source.into(),
    })?;
    let directory_stat = fstat(directory).map_err(|source| LinuxProjectQuotaError::Io {
        operation: "inspect project-quota directory",
        path: path.to_owned(),
        source: source.into(),
    })?;
    if filesystem_stat.st_dev != directory_stat.st_dev
        || FileType::from_raw_mode(directory_stat.st_mode) != FileType::Directory
    {
        return Err(LinuxProjectQuotaError::FilesystemIdentity {
            path: path.to_owned(),
        });
    }
    let statfs = fstatfs(filesystem).map_err(|source| LinuxProjectQuotaError::Io {
        operation: "identify project-quota filesystem",
        path: path.to_owned(),
        source: source.into(),
    })?;
    if statfs.f_type != libc::EXT4_SUPER_MAGIC {
        return Err(LinuxProjectQuotaError::UnsupportedFilesystem {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn validate_empty_directory(
    directory: &OwnedFd,
    path: &Path,
) -> Result<(), LinuxProjectQuotaError> {
    // Reopen the pinned directory rather than duplicating its descriptor. A
    // duplicate shares the open-file-description offset, so one scan could
    // leave a later release check at EOF and falsely authenticate nonempty
    // state.
    let scan = openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| LinuxProjectQuotaError::Io {
        operation: "open project-quota directory for bounded scan",
        path: path.to_owned(),
        source: source.into(),
    })?;
    let mut buffer = [MaybeUninit::uninit(); DIRECTORY_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(scan, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|source| LinuxProjectQuotaError::Io {
            operation: "scan project-quota run directory",
            path: path.to_owned(),
            source: source.into(),
        })?;
        let name = entry.file_name();
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            return Err(LinuxProjectQuotaError::DirectoryNotEmpty {
                path: path.to_owned(),
            });
        }
    }
    Ok(())
}

fn get_project_attributes(
    directory: &OwnedFd,
    path: &Path,
) -> Result<Fsxattr, LinuxProjectQuotaError> {
    let getter = unsafe {
        // SAFETY: the opcode is Linux FS_IOC_FSGETXATTR and Fsxattr exactly
        // matches the stable UAPI structure written by the kernel.
        Getter::<FS_IOC_FSGETXATTR, Fsxattr>::new()
    };
    unsafe {
        // SAFETY: the pinned directory is live and the getter owns writable
        // storage for exactly one Fsxattr result.
        ioctl(directory, getter)
    }
    .map_err(|source| LinuxProjectQuotaError::Io {
        operation: "read project-quota directory attributes",
        path: path.to_owned(),
        source: source.into(),
    })
}

fn set_project_attributes(
    directory: &OwnedFd,
    path: &Path,
    attributes: Fsxattr,
) -> Result<(), LinuxProjectQuotaError> {
    let setter = unsafe {
        // SAFETY: the opcode is Linux FS_IOC_FSSETXATTR and Fsxattr exactly
        // matches the stable UAPI structure read by the kernel.
        Setter::<FS_IOC_FSSETXATTR, Fsxattr>::new(attributes)
    };
    unsafe {
        // SAFETY: the pinned directory is live and the setter points to one
        // initialized Fsxattr value for the duration of the call.
        ioctl(directory, setter)
    }
    .map_err(|source| LinuxProjectQuotaError::Io {
        operation: "write project-quota directory attributes",
        path: path.to_owned(),
        source: source.into(),
    })
}

fn verify_project_attributes(
    directory: &OwnedFd,
    path: &Path,
    expected: Fsxattr,
) -> Result<(), LinuxProjectQuotaError> {
    let actual = get_project_attributes(directory, path)?;
    if !project_attributes_match(actual, expected) {
        return Err(LinuxProjectQuotaError::AttributeMismatch {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn project_attributes_match(actual: Fsxattr, expected: Fsxattr) -> bool {
    // `fsx_nextents` is kernel-owned output and can change as directory data
    // is allocated. Authenticate only fields accepted by FSSETXATTR.
    actual.fsx_xflags == expected.fsx_xflags
        && actual.fsx_extsize == expected.fsx_extsize
        && actual.fsx_projid == expected.fsx_projid
        && actual.fsx_cowextsize == expected.fsx_cowextsize
}

fn project_quota_info(
    filesystem: &OwnedFd,
    path: &Path,
) -> Result<IfDqinfo, LinuxProjectQuotaError> {
    let mut info = IfDqinfo::default();
    quota_syscall(
        filesystem,
        quota_command(libc::Q_GETINFO),
        0,
        (&raw mut info).cast(),
        "authenticate enabled ext4 project quotas",
        path,
    )?;
    Ok(info)
}

fn get_project_quota(
    filesystem: &OwnedFd,
    path: &Path,
    project_id: u32,
) -> Result<IfDqblk, LinuxProjectQuotaError> {
    let mut quota = IfDqblk::default();
    quota_syscall(
        filesystem,
        quota_command(libc::Q_GETQUOTA),
        project_id,
        (&raw mut quota).cast(),
        "read ext4 project quota",
        path,
    )?;
    Ok(quota)
}

fn set_project_quota(
    filesystem: &OwnedFd,
    path: &Path,
    project_id: u32,
    limits: LinuxProjectQuotaLimits,
) -> Result<(), LinuxProjectQuotaError> {
    let mut quota = quota_limits(limits);
    quota_syscall(
        filesystem,
        quota_command(libc::Q_SETQUOTA),
        project_id,
        (&raw mut quota).cast(),
        "install ext4 project quota",
        path,
    )
}

fn clear_project_quota(
    filesystem: &OwnedFd,
    path: &Path,
    project_id: u32,
) -> Result<(), LinuxProjectQuotaError> {
    let mut quota = IfDqblk {
        dqb_valid: libc::QIF_LIMITS,
        ..IfDqblk::default()
    };
    quota_syscall(
        filesystem,
        quota_command(libc::Q_SETQUOTA),
        project_id,
        (&raw mut quota).cast(),
        "clear ext4 project quota",
        path,
    )
}

fn sync_project_quota(filesystem: &OwnedFd, path: &Path) -> Result<(), LinuxProjectQuotaError> {
    quota_syscall(
        filesystem,
        quota_command(libc::Q_SYNC),
        0,
        std::ptr::null_mut(),
        "synchronize ext4 project quota",
        path,
    )
}

fn quota_limits(limits: LinuxProjectQuotaLimits) -> IfDqblk {
    IfDqblk {
        dqb_bhardlimit: limits.quota_blocks,
        dqb_bsoftlimit: limits.quota_blocks,
        dqb_ihardlimit: limits.maximum_inodes,
        dqb_isoftlimit: limits.maximum_inodes,
        dqb_valid: libc::QIF_LIMITS,
        ..IfDqblk::default()
    }
}

fn project_quota_record_is_unused(quota: IfDqblk) -> bool {
    quota.dqb_bhardlimit == 0
        && quota.dqb_bsoftlimit == 0
        && quota.dqb_curspace == 0
        && quota.dqb_ihardlimit == 0
        && quota.dqb_isoftlimit == 0
        && quota.dqb_curinodes == 0
        && quota.dqb_btime == 0
        && quota.dqb_itime == 0
}

fn project_id_is_supported(project_id: u32) -> bool {
    project_id != 0 && project_id <= MAX_QUOTACTL_PROJECT_ID
}

fn verify_project_quota(
    filesystem: &OwnedFd,
    path: &Path,
    project_id: u32,
    limits: LinuxProjectQuotaLimits,
) -> Result<(), LinuxProjectQuotaError> {
    let actual = get_project_quota(filesystem, path, project_id)?;
    let expected = quota_limits(limits);
    if actual.dqb_valid & libc::QIF_LIMITS != libc::QIF_LIMITS
        || actual.dqb_bhardlimit != expected.dqb_bhardlimit
        || actual.dqb_bsoftlimit != expected.dqb_bsoftlimit
        || actual.dqb_ihardlimit != expected.dqb_ihardlimit
        || actual.dqb_isoftlimit != expected.dqb_isoftlimit
    {
        return Err(LinuxProjectQuotaError::QuotaMismatch {
            path: path.to_owned(),
            project_id,
        });
    }
    Ok(())
}

fn verify_project_usage_within_limit(
    filesystem: &OwnedFd,
    path: &Path,
    project_id: u32,
    limits: LinuxProjectQuotaLimits,
) -> Result<(), LinuxProjectQuotaError> {
    let actual = get_project_quota(filesystem, path, project_id)?;
    if actual.dqb_curspace > limits.enforced_bytes() || actual.dqb_curinodes > limits.maximum_inodes
    {
        return Err(LinuxProjectQuotaError::QuotaMismatch {
            path: path.to_owned(),
            project_id,
        });
    }
    Ok(())
}

fn verify_project_quota_cleared(
    filesystem: &OwnedFd,
    path: &Path,
    project_id: u32,
) -> Result<(), LinuxProjectQuotaError> {
    let actual = get_project_quota(filesystem, path, project_id)?;
    if actual.dqb_bhardlimit != 0
        || actual.dqb_bsoftlimit != 0
        || actual.dqb_ihardlimit != 0
        || actual.dqb_isoftlimit != 0
        || actual.dqb_curspace != 0
        || actual.dqb_curinodes != 0
    {
        return Err(LinuxProjectQuotaError::QuotaMismatch {
            path: path.to_owned(),
            project_id,
        });
    }
    Ok(())
}

fn quota_command(command: libc::c_int) -> libc::c_int {
    let command = u32::from_ne_bytes(command.to_ne_bytes());
    let encoded = (command << QUOTA_SUBCOMMAND_SHIFT) | PROJECT_QUOTA_TYPE;
    libc::c_int::from_ne_bytes(encoded.to_ne_bytes())
}

fn quota_syscall(
    filesystem: &OwnedFd,
    command: libc::c_int,
    project_id: u32,
    address: *mut libc::c_void,
    operation: &'static str,
    path: &Path,
) -> Result<(), LinuxProjectQuotaError> {
    let result = unsafe {
        // SAFETY: SYS_quotactl_fd receives a live filesystem fd, a QCMD
        // project-quota operation, a 32-bit ID, and either null or a pointer to
        // the exact stable UAPI structure selected by that operation.
        libc::syscall(
            libc::SYS_quotactl_fd,
            filesystem.as_raw_fd(),
            command,
            project_id,
            address,
        )
    };
    if result != 0 {
        return Err(LinuxProjectQuotaError::Io {
            operation,
            path: path.to_owned(),
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn byte_limit_rounds_down_to_a_hard_kernel_ceiling() {
        let aligned = LinuxProjectQuotaLimits::new(8 * 1024, 17)
            .unwrap_or_else(|error| panic!("aligned quota: {error}"));
        assert_eq!(aligned.requested_bytes(), 8 * 1024);
        assert_eq!(aligned.enforced_bytes(), 8 * 1024);
        assert_eq!(aligned.maximum_inodes(), 17);

        let unaligned = LinuxProjectQuotaLimits::new(8 * 1024 + 1023, 17)
            .unwrap_or_else(|error| panic!("unaligned quota: {error}"));
        assert_eq!(unaligned.requested_bytes(), 8 * 1024 + 1023);
        assert_eq!(unaligned.enforced_bytes(), 8 * 1024);
        assert!(unaligned.enforced_bytes() <= unaligned.requested_bytes());
    }

    #[test]
    fn quota_limits_reject_unenforceable_or_unbounded_profiles() {
        assert!(LinuxProjectQuotaLimits::new(1023, 1).is_err());
        assert!(LinuxProjectQuotaLimits::new(1024, 0).is_err());
        assert!(LinuxProjectQuotaLimits::new(1024, MAX_PROJECT_QUOTA_INODES + 1).is_err());
    }

    #[test]
    fn project_identifier_fits_the_signed_quotactl_argument() {
        assert!(!project_id_is_supported(0));
        assert!(project_id_is_supported(1));
        assert!(project_id_is_supported(MAX_QUOTACTL_PROJECT_ID));
        assert!(!project_id_is_supported(MAX_QUOTACTL_PROJECT_ID + 1));
    }

    #[test]
    fn kernel_abi_layout_and_project_commands_are_frozen() {
        assert_eq!(size_of::<Fsxattr>(), 28);
        assert_eq!(align_of::<Fsxattr>(), 4);
        assert_eq!(size_of::<IfDqblk>(), 72);
        assert_eq!(align_of::<IfDqblk>(), 8);
        assert_eq!(size_of::<IfDqinfo>(), 24);
        assert_eq!(align_of::<IfDqinfo>(), 8);
        assert_eq!(
            u32::from_ne_bytes(quota_command(libc::Q_GETINFO).to_ne_bytes()),
            0x8000_0502
        );
        assert_eq!(
            u32::from_ne_bytes(quota_command(libc::Q_GETQUOTA).to_ne_bytes()),
            0x8000_0702
        );
        assert_eq!(
            u32::from_ne_bytes(quota_command(libc::Q_SETQUOTA).to_ne_bytes()),
            0x8000_0802
        );
    }

    #[test]
    fn quota_record_sets_equal_hard_and_soft_bounds() {
        let limits = LinuxProjectQuotaLimits::new(64 * 1024 + 19, 32)
            .unwrap_or_else(|error| panic!("quota: {error}"));
        let quota = quota_limits(limits);
        assert_eq!(quota.dqb_bhardlimit, 64);
        assert_eq!(quota.dqb_bsoftlimit, 64);
        assert_eq!(quota.dqb_ihardlimit, 32);
        assert_eq!(quota.dqb_isoftlimit, 32);
        assert_eq!(quota.dqb_valid, libc::QIF_LIMITS);
    }

    #[test]
    fn project_identifier_reuse_requires_a_completely_empty_quota_record() {
        assert!(project_quota_record_is_unused(IfDqblk::default()));

        let configured = IfDqblk {
            dqb_bhardlimit: 1,
            ..IfDqblk::default()
        };
        assert!(!project_quota_record_is_unused(configured));

        let stale_grace = IfDqblk {
            dqb_btime: 1,
            ..IfDqblk::default()
        };
        assert!(!project_quota_record_is_unused(stale_grace));
    }

    #[test]
    fn attribute_readback_ignores_only_kernel_owned_extent_count() {
        let expected = Fsxattr {
            fsx_xflags: FS_XFLAG_PROJINHERIT,
            fsx_extsize: 4096,
            fsx_nextents: 1,
            fsx_projid: 42,
            fsx_cowextsize: 8192,
            fsx_pad: [0; 8],
        };
        let mut actual = expected;
        actual.fsx_nextents = 99;
        actual.fsx_pad = [0xff; 8];
        assert!(project_attributes_match(actual, expected));

        actual.fsx_projid = 43;
        assert!(!project_attributes_match(actual, expected));
    }
}
