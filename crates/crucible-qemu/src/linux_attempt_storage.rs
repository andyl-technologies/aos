//! Lifecycle-bound Linux storage ownership for one QEMU attempt.
//!
//! The low-level project-quota transaction deliberately accepts already-open
//! descriptors and an already-allocated project ID. This module supplies the
//! missing daemon-incarnation ownership: it locks one dedicated run root,
//! allocates from an operator-reserved project-ID range, creates and pins a
//! unique child directory, installs the hard ext4 project quota, transfers the
//! directory to the configured unprivileged QEMU identity, and keeps every
//! authority until exact cleanup is durable.
//!
//! The root must be a private, empty ext4 directory with project quotas active.
//! A dirty root after restart is rejected rather than guessing whether an old
//! attempt is safe to reclaim. Project IDs are recycled only after quota
//! removal, authenticated directory removal, and parent-directory `fsync` all
//! succeed. Bounded descriptor-relative cleanup removes attempt artifacts only
//! after process reap. Dropping an unfinished owner intentionally leaks its
//! pinned root lock and kernel authority; the future combined process/storage
//! quarantine owner must consume the explicit retry errors instead.

use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, RawDir, fchmod, fchown, flock, fstat, fsync,
    mkdirat, open, openat, statat, unlinkat,
};
use rustix::io::fcntl_dupfd_cloexec;
use rustix::process::{Gid, Uid, geteuid};
use thiserror::Error;

use crate::linux_project_quota::{
    LinuxProjectQuotaError, LinuxProjectQuotaLimits, LinuxProjectQuotaReservation,
    validate_project_quota_root,
};
use crate::spawn::{QemuChildCredentials, validate_guarded_launch_resources};
use crate::{
    DEFAULT_VMSTATE_FILE_NAME, QemuChildProcessContract, QemuLaunchCommand,
    QemuPreparedRunDirectory, QemuSpawnError,
};

const ATTEMPT_COUNTER_HEX_BYTES: usize = 16;
const ATTEMPT_NAME_SEPARATOR_BYTES: usize = 1;
const MAX_RUN_DIRECTORY_NAME_BYTES: usize = 128;
const MAX_ATTEMPT_NAMESPACE_BYTES: usize =
    MAX_RUN_DIRECTORY_NAME_BYTES - ATTEMPT_NAME_SEPARATOR_BYTES - ATTEMPT_COUNTER_HEX_BYTES;
const MAX_PROJECT_ID_COUNT: u32 = 65_536;
const MAX_QUOTACTL_PROJECT_ID: u32 = 0x7fff_ffff;
const MAX_ATTEMPT_ARTIFACT_INODES: u64 = 65_536;
const ROOT_SCAN_BUFFER_BYTES: usize = 4096;
const GENERATION_NAME_PREFIX: &str = "generation-";

/// Validated configuration for one daemon-incarnation attempt-storage root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LinuxQemuAttemptStorageConfig {
    run_root: PathBuf,
    attempt_namespace: String,
    first_project_id: u32,
    project_id_count: u32,
    child_user_id: u32,
    child_group_id: u32,
    maximum_inodes: u64,
}

impl LinuxQemuAttemptStorageConfig {
    /// Validates one private ext4 attempt-storage namespace.
    ///
    /// `attempt_namespace` must be unique to the daemon incarnation, and the
    /// project-ID range must be reserved exclusively for this root. The root is
    /// accessed only later by [`LinuxQemuAttemptStorageFactory::open`].
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptStorageError::InvalidConfig`] when the root,
    /// namespace, project-ID range, or inode ceiling is invalid. Returns
    /// [`LinuxQemuAttemptStorageError::ChildCredentials`] when the child identity
    /// is root, overlaps any supervisor identity, or cannot be inspected.
    pub(crate) fn new(
        run_root: impl Into<PathBuf>,
        attempt_namespace: impl Into<String>,
        first_project_id: u32,
        project_id_count: u32,
        child_user_id: u32,
        child_group_id: u32,
        maximum_inodes: u64,
    ) -> Result<Self, LinuxQemuAttemptStorageError> {
        let run_root = run_root.into();
        let attempt_namespace = attempt_namespace.into();
        if !run_root.is_absolute() || run_root.parent().is_none() {
            return Err(invalid_config(
                "attempt-storage root must be an absolute dedicated directory",
            ));
        }
        if !valid_attempt_namespace(&attempt_namespace) {
            return Err(invalid_config(
                "attempt-storage namespace must be bounded ASCII alphanumeric, dash, or underscore",
            ));
        }
        if first_project_id == 0
            || project_id_count == 0
            || project_id_count > MAX_PROJECT_ID_COUNT
            || first_project_id
                .checked_add(project_id_count - 1)
                .is_none_or(|last| last > MAX_QUOTACTL_PROJECT_ID)
        {
            return Err(invalid_config(
                "attempt-storage project-ID range is outside the supported bound",
            ));
        }
        if child_user_id == 0
            || child_group_id == 0
            || child_user_id == u32::MAX
            || child_group_id == u32::MAX
        {
            return Err(invalid_config(
                "attempt-storage child user and group must be concrete non-root IDs",
            ));
        }
        QemuChildCredentials::new(child_user_id, child_group_id)
            .map_err(|source| LinuxQemuAttemptStorageError::ChildCredentials { source })?;
        if maximum_inodes > MAX_ATTEMPT_ARTIFACT_INODES {
            return Err(invalid_config(
                "attempt-storage inode ceiling exceeds the bounded cleanup profile",
            ));
        }
        LinuxProjectQuotaLimits::new(1024, maximum_inodes)
            .map_err(LinuxQemuAttemptStorageError::ProjectQuota)?;

        Ok(Self {
            run_root,
            attempt_namespace,
            first_project_id,
            project_id_count,
            child_user_id,
            child_group_id,
            maximum_inodes,
        })
    }

    /// Returns the dedicated run-root path.
    #[must_use]
    pub(crate) fn run_root(&self) -> &Path {
        &self.run_root
    }

    /// Returns the daemon-incarnation directory-name namespace.
    #[must_use]
    pub(crate) fn attempt_namespace(&self) -> &str {
        &self.attempt_namespace
    }

    /// Returns the first operator-reserved project identifier.
    #[must_use]
    pub(crate) const fn first_project_id(&self) -> u32 {
        self.first_project_id
    }

    /// Returns the number of operator-reserved project identifiers.
    #[must_use]
    pub(crate) const fn project_id_count(&self) -> u32 {
        self.project_id_count
    }

    /// Returns the unprivileged QEMU user identifier.
    #[must_use]
    pub(crate) const fn child_user_id(&self) -> u32 {
        self.child_user_id
    }

    /// Returns the unprivileged QEMU group identifier.
    #[must_use]
    pub(crate) const fn child_group_id(&self) -> u32 {
        self.child_group_id
    }

    /// Returns the hard inode ceiling installed for every attempt.
    #[must_use]
    pub(crate) const fn maximum_inodes(&self) -> u64 {
        self.maximum_inodes
    }
}

/// Exclusive allocator for one private ext4 QEMU run root.
#[derive(Debug)]
#[must_use = "the run-root lock must outlive every attempt storage owner"]
pub(crate) struct LinuxQemuAttemptStorageFactory {
    config: LinuxQemuAttemptStorageConfig,
    root: OwnedFd,
    project_ids: Arc<ProjectIdPool>,
    next_attempt: AtomicU64,
}

impl LinuxQemuAttemptStorageFactory {
    /// Opens, validates, and exclusively locks the configured run root.
    ///
    /// Configuration validation has already completed without path access. The
    /// root must be owned by the effective supervisor user, have mode `0700`,
    /// be empty, reside on ext4, and permit project-quota queries. The advisory
    /// lock requires every supervisor for this operator-owned root to cooperate.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptStorageError`] when the root cannot be opened,
    /// its filesystem or access policy is wrong, it contains a prior attempt,
    /// or another daemon still owns the namespace lock.
    pub(crate) fn open(
        config: LinuxQemuAttemptStorageConfig,
    ) -> Result<Self, LinuxQemuAttemptStorageError> {
        let path = config.run_root().to_owned();
        let root = open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| io_error("open QEMU attempt-storage root", &path, source))?;
        validate_root_policy(&root, &path)?;
        validate_project_quota_root(&root, &path)
            .map_err(LinuxQemuAttemptStorageError::ProjectQuota)?;
        validate_empty_root(&root, &path)?;
        lock_namespace(&root, &path)?;

        Ok(Self {
            project_ids: Arc::new(ProjectIdPool::new(
                config.first_project_id,
                config.project_id_count,
            )),
            config,
            root,
            next_attempt: AtomicU64::new(0),
        })
    }

    /// Returns the validated storage-root configuration.
    #[must_use]
    pub(crate) const fn config(&self) -> &LinuxQemuAttemptStorageConfig {
        &self.config
    }

    /// Creates one quota-bound, pinned attempt run directory.
    ///
    /// The directory is not returned until quota limits, project inheritance,
    /// child ownership, inode identity, and directory durability all read back
    /// exactly. The directory starts empty; VMState and other attempt artifacts
    /// must be provisioned through the later combined resource owner.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptStorageCreateError`]. A failure after directory
    /// creation carries a complete owner that can retry cleanup or transfer to
    /// quarantine. A failure before creation releases the unused project ID.
    pub(crate) fn begin(
        &self,
        maximum_writable_bytes: u64,
    ) -> Result<LinuxQemuAttemptStorageOwner, LinuxQemuAttemptStorageCreateError> {
        let limits =
            LinuxProjectQuotaLimits::new(maximum_writable_bytes, self.config.maximum_inodes)
                .map_err(LinuxQemuAttemptStorageCreateError::without_owner)?;
        let sequence = self
            .next_attempt
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                LinuxQemuAttemptStorageCreateError::without_owner(
                    LinuxQemuAttemptStorageError::SequenceExhausted,
                )
            })?;
        let name = attempt_name(&self.config.attempt_namespace, sequence);
        let path = self.config.run_root.join(&name);
        let lease = self.project_ids.allocate().ok_or_else(|| {
            LinuxQemuAttemptStorageCreateError::without_owner(
                LinuxQemuAttemptStorageError::ProjectIdsExhausted,
            )
        })?;
        let parent_directory =
            duplicate_fd(&self.root, "retain attempt-storage namespace lock", &path)
                .map_err(LinuxQemuAttemptStorageCreateError::without_owner)?;

        mkdirat(&self.root, name.as_str(), Mode::from_bits_truncate(0o700))
            .map_err(|source| io_error("create QEMU attempt run directory", &path, source))
            .map_err(LinuxQemuAttemptStorageCreateError::without_owner)?;

        let mut owner = LinuxQemuAttemptStorageOwner {
            path,
            name,
            parent_directory: Some(parent_directory),
            directory: None,
            project_id: lease.commit(),
            quota: None,
            child_user_id: self.config.child_user_id,
            child_group_id: self.config.child_group_id,
            maximum_inodes: limits.maximum_inodes(),
            next_generation: Some(1),
            removed: false,
            released: false,
        };
        if let Err(source) = owner.install(limits) {
            return Err(LinuxQemuAttemptStorageCreateError::with_owner(
                source, owner,
            ));
        }
        Ok(owner)
    }
}

/// Pinned quota and directory authority for one QEMU attempt.
#[derive(Debug)]
#[must_use = "release after process reap or transfer the complete storage owner to quarantine"]
pub(crate) struct LinuxQemuAttemptStorageOwner {
    path: PathBuf,
    name: String,
    parent_directory: Option<OwnedFd>,
    directory: Option<OwnedFd>,
    project_id: ProjectIdLease,
    quota: Option<LinuxProjectQuotaReservation>,
    child_user_id: u32,
    child_group_id: u32,
    maximum_inodes: u64,
    next_generation: Option<u64>,
    removed: bool,
    released: bool,
}

impl LinuxQemuAttemptStorageOwner {
    /// Returns the diagnostic path of the exact pinned run directory.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the exact allocated project identifier.
    #[must_use]
    pub(crate) fn project_id(&self) -> u32 {
        self.project_id.project_id()
    }

    /// Returns the installed quota limits when installation reached that phase.
    #[must_use]
    pub(crate) fn limits(&self) -> Option<LinuxProjectQuotaLimits> {
        self.quota
            .as_ref()
            .map(LinuxProjectQuotaReservation::limits)
    }

    /// Returns the pinned run-directory descriptor.
    ///
    /// This borrowed capability is for descriptor-relative artifact
    /// provisioning and launch preparation. It grants neither quota release nor
    /// project-ID reuse.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptStorageError::MissingAuthority`] if the
    /// directory was already durably removed.
    pub(crate) fn directory(&self) -> Result<&OwnedFd, LinuxQemuAttemptStorageError> {
        self.directory
            .as_ref()
            .ok_or_else(|| LinuxQemuAttemptStorageError::MissingAuthority {
                path: self.path.clone(),
            })
    }

    /// Provisions and lends one descriptor-pinned generation run directory.
    ///
    /// Resource admission is checked before generation-directory creation. Each
    /// successful call receives a fresh monotone child below the attempt root.
    /// The returned authority owns only duplicated generation-directory and
    /// VMState descriptors; the single aggregate quota, cleanup namespace,
    /// project-ID lease, and every partially created generation remain here.
    /// Issuance retains only the next ordinal, so its memory use is independent
    /// of the number of generations and the inode quota remains the hard count
    /// bound.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptStorageError`] when admission changes, the
    /// attempt-root identity is invalid, the monotone generation sequence is
    /// exhausted, or child-directory/VMState provisioning or durability fails.
    pub(crate) fn prepare_generation_run_directory(
        &mut self,
        command: &QemuLaunchCommand,
        contract: &QemuChildProcessContract,
    ) -> Result<QemuPreparedRunDirectory, LinuxQemuAttemptStorageError> {
        validate_guarded_launch_resources(command, contract)
            .map_err(LinuxQemuAttemptStorageError::LaunchPreparation)?;
        self.pin_directory()?;
        self.verify_named_directory()?;

        let generation = self.next_generation.ok_or_else(|| {
            LinuxQemuAttemptStorageError::GenerationSequenceExhausted {
                path: self.path.clone(),
            }
        })?;
        self.next_generation = generation.checked_add(1);
        let (path, directory) = create_generation_directory(
            self.directory()?,
            &self.path,
            generation,
            self.child_user_id,
            self.child_group_id,
        )?;
        let vmstate =
            provision_vmstate_file(&directory, &path, self.child_user_id, self.child_group_id)?;
        let directory = duplicate_fd(&directory, "lend pinned QEMU generation directory", &path)?;
        let prepared = QemuPreparedRunDirectory::from_admitted_descriptors(
            command, &path, directory, vmstate, contract,
        )
        .map_err(LinuxQemuAttemptStorageError::LaunchPreparation)?;
        Ok(prepared)
    }

    /// Releases quota and removes the exact empty run directory after reap.
    ///
    /// The caller must first attest that every attempt process and helper has
    /// been reaped and that no remaining artifact is required. This operation
    /// does not recursively delete files: a nonempty directory retains the
    /// complete owner for a bounded, policy-driven cleanup or quarantine pass.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptStorageReleaseError`] with this complete owner
    /// when identity, emptiness, quota release, directory removal, or durability
    /// fails. An exact retry resumes from the last completed phase.
    pub(crate) fn release(mut self) -> Result<(), LinuxQemuAttemptStorageReleaseError> {
        if let Err(source) = self.release_in_place() {
            return Err(LinuxQemuAttemptStorageReleaseError {
                owner: Box::new(self),
                source,
            });
        }
        Ok(())
    }

    /// Removes bounded attempt artifacts, then releases quota and the directory.
    ///
    /// The caller must first attest that every process able to mutate this run
    /// directory has been reaped. Cleanup never follows symlinks or crosses the
    /// run directory's filesystem. Work, retained names, and nesting are all
    /// bounded by the installed inode ceiling, while traversal keeps only the
    /// current directory descriptor open.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuAttemptStorageReleaseError`] with this complete owner
    /// when traversal, removal, quota release, or durability fails. Already
    /// removed entries make exact retry monotone.
    pub(crate) fn cleanup_and_release(mut self) -> Result<(), LinuxQemuAttemptStorageReleaseError> {
        let result = self
            .cleanup_contents_in_place()
            .and_then(|()| self.release_in_place());
        if let Err(source) = result {
            return Err(LinuxQemuAttemptStorageReleaseError {
                owner: Box::new(self),
                source,
            });
        }
        Ok(())
    }

    fn install(
        &mut self,
        limits: LinuxProjectQuotaLimits,
    ) -> Result<(), LinuxQemuAttemptStorageError> {
        let directory = open_directory_at(self.parent_directory()?, &self.name, &self.path)?;
        self.directory = Some(directory);

        let filesystem = duplicate_fd(
            self.parent_directory()?,
            "retain project-quota filesystem authority",
            &self.path,
        )?;
        let quota_directory = duplicate_fd(
            self.directory()?,
            "retain project-quota directory authority",
            &self.path,
        )?;
        match LinuxProjectQuotaReservation::install(
            filesystem,
            quota_directory,
            self.path.clone(),
            self.project_id(),
            limits,
        ) {
            Ok(quota) => self.quota = Some(quota),
            Err(error) => {
                let (source, cleanup) = error.into_parts();
                self.quota = cleanup;
                return Err(LinuxQemuAttemptStorageError::ProjectQuota(source));
            }
        }

        let directory = self.directory()?;
        fchmod(directory, Mode::from_bits_truncate(0o700))
            .map_err(|source| io_error("set QEMU run-directory mode", &self.path, source))?;
        let child_user = Uid::from_raw(self.child_user_id);
        let child_group = Gid::from_raw(self.child_group_id);
        fchown(directory, Some(child_user), Some(child_group)).map_err(|source| {
            io_error("assign QEMU run-directory ownership", &self.path, source)
        })?;
        fsync(directory)
            .map_err(|source| io_error("synchronize QEMU run directory", &self.path, source))?;
        verify_directory_policy(
            directory,
            &self.path,
            self.child_user_id,
            self.child_group_id,
        )?;
        self.quota
            .as_ref()
            .ok_or_else(|| LinuxQemuAttemptStorageError::MissingAuthority {
                path: self.path.clone(),
            })?
            .verify_usage()
            .map_err(LinuxQemuAttemptStorageError::ProjectQuota)?;
        fsync(self.parent_directory()?)
            .map_err(|source| io_error("synchronize QEMU run-root creation", &self.path, source))
    }

    fn release_in_place(&mut self) -> Result<(), LinuxQemuAttemptStorageError> {
        if self.released {
            return Ok(());
        }
        if !self.removed {
            self.pin_directory()?;
            self.verify_named_directory()?;
            if let Some(quota) = self.quota.take() {
                match quota.release() {
                    Ok(()) => {}
                    Err(error) => {
                        let (source, reservation) = error.into_parts();
                        self.quota = Some(reservation);
                        return Err(LinuxQemuAttemptStorageError::ProjectQuota(source));
                    }
                }
            }
            unlinkat(
                self.parent_directory()?,
                self.name.as_str(),
                AtFlags::REMOVEDIR,
            )
            .map_err(|source| io_error("remove QEMU attempt run directory", &self.path, source))?;
            self.removed = true;
        }
        fsync(self.parent_directory()?)
            .map_err(|source| io_error("synchronize QEMU run-root removal", &self.path, source))?;
        self.project_id.recycle()?;
        self.released = true;
        self.directory = None;
        self.parent_directory = None;
        Ok(())
    }

    fn cleanup_contents_in_place(&mut self) -> Result<(), LinuxQemuAttemptStorageError> {
        if self.removed {
            return Ok(());
        }
        self.pin_directory()?;
        self.verify_named_directory()?;
        let root = duplicate_fd(
            self.directory()?,
            "retain QEMU run directory for artifact cleanup",
            &self.path,
        )?;
        cleanup_directory_contents(root, &self.path, self.maximum_inodes)
    }

    fn pin_directory(&mut self) -> Result<(), LinuxQemuAttemptStorageError> {
        if self.directory.is_none() {
            self.directory = Some(open_directory_at(
                self.parent_directory()?,
                &self.name,
                &self.path,
            )?);
        }
        Ok(())
    }

    fn verify_named_directory(&self) -> Result<(), LinuxQemuAttemptStorageError> {
        let named = open_directory_at(self.parent_directory()?, &self.name, &self.path)?;
        let retained = fstat(self.directory()?)
            .map_err(|source| io_error("identify pinned QEMU run directory", &self.path, source))?;
        let actual = fstat(&named)
            .map_err(|source| io_error("identify named QEMU run directory", &self.path, source))?;
        if retained.st_dev != actual.st_dev || retained.st_ino != actual.st_ino {
            return Err(LinuxQemuAttemptStorageError::DirectoryIdentity {
                path: self.path.clone(),
            });
        }
        Ok(())
    }

    fn parent_directory(&self) -> Result<&OwnedFd, LinuxQemuAttemptStorageError> {
        self.parent_directory.as_ref().ok_or_else(|| {
            LinuxQemuAttemptStorageError::MissingAuthority {
                path: self.path.clone(),
            }
        })
    }
}

impl Drop for LinuxQemuAttemptStorageOwner {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Some(directory) = self.directory.take() {
            std::mem::forget(directory);
        }
        if let Some(parent_directory) = self.parent_directory.take() {
            std::mem::forget(parent_directory);
        }
        if let Some(quota) = self.quota.take() {
            std::mem::forget(quota);
        }
    }
}

/// Failed attempt-storage creation with optional retained cleanup authority.
#[derive(Debug, Error)]
#[error("failed to create Linux QEMU attempt storage: {source}")]
#[must_use = "recover partial storage authority or leave it enforced fail-closed"]
pub(crate) struct LinuxQemuAttemptStorageCreateError {
    source: LinuxQemuAttemptStorageError,
    owner: Option<Box<LinuxQemuAttemptStorageOwner>>,
}

impl LinuxQemuAttemptStorageCreateError {
    fn without_owner(source: impl Into<LinuxQemuAttemptStorageError>) -> Self {
        Self {
            source: source.into(),
            owner: None,
        }
    }

    fn with_owner(
        source: LinuxQemuAttemptStorageError,
        owner: LinuxQemuAttemptStorageOwner,
    ) -> Self {
        Self {
            source,
            owner: Some(Box::new(owner)),
        }
    }

    /// Returns the creation diagnostic without consuming retained authority.
    #[must_use]
    pub(crate) const fn source_error(&self) -> &LinuxQemuAttemptStorageError {
        &self.source
    }

    /// Recovers partial storage authority, when directory creation occurred.
    #[must_use = "retry cleanup or transfer the attempt storage to quarantine"]
    pub(crate) fn into_owner(mut self) -> Option<LinuxQemuAttemptStorageOwner> {
        self.owner.take().map(|owner| *owner)
    }
}

/// Failed release that retains the complete attempt-storage owner.
#[derive(Debug, Error)]
#[error("failed to release Linux QEMU attempt storage: {source}")]
#[must_use = "retry release or transfer the attempt storage to quarantine"]
pub(crate) struct LinuxQemuAttemptStorageReleaseError {
    owner: Box<LinuxQemuAttemptStorageOwner>,
    source: LinuxQemuAttemptStorageError,
}

impl LinuxQemuAttemptStorageReleaseError {
    /// Returns the release diagnostic without consuming retained authority.
    #[must_use]
    pub(crate) const fn source_error(&self) -> &LinuxQemuAttemptStorageError {
        &self.source
    }

    /// Recovers the complete owner for exact retry or quarantine.
    #[must_use = "retry release or transfer the attempt storage to quarantine"]
    pub(crate) fn into_owner(self) -> LinuxQemuAttemptStorageOwner {
        *self.owner
    }
}

/// Stable storage-policy, allocation, identity, or kernel-operation failure.
#[derive(Debug, Error)]
pub(crate) enum LinuxQemuAttemptStorageError {
    /// Configuration cannot establish the required bound or namespace.
    #[error("invalid Linux QEMU attempt-storage configuration: {message}")]
    InvalidConfig {
        /// Stable validation diagnostic.
        message: &'static str,
    },
    /// The run root is not privately owned by this supervisor.
    #[error("QEMU attempt-storage root must be supervisor-owned mode 0700: {path}")]
    RootPolicy {
        /// Diagnostic root path.
        path: PathBuf,
    },
    /// A prior attempt or unrelated entry remains in the dedicated root.
    #[error("QEMU attempt-storage root is not empty: {path}")]
    RootNotEmpty {
        /// Diagnostic root path.
        path: PathBuf,
    },
    /// Another daemon owns the cooperative namespace lock.
    #[error("QEMU attempt-storage root is already locked: {path}")]
    NamespaceLocked {
        /// Diagnostic root path.
        path: PathBuf,
    },
    /// Every reserved project identifier is owned by a live or quarantined attempt.
    #[error("QEMU attempt-storage project-ID pool is exhausted")]
    ProjectIdsExhausted,
    /// The daemon-incarnation attempt-name sequence cannot advance.
    #[error("QEMU attempt-storage name sequence is exhausted")]
    SequenceExhausted,
    /// A named run directory no longer matches its pinned inode.
    #[error("QEMU attempt run-directory identity changed: {path}")]
    DirectoryIdentity {
        /// Diagnostic run-directory path.
        path: PathBuf,
    },
    /// Run-directory ownership or mode did not read back exactly.
    #[error("QEMU attempt run-directory ownership did not verify: {path}")]
    DirectoryPolicy {
        /// Diagnostic run-directory path.
        path: PathBuf,
    },
    /// A required pinned descriptor was already released.
    #[error("QEMU attempt-storage authority is unavailable: {path}")]
    MissingAuthority {
        /// Diagnostic run-directory path.
        path: PathBuf,
    },
    /// Project-ID ownership did not match the linear owner lifecycle.
    #[error("QEMU attempt-storage project-ID ownership is inconsistent")]
    ProjectIdOwnership,
    /// Artifact cleanup exceeded a reviewed structural bound or invariant.
    #[error("QEMU attempt artifact cleanup failed for {path}: {message}")]
    CleanupBound {
        /// Diagnostic run-directory path.
        path: PathBuf,
        /// Stable cleanup diagnostic.
        message: &'static str,
    },
    /// The monotone generation-directory sequence cannot advance.
    #[error("QEMU attempt generation-directory sequence is exhausted: {path}")]
    GenerationSequenceExhausted {
        /// Diagnostic attempt-root path.
        path: PathBuf,
    },
    /// The exact-VMState container did not match its required empty-file policy.
    #[error("QEMU exact-VMState container policy did not verify: {path}")]
    VmStatePolicy {
        /// Diagnostic exact-VMState path.
        path: PathBuf,
    },
    /// The child identity is not isolated from the supervisor credentials.
    #[error("QEMU attempt-storage child credentials are not isolated: {source}")]
    ChildCredentials {
        /// Exact guarded-spawn credential validation failure.
        #[source]
        source: crate::QemuSpawnError,
    },
    /// Descriptor-pinned guarded-launch preparation failed.
    #[error("QEMU attempt run-directory preparation failed: {0}")]
    LaunchPreparation(#[source] QemuSpawnError),
    /// The ext4 project-quota transaction failed.
    #[error(transparent)]
    ProjectQuota(#[from] LinuxProjectQuotaError),
    /// One filesystem operation failed.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Diagnostic path.
        path: PathBuf,
        /// Underlying operating-system failure.
        #[source]
        source: io::Error,
    },
}

#[derive(Debug)]
struct ProjectIdPool {
    first: u32,
    allocated: Box<[AtomicBool]>,
    cursor: AtomicU32,
}

impl ProjectIdPool {
    fn new(first: u32, count: u32) -> Self {
        let allocated = (0..count)
            .map(|_| AtomicBool::new(false))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            first,
            allocated,
            cursor: AtomicU32::new(0),
        }
    }

    fn allocate(self: &Arc<Self>) -> Option<ProjectIdLease> {
        let count = u32::try_from(self.allocated.len()).ok()?;
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % count;
        for offset in 0..count {
            let index = (start + offset) % count;
            let slot = &self.allocated[usize::try_from(index).ok()?];
            if slot
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.cursor.store((index + 1) % count, Ordering::Relaxed);
                return Some(ProjectIdLease {
                    pool: Arc::clone(self),
                    index,
                    committed: false,
                    recycled: false,
                });
            }
        }
        None
    }

    fn release(&self, index: u32) -> Result<(), LinuxQemuAttemptStorageError> {
        let slot = self
            .allocated
            .get(
                usize::try_from(index)
                    .map_err(|_| LinuxQemuAttemptStorageError::ProjectIdOwnership)?,
            )
            .ok_or(LinuxQemuAttemptStorageError::ProjectIdOwnership)?;
        slot.compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| LinuxQemuAttemptStorageError::ProjectIdOwnership)
    }
}

#[derive(Debug)]
struct ProjectIdLease {
    pool: Arc<ProjectIdPool>,
    index: u32,
    committed: bool,
    recycled: bool,
}

impl ProjectIdLease {
    fn commit(mut self) -> Self {
        self.committed = true;
        self
    }

    fn project_id(&self) -> u32 {
        self.pool.first + self.index
    }

    fn recycle(&mut self) -> Result<(), LinuxQemuAttemptStorageError> {
        if self.recycled {
            return Ok(());
        }
        self.pool.release(self.index)?;
        self.recycled = true;
        Ok(())
    }
}

impl Drop for ProjectIdLease {
    fn drop(&mut self) {
        if !self.committed && !self.recycled {
            let _ = self.pool.release(self.index);
            self.recycled = true;
        }
    }
}

#[derive(Debug)]
struct CleanupDirectory {
    name_in_parent: Option<CString>,
    device: u64,
    inode: u64,
    children: Vec<CString>,
}

fn cleanup_directory_contents(
    mut directory: OwnedFd,
    path: &Path,
    maximum_inodes: u64,
) -> Result<(), LinuxQemuAttemptStorageError> {
    let root_metadata =
        fstat(&directory).map_err(|source| io_error("identify QEMU cleanup root", path, source))?;
    let root_device = root_metadata.st_dev;
    let mut observed_entries = 1_u64;
    let mut stack = vec![scan_cleanup_directory(
        &directory,
        None,
        path,
        root_device,
        maximum_inodes,
        &mut observed_entries,
    )?];

    loop {
        let Some(frame) = stack.last_mut() else {
            return Err(LinuxQemuAttemptStorageError::CleanupBound {
                path: path.to_owned(),
                message: "artifact-cleanup traversal lost its root frame",
            });
        };
        if let Some(child_name) = frame.children.pop() {
            let child = openat(
                &directory,
                child_name.as_c_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|source| io_error("open nested QEMU artifact directory", path, source))?;
            let child_frame = scan_cleanup_directory(
                &child,
                Some(child_name),
                path,
                root_device,
                maximum_inodes,
                &mut observed_entries,
            )?;
            directory = child;
            stack.push(child_frame);
            continue;
        }

        fsync(&directory).map_err(|source| {
            io_error("synchronize cleaned QEMU artifact directory", path, source)
        })?;
        if stack.len() == 1 {
            return Ok(());
        }
        let child = stack
            .pop()
            .ok_or_else(|| LinuxQemuAttemptStorageError::CleanupBound {
                path: path.to_owned(),
                message: "artifact-cleanup traversal lost a child frame",
            })?;
        let child_name = child.name_in_parent.as_ref().ok_or_else(|| {
            LinuxQemuAttemptStorageError::CleanupBound {
                path: path.to_owned(),
                message: "nested artifact directory omitted its parent name",
            }
        })?;
        let parent = openat(
            &directory,
            "..",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| io_error("reopen QEMU artifact parent directory", path, source))?;
        let parent_frame =
            stack
                .last()
                .ok_or_else(|| LinuxQemuAttemptStorageError::CleanupBound {
                    path: path.to_owned(),
                    message: "nested artifact directory omitted its parent frame",
                })?;
        verify_cleanup_directory_identity(&parent, parent_frame.device, parent_frame.inode, path)?;
        verify_cleanup_child_identity(&parent, child_name, &directory, path)?;
        unlinkat(&parent, child_name.as_c_str(), AtFlags::REMOVEDIR)
            .map_err(|source| io_error("remove nested QEMU artifact directory", path, source))?;
        directory = parent;
    }
}

fn scan_cleanup_directory(
    directory: &OwnedFd,
    name_in_parent: Option<CString>,
    path: &Path,
    root_device: u64,
    maximum_inodes: u64,
    observed_entries: &mut u64,
) -> Result<CleanupDirectory, LinuxQemuAttemptStorageError> {
    let directory_metadata = fstat(directory)
        .map_err(|source| io_error("identify QEMU artifact directory", path, source))?;
    if directory_metadata.st_dev != root_device {
        return Err(LinuxQemuAttemptStorageError::DirectoryIdentity {
            path: path.to_owned(),
        });
    }
    let scan = openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| io_error("open QEMU artifact directory for cleanup", path, source))?;
    let mut buffer = [MaybeUninit::uninit(); ROOT_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(scan, &mut buffer);
    let mut children = Vec::new();
    while let Some(entry) = entries.next() {
        let entry =
            entry.map_err(|source| io_error("scan QEMU artifact directory", path, source))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *observed_entries = observed_entries.checked_add(1).ok_or_else(|| {
            LinuxQemuAttemptStorageError::CleanupBound {
                path: path.to_owned(),
                message: "attempt artifact entry count overflowed",
            }
        })?;
        if *observed_entries > maximum_inodes {
            return Err(LinuxQemuAttemptStorageError::CleanupBound {
                path: path.to_owned(),
                message: "attempt artifacts exceed the cleanup-entry ceiling",
            });
        }
        let metadata = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|source| io_error("inspect QEMU attempt artifact", path, source))?;
        if metadata.st_dev != root_device {
            return Err(LinuxQemuAttemptStorageError::DirectoryIdentity {
                path: path.to_owned(),
            });
        }
        if FileType::from_raw_mode(metadata.st_mode) == FileType::Directory {
            children
                .try_reserve(1)
                .map_err(|_| LinuxQemuAttemptStorageError::CleanupBound {
                    path: path.to_owned(),
                    message: "attempt artifact cleanup cannot retain bounded child names",
                })?;
            children.push(name.to_owned());
        } else {
            unlinkat(directory, name, AtFlags::empty())
                .map_err(|source| io_error("remove QEMU attempt artifact", path, source))?;
        }
    }
    children.sort();
    Ok(CleanupDirectory {
        name_in_parent,
        device: directory_metadata.st_dev,
        inode: directory_metadata.st_ino,
        children,
    })
}

fn verify_cleanup_directory_identity(
    directory: &OwnedFd,
    expected_device: u64,
    expected_inode: u64,
    path: &Path,
) -> Result<(), LinuxQemuAttemptStorageError> {
    let actual = fstat(directory)
        .map_err(|source| io_error("reauthenticate QEMU artifact directory", path, source))?;
    if actual.st_dev != expected_device || actual.st_ino != expected_inode {
        return Err(LinuxQemuAttemptStorageError::DirectoryIdentity {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn verify_cleanup_child_identity(
    parent: &OwnedFd,
    name: &CString,
    child: &OwnedFd,
    path: &Path,
) -> Result<(), LinuxQemuAttemptStorageError> {
    let named = openat(
        parent,
        name.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        io_error(
            "reauthenticate nested QEMU artifact directory",
            path,
            source,
        )
    })?;
    let expected = fstat(child)
        .map_err(|source| io_error("identify retained QEMU artifact directory", path, source))?;
    let actual = fstat(&named)
        .map_err(|source| io_error("identify named QEMU artifact directory", path, source))?;
    if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
        return Err(LinuxQemuAttemptStorageError::DirectoryIdentity {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn valid_attempt_namespace(namespace: &str) -> bool {
    !namespace.is_empty()
        && namespace.len() <= MAX_ATTEMPT_NAMESPACE_BYTES
        && namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn attempt_name(namespace: &str, sequence: u64) -> String {
    format!("{namespace}-{sequence:016x}")
}

fn generation_name(generation: u64) -> String {
    format!("{GENERATION_NAME_PREFIX}{generation:016x}")
}

fn validate_root_policy(root: &OwnedFd, path: &Path) -> Result<(), LinuxQemuAttemptStorageError> {
    let metadata = fstat(root)
        .map_err(|source| io_error("inspect QEMU attempt-storage root", path, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != geteuid().as_raw()
        || metadata.st_mode & 0o777 != 0o700
    {
        return Err(LinuxQemuAttemptStorageError::RootPolicy {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn verify_directory_policy(
    directory: &OwnedFd,
    path: &Path,
    child_user_id: u32,
    child_group_id: u32,
) -> Result<(), LinuxQemuAttemptStorageError> {
    let metadata = fstat(directory)
        .map_err(|source| io_error("inspect QEMU attempt run directory", path, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != child_user_id
        || metadata.st_gid != child_group_id
        || metadata.st_mode & 0o777 != 0o700
    {
        return Err(LinuxQemuAttemptStorageError::DirectoryPolicy {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// Creates and authenticates one monotone child below the quota-bound attempt root.
fn create_generation_directory(
    attempt_directory: &OwnedFd,
    attempt_path: &Path,
    generation: u64,
    child_user_id: u32,
    child_group_id: u32,
) -> Result<(PathBuf, OwnedFd), LinuxQemuAttemptStorageError> {
    let name = generation_name(generation);
    let path = attempt_path.join(&name);
    mkdirat(
        attempt_directory,
        name.as_str(),
        Mode::from_bits_truncate(0o700),
    )
    .map_err(|source| io_error("create QEMU generation directory", &path, source))?;

    let directory = open_directory_at(attempt_directory, &name, &path)?;
    fchmod(&directory, Mode::from_bits_truncate(0o700))
        .map_err(|source| io_error("set QEMU generation-directory mode", &path, source))?;
    fchown(
        &directory,
        Some(Uid::from_raw(child_user_id)),
        Some(Gid::from_raw(child_group_id)),
    )
    .map_err(|source| io_error("assign QEMU generation-directory ownership", &path, source))?;
    fsync(&directory)
        .map_err(|source| io_error("synchronize QEMU generation directory", &path, source))?;
    verify_directory_policy(&directory, &path, child_user_id, child_group_id)?;
    fsync(attempt_directory)
        .map_err(|source| io_error("synchronize QEMU generation creation", &path, source))?;
    Ok((path, directory))
}

/// Creates or resumes policy installation for the empty exact-VMState destination.
///
/// Retrying an interrupted setup may reopen the same empty regular file and
/// reapply its policy. Any file with content is treated as materialization state
/// owned by another phase and is never silently reused.
fn provision_vmstate_file(
    directory: &OwnedFd,
    directory_path: &Path,
    child_user_id: u32,
    child_group_id: u32,
) -> Result<OwnedFd, LinuxQemuAttemptStorageError> {
    let path = directory_path.join(DEFAULT_VMSTATE_FILE_NAME);
    let create_flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let vmstate = match openat(
        directory,
        DEFAULT_VMSTATE_FILE_NAME,
        create_flags,
        Mode::from_bits_truncate(0o600),
    ) {
        Ok(vmstate) => vmstate,
        Err(rustix::io::Errno::EXIST) => openat(
            directory,
            DEFAULT_VMSTATE_FILE_NAME,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| io_error("reopen exact-VMState container", &path, source))?,
        Err(source) => {
            return Err(io_error("create exact-VMState container", &path, source));
        }
    };

    let metadata = fstat(&vmstate)
        .map_err(|source| io_error("inspect exact-VMState container", &path, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile || metadata.st_size != 0 {
        return Err(LinuxQemuAttemptStorageError::VmStatePolicy { path });
    }

    fchmod(&vmstate, Mode::from_bits_truncate(0o600))
        .map_err(|source| io_error("set exact-VMState container mode", &path, source))?;
    fchown(
        &vmstate,
        Some(Uid::from_raw(child_user_id)),
        Some(Gid::from_raw(child_group_id)),
    )
    .map_err(|source| io_error("assign exact-VMState container ownership", &path, source))?;
    fsync(&vmstate)
        .map_err(|source| io_error("synchronize exact-VMState container", &path, source))?;
    fsync(directory)
        .map_err(|source| io_error("synchronize exact-VMState directory", &path, source))?;

    let metadata = fstat(&vmstate)
        .map_err(|source| io_error("verify exact-VMState container", &path, source))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != child_user_id
        || metadata.st_gid != child_group_id
        || metadata.st_mode & 0o777 != 0o600
        || metadata.st_size != 0
    {
        return Err(LinuxQemuAttemptStorageError::VmStatePolicy { path });
    }
    Ok(vmstate)
}

fn validate_empty_root(root: &OwnedFd, path: &Path) -> Result<(), LinuxQemuAttemptStorageError> {
    let scan = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| io_error("open QEMU attempt-storage root for scan", path, source))?;
    let mut buffer = [MaybeUninit::uninit(); ROOT_SCAN_BUFFER_BYTES];
    let mut entries = RawDir::new(scan, &mut buffer);
    while let Some(entry) = entries.next() {
        let entry =
            entry.map_err(|source| io_error("scan QEMU attempt-storage root", path, source))?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Err(LinuxQemuAttemptStorageError::RootNotEmpty {
                path: path.to_owned(),
            });
        }
    }
    Ok(())
}

fn lock_namespace(root: &OwnedFd, path: &Path) -> Result<(), LinuxQemuAttemptStorageError> {
    flock(root, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
        if source == rustix::io::Errno::WOULDBLOCK {
            LinuxQemuAttemptStorageError::NamespaceLocked {
                path: path.to_owned(),
            }
        } else {
            io_error("lock QEMU attempt-storage root", path, source)
        }
    })
}

fn open_directory_at(
    parent: &OwnedFd,
    name: &str,
    path: &Path,
) -> Result<OwnedFd, LinuxQemuAttemptStorageError> {
    openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| io_error("open QEMU attempt run directory", path, source))
}

fn duplicate_fd(
    descriptor: &OwnedFd,
    operation: &'static str,
    path: &Path,
) -> Result<OwnedFd, LinuxQemuAttemptStorageError> {
    fcntl_dupfd_cloexec(descriptor, 0).map_err(|source| io_error(operation, path, source))
}

fn invalid_config(message: &'static str) -> LinuxQemuAttemptStorageError {
    LinuxQemuAttemptStorageError::InvalidConfig { message }
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: rustix::io::Errno,
) -> LinuxQemuAttemptStorageError {
    LinuxQemuAttemptStorageError::Io {
        operation,
        path: path.to_owned(),
        source: source.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn must_succeed<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error:?}"),
        }
    }

    fn must_exist<T>(value: Option<T>, context: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    fn must_fail<T: std::fmt::Debug, E>(result: Result<T, E>, context: &str) -> E {
        match result {
            Ok(value) => panic!("{context}: unexpectedly succeeded with {value:?}"),
            Err(error) => error,
        }
    }

    fn test_child_id() -> u32 {
        must_exist(
            (100_000..100_128)
                .find(|candidate| QemuChildCredentials::new(*candidate, *candidate).is_ok()),
            "one test child identity must differ from supervisor credentials",
        )
    }

    fn config() -> LinuxQemuAttemptStorageConfig {
        let child_id = test_child_id();
        must_succeed(
            LinuxQemuAttemptStorageConfig::new(
                "/var/lib/crucible/attempts",
                "daemon_1",
                10_000,
                4,
                child_id,
                child_id,
                4096,
            ),
            "valid storage configuration",
        )
    }

    #[test]
    fn configuration_rejects_invalid_values_before_storage_access() {
        assert!(LinuxQemuAttemptStorageConfig::new("relative", "daemon", 1, 1, 1, 1, 1,).is_err());
        assert!(LinuxQemuAttemptStorageConfig::new("/", "daemon", 1, 1, 1, 1, 1).is_err());
        assert!(
            LinuxQemuAttemptStorageConfig::new("/missing", "bad/name", 1, 1, 1, 1, 1,).is_err()
        );
        assert!(LinuxQemuAttemptStorageConfig::new("/missing", "daemon", 0, 1, 1, 1, 1,).is_err());
        assert!(
            LinuxQemuAttemptStorageConfig::new(
                "/missing",
                "daemon",
                MAX_QUOTACTL_PROJECT_ID,
                2,
                1,
                1,
                1,
            )
            .is_err()
        );
        assert!(
            LinuxQemuAttemptStorageConfig::new(
                "/missing",
                "daemon",
                1,
                1,
                test_child_id(),
                test_child_id(),
                MAX_ATTEMPT_ARTIFACT_INODES + 1,
            )
            .is_err()
        );
        assert!(
            LinuxQemuAttemptStorageConfig::new(
                "/missing",
                "daemon",
                1,
                MAX_PROJECT_ID_COUNT + 1,
                1,
                1,
                1,
            )
            .is_err()
        );
        assert!(LinuxQemuAttemptStorageConfig::new("/missing", "daemon", 1, 1, 0, 1, 1,).is_err());
        assert!(
            LinuxQemuAttemptStorageConfig::new("/missing", "daemon", 1, 1, u32::MAX, 1, 1,)
                .is_err()
        );
        assert!(
            LinuxQemuAttemptStorageConfig::new(
                "/missing",
                "daemon",
                1,
                1,
                test_child_id(),
                test_child_id(),
                0,
            )
            .is_err()
        );
        assert!(
            LinuxQemuAttemptStorageConfig::new(
                "/missing",
                "daemon",
                1,
                1,
                geteuid().as_raw(),
                test_child_id(),
                1,
            )
            .is_err(),
            "the storage identity must differ from every supervisor identity"
        );
    }

    #[test]
    fn cleanup_is_descriptor_relative_and_does_not_follow_symlinks() {
        let root = must_succeed(tempfile::tempdir(), "temporary cleanup root");
        let outside = must_succeed(tempfile::NamedTempFile::new(), "external artifact");
        must_succeed(
            std::fs::write(root.path().join("artifact"), b"discard"),
            "ordinary artifact",
        );
        must_succeed(
            std::os::unix::fs::symlink(outside.path(), root.path().join("external")),
            "external symlink",
        );
        must_succeed(
            std::fs::create_dir(root.path().join("nested")),
            "nested artifact directory",
        );
        must_succeed(
            std::fs::write(root.path().join("nested/child"), b"discard"),
            "nested artifact",
        );
        let directory = must_succeed(
            open(
                root.path(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ),
            "open cleanup root",
        );

        must_succeed(
            cleanup_directory_contents(directory, root.path(), 5),
            "bounded cleanup",
        );

        assert_eq!(
            must_succeed(std::fs::read_dir(root.path()), "read cleaned root").count(),
            0
        );
        assert!(outside.path().is_file(), "symlink target remains untouched");
    }

    #[test]
    fn vmstate_provisioning_uses_the_pinned_directory_and_is_retryable() {
        let root = must_succeed(tempfile::tempdir(), "temporary VMState root");
        let diagnostic = root.path().join("attempt");
        let retained = root.path().join("retained");
        must_succeed(std::fs::create_dir(&diagnostic), "create attempt directory");
        let directory = must_succeed(
            open(
                &diagnostic,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ),
            "pin attempt directory",
        );
        must_succeed(
            std::fs::rename(&diagnostic, &retained),
            "rename pinned attempt directory",
        );
        must_succeed(std::fs::create_dir(&diagnostic), "create path replacement");

        let user = geteuid().as_raw();
        let group = rustix::process::getegid().as_raw();
        let first = must_succeed(
            provision_vmstate_file(&directory, &diagnostic, user, group),
            "provision descriptor-relative VMState",
        );
        let first_metadata = must_succeed(fstat(&first), "inspect first VMState descriptor");
        let second = must_succeed(
            provision_vmstate_file(&directory, &diagnostic, user, group),
            "retry exact VMState provisioning",
        );
        let second_metadata = must_succeed(fstat(&second), "inspect second VMState descriptor");

        assert_eq!(first_metadata.st_dev, second_metadata.st_dev);
        assert_eq!(first_metadata.st_ino, second_metadata.st_ino);
        assert_eq!(first_metadata.st_mode & 0o777, 0o600);
        assert_eq!(first_metadata.st_uid, user);
        assert_eq!(first_metadata.st_gid, group);
        assert_eq!(first_metadata.st_size, 0);
        assert!(retained.join(DEFAULT_VMSTATE_FILE_NAME).is_file());
        assert!(!diagnostic.join(DEFAULT_VMSTATE_FILE_NAME).exists());
    }

    #[test]
    fn generation_directories_are_monotone_distinct_and_descriptor_pinned() {
        let root = must_succeed(tempfile::tempdir(), "temporary attempt root");
        let directory = must_succeed(
            open(
                root.path(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ),
            "pin attempt root",
        );
        let user = geteuid().as_raw();
        let group = rustix::process::getegid().as_raw();

        let (first_path, first) = must_succeed(
            create_generation_directory(&directory, root.path(), 1, user, group),
            "create first generation",
        );
        let (second_path, second) = must_succeed(
            create_generation_directory(&directory, root.path(), 2, user, group),
            "create second generation",
        );
        let first_identity = must_succeed(fstat(&first), "identify first generation");
        let second_identity = must_succeed(fstat(&second), "identify second generation");
        assert_eq!(first_path, root.path().join("generation-0000000000000001"));
        assert_eq!(second_path, root.path().join("generation-0000000000000002"));
        assert_ne!(first_identity.st_ino, second_identity.st_ino);

        let first_vmstate = must_succeed(
            provision_vmstate_file(&first, &first_path, user, group),
            "provision first generation VMState",
        );
        let second_vmstate = must_succeed(
            provision_vmstate_file(&second, &second_path, user, group),
            "provision second generation VMState",
        );
        let first_vmstate_identity =
            must_succeed(fstat(&first_vmstate), "identify first generation VMState");
        let second_vmstate_identity =
            must_succeed(fstat(&second_vmstate), "identify second generation VMState");
        assert_ne!(
            first_vmstate_identity.st_ino,
            second_vmstate_identity.st_ino
        );
    }

    #[test]
    fn cleanup_depth_is_bounded_by_inodes_instead_of_open_descriptors() {
        const DEPTH: usize = 300;

        let root = must_succeed(tempfile::tempdir(), "temporary cleanup root");
        let mut current = must_succeed(
            open(
                root.path(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ),
            "open cleanup root",
        );
        for _ in 0..DEPTH {
            must_succeed(
                mkdirat(&current, "nested", Mode::from_bits_truncate(0o700)),
                "create deep artifact directory",
            );
            current = must_succeed(
                openat(
                    &current,
                    "nested",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                ),
                "descend into deep artifact directory",
            );
        }
        drop(current);
        let directory = must_succeed(
            open(
                root.path(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ),
            "reopen cleanup root",
        );

        must_succeed(
            cleanup_directory_contents(directory, root.path(), (DEPTH + 1) as u64),
            "deep bounded cleanup",
        );
        assert_eq!(
            must_succeed(std::fs::read_dir(root.path()), "read cleaned root").count(),
            0
        );
    }

    #[test]
    fn cleanup_entry_bound_fails_closed_and_allows_exact_retry() {
        let root = must_succeed(tempfile::tempdir(), "temporary cleanup root");
        must_succeed(std::fs::write(root.path().join("a"), b"a"), "artifact a");
        must_succeed(std::fs::write(root.path().join("b"), b"b"), "artifact b");
        let open_root = || {
            must_succeed(
                open(
                    root.path(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                ),
                "open cleanup root",
            )
        };

        let error = must_fail(
            cleanup_directory_contents(open_root(), root.path(), 2),
            "cleanup over inode ceiling",
        );
        assert!(matches!(
            error,
            LinuxQemuAttemptStorageError::CleanupBound { .. }
        ));
        assert_eq!(
            must_succeed(std::fs::read_dir(root.path()), "read partial cleanup").count(),
            1,
            "partial removal is monotone"
        );

        must_succeed(
            cleanup_directory_contents(open_root(), root.path(), 2),
            "retry remaining bounded cleanup",
        );
        assert_eq!(
            must_succeed(std::fs::read_dir(root.path()), "read cleaned root").count(),
            0
        );
    }

    #[test]
    fn configuration_and_names_preserve_exact_bounds() {
        let config = config();
        assert_eq!(config.run_root(), Path::new("/var/lib/crucible/attempts"));
        assert_eq!(config.attempt_namespace(), "daemon_1");
        assert_eq!(config.first_project_id(), 10_000);
        assert_eq!(config.project_id_count(), 4);
        assert_eq!(config.child_user_id(), test_child_id());
        assert_eq!(config.child_group_id(), test_child_id());
        assert_eq!(config.maximum_inodes(), 4096);
        assert_eq!(attempt_name("daemon_1", 0), "daemon_1-0000000000000000");
        assert_eq!(
            attempt_name("daemon_1", u64::MAX),
            "daemon_1-ffffffffffffffff"
        );
        let maximum_namespace = "a".repeat(MAX_ATTEMPT_NAMESPACE_BYTES);
        assert_eq!(
            attempt_name(&maximum_namespace, u64::MAX).len(),
            MAX_RUN_DIRECTORY_NAME_BYTES
        );
        assert_eq!(generation_name(1), "generation-0000000000000001");
        assert_eq!(generation_name(u64::MAX), "generation-ffffffffffffffff");
    }

    #[test]
    fn project_ids_recycle_only_before_commit_or_after_explicit_release() {
        let pool = Arc::new(ProjectIdPool::new(20_000, 2));
        let first = must_exist(pool.allocate(), "first project ID");
        assert_eq!(first.project_id(), 20_000);
        drop(first);
        let recycled = must_exist(pool.allocate(), "uncommitted ID recycled");
        assert_eq!(recycled.project_id(), 20_001);
        let mut committed = recycled.commit();
        let other = must_exist(pool.allocate(), "second project ID").commit();
        assert!(pool.allocate().is_none());
        drop(other);
        assert!(
            pool.allocate().is_none(),
            "dropped committed ID stays reserved"
        );
        must_succeed(committed.recycle(), "explicit release");
        assert!(pool.allocate().is_some());
    }

    #[test]
    fn ordinary_filesystem_fails_closed_before_child_creation() {
        let root = must_succeed(tempfile::tempdir(), "temporary root");
        must_succeed(
            std::fs::set_permissions(
                root.path(),
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            ),
            "private root mode",
        );
        let config = must_succeed(
            LinuxQemuAttemptStorageConfig::new(
                root.path(),
                "daemon",
                10_000,
                2,
                test_child_id(),
                test_child_id(),
                128,
            ),
            "valid configuration",
        );
        let error = must_fail(
            LinuxQemuAttemptStorageFactory::open(config),
            "non-ext4 or quota-disabled test root must fail",
        );
        assert!(matches!(
            error,
            LinuxQemuAttemptStorageError::ProjectQuota(
                LinuxProjectQuotaError::UnsupportedFilesystem { .. }
                    | LinuxProjectQuotaError::Io { .. }
            )
        ));
        assert_eq!(
            must_succeed(std::fs::read_dir(root.path()), "read root").count(),
            0
        );
    }

    #[test]
    fn public_root_mode_is_rejected_before_quota_access() {
        let root = must_succeed(tempfile::tempdir(), "temporary root");
        must_succeed(
            std::fs::set_permissions(
                root.path(),
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
            ),
            "public root mode",
        );
        let config = must_succeed(
            LinuxQemuAttemptStorageConfig::new(
                root.path(),
                "daemon",
                10_000,
                2,
                test_child_id(),
                test_child_id(),
                128,
            ),
            "valid configuration",
        );
        let error = must_fail(
            LinuxQemuAttemptStorageFactory::open(config),
            "public root must fail before quota access",
        );
        assert!(matches!(
            error,
            LinuxQemuAttemptStorageError::RootPolicy { .. }
        ));
        assert_eq!(
            must_succeed(std::fs::read_dir(root.path()), "read root").count(),
            0
        );
    }
}
