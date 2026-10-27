//! Original opened artifact/runtime guard for the fixed worker profile.
//!
//! Manifest claims are measured by the parent using these same opened files.
//! Read-only mounts and retained kernel file leases are actual prerequisites;
//! no pathname-only validation or fallback can mint this guard.

use super::*;
use crate::{LinuxReadLeaseFile, LinuxReadLeaseOwner};
use rustix::fs::{OFlags, StatVfsMountFlags, fstat, fstatvfs, open};
use rustix::io::fcntl_dupfd_cloexec;
use std::os::fd::AsRawFd;

struct OriginalProgram {
    launcher: Mutex<LinuxReadLeaseFile>,
    launcher_measurement: File,
    launcher_exec: OwnedFd,
    worker: Mutex<LinuxReadLeaseFile>,
    worker_measurement: File,
    worker_path: PathBuf,
    worker_digest: [u8; 32],
    algorithm_digest: [u8; 32],
    roots: Vec<(PathBuf, OwnedFd)>,
    revoked: AtomicBool,
}

/// Retains the original opened helper/worker and exact read-only runtime mounts.
#[derive(Clone)]
pub struct LinuxPureWorkerProgram {
    original: Arc<OriginalProgram>,
}

/// Identifies the same original opened program; equality is not a digest claim.
#[derive(Clone)]
pub struct LinuxPureWorkerProgramIdentity {
    original: Arc<OriginalProgram>,
}

impl PartialEq for LinuxPureWorkerProgramIdentity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.original, &other.original)
    }
}

impl Eq for LinuxPureWorkerProgramIdentity {}

impl std::fmt::Debug for LinuxPureWorkerProgramIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinuxPureWorkerProgramIdentity")
            .finish_non_exhaustive()
    }
}

impl LinuxPureWorkerProgram {
    /// Opens original artifacts with leases and actual read-only runtime mounts.
    ///
    /// The parent must measure these SAME opened files and complete runtime
    /// inventory against its selected manifest before binding a Source job.
    /// This guard authenticates kernel/original identity, not manifest claims.
    ///
    /// # Errors
    /// Refuses missing read-only mount/lease support, noncanonical or broad roots,
    /// conflicting files, changed ownership or native open failures. It never
    /// falls back to pathname execution or renewed lease acquisition.
    pub fn open(
        launcher: &Path,
        worker: &Path,
        runtime_roots: &[PathBuf],
        worker_digest: [u8; 32],
        algorithm_digest: [u8; 32],
    ) -> Result<Self, LinuxPureWorkerError> {
        if !normalized_absolute(launcher)
            || !normalized_absolute(worker)
            || runtime_roots.is_empty()
            || runtime_roots.len() > 128
            || runtime_roots.iter().enumerate().any(|(index, path)| {
                !canonical_store_root(path) || runtime_roots[..index].contains(path)
            })
            || !runtime_roots.iter().any(|root| launcher.starts_with(root))
            || !runtime_roots.iter().any(|root| worker.starts_with(root))
        {
            return Err(LinuxPureWorkerError::Configuration);
        }
        check_loader_policy()?;
        let owner = Arc::new(
            LinuxReadLeaseOwner::new()
                .map_err(|_| LinuxPureWorkerError::HostControlsUnavailable)?,
        );
        let launcher = LinuxReadLeaseFile::open(launcher, Some(owner.clone()))
            .map_err(|_| LinuxPureWorkerError::HostControlsUnavailable)?;
        let worker_file = LinuxReadLeaseFile::open(worker, Some(owner))
            .map_err(|_| LinuxPureWorkerError::HostControlsUnavailable)?;
        for file in [&launcher, &worker_file] {
            file.lease()
                .ok_or(LinuxPureWorkerError::HostControlsUnavailable)?
                .verify_current()
                .map_err(|_| LinuxPureWorkerError::HostControlsUnavailable)?;
            if !fstatvfs(file.file())
                .map_err(io::Error::from)?
                .f_flag
                .contains(StatVfsMountFlags::RDONLY)
            {
                return Err(LinuxPureWorkerError::HostControlsUnavailable);
            }
        }
        let mut roots = Vec::new();
        for path in runtime_roots {
            let descriptor = open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from)?;
            if !fstatvfs(&descriptor)
                .map_err(io::Error::from)?
                .f_flag
                .contains(StatVfsMountFlags::RDONLY)
            {
                return Err(LinuxPureWorkerError::HostControlsUnavailable);
            }
            roots.push((path.clone(), descriptor));
        }
        let launcher_measurement = launcher.file().try_clone()?;
        let worker_measurement = worker_file.file().try_clone()?;
        let launcher_exec = fcntl_dupfd_cloexec(launcher.file(), 3).map_err(io::Error::from)?;
        let result = Self {
            original: Arc::new(OriginalProgram {
                launcher: Mutex::new(launcher),
                launcher_measurement,
                launcher_exec,
                worker: Mutex::new(worker_file),
                worker_measurement,
                worker_path: worker.to_owned(),
                worker_digest,
                algorithm_digest,
                roots,
                revoked: AtomicBool::new(false),
            }),
        };
        result.verify_current()?;
        Ok(result)
    }

    /// Borrows the original helper file for the parent's complete measurement.
    pub fn launcher_file(&self) -> &File {
        &self.original.launcher_measurement
    }
    /// Borrows the original worker file for the parent's complete measurement.
    pub fn worker_file(&self) -> &File {
        &self.original.worker_measurement
    }
    /// Copies the worker digest claim that the parent measures before binding Source.
    pub fn worker_digest(&self) -> [u8; 32] {
        self.original.worker_digest
    }

    /// Copies the selected pure algorithm identity DATA, without certifying it.
    pub fn algorithm_digest(&self) -> [u8; 32] {
        self.original.algorithm_digest
    }

    /// Returns opaque original instance identity without a forgeable constructor.
    pub fn identity(&self) -> LinuxPureWorkerProgramIdentity {
        LinuxPureWorkerProgramIdentity {
            original: self.original.clone(),
        }
    }
    pub(super) fn same_identity(&self, other: &LinuxPureWorkerProgramIdentity) -> bool {
        Arc::ptr_eq(&self.original, &other.original)
    }
    pub(super) fn worker_path(&self) -> &Path {
        &self.original.worker_path
    }
    pub(super) fn runtime_roots(&self) -> impl Iterator<Item = &PathBuf> {
        self.original.roots.iter().map(|(p, _)| p)
    }
    pub(super) fn worker_device(&self) -> Result<(u64, u64), LinuxPureWorkerError> {
        let s = fstat(self.worker_file()).map_err(io::Error::from)?;
        Ok((s.st_dev, s.st_ino))
    }
    pub(super) fn direct_buffer_parts(&self) -> Result<(usize, usize), LinuxPureWorkerError> {
        let paths = self.original.roots.iter().try_fold(
            self.original.worker_path.capacity(),
            |sum, (path, _)| {
                sum.checked_add(path.capacity())
                    .ok_or(LinuxPureWorkerError::Configuration)
            },
        )?;
        let roster = self
            .original
            .roots
            .capacity()
            .checked_mul(std::mem::size_of::<(PathBuf, OwnedFd)>())
            .ok_or(LinuxPureWorkerError::Configuration)?;
        Ok((paths, roster))
    }

    /// Reports the same original program Arc's compiled payload layout as DATA.
    ///
    /// The caller separately counts the Arc control header, direct buffers and
    /// opaque acquired-lease notification backing. This performs no file query,
    /// lease validation, identity clone or native operation.
    pub fn retained_payload_layout_data(&self) -> std::alloc::Layout {
        std::alloc::Layout::for_value(self.original.as_ref())
    }

    /// Observes this retained program view's actual path and root-vector buffers.
    ///
    /// Repeated strong views retain all rows. Descriptor payloads and acquired
    /// lease notification backing remain separate from these selected buffers.
    /// No file, descriptor, pointer or live program authority escapes.
    ///
    /// # Errors
    /// Returns the observer's first refusal, preserving every original owner.
    pub fn observe_direct_buffers<E>(
        &self,
        observe: &mut impl FnMut(LinuxPureWorkerBufferCapacityData) -> Result<(), E>,
    ) -> Result<(), E> {
        let OriginalProgram {
            launcher: _,
            launcher_measurement: _,
            launcher_exec: _,
            worker: _,
            worker_measurement: _,
            worker_path,
            worker_digest: _,
            algorithm_digest: _,
            roots,
            revoked: _,
        } = self.original.as_ref();
        observe_program_buffers(worker_path, roots, observe)
    }

    /// Names concrete program layout and direct-buffer observation controls.
    pub fn retained_capacity_counter_scratch_data() -> usize {
        use std::{alloc::Layout, mem::size_of};

        size_of::<&Self>()
            + size_of::<&OriginalProgram>()
            + size_of::<Layout>()
            + size_of::<(
                &Mutex<LinuxReadLeaseFile>,
                &File,
                &OwnedFd,
                &Mutex<LinuxReadLeaseFile>,
                &File,
                &PathBuf,
                &[u8; 32],
                &[u8; 32],
                &Vec<(PathBuf, OwnedFd)>,
                &AtomicBool,
            )>()
    }

    pub(super) fn command(&self) -> Result<Command, LinuxPureWorkerError> {
        self.verify_current()?;
        // The retained private fd stays live through std spawn. Its /proc name
        // resolves the opened helper inode; it is never exposed as a raw API.
        Ok(Command::new(format!(
            "/proc/self/fd/{}",
            self.original.launcher_exec.as_raw_fd()
        )))
    }
    /// Reauthenticates retained kernel leases and all current read-only roots.
    ///
    /// # Errors
    /// Permanently refuses a broken lease, changed file/directory identity or
    /// writable/remounted runtime. Trusted operators must not mutate an admitted
    /// installation through another mount; readonly mounts are not a defense
    /// against a hostile administrator changing the filesystem underneath them.
    pub fn verify_current(&self) -> Result<(), LinuxPureWorkerError> {
        if self.original.revoked.load(Ordering::Acquire) {
            return Err(LinuxPureWorkerError::HostControlsUnavailable);
        }
        let result = (|| {
            check_loader_policy()?;
            for lease in [&self.original.launcher, &self.original.worker] {
                let file = lease
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                file.lease()
                    .ok_or(LinuxPureWorkerError::HostControlsUnavailable)?
                    .verify_current()
                    .map_err(|_| LinuxPureWorkerError::HostControlsUnavailable)?;
                if !fstatvfs(file.file())
                    .map_err(io::Error::from)?
                    .f_flag
                    .contains(StatVfsMountFlags::RDONLY)
                {
                    return Err(LinuxPureWorkerError::HostControlsUnavailable);
                }
            }
            for (path, original) in &self.original.roots {
                let named = open(
                    path,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )
                .map_err(io::Error::from)?;
                let a = fstat(original).map_err(io::Error::from)?;
                let z = fstat(&named).map_err(io::Error::from)?;
                if a.st_dev != z.st_dev
                    || a.st_ino != z.st_ino
                    || !fstatvfs(&named)
                        .map_err(io::Error::from)?
                        .f_flag
                        .contains(StatVfsMountFlags::RDONLY)
                {
                    return Err(LinuxPureWorkerError::HostControlsUnavailable);
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.original.revoked.store(true, Ordering::Release);
        }
        result
    }
}

/// Visits the defining private roster before each initialized path child.
pub(super) fn observe_program_buffers<E>(
    worker: &PathBuf,
    roots: &Vec<(PathBuf, OwnedFd)>,
    observe: &mut impl FnMut(LinuxPureWorkerBufferCapacityData) -> Result<(), E>,
) -> Result<(), E> {
    observe(LinuxPureWorkerBufferCapacityData::bytes(worker.capacity()))?;
    observe(LinuxPureWorkerBufferCapacityData::vector(roots))?;
    for (path, _) in roots {
        observe(LinuxPureWorkerBufferCapacityData::bytes(path.capacity()))?;
    }
    Ok(())
}

fn normalized_absolute(path: &Path) -> bool {
    path.as_os_str().len() <= 4096
        && path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn canonical_store_root(path: &Path) -> bool {
    if path.parent() != Some(Path::new("/nix/store")) || !normalized_absolute(path) {
        return false;
    }
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let bytes = name.as_bytes();
    bytes.len() > 33
        && bytes.len() <= 255
        && bytes[32] == b'-'
        && bytes[..32]
            .iter()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(byte))
}

fn check_loader_policy() -> Result<(), LinuxPureWorkerError> {
    // Empty environment does not disable glibc's system-wide preload file.
    // Trusted administrators must not install or mutate loader policy while
    // this profile is admitted; no hostile-admin isolation is claimed.
    match std::fs::symlink_metadata("/etc/ld.so.preload") {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(LinuxPureWorkerError::HostControlsUnavailable),
    }
}

#[cfg(test)]
#[path = "program/capacity_tests.rs"]
mod capacity_tests;
