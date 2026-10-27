//! Descriptor-pinned cgroup and ext4 quota ownership for the single worker slot.
//!
//! These are concrete kernel controls, adapted from the existing QEMU owner;
//! no QEMU contract, hot-fork state, engine hash or guest artifact enters here.

use super::*;
use aos_linux_project_quota::{
    LinuxProjectQuotaLimits, LinuxProjectQuotaReservation, validate_project_quota_root,
};
use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, fchmod, flock, fstat, fstatfs, fsync, mkdirat, open,
    openat, unlinkat,
};

const NAME: &str = "pure-worker";
const INPUT: &str = "input";
const CONTROL_BYTES: u64 = 4096;

pub(super) struct Roots {
    pub(super) configuration: LinuxPureWorkerConfiguration,
    cgroup: OwnedFd,
    run: OwnedFd,
}

fn errno(error: rustix::io::Errno) -> LinuxPureWorkerError {
    io::Error::from(error).into()
}

fn directory(path: &Path) -> Result<OwnedFd, LinuxPureWorkerError> {
    open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(errno)
}

fn directory_at(parent: &OwnedFd, name: &str) -> Result<OwnedFd, LinuxPureWorkerError> {
    openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(errno)
}

fn control(directory: &OwnedFd, name: &str, write: bool) -> io::Result<File> {
    openat(
        directory,
        name,
        OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | if write {
                OFlags::WRONLY
            } else {
                OFlags::RDONLY
            },
        Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)
}

fn read_control(directory: &OwnedFd, name: &str) -> io::Result<String> {
    let mut text = String::new();
    control(directory, name, false)?
        .take(CONTROL_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > CONTROL_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(text)
}

fn write_control(directory: &OwnedFd, name: &str, value: &str) -> io::Result<()> {
    control(directory, name, true)?.write_all(value.as_bytes())?;
    if read_control(directory, name)?.trim() != value.trim() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn same(directory: &OwnedFd, named: &OwnedFd) -> Result<(), LinuxPureWorkerError> {
    let a = fstat(directory).map_err(errno)?;
    let b = fstat(named).map_err(errno)?;
    if a.st_dev != b.st_dev || a.st_ino != b.st_ino {
        return Err(LinuxPureWorkerError::HostControlsUnavailable);
    }
    Ok(())
}

impl Roots {
    pub(super) fn open(
        configuration: LinuxPureWorkerConfiguration,
    ) -> Result<Self, LinuxPureWorkerError> {
        if !configuration.cgroup_root.is_absolute()
            || !configuration.run_root.is_absolute()
            || configuration.project_id == 0
            || configuration.project_id > 0x7fff_ffff
            || configuration.child_user_id == 0
            || configuration.child_group_id == 0
            || configuration.child_user_id == rustix::process::geteuid().as_raw()
            || configuration.child_group_id == rustix::process::getegid().as_raw()
        {
            return Err(LinuxPureWorkerError::Configuration);
        }
        let run = directory(&configuration.run_root)?;
        let metadata = fstat(&run).map_err(errno)?;
        if metadata.st_uid != rustix::process::geteuid().as_raw()
            || metadata.st_mode & 0o777 != 0o700
        {
            return Err(LinuxPureWorkerError::HostControlsUnavailable);
        }
        validate_project_quota_root(&run, &configuration.run_root)?;
        // The pinned parent plus cooperative root lock remains live in every attempt.
        flock(&run, FlockOperation::NonBlockingLockExclusive).map_err(errno)?;
        if std::fs::read_dir(&configuration.run_root)?.next().is_some() {
            return Err(LinuxPureWorkerError::HostControlsUnavailable);
        }
        let cgroup = directory(&configuration.cgroup_root)?;
        if fstatfs(&cgroup).map_err(errno)?.f_type != libc::CGROUP2_SUPER_MAGIC {
            return Err(LinuxPureWorkerError::HostControlsUnavailable);
        }
        for file in ["cgroup.controllers", "cgroup.subtree_control"] {
            let words = read_control(&cgroup, file)?;
            if ["cpu", "memory", "pids"]
                .iter()
                .any(|v| !words.split_ascii_whitespace().any(|w| w == *v))
            {
                return Err(LinuxPureWorkerError::HostControlsUnavailable);
            }
        }
        flock(&cgroup, FlockOperation::NonBlockingLockExclusive).map_err(errno)?;
        Ok(Self {
            configuration,
            cgroup,
            run,
        })
    }
    pub(super) fn create_workspace(
        self: &Arc<Self>,
        slot: &mut Option<Workspace>,
    ) -> Result<(), LinuxPureWorkerError> {
        mkdirat(&self.run, NAME, Mode::from_bits_truncate(0o700)).map_err(errno)?;
        *slot = Some(Workspace {
            roots: self.clone(),
            directory: None,
            quota: None,
            removed: false,
            inodes: 0,
        });
        let owner = slot.as_mut().ok_or(LinuxPureWorkerError::Phase)?;
        owner.directory = Some(directory_at(&self.run, NAME)?);
        Ok(())
    }
    pub(super) fn create_group(
        self: &Arc<Self>,
        slot: &mut Option<Cgroup>,
    ) -> Result<(), LinuxPureWorkerError> {
        mkdirat(&self.cgroup, NAME, Mode::from_bits_truncate(0o700)).map_err(errno)?;
        *slot = Some(Cgroup {
            roots: self.clone(),
            directory: None,
            path: self.configuration.cgroup_root.join(NAME),
            removed: false,
            memory_oom_kills_before: None,
        });
        slot.as_mut().ok_or(LinuxPureWorkerError::Phase)?.directory =
            Some(directory_at(&self.cgroup, NAME)?);
        Ok(())
    }
}

pub(super) struct Workspace {
    roots: Arc<Roots>,
    directory: Option<OwnedFd>,
    quota: Option<LinuxProjectQuotaReservation>,
    removed: bool,
    inodes: u64,
}

impl Workspace {
    pub(super) fn observe_path_buffer<E>(
        &self,
        observe: &mut impl FnMut(LinuxPureWorkerBufferCapacityData) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(quota) = &self.quota {
            observe(LinuxPureWorkerBufferCapacityData::bytes(
                quota.retained_path_buffer_data().capacity(),
            ))?;
        }
        Ok(())
    }

    pub(super) fn path_buffer_bytes(&self) -> usize {
        self.quota
            .as_ref()
            .map_or(0, LinuxProjectQuotaReservation::retained_path_storage_data)
    }

    fn pin(&mut self) -> Result<&OwnedFd, LinuxPureWorkerError> {
        if self.directory.is_none() {
            self.directory = Some(directory_at(&self.roots.run, NAME)?);
        }
        self.directory.as_ref().ok_or(LinuxPureWorkerError::Phase)
    }
    fn directory(&self) -> Result<&OwnedFd, LinuxPureWorkerError> {
        self.directory.as_ref().ok_or(LinuxPureWorkerError::Phase)
    }
    pub(super) fn install_quota(
        &mut self,
        limits: LinuxPureWorkerLimits,
    ) -> Result<(), LinuxPureWorkerError> {
        self.inodes = limits.inodes;
        let filesystem = self.roots.run.try_clone()?;
        let directory = self.pin()?.try_clone()?;
        let quota_limits = LinuxProjectQuotaLimits::new(limits.disk_bytes, limits.inodes)?;
        match LinuxProjectQuotaReservation::install(
            filesystem,
            directory,
            self.roots.configuration.run_root.join(NAME),
            self.roots.configuration.project_id,
            quota_limits,
        ) {
            Ok(quota) => self.quota = Some(quota),
            Err(error) => {
                let (source, partial) = error.into_parts();
                self.quota = partial;
                return Err(source.into());
            }
        }
        Ok(())
    }
    pub(super) fn create_input(&self) -> Result<File, LinuxPureWorkerError> {
        openat(
            self.directory()?,
            INPUT,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map(File::from)
        .map_err(errno)
    }
    pub(super) fn create_output(&self, name: &str) -> Result<File, LinuxPureWorkerError> {
        openat(
            self.directory()?,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map(File::from)
        .map_err(errno)
    }
    pub(super) fn open_readonly_input(&self, length: u64) -> Result<File, LinuxPureWorkerError> {
        let fd = openat(
            self.directory()?,
            INPUT,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(errno)?;
        let metadata = fstat(&fd).map_err(errno)?;
        if metadata.st_size < 0
            || metadata.st_size as u64 != length
            || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            return Err(LinuxPureWorkerError::Phase);
        }
        fchmod(&fd, Mode::from_bits_truncate(0o400)).map_err(errno)?;
        Ok(File::from(fd))
    }
    pub(super) fn release(&mut self) -> Result<(), LinuxPureWorkerError> {
        if !self.removed {
            let root = self.pin()?.try_clone()?;
            let named = directory_at(&self.roots.run, NAME)?;
            same(&root, &named)?;
            crate::LinuxDirectoryCleanup::new(root, &self.roots.configuration.run_root)
                .clear_contents(self.inodes.max(1))
                .map_err(|_| LinuxPureWorkerError::HostControlsUnavailable)?;
            if let Some(quota) = self.quota.take() {
                match quota.release() {
                    Ok(()) => (),
                    Err(error) => {
                        let (source, owner) = error.into_parts();
                        self.quota = Some(owner);
                        return Err(source.into());
                    }
                }
            }
            unlinkat(&self.roots.run, NAME, AtFlags::REMOVEDIR).map_err(errno)?;
            self.removed = true;
        }
        fsync(&self.roots.run).map_err(errno)?;
        self.directory = None;
        Ok(())
    }
}

pub(super) struct Cgroup {
    roots: Arc<Roots>,
    directory: Option<OwnedFd>,
    pub(super) path: PathBuf,
    removed: bool,
    memory_oom_kills_before: Option<u64>,
}

impl Cgroup {
    fn pin(&mut self) -> Result<&OwnedFd, LinuxPureWorkerError> {
        if self.directory.is_none() {
            self.directory = Some(directory_at(&self.roots.cgroup, NAME)?);
        }
        self.directory.as_ref().ok_or(LinuxPureWorkerError::Phase)
    }
    fn directory(&self) -> Result<&OwnedFd, LinuxPureWorkerError> {
        self.directory.as_ref().ok_or(LinuxPureWorkerError::Phase)
    }
    pub(super) fn configure(
        &mut self,
        limits: LinuxPureWorkerLimits,
    ) -> Result<(), LinuxPureWorkerError> {
        let directory = self.pin()?;
        write_control(directory, "cpu.max", "100000 100000\n")?;
        write_control(
            directory,
            "memory.max",
            &format!("{}\n", limits.memory_bytes),
        )?;
        write_control(directory, "memory.swap.max", "0\n")?;
        write_control(directory, "pids.max", "1\n")?;
        self.memory_oom_kills_before = Some(read_oom_kills(directory)?);
        Ok(())
    }
    pub(super) fn identity(&self) -> Result<(u64, u64), LinuxPureWorkerError> {
        let stat = fstat(self.directory()?).map_err(errno)?;
        Ok((stat.st_dev, stat.st_ino))
    }
    pub(super) fn kill(&self) -> Result<(), LinuxPureWorkerError> {
        control(self.directory()?, "cgroup.kill", true)?.write_all(b"1\n")?;
        Ok(())
    }
    pub(super) fn oom_kill_delta(&self) -> Result<Option<u64>, LinuxPureWorkerError> {
        self.memory_oom_kills_before
            .map(|before| {
                read_oom_kills(self.directory()?)?
                    .checked_sub(before)
                    .ok_or(LinuxPureWorkerError::HostControlsUnavailable)
            })
            .transpose()
    }

    pub(super) fn remove_if_empty(&mut self) -> Result<(), LinuxPureWorkerError> {
        if self.removed {
            return Ok(());
        }
        let directory = self.pin()?.try_clone()?;
        let events = read_control(&directory, "cgroup.events")?;
        let mut populated = None;
        for line in events.lines() {
            let mut words = line.split_ascii_whitespace();
            if words.next() == Some("populated") {
                if populated.is_some() {
                    return Err(LinuxPureWorkerError::HostControlsUnavailable);
                }
                populated = match (words.next(), words.next()) {
                    (Some("0"), None) => Some(false),
                    (Some("1"), None) => Some(true),
                    _ => return Err(LinuxPureWorkerError::HostControlsUnavailable),
                };
            }
        }
        if populated != Some(false) {
            return Err(LinuxPureWorkerError::HostControlsUnavailable);
        }
        same(&directory, &directory_at(&self.roots.cgroup, NAME)?)?;
        unlinkat(&self.roots.cgroup, NAME, AtFlags::REMOVEDIR).map_err(errno)?;
        self.removed = true;
        self.directory = None;
        Ok(())
    }
}

fn read_oom_kills(directory: &OwnedFd) -> Result<u64, LinuxPureWorkerError> {
    let text = read_control(directory, "memory.events")?;
    let mut result = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() == Some("oom_kill") {
            if result.is_some() {
                return Err(LinuxPureWorkerError::HostControlsUnavailable);
            }
            result = match (fields.next(), fields.next()) {
                (Some(value), None) => value.parse::<u64>().ok(),
                _ => None,
            };
            if result.is_none() {
                return Err(LinuxPureWorkerError::HostControlsUnavailable);
            }
        }
    }
    result.ok_or(LinuxPureWorkerError::HostControlsUnavailable)
}
