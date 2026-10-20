//! Shares original tree creation with selected native-prefix retention.
//!
//! The ordinary adapter preserves each control File's lexical disposal. The
//! selected startup keeps all reached originals until the actual tree and its
//! subsequent original bookends have completed; a refused prefix is not reset.

use super::*;
use std::os::fd::OwnedFd;
use aos_sandbox_linux::cgroup::{CgroupActiveOriginalV2, CgroupChildOriginalV2,
    CgroupPopulationMonitorOriginalV3, ExactCgroupMembershipReadbackV1};
use aos_sandbox_linux::pidfd::{PidFdOpenAttemptV1, PidFdProcessIdentityOriginalV1};

pub(crate) struct ExecutionTreeOpeningOriginalV1 {
    retained: bool,
    root: CgroupActiveOriginalV2,
    child: CgroupChildOriginalV2,
    anchor: Option<RetainedCgroupAnchor>,
    controls: [Option<Result<OwnedFd, Error>>; 4],
    pidfd: PidFdOpenAttemptV1,
    leader: Option<PidFd>,
    identity: [PidFdProcessIdentityOriginalV1; 2],
    population_native: CgroupPopulationMonitorOriginalV3,
    population: Option<CgroupPopulationMonitor>,
    migration: Option<Result<OwnedFd, Error>>,
    migration_write: Option<rustix::io::Result<usize>>,
    membership: ExactCgroupMembershipReadbackV1,
    returned: Option<Result<(), Error>>,
}

impl ExecutionTreeOpeningOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { retained: true, root: CgroupActiveOriginalV2::new(), child: CgroupChildOriginalV2::new(),
            anchor: None, controls: std::array::from_fn(|_| None), pidfd: PidFdOpenAttemptV1::new(),
            leader: None, identity: std::array::from_fn(|_| PidFdProcessIdentityOriginalV1::new()),
            population_native: CgroupPopulationMonitorOriginalV3::new(), population: None,
            migration: None, migration_write: None, membership: ExactCgroupMembershipReadbackV1::new(), returned: None }
    }

    pub(crate) fn capture_once(&mut self, root: &RetainedCgroupAnchor, execution: &[u8; 16], pid: u32)
        -> Result<ExecutionTree, Error>
    {
        if self.returned.is_some() { return Err(Error::AmbiguousEffect); }
        match create(root, execution, pid, self) {
            Ok(tree) => { self.returned = Some(Ok(())); Ok(tree) }
            Err(error) => { self.returned = Some(Err(error)); Err(Error::AmbiguousEffect) }
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.root.failure().map(|error| error as _)
            .or_else(|| self.child.failure().map(|error| error as _))
            .or_else(|| self.controls.iter().find_map(|slot|
                slot.as_ref()?.as_ref().err().map(|error| error as _)))
            .or_else(|| self.pidfd.failure().map(|error| error as _))
            .or_else(|| self.identity[0].failure())
            .or_else(|| self.population_native.failure())
            .or_else(|| self.migration.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.migration_write.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.membership.failure().map(|error| error as _))
            .or_else(|| self.identity[1].failure())
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|error| error as _))
    }

    fn anchor(&self) -> Result<&RetainedCgroupAnchor, Error> {
        self.anchor.as_ref().ok_or(Error::AmbiguousEffect)
    }

    fn leader(&self) -> Result<&PidFd, Error> {
        self.leader.as_ref().ok_or(Error::AmbiguousEffect)
    }

    fn observe_identity(&mut self, index: usize) -> Result<PidFdProcessIdentity, Error> {
        if !self.retained { return Ok(self.leader()?.process_identity()?); }
        let leader = self.leader.as_ref().ok_or(Error::AmbiguousEffect)?;
        self.identity[index].capture_once(leader)?;
        self.identity[index].identity().ok_or(Error::AmbiguousEffect)
    }

    fn control(&mut self, index: usize, name: &str, directory: &rustix::fs::Stat) -> Result<(), Error> {
        let opened = openat(self.anchor()?.as_fd(), name,
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(Into::into);
        if self.retained {
            self.controls[index] = Some(opened);
            let file = self.controls[index].as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(Error::AmbiguousEffect)?;
            require_control(file, directory)
        } else {
            let file = opened?;
            require_control(&file, directory)
        }
    }
}

fn require_control(file: &OwnedFd, directory: &rustix::fs::Stat) -> Result<(), Error>
{
    if fstat(file)?.st_uid != 0 { return Err(Error::UnprotectedLedger); }
    fchmod(file, Mode::from_raw_mode(0o600))?;
    let control = fstat(file)?;
    if control.st_uid != 0 || control.st_mode & 0o777 != 0o600 || control.st_dev != directory.st_dev {
        return Err(Error::UnprotectedLedger);
    }
    aos_sandbox_linux::guest_confinement::require_guest_cgroup_object(file.as_fd())?;
    Ok(())
}

pub(super) fn ordinary(root: &RetainedCgroupAnchor, execution: &[u8; 16], pid: u32)
    -> Result<ExecutionTree, Error>
{
    let mut local = ExecutionTreeOpeningOriginalV1::new();
    local.retained = false;
    create(root, execution, pid, &mut local)
}

fn create(root: &RetainedCgroupAnchor, execution: &[u8; 16], pid: u32,
    original: &mut ExecutionTreeOpeningOriginalV1) -> Result<ExecutionTree, Error>
{
    aos_sandbox_linux::guest_confinement::require_guest_owner()?;
    if original.retained { original.root.capture_once_v2(root)?; } else { root.validate_active()?; }
    let name = execution.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    match mkdirat(root.as_fd(), &name, Mode::from_raw_mode(0o700)) {
        Ok(()) => {},
        Err(rustix::io::Errno::EXIST) => return Err(Error::AmbiguousEffect),
        Err(error) => return Err(error.into()),
    }
    original.anchor = Some(if original.retained {
        original.child.resolve_descendant_once(root, Path::new(&name))?;
        original.child.take_completed_once().ok_or(Error::AmbiguousEffect)?
    } else { root.resolve_descendant(Path::new(&name))? });
    let directory = fstat(original.anchor()?.as_fd())?;
    aos_sandbox_linux::guest_confinement::require_guest_cgroup_object(original.anchor()?.as_fd())?;
    if directory.st_uid != 0 || directory.st_gid != 0 || directory.st_mode & 0o777 != 0o700 {
        return Err(Error::UnprotectedLedger);
    }
    for (index, control) in ["cgroup.procs", "cgroup.threads", "cgroup.kill", "cgroup.freeze"].iter().enumerate() {
        original.control(index, control, &directory)?;
    }
    let pid = NonZeroU32::new(pid).ok_or(Error::InvalidRequest)?;
    original.leader = Some(if original.retained {
        original.pidfd.capture_once(pid).map_err(|_| Error::AmbiguousEffect)?;
        original.pidfd.take_validated().ok_or(Error::AmbiguousEffect)?
    } else { PidFd::open(pid)? });
    let before = original.observe_identity(0)?;
    original.population = Some(if original.retained {
        original.population_native.capture_once_v3(original.anchor.as_ref().ok_or(Error::AmbiguousEffect)?)?;
        original.population_native.take_completed_once_v3().ok_or(Error::AmbiguousEffect)?
    } else { original.anchor()?.population_monitor()? });
    let migration = openat(original.anchor()?.as_fd(), "cgroup.procs",
        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(Into::into);
    original.migration = Some(if original.retained { migration } else { Ok(migration?) });
    let migration = original.migration.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or(Error::AmbiguousEffect)?;
    let record = format!("{}\n", pid.get());
    let written = rustix::io::write(migration, record.as_bytes());
    let written = if original.retained {
        original.migration_write = Some(written);
        match original.migration_write.as_ref() {
            Some(Ok(written)) => *written,
            Some(Err(cause)) => return Err((*cause).into()),
            None => return Err(Error::AmbiguousEffect),
        }
    } else { written? };
    if written != record.len() { return Err(Error::AmbiguousEffect); }
    if original.retained {
        original.membership.capture_once(original.anchor.as_ref().ok_or(Error::AmbiguousEffect)?,
            original.leader.as_ref().ok_or(Error::AmbiguousEffect)?)
            .map_err(|_| Error::AmbiguousEffect)?;
    } else { original.anchor()?.verify_exact_membership(original.leader()?)?; }
    let placed = original.observe_identity(1)?;
    if placed.pid() != before.pid() || placed.thread_group_id() != before.thread_group_id()
        || placed.parent_pid() != before.parent_pid() || placed.start_time_ticks() != before.start_time_ticks()
    { return Err(Error::AmbiguousEffect); }
    Ok(ExecutionTree { anchor: original.anchor.take().ok_or(Error::AmbiguousEffect)?,
        population: original.population.take().ok_or(Error::AmbiguousEffect)?,
        leader: original.leader.take().ok_or(Error::AmbiguousEffect)?, original_leader: placed })
}
