//! Retained proper-descendant cgroup ownership for one original execution.
//!
//! A trusted helper blocks on its spec pipe until its actual pidfd has been
//! migrated and the process ledger accepted. Tenant MAC denies every cgroup
//! mutation alias; later cancellation observes recursive emptiness and leader
//! exit, not PGID, pathname metadata, or PDEATHSIG. Cold state cannot adopt one.

use std::num::NonZeroU32;
use std::os::fd::AsFd as _;
use std::path::Path;
use std::time::Instant;

use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitor, CgroupPopulationState, RetainedCgroupAnchor,
};
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use rustix::fs::{Mode, OFlags, fchmod, fstat, mkdirat, openat};

use crate::GuestProcessEffectErrorV1 as Error;

mod signal;

pub(crate) struct ExecutionTree {
    anchor: RetainedCgroupAnchor,
    population: CgroupPopulationMonitor,
    leader: PidFd,
    original_leader: PidFdProcessIdentity,
}

#[cfg(test)]
mod tests {
    //! Actual inherited-cgroup prerequisite; no admitted execution or IO grant.
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::*;

    #[test]
    #[ignore = "requires enforcing Guest Owner and the real nspawn FD4/6/7 handoff"]
    fn actual_helper_membership_and_recursive_kill_never_adopt_a_cold_child() {
        let payload =
            aos_sandbox_linux::guest_cgroup::GuestPayloadCgroupCustodyV1::from_inherited().unwrap();
        let root = payload.execution_root().unwrap();
        let mut child = Command::new("/usr/libexec/aos-sandbox-guest-exec")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // No spec is released: this is the actual blocked, measured Owner
        // helper, not a fabricated PID or an execution authorization factory.
        let tree = ExecutionTree::create(&root, &[0xa1; 16], child.id()).unwrap();
        tree.require_leader().unwrap();
        assert!(!tree.empty_and_exited().unwrap());

        tree.kill_and_wait(Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert!(tree.empty_and_exited().unwrap());
        assert!(child.try_wait().unwrap().is_some());
        assert!(matches!(
            ExecutionTree::create(&root, &[0xa1; 16], std::process::id()),
            Err(Error::AmbiguousEffect),
        ));
    }
}

impl ExecutionTree {
    pub(crate) fn create(
        root: &RetainedCgroupAnchor,
        execution: &[u8; 16],
        leader: u32,
    ) -> Result<Self, Error> {
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;
        root.validate_active()?;
        let name = execution
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        // A present child is ambiguous even when empty. No cold record, scalar
        // PID or same-name replacement can reconstruct this in-memory custody.
        match mkdirat(root.as_fd(), &name, Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => return Err(Error::AmbiguousEffect),
            Err(error) => return Err(error.into()),
        }
        let anchor = root.resolve_descendant(Path::new(&name))?;
        let directory = fstat(anchor.as_fd())?;
        aos_sandbox_linux::guest_confinement::require_guest_cgroup_object(anchor.as_fd())?;
        if directory.st_uid != 0 || directory.st_gid != 0 || directory.st_mode & 0o777 != 0o700 {
            return Err(Error::UnprotectedLedger);
        }
        for control in [
            "cgroup.procs",
            "cgroup.threads",
            "cgroup.kill",
            "cgroup.freeze",
        ] {
            let file = openat(
                anchor.as_fd(),
                control,
                OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            if fstat(&file)?.st_uid != 0 {
                return Err(Error::UnprotectedLedger);
            }
            fchmod(&file, Mode::from_raw_mode(0o600))?;
            let control = fstat(&file)?;
            if control.st_uid != 0
                || control.st_mode & 0o777 != 0o600
                || control.st_dev != directory.st_dev
            {
                return Err(Error::UnprotectedLedger);
            }
            aos_sandbox_linux::guest_confinement::require_guest_cgroup_object(file.as_fd())?;
        }
        let pid = NonZeroU32::new(leader).ok_or(Error::InvalidRequest)?;
        let leader = PidFd::open(pid)?;
        let original = leader.process_identity()?;
        let population = anchor.population_monitor()?;
        let migration = openat(
            anchor.as_fd(),
            "cgroup.procs",
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let record = format!("{}\n", pid.get());
        if rustix::io::write(&migration, record.as_bytes())? != record.len() {
            return Err(Error::AmbiguousEffect);
        }
        anchor.verify_exact_membership(&leader)?;
        let placed = leader.process_identity()?;
        if placed.pid() != original.pid()
            || placed.thread_group_id() != original.thread_group_id()
            || placed.parent_pid() != original.parent_pid()
            || placed.start_time_ticks() != original.start_time_ticks()
        {
            return Err(Error::AmbiguousEffect);
        }
        Ok(Self {
            anchor,
            population,
            leader,
            original_leader: placed,
        })
    }

    pub(crate) fn kernel_id(&self) -> u64 {
        self.anchor.kernel_id()
    }

    pub(crate) fn leader_start_ticks(&self) -> Result<u64, Error> {
        Ok(self.leader.process_identity()?.start_time_ticks())
    }

    pub(crate) fn require_leader(&self) -> Result<(), Error> {
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;
        self.anchor.verify_exact_membership(&self.leader)?;
        Ok(())
    }

    pub(crate) fn matches(&self, record: &crate::ledger::ProcessRecord) -> Result<bool, Error> {
        if !self.leader.is_alive()? {
            return Ok(false);
        }
        self.require_leader()?;
        let identity = self.leader.process_identity()?;
        Ok(record.version == 2
            && record.cgroup == Some(self.kernel_id())
            && identity.pid() == record.pid
            && identity.start_time_ticks() == record.start_ticks
            && self
                .leader
                .info()?
                .credentials()
                .map(|credentials| credentials.effective_user_id())
                == Some(record.uid)
            && aos_sandbox_linux::guest_confinement::task_has_subject(
                &self.leader,
                aos_sandbox_linux::guest_confinement::GUEST_TENANT_CONTEXT,
            )?)
    }

    /// Joins the admitted row to original live ownership, even after leader exit.
    /// Descendants may change credentials or session IDs without leaving their
    /// retained execution subtree; neither change manufactures new ownership.
    pub(crate) fn require_original_scope(
        &self,
        record: &crate::ledger::ProcessRecord,
    ) -> Result<(), Error> {
        self.require_original_identity(record)?;
        if record.canceled || record.terminal.is_some() {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }

    /// Checks original owned scope and current subtree activity, not a live leader UID.
    ///
    /// The owning caller retains its shared barrier and this actual tree through
    /// dependent effects. This predicate does not reconstruct cold ownership or
    /// confer Controller/Host or SSH holder authority.
    ///
    /// # Errors
    /// Rejects legacy/foreign/canceled/terminal scope, lost cgroup confinement
    /// or an original subtree that is both recursively empty and leader-exited.
    pub(crate) fn require_active_original_scope(
        &self,
        record: &crate::ledger::ProcessRecord,
    ) -> Result<(), Error> {
        self.require_original_scope(record)?;
        if self.empty_and_exited()? {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }

    /// Joins historical terminal data to this originally retained tree only.
    /// This permits no mutation, attach reservation or descriptor transfer.
    pub(crate) fn require_original_identity(
        &self,
        record: &crate::ledger::ProcessRecord,
    ) -> Result<(), Error> {
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;
        self.anchor.validate_active()?;
        if record.version != 2
            || record.cgroup != Some(self.kernel_id())
            || record.pid != self.original_leader.pid()
            || record.start_ticks != self.original_leader.start_time_ticks()
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }

    pub(crate) fn empty_and_exited(&self) -> Result<bool, Error> {
        Ok(matches!(
            self.population.state()?,
            CgroupPopulationState::Empty | CgroupPopulationState::Retired
        ) && !self.leader.is_alive()?)
    }

    pub(crate) fn kill_and_wait(&self, deadline: Instant) -> Result<(), Error> {
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;
        if !self.empty_and_exited()? {
            self.anchor.kill_all()?;
        }
        while !self.empty_and_exited()? {
            crate::process::check_deadline(deadline)?;
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        Ok(())
    }
}
