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
use aos_linux_descriptors::pidfd::PidFd;
use aos_sandbox_linux::pidfd::PidFdProcessIdentity;
use rustix::fs::{Mode, OFlags, fchmod, fstat, mkdirat, openat};

use crate::GuestProcessEffectErrorV1 as Error;

mod signal;
mod opening;
pub(super) use opening::ExecutionTreeOpeningOriginalV1;

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
        let mut lifetime = aos_sandbox_linux::process::ExecutionChildLifetimeOriginalV1::new();
        lifetime.start_once(5_000_000_000).unwrap();
        let (origin, duration, cutoff) = lifetime.origin_data_v1().unwrap();
        let mut child = Command::new("/usr/libexec/aos-sandbox-guest-exec")
            .args(["--lifetime-v1", &origin.to_string(), &duration.to_string(), &cutoff.to_string()])
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
    #[test]
    #[ignore = "requires enforcing Guest Owner, real FD4/6/7 and the short distinct-session Tenant spec fixture"]
    fn continue_disconnect_reaps_leader_and_kills_remaining_original_descendants_at_timeout() {
        use aos_sandbox_model::{DecodeLimits, decode_execution_spec_v1};
        let bytes = std::fs::read(std::env::var_os("AOS_TEST_SHORT_DISTINCT_SESSION_EXECUTION_SPEC")
            .expect("actual short Continue distinct-session fixture")).unwrap();
        let specification = decode_execution_spec_v1(&bytes, DecodeLimits::default()).unwrap();
        assert_eq!(specification.io().disconnect_policy(), aos_sandbox_model::ExecutionDisconnectPolicyV1::Continue);
        assert!((100_000_000..=3_000_000_000).contains(&specification.timeout().nanoseconds()));
        let payload = aos_sandbox_linux::guest_cgroup::GuestPayloadCgroupCustodyV1::from_inherited().unwrap();
        let root = payload.execution_root().unwrap();
        let mut lifetime = aos_sandbox_linux::process::ExecutionChildLifetimeOriginalV1::new();
        lifetime.start_once(specification.timeout().nanoseconds()).unwrap();
        let (origin, timeout, cutoff) = lifetime.origin_data_v1().unwrap();
        let mut child = Command::new("/usr/libexec/aos-sandbox-guest-exec")
            .args(["--lifetime-v1", &origin.to_string(), &timeout.to_string(), &cutoff.to_string()])
            .env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        lifetime.bind_child_once(&child).unwrap();
        let tree = ExecutionTree::create(&root, specification.execution().as_bytes(), child.id()).unwrap();
        let record = crate::ledger::ProcessRecord {
            version: 3, runtime: [1;32], operation: [2;16], execution: *specification.execution().as_bytes(),
            incarnation: *specification.target().incarnation().as_bytes(),
            assignment_epoch: specification.target().assignment_epoch().get(),
            principal: *specification.principal().as_bytes(), audit: *specification.audit().as_bytes(),
            uid: specification.command().credentials().user_id(), pid: child.id(),
            start_ticks: tree.leader_start_ticks().unwrap(), pty: false, attach_io: None,
            cgroup: Some(tree.kernel_id()), cancel_on_disconnect: Some(false),
            lifetime: Some(crate::ledger::ExecutionLifetimeRecordV1 { version: 1,
                origin_boottime_nanoseconds: origin, timeout_nanoseconds: timeout,
                deadline_boottime_nanoseconds: cutoff,
                specification_digest: *aos_sandbox_model::execution_spec_digest_v1(&specification).as_bytes() }),
            timed_out: false, canceled: false, terminal: None, terminal_waitstatus: None,
        };
        let mut input = child.stdin.take().unwrap();
        crate::process::write_specification(&mut input, &bytes,
            Instant::now() + Duration::from_secs(3), &record).unwrap();
        drop(input); // Continue does not translate this disconnect into cancel.
        while tree.leader.is_alive().unwrap() || tree.population.state().unwrap() != CgroupPopulationState::Populated {
            assert!(!lifetime.is_expired().unwrap(), "fixture must leave real descendants before its original timeout");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(!tree.empty_and_exited().unwrap());
        while !lifetime.is_expired().unwrap() { std::thread::sleep(Duration::from_millis(2)); }
        tree.terminate_expired_child_v1(&record, &mut lifetime, &mut child).unwrap();
        let final_cutoff = Instant::now() + Duration::from_secs(3);
        while lifetime.completed_status_v1().is_none() {
            assert!(Instant::now() < final_cutoff);
            lifetime.poll_termination_once(&tree.population, &mut child).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(tree.empty_and_exited().unwrap());
        assert!(child.try_wait().unwrap().is_some());
        assert!(lifetime.failure().is_none());
    }

}

impl ExecutionTree {
    pub(crate) fn create(
        root: &RetainedCgroupAnchor,
        execution: &[u8; 16],
        leader: u32,
    ) -> Result<Self, Error> {
        opening::ordinary(root, execution, leader)
    }

    pub(crate) fn kernel_id(&self) -> u64 {
        self.anchor.kernel_id()
    }

    pub(crate) fn leader_start_ticks(&self) -> Result<u64, Error> {
        Ok(aos_sandbox_linux::pidfd::process_identity(&(self.leader))?.start_time_ticks())
    }

    pub(crate) fn require_leader(&self) -> Result<(), Error> {
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;
        self.anchor.verify_exact_membership(&self.leader)?;
        Ok(())
    }

    pub(super) fn leader_start_ticks_retaining_v1(&self,
        original: &mut aos_sandbox_linux::pidfd::PidFdProcessIdentityOriginalV1) -> Result<u64, Error>
    {
        original.capture_once(&self.leader)?;
        Ok(original.identity().ok_or(Error::AmbiguousEffect)?.start_time_ticks())
    }

    pub(super) fn require_leader_retaining_v1(&self,
        original: &mut aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1) -> Result<(), Error>
    {
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;
        original.capture_once(&self.anchor, &self.leader).map_err(|_| Error::AmbiguousEffect)
    }

    pub(crate) fn matches(&self, record: &crate::ledger::ProcessRecord) -> Result<bool, Error> {
        if !self.leader.is_alive()? {
            return Ok(false);
        }
        self.require_leader()?;
        let identity = aos_sandbox_linux::pidfd::process_identity(&(self.leader))?;
        Ok(matches!(record.version, 2 | 3)
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
        if let Some(lifetime) = record.lifetime.as_ref() {
            aos_sandbox_linux::process::require_child_lifetime_data_v1(
                lifetime.origin_boottime_nanoseconds, lifetime.timeout_nanoseconds,
                lifetime.deadline_boottime_nanoseconds,
            )?;
        }
        if record.canceled || record.timed_out || record.terminal.is_some() {
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
        self.require_original_coordinates(record)
    }

    fn require_original_coordinates(&self, record: &crate::ledger::ProcessRecord) -> Result<(), Error> {
        if !matches!(record.version, 2 | 3)
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

    // Only the admitted original Guest process calls this after its immutable
    // timeout. The mechanical owner retains kill/population/reap failures.
    pub(crate) fn terminate_expired_child_v1(&self, record: &crate::ledger::ProcessRecord,
        original: &mut aos_sandbox_linux::process::ExecutionChildLifetimeOriginalV1,
        child: &mut std::process::Child) -> Result<(), Error>
    {
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;
        self.require_original_coordinates(record)?;
        // SAME lower active recipe now owns its failing file prefix. Coordinate
        // comparison cannot substitute a pathname or grant a different child.
        original.terminate_once(&self.anchor, &self.population, child)
            .map_err(|_| Error::AmbiguousEffect)
    }

    pub(crate) fn population_for_original_timeout_v1(&self) -> &CgroupPopulationMonitor {
        &self.population
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
