//! Frozen, bounded whole-original-execution signal delivery.
//!
//! Linux has no transactional arbitrary multi-TGID signal operation. The Owner
//! holds the execution barrier, freezes its own retained subtree, pins and
//! preflights the complete TGID set, then sends explicitly TGID-scoped signals.
//! A partial send is ambiguous and the surrounding durable reservation cannot
//! be replayed. Restoration changes only this subtree's original freezer
//! request, never an ancestor's suspension or a tenant's job-control stop.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use aos_sandbox_linux::cgroup::CgroupFreezerState;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};

use super::{Error, ExecutionTree, NonZeroU32, Path};

const MAXIMUM_TGIDS: usize = 4096;
const MAXIMUM_PROCS_BYTES: usize = MAXIMUM_TGIDS * 11;

impl ExecutionTree {
    /// Requires the caller's original durable effect reservation and tree barrier.
    pub(crate) fn signal(&self, code: u8, deadline: Instant) -> Result<(), Error> {
        self.signal_with_current_cut(code, deadline, || Ok(()))
    }

    /// Rechecks the owning effect's narrowed wall/BOOTTIME cut at each send.
    /// The callback can deny but cannot select a process or construct permission.
    pub(crate) fn signal_with_current_cut(
        &self,
        code: u8,
        deadline: Instant,
        mut current: impl FnMut() -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !(1..=64).contains(&code) {
            return Err(Error::InvalidRequest);
        }
        aos_sandbox_linux::guest_confinement::require_guest_owner()?;
        self.anchor.validate_active()?;
        crate::process::check_deadline(deadline)?;
        current()?;
        if self.empty_and_exited()? {
            return Err(Error::Unavailable("original execution has exited"));
        }
        if code == 9 {
            // cgroup.kill fences concurrent forks and reaches every original
            // descendant, including changed sessions and a dead leader's tree.
            // Activity observation above may have consumed the narrowed cut.
            current()?;
            crate::process::check_deadline(deadline)?;
            let mut effect_attempted = false;
            let killed = self.anchor.kill_all_with_current_cut(|| {
                // This executes after inner cgroup/control FD validation and
                // again before every interrupted-write retry, not just at entry.
                current()?;
                crate::process::check_deadline(deadline)?;
                effect_attempted = true;
                Ok::<(), Error>(())
            });
            if effect_attempted {
                killed.map_err(|_| Error::AmbiguousEffect)?;
            } else {
                killed?;
            }
            current().map_err(|_| Error::AmbiguousEffect)?;
            crate::process::check_deadline(deadline).map_err(|_| Error::AmbiguousEffect)?;
            return Ok(());
        }

        let original = self.own_freezer_request()?;
        let mut effect_attempted = false;
        // Even a failed write may have changed the kernel request. Always
        // restore the exact original request before returning ordinary success.
        let result = (|| {
            current()?;
            self.anchor
                .request_freezer_state(CgroupFreezerState::Frozen)?;
            self.wait_frozen(deadline)?;
            let members = self.pin_frozen_members(deadline)?;
            self.recheck_frozen_members(&members, deadline)?;
            current()?;
            for (process, identity) in &members {
                crate::process::check_deadline(deadline)?;
                current()?;
                if self.own_freezer_request()? != CgroupFreezerState::Frozen
                    || self.anchor.freezer_state()? != CgroupFreezerState::Frozen
                {
                    return Err(Error::AmbiguousEffect);
                }
                self.require_frozen_member(process)?;
                if process.process_identity()? != *identity {
                    return Err(Error::AmbiguousEffect);
                }
                // Freeze, membership and identity reads cannot carry a stale
                // wall/BOOTTIME observation into the actual signal attempt.
                current()?;
                crate::process::check_deadline(deadline)?;
                effect_attempted = true;
                process
                    .send_thread_group_signal(code)
                    .map_err(|_| Error::AmbiguousEffect)?;
                current()?;
            }
            self.recheck_frozen_members(&members, deadline)?;
            current()
        })();

        // Cleanup is nonauthorizing and must still restore an owned request
        // when the effect's authority/deadline expires during delivery.
        let restored = self.restore_own_freezer_request(original);
        if restored.is_err() {
            return Err(Error::AmbiguousEffect);
        }
        if effect_attempted && result.is_err() {
            return Err(Error::AmbiguousEffect);
        }
        result
    }

    fn own_freezer_request(&self) -> Result<CgroupFreezerState, Error> {
        let root =
            BeneathRoot::from_owned(rustix::io::fcntl_dupfd_cloexec(self.anchor.as_fd(), 0)?)?;
        match root
            .open_regular(Path::new("cgroup.freeze"))?
            .read_bounded(2)?
            .as_slice()
        {
            b"0\n" => Ok(CgroupFreezerState::Thawed),
            b"1\n" => Ok(CgroupFreezerState::Frozen),
            _ => Err(Error::AmbiguousEffect),
        }
    }

    fn restore_own_freezer_request(&self, original: CgroupFreezerState) -> Result<(), Error> {
        self.anchor.request_freezer_state(original)?;
        if self.own_freezer_request()? != original {
            return Err(Error::AmbiguousEffect);
        }
        if original == CgroupFreezerState::Frozen {
            self.wait_frozen(Instant::now() + Duration::from_secs(2))?;
        }
        // A zero own request may remain effectively frozen by an ancestor.
        // Do not clear that ancestor or demand a falsely global thawed state.
        Ok(())
    }

    fn wait_frozen(&self, deadline: Instant) -> Result<(), Error> {
        loop {
            crate::process::check_deadline(deadline)?;
            if self.anchor.freezer_state()? == CgroupFreezerState::Frozen {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn member_ids(&self) -> Result<BTreeSet<NonZeroU32>, Error> {
        let root =
            BeneathRoot::from_owned(rustix::io::fcntl_dupfd_cloexec(self.anchor.as_fd(), 0)?)?;
        let bytes = root
            .open_regular(Path::new("cgroup.procs"))?
            .read_bounded(MAXIMUM_PROCS_BYTES)?;
        parse_member_ids(&bytes)
    }

    fn pin_frozen_members(
        &self,
        deadline: Instant,
    ) -> Result<Vec<(PidFd, PidFdProcessIdentity)>, Error> {
        let ids = self.member_ids()?;
        let mut members = Vec::with_capacity(ids.len());
        for id in ids {
            crate::process::check_deadline(deadline)?;
            let process = PidFd::open(id)?;
            self.require_frozen_member(&process)?;
            let identity = process.process_identity()?;
            if identity.pid() != id.get() || identity.thread_group_id() != id.get() {
                return Err(Error::AmbiguousEffect);
            }
            members.push((process, identity));
        }
        Ok(members)
    }

    fn require_frozen_member(&self, process: &PidFd) -> Result<(), Error> {
        self.anchor.verify_exact_membership(process)?;
        if !process.is_alive()?
            || !aos_sandbox_linux::guest_confinement::task_has_subject(
                process,
                aos_sandbox_linux::guest_confinement::GUEST_TENANT_CONTEXT,
            )?
        {
            return Err(Error::AmbiguousEffect);
        }
        Ok(())
    }

    fn recheck_frozen_members(
        &self,
        members: &[(PidFd, PidFdProcessIdentity)],
        deadline: Instant,
    ) -> Result<(), Error> {
        crate::process::check_deadline(deadline)?;
        if self.own_freezer_request()? != CgroupFreezerState::Frozen
            || self.anchor.freezer_state()? != CgroupFreezerState::Frozen
            || self.member_ids()?
                != members
                    .iter()
                    .map(|(_, identity)| {
                        NonZeroU32::new(identity.pid()).ok_or(Error::AmbiguousEffect)
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?
        {
            return Err(Error::AmbiguousEffect);
        }
        for (process, original) in members {
            self.require_frozen_member(process)?;
            if process.process_identity()? != *original {
                return Err(Error::AmbiguousEffect);
            }
        }
        crate::process::check_deadline(deadline)
    }
}

fn parse_member_ids(bytes: &[u8]) -> Result<BTreeSet<NonZeroU32>, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::AmbiguousEffect)?;
    let mut ids = BTreeSet::new();
    for line in text.split_inclusive('\n') {
        let value = line.strip_suffix('\n').ok_or(Error::AmbiguousEffect)?;
        let id = value
            .parse::<u32>()
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(Error::AmbiguousEffect)?;
        if value != id.get().to_string() || !ids.insert(id) || ids.len() > MAXIMUM_TGIDS {
            return Err(Error::AmbiguousEffect);
        }
    }
    if ids.is_empty() {
        return Err(Error::AmbiguousEffect);
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    //! Canonical bounded target sets; actual freezer/pidfd effects need the VM.

    use super::*;

    #[test]
    fn member_ids_reject_partial_duplicate_sentinel_and_oversized_sets() {
        assert_eq!(parse_member_ids(b"3\n2\n").unwrap().len(), 2);
        for invalid in [
            b"".as_slice(),
            b"0\n",
            b"02\n",
            b"2",
            b"2\n2\n",
            b"-1\n",
            b"2 \n",
        ] {
            assert!(parse_member_ids(invalid).is_err());
        }
        let oversized = (1..=MAXIMUM_TGIDS + 1)
            .map(|id| format!("{id}\n"))
            .collect::<String>();
        assert!(parse_member_ids(oversized.as_bytes()).is_err());
    }

    #[test]
    #[ignore = "requires enforcing Guest Owner, real FD4/6/7 and the distinct-session Tenant spec fixture"]
    fn actual_original_tree_signals_survive_leader_exit_and_restore_only_own_freezer() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        use aos_sandbox_core::{DecodeLimits, decode_execution_spec_v1};

        // This is an effect prerequisite, not accepted-Create qualification.
        // The fixture spec's measured Tenant command forks two distinct-session
        // descendants and exits its leader. No fixture PID selects a target.
        let specification = std::fs::read(
            std::env::var_os("AOS_TEST_DISTINCT_SESSION_EXECUTION_SPEC")
                .expect("original distinct-session fixture specification"),
        )
        .unwrap();
        let decoded = decode_execution_spec_v1(&specification, DecodeLimits::default()).unwrap();
        assert_eq!(decoded.command().credentials().user_id(), 0);
        let payload =
            aos_sandbox_linux::guest_cgroup::GuestPayloadCgroupCustodyV1::from_inherited().unwrap();
        let root = payload.execution_root().unwrap();
        let ledger = crate::ledger::Ledger::open().unwrap();
        let mut child = Command::new("/usr/libexec/aos-sandbox-guest-exec")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let tree =
            ExecutionTree::create(&root, decoded.execution().as_bytes(), child.id()).unwrap();
        let record = crate::ledger::ProcessRecord {
            version: 2,
            runtime: [1; 32],
            operation: [2; 16],
            execution: *decoded.execution().as_bytes(),
            incarnation: *decoded.target().incarnation().as_bytes(),
            assignment_epoch: decoded.target().assignment_epoch().get(),
            principal: *decoded.principal().as_bytes(),
            audit: *decoded.audit().as_bytes(),
            uid: 0,
            pid: child.id(),
            start_ticks: tree.leader_start_ticks().unwrap(),
            pty: false,
            attach_io: None,
            cgroup: Some(tree.kernel_id()),
            cancel_on_disconnect: Some(false),
            canceled: false,
            terminal: None,
            terminal_waitstatus: None,
        };
        let barrier = ledger.effect_barrier();
        let _held = barrier.lock().unwrap();
        ledger.write_process(decoded.execution(), &record).unwrap();
        let mut input = child.stdin.take().unwrap();
        input
            .write_all(&(specification.len() as u32).to_be_bytes())
            .unwrap();
        input.write_all(&specification).unwrap();
        drop(input);
        let deadline = Instant::now() + Duration::from_secs(5);
        while tree.leader.is_alive().unwrap() || tree.member_ids().unwrap().len() < 2 {
            crate::process::check_deadline(deadline).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(child.try_wait().unwrap().is_some());
        tree.require_original_scope(&record).unwrap();
        assert!(!tree.matches(&record).unwrap());
        tree.require_active_original_scope(&record).unwrap();

        // Active original ownership survives a reaped UID0 leader, but a cold
        // ledger row still cannot recover the tree or authorize initial IO.
        assert!(
            ledger
                .with_active_original_tree_v5(&record, |_| Ok(()))
                .is_err()
        );
        let mut foreign = record.clone();
        foreign.cgroup = Some(tree.kernel_id().checked_add(1).unwrap());
        assert!(tree.require_active_original_scope(&foreign).is_err());
        foreign = record.clone();
        foreign.start_ticks = foreign.start_ticks.checked_add(1).unwrap();
        assert!(tree.require_active_original_scope(&foreign).is_err());
        foreign = record.clone();
        foreign.version = 1;
        assert!(tree.require_active_original_scope(&foreign).is_err());
        foreign = record.clone();
        foreign.canceled = true;
        assert!(tree.require_active_original_scope(&foreign).is_err());
        foreign = record.clone();
        foreign.terminal = Some(crate::ledger::StoredOutcome {
            phase: 3,
            result: Vec::new(),
        });
        assert!(tree.require_active_original_scope(&foreign).is_err());

        tree.signal(19, deadline).unwrap();
        assert_eq!(
            tree.own_freezer_request().unwrap(),
            CgroupFreezerState::Thawed
        );
        tree.signal(18, deadline).unwrap();
        assert_eq!(
            tree.own_freezer_request().unwrap(),
            CgroupFreezerState::Thawed
        );
        tree.anchor
            .request_freezer_state(CgroupFreezerState::Frozen)
            .unwrap();
        tree.wait_frozen(deadline).unwrap();
        tree.signal(18, deadline).unwrap();
        assert_eq!(
            tree.own_freezer_request().unwrap(),
            CgroupFreezerState::Frozen
        );
        tree.anchor
            .request_freezer_state(CgroupFreezerState::Thawed)
            .unwrap();

        // Losing the cut at the final post-identity boundary must not send
        // even the first TGID signal, and cleanup still restores the own request.
        let mut current_checks = 0;
        let denied = tree.signal_with_current_cut(19, deadline, || {
            current_checks += 1;
            if current_checks < 5 {
                Ok(())
            } else {
                Err(Error::InvalidRequest)
            }
        });
        assert!(matches!(denied, Err(Error::InvalidRequest)));
        assert_eq!(current_checks, 5);
        assert_eq!(
            tree.own_freezer_request().unwrap(),
            CgroupFreezerState::Thawed
        );

        // Losing the held cut after the first real TGID send is ambiguous,
        // but cleanup still restores the original own request, not an ancestor.
        let mut current_checks = 0;
        let partial = tree.signal_with_current_cut(18, deadline, || {
            current_checks += 1;
            if current_checks < 6 {
                Ok(())
            } else {
                Err(Error::InvalidRequest)
            }
        });
        assert!(matches!(partial, Err(Error::AmbiguousEffect)));
        assert_eq!(current_checks, 6);
        assert_eq!(
            tree.own_freezer_request().unwrap(),
            CgroupFreezerState::Thawed
        );

        // An ancestor's independent request must survive a child's SIGCONT.
        root.request_freezer_state(CgroupFreezerState::Frozen)
            .unwrap();
        tree.wait_frozen(deadline).unwrap();
        tree.signal(18, deadline).unwrap();
        assert_eq!(
            tree.own_freezer_request().unwrap(),
            CgroupFreezerState::Thawed
        );
        assert_eq!(root.freezer_state().unwrap(), CgroupFreezerState::Frozen);
        root.request_freezer_state(CgroupFreezerState::Thawed)
            .unwrap();

        assert!(tree.signal(15, Instant::now()).is_err());
        assert_eq!(
            tree.own_freezer_request().unwrap(),
            CgroupFreezerState::Thawed
        );

        let members = tree.member_ids().unwrap();
        let mut kill_checks = 0;
        let denied = tree.signal_with_current_cut(9, deadline, || {
            kill_checks += 1;
            if kill_checks == 1 {
                Ok(())
            } else {
                Err(Error::InvalidRequest)
            }
        });
        assert!(matches!(denied, Err(Error::InvalidRequest)));
        assert_eq!(kill_checks, 2);
        assert_eq!(tree.member_ids().unwrap(), members);

        // Narrow the test cut to immediate expiry as inner FD validation
        // begins. Only the post-validation check sees that expired deadline;
        // the earlier sample cannot permit a write, and descendants survive.
        let mut kill_checks = 0;
        let mut expired_cut = None;
        let denied = tree.signal_with_current_cut(9, deadline, || {
            kill_checks += 1;
            if kill_checks < 3 {
                if kill_checks == 2 {
                    expired_cut = Some(Instant::now());
                }
                Ok(())
            } else {
                crate::process::check_deadline(expired_cut.ok_or(Error::InvalidRequest)?)
            }
        });
        assert!(matches!(denied, Err(Error::Unavailable(_))));
        assert_eq!(kill_checks, 3);
        assert_eq!(tree.member_ids().unwrap(), members);
        for pid in &members {
            assert!(PidFd::open(*pid).unwrap().is_alive().unwrap());
        }
        tree.signal(9, deadline).unwrap();
        tree.kill_and_wait(deadline).unwrap();
        assert!(tree.empty_and_exited().unwrap());
        assert!(tree.require_active_original_scope(&record).is_err());
    }
}
