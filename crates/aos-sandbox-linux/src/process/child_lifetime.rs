//! Retains an original pre-spawn BOOTTIME duration and native child termination.
//!
//! These mechanics grant no execution, signal or cgroup authority. The caller
//! must hold its actual admitted child and original descendant-cgroup owner.
//! A later observation never restarts the original duration, including suspend.

use std::process::{Child, ExitStatus};

use crate::cgroup::{CgroupPopulationMonitor, CgroupPopulationState,
    CgroupPopulationObservationV1, CgroupKillAttemptV1, CgroupKillRefusalV1,
    RetainedCgroupAnchor};
use crate::{Error, Result};

/// Reports refusal while the actual lifetime and native observations remain held.
#[derive(Debug, thiserror::Error)]
#[error("original child lifetime is incomplete or refused")]
pub struct ExecutionChildLifetimeClosedV1;

#[derive(Clone, Copy)]
enum First { Origin, Deadline, Binding, Clock, Scope, Quiescence, DirectKill, Reap, Closed }

/// Owns one immutable pre-spawn duration and its once-only native timeout effect.
///
/// Successful clocks are comparison DATA at a reusable fixed resident peak.
/// Failed observations, kill-control files and child wait results stay resident.
/// No method reconstructs a child or a cgroup from historical scalar fields.
pub struct ExecutionChildLifetimeOriginalV1 {
    timeout: u64,
    origin: Option<rustix::time::Timespec>,
    origin_value: Option<Result<u64>>,
    deadline: Option<Result<u64>>,
    child: Option<u32>,
    clock: Option<rustix::time::Timespec>,
    clock_value: Option<Result<u64>>,
    scope: crate::cgroup::CgroupActiveOriginalV2,
    before_population: CgroupPopulationObservationV1,
    population: CgroupPopulationObservationV1,
    kill: CgroupKillAttemptV1,
    kill_result: Option<std::result::Result<(), CgroupKillRefusalV1>>,
    terminal_population: bool,
    unreleased_child: bool,
    direct_kill: Option<std::io::Result<()>>,
    reap: Option<std::io::Result<Option<ExitStatus>>>,
    first: Option<First>,
    entered: bool,
    timeout_entered: bool,
}

impl Default for ExecutionChildLifetimeOriginalV1 {
    fn default() -> Self { Self::new() }
}

impl ExecutionChildLifetimeOriginalV1 {
    /// Constructs inert fixed destinations without a clock read or native effect.
    #[must_use]
    pub fn new() -> Self {
        Self { timeout: 0, origin: None, origin_value: None, deadline: None,
            child: None, clock: None, clock_value: None,
            scope: crate::cgroup::CgroupActiveOriginalV2::new(),
            before_population: CgroupPopulationObservationV1::new(),
            population: CgroupPopulationObservationV1::new(),
            kill: CgroupKillAttemptV1::new(), kill_result: None,
            terminal_population: false, unreleased_child: false,
            direct_kill: None, reap: None, first: None,
            entered: false, timeout_entered: false }
    }

    /// Prices actual native owners, construction overlap and bounded diagnostics.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let (scope, scope_files, _) = crate::cgroup::CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?.checked_add(scope)?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?.checked_mul(2)?)?
            .checked_add(CgroupKillAttemptV1::requested_bytes_v1()?)?
            .checked_add(8 * 256)?;
        // cgroup.procs and cgroup.kill can both survive a failed native effect.
        Some((bytes, scope_files.checked_add(crate::cgroup::CgroupKillAttemptV1::maximum_retained_files_v1())?, 3))
    }

    /// Samples the original duration immediately before the actual helper spawn.
    ///
    /// # Errors
    /// Retains zero-duration, clock-conversion, overflow or repeated-entry refusal.
    pub fn start_once(&mut self, timeout_nanoseconds: u64)
        -> std::result::Result<(), ExecutionChildLifetimeClosedV1>
    {
        if self.entered {
            self.first.get_or_insert(First::Closed);
            return Err(ExecutionChildLifetimeClosedV1);
        }
        self.entered = true;
        self.timeout = timeout_nanoseconds;
        self.origin = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.origin_value = self.origin.map(clock_nanoseconds);
        let Some(Ok(origin)) = self.origin_value.as_ref() else {
            self.first = Some(First::Origin);
            return Err(ExecutionChildLifetimeClosedV1);
        };
        self.deadline = Some(origin.checked_add(timeout_nanoseconds)
            .filter(|_| timeout_nanoseconds != 0)
            .ok_or_else(|| Error::invalid("child lifetime", "duration is zero or deadline overflowed")));
        if !matches!(self.deadline, Some(Ok(_))) {
            self.first = Some(First::Deadline);
            return Err(ExecutionChildLifetimeClosedV1);
        }
        Ok(())
    }

    /// Joins the actual owned child once, before releasing its private input.
    ///
    /// # Errors
    /// Refuses missing origin, a failed prior stage or a second child binding.
    pub fn bind_child_once(&mut self, child: &Child)
        -> std::result::Result<(), ExecutionChildLifetimeClosedV1>
    {
        if self.first.is_some() || !self.entered || self.child.is_some() {
            self.first.get_or_insert(First::Binding);
            return Err(ExecutionChildLifetimeClosedV1);
        }
        self.child = Some(child.id());
        Ok(())
    }

    /// Borrows the original duration and deadline as comparison DATA.
    #[must_use]
    pub fn origin_data_v1(&self) -> Option<(u64, u64, u64)> {
        if self.first.is_some() { return None; }
        Some((*self.origin_value.as_ref()?.as_ref().ok()?, self.timeout,
            *self.deadline.as_ref()?.as_ref().ok()?))
    }

    /// Samples expiration against the original BOOTTIME, never a fresh window.
    ///
    /// # Errors
    /// Retains a failed clock or prior refusal without replacing its original.
    pub fn is_expired(&mut self)
        -> std::result::Result<bool, ExecutionChildLifetimeClosedV1>
    {
        self.sample_expiration_v1(None)
    }

    /// Samples the same original clock against an additional earlier cutoff.
    ///
    /// This comparison cannot extend the original execution deadline or enter
    /// its timeout effect. The SSH startup owner uses its already-recorded
    /// operation cutoff while its own native child remains unreleased.
    ///
    /// # Errors
    /// Retains the same original clock, binding or prior-refusal failure.
    pub fn is_expired_before_v1(&mut self, earlier_cutoff: u64)
        -> std::result::Result<bool, ExecutionChildLifetimeClosedV1>
    {
        self.sample_expiration_v1(Some(earlier_cutoff))
    }

    fn sample_expiration_v1(&mut self, earlier_cutoff: Option<u64>)
        -> std::result::Result<bool, ExecutionChildLifetimeClosedV1>
    {
        if self.first.is_some() || !self.entered {
            return Err(ExecutionChildLifetimeClosedV1);
        }
        self.clock = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.clock_value = self.clock.map(clock_nanoseconds);
        let Some(Ok(now)) = self.clock_value.as_ref() else {
            self.first = Some(First::Clock);
            return Err(ExecutionChildLifetimeClosedV1);
        };
        let Some(Ok(deadline)) = self.deadline.as_ref() else {
            self.first = Some(First::Deadline);
            return Err(ExecutionChildLifetimeClosedV1);
        };
        let Some(Ok(origin)) = self.origin_value.as_ref() else {
            self.first = Some(First::Origin);
            return Err(ExecutionChildLifetimeClosedV1);
        };
        if now < origin {
            self.clock_value = Some(Err(Error::invalid("child lifetime", "BOOTTIME moved before the original origin")));
            self.first = Some(First::Clock);
            return Err(ExecutionChildLifetimeClosedV1);
        }
        Ok(now >= &earlier_cutoff.map_or(*deadline, |earlier| earlier.min(*deadline)))
    }

    /// Enters the same retained kill/population primitives once for this child.
    ///
    /// The caller must first verify its original child/cgroup admission. No
    /// wait loop holds the supervisor: other due original children can enter
    /// their kill before this child finishes exiting.
    ///
    /// # Errors
    /// Retains failed population/kill prefixes and always attempts the final
    /// population and original child wait. Reentry never dispatches another kill.
    pub fn terminate_once(&mut self, anchor: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor, child: &mut Child)
        -> std::result::Result<(), ExecutionChildLifetimeClosedV1>
    {
        if self.timeout_entered || self.child != Some(child.id()) || !self.is_expired()? {
            self.first.get_or_insert(First::Closed);
            return Err(ExecutionChildLifetimeClosedV1);
        }
        self.timeout_entered = true;
        if self.scope.capture_once_v2(anchor).is_err() {
            self.first.get_or_insert(First::Scope);
        } else if population.observe_state_retaining_v1(&mut self.before_population).is_err() {
            self.first.get_or_insert(First::Quiescence);
        } else if self.before_population.state() == Some(CgroupPopulationState::Populated) {
            self.kill_result = Some(self.kill.capture_once_bounded_v2(anchor));
            if !matches!(self.kill_result, Some(Ok(()))) {
                self.first.get_or_insert(First::Quiescence);
            }
        }
        // Both final observations are owed even after an earlier native refusal.
        self.observe_termination(population, child);
        if self.first.is_none() { Ok(()) } else { Err(ExecutionChildLifetimeClosedV1) }
    }

    /// Polls only the already-entered original's pending population and child wait.
    ///
    /// # Errors
    /// Refuses another child or a failed earlier observation. Successful pending
    /// reads complete before their fixed destination is reused; errors never do.
    pub fn poll_termination_once(&mut self, population: &CgroupPopulationMonitor,
        child: &mut Child) -> std::result::Result<(), ExecutionChildLifetimeClosedV1>
    {
        if !self.timeout_entered || self.child != Some(child.id()) || self.first.is_some() {
            return Err(ExecutionChildLifetimeClosedV1);
        }
        self.observe_termination(population, child);
        if self.first.is_none() { Ok(()) } else { Err(ExecutionChildLifetimeClosedV1) }
    }

    fn observe_termination(&mut self, population: &CgroupPopulationMonitor, child: &mut Child) {
        if !self.terminal_population {
            // A prior positive pending record has no native effect or later
            // comparison debt. Keep failed raw reads; reuse only complete DATA.
            if self.population.state().is_some() {
                self.population = CgroupPopulationObservationV1::new();
            }
            if population.observe_state_retaining_v1(&mut self.population).is_err() {
                self.first.get_or_insert(First::Quiescence);
            } else {
                self.terminal_population = matches!(self.population.state(),
                    Some(CgroupPopulationState::Empty | CgroupPopulationState::Retired));
            }
        }
        if !matches!(self.reap, Some(Ok(Some(_)))) {
            self.reap = Some(child.try_wait());
            if matches!(self.reap, Some(Err(_))) {
                self.first.get_or_insert(First::Reap);
            }
        }
    }

    /// Reports whether the original timeout effect has already entered.
    #[must_use]
    pub const fn timeout_entered_v1(&self) -> bool { self.timeout_entered }

    /// Terminates only an original helper whose private input is still unreleased.
    ///
    /// The caller must prove that this actual owned child cannot have consumed
    /// its specification or created descendants. This mechanical method grants
    /// no such permission; the Guest's private pending owner supplies that law.
    ///
    /// # Errors
    /// Retains kill/wait errors and refuses another child, early entry or reentry.
    pub fn terminate_unreleased_child_once(&mut self, child: &mut Child)
        -> std::result::Result<(), ExecutionChildLifetimeClosedV1>
    {
        if self.timeout_entered || self.child != Some(child.id()) || !self.is_expired()? {
            self.first.get_or_insert(First::Closed);
            return Err(ExecutionChildLifetimeClosedV1);
        }
        self.timeout_entered = true;
        self.unreleased_child = true;
        self.reap = Some(child.try_wait());
        match self.reap.as_ref() {
            Some(Ok(Some(_))) => return Ok(()),
            Some(Err(_)) => {
                self.first.get_or_insert(First::Reap);
                return Err(ExecutionChildLifetimeClosedV1);
            }
            _ => {}
        }
        self.direct_kill = Some(child.kill());
        if !matches!(self.direct_kill, Some(Ok(()))) {
            self.first.get_or_insert(First::DirectKill);
        }
        // The same owned child remains independently waitable after kill error.
        self.reap = Some(child.try_wait());
        if matches!(self.reap, Some(Err(_))) { self.first.get_or_insert(First::Reap); }
        if self.first.is_none() { Ok(()) } else { Err(ExecutionChildLifetimeClosedV1) }
    }

    /// Polls only the same already-entered helper's actual wait outcome.
    ///
    /// # Errors
    /// Retains errors and refuses another child, failed original or new effect.
    pub fn poll_unreleased_child_once(&mut self, child: &mut Child)
        -> std::result::Result<(), ExecutionChildLifetimeClosedV1>
    {
        if !self.timeout_entered || !self.unreleased_child || self.child != Some(child.id()) || self.first.is_some() {
            return Err(ExecutionChildLifetimeClosedV1);
        }
        if !matches!(self.reap, Some(Ok(Some(_)))) {
            self.reap = Some(child.try_wait());
            if matches!(self.reap, Some(Err(_))) { self.first.get_or_insert(First::Reap); }
        }
        if self.first.is_none() { Ok(()) } else { Err(ExecutionChildLifetimeClosedV1) }
    }

    /// Reports actual recursive quiescence and the retained original wait status.
    #[must_use]
    pub fn completed_status_v1(&self) -> Option<ExitStatus> {
        if self.first.is_some() || !self.timeout_entered || !(self.terminal_population || self.unreleased_child) { return None; }
        self.reap.as_ref()?.as_ref().ok()?.as_ref().copied()
    }

    /// Borrows the first actual native cause without another observation or effect.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Origin => self.origin_value.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Deadline => self.deadline.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Clock => self.clock_value.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Scope => self.scope.failure().map(|cause| cause as _),
            First::Quiescence => self.before_population.failure()
                .or_else(|| self.kill.native_failure_v2())
                .or_else(|| self.population.failure()),
            First::DirectKill => self.direct_kill.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Reap => self.reap.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error)
                .or(Some(&ExecutionChildLifetimeClosedV1)),
            First::Binding | First::Closed => Some(&ExecutionChildLifetimeClosedV1),
        }
    }
}

/// Validates an inherited original duration before the trusted child enters exec.
///
/// This is comparison DATA, not a clock origin, child admission or permission.
///
/// # Errors
/// Refuses zero duration, arithmetic substitution or expiration on this BOOTTIME.
pub fn require_child_lifetime_data_v1(origin: u64, timeout: u64, deadline: u64) -> Result<()> {
    let now = clock_nanoseconds(rustix::time::clock_gettime(rustix::time::ClockId::Boottime))?;
    if timeout == 0 || origin.checked_add(timeout) != Some(deadline) || now < origin || now >= deadline {
        return Err(Error::invalid("child lifetime", "original duration is invalid or expired"));
    }
    Ok(())
}

fn clock_nanoseconds(value: rustix::time::Timespec) -> Result<u64> {
    u64::try_from(value.tv_sec).ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| u64::try_from(value.tv_nsec).ok().filter(|nanos| *nanos < 1_000_000_000)
            .and_then(|nanos| seconds.checked_add(nanos)))
        .ok_or_else(|| Error::invalid("child lifetime", "CLOCK_BOOTTIME is not representable"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    struct OwnedTestChild(Child);

    impl Drop for OwnedTestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn an_earlier_startup_cut_does_not_replace_the_original_execution_lifetime() {
        let mut original = ExecutionChildLifetimeOriginalV1::new();
        original.start_once(10_000_000_000).unwrap();
        let initial = original.origin_data_v1().unwrap();

        assert!(original.is_expired_before_v1(0).unwrap());

        assert!(!original.is_expired().unwrap());
        assert_eq!(original.origin_data_v1(), Some(initial));
        assert!(!original.timeout_entered);
    }

    #[test]
    fn continue_disconnect_does_not_restart_or_cancel_original_child_timeout() {
        const CHILD: &str = "AOS_TEST_ORIGINAL_LIFETIME_CHILD";
        if std::env::var_os(CHILD).is_some() {
            // This exact helper never spawns or execs another process. Closing
            // its parent input is intentionally not a cancellation command.
            std::thread::sleep(Duration::from_secs(10));
            return;
        }
        let mut original = ExecutionChildLifetimeOriginalV1::new();
        original.start_once(1_000_000_000).unwrap();
        let initial = original.origin_data_v1().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let mut child = OwnedTestChild(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process::child_lifetime::tests::continue_disconnect_does_not_restart_or_cancel_original_child_timeout"])
            .env(CHILD, "1").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().unwrap());
        original.bind_child_once(&child.0).unwrap();
        drop(child.0.stdin.take());
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(!original.is_expired().unwrap());
        let upper = Instant::now() + Duration::from_secs(5);
        while !original.is_expired().unwrap() {
            assert!(child.0.try_wait().unwrap().is_none());
            assert!(Instant::now() < upper);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(original.origin_data_v1(), Some(initial));
        original.terminate_unreleased_child_once(&mut child.0).unwrap();
        while original.completed_status_v1().is_none() {
            assert!(Instant::now() < upper);
            original.poll_unreleased_child_once(&mut child.0).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(original.completed_status_v1().unwrap().signal(), Some(9));
        assert!(original.failure().is_none());
    }

    #[test]
    fn invalid_or_expired_original_never_starts_a_fresh_window() {
        let mut refused = ExecutionChildLifetimeOriginalV1::new();
        assert!(refused.start_once(0).is_err());
        let first = refused.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(refused.start_once(1_000_000_000).is_err());
        assert_eq!(refused.failure().unwrap() as *const dyn std::error::Error as *const (), first);
        let mut expired = ExecutionChildLifetimeOriginalV1::new();
        expired.start_once(1).unwrap();
        let (origin, duration, deadline) = expired.origin_data_v1().unwrap();
        while !expired.is_expired().unwrap() { std::thread::yield_now(); }
        assert!(require_child_lifetime_data_v1(origin, duration, deadline).is_err());
        assert!(require_child_lifetime_data_v1(origin, duration, deadline + 1).is_err());
    }
}
