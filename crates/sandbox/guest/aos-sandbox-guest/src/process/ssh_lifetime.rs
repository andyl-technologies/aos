//! Keeps the same paid SSH subtree reachable by the existing timeout actor.
//!
//! Main owns libc spawn, the actual ChildGuard and listener/bootstrap receipt.
//! This slot owns only the moved standing scope. Neither the live-map mutex
//! nor a mutex needed by this slot spans main's native spawn or receipt wait.

use super::*;
use aos_sandbox_linux::guest_cgroup::{GuestSshScopeOriginalV1, GuestSshStandingOriginalV1};
use aos_sandbox_linux::process::{
    ExecutionChildLifetimeClosedV1, ExecutionChildLifetimeOriginalV1,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::GuestSshBootstrapOriginalV1;

pub(super) struct SshStandingExecutionV1 {
    original: GuestSshStandingOriginalV1,
    clock: Option<Result<bool, ExecutionChildLifetimeClosedV1>>,
    wall: Option<rustix::time::Timespec>,
    wall_error: Option<GuestProcessEffectErrorV1>,
    requested: bool,
    containment: Option<Result<bool, aos_sandbox_linux::Error>>,
}

impl SshStandingExecutionV1 {
    fn new(original: GuestSshStandingOriginalV1) -> Self {
        Self {
            original,
            clock: None,
            wall: None,
            wall_error: None,
            requested: false,
            containment: None,
        }
    }

    pub(super) fn poll_due_once(
        &mut self,
        lifetime: &mut ExecutionChildLifetimeOriginalV1,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        if !self.requested {
            self.clock = Some(
                lifetime.is_expired_before_v1(self.original.current_boottime_cutoff_data_v1()),
            );
            let previous_wall = self.wall;
            self.wall = Some(rustix::time::clock_gettime(rustix::time::ClockId::Realtime));
            let wall = self
                .wall
                .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
            if wall.tv_sec < 0
                || !(0..1_000_000_000).contains(&wall.tv_nsec)
                || previous_wall.is_some_and(|previous| {
                    (wall.tv_sec, wall.tv_nsec) < (previous.tv_sec, previous.tv_nsec)
                })
            {
                self.wall_error = Some(GuestProcessEffectErrorV1::InvalidRequest);
            }
            self.requested = !matches!(self.clock, Some(Ok(false)))
                || self.wall_error.is_some()
                || wall.tv_sec >= self.original.wall_expiry_data_v1();
        }
        if self.requested {
            // Unknown clocks stop this owned startup, but cannot suppress its
            // separately checked seal/kill/population and independent posts.
            self.containment = Some(self.original.poll_containment_once_v1());
        }
        if self.clock.as_ref().is_some_and(Result::is_err)
            || self.wall_error.is_some()
            || self.containment.as_ref().is_some_and(Result::is_err)
        {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        Ok(())
    }

    fn complete_startup(
        &mut self,
        bootstrap: &GuestSshBootstrapOriginalV1,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        if self.requested
            || self.wall_error.is_some()
            || self.clock.as_ref().is_some_and(Result::is_err)
        {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        self.original.complete_startup_once_v1(bootstrap)?;
        Ok(())
    }
}

impl Ledger {
    /// Captures the actual barrier-stable roster's remaining simultaneous FDs.
    ///
    /// The sole effect actor calls this while holding its existing barrier.
    /// Bridge intake can accept one socket/peer pidfd before waiting there;
    /// only its native timeout polls remain able to grow the shared table.
    pub(crate) fn ssh_birth_inputs_v1(
        &self,
        process: &ProcessRecord,
    ) -> Result<(aos_sandbox_guest_protocol::openssh_receiving::OpenSshDescendantPlanDataV1, u64),
        GuestProcessEffectErrorV1>
    {
        let live = self.live().lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        if live.pending.is_some() || live.pending_lent || live.has_failed_input_v1() {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        let actual = live.get(&process.execution)
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        if actual.record.operation != process.operation
            || actual.record.runtime != process.runtime
            || actual.record.pid != process.pid
            || actual.record.start_ticks != process.start_ticks
            || actual.record.lifetime != process.lifetime
            || actual.record.terminal.is_some()
            || actual.timeout_record.is_some()
            || actual.ssh_standing.is_some()
        {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        let plan = actual.ssh_plan.ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        let lifetime_files = ExecutionChildLifetimeOriginalV1::receiving_obligations_v1()
            .and_then(|(_, files, _)| u64::try_from(files).ok())
            .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        let standing_files = GuestSshStandingOriginalV1::receiving_obligations_v1()
            .and_then(|(_, files, _)| u64::try_from(files).ok())
            .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;

        // Sum complete suppliers instead of crediting already open positions.
        // Each timeout can retain its active/kill files. A concurrent ordinary
        // GuestOwner check has three files; one accepted bridge carrier has two.
        // Only this main actor adds slots, so this roster cannot grow at birth.
        let mut future_files = 2_u64.checked_add(3)
            .and_then(|files| files.checked_add(standing_files))
            .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        for member in live.values() {
            future_files = future_files.checked_add(lifetime_files)
                .and_then(|files| files.checked_add(
                    if member.ssh_standing.is_some() { standing_files } else { 0 }))
                .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        }
        Ok((plan, future_files))
    }

    // All fallible gates borrow the parent's Option. The native owner moves
    // only after the SAME original live execution and one vacant slot match.
    pub(crate) fn park_ssh_standing_once_v1(
        &self,
        process: &ProcessRecord,
        original: &mut Option<GuestSshStandingOriginalV1>,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        let mut live = self
            .live()
            .lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        let actual = live
            .get_mut(&process.execution)
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        if actual.record.operation != process.operation
            || actual.record.runtime != process.runtime
            || actual.record.pid != process.pid
            || actual.record.start_ticks != process.start_ticks
            || actual.record.lifetime != process.lifetime
            || actual.ssh_plan.is_none()
            || actual.ssh_standing.is_some()
            || actual.timeout_record.is_some()
            || actual.record.terminal.is_some()
        {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        let original = original
            .take()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        actual.ssh_standing = Some(Box::new(SshStandingExecutionV1::new(original)));
        Ok(())
    }

    pub(crate) fn complete_ssh_startup_once_v1(
        &self,
        process: &ProcessRecord,
        bootstrap: &GuestSshBootstrapOriginalV1,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        let mut live = self
            .live()
            .lock()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        let actual = live
            .get_mut(&process.execution)
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        if actual.record.runtime != process.runtime
            || actual.record.operation != process.operation
            || actual.record.lifetime != process.lifetime
            || actual.record.terminal.is_some()
            || actual.timeout_record.is_some()
        {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        actual
            .ssh_standing
            .as_mut()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?
            .complete_startup(bootstrap)
    }

    pub(crate) fn request_ssh_retirement_v1(&self, execution: [u8; 16]) {
        // Poison refuses every positive caller but cannot erase native custody
        // or suppress already-owned negative cleanup during unwind.
        let mut live = self
            .live()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(standing) = live
            .get_mut(&execution)
            .and_then(|process| process.ssh_standing.as_mut())
        {
            standing.requested = true;
        }
    }

    pub(crate) fn poll_ssh_retirement_v1(
        &self,
        execution: [u8; 16],
        birth: &mut GuestSshScopeOriginalV1,
    ) -> Result<bool, GuestProcessEffectErrorV1> {
        let mut live = self
            .live()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let actual = live
            .get_mut(&execution)
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let standing = actual
            .ssh_standing
            .as_mut()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        standing.requested = true;
        let containment = standing.poll_due_once(&mut actual.lifetime);
        // Direct-child kill/reap is owed even if the independent standing
        // prefix refused. Its native owner remains on the caller's birth.
        let child = birth.poll_retirement_once_v1(&standing.original);
        containment?;
        child.map_err(Into::into)
    }
}
