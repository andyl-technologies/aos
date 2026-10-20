//! Retains a finite disabling disposition for an already issued native scope.
//!
//! The caller authenticates its continuously held PIDFD, cgroup and events
//! original before entry. This native recipe constructs no authority or clock
//! deadline: it shares the bounded kill engine, waits once for leader exit and
//! at most once for a population change, and requires actual death plus Empty
//! or authenticated Retired. Every interrupted or uncertain prefix is retained.

use super::*;
use crate::pidfd::PidFd;
use rustix::event::{PollFd, PollFlags};

/// Reports refusal while the issued-scope native original stays retained.
#[derive(Debug, thiserror::Error)]
#[error("issued cgroup native disposition remains unresolved")]
pub struct IssuedCgroupQuiescenceRefusalV2;

#[derive(Clone, Copy)]
enum First {
    Order,
    Affinity,
    BeforeAlive,
    BeforePopulation,
    Kill,
    LeaderWait,
    EventsWait,
    AfterAlive,
    AfterPopulation,
    FinalAlive,
    FinalPopulation,
    Unresolved,
}

#[derive(Default)]
struct PollOriginalV2 {
    returned: Option<std::result::Result<usize, rustix::io::Errno>>,
    readiness: Option<PollFlags>,
    invalid: bool,
}

impl PollOriginalV2 {
    fn observe_once(
        &mut self,
        fd: BorrowedFd<'_>,
        requested: PollFlags,
        allowed: PollFlags,
    ) -> bool {
        let mut descriptors = [PollFd::new(&fd, requested)];
        self.returned = Some(rustix::event::poll(&mut descriptors, None));
        let flags = descriptors[0].revents();
        self.readiness = Some(flags);
        self.invalid = !matches!(self.returned, Some(Ok(1)))
            || flags.is_empty()
            || !flags.difference(allowed).is_empty();
        !self.invalid
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.returned
            .as_ref()?
            .as_ref()
            .err()
            .map(|error| error as _)
    }
}

/// Retains one issued-scope kill, finite native waits and all reached posts.
///
/// This holder owns no process or scope permission. Its caller must keep the
/// same authenticated native pins and prepaid disabling authority resident.
/// A successful kill or readiness notification alone never proves quiescence.
pub struct IssuedCgroupQuiescenceAttemptV2 {
    entered: bool,
    affinity: Option<Result<()>>,
    before_alive: Option<Result<bool>>,
    before_population: CgroupPopulationObservationV1,
    before_result: Option<std::result::Result<(), CgroupPopulationObservationRefusalV1>>,
    kill: CgroupKillAttemptV1,
    killed: Option<std::result::Result<(), CgroupKillRefusalV1>>,
    leader_wait: PollOriginalV2,
    events_wait: PollOriginalV2,
    after_alive: Option<Result<bool>>,
    after_population: CgroupPopulationObservationV1,
    after_result: Option<std::result::Result<(), CgroupPopulationObservationRefusalV1>>,
    final_alive: Option<Result<bool>>,
    final_population: CgroupPopulationObservationV1,
    final_result: Option<std::result::Result<(), CgroupPopulationObservationRefusalV1>>,
    first: Option<First>,
}

impl Default for IssuedCgroupQuiescenceAttemptV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl IssuedCgroupQuiescenceAttemptV2 {
    /// Creates inert destinations without native observation or permission.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entered: false,
            affinity: None,
            before_alive: None,
            before_population: CgroupPopulationObservationV1::new(),
            before_result: None,
            kill: CgroupKillAttemptV1::new(),
            killed: None,
            leader_wait: Default::default(),
            events_wait: Default::default(),
            after_alive: None,
            after_population: CgroupPopulationObservationV1::new(),
            after_result: None,
            final_alive: None,
            final_population: CgroupPopulationObservationV1::new(),
            final_result: None,
            first: None,
        }
    }

    /// Quotes native owners, bounded diagnostics and all population buffers.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(CgroupKillAttemptV1::requested_bytes_v1()?)?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?.checked_mul(3)?)?
            .checked_add(8 * 256)?;
        Some((
            bytes,
            CgroupKillAttemptV1::maximum_retained_files_v1(),
            CgroupKillAttemptV1::METADATA_ENTRIES_V1,
        ))
    }

    /// Executes one already-authorized disabling programme on the held pins.
    ///
    /// Each blocking native wait is entered at most once and retains EINTR as
    /// an actual failure. No polling loop, new timeout or effect-current gate
    /// can renew the operation. Independent liveness and population posts run
    /// even after kill or wait refusal; a remaining task stays unresolved.
    ///
    /// # Errors
    /// Refuses repeated entry, foreign events, native failures or missing
    /// actual leader death and exact Empty/Retired population evidence.
    pub fn capture_once_v2(
        &mut self,
        process: &PidFd,
        anchor: &RetainedCgroupAnchor,
        monitor: &CgroupPopulationMonitor,
    ) -> std::result::Result<(), IssuedCgroupQuiescenceRefusalV2> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(IssuedCgroupQuiescenceRefusalV2);
        }
        self.entered = true;
        self.first = Some(First::Affinity);
        self.affinity = Some(monitor.require_same_cgroup(anchor));
        if !matches!(self.affinity, Some(Ok(()))) {
            return Err(IssuedCgroupQuiescenceRefusalV2);
        }
        self.first = None;

        self.before_alive = Some(process.is_alive());
        if !matches!(self.before_alive, Some(Ok(_))) {
            self.first.get_or_insert(First::BeforeAlive);
        }
        self.before_result = Some(monitor.observe_state_retaining_v1(&mut self.before_population));
        if !matches!(self.before_result, Some(Ok(()))) {
            self.first.get_or_insert(First::BeforePopulation);
        }
        let already_quiet =
            matches!(self.before_alive, Some(Ok(false))) && quiet(&self.before_population);
        if !already_quiet {
            // The actual issued-scope caller consumed its existing two-write
            // allowance before entry. This is the same bounded native engine.
            self.killed = Some(self.kill.capture_once_bounded_v2(anchor));
            if !matches!(self.killed, Some(Ok(()))) {
                self.first.get_or_insert(First::Kill);
            }
        }

        self.after_alive = Some(process.is_alive());
        if !matches!(self.after_alive, Some(Ok(_))) {
            self.first.get_or_insert(First::AfterAlive);
        }
        self.after_result = Some(monitor.observe_state_retaining_v1(&mut self.after_population));
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::AfterPopulation);
        }
        if matches!(self.killed, Some(Ok(()))) && self.first.is_none() {
            if matches!(self.after_alive, Some(Ok(true)))
                && !self.leader_wait.observe_once(
                    process.as_fd(),
                    PollFlags::IN | PollFlags::RDNORM,
                    PollFlags::IN | PollFlags::RDNORM | PollFlags::HUP,
                )
            {
                self.first.get_or_insert(First::LeaderWait);
            }
            if !self.leader_wait.invalid && matches!(
                self.after_population.state(),
                Some(CgroupPopulationState::Populated)
            ) && !self.events_wait.observe_once(
                monitor.events.as_fd(),
                PollFlags::PRI,
                PollFlags::PRI | PollFlags::ERR | PollFlags::HUP,
            ) {
                self.first.get_or_insert(First::EventsWait);
            }
        }

        self.final_alive = Some(process.is_alive());
        if !matches!(self.final_alive, Some(Ok(_))) {
            self.first.get_or_insert(First::FinalAlive);
        }
        self.final_result = Some(monitor.observe_state_retaining_v1(&mut self.final_population));
        if !matches!(self.final_result, Some(Ok(()))) {
            self.first.get_or_insert(First::FinalPopulation);
        }
        if !matches!(self.final_alive, Some(Ok(false))) || !quiet(&self.final_population) {
            self.first.get_or_insert(First::Unresolved);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(IssuedCgroupQuiescenceRefusalV2)
        }
    }

    /// Borrows the earliest actual native cause without repeating an original.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Affinity => self
                .affinity
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::BeforeAlive => self
                .before_alive
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::BeforePopulation => self.before_population.failure(),
            First::Kill => self.kill.native_failure_v2(),
            First::LeaderWait => self.leader_wait.failure(),
            First::EventsWait => self.events_wait.failure(),
            First::AfterAlive => self
                .after_alive
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::AfterPopulation => self.after_population.failure(),
            First::FinalAlive => self
                .final_alive
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::FinalPopulation => self.final_population.failure(),
            First::Order | First::Unresolved => None,
        }
        .or(Some(&IssuedCgroupQuiescenceRefusalV2))
    }
}

fn quiet(original: &CgroupPopulationObservationV1) -> bool {
    matches!(
        original.state(),
        Some(CgroupPopulationState::Empty | CgroupPopulationState::Retired)
    )
}
