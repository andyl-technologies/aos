//! Drives the same original supervisor to clean exit after initial helper finish.
//!
//! Fixed retained turns preserve native poll outcomes and events. All borrowed
//! descriptors remain owned by the original supervisor; no second process or
//! reaping engine is introduced. This is not whole-unit drain after uncertainty.

use super::*;
use aos_sandbox_linux::process::FixedProcessRetainedSessionOutcome;
use rustix::event::{PollFd, poll};

const MAXIMUM_TURNS: usize = 128;

pub(super) struct InitialHelperCleanupOriginalV1 {
    next: usize,
    turns: [CleanupTurnOriginalV1; MAXIMUM_TURNS],
}

struct CleanupTurnOriginalV1 {
    progress: Option<FixedProcessDrivenProgressV1>,
    clocks: [Option<Timespec>; 4],
    waited: Option<Result<usize, rustix::io::Errno>>,
    events: [PollFlags; 5],
    count: usize,
}

impl InitialHelperCleanupOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            next: 0,
            turns: std::array::from_fn(|_| CleanupTurnOriginalV1 {
                progress: None,
                clocks: [None; 4],
                waited: None,
                events: [PollFlags::empty(); 5],
                count: 0,
            }),
        }
    }

    pub(super) fn receiving_bytes_v1() -> Option<usize> {
        // Fixed retained turns are covered by the enclosing Self construction.
        // The only extra carrier is the short stack array of borrowed polls.
        std::mem::size_of::<PollFd<'_>>()
            .checked_mul(5)?
            .checked_mul(3)
    }
}

impl CleanupTurnOriginalV1 {
    fn sample(&mut self, index: usize, cut: FixedProcessBoottimeCutV1) -> bool {
        self.clocks[index] = Some(clock_gettime(ClockId::Boottime));
        self.clocks[index]
            .and_then(nanoseconds)
            .is_some_and(|now| now < cut.exclusive_nanoseconds())
    }
}

impl InitialTpmHelperDrivingLoanV1<'_> {
    /// Advances one retained original cleanup turn after the finish send.
    ///
    /// A true result requires the actual supervisor's Ended state, no original
    /// cause or cleanup debt, and its normal exit-zero outcome. It grants no
    /// canonical checkpoint authority or uncertain-failure unit-drain claim.
    /// Source currentness must independently bracket every reached turn.
    ///
    /// # Errors
    /// Refuses wrong phase, reentry after completion, exhausted fixed turns,
    /// elapsed cut, original cleanup debt or an abnormal/nonzero outcome.
    pub fn advance_initial_cleanup_once_v1(
        &mut self,
    ) -> Result<bool, InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            if !matches!(
                self.handoff.phase,
                Phase::FinishSent | Phase::CleanupAdvanceReady
            ) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            self.require_phase(self.handoff.phase)?;
            self.handoff.phase = Phase::CleanupAdvancing;
            let index = self.handoff.cleanup.next;
            let turn = self
                .handoff
                .cleanup
                .turns
                .get_mut(index)
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            self.handoff.cleanup.next += 1;
            if !turn.sample(0, self.cut) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            turn.progress = Some(self.driving.advance_once());
            if !turn.sample(1, self.cut) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            match turn.progress {
                Some(FixedProcessDrivenProgressV1::Ended) => {
                    if !matches!(
                        self.driving.clean_ended_outcome_v1(),
                        Some(FixedProcessRetainedSessionOutcome::Completed {
                            exit_code: Some(0),
                            signal: None,
                            ..
                        })
                    ) {
                        return Err(InitialTpmHelperBirthClosedV1);
                    }
                    self.handoff.phase = Phase::Cleaned;
                    Ok(true)
                }
                Some(FixedProcessDrivenProgressV1::Debt) | None => {
                    Err(InitialTpmHelperBirthClosedV1)
                }
                _ => {
                    self.handoff.phase = Phase::CleanupNeedsWait;
                    Ok(false)
                }
            }
        })();
        if result.is_err() {
            self.first.get_or_insert(InitialTpmHelperBirthClosedV1);
        }
        result
    }

    /// Waits once on the original supervisor's bounded descriptor view.
    ///
    /// Its own BOOTTIME timer bounds this wait and cleanup retry wakeups. A
    /// missing view does not synthesize an event; the next bounded native turn
    /// must establish completion. Poll events are retained as mechanics only.
    ///
    /// # Errors
    /// Retains native poll errors and forwards them to the same supervisor;
    /// refuses wrong phase, missing timer/view descriptors or elapsed cut.
    pub fn wait_initial_cleanup_once_v1(&mut self) -> Result<(), InitialTpmHelperBirthClosedV1> {
        let result = (|| {
            self.require_phase(Phase::CleanupNeedsWait)?;
            self.handoff.phase = Phase::CleanupAdvanceReady;
            let index = self
                .handoff
                .cleanup
                .next
                .checked_sub(1)
                .ok_or(InitialTpmHelperBirthClosedV1)?;
            let turn = &mut self.handoff.cleanup.turns[index];
            if !turn.sample(2, self.cut) {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            if let Some(view) = self.driving.wait_view() {
                let mut descriptors = view.descriptors();
                let first = descriptors.next().ok_or(InitialTpmHelperBirthClosedV1)?;
                // Only the populated prefix is polled. The initial duplicates
                // borrow that same real descriptor and create no native FDs.
                let mut polls: [PollFd<'_>; 5] =
                    std::array::from_fn(|_| PollFd::from_borrowed_fd(first, PollFlags::IN));
                turn.count = 1;
                for descriptor in descriptors {
                    let entry = polls
                        .get_mut(turn.count)
                        .ok_or(InitialTpmHelperBirthClosedV1)?;
                    *entry = PollFd::from_borrowed_fd(descriptor, PollFlags::IN);
                    turn.count += 1;
                }
                turn.waited = Some(poll(&mut polls[..turn.count], None));
                for (index, descriptor) in polls[..turn.count].iter().enumerate() {
                    turn.events[index] = descriptor.revents();
                }
            }
            let after = turn.sample(3, self.cut);
            if let Some(Err(cause)) = turn.waited {
                self.driving.wait_failed(cause.into());
                return Err(InitialTpmHelperBirthClosedV1);
            }
            if !after {
                return Err(InitialTpmHelperBirthClosedV1);
            }
            Ok(())
        })();
        self.retain_refusal(result)
    }
}
