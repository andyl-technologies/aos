//! Shares the existing empty/kill/deadline/poll cancellation sequence.
//!
//! Cancellation and population observations remain separate. A kill result is
//! never quiescence proof; only a later actual empty/retired observation ends
//! this sequence. Selected native errors and bytes stay on the supplied owner.

use super::*;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);

/// Preserves the ordinary cancellation and clock/refusal categories.
#[derive(Debug, thiserror::Error)]
pub enum StorageRecoveryQuiescenceErrorV1 {
    /// Contains the returned native error or retained-native marker.
    #[error(transparent)]
    Kernel(#[from] Error),
    /// Rejects a negative boottime seconds value.
    #[error("CLOCK_BOOTTIME seconds are invalid")]
    Seconds,
    /// Rejects a negative boottime nanoseconds value.
    #[error("CLOCK_BOOTTIME nanoseconds are invalid")]
    Nanoseconds,
    /// Rejects boottime conversion overflow.
    #[error("CLOCK_BOOTTIME overflowed")]
    ClockOverflow,
    /// Rejects a deadline addition overflow.
    #[error("workspace pin quiescence deadline overflowed")]
    DeadlineOverflow,
    /// Preserves the existing bounded cancellation timeout.
    #[error("recovered worker cgroup cancellation timed out")]
    Elapsed,
    /// Refuses reentry without another native action.
    #[error("Storage recovery cancellation is closed")]
    Closed,
}

trait Observation {
    fn population(&mut self, monitor: &CgroupPopulationMonitor) -> Result<CgroupPopulationState>;
    fn kill(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()>;
    fn clock(&mut self) -> std::result::Result<u64, StorageRecoveryQuiescenceErrorV1>;
}

fn clock_value(value: rustix::time::Timespec)
    -> std::result::Result<u64, StorageRecoveryQuiescenceErrorV1>
{
    let seconds = u64::try_from(value.tv_sec).map_err(|_| StorageRecoveryQuiescenceErrorV1::Seconds)?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| StorageRecoveryQuiescenceErrorV1::Nanoseconds)?;
    seconds.checked_mul(1_000_000_000).and_then(|value| value.checked_add(nanos))
        .ok_or(StorageRecoveryQuiescenceErrorV1::ClockOverflow)
}

fn quiesce(anchor: &RetainedCgroupAnchor, monitor: &CgroupPopulationMonitor,
    observation: &mut impl Observation,
) -> std::result::Result<(), StorageRecoveryQuiescenceErrorV1> {
    if observation.population(monitor)? != CgroupPopulationState::Populated { return Ok(()); }
    observation.kill(anchor)?;
    let deadline = observation.clock()?.checked_add(TIMEOUT.as_nanos() as u64)
        .ok_or(StorageRecoveryQuiescenceErrorV1::DeadlineOverflow)?;
    while observation.population(monitor)? == CgroupPopulationState::Populated {
        let remaining = deadline.checked_sub(observation.clock()?)
            .filter(|remaining| *remaining != 0).ok_or(StorageRecoveryQuiescenceErrorV1::Elapsed)?;
        std::thread::sleep(Duration::from_nanos(remaining).min(POLL));
    }
    Ok(())
}

struct Ordinary;

impl Observation for Ordinary {
    fn population(&mut self, monitor: &CgroupPopulationMonitor) -> Result<CgroupPopulationState> {
        monitor.state()
    }

    fn kill(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> { anchor.kill_all() }

    fn clock(&mut self) -> std::result::Result<u64, StorageRecoveryQuiescenceErrorV1> {
        clock_value(rustix::time::clock_gettime(rustix::time::ClockId::Boottime))
    }
}

/// Runs the same ordinary cancellation sequence without retaining new owners.
///
/// # Errors
/// Preserves the native error, old clock checks and bounded timeout category.
pub fn quiesce_storage_worker_cgroup_v1(anchor: &RetainedCgroupAnchor, monitor: &CgroupPopulationMonitor)
    -> std::result::Result<(), StorageRecoveryQuiescenceErrorV1>
{
    quiesce(anchor, monitor, &mut Ordinary)
}

#[derive(Clone, Copy)]
enum First { Population, Kill, Clock, Sequence, Closed }

/// Owns the selected cancellation's raw population, kill and clock observations.
///
/// Positive population records complete their own exact same-OFD read/parse
/// scope before replacement. Negative records and every reached kill partial
/// remain resident. The outer genuine stage still owes its independent post.
pub struct StorageWorkerRecoveryQuiescenceV1 {
    population: CgroupPopulationObservationV1,
    kill: CgroupKillAttemptV1,
    kill_result: Option<std::result::Result<(), CgroupKillRefusalV1>>,
    clock: Option<rustix::time::Timespec>,
    clock_result: Option<std::result::Result<u64, StorageRecoveryQuiescenceErrorV1>>,
    result: Option<std::result::Result<(), StorageRecoveryQuiescenceErrorV1>>,
    first: Option<First>,
    entered: bool,
}

impl Default for StorageWorkerRecoveryQuiescenceV1 {
    fn default() -> Self { Self::new() }
}

impl StorageWorkerRecoveryQuiescenceV1 {
    /// Creates fixed empty native destinations without IO or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self { population: CgroupPopulationObservationV1::new(), kill: CgroupKillAttemptV1::new(),
            kill_result: None, clock: None, clock_result: None, result: None, first: None, entered: false }
    }

    /// Prices its owner/construction frame, raw reader and bounded errors.
    #[must_use]
    pub fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?)?
            .checked_add(12 * 256)
    }

    /// Runs the same native sequence once, retaining every refused observation.
    ///
    /// # Errors
    /// Retains the actual population, kill, clock or timeout cause; repeated
    /// entry cannot replace the earlier completed or failed sequence.
    pub fn capture_once(&mut self, anchor: &RetainedCgroupAnchor, monitor: &CgroupPopulationMonitor)
        -> std::result::Result<(), StorageRecoveryQuiescenceErrorV1>
    {
        if self.entered {
            self.first.get_or_insert(First::Closed);
            return Err(StorageRecoveryQuiescenceErrorV1::Closed);
        }
        self.entered = true;
        self.result = Some(quiesce(anchor, monitor, self));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else {
            self.first.get_or_insert(First::Sequence);
            Err(StorageRecoveryQuiescenceErrorV1::Closed)
        }
    }

    /// Reports complete native quiescence; this is DATA, never disposal credit.
    #[must_use]
    pub fn completed(&self) -> bool { self.first.is_none() && matches!(self.result, Some(Ok(()))) }

    /// Borrows the actual first cause rather than a retained-native marker.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Population => self.population.failure(),
            First::Kill => self.kill.failure().map(|cause| cause as &(dyn std::error::Error + 'static)),
            First::Clock => self.clock_result.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Sequence => self.result.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Closed => Some(&StorageRecoveryQuiescenceErrorV1::Closed),
        }
    }
}

impl Observation for StorageWorkerRecoveryQuiescenceV1 {
    fn population(&mut self, monitor: &CgroupPopulationMonitor) -> Result<CgroupPopulationState> {
        if self.population.state().is_some() {
            // Only the already completed positive native read is disposed.
            self.population = CgroupPopulationObservationV1::new();
        }
        if monitor.observe_state_retaining_v1(&mut self.population).is_err() {
            self.first.get_or_insert(First::Population);
            return Err(Error::invalid("Storage recovery population", "native original retained"));
        }
        self.population.state().ok_or_else(|| Error::invalid("Storage recovery population", "state absent"))
    }

    fn kill(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        self.kill_result = Some(self.kill.capture_once(anchor));
        if matches!(self.kill_result, Some(Ok(()))) { Ok(()) } else {
            self.first.get_or_insert(First::Kill);
            Err(Error::invalid("Storage recovery cancellation", "native original retained"))
        }
    }

    fn clock(&mut self) -> std::result::Result<u64, StorageRecoveryQuiescenceErrorV1> {
        self.clock = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        let Some(value) = self.clock else { std::process::abort() };
        self.clock_result = Some(clock_value(value));
        match self.clock_result.as_ref() {
            Some(Ok(value)) => Ok(*value),
            _ => {
                self.first.get_or_insert(First::Clock);
                Err(StorageRecoveryQuiescenceErrorV1::Closed)
            }
        }
    }
}
