//! Sequential positive-only kernel clock retirement with an independent post.

use std::error::Error;

use aos_sandbox_core::{AccountingError, OwnershipLeaseVerificationError, RawPairedClockSample,
    ResourceDimension as D, ResourceVector};

use crate::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};
use super::FixedServiceOperationClosedV4 as Closed;

// The ordinary lane limits remain purpose-specific (opening29, Network14,
// Mount15, inventories3). Network's additional worker lane covers FDSTORE and
// BARRIER plus at most81 Prepare request frames and one observation namespace
// request. Each framed send has at most2
// native attempts. Each of the two child purposes additionally sends exactly
// one native Source prebirth request, with no retry or renewed deadline.
// A failed Prepare or failed Observe may additionally reach
// at most2 disabling cleanup writes; those failure paths are exclusive. Only
// the actual signed Network63/9 worker port enters this finite lane. Owed
// negative ACKs use their already-issued native custody without a fresh effect
// clock. Actual parent connect/receive/custody/public handoff gates are below.
const NETWORK_WORKER_PREBIRTH_PAIRS: usize = 2;
// Each same-Source PREPARED wait uses a fresh original pair to clamp its one
// native poll to D. A readonly acknowledgement does not renew that deadline.
const NETWORK_WORKER_PREPARED_PAIRS: usize = 2;
// Actual pre-READY custody waits each clamp one native poll to the SAME D.
const NETWORK_WORKER_BIRTH_CUSTODY_PAIRS: usize = 2;
// Each completed native custody join permits one actual PID1 ARMED send.
const NETWORK_WORKER_ARMED_PAIRS: usize = 2;
// Each P/O connect has one actual final native gate.
const NETWORK_WORKER_PARENT_CONNECT_PAIRS: usize = 2;
// Each P/O READY and terminal receive has one enclosing paid Source clock.
const NETWORK_WORKER_PARENT_RECEIVE_PAIRS: usize = 4;
// Only P runs the actual synchronous Domain custody binder.
const NETWORK_WORKER_PARENT_CUSTODY_PAIRS: usize = 1;
// O sends its fixed H03 header and full six-right record at separate frontiers.
const NETWORK_WORKER_PARENT_HANDOFF_PAIRS: usize = 2;
// Each actual PID1 exit reply has an original-D wait and positive after join.
const NETWORK_WORKER_COMPLETION_PAIRS: usize = 4;
const NETWORK_WORKER_PRIMARY_PAIRS: usize = 2 + 2 * (81 + 1)
    + NETWORK_WORKER_PREBIRTH_PAIRS + NETWORK_WORKER_PREPARED_PAIRS
    + NETWORK_WORKER_BIRTH_CUSTODY_PAIRS + NETWORK_WORKER_ARMED_PAIRS
    + NETWORK_WORKER_PARENT_CONNECT_PAIRS + NETWORK_WORKER_PARENT_RECEIVE_PAIRS
    + NETWORK_WORKER_PARENT_CUSTODY_PAIRS + NETWORK_WORKER_PARENT_HANDOFF_PAIRS
    + NETWORK_WORKER_COMPLETION_PAIRS;
const NETWORK_WORKER_EFFECT_PAIRS: usize = NETWORK_WORKER_PRIMARY_PAIRS + 2;
const MAXIMUM_PRIMARY_PAIRS: usize = 14 + NETWORK_WORKER_EFFECT_PAIRS;
type Attempt = RetainedKernelPairedClockAttemptV1<ClockError>;

#[derive(Debug, thiserror::Error)]
enum ClockError {
    #[error("fixed-service kernel clock is not current")]
    Stale,
    #[error(transparent)]
    Kernel(aos_sandbox_linux::Error),
    #[error(transparent)]
    Continuity(OwnershipLeaseVerificationError),
}

impl KernelPairedClockErrorV1 for ClockError {
    fn stale() -> Self { Self::Stale }
    fn kernel(error: aos_sandbox_linux::Error) -> Self { Self::Kernel(error) }
}

pub(super) struct OperationClockV4 {
    primary: Attempt,
    samples: [Option<RawPairedClockSample>; MAXIMUM_PRIMARY_PAIRS],
    used: usize,
    ordinary_used: usize,
    worker_used: usize,
    after: Attempt,
    after_result: Option<Result<RawPairedClockSample, Closed>>,
    first: Option<ClockError>,
    primary_failed: bool,
    after_failed_first: bool,
    deadline: Option<u64>,
    wall_expiry: Option<i64>,
}

impl Default for OperationClockV4 {
    fn default() -> Self {
        Self { primary: Default::default(), samples: [None; MAXIMUM_PRIMARY_PAIRS], used: 0, ordinary_used: 0, worker_used: 0,
            after: Default::default(), after_result: None, first: None, primary_failed: false, after_failed_first: false,
            deadline: None, wall_expiry: None }
    }
}

impl OperationClockV4 {
    pub(super) fn opening_data(&self) -> Result<RawPairedClockSample, Closed> {
        if self.first.is_some() || self.after_result.is_some() { return Err(Closed); }
        self.samples[0].ok_or(Closed)
    }

    pub(super) fn retained_interval_data_v4(&self) -> Result<(RawPairedClockSample, u64), Closed> {
        if self.first.is_some() || self.after_result.is_some() { return Err(Closed); }
        let current = self.used.checked_sub(1).and_then(|index| self.samples[index]).ok_or(Closed)?;
        Ok((current, self.deadline.ok_or(Closed)?))
    }

    pub(super) fn retained_wall_ceiling_data_v4(&mut self) -> Result<Option<i64>, Closed> {
        self.require_current()?;
        Ok(self.wall_expiry)
    }

    pub(super) fn dynamic_demand() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let bytes = Attempt::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<Attempt>()))
            .and_then(|bytes| bytes.checked_mul(2)).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(overflow)?;
        let names = Attempt::receiving_metadata_cells_v1().and_then(|names| names.checked_mul(2))
            .and_then(|names| u64::try_from(names).ok()).ok_or(overflow)?;
        let files = Attempt::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)
            .and_then(|files| u64::try_from(files).ok()).ok_or(overflow)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, files)
            .with(D::MetadataEntries, names))
    }

    pub(super) fn observe_primary(&mut self, limit: usize) -> Result<RawPairedClockSample, Closed> {
        self.observe_selected_primary_v4(limit, false)
    }

    pub(super) fn observe_worker_primary_v4(&mut self) -> Result<RawPairedClockSample, Closed> {
        self.observe_selected_primary_v4(NETWORK_WORKER_PRIMARY_PAIRS, true)
    }

    pub(super) fn observe_worker_cleanup_primary_v4(&mut self) -> Result<RawPairedClockSample, Closed> {
        self.observe_selected_primary_v4(NETWORK_WORKER_EFFECT_PAIRS, true)
    }

    fn observe_selected_primary_v4(&mut self, limit: usize, worker: bool) -> Result<RawPairedClockSample, Closed> {
        let lane_used = if worker { self.worker_used } else { self.ordinary_used };
        if self.first.is_some() || self.after_result.is_some() || lane_used >= limit
            || self.used >= self.samples.len()
        {
            self.first.get_or_insert(ClockError::Stale);
            return Err(Closed);
        }
        if self.used != 0 {
            // The SAME kernel recipe closed both successful boot readers
            // before returning the previous pair. Only those pure completed
            // buffers retire here; a failed/partial reader is never replaced.
            drop(std::mem::take(&mut self.primary));
        }
        let result = self.primary.observe_once(None);
        let current = match result {
            Ok(current) => current,
            Err(error) => {
                self.primary_failed = true;
                self.first.get_or_insert(error);
                return Err(Closed);
            }
        };
        let previous = self.used.checked_sub(1).and_then(|index| self.samples[index]);
        self.samples[self.used] = Some(current);
        self.used += 1;
        if worker { self.worker_used += 1; } else { self.ordinary_used += 1; }
        if let Some(previous) = previous {
            if let Err(error) = previous.validate_later_sample(current) {
                self.first.get_or_insert(ClockError::Continuity(error));
                return Err(Closed);
            }
        }
        self.require_sample(current)?;
        Ok(current)
    }

    pub(super) fn narrow(&mut self, deadline: u64, wall_expiry: Option<i64>) -> Result<(), Closed> {
        if deadline == 0 || self.first.is_some() || self.after_result.is_some() {
            self.first.get_or_insert(ClockError::Stale);
            return Err(Closed);
        }
        self.deadline = Some(self.deadline.map_or(deadline, |held| held.min(deadline)));
        if let Some(expiry) = wall_expiry {
            self.wall_expiry = Some(self.wall_expiry.map_or(expiry, |held| held.min(expiry)));
        }
        let current = self.used.checked_sub(1).and_then(|index| self.samples[index]).ok_or(Closed)?;
        self.require_sample(current)
    }

    pub(super) fn require_current(&mut self) -> Result<(), Closed> {
        let current = self.used.checked_sub(1).and_then(|index| self.samples[index]).ok_or(Closed)?;
        if self.deadline.is_none() || self.first.is_some() || self.after_result.is_some() { return Err(Closed); }
        self.require_sample(current)
    }

    fn require_sample(&mut self, current: RawPairedClockSample) -> Result<(), Closed> {
        if self.deadline.is_some_and(|deadline| current.boottime_nanoseconds() >= deadline)
            || self.wall_expiry.is_some_and(|expiry| current.wall_seconds() >= expiry)
        {
            self.first.get_or_insert(ClockError::Stale);
            return Err(Closed);
        }
        Ok(())
    }

    pub(super) fn finish_once(&mut self) -> Result<(), Closed> {
        if self.after_result.is_some() { return Err(Closed); }
        // No healthy-primary guard can suppress this separate prepaid reader.
        let result = self.after.observe_once(None);
        self.after_result = Some(match result {
            Ok(current) => {
                let previous = self.used.checked_sub(1).and_then(|index| self.samples[index]);
                if let Some(previous) = previous {
                    if let Err(error) = previous.validate_later_sample(current) {
                        self.first.get_or_insert(ClockError::Continuity(error));
                    }
                }
                let _ = self.require_sample(current);
                Ok(current)
            }
            Err(error) => {
                self.after_failed_first = self.first.is_none();
                self.first.get_or_insert(error);
                Err(Closed)
            }
        });
        if self.used == 0 || self.deadline.is_none() {
            self.first.get_or_insert(ClockError::Stale);
        }
        if self.first.is_some() { Err(Closed) } else { Ok(()) }
    }

    pub(super) fn completed_inventory_pair_v5(&self) -> bool {
        self.first.is_none() && self.used > 0 && self.deadline.is_some()
            && matches!(self.after_result, Some(Ok(_)))
            && self.primary.failure().is_none() && self.after.failure().is_none()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.primary_failed {
            self.primary.failure().or_else(|| self.first.as_ref().map(|cause| cause as _))
        } else if self.after_failed_first {
            self.after.failure().or_else(|| self.first.as_ref().map(|cause| cause as _))
        } else {
            self.first.as_ref().map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.after.failure())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owed_pair_still_enters_after_primary_schedule_refusal() {
        let mut clock = OperationClockV4::default();

        assert!(clock.observe_primary(0).is_err());
        let original = clock.failure().unwrap() as *const dyn Error;
        assert!(clock.finish_once().is_err());

        assert!(clock.after_result.is_some());
        assert!(std::ptr::addr_eq(clock.failure().unwrap() as *const dyn Error, original));
        assert!(clock.observe_primary(MAXIMUM_PRIMARY_PAIRS).is_err());
    }

    #[test]
    fn later_real_kernel_pairs_keep_original_ceiling_and_provenance() {
        let mut clock = OperationClockV4::default();
        let before = clock.observe_primary(1).unwrap();
        let deadline = before.boottime_nanoseconds().checked_add(60_000_000_000).unwrap();
        clock.narrow(deadline, None).unwrap();

        let next = clock.observe_primary(2).unwrap();
        before.validate_later_sample(next).unwrap();
        clock.narrow(deadline.checked_add(1).unwrap(), None).unwrap();
        assert_eq!(clock.deadline, Some(deadline));
        clock.finish_once().unwrap();

        assert_eq!(clock.used, 2);
        assert!(clock.after_result.as_ref().unwrap().is_ok());
        assert!(clock.primary.failure().is_none());
        assert!(clock.after.failure().is_none());
    }
    #[test]
    fn worker_lane_preserves_the_existing_domain_lane_and_owed_after() {
        let mut clock = OperationClockV4::default();
        let opening = clock.observe_primary(1).unwrap();
        let deadline = opening.boottime_nanoseconds().checked_add(60_000_000_000).unwrap();
        clock.narrow(deadline, None).unwrap();

        for _ in 0..NETWORK_WORKER_PRIMARY_PAIRS {
            clock.observe_worker_primary_v4().unwrap();
        }
        // The additional sends do not spend a generic domain/CAS/send slot.
        clock.observe_primary(2).unwrap();
        assert_eq!(clock.ordinary_used, 2);
        assert_eq!(clock.worker_used, NETWORK_WORKER_PRIMARY_PAIRS);
        clock.observe_worker_cleanup_primary_v4().unwrap();
        clock.observe_worker_cleanup_primary_v4().unwrap();
        assert_eq!(clock.worker_used, NETWORK_WORKER_EFFECT_PAIRS);
        assert_eq!(clock.deadline, Some(deadline));

        assert!(clock.observe_worker_cleanup_primary_v4().is_err());
        let first = clock.failure().unwrap() as *const dyn Error;
        assert!(clock.finish_once().is_err());
        assert!(clock.after_result.is_some());
        assert!(std::ptr::addr_eq(clock.failure().unwrap() as *const dyn Error, first));
    }

}
