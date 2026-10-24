//! Retains only the original primary clock at an existing upper clock frontier.
//!
//! This finite observation has no startup, peer, queue or Root-post effect.
//! Its owner retains every paid capture until the same selected flight retires;
//! the caller keeps its independent Root and final-clock posts at their original
//! positions, including after an earlier native or semantic failure.

use std::error::Error;
use std::time::Instant;

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};

use super::{
    ClockError, MAXIMUM_FLIGHT, RootObservationErrorV1 as Closed, RootQ04TransportOriginalV1,
    cause, positive,
};
use crate::kernel_clock::RetainedKernelPairedClockAttemptV1;

pub(super) struct OriginalClockV1 {
    clock: RetainedKernelPairedClockAttemptV1<ClockError>,
    current: Option<Result<RawPairedClockSample, ClockError>>,
    returned: Option<Result<(), Closed>>,
}

impl OriginalClockV1 {
    fn new() -> Self {
        Self {
            clock: Default::default(),
            current: None,
            returned: None,
        }
    }

    fn demand(count: usize) -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(count.checked_add(3)?)?
            .checked_add(std::mem::size_of::<Result<(), Closed>>().checked_mul(6)?)?
            .checked_add(
                std::mem::size_of::<Result<RawPairedClockSample, Closed>>().checked_mul(3)?,
            )?
            .checked_add(
                RetainedKernelPairedClockAttemptV1::<ClockError>::dominant_requested_bytes_v1()?,
            )?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(
                    D::OpenFiles,
                    RetainedKernelPairedClockAttemptV1::<ClockError>::MAXIMUM_RETAINED_FILES_V1
                        as u64,
                ),
        )
    }

    pub(super) fn is_complete_v1(&self) -> bool {
        matches!(self.returned, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.clock
            .failure()
            .or_else(|| cause(&self.current))
            .or_else(|| cause(&self.returned))
    }
}

pub(super) fn observe_original_clock_v1(
    clock: &mut RetainedKernelPairedClockAttemptV1<ClockError>,
    current: &mut Option<Result<RawPairedClockSample, ClockError>>,
    original: RawPairedClockSample,
    started: Instant,
) -> Result<(), Closed> {
    *current = Some(clock.observe_once(Some(original)));
    positive(current)?;
    if started.elapsed() >= MAXIMUM_FLIGHT {
        return Err(Closed::Service);
    }
    Ok(())
}

impl RootQ04TransportOriginalV1<'_> {
    /// Observes only the same original primary clock at the caller's clock frontier.
    ///
    /// This performs no startup, peer, queue, role or independent Root post. It
    /// remains a negative observation after refusal and cannot reopen a flight.
    /// The real financial debit precedes allocation and native clock capture.
    ///
    /// # Errors
    /// Retains native clock, interval, funding or destination-allocation failure.
    pub fn observe_original_clock_once_v1(&mut self) -> Result<RawPairedClockSample, Closed> {
        let original = *positive(&self.original_pair)?;
        let started = self.started.ok_or(Closed::Service)?;
        let count = self
            .original_clocks
            .len()
            .checked_add(1)
            .ok_or(Closed::Service)?;
        let demand = OriginalClockV1::demand(count).ok_or(Closed::Service)?;
        let financial = self.financial.as_ref().ok_or(Closed::Service)?;
        if let Err(error) = financial.debit_q04_transport_v1(demand) {
            self.crossing_funding.get_or_insert(error);
            return Err(Closed::Service);
        }
        if let Err(error) = self.original_clocks.try_reserve_exact(1) {
            self.crossing_reservation.get_or_insert(error);
            return Err(Closed::Service);
        }
        self.original_clocks.push(OriginalClockV1::new());
        let clock = self.original_clocks.last_mut().ok_or(Closed::Service)?;
        let permanent = financial.q04_permanent_v1();
        clock.returned = Some((|| {
            let _observation = permanent.enter_observation()?;
            observe_original_clock_v1(&mut clock.clock, &mut clock.current, original, started)
        })());
        if !clock.is_complete_v1() {
            self.closed.get_or_insert(Closed::Service);
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(Closed::Service);
        }
        positive(&clock.current)
            .copied()
            .map_err(|_| Closed::Service)
    }
}
