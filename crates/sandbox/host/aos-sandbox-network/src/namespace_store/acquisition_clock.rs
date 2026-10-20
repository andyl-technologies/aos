//! Retains one fixed native startup acquisition interval without effect authority.
//!
//! The paired kernel sampler is the existing Broker engine. Its five-second
//! limit bounds first-local systemd/native acquisition only; it never supplies
//! a request, lease, execution deadline or replacement operation. Positive
//! before/after results stay with the same owner through the outer F posts.

use aos_sandbox_broker::kernel_clock::{
    KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};

const ACQUISITION_NANOSECONDS: u64 = 5_000_000_000;
type Attempt = RetainedKernelPairedClockAttemptV1<ClockError>;

#[derive(Debug, thiserror::Error)]
enum ClockError {
    #[error("Network native startup acquisition clock is not current")]
    Stale,
    #[error(transparent)]
    Kernel(aos_sandbox_linux::Error),
    #[error(transparent)]
    Continuity(aos_sandbox_model::OwnershipLeaseVerificationError),
}

impl KernelPairedClockErrorV1 for ClockError {
    fn stale() -> Self {
        Self::Stale
    }

    fn kernel(cause: aos_sandbox_linux::Error) -> Self {
        Self::Kernel(cause)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Network native startup acquisition is incomplete or refused")]
pub(crate) struct NetworkStartupClockRefusalV4;

/// Borrows mechanical DATA from the actual retained initial kernel sample.
#[derive(Clone, Copy)]
pub(crate) struct NetworkStartupHorizonV4 {
    pub(crate) sample: RawPairedClockSample,
    pub(crate) boottime_cutoff: u64,
    pub(crate) deadline: tokio::time::Instant,
}

pub(crate) struct NetworkStartupAcquisitionClockV4 {
    before: Attempt,
    after: Attempt,
    before_result: Option<Result<RawPairedClockSample, ClockError>>,
    after_result: Option<Result<RawPairedClockSample, ClockError>>,
    horizon: Option<NetworkStartupHorizonV4>,
    comparison: Option<Result<(), ClockError>>,
    closed: Option<ClockError>,
}

impl NetworkStartupAcquisitionClockV4 {
    pub(crate) fn new() -> Self {
        Self {
            before: Attempt::default(),
            after: Attempt::default(),
            before_result: None,
            after_result: None,
            horizon: None,
            comparison: None,
            closed: None,
        }
    }

    pub(crate) fn receiving_demand_v4() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(Attempt::dominant_requested_bytes_v1()?.checked_mul(2)?)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(
                    D::OpenFiles,
                    u64::try_from(Attempt::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)?).ok()?,
                )
                .with(
                    D::MetadataEntries,
                    u64::try_from(Attempt::receiving_metadata_cells_v1()?.checked_mul(2)?).ok()?,
                ),
        )
    }

    pub(crate) fn begin_once_v4(
        &mut self,
    ) -> Result<NetworkStartupHorizonV4, NetworkStartupClockRefusalV4> {
        if self.before_result.is_some() || self.after_result.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(ClockError::Stale);
            return Err(NetworkStartupClockRefusalV4);
        }
        // Start the coarse timeout before the actual paired observation. Its
        // timer therefore cannot extend the five-second native BOOTTIME bound.
        let reference = tokio::time::Instant::now();
        self.before_result = Some(self.before.observe_once(None));
        let Some(Ok(sample)) = self.before_result.as_ref() else {
            return Err(NetworkStartupClockRefusalV4);
        };
        let Some(boottime_cutoff) = sample
            .boottime_nanoseconds()
            .checked_add(ACQUISITION_NANOSECONDS)
        else {
            self.closed = Some(ClockError::Stale);
            return Err(NetworkStartupClockRefusalV4);
        };
        let Some(deadline) =
            reference.checked_add(std::time::Duration::from_nanos(ACQUISITION_NANOSECONDS))
        else {
            self.closed = Some(ClockError::Stale);
            return Err(NetworkStartupClockRefusalV4);
        };
        let horizon = NetworkStartupHorizonV4 {
            sample: *sample,
            boottime_cutoff,
            deadline,
        };
        self.horizon = Some(horizon);
        Ok(horizon)
    }

    pub(crate) fn finish_once_v4(&mut self) -> Result<(), NetworkStartupClockRefusalV4> {
        if self.after_result.is_some() || self.before_result.is_none() {
            self.closed.get_or_insert(ClockError::Stale);
            return Err(NetworkStartupClockRefusalV4);
        }
        // Enter this independent original even when before/body already failed.
        let baseline = self
            .before_result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied();
        self.after_result = Some(self.after.observe_once(baseline));
        self.comparison = Some(match (self.horizon, self.after_result.as_ref()) {
            (Some(horizon), Some(Ok(current))) => horizon
                .sample
                .validate_later_sample(*current)
                .map_err(ClockError::Continuity)
                .and_then(|()| {
                    if current.boottime_nanoseconds() >= horizon.boottime_cutoff {
                        Err(ClockError::Stale)
                    } else {
                        Ok(())
                    }
                }),
            _ => Err(ClockError::Stale),
        });
        if self.failure().is_none() && matches!(self.comparison, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NetworkStartupClockRefusalV4)
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before
            .failure()
            .or_else(|| {
                self.before_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.after.failure())
            .or_else(|| {
                self.after_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.comparison
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}
