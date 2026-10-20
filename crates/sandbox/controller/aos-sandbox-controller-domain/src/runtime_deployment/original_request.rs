//! Owns the selected publisher's authenticated original request and clock window.
//!
//! Only the existing genuine Storage-delegate capture can construct the owning
//! request/record loan. Consuming it ends the record borrow without cloning the
//! request. The resulting window grants only an original clock comparison;
//! currentness still requires the live delegate, Origins, carrier and Invocation.

use std::num::NonZeroU64;

use aos_sandbox_linux::pidfd::PidFdProcessIdentity;
use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;
use aos_sandbox_protocol::runtime_deployment::canary::CanaryPublisherRequestV3;

/// Owns the sole decoded request while borrowing its authenticated original record.
///
/// No mutable capture or socket borrow escapes with this product. It exposes no
/// record, descriptor, constructor or currentness/signing authority.
#[must_use = "retain the authentic request until its original window is consumed"]
pub struct RuntimeDeploymentAuthenticatedRequestV3<'record> {
    request: CanaryPublisherRequestV3,
    _record: &'record ReceivedDescriptorRecord,
    cookie: NonZeroU64,
    identity: PidFdProcessIdentity,
}

impl<'record> RuntimeDeploymentAuthenticatedRequestV3<'record> {
    pub(super) fn from_completed_capture(
        request: CanaryPublisherRequestV3,
        record: &'record ReceivedDescriptorRecord,
        cookie: NonZeroU64,
        identity: PidFdProcessIdentity,
    ) -> Self {
        Self {
            request,
            _record: record,
            cookie,
            identity,
        }
    }

    /// Ends the record borrow and moves the same request into its original window.
    ///
    /// No decoding, cloning, clock observation or descriptor retirement occurs.
    #[must_use]
    pub fn into_original_window(self) -> RuntimeDeploymentOriginalWindowV3 {
        RuntimeDeploymentOriginalWindowV3 {
            request: self.request,
            cookie: self.cookie,
            identity: self.identity,
        }
    }
}

/// Owns a genuinely authenticated request's unchanged boot and exclusive window.
///
/// This cannot construct a delegate, floor or effect owner. Mutable original
/// rechecks remain mandatory; its request projection is descriptive DATA only.
pub struct RuntimeDeploymentOriginalWindowV3 {
    request: CanaryPublisherRequestV3,
    cookie: NonZeroU64,
    identity: PidFdProcessIdentity,
}

impl RuntimeDeploymentOriginalWindowV3 {
    /// Borrows the same decoded request without reinterpreting its authority.
    #[must_use]
    pub fn request(&self) -> &CanaryPublisherRequestV3 {
        &self.request
    }

    /// Compares the actual paired original clock with the unchanged signed window.
    ///
    /// # Errors
    /// Retains both failed observations when both fail, and refuses invalid
    /// clock arithmetic, another boot or an expired/not-yet-active window.
    pub fn require_clock(&self) -> Result<(), RuntimeDeploymentOriginalClockCauseV3> {
        let (boot, now) = observe_original_runtime_deployment_clock_v3()?;
        if boot != self.request.boot
            || now < self.request.not_before
            || now >= self.request.deadline
        {
            return Err(RuntimeDeploymentOriginalClockCauseV3::Changed);
        }

        Ok(())
    }

    pub(super) fn matches_capture(
        &self,
        cookie: Option<NonZeroU64>,
        identity: Option<PidFdProcessIdentity>,
    ) -> bool {
        cookie == Some(self.cookie) && identity == Some(self.identity)
    }
}

/// Retains the exact original publisher paired-clock failure.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeDeploymentOriginalClockCauseV3 {
    /// The original kernel boot observation failed.
    #[error("selected publisher original kernel observation failed")]
    Kernel(#[source] aos_sandbox_linux::Error),
    /// Both independent original observations failed.
    #[error("selected publisher original paired clock observation failed")]
    Paired {
        /// The actual kernel boot error.
        #[source]
        kernel: aos_sandbox_linux::Error,
        /// The actual boottime conversion error.
        clock: RuntimeDeploymentOriginalClockRangeV3,
    },
    /// The original boottime conversion failed.
    #[error("selected publisher original clock observation is invalid")]
    Clock(#[source] RuntimeDeploymentOriginalClockRangeV3),
    /// The original boot or exclusive window differs.
    #[error("selected publisher original boot or exclusive window changed")]
    Changed,
}

/// Distinguishes invalid clock coordinates from checked arithmetic overflow.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeDeploymentOriginalClockRangeV3 {
    /// Seconds or nanoseconds are outside the original supported range.
    #[error("CLOCK_BOOTTIME has invalid seconds or nanoseconds")]
    Range,
    /// Conversion to nanoseconds overflowed.
    #[error("CLOCK_BOOTTIME nanosecond arithmetic overflowed")]
    Overflow,
}

/// Observes both original publisher clock components before classifying errors.
///
/// # Errors
/// Preserves the actual kernel error, boottime range/overflow error, or both.
pub fn observe_original_runtime_deployment_clock_v3()
    -> Result<([u8; 16], u64), RuntimeDeploymentOriginalClockCauseV3>
{
    let boot = aos_sandbox_linux::boot::KernelBootId::current();
    let now = original_boottime_v3();

    match (boot, now) {
        (Ok(boot), Ok(now)) => Ok((boot.into_bytes(), now)),
        (Err(kernel), Err(clock)) => {
            Err(RuntimeDeploymentOriginalClockCauseV3::Paired { kernel, clock })
        }
        (Err(kernel), Ok(_)) => Err(RuntimeDeploymentOriginalClockCauseV3::Kernel(kernel)),
        (Ok(_), Err(clock)) => Err(RuntimeDeploymentOriginalClockCauseV3::Clock(clock)),
    }
}

fn original_boottime_v3() -> Result<u64, RuntimeDeploymentOriginalClockRangeV3> {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(value.tv_sec).map_err(|_| RuntimeDeploymentOriginalClockRangeV3::Range)?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| RuntimeDeploymentOriginalClockRangeV3::Range)?;
    if nanos >= 1_000_000_000 {
        return Err(RuntimeDeploymentOriginalClockRangeV3::Range);
    }

    seconds.checked_mul(1_000_000_000).and_then(|value| value.checked_add(nanos))
        .ok_or(RuntimeDeploymentOriginalClockRangeV3::Overflow)
}
